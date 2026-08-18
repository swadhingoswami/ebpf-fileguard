#include "fileguard/controller.hpp"

#include <chrono>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>

#include "fileguard/config_parser.hpp"
#include "fileguard/decision_engine.hpp"

namespace fileguard {

namespace {

// Offset between the kernel's boot-time clock (bpf_ktime_get_ns) and the wall
// clock, captured once at startup so event timestamps can be rendered as local
// time. Approximation on macOS (CLOCK_MONOTONIC); exact on Linux
// (CLOCK_BOOTTIME). Display-only; ordering and storage never depend on it.
int64_t boot_wall_offset_ns() {
    const auto wall = std::chrono::system_clock::now().time_since_epoch();
#if defined(__linux__)
    struct timespec ts {};
    clock_gettime(CLOCK_BOOTTIME, &ts);
    const auto boot = std::chrono::seconds(ts.tv_sec) + std::chrono::nanoseconds(ts.tv_nsec);
#else
    const auto boot = std::chrono::steady_clock::now().time_since_epoch();
#endif
    return std::chrono::duration_cast<std::chrono::nanoseconds>(wall - boot).count();
}

std::string format_event_time(int64_t timestamp_ns, int64_t offset_ns) {
    const int64_t wall_ns = timestamp_ns + offset_ns;
    const auto secs = std::chrono::seconds(wall_ns / 1'000'000'000);
    const auto ms = (wall_ns % 1'000'000'000) / 1'000'000;
    const auto tp = std::chrono::system_clock::time_point(secs);
    const std::time_t t = std::chrono::system_clock::to_time_t(tp);
    std::tm tm_buf{};
#if defined(_WIN32)
    localtime_s(&tm_buf, &t);
#else
    localtime_r(&t, &tm_buf);
#endif
    std::ostringstream ss;
    ss << std::put_time(&tm_buf, "%Y-%m-%d %H:%M:%S") << '.' << std::setfill('0')
       << std::setw(3) << ms;
    return ss.str();
}

}  // namespace

// ---------------------------------------------------------------- PolicyManager

ResultVoid PolicyManager::install(std::shared_ptr<const Policy> policy) {
    if (!policy) return err("cannot install a null policy");
    if (auto v = policy->validate(); !v) return err(v.error());
    std::lock_guard<std::mutex> lock(mu_);
    current_ = std::move(policy);
    return ok_v();
}

std::shared_ptr<const Policy> PolicyManager::current() const {
    std::lock_guard<std::mutex> lock(mu_);
    return current_;
}

int32_t PolicyManager::version() const {
    std::lock_guard<std::mutex> lock(mu_);
    return current_ ? current_->version() : 0;
}

// ---------------------------------------------------------------- Controller

Controller::Controller(ControllerConfig cfg)
    : cfg_(std::move(cfg)),
      queue_(cfg_.event_queue_capacity),
      boot_offset_ns_(boot_wall_offset_ns()) {
    if (cfg_.console_output) {
        sinks_.add(std::make_unique<ConsoleSink>(std::cout));
    }
    if (!cfg_.json_log.empty()) {
        json_log_stream_.open(cfg_.json_log, std::ios::out | std::ios::app);
        if (!json_log_stream_) {
            std::cerr << "warning: cannot open JSON log '" << cfg_.json_log
                      << "' (events will not be logged there)\n";
        } else {
            sinks_.add(std::make_unique<JsonSink>(json_log_stream_));
        }
    }
}

Controller::~Controller() {
    (void)request_stop();
}

ResultVoid Controller::start() {
    if (started_.exchange(true)) {
        return err("controller already started");
    }

    // 1. Enforcement backend first: the startup policy must be applied to the
    //    kernel, so the enforcer has to exist before load_policy runs.
    cfg_.enforcer.on_event = [this](const RawEvent& raw) { emit_event(raw); };
    enforcer_ = create_enforcer(cfg_.enforcer);
    if (auto e = enforcer_->load(); !e) {
        return err(e.error());
    }

    // 2. Startup policy (optional; can be replaced later via load_policy).
    if (!cfg_.policy_file.empty()) {
        auto policy = ConfigParser::from_file(cfg_.policy_file);
        if (!policy) return err(policy.error());
        if (auto e = load_policy(std::make_shared<const Policy>(std::move(*policy))); !e) {
            return err(e.error());
        }
    }

    // 3. Worker threads: ring-buffer poller (producer) + logger (consumer).
    ring_thread_ = std::jthread([this](std::stop_token st) { ring_poll_loop(st); });
    consumer_thread_ = std::jthread([this](std::stop_token st) { consumer_loop(st); });

    return ok_v();
}

ResultVoid Controller::load_policy(std::shared_ptr<const Policy> policy) {
    if (!policy) return err("cannot install a null policy");
    if (auto v = policy->validate(); !v) return err(v.error());

    // Compile and apply to the kernel first; only on success swap the
    // userspace policy. On any failure the previous policy stays active in
    // userspace (and, where possible, in the kernel).
    PolicyCompiler compiler;
    auto compiled = compiler.compile(*policy);
    if (!compiled) return err(compiled.error());

    if (enforcer_) {
        if (auto e = enforcer_->apply_policy(*compiled); !e) {
            return err("kernel policy install failed: " + e.error());
        }
    }

    // Rebuild the reverse resolver for event enrichment.
    auto resolver = std::make_shared<PathResolver>();
    const auto& resources = policy->protected_resources();
    const auto& compiled_res = compiled->protected_resources;
    for (size_t i = 0; i < resources.size() && i < compiled_res.size(); ++i) {
        resolver->add(compiled_res[i], resources[i].path);
    }
    const auto& rules = policy->rules();
    const auto& compiled_rules = compiled->rules;
    for (size_t i = 0; i < rules.size() && i < compiled_rules.size(); ++i) {
        resolver->add(compiled_rules[i].process, rules[i].process.value);
    }
    {
        std::lock_guard<std::mutex> lock(resolver_mu_);
        resolver_ = std::move(resolver);
    }

    if (auto e = policy_manager_.install(std::move(policy)); !e) {
        return err(e.error());
    }
    return ok_v();
}

ResultVoid Controller::request_stop() {
    if (!started_) return ok_v();
    started_ = false;

    queue_.request_stop();  // unblocks any blocked producer/consumer
    if (ring_thread_.joinable()) ring_thread_.request_stop();
    if (consumer_thread_.joinable()) consumer_thread_.request_stop();

    if (ring_thread_.joinable()) ring_thread_.join();
    if (consumer_thread_.joinable()) consumer_thread_.join();

    if (enforcer_) {
        if (auto e = enforcer_->detach(); !e) {
            return err(e.error());
        }
    }
    sinks_.flush();
    return ok_v();
}

EnforcerStatus Controller::status() const {
    if (!enforcer_) {
        EnforcerStatus s;
        s.backend = "unloaded";
        return s;
    }
    return enforcer_->status();
}

void Controller::add_event_stream_client(std::shared_ptr<EventStreamClient> client) {
    std::lock_guard<std::mutex> lock(clients_mu_);
    clients_.push_back(std::move(client));
}

void Controller::remove_event_stream_client(const EventStreamClient* client) {
    std::lock_guard<std::mutex> lock(clients_mu_);
    std::erase_if(clients_, [client](const auto& c) { return c.get() == client; });
}

void Controller::ring_poll_loop(std::stop_token stop) {
    if (enforcer_) {
        enforcer_->run(stop);
    } else {
        while (!stop.stop_requested()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
}

void Controller::emit_event(const RawEvent& raw) {
    std::shared_ptr<const PathResolver> resolver;
    {
        std::lock_guard<std::mutex> lock(resolver_mu_);
        resolver = resolver_;
    }

    SecurityEvent ev;
    ev.timestamp = format_event_time(static_cast<int64_t>(raw.timestamp_ns),
                                     boot_offset_ns_);
    ev.pid = raw.pid;
    ev.tgid = raw.tgid;
    ev.uid = raw.uid;
    ev.gid = raw.gid;
    ev.comm = raw.comm;
    ev.process_path = resolver ? resolver->resolve(raw.process) : raw.process.to_string();
    ev.resource_path = resolver ? resolver->resolve(raw.resource) : raw.resource.to_string();
    ev.operation = raw.operation;
    ev.action = raw.action;
    ev.reason = raw.reason;
    ev.rule_id = raw.rule_id;

    queue_.push(std::make_shared<const SecurityEvent>(std::move(ev)));
}

void Controller::consumer_loop(std::stop_token /*stop*/) {
    while (true) {
        std::shared_ptr<const SecurityEvent> ev;
        if (!queue_.pop(ev)) break;  // stopped and drained

        sinks_.write(*ev);

        std::lock_guard<std::mutex> lock(clients_mu_);
        for (auto it = clients_.begin(); it != clients_.end();) {
            if ((*it)->closed()) {
                it = clients_.erase(it);
                continue;
            }
            (*it)->push(*ev);
            ++it;
        }
    }
}

}  // namespace fileguard
