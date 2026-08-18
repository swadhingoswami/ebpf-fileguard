#include "fileguard/daemon.hpp"

#include <cerrno>
#include <cstring>
#include <fstream>
#include <thread>

#include <nlohmann/json.hpp>

#if defined(__unix__) || defined(__APPLE__)
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
#else
#error "eBPF FileGuard daemon requires a POSIX platform (unix sockets)"
#endif

#include "fileguard/config_parser.hpp"
#include "fileguard/decision_engine.hpp"
#include "fileguard/event_queue.hpp"

namespace fileguard {

namespace {

using nlohmann::json;

std::string json_of(const SecurityEvent& e) {
    return json{{"timestamp", e.timestamp},
                {"pid", e.pid},
                {"tgid", e.tgid},
                {"uid", e.uid},
                {"gid", e.gid},
                {"comm", e.comm},
                {"process", e.process_path},
                {"resource", e.resource_path},
                {"operation", operation_name(e.operation)},
                {"action", action_name(e.action)},
                {"reason", reason_name(e.reason)},
                {"rule_id", e.rule_id}}
        .dump();
}

bool write_all(int fd, const std::string& data) {
    size_t off = 0;
    while (off < data.size()) {
        const ssize_t n = ::send(fd, data.data() + off, data.size() - off, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        off += static_cast<size_t>(n);
    }
    return true;
}

}  // namespace

// Streams events to a single socket client. Push() is called from the
// controller's consumer thread (producer); the writer thread owns the socket.
SocketStreamClient::SocketStreamClient(int fd)
    : fd_(fd), queue_(1024) {
    writer_ = std::jthread([this] { writer_loop(); });
}

SocketStreamClient::~SocketStreamClient() {
    if (writer_.joinable()) writer_.join();
    if (fd_ >= 0) ::close(fd_);
}

void SocketStreamClient::push(const SecurityEvent& event) {
    if (closed_.load(std::memory_order_relaxed)) return;
    if (!queue_.try_push(json_of(event))) {
        dropped_.fetch_add(1, std::memory_order_relaxed);
    }
}

bool SocketStreamClient::closed() const {
    return closed_.load(std::memory_order_acquire);
}

void SocketStreamClient::shutdown() {
    closed_.store(true, std::memory_order_release);
    queue_.request_stop();
}

void SocketStreamClient::writer_loop() {
    std::string line;
    while (!closed_.load(std::memory_order_relaxed)) {
        if (!queue_.pop(line)) break;  // stopped & drained
        if (!write_all(fd_, line)) {
            closed_.store(true, std::memory_order_release);
            break;
        }
    }
    closed_.store(true, std::memory_order_release);
}

Daemon::Daemon(DaemonConfig cfg)
    : cfg_(std::move(cfg)), controller_(cfg_.controller) {}

Daemon::~Daemon() {
    (void)stop();
}

ResultVoid Daemon::run() {
    if (cfg_.socket_path.size() >= sizeof(sockaddr_un::sun_path)) {
        return err("socket path too long: '" + cfg_.socket_path + "'");
    }

    ::unlink(cfg_.socket_path.c_str());
    const int listen_fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        return err("socket(2) failed: " + std::string(std::strerror(errno)));
    }

    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, cfg_.socket_path.c_str(),
                 sizeof(addr.sun_path) - 1);

    if (::bind(listen_fd, reinterpret_cast<const sockaddr*>(&addr),
               sizeof(addr)) < 0) {
        const std::string msg = std::strerror(errno);
        ::close(listen_fd);
        return err("bind(" + cfg_.socket_path + ") failed: " + msg +
                   " — is another fileguard daemon running?");
    }
    ::chmod(cfg_.socket_path.c_str(), 0600);
    if (::listen(listen_fd, 16) < 0) {
        const std::string msg = std::strerror(errno);
        ::close(listen_fd);
        ::unlink(cfg_.socket_path.c_str());
        return err("listen failed: " + msg);
    }

    if (!cfg_.pid_file.empty()) {
        std::ofstream pf(cfg_.pid_file, std::ios::trunc);
        if (pf) pf << ::getpid() << '\n';
    }

    if (auto e = controller_.start(); !e) {
        ::close(listen_fd);
        ::unlink(cfg_.socket_path.c_str());
        if (!cfg_.pid_file.empty()) ::unlink(cfg_.pid_file.c_str());
        return err(e.error());
    }

    running_.store(true, std::memory_order_release);
    server_thread_ = std::jthread([this, listen_fd](std::stop_token st) {
        while (!st.stop_requested()) {
            pollfd pfd{listen_fd, POLLIN, 0};
            const int r = ::poll(&pfd, 1, 200);
            if (r == 0) continue;
            if (r < 0) {
                if (errno == EINTR) continue;
                break;
            }
            const int client_fd = ::accept(listen_fd, nullptr, nullptr);
            if (client_fd < 0) continue;
            std::thread([this, client_fd] { handle_client(client_fd); }).detach();
        }
        ::close(listen_fd);
        ::unlink(cfg_.socket_path.c_str());
    });

    // Serve until stop.
    while (running_.load(std::memory_order_acquire)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    if (server_thread_.joinable()) {
        server_thread_.request_stop();
        server_thread_.join();
    }
    if (auto e = controller_.request_stop(); !e) {
        return err(e.error());
    }
    if (!cfg_.pid_file.empty()) ::unlink(cfg_.pid_file.c_str());
    return ok_v();
}

ResultVoid Daemon::stop() {
    if (!running_.exchange(false)) {
        return ok_v();
    }
    // Close stream clients so their writer threads exit.
    std::lock_guard<std::mutex> lock(stream_clients_mu_);
    for (auto& c : stream_clients_) {
        c->shutdown();
    }
    stream_clients_.clear();
    return ok_v();
}

void Daemon::handle_client(int fd) {
    std::string buf;
    std::array<char, 4096> chunk{};
    while (running_.load(std::memory_order_acquire)) {
        pollfd pfd{fd, POLLIN, 0};
        const int r = ::poll(&pfd, 1, 200);
        if (r == 0) continue;
        if (r < 0) {
            if (errno == EINTR) continue;
            break;
        }
        const ssize_t n = ::recv(fd, chunk.data(), chunk.size(), 0);
        if (n <= 0) break;  // disconnect or error
        buf.append(chunk.data(), static_cast<size_t>(n));

        size_t nl;
        while ((nl = buf.find('\n')) != std::string::npos) {
            std::string line = buf.substr(0, nl);
            buf.erase(0, nl + 1);
            if (line.empty()) continue;
            if (!handle_line(fd, line)) return;  // client loop ended
        }
    }
    ::close(fd);
}

bool Daemon::handle_line(int fd, const std::string& line) {
    json req;
    try {
        req = json::parse(line);
    } catch (const json::parse_error&) {
        write_all(fd, json{{"ok", false}, {"error", "malformed request"}}.dump() + "\n");
        return true;
    }

    json resp;
    try {
        resp = handle_request(req);
    } catch (const std::exception& e) {
        resp = json{{"ok", false}, {"error", std::string("internal error: ") + e.what()}};
    }

    // Streaming requests switch this connection into event-feed mode.
    if (req.value("cmd", "") == "stream" && resp.value("ok", false) == true) {
        write_all(fd, resp.dump() + "\n");
        enter_stream_mode(fd);
        return false;
    }

    write_all(fd, resp.dump() + "\n");
    return true;
}

json Daemon::handle_request(const json& req) {
    const std::string cmd = req.value("cmd", "");
    if (cmd == "status") {
        const auto s = controller_.status();
        return json{{"ok", true},
                    {"status",
                     {{"attached", s.attached},
                      {"enforcing", s.enforcing},
                      {"backend", s.backend},
                      {"policy_version", s.policy_version},
                      {"protected_count", s.protected_count},
                      {"rule_count", s.rule_count},
                      {"detail", s.detail}}}};
    }

    if (cmd == "list") {
        const auto policy = controller_.policy_manager().current();
        json rules = json::array();
        json resources = json::array();
        if (policy) {
            for (const auto& r : policy->rules()) {
                rules.push_back({{"id", r.id},
                                 {"resource", r.resource.path},
                                 {"operation", operation_name(r.operation)},
                                 {"process", r.process.value},
                                 {"action", action_name(r.action)}});
            }
            for (const auto& res : policy->protected_resources()) {
                resources.push_back(res.path);
            }
        }
        return json{{"ok", true},
                    {"version", controller_.policy_manager().version()},
                    {"rules", rules},
                    {"protected_resources", resources}};
    }

    if (cmd == "load_policy") {
        if (!req.contains("policy") || !req["policy"].is_object()) {
            return json{{"ok", false}, {"error", "load_policy requires a 'policy' object"}};
        }
        auto parsed = ConfigParser::from_json(req["policy"].dump());
        if (!parsed) {
            return json{{"ok", false}, {"error", parsed.error()}};
        }
        auto policy = std::make_shared<const Policy>(std::move(*parsed));
        if (auto e = controller_.load_policy(std::move(policy)); !e) {
            return json{{"ok", false}, {"error", e.error()}};
        }
        return json{{"ok", true},
                    {"policy_version", controller_.policy_manager().version()}};
    }

    if (cmd == "stream") {
        // handle_line() switches this connection into event-feed mode after
        // this acknowledgment is sent.
        return json{{"ok", true}, {"stream", true}};
    }

    if (cmd == "stop") {
        // Reply first (the socket closes right after), then trigger shutdown.
        running_.store(false, std::memory_order_release);
        stop();
        return json{{"ok", true}, {"message", "stopping"}};
    }

    return json{{"ok", false}, {"error", "unknown command '" + cmd + "'"}};
}

void Daemon::enter_stream_mode(int fd) {
    auto client = std::make_shared<SocketStreamClient>(fd);
    {
        std::lock_guard<std::mutex> lock(stream_clients_mu_);
        stream_clients_.push_back(client);
    }
    controller_.add_event_stream_client(client);

    // Keep the connection alive until the client disconnects or we stop.
    while (running_.load(std::memory_order_acquire)) {
        pollfd pfd{fd, POLLIN, 0};
        const int r = ::poll(&pfd, 1, 200);
        if (r == 0) continue;
        if (r < 0) {
            if (errno == EINTR) continue;
            break;
        }
        char scratch[64];
        const ssize_t n = ::recv(fd, scratch, sizeof(scratch), 0);
        if (n <= 0) break;  // client closed
    }

    controller_.remove_event_stream_client(client.get());
    client->shutdown();
    {
        std::lock_guard<std::mutex> lock(stream_clients_mu_);
        std::erase_if(stream_clients_, [&](const auto& c) { return c == client; });
    }
    ::close(fd);
}

}  // namespace fileguard
