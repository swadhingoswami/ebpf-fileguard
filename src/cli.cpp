#include "fileguard/cli.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>

#include <nlohmann/json.hpp>

#include "fileguard/config_parser.hpp"
#include "fileguard/daemon.hpp"
#include "fileguard/decision_engine.hpp"
#include "fileguard/event_sink.hpp"
#include "fileguard/policy_compiler.hpp"
#include "fileguard/version.hpp"

#if defined(__unix__) || defined(__APPLE__)
#include <fcntl.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>
#endif

namespace fileguard {

namespace {

using nlohmann::json;

std::atomic<int> g_signal{0};

void signal_handler(int sig) {
    g_signal.store(sig, std::memory_order_relaxed);
}

std::string default_runtime_dir() {
#if defined(__linux__)
    if (::geteuid() == 0) return "/run/fileguard";
#endif
    return "/tmp/fileguard";
}

std::string socket_path(const std::string& dir) { return dir + "/fileguard.sock"; }
std::string pid_file_path(const std::string& dir) { return dir + "/fileguard.pid"; }

ResultVoid ensure_runtime_dir(const std::string& dir) {
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    if (ec) {
        return err("cannot create runtime directory '" + dir + "': " + ec.message());
    }
#if defined(__unix__) || defined(__APPLE__)
    ::chmod(dir.c_str(), 0700);
#endif
    return ok_v();
}

Result<int> daemon_connect(const std::string& sock) {
    if (!std::filesystem::exists(sock)) {
        return err("no fileguard controller is running (socket '" + sock +
                   "' does not exist). Start one with `guardctl serve --daemon`.");
    }
    const int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return err("socket(2): " + std::string(std::strerror(errno)));
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, sock.c_str(), sizeof(addr.sun_path) - 1);
    if (::connect(fd, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) < 0) {
        const std::string msg = std::strerror(errno);
        ::close(fd);
        return err("connect to controller failed: " + msg);
    }
    return fd;
}

Result<json> request_json(const std::string& sock, const json& req) {
    auto fd = daemon_connect(sock);
    if (!fd) return err(fd.error());

    const std::string payload = req.dump() + "\n";
    size_t off = 0;
    while (off < payload.size()) {
        const ssize_t n = ::send(*fd, payload.data() + off, payload.size() - off,
                                 MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR) continue;
            const std::string msg = std::strerror(errno);
            ::close(*fd);
            return err("send to controller failed: " + msg);
        }
        off += static_cast<size_t>(n);
    }

    std::string line;
    std::array<char, 4096> buf{};
    while (line.find('\n') == std::string::npos) {
        const ssize_t n = ::recv(*fd, buf.data(), buf.size(), 0);
        if (n <= 0) break;
        line.append(buf.data(), static_cast<size_t>(n));
        if (line.size() > (1u << 20)) break;  // sanity bound
    }
    ::close(*fd);
    const auto nl = line.find('\n');
    if (nl != std::string::npos) line.erase(nl);
    if (line.empty()) return err("controller closed the connection without a response");

    try {
        return json::parse(line);
    } catch (const json::parse_error& e) {
        return err("controller returned malformed JSON: " + std::string(e.what()));
    }
}

Action action_from_name(const std::string& s) {
    return s == "ALLOW" ? Action::Allow : Action::Deny;
}

Operation operation_from_name(const std::string& s) {
    return s == "OPEN" ? Operation::Open : Operation::Open;
}

Reason reason_from_name(const std::string& s) {
    if (s == "POLICY_RULE") return Reason::PolicyRule;
    if (s == "DEFAULT_DENY") return Reason::DefaultDeny;
    if (s == "UNKNOWN_PROCESS") return Reason::UnknownProcess;
    return Reason::ResourceUnprotected;
}

SecurityEvent event_from_json(const json& j) {
    SecurityEvent e;
    e.timestamp = j.value("timestamp", std::string(""));
    e.pid = j.value("pid", 0u);
    e.tgid = j.value("tgid", 0u);
    e.uid = j.value("uid", 0u);
    e.gid = j.value("gid", 0u);
    e.comm = j.value("comm", std::string(""));
    e.process_path = j.value("process", std::string(""));
    e.resource_path = j.value("resource", std::string(""));
    e.operation = operation_from_name(j.value("operation", std::string("OPEN")));
    e.action = action_from_name(j.value("action", std::string("DENY")));
    e.reason = reason_from_name(j.value("reason", std::string("DEFAULT_DENY")));
    e.rule_id = j.value("rule_id", 0u);
    return e;
}

void print_status(const json& resp) {
    if (!resp.value("ok", false)) {
        std::cerr << "status: " << resp.value("error", std::string("unknown error"))
                  << '\n';
        return;
    }
    const auto& s = resp["status"];
    std::cout << "fileguard: running\n";
    std::cout << "  backend:        " << s.value("backend", std::string("?")) << '\n';
    std::cout << "  attached:       " << (s.value("attached", false) ? "yes" : "no")
              << '\n';
    std::cout << "  enforcing:      " << (s.value("enforcing", false) ? "yes" : "no")
              << '\n';
    std::cout << "  policy version: " << s.value("policy_version", 0) << '\n';
    std::cout << "  protected:      " << s.value("protected_count", 0) << '\n';
    std::cout << "  rules:          " << s.value("rule_count", 0) << '\n';
    std::cout << "  detail:         " << s.value("detail", std::string("")) << '\n';
}

// ------------------------------------------------------------ subcommands

int run_serve(const CliArgs& args) {
    const std::string sock = socket_path(args.runtime_dir);
    if (std::filesystem::exists(sock)) {
        std::cerr << "fileguard: a controller is already running (" << sock << ")\n";
        return 1;
    }

    if (args.daemonize) {
        const pid_t pid = ::fork();
        if (pid < 0) {
            std::cerr << "fork failed: " << std::strerror(errno) << '\n';
            return 1;
        }
        if (pid > 0) {
            return 0;  // parent exits; child below keeps running
        }
        ::setsid();
        const int devnull = ::open("/dev/null", O_RDWR);
        if (devnull >= 0) {
            ::dup2(devnull, STDIN_FILENO);
            ::dup2(devnull, STDOUT_FILENO);
            ::dup2(devnull, STDERR_FILENO);
            if (devnull > 2) ::close(devnull);
        }
        // The child continues executing run_serve() below, as the daemon.
    }

    if (auto e = ensure_runtime_dir(args.runtime_dir); !e) {
        std::cerr << "fileguard: " << e.error() << '\n';
        return 1;
    }

    DaemonConfig cfg;
    cfg.controller.policy_file = args.policy_file;
    cfg.controller.runtime_dir = args.runtime_dir;
    cfg.controller.console_output = !args.daemonize;
    cfg.controller.json_log = args.log_file;
    cfg.socket_path = sock;
    cfg.pid_file = pid_file_path(args.runtime_dir);

    Daemon daemon(cfg);

    std::atomic<bool> done{false};
    std::atomic<int> rc{0};
    std::string daemon_error;
    std::mutex mu;
    std::condition_variable cv;

    std::jthread run_thread([&] {
        const auto r = daemon.run();
        if (r) {
            rc = 0;
        } else {
            rc = 1;
            daemon_error = r.error();
        }
        done = true;
        cv.notify_all();
    });

    std::cout << "fileguard: serving on " << sock << '\n';
    std::cout << "  " << kProjectName << " " << kVersion << " — " << kTagline
              << '\n';

    {
        std::unique_lock<std::mutex> lk(mu);
        while (!done && g_signal.load(std::memory_order_relaxed) == 0) {
            cv.wait_for(lk, std::chrono::milliseconds(200));
        }
    }

    const int sig = g_signal.load(std::memory_order_relaxed);
    if (sig != 0) {
        std::cout << "\nfileguard: received signal " << sig << ", shutting down\n";
        (void)daemon.stop();
    }
    run_thread.join();

    if (rc != 0) {
        std::cerr << "fileguard: controller exited with an error: "
                  << (daemon_error.empty() ? "unknown" : daemon_error) << '\n';
        return rc;
    }
    std::cout << "fileguard: stopped cleanly\n";
    return 0;
}

int run_policy_validate(const CliArgs& args) {
    auto policy = ConfigParser::from_file(args.policy_file);
    if (!policy) {
        std::cerr << "invalid policy: " << policy.error() << '\n';
        return 1;
    }
    // Full compile check catches unresolvable paths too.
    PolicyCompiler compiler;
    if (auto compiled = compiler.compile(*policy); !compiled) {
        std::cerr << "invalid policy: " << compiled.error() << '\n';
        return 1;
    }
    std::cout << "OK: policy '" << args.policy_file << "' is valid"
              << " (version " << policy->version() << ", "
              << policy->protected_resources().size() << " protected resource(s), "
              << policy->rules().size() << " rule(s), default "
              << action_name(policy->default_action()) << ")\n";
    return 0;
}

int run_policy_load(const CliArgs& args) {
    // Validate and compile locally first so bad policies never reach the daemon.
    auto policy = ConfigParser::from_file(args.policy_file);
    if (!policy) {
        std::cerr << "invalid policy: " << policy.error() << '\n';
        return 1;
    }
    PolicyCompiler compiler;
    auto compiled = compiler.compile(*policy);
    if (!compiled) {
        std::cerr << "invalid policy: " << compiled.error() << '\n';
        return 1;
    }

    const std::string sock = socket_path(args.runtime_dir);
    if (std::filesystem::exists(sock)) {
        auto resp = request_json(sock, json{{"cmd", "load_policy"},
                                            {"policy", json::parse(
                                                          [&] {
                                                              std::ifstream f(args.policy_file);
                                                              std::ostringstream ss;
                                                              ss << f.rdbuf();
                                                              return ss.str();
                                                          }())}});
        if (!resp) return 1;
        if (!resp->value("ok", false)) {
            std::cerr << "policy rejected: " << resp->value("error", std::string(""))
                      << '\n';
            return 1;
        }
        std::cout << "policy loaded (version " << resp->value("policy_version", 0)
                  << ")\n";
        return 0;
    }

    std::cout << "no controller running; starting fileguard daemon with the new "
                 "policy...\n";
    CliArgs spawn = args;
    spawn.command = "serve";
    spawn.daemonize = true;
    return run_serve(spawn);
}

int run_policy_list(const CliArgs& args) {
    const std::string sock = socket_path(args.runtime_dir);
    auto resp = request_json(sock, json{{"cmd", "list"}});
    if (!resp) {
        std::cerr << "policy list: " << resp.error() << '\n';
        return 1;
    }
    if (!resp->value("ok", false)) {
        std::cerr << "policy list: " << resp->value("error", std::string("")) << '\n';
        return 1;
    }
    std::cout << "policy version: " << resp->value("version", 0) << '\n';
    std::cout << "protected resources:\n";
    for (const auto& p : (*resp)["protected_resources"]) {
        std::cout << "  " << p.get<std::string>() << '\n';
    }
    std::cout << "rules:\n";
    for (const auto& r : (*resp)["rules"]) {
        std::cout << "  " << r.value("id", std::string("?")) << ": "
                  << r.value("process", std::string("?")) << " -> "
                  << r.value("resource", std::string("?")) << " ["
                  << r.value("operation", std::string("OPEN")) << "] "
                  << r.value("action", std::string("DENY")) << '\n';
    }
    return 0;
}

int run_status(const CliArgs& args) {
    const std::string sock = socket_path(args.runtime_dir);
    auto resp = request_json(sock, json{{"cmd", "status"}});
    if (!resp) {
        std::cerr << "fileguard: not running — " << resp.error() << '\n';
        return 1;
    }
    print_status(*resp);
    return 0;
}

int run_events(const CliArgs& args) {
    const std::string sock = socket_path(args.runtime_dir);
    auto fd = daemon_connect(sock);
    if (!fd) {
        std::cerr << "events: " << fd.error() << '\n';
        return 1;
    }
    const std::string req = json{{"cmd", "stream"}, {"json", args.json_output}}.dump() + "\n";
    (void)::send(*fd, req.data(), req.size(), MSG_NOSIGNAL);

    ConsoleSink table(std::cout);
    std::array<char, 4096> buf{};
    std::string pending;
    int seen = 0;
    const bool show_table = !args.json_output;

    while (args.event_count < 0 || seen < args.event_count) {
        const ssize_t n = ::recv(*fd, buf.data(), buf.size(), 0);
        if (n <= 0) break;
        pending.append(buf.data(), static_cast<size_t>(n));

        size_t nl;
        while ((nl = pending.find('\n')) != std::string::npos) {
            std::string line = pending.substr(0, nl);
            pending.erase(0, nl + 1);
            if (line.empty()) continue;

            json j;
            try {
                j = json::parse(line);
            } catch (const json::parse_error&) {
                continue;
            }
            if (j.contains("event")) {
                if (show_table) {
                    table.write(event_from_json(j["event"]));
                } else {
                    std::cout << j["event"].dump() << '\n';
                }
                ++seen;
            } else if (j.value("ok", false) == false && j.contains("error")) {
                std::cerr << "events: " << j.value("error", std::string("")) << '\n';
            }
        }
    }
    table.flush();
    std::cerr << "events: stream ended (" << seen << " event(s))\n";
    ::close(*fd);
    return 0;
}

int run_stop(const CliArgs& args) {
    const std::string sock = socket_path(args.runtime_dir);
    auto resp = request_json(sock, json{{"cmd", "stop"}});
    if (!resp) {
        std::cerr << "stop: " << resp.error() << '\n';
        return 1;
    }
    std::cout << "fileguard: " << resp->value("message", std::string("stopped"))
              << '\n';
    return 0;
}

}  // namespace

Result<CliArgs> parse_cli(int argc, char** argv) {
    CliArgs args;
    args.runtime_dir = default_runtime_dir();

    std::vector<std::string> tokens;
    for (int i = 1; i < argc; ++i) {
        tokens.emplace_back(argv[i]);
    }
    if (tokens.empty()) {
        return err("no command given. Try `guardctl --help`.");
    }

    const std::string first = tokens[0];
    if (first == "--help" || first == "-h" || first == "help") {
        args.command = "help";
        return args;
    }
    if (first == "--version" || first == "-V") {
        args.command = "version";
        return args;
    }

    if (first == "serve") {
        args.command = "serve";
        for (size_t i = 1; i < tokens.size(); ++i) {
            const std::string& t = tokens[i];
            if (t == "--daemon") {
                args.daemonize = true;
            } else if ((t == "--policy" || t == "-p") && i + 1 < tokens.size()) {
                args.policy_file = tokens[++i];
            } else if (t == "--log" && i + 1 < tokens.size()) {
                args.log_file = tokens[++i];
            } else if (t == "--runtime-dir" && i + 1 < tokens.size()) {
                args.runtime_dir = tokens[++i];
            } else {
                return err("unknown serve option: '" + t + "'");
            }
        }
        return args;
    }

    if (first == "status") {
        args.command = "status";
        for (size_t i = 1; i < tokens.size(); ++i) {
            if (tokens[i] == "--runtime-dir" && i + 1 < tokens.size()) {
                args.runtime_dir = tokens[++i];
            } else {
                return err("unknown status option: '" + tokens[i] + "'");
            }
        }
        return args;
    }
    if (first == "events") {
        args.command = "events";
        for (size_t i = 1; i < tokens.size(); ++i) {
            const std::string& t = tokens[i];
            if (t == "--json") {
                args.json_output = true;
            } else if (t == "--count" && i + 1 < tokens.size()) {
                args.event_count = std::atoi(tokens[++i].c_str());
            } else if (t == "--runtime-dir" && i + 1 < tokens.size()) {
                args.runtime_dir = tokens[++i];
            } else {
                return err("unknown events option: '" + t + "'");
            }
        }
        return args;
    }
    if (first == "stop") {
        args.command = "stop";
        for (size_t i = 1; i < tokens.size(); ++i) {
            if (tokens[i] == "--runtime-dir" && i + 1 < tokens.size()) {
                args.runtime_dir = tokens[++i];
            } else {
                return err("unknown stop option: '" + tokens[i] + "'");
            }
        }
        return args;
    }

    if (first == "policy") {
        if (tokens.size() < 2) {
            return err("`guardctl policy` needs a subcommand: validate|load|list");
        }
        const std::string sub = tokens[1];
        if (sub == "validate") {
            if (tokens.size() < 3) return err("usage: guardctl policy validate <file>");
            args.command = "policy-validate";
            args.policy_file = tokens[2];
        } else if (sub == "load") {
            if (tokens.size() < 3) return err("usage: guardctl policy load <file>");
            args.command = "policy-load";
            args.policy_file = tokens[2];
            for (size_t i = 3; i < tokens.size(); ++i) {
                if (tokens[i] == "--runtime-dir" && i + 1 < tokens.size()) {
                    args.runtime_dir = tokens[++i];
                } else {
                    return err("unknown policy load option: '" + tokens[i] + "'");
                }
            }
        } else if (sub == "list") {
            args.command = "policy-list";
            for (size_t i = 2; i < tokens.size(); ++i) {
                if (tokens[i] == "--runtime-dir" && i + 1 < tokens.size()) {
                    args.runtime_dir = tokens[++i];
                } else {
                    return err("unknown policy list option: '" + tokens[i] + "'");
                }
            }
        } else {
            return err("unknown policy subcommand: '" + sub + "'");
        }
        return args;
    }

    return err("unknown command: '" + first + "'");
}

int run_cli(const CliArgs& args) {
    struct sigaction sa {};
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);

    if (args.command == "serve") return run_serve(args);
    if (args.command == "policy-validate") return run_policy_validate(args);
    if (args.command == "policy-load") return run_policy_load(args);
    if (args.command == "policy-list") return run_policy_list(args);
    if (args.command == "status") return run_status(args);
    if (args.command == "events") return run_events(args);
    if (args.command == "stop") return run_stop(args);
    if (args.command == "version") {
        std::cout << kProjectName << " " << kVersion << " — " << kTagline << '\n';
        return 0;
    }
    if (args.command == "help") {
        std::cout << R"(eBPF FileGuard — Kernel-Assisted Runtime File Access Control

usage:
  guardctl serve [--policy FILE] [--daemon] [--log FILE] [--runtime-dir DIR]
  guardctl policy validate FILE
  guardctl policy load FILE
  guardctl policy list
  guardctl status
  guardctl events [--json] [--count N]
  guardctl stop
  guardctl --version | --help
)";
        return 0;
    }
    std::cerr << "unknown command\n";
    return 1;
}

int guardctl_main(int argc, char** argv) {
    auto parsed = parse_cli(argc, argv);
    if (!parsed) {
        std::cerr << "guardctl: " << parsed.error() << '\n';
        return 2;
    }
    return run_cli(*parsed);
}

}  // namespace fileguard
