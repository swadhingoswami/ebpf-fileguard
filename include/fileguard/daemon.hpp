#pragma once

#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <nlohmann/json_fwd.hpp>

#include "controller.hpp"
#include "core_utils.hpp"
#include "event_queue.hpp"

namespace fileguard {

// Streams events to a single socket client. The controller's consumer thread
// calls push() (producer); a dedicated writer thread owns the socket. If a
// client is slow, its own queue fills and events are dropped for it alone
// (counted, documented in docs/11-concurrency.md) without stalling the rest of
// the pipeline.
class SocketStreamClient : public EventStreamClient {
public:
    explicit SocketStreamClient(int fd);
    ~SocketStreamClient() override;
    void push(const SecurityEvent& event) override;
    bool closed() const override;
    void shutdown();

private:
    void writer_loop();

    int fd_;
    SpscQueue<std::string> queue_;
    std::jthread writer_;
    std::atomic<bool> closed_{false};
    std::atomic<uint64_t> dropped_{0};
};

struct DaemonConfig {
    ControllerConfig controller;
    std::string socket_path;  // e.g. /run/fileguard/fileguard.sock
    std::string pid_file;
};

// Long-running controller process that exposes a control plane over a UNIX
// domain socket:
//
//   guardctl status        -> {"cmd":"status"}         -> {"ok":true,"status":{...}}
//   guardctl policy load   -> {"cmd":"load_policy", "policy": <json>}
//   guardctl policy list   -> {"cmd":"list"}           -> {"ok":true,"rules":[...]}
//   guardctl events        -> {"cmd":"stream","json":..} -> {"event":{...}} per line
//   guardctl stop          -> {"cmd":"stop"}           -> {"ok":true}
//
// Protocol: one JSON object per line (NDJSON). All commands are handled
// inline; `stream` hands the client an EventStreamClient that the controller's
// consumer thread feeds directly, so a slow client only ever stalls its own
// writer thread.
class Daemon {
public:
    explicit Daemon(DaemonConfig cfg);
    ~Daemon();

    Daemon(const Daemon&) = delete;
    Daemon& operator=(const Daemon&) = delete;

    ResultVoid run();          // blocks until stop
    ResultVoid stop();

private:
    void handle_client(int fd);
    bool handle_line(int fd, const std::string& line);
    nlohmann::json handle_request(const nlohmann::json& req);
    void enter_stream_mode(int fd);

    DaemonConfig cfg_;
    Controller controller_;
    std::atomic<bool> running_{false};
    std::jthread server_thread_;
    mutable std::mutex stream_clients_mu_;
    std::vector<std::shared_ptr<SocketStreamClient>> stream_clients_;
};

}  // namespace fileguard
