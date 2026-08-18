#pragma once

#include <atomic>
#include <fstream>
#include <memory>
#include <mutex>
#include <stop_token>
#include <string>
#include <thread>

#include "core_utils.hpp"
#include "enforcer.hpp"
#include "event_queue.hpp"
#include "event_sink.hpp"
#include "path_resolver.hpp"
#include "policy.hpp"
#include "policy_compiler.hpp"
#include "security_event.hpp"

namespace fileguard {

// Owns the single current policy. Writes are serialized; reads get a stable
// shared_ptr to an immutable Policy. Policy installs validate before swapping,
// so the system is never exposed to a partially-validated policy.
class PolicyManager {
public:
    // Validates and installs. On error the current policy is left untouched.
    ResultVoid install(std::shared_ptr<const Policy> policy);

    // Current policy, or nullptr if none has been installed yet.
    std::shared_ptr<const Policy> current() const;

    // Current policy version, or 0.
    int32_t version() const;

private:
    mutable std::mutex mu_;
    std::shared_ptr<const Policy> current_;
};

// An active event-stream consumer (a socket client subscribed to events).
// Implemented by the daemon; the controller only knows the interface.
class EventStreamClient {
public:
    virtual ~EventStreamClient() = default;
    virtual void push(const SecurityEvent& event) = 0;
    virtual bool closed() const = 0;
};

struct ControllerConfig {
    std::string policy_file;      // policy JSON to load at startup
    std::string runtime_dir = "/tmp/fileguard";
    bool console_output = true;   // print human table to stdout
    std::string json_log;         // optional NDJSON file sink ("" = off)
    size_t event_queue_capacity = 65536;
    EnforcerConfig enforcer;      // on_event wired by the controller
};

// Wires the whole pipeline together:
//
//   PolicyManager ----compile----> CompiledPolicy ----apply----> IEnforcer (kernel)
//                                                                      |
//   ring poll thread  <--RawEvent-- (kernel ring buffer)              |
//        | decode + enrich (PathResolver)                             |
//        v                                                           |
//   SpscQueue<shared_ptr<const SecurityEvent>>                       |
//        |                                                           |
//   consumer thread -> SinkSet (console/JSON) + EventStreamClients  <+
//
// Ownership: the controller owns the PolicyManager, the enforcer (via
// unique_ptr), the resolver (shared_ptr<const>, rebuilt per policy), the SPSC
// queue and the two worker threads (jthread, joined in the destructor).
class Controller {
public:
    explicit Controller(ControllerConfig cfg);
    ~Controller();

    Controller(const Controller&) = delete;
    Controller& operator=(const Controller&) = delete;

    // Loads policy_file, creates the enforcer, attaches, installs the policy
    // and starts the worker threads. Blocks nothing; the caller keeps the
    // process alive and calls request_stop() on signals.
    ResultVoid start();

    // Thread-safe policy replacement: parse/validate/compile/apply in one
    // step. Returns an error without touching the running policy on any
    // failure. Policy documents must be validated by the caller first.
    ResultVoid load_policy(std::shared_ptr<const Policy> policy);

    // Signals shutdown: stops the ring poll, drains the event queue, detaches
    // the enforcer. Idempotent.
    ResultVoid request_stop();

    // Current enforcement status (also used by `guardctl status`).
    EnforcerStatus status() const;

    // Event stream subscription management (daemon socket clients).
    void add_event_stream_client(std::shared_ptr<EventStreamClient> client);
    void remove_event_stream_client(const EventStreamClient* client);

    const PolicyManager& policy_manager() const { return policy_manager_; }

private:
    void ring_poll_loop(std::stop_token stop);
    void consumer_loop(std::stop_token stop);
    void emit_event(const RawEvent& raw);

    ControllerConfig cfg_;
    PolicyManager policy_manager_;
    std::unique_ptr<IEnforcer> enforcer_;
    std::shared_ptr<const PathResolver> resolver_;
    mutable std::mutex resolver_mu_;

    SpscQueue<std::shared_ptr<const SecurityEvent>> queue_;
    SinkSet sinks_;
    std::ofstream json_log_stream_;
    int64_t boot_offset_ns_;

    mutable std::mutex clients_mu_;
    std::vector<std::shared_ptr<EventStreamClient>> clients_;

    std::atomic<bool> started_{false};
    std::jthread ring_thread_;
    std::jthread consumer_thread_;
};

}  // namespace fileguard
