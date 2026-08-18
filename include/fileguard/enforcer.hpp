#pragma once

#include <cstdint>
#include <memory>
#include <stop_token>
#include <string>

#include "core_utils.hpp"
#include "policy_compiler.hpp"
#include "security_event.hpp"

namespace fileguard {

// Backend-agnostic description of the enforcement runtime state. Used by the
// CLI `status` command and the daemon's status reply.
struct EnforcerStatus {
    bool attached = false;         // BPF program currently attached
    bool enforcing = false;        // config.enabled == 1
    std::string backend = "none";  // "null" | "ebpf-lsm"
    int32_t policy_version = 0;
    size_t protected_count = 0;
    size_t rule_count = 0;
    std::string detail;            // human-readable, e.g. map/ring sizes
};

// Callback invoked by the enforcer for every decoded ring-buffer record.
// Called on the enforcer's polling thread; must be cheap and must not block
// for long (it enqueues to the SPSC event queue).
using EventHandler = std::function<void(const RawEvent&)>;

struct EnforcerConfig {
    uint32_t ringbuf_bytes = 1u << 20;  // 1 MiB ring buffer
    uint32_t map_entries = 4096;        // hash map capacity for rules/protected
    std::string runtime_dir;            // for pins / status files
    EventHandler on_event;              // required for the Linux backend
};

// Abstraction over the enforcement backend so the controller is testable and
// portable.
//
//   Linux:  LinuxEBPFEnforcer — loads fileguard.bpf.o, attaches the LSM
//           program, synchronizes CompiledPolicy into the maps, polls the
//           ring buffer, detaches on shutdown.
//   other:  NullEnforcer — a no-op stand-in so the whole controller builds
//           and runs (in pass-through mode) on non-Linux hosts.
//
// Enforcement happens IN THE KERNEL once `load()` + `apply_policy()` succeed;
// the userspace process can exit and the LSM program keeps enforcing the last
// installed policy. The enforcer only controls the userspace <-> kernel data
// path (events, updates).
class IEnforcer {
public:
    virtual ~IEnforcer() = default;

    // Open the object, load+attach the program. Failures are explicit.
    virtual ResultVoid load() = 0;

    // Install (or replace) the compiled policy in the kernel maps. Must be
    // called after load() and before the policy can be enforced.
    virtual ResultVoid apply_policy(const CompiledPolicy& policy) = 0;

    // Returns the current kernel-side state. Safe to call from any thread.
    virtual EnforcerStatus status() const = 0;

    // Polls the ring buffer and dispatches events to the configured handler
    // until `stop_token` is requested. Blocks the calling thread. This is the
    // producer side of the event pipeline.
    virtual void run(std::stop_token stop) = 0;

    // Detach the LSM program and close all BPF resources. After this the
    // system reverts to fail-open (unprotected) behavior.
    virtual ResultVoid detach() = 0;
};

// Factory. On Linux returns a LinuxEBPFEnforcer; elsewhere a NullEnforcer.
std::unique_ptr<IEnforcer> create_enforcer(const EnforcerConfig& cfg);

}  // namespace fileguard
