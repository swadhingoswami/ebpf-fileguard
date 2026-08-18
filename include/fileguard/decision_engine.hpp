#pragma once

#include "abi.h"
#include "core_utils.hpp"
#include "policy.hpp"

namespace fileguard {

// Why a decision was made. Values match the kernel-side FG_REASON_* codes in
// abi.h so an event reason round-trips losslessly.
enum class Reason : uint8_t {
    PolicyRule = FG_REASON_POLICY_RULE,
    DefaultDeny = FG_REASON_DEFAULT_DENY,
    UnknownProcess = FG_REASON_UNKNOWN_PROCESS,
    ResourceUnprotected = FG_REASON_UNKNOWN_RESOURCE,
};

constexpr const char* reason_name(Reason r) {
    switch (r) {
        case Reason::PolicyRule: return "POLICY_RULE";
        case Reason::DefaultDeny: return "DEFAULT_DENY";
        case Reason::UnknownProcess: return "UNKNOWN_PROCESS";
        case Reason::ResourceUnprotected: return "RESOURCE_UNPROTECTED";
    }
    return "?";
}

// A request to access a resource, expressed in path terms. The userspace
// DecisionEngine evaluates these; the kernel enforces an equivalent policy
// compiled from the same Policy object (see PolicyCompiler).
struct AccessRequest {
    std::string resource_path;
    ProcessIdentity process;
    Operation operation = Operation::Open;
};

// The outcome of evaluating an AccessRequest against a Policy.
struct Decision {
    Action action = Action::Deny;
    Reason reason = Reason::DefaultDeny;
    std::string matched_rule_id;
    uint32_t matched_rule_index = 0;
};

// Pure decision logic, mirroring the eBPF program's lookup flow:
//
//   resource protected?  --NO--> ALLOW
//        |
//        YES
//        |
//   explicit rule for (resource, process, operation)?
//        |
//        +-- YES --> apply rule action
//        +-- NO  --> default action (DENY for protected resources)
//
// The kernel runs this against compiled (dev, ino) identities; this engine
// runs the same semantics against paths. Both must stay in sync — the eBPF
// program is the enforcement authority, this engine powers tests, the CLI
// validate command, and the policy dry-run.
class DecisionEngine {
public:
    static Decision evaluate(const Policy& policy, const AccessRequest& request);
};

}  // namespace fileguard
