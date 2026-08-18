#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "core_utils.hpp"

namespace fileguard {

// ---------------------------------------------------------------------------
// Strongly-typed policy vocabulary.
//
// The policy model is:
//
//     default-action                 (applies to protected resources only)
//     protected-resource             -> identity of a file worth protecting
//     rule                           -> (resource, process, operation, action)
//
// Protected resources use a default-DENY model: a protected resource may only
// be accessed if an explicit rule grants the requesting process access to it
// for the requested operation. Unprotected resources are unaffected.
// ---------------------------------------------------------------------------

enum class Operation : uint8_t { Open = 1 };
enum class Action : uint8_t { Allow = 0, Deny = 1 };
enum class ProcessIdentityType : uint8_t { ExePath = 1 };

constexpr const char* operation_name(Operation op) {
    return op == Operation::Open ? "OPEN" : "?";
}

constexpr const char* action_name(Action a) {
    return a == Action::Allow ? "ALLOW" : "DENY";
}

// Identifies the process that may (or may not) access a protected resource.
// Level 1 of the identity evolution path (docs/05-policy-model.md): the
// absolute path of the executable image. Levels 2-4 (uid, stable attrs,
// content hash) are future extensions of this struct.
struct ProcessIdentity {
    ProcessIdentityType type = ProcessIdentityType::ExePath;
    std::string value;  // e.g. "/usr/local/bin/backup-agent"
};

// Identifies the protected resource by its configured path. The enforcement
// backend resolves the path to a FileId (dev, ino) at policy install time.
struct ResourceIdentity {
    std::string path;                    // absolute path, e.g. "/protected/secret.txt"
    std::optional<Operation> operation;  // MVP: only OPEN
};

struct PolicyRule {
    std::string id;             // unique human-readable identifier
    ResourceIdentity resource;  // must reference a protected resource
    ProcessIdentity process;
    Operation operation = Operation::Open;
    Action action = Action::Allow;
};

// An immutable, validated policy. Validation happens once at parse/load time
// (see ConfigParser::from_json and Policy::validate); after construction the
// object is never mutated. PolicyManager holds a shared_ptr<const Policy> and
// swaps it atomically on update.
class Policy {
public:
    // Structured constructor; use ConfigParser for file/JSON input.
    Policy() = default;
    Policy(int32_t version, Action default_action,
           std::vector<ResourceIdentity> protected_resources,
           std::vector<PolicyRule> rules)
        : version_(version),
          default_action_(default_action),
          protected_resources_(std::move(protected_resources)),
          rules_(std::move(rules)) {}

    // Validates invariants. Returns ok_v() or a human-readable message.
    ResultVoid validate() const;

    // True if `path` is listed as a protected resource (exact match).
    [[nodiscard]] bool is_protected(std::string_view path) const;
    // Returns the first rule matching resource+process+operation, or nullptr.
    [[nodiscard]] const PolicyRule* find_rule(std::string_view resource_path,
                                              const ProcessIdentity& process,
                                              Operation op) const;

    [[nodiscard]] int32_t version() const { return version_; }
    [[nodiscard]] Action default_action() const { return default_action_; }
    [[nodiscard]] const std::vector<ResourceIdentity>& protected_resources() const {
        return protected_resources_;
    }
    [[nodiscard]] const std::vector<PolicyRule>& rules() const { return rules_; }

private:
    int32_t version_ = 0;
    Action default_action_ = Action::Deny;
    std::vector<ResourceIdentity> protected_resources_;
    std::vector<PolicyRule> rules_;
};

}  // namespace fileguard
