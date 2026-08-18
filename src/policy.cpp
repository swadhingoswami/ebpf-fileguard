#include "fileguard/policy.hpp"

#include <unordered_set>

namespace fileguard {

ResultVoid Policy::validate() const {
    if (version_ < 0) {
        return err("policy version must be non-negative");
    }

    std::unordered_set<std::string> protected_paths;
    for (const auto& res : protected_resources_) {
        if (res.path.empty()) {
            return err("protected resource has an empty path");
        }
        if (res.path.front() != '/') {
            return err("protected resource path must be absolute: '" + res.path + "'");
        }
        if (res.operation && *res.operation != Operation::Open) {
            return err("unsupported operation on protected resource '" + res.path +
                       "' (MVP supports OPEN only)");
        }
        if (!protected_paths.insert(res.path).second) {
            return err("duplicate protected resource: '" + res.path + "'");
        }
    }

    std::unordered_set<std::string> rule_ids;
    for (const auto& rule : rules_) {
        if (rule.id.empty()) {
            return err("rule has an empty id");
        }
        if (!rule_ids.insert(rule.id).second) {
            return err("duplicate rule id: '" + rule.id + "'");
        }
        if (rule.resource.path.empty() || rule.resource.path.front() != '/') {
            return err("rule '" + rule.id + "' resource path must be absolute");
        }
        if (protected_paths.count(rule.resource.path) == 0) {
            return err("rule '" + rule.id + "' references resource '" +
                       rule.resource.path +
                       "' which is not listed in protected_resources");
        }
        if (rule.process.type != ProcessIdentityType::ExePath) {
            return err("rule '" + rule.id +
                       "' uses an unsupported process identity type (MVP: exe_path)");
        }
        if (rule.process.value.empty()) {
            return err("rule '" + rule.id + "' has an empty process path");
        }
        if (rule.operation != Operation::Open) {
            return err("rule '" + rule.id +
                       "' uses an unsupported operation (MVP supports OPEN only)");
        }
    }

    return ok_v();
}

bool Policy::is_protected(std::string_view path) const {
    for (const auto& res : protected_resources_) {
        if (res.path == path) return true;
    }
    return false;
}

const PolicyRule* Policy::find_rule(std::string_view resource_path,
                                    const ProcessIdentity& process,
                                    Operation op) const {
    for (const auto& rule : rules_) {
        if (rule.resource.path == resource_path &&
            rule.process.type == process.type &&
            rule.process.value == process.value && rule.operation == op) {
            return &rule;
        }
    }
    return nullptr;
}

}  // namespace fileguard
