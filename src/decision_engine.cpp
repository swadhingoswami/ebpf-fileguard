#include "fileguard/decision_engine.hpp"

namespace fileguard {

Decision DecisionEngine::evaluate(const Policy& policy, const AccessRequest& request) {
    Decision decision;
    decision.action = Action::Deny;
    decision.reason = Reason::DefaultDeny;

    // Unprotected resources are always allowed (normal Linux semantics).
    if (!policy.is_protected(request.resource_path)) {
        decision.action = Action::Allow;
        decision.reason = Reason::ResourceUnprotected;
        return decision;
    }

    // Protected resource: an explicit matching rule decides, otherwise the
    // policy's default action applies (DENY for secure configurations).
    const PolicyRule* rule = policy.find_rule(request.resource_path, request.process,
                                              request.operation);
    if (rule) {
        decision.action = rule->action;
        decision.reason = Reason::PolicyRule;
        decision.matched_rule_id = rule->id;
        return decision;
    }

    decision.action = policy.default_action();
    decision.reason = Reason::DefaultDeny;
    return decision;
}

}  // namespace fileguard
