#include <catch2/catch_test_macros.hpp>

#include "fileguard/config_parser.hpp"
#include "fileguard/decision_engine.hpp"

using namespace fileguard;

namespace {

ProcessIdentity cat() { return {ProcessIdentityType::ExePath, "/bin/cat"}; }
ProcessIdentity backup() { return {ProcessIdentityType::ExePath, "/usr/local/bin/backup-agent"}; }

Policy policy_with_default(Action def) {
    return Policy(1, def,
                  {ResourceIdentity{"/protected/secret.txt", Operation::Open}},
                  {PolicyRule{"allow-backup", {"/protected/secret.txt", Operation::Open},
                              backup(), Operation::Open, Action::Allow}});
}

}  // namespace

TEST_CASE("Unprotected resource is always allowed", "[decision]") {
    const auto policy = policy_with_default(Action::Deny);
    const auto d = DecisionEngine::evaluate(
        policy, AccessRequest{"/etc/hosts", cat(), Operation::Open});
    CHECK(d.action == Action::Allow);
    CHECK(d.reason == Reason::ResourceUnprotected);
}

TEST_CASE("Protected resource with matching allow rule", "[decision]") {
    const auto policy = policy_with_default(Action::Deny);
    const auto d = DecisionEngine::evaluate(
        policy, AccessRequest{"/protected/secret.txt", backup(), Operation::Open});
    CHECK(d.action == Action::Allow);
    CHECK(d.reason == Reason::PolicyRule);
    CHECK(d.matched_rule_id == "allow-backup");
}

TEST_CASE("Protected resource with explicit deny rule", "[decision]") {
    Policy p(1, Action::Deny, {ResourceIdentity{"/protected/secret.txt", Operation::Open}},
             {PolicyRule{"deny-backup", {"/protected/secret.txt", Operation::Open},
                         backup(), Operation::Open, Action::Deny}});
    const auto d = DecisionEngine::evaluate(
        p, AccessRequest{"/protected/secret.txt", backup(), Operation::Open});
    CHECK(d.action == Action::Deny);
    CHECK(d.reason == Reason::PolicyRule);
}

TEST_CASE("Protected resource, unauthorized process -> default DENY", "[decision]") {
    const auto policy = policy_with_default(Action::Deny);
    const auto d = DecisionEngine::evaluate(
        policy, AccessRequest{"/protected/secret.txt", cat(), Operation::Open});
    CHECK(d.action == Action::Deny);
    CHECK(d.reason == Reason::DefaultDeny);
    CHECK(d.matched_rule_id.empty());
}

TEST_CASE("Default action ALLOW applies to unmatched protected access", "[decision]") {
    const auto policy = policy_with_default(Action::Allow);
    const auto d = DecisionEngine::evaluate(
        policy, AccessRequest{"/protected/secret.txt", cat(), Operation::Open});
    CHECK(d.action == Action::Allow);
    CHECK(d.reason == Reason::DefaultDeny);
}

TEST_CASE("Matching wrong process does not match a rule", "[decision]") {
    const auto policy = policy_with_default(Action::Deny);
    const auto d = DecisionEngine::evaluate(
        policy, AccessRequest{"/protected/secret.txt",
                              {ProcessIdentityType::ExePath, "/bin/cp"}, Operation::Open});
    CHECK(d.action == Action::Deny);
    CHECK(d.reason == Reason::DefaultDeny);
}
