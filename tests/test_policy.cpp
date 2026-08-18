#include <catch2/catch_test_macros.hpp>

#include "fileguard/policy.hpp"
#include "fileguard/config_parser.hpp"

using namespace fileguard;

namespace {

Policy good_policy() {
    return Policy(1, Action::Deny,
                  {ResourceIdentity{"/protected/secret.txt", Operation::Open}},
                  {PolicyRule{"r1", {"/protected/secret.txt", Operation::Open},
                              {ProcessIdentityType::ExePath, "/bin/cat"},
                              Operation::Open, Action::Allow}});
}

}  // namespace

TEST_CASE("Policy::validate accepts a consistent policy", "[policy]") {
    CHECK(good_policy().validate().has_value());
}

TEST_CASE("Policy::validate rejects a rule for an unprotected resource", "[policy]") {
    Policy p(1, Action::Deny,
             {ResourceIdentity{"/protected/secret.txt", Operation::Open}},
             {PolicyRule{"r1", {"/protected/secret.txt", Operation::Open},
                         {ProcessIdentityType::ExePath, "/bin/cat"},
                         Operation::Open, Action::Allow},
              PolicyRule{"r2", {"/etc/passwd", Operation::Open},
                         {ProcessIdentityType::ExePath, "/bin/cat"},
                         Operation::Open, Action::Allow}});
    CHECK(!p.validate().has_value());
}

TEST_CASE("Policy::validate rejects duplicate rule ids", "[policy]") {
    Policy p(1, Action::Deny,
             {ResourceIdentity{"/protected/secret.txt", Operation::Open}},
             {PolicyRule{"dup", {"/protected/secret.txt", Operation::Open},
                         {ProcessIdentityType::ExePath, "/bin/cat"},
                         Operation::Open, Action::Allow},
              PolicyRule{"dup", {"/protected/secret.txt", Operation::Open},
                         {ProcessIdentityType::ExePath, "/bin/vim"},
                         Operation::Open, Action::Deny}});
    CHECK(!p.validate().has_value());
}

TEST_CASE("Policy::validate rejects negative versions", "[policy]") {
    Policy p(-1, Action::Deny, {}, {});
    CHECK(!p.validate().has_value());
}

TEST_CASE("is_protected matches the configured path", "[policy]") {
    const auto policy = good_policy();
    CHECK(policy.is_protected("/protected/secret.txt"));
    CHECK_FALSE(policy.is_protected("/etc/hosts"));
}

TEST_CASE("find_rule requires resource, process and operation to match", "[policy]") {
    const auto policy = good_policy();
    const auto* rule = policy.find_rule("/protected/secret.txt",
                                        {ProcessIdentityType::ExePath, "/bin/cat"},
                                        Operation::Open);
    REQUIRE(rule != nullptr);
    CHECK(rule->id == "r1");
    CHECK(policy.find_rule("/protected/secret.txt",
                           {ProcessIdentityType::ExePath, "/bin/other"},
                           Operation::Open) == nullptr);
    CHECK(policy.find_rule("/etc/hosts",
                           {ProcessIdentityType::ExePath, "/bin/cat"},
                           Operation::Open) == nullptr);
}
