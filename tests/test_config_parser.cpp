#include <catch2/catch_test_macros.hpp>

#include "fileguard/config_parser.hpp"
#include "fileguard/decision_engine.hpp"

using namespace fileguard;

namespace {

constexpr const char* kGoodPolicy = R"({
    "version": 3,
    "defaults": { "action": "DENY" },
    "protected_resources": [
        { "path": "/protected/secret.txt", "operation": "OPEN" }
    ],
    "rules": [
        {
            "id": "allow-backup",
            "resource": "/protected/secret.txt",
            "operation": "OPEN",
            "process": { "type": "exe_path", "value": "/usr/local/bin/backup-agent" },
            "action": "ALLOW"
        }
    ]
})";

}  // namespace

TEST_CASE("ConfigParser accepts a valid policy", "[config]") {
    auto policy = ConfigParser::from_json(kGoodPolicy);
    REQUIRE(policy.has_value());
    CHECK(policy->version() == 3);
    CHECK(policy->default_action() == Action::Deny);
    REQUIRE(policy->protected_resources().size() == 1);
    CHECK(policy->protected_resources()[0].path == "/protected/secret.txt");
    REQUIRE(policy->rules().size() == 1);
    CHECK(policy->rules()[0].id == "allow-backup");
    CHECK(policy->rules()[0].process.value == "/usr/local/bin/backup-agent");
    CHECK(policy->rules()[0].action == Action::Allow);
}

TEST_CASE("ConfigParser rejects malformed JSON", "[config]") {
    auto policy = ConfigParser::from_json("{ not valid json");
    REQUIRE(!policy.has_value());
}

TEST_CASE("ConfigParser rejects unknown action", "[config]") {
    const std::string bad = R"({
        "defaults": { "action": "MAYBE" },
        "protected_resources": [],
        "rules": []
    })";
    auto policy = ConfigParser::from_json(bad);
    REQUIRE(!policy.has_value());
}

TEST_CASE("ConfigParser defaults action to DENY when omitted", "[config]") {
    const std::string p = R"({
        "protected_resources": [],
        "rules": []
    })";
    auto policy = ConfigParser::from_json(p);
    REQUIRE(policy.has_value());
    CHECK(policy->default_action() == Action::Deny);
}

TEST_CASE("ConfigParser rejects rule for an unprotected resource", "[config]") {
    const std::string bad = R"({
        "protected_resources": [ { "path": "/protected/secret.txt" } ],
        "rules": [
            {
                "id": "r1",
                "resource": "/etc/passwd",
                "process": { "type": "exe_path", "value": "/bin/cat" },
                "action": "ALLOW"
            }
        ]
    })";
    auto policy = ConfigParser::from_json(bad);
    REQUIRE(!policy.has_value());
}

TEST_CASE("ConfigParser rejects unsupported process identity type", "[config]") {
    const std::string bad = R"({
        "protected_resources": [ { "path": "/protected/secret.txt" } ],
        "rules": [
            {
                "id": "r1",
                "resource": "/protected/secret.txt",
                "process": { "type": "uid", "value": "1000" },
                "action": "ALLOW"
            }
        ]
    })";
    auto policy = ConfigParser::from_json(bad);
    REQUIRE(!policy.has_value());
}

TEST_CASE("ConfigParser rejects relative paths", "[config]") {
    const std::string bad = R"({
        "protected_resources": [ { "path": "relative/path.txt" } ],
        "rules": []
    })";
    auto policy = ConfigParser::from_json(bad);
    REQUIRE(!policy.has_value());
}

TEST_CASE("ConfigParser rejects duplicate rule ids", "[config]") {
    const std::string bad = R"({
        "protected_resources": [ { "path": "/protected/secret.txt" } ],
        "rules": [
            {
                "id": "dup",
                "resource": "/protected/secret.txt",
                "process": { "type": "exe_path", "value": "/bin/cat" },
                "action": "ALLOW"
            },
            {
                "id": "dup",
                "resource": "/protected/secret.txt",
                "process": { "type": "exe_path", "value": "/bin/vim" },
                "action": "ALLOW"
            }
        ]
    })";
    auto policy = ConfigParser::from_json(bad);
    REQUIRE(!policy.has_value());
}
