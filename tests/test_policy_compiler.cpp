#include <catch2/catch_test_macros.hpp>

#include "fileguard/policy_compiler.hpp"

using namespace fileguard;

namespace {

FileId id(uint32_t major, uint32_t minor, uint64_t ino) {
    FileId f;
    f.dev_major = major;
    f.dev_minor = minor;
    f.ino = ino;
    return f;
}

Policy make_policy() {
    return Policy(7, Action::Deny,
                  {ResourceIdentity{"/protected/secret.txt", Operation::Open}},
                  {PolicyRule{"allow-backup",
                              {"/protected/secret.txt", Operation::Open},
                              {ProcessIdentityType::ExePath, "/usr/local/bin/backup-agent"},
                              Operation::Open, Action::Allow}});
}

}  // namespace

TEST_CASE("Compiler resolves paths through the resolver", "[compiler]") {
    auto resolver = [](const std::string& path) -> Result<FileId> {
        if (path == "/protected/secret.txt") return id(1, 2, 1000);
        if (path == "/usr/local/bin/backup-agent") return id(1, 2, 2000);
        return err("unexpected path " + path);
    };
    PolicyCompiler compiler(resolver);
    auto compiled = compiler.compile(make_policy());
    REQUIRE(compiled.has_value());

    CHECK(compiled->version == 7);
    REQUIRE(compiled->protected_resources.size() == 1);
    CHECK(compiled->protected_resources[0] == id(1, 2, 1000));
    REQUIRE(compiled->rules.size() == 1);
    CHECK(compiled->rules[0].resource == id(1, 2, 1000));
    CHECK(compiled->rules[0].process == id(1, 2, 2000));
    CHECK(compiled->rules[0].rule_id == 1);
    CHECK(compiled->rules[0].action == Action::Allow);
}

TEST_CASE("Compiler surfaces unresolvable resource paths", "[compiler]") {
    auto resolver = [](const std::string&) -> Result<FileId> {
        return err("no such file");
    };
    PolicyCompiler compiler(resolver);
    auto compiled = compiler.compile(make_policy());
    REQUIRE(!compiled.has_value());
    CHECK(compiled.error().find("no such file") != std::string::npos);
}

TEST_CASE("Compiler rejects an invalid policy even with a working resolver",
          "[compiler]") {
    auto resolver = [](const std::string&) -> Result<FileId> {
        return id(1, 2, 42);
    };
    Policy p(1, Action::Deny, {}, {});  // rule references unprotected resource
    p = Policy(1, Action::Deny, {ResourceIdentity{"/a", Operation::Open}},
               {PolicyRule{"r", {"/b", Operation::Open},
                           {ProcessIdentityType::ExePath, "/bin/x"},
                           Operation::Open, Action::Allow}});
    PolicyCompiler compiler(resolver);
    auto compiled = compiler.compile(p);
    REQUIRE(!compiled.has_value());
}

TEST_CASE("Rule ids are 1-based indexes into the rule list", "[compiler]") {
    auto resolver = [](const std::string&) -> Result<FileId> {
        return id(1, 1, 7);
    };
    Policy p(1, Action::Deny, {ResourceIdentity{"/a", Operation::Open}},
             {PolicyRule{"r1", {"/a", Operation::Open},
                         {ProcessIdentityType::ExePath, "/bin/1"},
                         Operation::Open, Action::Allow},
              PolicyRule{"r2", {"/a", Operation::Open},
                         {ProcessIdentityType::ExePath, "/bin/2"},
                         Operation::Open, Action::Deny}});
    PolicyCompiler compiler(resolver);
    auto compiled = compiler.compile(p);
    REQUIRE(compiled.has_value());
    REQUIRE(compiled->rules.size() == 2);
    CHECK(compiled->rules[0].rule_id == 1);
    CHECK(compiled->rules[1].rule_id == 2);
}
