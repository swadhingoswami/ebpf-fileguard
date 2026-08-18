#include <sstream>

#include <catch2/catch_test_macros.hpp>

#include "fileguard/event_sink.hpp"

using namespace fileguard;

namespace {

SecurityEvent make_event() {
    SecurityEvent e;
    e.timestamp = "2026-08-18 12:00:00.000";
    e.pid = 1234;
    e.uid = 0;
    e.comm = "backup-agent";
    e.process_path = "/usr/local/bin/backup-agent";
    e.resource_path = "/protected/secret.txt";
    e.operation = Operation::Open;
    e.action = Action::Allow;
    e.reason = Reason::PolicyRule;
    e.rule_id = 1;
    return e;
}

}  // namespace

TEST_CASE("ConsoleSink renders the expected columns", "[sink]") {
    std::ostringstream ss;
    ConsoleSink sink(ss);
    sink.write(make_event());
    const std::string out = ss.str();
    CHECK(out.find("PID") != std::string::npos);
    CHECK(out.find("ACTION") != std::string::npos);
    CHECK(out.find("backup-agent") != std::string::npos);
    CHECK(out.find("/protected/secret.txt") != std::string::npos);
    CHECK(out.find("ALLOW") != std::string::npos);
    CHECK(out.find("POLICY_RULE") != std::string::npos);
}

TEST_CASE("JsonSink emits one compact JSON object per line", "[sink]") {
    std::ostringstream ss;
    JsonSink sink(ss);
    sink.write(make_event());
    sink.write(make_event());
    const std::string out = ss.str();
    CHECK(out.find('\n') != std::string::npos);
    const auto first = out.find('\n');
    CHECK(out.substr(0, first).find("\"resource\":\"/protected/secret.txt\"") !=
          std::string::npos);
    CHECK(out.substr(0, first).find("\"action\":\"ALLOW\"") != std::string::npos);
}
