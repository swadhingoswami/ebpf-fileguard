#pragma once

#include <cstdint>
#include <string>

#include "abi.h"
#include "core_utils.hpp"
#include "decision_engine.hpp"
#include "file_id.hpp"
#include "policy.hpp"

namespace fileguard {

// A fully decoded, enriched security event produced by the event pipeline.
//
// Decode path:
//   ringbuf record (fileguard_event_t)     <- kernel, compact
//        |  EventConsumer::decode()
//        v
//   RawEvent
//        |  PathResolver enrichment (FileId -> configured path)
//        v
//   SecurityEvent                          <- userspace, human-friendly
struct RawEvent {
    uint64_t timestamp_ns = 0;
    uint32_t pid = 0;
    uint32_t tgid = 0;
    uint32_t uid = 0;
    uint32_t gid = 0;
    FileId resource;
    FileId process;
    uint32_t rule_id = 0;
    Operation operation = Operation::Open;
    Action action = Action::Deny;
    Reason reason = Reason::DefaultDeny;
    std::string comm;
};

struct SecurityEvent {
    std::string timestamp;      // RFC3339-ish local time, e.g. "2026-08-18 12:34:56.789"
    uint32_t pid = 0;
    uint32_t tgid = 0;
    uint32_t uid = 0;
    uint32_t gid = 0;
    std::string comm;
    std::string process_path;   // enriched from policy config or dev:ino
    std::string resource_path;  // enriched from policy config or dev:ino
    Operation operation = Operation::Open;
    Action action = Action::Deny;
    Reason reason = Reason::DefaultDeny;
    uint32_t rule_id = 0;
};

}  // namespace fileguard
