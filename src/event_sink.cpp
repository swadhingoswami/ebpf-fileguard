#include "fileguard/event_sink.hpp"

#include <iomanip>
#include <sstream>

#include <nlohmann/json.hpp>

namespace fileguard {

namespace {

// Column widths for the console table.
constexpr size_t kPidW = 8;
constexpr size_t kUidW = 6;
constexpr size_t kCommW = 16;
constexpr size_t kProcW = 36;
constexpr size_t kFileW = 44;
constexpr size_t kOpW = 6;
constexpr size_t kActionW = 7;
constexpr size_t kReasonW = 20;

std::string truncate(const std::string& s, size_t w) {
    if (s.size() <= w) return s;
    if (w <= 3) return s.substr(0, w);
    return s.substr(0, w - 3) + "...";
}

}  // namespace

void ConsoleSink::write(const SecurityEvent& e) {
    if (!header_printed_) {
        out_ << std::left << std::setw(kPidW) << "PID" << std::setw(kUidW) << "UID"
             << std::setw(kCommW) << "COMM" << std::setw(kProcW) << "PROCESS"
             << std::setw(kFileW) << "FILE" << std::setw(kOpW) << "OP"
             << std::setw(kActionW) << "ACTION" << std::setw(kReasonW) << "REASON"
             << '\n';
        out_ << std::string(kPidW + kUidW + kCommW + kProcW + kFileW + kOpW +
                                kActionW + kReasonW,
                            '-')
             << '\n';
        header_printed_ = true;
    }
    out_ << std::left << std::setw(kPidW) << e.pid << std::setw(kUidW) << e.uid
         << std::setw(kCommW) << truncate(e.comm, kCommW) << std::setw(kProcW)
         << truncate(e.process_path, kProcW) << std::setw(kFileW)
         << truncate(e.resource_path, kFileW) << std::setw(kOpW)
         << operation_name(e.operation) << std::setw(kActionW)
         << action_name(e.action) << std::setw(kReasonW) << reason_name(e.reason)
         << '\n';
}

void ConsoleSink::flush() { out_.flush(); }

void JsonSink::write(const SecurityEvent& e) {
    nlohmann::json j = {{"timestamp", e.timestamp},
                        {"pid", e.pid},
                        {"tgid", e.tgid},
                        {"uid", e.uid},
                        {"gid", e.gid},
                        {"comm", e.comm},
                        {"process", e.process_path},
                        {"resource", e.resource_path},
                        {"operation", operation_name(e.operation)},
                        {"action", action_name(e.action)},
                        {"reason", reason_name(e.reason)},
                        {"rule_id", e.rule_id}};
    out_ << j.dump() << '\n';
}

}  // namespace fileguard
