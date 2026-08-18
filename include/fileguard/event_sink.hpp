#pragma once

#include <memory>
#include <ostream>
#include <string>
#include <vector>

#include "security_event.hpp"

namespace fileguard {

// Sink abstraction for security events. Multiple sinks can be attached at
// once (e.g. console + JSON log). Sinks must be cheap and non-blocking enough
// to keep up with the ring buffer; see docs/11-concurrency for the design.
class ISink {
public:
    virtual ~ISink() = default;
    virtual void write(const SecurityEvent& event) = 0;
    virtual void flush() {}
};

// Human-readable aligned table, matching the CLI examples in the spec:
//
//   PID      PROCESS          FILE                       OP     ACTION  REASON
//   1234     backup-agent     /protected/secret.txt     OPEN   ALLOW   POLICY_RULE
//   4567     cat              /protected/secret.txt     OPEN   DENY    DEFAULT_DENY
class ConsoleSink : public ISink {
public:
    explicit ConsoleSink(std::ostream& out) : out_(out) {}
    void write(const SecurityEvent& event) override;
    void flush() override;

private:
    std::ostream& out_;
    bool header_printed_ = false;
};

// Newline-delimited JSON (NDJSON) sink — suitable for logs and machine
// consumption. One compact object per line.
class JsonSink : public ISink {
public:
    explicit JsonSink(std::ostream& out) : out_(out) {}
    void write(const SecurityEvent& event) override;

private:
    std::ostream& out_;
};

class SinkSet {
public:
    void add(std::unique_ptr<ISink> sink) { sinks_.push_back(std::move(sink)); }
    void write(const SecurityEvent& event) {
        for (auto& s : sinks_) s->write(event);
    }
    void flush() {
        for (auto& s : sinks_) s->flush();
    }

private:
    std::vector<std::unique_ptr<ISink>> sinks_;
};

}  // namespace fileguard
