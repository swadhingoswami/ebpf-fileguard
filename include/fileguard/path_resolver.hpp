#pragma once

#include <string>
#include <unordered_map>

#include "file_id.hpp"

namespace fileguard {

// FileId must be hashable for std::unordered_map.
struct FileIdHash {
    size_t operator()(FileId id) const noexcept {
        size_t h = static_cast<size_t>(id.ino);
        h ^= static_cast<size_t>(id.dev_major) << 20;
        h ^= static_cast<size_t>(id.dev_minor) << 8;
        return h;
    }
};

// Reverse identity resolver used for event enrichment.
//
// The kernel only ever sends (dev, ino) pairs across the ring buffer. This
// object maps those pairs back to the human-readable paths that were used in
// the installed policy, so events can be rendered as:
//
//     process=/usr/local/bin/backup-agent  resource=/protected/secret.txt
//
// It is built from a compiled policy and is immutable afterwards, so it can be
// shared across threads without locks. Unresolved FileIds render as
// "dev:ino:ino" (e.g. "1:2:12345").
class PathResolver {
public:
    void add(FileId id, std::string path);
    // Returns the configured path, or "major:minor:ino" for unknown ids.
    [[nodiscard]] std::string resolve(FileId id) const;

    [[nodiscard]] size_t size() const { return map_.size(); }

private:
    std::unordered_map<FileId, std::string, FileIdHash> map_;
};

}  // namespace fileguard
