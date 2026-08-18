#pragma once

#include <cstdint>
#include <string>

#include "abi.h"

namespace fileguard {

// Compile-time check that the C++ FileId matches the ABI layout.
static_assert(sizeof(::fileguard_file_id_t) == sizeof(uint64_t) + sizeof(uint32_t) * 2,
              "ABI file id layout changed");

// Identity of a file on the local filesystem, expressed as (device major,
// device minor, inode). Both kernel and userland can derive these three
// numbers without depending on dev_t encodings (see abi.h).
//
// (major, minor, ino) is NOT a globally unique file identity: it is local to
// a host and, on some filesystems, to a mount/overlay. Within one host it is
// stable across path renames and hard links, which is what the enforcement
// logic needs. See docs/11-limitations.md.
struct FileId {
    uint32_t dev_major = 0;
    uint32_t dev_minor = 0;
    uint64_t ino = 0;

    [[nodiscard]] bool operator==(const FileId& other) const noexcept {
        return dev_major == other.dev_major && dev_minor == other.dev_minor &&
               ino == other.ino;
    }
    [[nodiscard]] bool operator!=(const FileId& other) const noexcept {
        return !(*this == other);
    }
    [[nodiscard]] bool operator<(const FileId& other) const noexcept {
        if (dev_major != other.dev_major) return dev_major < other.dev_major;
        if (dev_minor != other.dev_minor) return dev_minor < other.dev_minor;
        return ino < other.ino;
    }

    [[nodiscard]] bool valid() const noexcept { return ino != 0; }

    [[nodiscard]] std::string to_string() const {
        return std::to_string(dev_major) + ":" + std::to_string(dev_minor) + ":" +
               std::to_string(ino);
    }

    [[nodiscard]] ::fileguard_file_id_t to_abi() const noexcept {
        ::fileguard_file_id_t id{};
        id.dev_major = dev_major;
        id.dev_minor = dev_minor;
        id.ino = ino;
        return id;
    }

    static FileId from_abi(const ::fileguard_file_id_t& id) noexcept {
        FileId f;
        f.dev_major = id.dev_major;
        f.dev_minor = id.dev_minor;
        f.ino = id.ino;
        return f;
    }
};

}  // namespace fileguard
