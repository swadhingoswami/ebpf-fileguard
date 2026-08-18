#pragma once

#include <functional>
#include <string>
#include <vector>

#include "core_utils.hpp"
#include "file_id.hpp"
#include "policy.hpp"

namespace fileguard {

// A policy compiled to its flat, kernel-ready form. This is the exact payload
// the eBPF maps are populated with; it is deliberately free of any string
// paths so that nothing heavy has to cross the kernel boundary.
struct CompiledRule {
    uint32_t rule_id;          // index into the source Policy::rules() (1-based)
    FileId resource;
    FileId process;
    Operation operation = Operation::Open;
    Action action = Action::Allow;
};

struct CompiledPolicy {
    int32_t version = 0;
    std::vector<FileId> protected_resources;
    std::vector<CompiledRule> rules;
};

// Resolves a filesystem path to a FileId. The default implementation uses
// stat(2) (which follows symlinks — see docs/09-testing.md for the symlink
// discussion). Tests inject a fake resolver to avoid depending on real files.
using FileResolver =
    std::function<Result<FileId>(const std::string& /* path */)>;

// The default resolver: stat(2) with (major, minor, ino) extraction.
Result<FileId> resolve_path_with_stat(const std::string& path);

// Compiles a validated Policy into CompiledPolicy by resolving every path to
// a FileId. Resolution failures (missing files, permission errors) are
// surfaced as errors here — a policy that cannot be fully resolved is never
// installed.
//
// The inverse mapping (FileId -> configured path) lives in PathResolver and is
// used for event enrichment.
class PolicyCompiler {
public:
    PolicyCompiler() = default;
    explicit PolicyCompiler(FileResolver resolver) : resolver_(std::move(resolver)) {}

    Result<CompiledPolicy> compile(const Policy& policy) const;

private:
    FileResolver resolver_ = resolve_path_with_stat;
};

}  // namespace fileguard
