#include "fileguard/policy_compiler.hpp"

#include <cerrno>
#include <cstring>

#include <sys/stat.h>
#include <sys/types.h>

#if defined(__linux__)
#include <sys/sysmacros.h>
#endif

namespace fileguard {

Result<FileId> resolve_path_with_stat(const std::string& path) {
    struct stat st {};
    if (::stat(path.c_str(), &st) != 0) {
        const int e = errno;
        return err("cannot stat '" + path + "': " + std::string(strerror(e)));
    }
    FileId id;
#if defined(__APPLE__)
    // Apple's dev_t is signed int32; the major()/minor() macros internally
    // re-cast it and trip -Wsign-conversion. Passing an unsigned copy keeps
    // the macros' encoding intact without the diagnostic.
    const auto dev = static_cast<unsigned>(st.st_dev);
    id.dev_major = static_cast<uint32_t>(major(dev));
    id.dev_minor = static_cast<uint32_t>(minor(dev));
#else
    id.dev_major = static_cast<uint32_t>(major(st.st_dev));
    id.dev_minor = static_cast<uint32_t>(minor(st.st_dev));
#endif
    id.ino = static_cast<uint64_t>(st.st_ino);
    return id;
}

Result<CompiledPolicy> PolicyCompiler::compile(const Policy& policy) const {
    if (auto v = policy.validate(); !v) {
        return err(v.error());
    }

    CompiledPolicy compiled;
    compiled.version = policy.version();

    // Resolve every protected resource once; the inode-based identity is what
    // the kernel will match against at security_file_open time.
    std::vector<std::pair<std::string, FileId>> resolved_resources;
    resolved_resources.reserve(policy.protected_resources().size());
    for (const auto& res : policy.protected_resources()) {
        auto id = resolver_(res.path);
        if (!id) {
            return err(id.error());
        }
        if (!id->valid()) {
            return err("resolved zero inode for protected resource '" + res.path + "'");
        }
        compiled.protected_resources.push_back(*id);
        resolved_resources.emplace_back(res.path, *id);
    }

    compiled.rules.reserve(policy.rules().size());
    uint32_t rule_index = 1;
    for (const auto& rule : policy.rules()) {
        // Reuse the already-resolved resource id (paths are validated to be
        // protected, so the lookup always succeeds).
        const FileId* res_id = nullptr;
        for (const auto& [path, id] : resolved_resources) {
            if (path == rule.resource.path) {
                res_id = &id;
                break;
            }
        }
        if (res_id == nullptr) {
            return err("internal error: unresolved protected resource for rule '" +
                       rule.id + "'");
        }

        auto proc_id = resolver_(rule.process.value);
        if (!proc_id) {
            return err(proc_id.error());
        }
        if (!proc_id->valid()) {
            return err("resolved zero inode for process '" + rule.process.value + "'");
        }

        CompiledRule c;
        c.rule_id = rule_index++;
        c.resource = *res_id;
        c.process = *proc_id;
        c.operation = rule.operation;
        c.action = rule.action;
        compiled.rules.push_back(c);
    }

    return compiled;
}

}  // namespace fileguard
