// Linux-only implementation of the eBPF LSM enforcement backend.
// Compiled exclusively when ENABLE_EBPF=ON (see ebpf/CMakeLists.txt).

#include "fileguard/ebpf_manager.hpp"

#if defined(__linux__)

#include <cerrno>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "abi.h"
#include "fileguard.skel.h"

namespace fileguard {

namespace {

std::string bpf_err(int e) {
    return std::string(" (errno=") + std::to_string(e) + ": " + std::strerror(e) + ")";
}

// The opaque void* members in ebpf_manager.hpp hide the libbpf types from the
// portable header; recover the concrete pointers here (C++ has no implicit
// void* -> T* conversion).
struct fileguard_bpf* skel_of(void* p) { return static_cast<struct fileguard_bpf*>(p); }
struct ring_buffer* ring_of(void* p) { return static_cast<struct ring_buffer*>(p); }

}  // namespace

LinuxEBPFEnforcer::LinuxEBPFEnforcer(EnforcerConfig cfg) : cfg_(std::move(cfg)) {}

LinuxEBPFEnforcer::~LinuxEBPFEnforcer() {
    (void)detach();
}

ResultVoid LinuxEBPFEnforcer::load() {
    std::lock_guard<std::mutex> lock(state_mu_);
    if (skel_) return err("enforcer already loaded");

    struct fileguard_bpf* skel = fileguard_bpf__open();
    if (!skel) {
        return err("fileguard_bpf__open failed: " + bpf_err(errno));
    }

    if (cfg_.map_entries > 0) {
        bpf_map__set_max_entries(skel->maps.fileguard_protected, cfg_.map_entries);
        bpf_map__set_max_entries(skel->maps.fileguard_rules, cfg_.map_entries);
    }
    if (cfg_.ringbuf_bytes > 0) {
        bpf_map__set_max_entries(skel->maps.fileguard_events, cfg_.ringbuf_bytes);
    }

    if (fileguard_bpf__load(skel)) {
        const std::string msg = bpf_err(errno);
        fileguard_bpf__destroy(skel);
        return err("fileguard_bpf__load failed" + msg +
                   " — check the verifier log above; the kernel needs "
                   "CONFIG_BPF=y, CONFIG_BPF_LSM=y, CONFIG_BPF_RINGBUF=y, "
                   "CONFIG_DEBUG_INFO_BTF=y and CAP_BPF/CAP_SYS_ADMIN.");
    }

    if (fileguard_bpf__attach(skel)) {
        const std::string msg = bpf_err(errno);
        fileguard_bpf__destroy(skel);
        return err("fileguard_bpf__attach failed" + msg +
                   " — check that the kernel was booted with the bpf LSM "
                   "in the CONFIG_LSM=... ordering.");
    }

    ring_ = ring_buffer__new(bpf_map__fd(skel->maps.fileguard_events),
                             &LinuxEBPFEnforcer::ring_callback, this, nullptr);
    if (!ring_) {
        const std::string msg = bpf_err(errno);
        fileguard_bpf__destroy(skel);
        return err("ring_buffer__new failed" + msg);
    }

    skel_ = skel;
    status_.attached = true;
    status_.enforcing = false;
    status_.backend = "ebpf-lsm";
    status_.detail = "LSM hook security_file_open attached";
    return ok_v();
}

ResultVoid LinuxEBPFEnforcer::clear_map(void* obj, const char* map_name) {
    auto* skel = static_cast<struct fileguard_bpf*>(obj);
    int fd = -1;
    if (std::strcmp(map_name, FG_MAP_PROTECTED) == 0) {
        fd = bpf_map__fd(skel->maps.fileguard_protected);
    } else if (std::strcmp(map_name, FG_MAP_RULES) == 0) {
        fd = bpf_map__fd(skel->maps.fileguard_rules);
    } else {
        return err("clear_map: unknown map '" + std::string(map_name) + "'");
    }
    if (fd < 0) {
        return err("clear_map: cannot get fd for '" + std::string(map_name) + "'");
    }

    std::vector<unsigned char> key(64, 0);
    std::vector<unsigned char> next_key(64, 0);
    int res = bpf_map_get_next_key(fd, nullptr, key.data());
    while (res == 0) {
        bpf_map_delete_elem(fd, key.data());
        res = bpf_map_get_next_key(fd, key.data(), next_key.data());
        if (res == 0) {
            std::copy(next_key.begin(), next_key.end(), key.begin());
        }
    }
    if (res != 0 && res != -ENOENT) {
        return err("clear_map: iteration failed for '" + std::string(map_name) +
                   "'" + bpf_err(errno));
    }
    return ok_v();
}

ResultVoid LinuxEBPFEnforcer::apply_policy(const CompiledPolicy& policy) {
    std::lock_guard<std::mutex> lock(state_mu_);
    if (!skel_) return err("enforcer not loaded");

    const int cfg_fd = bpf_map__fd(skel_of(skel_)->maps.fileguard_config);
    const int prot_fd = bpf_map__fd(skel_of(skel_)->maps.fileguard_protected);
    const int rules_fd = bpf_map__fd(skel_of(skel_)->maps.fileguard_rules);

    // Phase 1: pause enforcement (fail-open window) so a half-updated map
    // never makes a wrong decision. The window is bounded by the map writes.
    __u32 zero = 0;
    fileguard_config_t cfg{};
    cfg.enabled = 0;
    if (bpf_map_update_elem(cfg_fd, &zero, &cfg, BPF_ANY) < 0) {
        return err("cannot pause enforcement (config map)" + bpf_err(errno));
    }

    // Phase 2: replace the map contents.
    if (auto e = clear_map(skel_, FG_MAP_PROTECTED); !e) return e;
    if (auto e = clear_map(skel_, FG_MAP_RULES); !e) return e;

    for (const auto& id : policy.protected_resources) {
        const fileguard_file_id_t key = id.to_abi();
        fileguard_protected_val_t val{};
        if (bpf_map_update_elem(prot_fd, &key, &val, BPF_NOEXIST) < 0 &&
            errno != EEXIST) {
            return err("cannot insert protected resource" + bpf_err(errno));
        }
    }
    for (const auto& rule : policy.rules) {
        fileguard_rule_key_t key{};
        key.res = rule.resource.to_abi();
        key.proc = rule.process.to_abi();
        fileguard_rule_val_t val{};
        val.rule_id = rule.rule_id;
        val.action = static_cast<uint32_t>(rule.action);
        val.operation = static_cast<uint32_t>(rule.operation);
        if (bpf_map_update_elem(rules_fd, &key, &val, BPF_NOEXIST) < 0 &&
            errno != EEXIST) {
            return err("cannot insert policy rule" + bpf_err(errno));
        }
    }

    // Phase 3: enable enforcement with the new policy version.
    cfg.enabled = 1;
    cfg.policy_version = static_cast<uint32_t>(policy.version);
    if (bpf_map_update_elem(cfg_fd, &zero, &cfg, BPF_ANY) < 0) {
        return err("cannot enable policy (config map)" + bpf_err(errno));
    }

    status_.policy_version = policy.version;
    status_.protected_count = policy.protected_resources.size();
    status_.rule_count = policy.rules.size();
    status_.enforcing = true;
    return ok_v();
}

EnforcerStatus LinuxEBPFEnforcer::status() const {
    std::lock_guard<std::mutex> lock(state_mu_);
    EnforcerStatus s = status_;
    if (skel_) {
        __u32 zero = 0;
        fileguard_config_t cfg{};
        if (bpf_map_lookup_elem(bpf_map__fd(skel_of(skel_)->maps.fileguard_config),
                                &zero, &cfg) == 0) {
            s.enforcing = cfg.enabled != 0;
            s.policy_version = static_cast<int32_t>(cfg.policy_version);
        }
    }
    return s;
}

void LinuxEBPFEnforcer::run(std::stop_token stop) {
    if (!ring_) return;
    while (!stop.stop_requested()) {
        const int n = ring_buffer__poll(ring_of(ring_), 100);
        if (n < 0) {
            std::lock_guard<std::mutex> lock(state_mu_);
            status_.detail = "ring buffer poll error" + bpf_err(errno);
            break;
        }
    }
}

ResultVoid LinuxEBPFEnforcer::detach() {
    std::lock_guard<std::mutex> lock(state_mu_);
    if (ring_) {
        ring_buffer__free(ring_of(ring_));
        ring_ = nullptr;
    }
    if (skel_) {
        fileguard_bpf__detach(skel_of(skel_));
        fileguard_bpf__destroy(skel_of(skel_));
        skel_ = nullptr;
    }
    status_.attached = false;
    status_.enforcing = false;
    status_.policy_version = 0;
    status_.detail = "detached: enforcement removed (fail-open)";
    return ok_v();
}

int LinuxEBPFEnforcer::ring_callback(void* ctx, void* data, size_t size) {
    auto* self = static_cast<LinuxEBPFEnforcer*>(ctx);
    if (!data || size != sizeof(fileguard_event_t)) {
        std::lock_guard<std::mutex> lock(self->state_mu_);
        self->status_.detail = "malformed ring buffer record";
        return 0;
    }
    const auto* e = static_cast<const fileguard_event_t*>(data);
    if (e->magic != FG_MAGIC) {
        std::lock_guard<std::mutex> lock(self->state_mu_);
        self->status_.detail = "ring buffer magic mismatch";
        return 0;
    }

    RawEvent raw;
    raw.timestamp_ns = e->timestamp_ns;
    raw.pid = e->pid;
    raw.tgid = e->tgid;
    raw.uid = e->uid;
    raw.gid = e->gid;
    raw.resource = FileId::from_abi(e->res);
    raw.process = FileId::from_abi(e->proc);
    raw.rule_id = e->rule_id;
    raw.operation = static_cast<Operation>(e->operation);
    raw.action = static_cast<Action>(e->action);
    raw.reason = static_cast<Reason>(e->reason);
    const size_t comm_len = strnlen(e->comm, FG_MAX_COMM);
    raw.comm.assign(e->comm, comm_len);

    if (self->cfg_.on_event) {
        self->cfg_.on_event(std::move(raw));
    }
    return 0;
}

}  // namespace fileguard

#endif  // __linux__
