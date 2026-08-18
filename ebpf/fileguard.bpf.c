// SPDX-License-Identifier: GPL-2.0
//
// fileguard.bpf.c — eBPF FileGuard LSM enforcement program.
//
// Hooks: security_file_open (eBPF LSM). Every open(2)/openat(2) on the system
// passes through this program when it is attached.
//
// Decision flow (kept in lock-step with the userspace DecisionEngine):
//
//   enabled?  --NO--> return 0 (allow)
//     |
//   resolve opened file identity (major, minor, ino)
//     |
//   in protected map?  --NO--> return 0 (allow, normal Linux semantics)
//     |
//   resolve current process executable identity (exe_file inode)
//     |
//   explicit rule in rules map?
//     |        +-- YES -> apply rule action (ALLOW: 0 | DENY: -EACCES)
//     +--------+-- NO  -> DENY (default-deny for protected resources)
//
// Every decision on a protected resource is emitted as a compact event into
// the ring buffer. Enforcement does NOT depend on the event path: if the ring
// buffer is full the decision is still returned.
//
// CO-RE: all kernel struct field accesses use BPF_CORE_READ so the program is
// portable across kernel versions on hosts with BTF (CONFIG_DEBUG_INFO_BTF).
// vmlinux.h is generated from the target kernel by bpftool at build time.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "abi.h"

char LICENSE[] SEC("license") = "GPL";

/* errno.h is unavailable in the freestanding BPF build (-nostdinc); EACCES
 * is 13 on every Linux architecture. Used as the LSM hook return value to
 * deny opens ("Permission denied"). */
#ifndef EACCES
#define EACCES 13
#endif

/* ---------------- maps ---------------- */

/* Protected resources: membership test on FileId. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, fileguard_file_id_t);
    __type(value, fileguard_protected_val_t);
} fileguard_protected SEC(".maps");

/* Policy rules: (resource, process) -> decision. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, fileguard_rule_key_t);
    __type(value, fileguard_rule_val_t);
} fileguard_rules SEC(".maps");

/* Single-element config: version + enabled flag. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, fileguard_config_t);
} fileguard_config SEC(".maps");

/* Event ring buffer. */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} fileguard_events SEC(".maps");

/* ---------------- helpers ---------------- */

static __always_inline bool fg_enabled(void)
{
    __u32 zero = 0;
    fileguard_config_t *cfg = bpf_map_lookup_elem(&fileguard_config, &zero);
    return cfg && cfg->enabled;
}

/* (major, minor, ino) of a struct file, independent of dev_t encoding. */
static __always_inline void fg_file_id(struct file *f, fileguard_file_id_t *out)
{
    struct inode *inode = BPF_CORE_READ(f, f_inode);
    if (!inode)
        return;
    __u64 dev = BPF_CORE_READ(inode, i_sb, s_dev);
    out->dev_major = (__u32)(dev >> 20);
    out->dev_minor = (__u32)(dev & 0xfffff);
    out->ino = BPF_CORE_READ(inode, i_ino);
}

/*
 * Identity of the current process's executable image (the exe_file inode).
 * This is the Level-1 identity: pathname of the executable. Reaching it here
 * costs a few BPF_CORE_READs and requires BTF; on failure the caller treats
 * the process as UNKNOWN (fail-closed for protected resources).
 */
static __always_inline void fg_process_exe_id(fileguard_file_id_t *out)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct mm_struct *mm = BPF_CORE_READ(task, mm);
    struct file *exe;

    if (!mm)
        return;
    exe = BPF_CORE_READ(mm, exe_file);
    if (!exe)
        return;
    fg_file_id(exe, out);
}

/*
 * Compute the decision for (res, proc). If `ev` is non-NULL it is filled with
 * the action/reason/rule_id (the event was already reserved). Returns 0 to
 * allow, -EACCES to deny. This is the enforcement core.
 */
static __always_inline int fg_decision(const fileguard_file_id_t *res,
                                       const fileguard_file_id_t *proc,
                                       fileguard_event_t *ev)
{
    if (proc->ino == 0) {
        /* Cannot identify the process executable: fail closed. */
        if (ev) {
            ev->action = FG_ACTION_DENY;
            ev->reason = FG_REASON_UNKNOWN_PROCESS;
        }
        return -EACCES;
    }

    fileguard_rule_key_t key = {
        .res = *res,
        .proc = *proc,
    };
    fileguard_rule_val_t *rule = bpf_map_lookup_elem(&fileguard_rules, &key);
    if (rule) {
        if (ev) {
            ev->rule_id = rule->rule_id;
            ev->action = rule->action;
            ev->reason = FG_REASON_POLICY_RULE;
        }
        return rule->action == FG_ACTION_ALLOW ? 0 : -EACCES;
    }

    /* Protected resource with no matching rule: default DENY. */
    if (ev) {
        ev->action = FG_ACTION_DENY;
        ev->reason = FG_REASON_DEFAULT_DENY;
    }
    return -EACCES;
}

/* ---------------- LSM program ---------------- */

SEC("lsm/file_open")
int BPF_PROG(fg_file_open, struct file *file)
{
    fileguard_file_id_t res = {};
    fileguard_file_id_t proc = {};
    __u64 pidtgid = bpf_get_current_pid_tgid();
    __u64 uidgid = bpf_get_current_uid_gid();
    fileguard_event_t *ev;

    /* Config-gated: the controller can pause enforcement (fail-open) during
     * a policy update by clearing enabled. */
    if (!fg_enabled())
        return 0;

    fg_file_id(file, &res);
    if (!res.ino)
        return 0; /* cannot identify the opened file: allow */

    /* Not protected: normal Linux semantics apply. */
    if (!bpf_map_lookup_elem(&fileguard_protected, &res))
        return 0;

    /* Protected resource: reserve an event slot, then decide. */
    ev = bpf_ringbuf_reserve(&fileguard_events, sizeof(*ev), 0);
    if (ev) {
        ev->magic = FG_MAGIC;
        ev->timestamp_ns = bpf_ktime_get_ns();
        ev->pid = (__u32)pidtgid;
        ev->tgid = (__u32)(pidtgid >> 32);
        ev->uid = (__u32)uidgid;              /* helper: (gid << 32) | uid */
        ev->gid = (__u32)(uidgid >> 32);
        ev->res = res;
        ev->operation = FG_OP_OPEN;
        bpf_get_current_comm(ev->comm, sizeof(ev->comm));
    }

    fg_process_exe_id(&proc);

    {
        int ret = fg_decision(&res, &proc, ev);
        if (ev)
            bpf_ringbuf_submit(ev, 0);
        return ret;
    }
}
