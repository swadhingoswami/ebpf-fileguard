// fileguard_abi.h — shared ABI between the eBPF kernel program and the
// userspace controller.
//
// This header is C and C++ compatible. The eBPF program includes it directly;
// the userspace C++ code includes it via <fileguard/abi.h>. Keep this small:
// everything here crosses the kernel/userspace boundary.
//
// Conventions
// -----------
// * Map names and the event record layout below are part of the ABI.
// * The event record is deliberately compact; heavy fields (paths, full
//   identities) are enriched in userspace, never transported here.
#ifndef FILEGUARD_ABI_H
#define FILEGUARD_ABI_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FG_MAX_COMM 16          /* matches TASK_COMM_LEN on Linux */
#define FG_MAGIC 0x46474152u    /* 'FGAR' — sanity tag for ringbuf records */

/* Map names (keep in sync with the eBPF program and userspace). */
#define FG_MAP_PROTECTED "fileguard_protected"
#define FG_MAP_RULES     "fileguard_rules"
#define FG_MAP_CONFIG    "fileguard_config"
#define FG_MAP_EVENTS    "fileguard_events"

/* Action codes. */
enum {
    FG_ACTION_ALLOW = 0,
    FG_ACTION_DENY  = 1,
};

/* Operation codes (only OPEN is supported in the MVP). */
enum {
    FG_OP_OPEN = 1,
};

/* Reason codes — why a decision was made. */
enum {
    FG_REASON_POLICY_RULE      = 1,  /* an explicit rule matched */
    FG_REASON_DEFAULT_DENY     = 2,  /* protected, no allow rule matched */
    FG_REASON_UNKNOWN_PROCESS  = 3,  /* protected but process exe unidentifiable */
    FG_REASON_UNKNOWN_RESOURCE = 4,  /* resource inode not resolvable */
};

/*
 * File identity.
 *
 * We deliberately do NOT use a single `dev_t`. The kernel's internal s_dev
 * encoding differs from the userland st_dev encoding on some systems. Both
 * sides can compute (major, minor) independently and cheaply:
 *   - kernel: MAJOR()/MINOR() on s_dev  ==  dev>>20 / dev&0xfffff
 *   - userland: major()/minor() from st_dev (glibc, encoding-aware)
 * This keeps the comparison correct regardless of the dev_t encoding in use.
 */
typedef struct {
    uint32_t dev_major;
    uint32_t dev_minor;
    uint64_t ino;
} fileguard_file_id_t;

/* Key for a (resource, process) policy rule in the rules hash map. */
typedef struct {
    fileguard_file_id_t res;
    fileguard_file_id_t proc;
} fileguard_rule_key_t;

/* Value for a policy rule. */
typedef struct {
    uint32_t rule_id;
    uint32_t action;     /* FG_ACTION_* */
    uint32_t operation;  /* FG_OP_* */
    uint32_t reserved;
} fileguard_rule_val_t;

/* Value for the protected-resources hash map (membership test only). */
typedef struct {
    uint8_t reserved;    /* non-NULL presence in the map is what matters */
} fileguard_protected_val_t;

/* Single-element config array map. */
typedef struct {
    uint32_t policy_version;
    uint32_t enabled;    /* 0 = pass-through (fail-open), 1 = enforcing */
    uint32_t reserved[2];
} fileguard_config_t;

/* Ringbuf event record — keep small and aligned. */
typedef struct {
    uint32_t magic;                 /* FG_MAGIC */
    uint64_t timestamp_ns;          /* bpf_ktime_get_ns() */
    uint32_t pid;                   /* thread id (kernel view) */
    uint32_t tgid;                  /* process id (kernel view) */
    uint32_t uid;
    uint32_t gid;
    fileguard_file_id_t res;        /* opened file */
    fileguard_file_id_t proc;       /* opening process executable */
    uint32_t rule_id;
    uint8_t  operation;             /* FG_OP_* */
    uint8_t  action;                /* FG_ACTION_* */
    uint8_t  reason;                /* FG_REASON_* */
    uint8_t  pad;
    char     comm[FG_MAX_COMM];
} fileguard_event_t;

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* FILEGUARD_ABI_H */
