// fileguard_abi.h — shared ABI between the eBPF kernel program and the
// userspace controller.
//
// This header is C and C++ compatible AND intentionally does not include any
// standard library header: it is consumed by the eBPF program, which compiles
// in a freestanding, libc-less environment (-target bpf). Fixed-width types
// are defined locally with primitives whose sizes are stable on every
// supported target (x86_64, arm64, s390x, riscv64, macOS): `unsigned int` is
// 32-bit and `unsigned long long` is 64-bit everywhere.
//
// Conventions
// -----------
// * Map names and the event record layout below are part of the ABI.
// * The event record is deliberately compact; heavy fields (paths, full
//   identities) are enriched in userspace, never transported here.
#ifndef FILEGUARD_ABI_H
#define FILEGUARD_ABI_H

/* Fixed-width types without <stdint.h> (see above). */
typedef unsigned char      fg_u8;
typedef unsigned short     fg_u16;
typedef unsigned int       fg_u32;
typedef unsigned long long fg_u64;

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
    fg_u32 dev_major;
    fg_u32 dev_minor;
    fg_u64 ino;
} fileguard_file_id_t;

/* Key for a (resource, process) policy rule in the rules hash map. */
typedef struct {
    fileguard_file_id_t res;
    fileguard_file_id_t proc;
} fileguard_rule_key_t;

/* Value for a policy rule. */
typedef struct {
    fg_u32 rule_id;
    fg_u32 action;     /* FG_ACTION_* */
    fg_u32 operation;  /* FG_OP_* */
    fg_u32 reserved;
} fileguard_rule_val_t;

/* Value for the protected-resources hash map (membership test only). */
typedef struct {
    fg_u8 reserved;    /* non-NULL presence in the map is what matters */
} fileguard_protected_val_t;

/* Single-element config array map. */
typedef struct {
    fg_u32 policy_version;
    fg_u32 enabled;    /* 0 = pass-through (fail-open), 1 = enforcing */
    fg_u32 reserved[2];
} fileguard_config_t;

/* Ringbuf event record — keep small and aligned. */
typedef struct {
    fg_u32 magic;                 /* FG_MAGIC */
    fg_u64 timestamp_ns;          /* bpf_ktime_get_ns() */
    fg_u32 pid;                   /* thread id (kernel view) */
    fg_u32 tgid;                  /* process id (kernel view) */
    fg_u32 uid;
    fg_u32 gid;
    fileguard_file_id_t res;      /* opened file */
    fileguard_file_id_t proc;     /* opening process executable */
    fg_u32 rule_id;
    fg_u8  operation;             /* FG_OP_* */
    fg_u8  action;                /* FG_ACTION_* */
    fg_u8  reason;                /* FG_REASON_* */
    fg_u8  pad;
    char   comm[FG_MAX_COMM];
} fileguard_event_t;

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* FILEGUARD_ABI_H */
