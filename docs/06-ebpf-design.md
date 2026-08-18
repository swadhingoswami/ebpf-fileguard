# 06 — eBPF Design

## Observation vs enforcement — a hard separation

Tracing mechanisms **observe**. They cannot reliably *stop* an operation:
a kprobe/tracepoint fires while the syscall is already underway, and
"fixing" the result or arguments afterwards is racy and fragile. **eBPF LSM**
is different: LSM hooks run *inside* the security decision path and their
return value (`0` or negative errno) is the decision.

| Mechanism | Observation | Enforcement | Kernel ≥ |
|---|---|---|---|
| tracepoints (`sys_enter_openat`, …) | ✔ rich, stable ABI | ✘ cannot reliably block | 4.7 |
| kprobes / kretprobes | ✔ any function | ✘ racy to block | 4.1 |
| fentry/fexit | ✔ fast, BTF-typed | ✘ same limitation | 5.5 |
| **eBPF LSM** | ✔ | ✔ **return value = decision** | 5.7 |
| uprobes | userspace only | ✘ | — |

**Choice for the MVP:** `SEC("lsm/file_open")` (the `security_file_open`
hook). It fires for every `open(2)`/`openat(2)` on the system, before the
file is opened, with the opened `struct file *` in hand. It gives both
observation and enforcement in one program.

## What is available at the hook

- `struct file *` → `f_inode->i_ino`, `i_sb->s_dev` → **opened file identity**.
- `bpf_get_current_pid_tgid()`, `bpf_get_current_uid_gid()`,
  `bpf_get_current_comm()` → actor metadata.
- `task->mm->exe_file` (via `BPF_CORE_READ`) → **process executable identity**.

## What we deliberately do NOT use

- **`bpf_d_path`** to obtain pathname strings in kernel. It has context
  restrictions across LSM hooks/kernel versions and encourages sending
  strings across the boundary. Instead we use **inode identity
  `(major, minor, ino)`**, computed in userspace at policy-install time from
  `stat(2)` and in kernel from `inode->i_ino` + `i_sb->s_dev`. No string
  ever crosses the ring buffer. (See `09-file-identity` notes and
  `11-limitations.md`.)
- **dev_t value comparison directly** — kernel `s_dev` and userland `st_dev`
  use different encodings on some platforms. Both sides derive
  `(major, minor)` (kernel: `dev>>20`, `dev&0xfffff`; userspace:
  `major()/minor()`) which match regardless of encoding.

## Program structure (`ebpf/fileguard.bpf.c`)

```
SEC("lsm/file_open") BPF_PROG(fg_file_open, struct file *file)
  ├─ fg_enabled()?   (config map)                 ── no ──► return 0
  ├─ fg_file_id(file) → (major, minor, ino)
  │     ino == 0 ? return 0                         (cannot identify → allow)
  ├─ in protected map?                              ── no ──► return 0
  ├─ reserve ringbuf event, fill header
  ├─ fg_process_exe_id() → current process exe
  │     unknown ? decision=DENY reason=UNKNOWN_PROCESS
  ├─ lookup rules[ (res, proc) ]
  │     hit  ? apply rule (ALLOW → 0 | DENY → -EACCES), reason=POLICY_RULE
  │     miss ? DENY, reason=DEFAULT_DENY
  └─ submit event, return decision
```

Key properties:

- **Enforcement never depends on the event path.** If the ring buffer is full
  (`bpf_ringbuf_reserve` fails) the decision is still computed and returned;
  only the event is dropped.
- **Default-deny lives in kernel**: protected resource + no rule ⇒ `-EACCES`.
- **Config-gated**: `config.enabled` lets the controller pause enforcement
  (fail-open) during a bounded policy-update window.
- **CO-RE**: every kernel field access uses `BPF_CORE_READ` against
  `vmlinux.h` generated from the running kernel, so the program is portable
  across kernel versions on BTF-enabled hosts.

## Maps

| Map | Type | Key | Value | Purpose |
|---|---|---|---|---|
| `fileguard_protected` | HASH | `fileguard_file_id_t` | marker | membership: is this file protected? |
| `fileguard_rules` | HASH | `{res, proc}` ids | `{rule_id, action, operation}` | explicit allow/deny rules |
| `fileguard_config` | ARRAY[1] | 0 | `{policy_version, enabled}` | update window + versioning |
| `fileguard_events` | RINGBUF (1 MiB) | — | `fileguard_event_t` | event transport |

Policy complexity (rule count) lives in the maps and userspace; the kernel
program is a couple of hash lookups.

## Verifier notes

- The program is **non-sleepable**; it uses only map lookups, ring buffer and
  `BPF_CORE_READ` — all safe in atomic context.
- `task->mm->exe_file` dereferences are allowed because
  `bpf_get_current_task()` returns a *trusted* `task_struct*`; NULL is
  handled (fail-closed: unknown process ⇒ deny).
- Return values: `0` or `-EACCES` (`EACCES` ⇒ "Permission denied" at the
  syscall), matching the demo expectations.

## Kernel version requirements (summary)

- **5.7** — eBPF LSM (`CONFIG_BPF_LSM`, `bpf` in `CONFIG_LSM`).
- **5.8** — BPF ring buffer.
- **5.19+** — recommended; LSM programs with typed-arg `BPF_PROG` handling.
- **6.x** — primary test target.
- Always requires **BTF** (`CONFIG_DEBUG_INFO_BTF`) for CO-RE and `vmlinux.h`.

The kernel is the enforcement authority; the controller only programs it.
See `11-limitations.md` for what this means when the program is unloaded.
