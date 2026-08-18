# 11 — Limitations

Honest statement of what this project can and cannot do, and under what
conditions the security properties hold.

## Identity

- **Level-1 identity (executable path → inode) is the weakest link.**
  - Replacing the executable changes its inode ⇒ identity changes. The MVP
    treats that as "different process" (deny until policy reload) — safe, but
    it means updates require a policy reload.
  - Scripts identify as their **interpreter** (the kernel's `exe_file`), not
    the script — policy must target `/bin/sh`, `/usr/bin/python3`, etc.
  - `argv[0]`/`comm` are spoofable and are used only for display.
- **No PID-based identity** (deliberate): PIDs are reused; the kernel exe
  inode is stable across the process lifetime.

## Resource identity (`(major, minor, ino)`)

| Case | Behavior | Note |
|---|---|---|
| symlink to protected file | denied | inode identity follows the target |
| hard link to protected file | denied | same inode |
| rename of protected file | still protected | inode follows the file |
| **protected file replaced (new inode)** | **not protected** | TOCTOU at install time; detectable, not auto-handled |
| bind mount | protected | same inode/superblock |
| deleted-but-open file | inode persists; new opens via that path fail at lookup | out of scope |
| different filesystem | `stat` resolves the actual fs | per-mount `s_dev` |
| overlayfs / containers / mount namespaces | identity is per-superblock | see "Containers" |

## Enforcement gaps

- **MVP enforces opens only.** Reads of an already-open file descriptor are
  not re-policed (a `security_file_permission`/`file_receive` program would
  extend this). `fcntl(F_SETFL)`/dup'd fds inherit the original decision.
- **Controller exit ⇒ fail-open.** The LSM program is kept alive by the
  controller's link fd. When the controller stops or crashes, the program is
  detached and the host reverts to unprotected until a controller returns.
  Fix: pin link + maps to bpffs (Phase 12). This is a **default-deny policy
  enforced by a default-fail-open deployment**; the two must not be confused.
- **Privileged attacker can unload/reconfigure** — out of model
  (`02-threat-model`).

## Kernel dependency

- Requires Linux ≥ 5.7 (eBPF LSM), ≥ 5.8 (ring buffer), BTF for CO-RE,
  `bpf` in the `CONFIG_LSM` order, and `CAP_BPF`/`CAP_SYS_ADMIN` at load.
- Field offsets are resolved with CO-RE against the *running* kernel's BTF;
  a program compiled against a different kernel must be rebuilt (the build
  regenerates `vmlinux.h` automatically).
- `task->mm->exe_file` is read without holding `mmap_lock`; the read is safe
  for the current task but the value could transiently be NULL — handled by
  fail-closed deny with reason `UNKNOWN_PROCESS`.

## Containers / namespaces

- The controller and the LSM program see one kernel. `s_dev` is per
  superblock/mount; two containers sharing an overlayfs share identities.
- A process inside a mount namespace sees different paths, but the kernel
  computes the same inode identity, so policy set from the host applies.
- Per-container policies (cgroup-aware identity) are a Level-3/4 evolution,
  not in the MVP.

## Availability / DoS

- A flood of opens on protected files fills the 1 MiB ring buffer; events
  are dropped (counted) but **enforcement continues** — decisions are
  computed independently of event delivery.
- The SPSC core queue is bounded: under sustained load the poller stalls
  (backpressure) rather than growing memory.
- A malicious **allowed** process can open the protected file as often as it
  likes — allow-list trusts it by design.

## Configuration security

- Policy files are read by `root`; the daemon expects them to be root-owned,
  non-world-writable (integration test checks the mode). The socket is
  created `0600` in a `0700` runtime directory.
- There is **no authentication** on the control socket in the MVP — anyone
  who can reach the socket file can query/load policy. The socket lives in a
  `0700` root-owned directory, which is the only protection; hardening =
  SO_PEERCRED checks.

## Not audited / not claimed

- No formal verification of the eBPF program's logic (beyond the verifier).
- No guarantee against a compromised kernel.
- `std::expected`-based error handling means all failure paths are explicit,
  but the *policy semantics* are only as good as the validation code.
