# 02 — Threat Model

## Assets

| Asset | Protection goal |
|---|---|
| Protected files (e.g. `/protected/secret.txt`) | confidentiality; availability against disruption via legitimate processes |
| The policy | integrity; only authorized administrators may change it |
| Security events | integrity/availability of the audit trail; a monitored process must not be able to suppress its own events |
| The eBPF program and maps | integrity; must not be unloaded or mutated by monitored processes |

## Adversaries

1. **Unauthorized local process** — e.g. `cat`, `vim`, an arbitrary download.
   Motive: read the protected file. Capability: can execute as any UID that
   has DAC permission (or runs as root).
2. **Unexpected executable** — a binary installed after the policy was
   written. Capability: same as (1).
3. **Compromised application** — a *different* program that becomes malicious
   and tries to widen its access. Capability: arbitrary userspace execution
   under one UID.
4. **Insider / automated agent** — repeats attempts, races, uses symlinks and
   hard links, renames files.

## Attack classes the MVP defends against

- Unauthorized local processes opening protected files → **denied in the
  kernel** with `-EACCES`.
- Access via **symlink or hard link** to a protected file → denied, because
  identity is the inode, not the pathname.
- Access after **renaming** a protected file → still denied (inode identity).
- Attempts by **any UID**, including root — the LSM hook is evaluated for
  every open, independent of DAC.
- Attempts under **concurrency** — every request is evaluated independently.

## Explicitly OUT of scope (documented, not defended)

| Threat | Why out of scope |
|---|---|
| Compromised Linux kernel | root of trust is the kernel; no userspace tool survives it |
| Kernel-level malware / rootkits | same |
| Attacker with `CAP_BPF`/`CAP_SYS_ADMIN`/root who can unload the eBPF program or rewrite the maps | the program's lifetime and contents are admin-controlled |
| Malicious privileged administrator reconfiguring the host | an admin can always do anything |
| Hardware attacks, cold-boot, etc. | out of scope |
| Malicious *allowed* process (e.g. a compromised `backup-agent`) | the allow-list explicitly trusts it — that is the policy owner's decision |

## Assumptions

- The host kernel is trusted and provides a working eBPF LSM
  (`CONFIG_BPF_LSM`, BTF, ring buffer).
- The administrator/operator who loads policies is trusted.
- `backup-agent` (the allowed process) is trusted and is what it claims to be —
  see `05-policy-model.md` § identity levels for why this is a **weakness**
  of the Level-1 identity and how higher levels tighten it.

## Failure semantics

| Condition | Result |
|---|---|
| eBPF program fails to load | controller refuses to start; **fail-open** (nothing enforced) and loud error |
| Policy update fails | old userspace policy kept; kernel paused (fail-open window) during the bounded update |
| Controller exits | LSM program is detached → **fail-open** until restarted (documented; pinning is a hardening item) |
| Ring buffer full | decisions still enforced; events dropped (observability loss, not security loss) |

See `11-limitations.md` for the detailed fail-open vs fail-closed analysis.
