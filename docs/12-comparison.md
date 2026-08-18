# 12 — Comparison with Existing Mechanisms

Accurate, balanced comparison. FileGuard is a *narrow, application-specific,
kernel-enforced allow-list*; the table shows where it fits and where it does
not.

## Linux DAC

- **Model**: ownership (uid/gid), mode bits, ACLs, capabilities. `open()`
  checks the *current process's credentials* against the *file's* metadata.
- **Strengths**: ubiquitous, fast, enforced by the kernel, works with zero
  configuration.
- **Limitations for our problem**:
  - Authorization is **per-user**, not **per-program**. `cat` run by an
    authorized user is authorized; `vim` by the same user too. FileGuard is
    per-executable: the *program* must be the allowed one.
  - **Root bypasses DAC** (`CAP_DAC_OVERRIDE`). A root shell can read any
    mode-0400 file. FileGuard denies at the LSM hook regardless of UID.
  - No decision logging/audit trail of *attempts*.
- **Relationship**: FileGuard **complements** DAC; DAC remains the
  first line, FileGuard adds a program-level allow-list on top.

## SELinux

- **Model**: MAC with labels (`user:role:type`) and a type-enforcement policy
  written in a dedicated language; default-deny, everything explicitly
  allowed; MLS/MCS support; enforce on many hooks.
- **Strengths**: decades of hardening, covers the whole system, rich policy,
  full labeling, strong against privilege escalation.
- **Limitations**:
  - **Requires a system-wide policy and labeling discipline**; writing and
    maintaining policy is expensive; misconfiguration can lock out the admin.
  - Often **not enabled** on general-purpose hosts, or not tuned for a single
    application.
  - Policy is compiled at boot; runtime tweaks need tooling (semanage) and
    the policy language, not plain JSON.
- **Relationship**: FileGuard is **not** a substitute for SELinux's
  system-wide MAC. It is a *small, programmable, application-scoped layer*
  useful where SELinux is off or unconcerned with one file. Where SELinux is
  deployed properly, it already does more.

## AppArmor

- **Model**: path/executable-based profiles ("program X may read Y"), default
  deny within a profile, learning mode, easy to read. Kernel-enforced via
  LSM (`security_file_open` among others).
- **Strengths**: readable profiles, per-application confinement, enforced in
  kernel, no relabeling.
- **Limitations**:
  - **Not always loaded/configured**; many distributions ship with
    `apparmor_parser` but no profile for arbitrary apps.
  - Profiles are system-wide configuration, not data-driven runtime policy;
  - Only one active AppArmor policy set at a time.
- **Relationship**: conceptually closest to FileGuard. The differences are
  *delivery*: FileGuard's policy is **JSON, validated, versioned, hot-loaded
  over a socket** and produces **structured audit events** — it is a
  programmable *runtime* control, whereas AppArmor is a *system policy*
  facility. FileGuard does not replace AppArmor's maturity or breadth.

## auditd

- **Model**: kernel audit framework; records syscalls/security events
  (including `security_file_open` failures) to logs. **Observation only** —
  it does not decide.
- **Strengths**: rich, trusted kernel-level audit trail; standard tooling.
- **Limitations**: high overhead at scale; complex rule language; no
  *enforcement* — an attacker who can read the file will still read it and
  merely be logged.
- **Relationship**: FileGuard *both* observes (events) and enforces. An
  operator could correlate FileGuard events with auditd; FileGuard's events
  are structured and include the decision and policy-rule identity.

## strace

- **Model**: ptrace-based userspace syscall tracing; shows what a process
  *did*. Debugging/tracing only.
- **Limitations**:
  - Not an enforcement mechanism — cannot stop a syscall.
  - Userspace observation can be **detected and evaded**; ptrace is
    restricted for security-sensitive processes.
  - High overhead; not designed for production monitoring at scale.
- **Relationship**: FileGuard's kernel hook sees the same events *without*
  ptrace, and *enforces*; strace is the debugger's tool, FileGuard is the
  security controller's.

## inotify

- **Model**: filesystem notifications (open/access/close events) delivered to
  a watching process via an fd.
- **Strengths**: simple API, good for file-watchers, sync, indexing.
- **Limitations for security**:
  - `IN_OPEN` fires **after** the open — observation only, cannot deny.
  - **No process identity** (inotify events do not reliably say *who*);
    no uid/gid, no exe.
  - Per-mount, global watch is expensive at scale; events can be dropped.
  - **Pathname-based** and racy; not suited as a security boundary.
- **Relationship**: FileGuard is a *security* mechanism (decision + identity
  + enforcement); inotify is a *notification* mechanism. They do not overlap.

## Summary matrix

| | DAC | SELinux | AppArmor | auditd | strace | inotify | FileGuard |
|---|---|---|---|---|---|---|---|
| Enforced in kernel | ✔ | ✔ | ✔ | ✘ | ✘ | ✘ | ✔ |
| Per-process (exe) decisions | ✘ | ~ | ✔ | ✘ | ✘ | ✘ | ✔ |
| Programmable/versioned runtime policy | ✘ | limited | ✘ | ✘ | — | — | ✔ |
| Default-deny for a subset | ✘ | ✔ (global) | ✔ (profile) | ✘ | ✘ | ✘ | ✔ (protected) |
| Structured security events | ✘ | ✘ | ✘ | ✔ | ✘ | partial | ✔ |
| Root cannot trivially bypass | ✘ | ✔ | ✔ | — | ✘ | — | ✔* |
| System-wide breadth | ✔ | ✔✔ | ✔✔ | ✔ | ✘ | ✘ | ✘ (narrow) |

\* For the documented threat model (`02-threat-model`); a privileged attacker
with CAP_BPF is out of scope.

## Bottom line

FileGuard occupies the niche "**default-deny, per-executable, hot-reloadable
file access control with structured telemetry**" — small enough to reason
about, strict enough to protect specific files, and honest about being neither
a MAC system nor a replacement for auditd.
