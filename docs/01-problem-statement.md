# 01 — Problem Statement

## The problem

Linux systems protect files with **DAC** permissions (ownership, mode bits) and
may add **MAC** layers such as **SELinux** or **AppArmor**. These mechanisms
answer the question "who may touch this file?" in terms of users, groups and
system-wide labels.

They do not answer a narrower, application-specific question:

> "This one file `/protected/secret.txt` may only be *read* by the *backup
> agent*, and nothing else — no matter who is logged in or what else the
> system permits."

That decision is:

- **per-resource** — only a handful of files are special;
- **per-process** — authorization is keyed on *which program* is running
  (its executable image), not on which user launched it;
- **independent of the global MAC policy** — many environments run with
  SELinux disabled, AppArmor unconfined, or simply have never written a
  profile for this application;
- **programmable** — the policy should be loadable, versioned and testable
  like configuration, not a filesystem layout.

## What this project does

**eBPF FileGuard** adds a runtime file-access control layer that:

1. **Observes** every file-open on the system at the kernel security hook
   `security_file_open` (via eBPF LSM).
2. **Identifies** the opened resource and the originating process by the
   *filesystem identity* of the file and of the process's executable.
3. **Evaluates** the request against an allow-list policy that an
   administrator loads from JSON.
4. **Enforces** the decision — `ALLOW` or `DENY` (`-EACCES`) — *inside the
   kernel*, before the process can proceed.
5. **Emits a compact security event** for every decision on a protected
   resource, which a C++ userspace controller enriches, logs and streams.

## What this project is NOT

It is **not a replacement** for SELinux or AppArmor.

| | SELinux / AppArmor | eBPF FileGuard |
|---|---|---|
| Scope | whole-system MAC, labels, integrity | narrow, app-specific allow-lists |
| Maturity | decades of deployment, CVE coverage | educational/learning maturity |
| Policy model | rich type-enforcement / profiles | single (resource, process, op) rule per entry |
| Attacker resistance | hardened, designed against privileged attackers | see `08-security-model.md` and `11-limitations.md` |

FileGuard is most useful where those frameworks are **unavailable,
unconfigured, or need a complementary, programmable, application-specific
layer**. It deliberately offers a smaller, easier-to-reason-about security
surface.

## Why it matters

- **Default-deny** for protected resources shrinks the attack surface of a
  specific file: even a root shell running `cat` cannot open it.
- The decision happens **at the kernel security boundary** — a compromised
  or careless userspace process cannot "ignore" the denial.
- Security telemetry is produced **by the kernel itself**, so it cannot be
  suppressed by the very process being monitored.
- It demonstrates the full eBPF + modern C++ stack used by production
  security tooling (Falco, Tetragon, security products).
