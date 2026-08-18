# 03 — Requirements

## Functional requirements (MVP)

1. Protect **one file** configured as a protected resource.
2. Authorize **one executable** by absolute path (`exe_path` identity).
3. Enforce the **OPEN** operation (open for reading).
4. **Default-deny** for protected resources: no matching allow rule ⇒ `DENY`.
5. An **unprotected** file is unaffected (normal Linux semantics).
6. Generate a **security event** for every decision on a protected resource
   (allow and deny).
7. A **C++ userspace controller** consumes, enriches and logs events.
8. Policy is **loaded from JSON configuration**, validated before install.
9. **Clean startup and shutdown** (attach/detach, thread join, socket cleanup).
10. Control plane via a CLI (`guardctl`) with: `status`, `policy validate`,
    `policy load`, `policy list`, `events`, `stop`.

## Non-functional requirements

- **Portable core**: policy parsing, decision logic and the controller build
  and test on macOS and Linux. The enforcement backend (eBPF LSM) is Linux-only
  and cleanly abstracted behind `IEnforcer`.
- **Concurrency-safe**: correct under concurrent events, policy reloads,
  logging and shutdown (see `07-cpp-design.md`).
- **No policy install half-states**: a policy that fails validation or whose
  paths cannot be resolved is rejected before anything is touched.
- **Explicit errors everywhere**; `std::expected` is the error channel; no
  swallowed failures.
- **Kernel-side code minimal and verifier-clean** (see `06-ebpf-design.md`).

## Kernel requirements (documented, not negotiable)

| Requirement | Value |
|---|---|
| eBPF LSM | Linux 5.7+ (`CONFIG_BPF_LSM=y`, `bpf` present in `CONFIG_LSM`) |
| BPF ring buffer | Linux 5.8+ |
| CO-RE / BTF | `CONFIG_DEBUG_INFO_BTF=y` (vmlinux BTF at `/sys/kernel/btf/vmlinux`) |
| Recommended / tested target | Linux 6.x; LSM programs with typed args (`BPF_PROG`) on 5.19+ |
| Privileges | root or `CAP_BPF`/`CAP_SYS_ADMIN` at load time |
| Build host | libbpf ≥ 0.7, bpftool, clang with BPF target, gcc 13+ (C++23 `std::expected`) |

The project **does not run on non-Linux kernels** for enforcement; on macOS it
builds and runs with a documented **null backend** for development and unit
testing of the policy engine and control plane.

## Acceptance criteria (MVP)

- `guardctl policy validate` rejects malformed / inconsistent policies.
- `guardctl policy load` results in `guardctl status` reporting the policy
  version and `enforcing: yes`.
- `backup-agent` reading the protected file succeeds.
- `cat` / `test-reader` reading it fails with `Permission denied`.
- An event row exists for each decision (console and/or JSON log).
- Unit tests and integration tests pass on the target Linux host
  (`ctest`, `scripts/integration-tests.sh`).
