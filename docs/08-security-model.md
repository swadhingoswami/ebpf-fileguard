# 08 — Security Model

## Allow-list model

Protected resources are **default-deny**. Every other file keeps normal Linux
semantics. The decision is taken in the kernel at `security_file_open`, i.e.
*at the security boundary*, before the calling process can proceed.

## Concrete security properties (not slogans)

1. **The decision is enforced in the kernel.** A denied open returns
   `-EACCES` from the syscall itself. The process cannot "keep going" or
   ignore the denial — there is nothing to ignore.
2. **The actor cannot suppress its own audit record.** The event is emitted
   from the same kernel program that enforces; a denied (or even allowed)
   process has no handle on the ring buffer or the userspace consumer.
3. **Root is not a bypass.** The LSM hook runs for every open, including
   `uid 0`; DAC override does not skip LSM. (SELinux/AppArmor share this
   property — this is *why* kernel enforcement matters, not a claim of
   novelty.)
4. **Default-deny shrinks the attack surface.** New or unknown executables
   are denied by construction; there is no "implicitly allowed" gap for
   protected files.
5. **Identity is filesystem identity, not a name.** Protecting the *inode*
   defeats symlink, hard-link and rename tricks that would defeat a
   pathname check (see `09-file-identity`).
6. **The kernel program is verifier-constrained.** CO-RE reads, no
   arbitrary memory access, no way for an attacker to inject logic; the
   policy lives in maps the attacker cannot write.
7. **Policy is centrally managed and versioned.** One validated JSON
   document compiles to the exact kernel state; status reports the version.

## Weaknesses (honest)

- **Level-1 identity (executable path/inode) is weak**: replace the binary
  and the "same path" is a different identity; scripts identify as their
  interpreter; the same binary across many users is one identity. Level 4
  (content hash) is the eventual answer.
- **Privileged attackers win**: anyone who can unload eBPF programs, edit
  the maps, or modify the controller is outside the model (`02-threat-model`).
- **Controller exit = fail-open**: the LSM program lives as long as the
  controller's link fd; when the controller stops, enforcement stops until a
  controller is back. Pinning to bpffs is the hardening step (Phase 12).
- **Pathname → inode at install time has TOCTOU**: if the protected file is
  *replaced* (new inode) after the policy is loaded, the new inode is not
  protected. Renames of the original inode remain protected. Detectable by
  re-verifying inodes, but that is not in the MVP.
- **No per-operation read/write split in the MVP**: `security_file_open`
  enforces *opens*. Reads of an already-open fd (e.g. after a race) are not
  separately policed. A `security_file_permission` program would close that
  gap.
- **eBPF is not a MAC system**: no labels, no type enforcement, no
  hierarchy. It cannot express SELinux policy richness.

## Fail-open vs fail-closed — the explicit tradeoff

| Situation | Behavior | Rationale |
|---|---|---|
| Program fails to load / verify | controller refuses to start; **fail-open**, loud | never run an unvalidated state; operator notices immediately |
| Policy install fails mid-update | kernel disabled (fail-open window) | never *partially* enforce; re-load to recover |
| Controller crashes/exits | LSM detached ⇒ **fail-open** | availability > strictness for the MVP; pinning changes this |
| Ring buffer full | decisions still enforced; **events dropped** | security preserved; observability degraded (counted) |
| Unknown process exe identity | **fail-closed** (deny) | conservative: deny when identity unavailable |

The MVP deliberately leans **fail-open for availability** (a broken control
plane must not brick the host) and **fail-closed for identity** (an
unidentifiable process is denied access to protected files).
