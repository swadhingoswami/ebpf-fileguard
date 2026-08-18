# 04 — Architecture

## Component diagram

```
+----------------------------------------------------------------------+
|                    guardctl  (single C++23 binary)                   |
|                                                                      |
|   CLI  ──►  Daemon (UNIX socket control plane)                       |
|                  │                                                   |
|   PolicyManager ◄── validate/compile ◄── ConfigParser (JSON)         |
|        │                                                            │
|        │ compile (paths → FileIds)                                   │
|        v                                                            │
|   PolicyCompiler ──► CompiledPolicy ──► IEnforcer.apply_policy()    │
|                                              │                       │
|   Controller ──► ring poll thread ──► RawEvent ──► PathResolver      │
|        │                                                  │          │
|        │  SPSC event queue (lock-free data path)          ▼          │
|        │                                             SecurityEvent   │
|        ▼                                                             │
|   consumer thread ──► SinkSet (console table + NDJSON log)          │
|        │                                                             │
|        └─► EventStreamClient(s) → socket streams (guardctl events)  │
+----------------------------------------------------------------------+
                              │            ▲
                  maps / ringbuf          │
                              ▼            │
+----------------------------------------------------------------------+
|                      Linux kernel                                     |
|                                                                      |
|   LSM hook  security_file_open(struct file *file)                    |
|        │                                                            │
|        ▼                                                            │
|   fileguard.bpf.c                                                    |
|        - resolve (major, minor, ino) of opened file                  |
|        - in protected map? ──no──► allow                             |
|        - resolve exe (major, minor, ino) of current process          |
|        - lookup rule map  ──► action / default DENY                  |
|        - ring buffer event (compact) ─────────────► userspace       │
|        - return 0 (allow) | -EACCES (deny)                           |
+----------------------------------------------------------------------+
```

## Components and responsibilities

| Component | Files | Owns | Notes |
|---|---|---|---|
| `ConfigParser` | `src/config_parser.cpp` | nothing | JSON → `Policy`; single input path |
| `Policy` / `PolicyManager` | `src/policy.cpp`, `controller.hpp` | the current immutable policy | swapped atomically; validates on install |
| `PolicyCompiler` | `src/policy_compiler.cpp` | compiled view | resolves every path to `FileId` via injectable `FileResolver`; fails loud |
| `DecisionEngine` | `src/decision_engine.cpp` | nothing (pure) | mirrors the kernel lookup for tests/dry-run |
| `PathResolver` | `src/path_resolver.cpp` | reverse `FileId → path` | rebuilt per policy; immutable; lock-free reads |
| `IEnforcer` | `src/enforcer.cpp` | backend lifecycle | `LinuxEBPFEnforcer` (Linux) or `NullEnforcer` (other) |
| `LinuxEBPFEnforcer` | `src/ebpf_manager_linux.cpp`, `ebpf/fileguard.bpf.*` | kernel maps + LSM attach | only built with `ENABLE_EBPF` |
| `Controller` | `src/controller.cpp` | pipeline: policy + enforcer + threads + sinks | central owner |
| `Daemon` | `src/daemon.cpp` | UNIX socket control plane | NDJSON protocol |
| `CLI` | `src/cli.cpp` | command dispatch | `serve`, `policy …`, `status`, `events`, `stop` |

## Who owns the policy

The **`PolicyManager`** owns the current `shared_ptr<const Policy>`; the
**controller** is the single writer, the daemon request handler is the only
entry point that can trigger a change. There is exactly one path that can
mutate policy: `ConfigParser` (validate) → `PolicyCompiler` (compile) →
`enforcer.apply_policy` (kernel maps) → swap userspace policy.

## How policy updates happen

1. `guardctl policy load file` parses and compiles **locally**; any error
   aborts before the daemon is contacted.
2. The daemon re-validates, re-compiles, then calls
   `Controller::load_policy`, which:
   - `apply_policy` on the kernel:
     1. set `config.enabled = 0` (**fail-open window**, bounded);
     2. clear `protected` and `rules` maps;
     3. re-insert every entry (validation on each `BPF_MAP_UPDATE`);
     4. set `config.enabled = 1` with the new `policy_version`.
   - only on success swaps `PolicyManager` and rebuilds `PathResolver`.
3. On failure the old userspace policy is retained; the kernel is left
   disabled (fail-open) — documented tradeoff (`05-policy-model.md`, `11-limitations.md`).

The window is *fail-open* (never *partially* enforcing), not *inconsistent*:
a half-updated map never makes decisions because `enabled` is off. See
`12-double-buffering` discussion in `05-policy-model.md`.

## How events move kernel → userspace

1. Kernel: `bpf_ringbuf_reserve` a compact `fileguard_event_t`
   (~70 bytes: ids, uid/gid/pid, comm, action, reason, rule id).
2. Userspace: `ring_buffer__poll` on a dedicated thread → `RawEvent`.
3. `Controller::emit_event` enriches with `PathResolver` → `SecurityEvent`.
4. Enqueued to a **bounded SPSC queue** (lock-free data path).
5. Consumer thread writes sinks (console/JSON) and fans out to socket stream
   clients.

Nothing larger than the fixed-size record crosses the kernel boundary — all
path strings live only in userspace.
