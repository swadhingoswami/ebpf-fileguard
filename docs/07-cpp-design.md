# 07 — C++ Design

Language: **C++23** (`std::expected`, `std::jthread`, `std::stop_token`,
structured bindings, `std::span`, `std::string_view`, scoped enums).
Compiler floor: gcc 13+ / clang 16+ (libc++ 18+).

## Module map

| Module | Header | Owns | Key interfaces |
|---|---|---|---|
| Policy core | `policy.hpp` | `Policy`, `PolicyRule`, identities | `Policy::validate()` |
| Config | `config_parser.hpp` | nothing | `ConfigParser::from_json/from_file` |
| Decisions | `decision_engine.hpp` | nothing (pure) | `DecisionEngine::evaluate` |
| Compile | `policy_compiler.hpp` | `CompiledPolicy` | `PolicyCompiler::compile` |
| Events | `security_event.hpp`, `event_sink.hpp` | `SecurityEvent`, sinks | `ISink`, `ConsoleSink`, `JsonSink` |
| Identity | `file_id.hpp`, `path_resolver.hpp` | `FileId`, reverse map | `PathResolver::resolve` |
| Queue | `event_queue.hpp` | `SpscQueue<T>` | SPSC bounded ring |
| Enforce | `enforcer.hpp`, `ebpf_manager.hpp` | backend lifecycle | `IEnforcer`, `LinuxEBPFEnforcer` |
| Orchestrate | `controller.hpp` | pipeline + threads | `Controller::start/load_policy/stop` |
| Serve | `daemon.hpp` | socket control plane | `Daemon::run` |
| CLI | `cli.hpp` | argv dispatch | `guardctl_main` |

## Ownership & lifetime

- **`Controller` owns**: `PolicyManager`, `unique_ptr<IEnforcer>`,
  `shared_ptr<const PathResolver>`, the `SpscQueue`, both `jthread`s, and the
  `SinkSet`. It is the single root; daemon → controller → everything.
- **`PolicyManager` owns**: `shared_ptr<const Policy>` — the *only* mutable
  policy state. Installs validate then swap under a mutex; readers take the
  shared_ptr and are immune to concurrent replacement (the old object stays
  alive via refcount).
- **`PathResolver`** is built per policy, `shared_ptr<const>`, then **never
  mutated** ⇒ lock-free concurrent reads. It is swapped (rarely) under a
  short mutex during policy install.
- **`SpscQueue<T>`**: stack-owned by Controller; producer = ring-poll thread,
  consumer = logger thread. `std::shared_ptr<const SecurityEvent>` payloads
  keep the event alive across the queue.
- **RAII everywhere**: `jthread` joins in destructor; `Daemon` cleans its
  socket in `run()` teardown and `stop()`; `LinuxEBPFEnforcer`'s destructor
  calls `detach()` (free ring buffer, detach + destroy skeleton); socket fds
  are closed by owner objects; no raw `new/delete`.

## Error handling

`Result<T> = std::expected<T, std::string>` everywhere a failure is possible.
Failures are surfaced up to the CLI exit codes; nothing is swallowed. The one
place a *non-fatal* condition exists (JSON log file open failure) is logged to
stderr and the sink is skipped.

## Concurrency model

```
ring poll thread  ──(RawEvent)──► enrich ──► SpscQueue ──► consumer thread ──► sinks + streams
     (SPSC producer)                                   (SPSC consumer)
```

- **Data path is lock-free**: bounded SPSC ring with atomic head/tail; the
  mutex/condvars are used only to *block* when full (producer backpressure)
  or empty (consumer idle). No event is ever dropped by the core queue — under
  a storm the poller stalls instead (bounded memory).
- **`std::shared_ptr<const SecurityEvent>`** as queue payload: zero data
  races; payloads immutable after publication.
- **Policy updates** synchronize via: enforcer `state_mu_` (map writes),
  `PolicyManager` mutex (swap), `resolver_mu_` (rare resolver swap). Reads on
  the hot path (policy, resolver, event payloads) are **lock-free**.
- **Sinks** are only touched by the consumer thread (single-writer), so sinks
  need no internal locking.
- **Socket stream clients**: each client has its own `SpscQueue` + writer
  thread; the consumer `try_push`es JSON lines. A slow client drops events
  *for itself* (counted) and never stalls logging or other clients.
- **Shutdown**: `request_stop()` → `queue.request_stop()` (unblocks both
  blocked ends, then drains) → stop+join both jthreads → `enforcer.detach()` →
  flush sinks → socket unlink. Ordering guarantees no use-after-free and a
  drained queue.

## Why these choices

- **SPSC not MPSC**: exactly one producer (the poller) and one consumer (the
  logger) by construction, so the simplest correct synchronization wins.
  A lock-free SPSC ring + condvar blocking is simpler to prove correct than a
  general concurrent queue, at the event rates this system targets.
- **`std::expected` not exceptions for control flow**: the codebase is
  intentionally exception-light in the hot path; errors are values.
- **`std::jthread` + stop tokens**: structured cancellation instead of
  `detach()`/`join()` juggling.
