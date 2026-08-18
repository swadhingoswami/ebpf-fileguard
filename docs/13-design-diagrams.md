# 13 — Design Diagrams

Rendered diagrams for the eBPF FileGuard design. All diagrams are
[Mermaid](https://mermaid.js.org/) and render directly on GitHub and in
editors that support Mermaid.

## Contents

1. [Sequence diagram — policy load + enforcement + events](#sequence-diagram)
2. [Class diagram — userspace C++](#class-diagram)
3. [Workflow — kernel decision flow](#workflow)
4. [Control-plane protocol](#control-plane-protocol)
5. [Thread model & concurrency](#thread-model--concurrency)
6. [Deployment / runtime layout](#deployment)

---

## Sequence diagram

A policy load, followed by one authorized and one unauthorized open, then the
event path.

```mermaid
sequenceDiagram
    autonumber
    actor Admin as Administrator
    participant CLI as guardctl (CLI)
    participant D as fileguard daemon<br/>(C++ controller)
    participant K as Linux kernel<br/>(LSM + eBPF program)
    participant P as process<br/>(backup-agent / cat)

    Admin->>CLI: guardctl policy load policy.json
    CLI->>D: load_policy (NDJSON over UNIX socket)
    D->>D: validate policy (schema + invariants)
    D->>D: compile (paths → FileId via stat(2))
    D->>K: apply_policy: enabled=0 → clear maps → insert → enabled=1
    D-->>CLI: ok, version N
    CLI-->>Admin: policy loaded

    par authorized open (backup-agent)
        P->>K: open("/protected/secret.txt")
        K->>K: security_file_open(file)
        K->>K: fg_file_id(file) → in protected map
        K->>K: fg_process_exe_id() → rule (res, proc) = ALLOW
        K-->>P: return 0 → open succeeds
        K->>K: reserve + fill + submit event (ring buffer)
        K->>D: ring_buffer__poll → ring_callback → RawEvent
        D->>D: emit_event: PathResolver → SecurityEvent
        D->>D: SPSC queue
        D->>D: consumer → sinks
        D-->>CLI: socket stream (guardctl events)
        CLI-->>Admin: ALLOW  POLICY_RULE
    and unauthorized open (cat)
        P->>K: open("/protected/secret.txt")
        K->>K: security_file_open(file)
        K->>K: fg_file_id(file) → in protected map
        K->>K: fg_process_exe_id() → no rule
        K-->>P: return -EACCES → "Permission denied"
        K->>K: reserve + fill + submit event (ring buffer)
        K->>D: ring_buffer__poll → ring_callback → RawEvent
        D->>D: emit_event: PathResolver → SecurityEvent
        D->>D: SPSC queue
        D->>D: consumer → sinks
        D-->>CLI: socket stream (guardctl events)
        CLI-->>Admin: DENY  DEFAULT_DENY
    end
```

## Class diagram

```mermaid
classDiagram
    direction LR

    class ConfigParser {
        <<utility>>
        +from_json(text) Result~Policy~
        +from_file(path) Result~Policy~
    }
    class Policy {
        -int32 version
        -Action default_action
        -vector~ResourceIdentity~ protected_resources
        -vector~PolicyRule~ rules
        +validate() ResultVoid
        +is_protected(path) bool
        +find_rule(resource, process, op) PolicyRule*
    }
    class PolicyRule {
        +string id
        +ResourceIdentity resource
        +ProcessIdentity process
        +Operation operation
        +Action action
    }
    class PolicyManager {
        -mutex mu
        -shared_ptr~const Policy~ current
        +install(policy) ResultVoid
        +current() shared_ptr~const Policy~
    }
    class PolicyCompiler {
        -FileResolver resolver
        +compile(policy) Result~CompiledPolicy~
    }
    class CompiledPolicy {
        +int32 version
        +vector~FileId~ protected_resources
        +vector~CompiledRule~ rules
    }
    class DecisionEngine {
        <<utility>>
        +evaluate(policy, request) Decision
    }
    class IEnforcer {
        <<interface>>
        +load() ResultVoid
        +apply_policy(compiled) ResultVoid
        +status() EnforcerStatus
        +run(stop_token) void
        +detach() ResultVoid
    }
    class LinuxEBPFEnforcer {
        -void* skel
        -void* ring
        +apply_policy(compiled) ResultVoid
        +run(stop_token) void
        +detach() ResultVoid
    }
    class NullEnforcer {
        <<non-Linux stand-in>>
        +load() ResultVoid
    }
    class PathResolver {
        -unordered_map~FileId,string~ map
        +add(id, path) void
        +resolve(id) string
    }
    class SpscQueue~T~ {
        -atomic head
        -atomic tail
        +push(T) void
        +pop(T) bool
        +request_stop() void
    }
    class RawEvent {
        +FileId resource
        +FileId process
        +Action action
        +Reason reason
    }
    class SecurityEvent {
        +string timestamp
        +string process_path
        +string resource_path
        +Action action
        +Reason reason
    }
    class ISink {
        <<interface>>
        +write(event) void
    }
    class Controller {
        -PolicyManager policy_manager
        -unique_ptr~IEnforcer~ enforcer
        -shared_ptr~const PathResolver~ resolver
        -SpscQueue~shared_ptr~ queue
        -jthread ring_thread
        -jthread consumer_thread
        +start() ResultVoid
        +load_policy(policy) ResultVoid
        +request_stop() ResultVoid
        +status() EnforcerStatus
    }
    class Daemon {
        -Controller controller
        -jthread server_thread
        +run() ResultVoid
        +stop() ResultVoid
    }

    ConfigParser ..> Policy : produces
    PolicyCompiler ..> Policy : reads
    PolicyCompiler ..> CompiledPolicy : produces
    PolicyManager o-- Policy : owns current
    DecisionEngine ..> Policy : reads
    IEnforcer <|-- LinuxEBPFEnforcer
    IEnforcer <|-- NullEnforcer
    Controller o-- PolicyManager
    Controller o-- IEnforcer
    Controller o-- SpscQueue
    Controller o-- PathResolver
    Daemon o-- Controller
    LinuxEBPFEnforcer ..> RawEvent : emits
    Controller ..> SecurityEvent : builds
    ISink <|.. ConsoleSink
    ISink <|.. JsonSink
    Controller o-- ISink : SinkSet
```

**Ownership & lifetime** (summary, full detail in `docs/07-cpp-design.md`):

| Object | Owner | Lifetime notes |
|---|---|---|
| `Policy` | `PolicyManager` (via `shared_ptr<const Policy>`) | immutable; swapped atomically on load |
| `IEnforcer` | `Controller` (`unique_ptr`) | destroyed in `Controller::~Controller` → `detach()` |
| `PathResolver` | `Controller` (`shared_ptr<const>`) | rebuilt per policy; lock-free reads |
| `SpscQueue` | `Controller` (value) | SPSC: poller → consumer; bounded, drains on stop |
| `jthread`s | `Controller` | joined in `request_stop()` |
| `SocketStreamClient` | `Daemon` | per-client queue + writer thread; dropped events counted |

## Workflow

### Kernel decision flow

```mermaid
flowchart TD
    A["Process calls open()"] --> B["LSM hook security_file_open<br/>(eBPF program attached)"]
    B --> C{"config.enabled?"}
    C -- "no (update window)" --> ALLOW["ALLOW — return 0"]
    C -- "yes" --> D["Resolve opened file id<br/>(dev_major, dev_minor, ino)"]
    D --> E{"In protected map?"}
    E -- "no (unprotected)" --> ALLOW
    E -- "yes" --> F["Resolve process exe id<br/>(exe_file inode)"]
    F --> G{"Explicit rule for<br/>(resource, process)?"}
    G -- "yes, action = ALLOW" --> ALLOW
    G -- "yes, action = DENY" --> DENY["DENY — return -EACCES"]
    G -- "no rule → default-deny" --> DENY
    ALLOW --> H["Submit compact event to ring buffer"]
    DENY --> H
    H --> I["Controller ring-poll thread"]
    I --> J["Enrich (PathResolver): ids → paths"]
    J --> K["SPSC queue"]
    K --> L["Consumer thread"]
    L --> M["Console table + NDJSON log"]
    L --> N["Socket stream → guardctl events"]
```

### Policy update flow (userspace)

```mermaid
flowchart TD
    A["guardctl policy load file.json"] --> B["ConfigParser.from_file"]
    B --> C{"JSON valid + invariants hold?"}
    C -- "no" --> ERR["rejected — error to CLI, exit 1<br/>previous policy untouched"]
    C -- "yes" --> D["PolicyCompiler.compile"]
    D --> E{"every path resolves via stat?"}
    E -- "no" --> ERR
    E -- "yes" --> F["enforcer.apply_policy (kernel)"]
    F --> G["1. config.enabled = 0 (pause)"]
    G --> H["2. clear protected + rules maps"]
    H --> I["3. insert new entries"]
    I --> J["4. config.enabled = 1, version = N"]
    J --> K["swap PolicyManager + rebuild PathResolver"]
    K --> L["CLI: policy loaded (version N)"]
```

## Control-plane protocol

The daemon exposes a **UNIX domain socket** (`/run/fileguard/fileguard.sock`
as root, `/tmp/fileguard/…` otherwise) speaking **NDJSON** — one JSON object
per line.

```mermaid
sequenceDiagram
    actor Admin as Administrator
    participant CLI as guardctl
    participant D as daemon

    CLI->>D: {"cmd":"status"}
    D-->>CLI: {"ok":true,"status":{backend,attached,enforcing,policy_version,...}}

    CLI->>D: {"cmd":"list"}
    D-->>CLI: {"ok":true,"version":N,"rules":[...],"protected_resources":[...]}

    CLI->>D: {"cmd":"load_policy","policy":{...}}
    D-->>CLI: {"ok":true,"policy_version":N}  or  {"ok":false,"error":"..."}

    CLI->>D: {"cmd":"stream","json":false}
    D-->>CLI: {"ok":true,"stream":true}
    loop live events
        D-->>CLI: {"event":{timestamp,pid,comm,process,resource,operation,action,reason,rule_id}}
    end

    CLI->>D: {"cmd":"stop"}
    D-->>CLI: {"ok":true,"message":"stopping"}
```

## Thread model & concurrency

```mermaid
flowchart LR
    K["kernel ring buffer"] --> RP["ring-poll thread<br/>(SPSC producer)"]
    RP --> E["emit_event: decode + enrich"]
    E --> Q["SpscQueue&lt;shared_ptr&lt;const SecurityEvent&gt;&gt;<br/>(lock-free data path)"]
    Q --> C["consumer thread<br/>(SPSC consumer)"]
    C --> S["sinks (console + NDJSON)"]
    C --> X["socket stream clients<br/>(own queue + writer thread)"]
    D["daemon socket server thread"] --> CT["client handler threads"]
    CT -->|load_policy| P["Controller (single policy writer)"]
    P -->|apply_policy| K
```

- **Data path is lock-free**: one producer (ring poller), one consumer
  (logger); atomics + a mutex/condvar pair only for blocking.
- **Policy**: writers serialized; readers get an immutable `shared_ptr`.
- **Sinks**: single-writer (consumer thread only) → no locks.
- **Shutdown**: `request_stop()` → queue stop (unblocks + drains) → join
  threads → `enforcer.detach()` → socket unlink.

## Deployment

```mermaid
flowchart LR
    A["admin terminal"] -->|"guardctl policy load"| B["UNIX socket<br/>/run/fileguard/fileguard.sock"]
    B --> C["fileguard daemon (root/CAP_BPF)"]
    C --> D["eBPF LSM program<br/>security_file_open"]
    D --> E["kernel maps:<br/>protected · rules · config"]
    D --> F["ring buffer"]
    F --> C
    C --> G["NDJSON log"]
    C -->|"guardctl events"| A
    H["protected file"] -.protected by.-> D
```
