# 09 — Testing

Two layers: **unit tests** (portable, run on macOS + Linux) and **integration
tests** (Linux, need root + eBPF). Run unit tests with `ctest`; run the full
integration matrix with `sudo ./scripts/integration-tests.sh`.

## Unit tests (`./build/fileguard_tests`)

| Area | File | What it checks |
|---|---|---|
| Config parsing | `tests/test_config_parser.cpp` | valid JSON, malformed JSON, unknown action, defaults, rule for unprotected resource, unsupported identity type, relative paths, duplicate ids |
| Policy invariants | `tests/test_policy.cpp` | validation rules, `is_protected`, `find_rule` |
| Decisions | `tests/test_decision_engine.cpp` | unprotected→allow; allow rule; explicit deny; default deny; default allow; wrong-process mismatch |
| Compiler | `tests/test_policy_compiler.cpp` | path→FileId resolution, unresolvable paths, invalid policy, 1-based rule ids |
| Identity | `tests/test_path_resolver.cpp` | known vs unknown FileId rendering |
| Queue | `tests/test_event_queue.cpp` | FIFO order, full/empty semantics, drain-after-stop |
| Sinks | `tests/test_event_sink.cpp` | console columns, NDJSON shape |

## Integration tests (`scripts/integration-tests.sh`) — Test 1-13

Setup (fixtures): `/protected/secret.txt`, `/usr/local/bin/backup-agent`,
`/usr/local/bin/test-reader`; a daemon started with a versioned policy.

### Test 1 — allowed process
`backup-agent /protected/secret.txt` → `Access allowed.`

### Test 2 — unauthorized process
`cat /protected/secret.txt` and `test-reader …` → `Permission denied`.

### Test 3 — multiple concurrent processes
Interleaved authorized/unauthorized runs → every decision correct and
independent.

### Test 4 — unprotected file
`cat normal.txt` → normal Linux behavior.

### Test 5 — policy reload
Reload `allow` → `deny`: `backup-agent` now denied; reload `allow` again →
allowed. Verifies kernel map replacement + versioning.

### Test 6 — invalid policy
`guardctl policy load config/policy.invalid.json` → rejected; the previously
loaded (allow) policy still enforces.

### Test 7 — executable replacement (identity)
`cp backup-agent backup-agent.new && mv …` → new inode ⇒ **denied** (the old
inode is what the map holds). Reload re-allows the new inode. Documents the
Level-1 weakness.

### Test 8 — symlink
`ln -s /protected/secret.txt link` → `cat link` denied (resolves to the
protected inode).

### Test 9 — hard link
`ln /protected/secret.txt hard` → `cat hard` denied (same inode).

### Test 10 — rename
`mv /protected/secret.txt /protected/renamed.txt` → still denied (inode
identity follows the file). Renamed back for later tests.

### Test 11 — concurrent access storm
`fileguard-bench -f /protected/secret.txt -n 2000` while enforcing → no
crash; `guardctl status` stays responsive; JSON log records the decisions.

### Test 12 — controller restart
`guardctl stop` detaches the LSM program (documented **fail-open gap**), then
`serve` re-attaches → enforcement resumes (`cat` denied again). The gap
behavior is asserted and documented, not hidden.

### Test 13 — eBPF unload (fail-open)
After `guardctl stop`, the program is unloaded and the protected file is
readable — **fail-open**. This is the documented default; pinning is the
hardening path.

## Security spot-checks (in the same script)

- Policy/config file not group/world writable.
- Different UID (`su daemon`) running an unauthorized binary still denied.
- Symlink / hard-link / rename / replacement attacks (Tests 7-10).
- Policy tampering: a modified file is only effective after an explicit
  validated reload; invalid reloads are rejected (Test 6).
- DoS via excessive events: storm test verifies the controller remains
  responsive and the ring buffer path does not crash the kernel program.

## What the MVP does NOT test yet

- PID-reuse races (identity is not PID-based, so this is structurally out);
  it is verified at the design level in `11-limitations.md`.
- Containers / mount namespaces (documented limitation).
- Read-after-open (needs `file_permission` program).
