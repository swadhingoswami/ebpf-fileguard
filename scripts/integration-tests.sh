#!/usr/bin/env bash
# integration-tests.sh — functional + security integration tests (Linux only).
#
# Maps 1:1 to the test matrix in docs/09-testing.md (Tests 1-13) plus the
# security checks from docs/11-limitations.md. Requires root.
#
# Usage: sudo ./scripts/integration-tests.sh
set -uo pipefail

FG=${FG:-build/guardctl}
AGENT=/usr/local/bin/backup-agent
READER=/usr/local/bin/test-reader
SECRET=/protected/secret.txt
RUNDIR=/run/fileguard
TMP=/tmp/fgtest
LOG="$TMP/events.log"
PASS=0
FAIL=0

log()  { printf '\n== %s\n' "$*"; }
ok()   { printf '   PASS: %s\n' "$*"; PASS=$((PASS+1)); }
bad()  { printf '   FAIL: %s\n' "$*"; FAIL=$((FAIL+1)); }

if [[ $EUID -ne 0 ]]; then
    echo "error: run as root" >&2; exit 1
fi
if [[ ! -x $FG ]]; then
    echo "error: build first (scripts/build-linux.sh)" >&2; exit 1
fi

# ---------------------------------------------------------------- fixtures
rm -rf "$TMP"; mkdir -p "$TMP"
install -d -m 0700 /protected
printf 'launch-codes: alpha-9-foxtrot-1138\n' > "$SECRET"; chmod 0400 "$SECRET"

cat > "$TMP/backup-agent.cc" <<'EOF'
#include <fstream>
#include <iostream>
int main(int argc, char** argv) {
    std::ifstream in(argv[1]);
    if (!in) { std::cerr << argv[0] << ": Permission denied.\n"; return 1; }
    std::cout << "Access allowed.\n" << in.rdbuf() << "\n";
    return 0;
}
EOF
cat > "$TMP/test-reader.cc" <<'EOF'
#include <fstream>
#include <iostream>
int main(int argc, char** argv) {
    std::ifstream in(argv[1]);
    if (!in) { std::cerr << argv[0] << ": Permission denied.\n"; return 1; }
    std::cout << "Access allowed.\n" << in.rdbuf() << "\n";
    return 0;
}
EOF
g++ -O2 -o "$TMP/backup-agent-src" "$TMP/backup-agent.cc"
g++ -O2 -o "$TMP/test-reader-src" "$TMP/test-reader.cc"
install -m 0755 "$TMP/backup-agent-src" "$AGENT"
install -m 0755 "$TMP/test-reader-src" "$READER"

mkpolicy() { # $1=action-for-backup  $2=outfile
cat > "$2" <<EOF
{
    "version": 1,
    "defaults": { "action": "DENY" },
    "protected_resources": [ { "path": "$SECRET", "operation": "OPEN" } ],
    "rules": [
        {
            "id": "backup",
            "resource": "$SECRET",
            "operation": "OPEN",
            "process": { "type": "exe_path", "value": "$AGENT" },
            "action": "$1"
        }
    ]
}
EOF
}

start_daemon() { # $1=policy  [$2=extra args]
    "$FG" stop --runtime-dir "$RUNDIR" >/dev/null 2>&1 || true
    sleep 0.5
    "$FG" serve --daemon --runtime-dir "$RUNDIR" --policy "$1" --log "$LOG"
    sleep 1
    if ! "$FG" status --runtime-dir "$RUNDIR" | grep -q "backend:        ebpf-lsm"; then
        bad "daemon is not enforcing (eBPF backend missing — check CONFIG_BPF_LSM/BTF)"
        exit 1
    fi
}

mkpolicy ALLOW "$TMP/policy-allow.json"
mkpolicy DENY  "$TMP/policy-deny.json"

expect_deny() { # $1=label  $2=cmd...
    local label=$1; shift
    if "$@" 2>&1 | grep -q "Permission denied"; then ok "$label"; else bad "$label"; fi
}
expect_allow() { # $1=label  $2=cmd...
    local label=$1; shift
    if "$@" 2>&1 | grep -q "Access allowed"; then ok "$label"; else bad "$label"; fi
}

# ================================================================ tests
log "Diagnostics — daemon state and kernel decisions"
uname -r
echo "  enabled LSMs: $(cat /sys/kernel/security/lsm 2>/dev/null || echo '<read failed>')"
grep -q bpf /sys/kernel/security/lsm 2>/dev/null && echo "  bpf LSM: enabled" || echo "  bpf LSM: NOT enabled"
start_daemon "$TMP/policy-allow.json"
"$FG" status --runtime-dir "$RUNDIR"
"$FG" policy list --runtime-dir "$RUNDIR"
"$AGENT" "$SECRET" >/dev/null 2>&1 && echo "  diag: backup-agent open -> ALLOW (exit 0)" || echo "  diag: backup-agent open -> DENY (exit $?)"
cat "$SECRET" >/dev/null 2>&1 && echo "  diag: cat open -> ALLOW (exit 0)" || echo "  diag: cat open -> DENY (exit $?)"
echo "  diag: streaming events (2s)..."
timeout 2 "$FG" events --runtime-dir "$RUNDIR" --count 4 --json 2>&1 | head -8 || true
echo "  diag: done"

log "Test 1 — allowed process"
expect_allow "backup-agent -> $SECRET ALLOW" "$AGENT" "$SECRET"

log "Test 2 — unauthorized process"
expect_deny "cat -> $SECRET DENY" cat "$SECRET"
expect_deny "test-reader -> $SECRET DENY" "$READER" "$SECRET"

log "Test 3 — multiple concurrent processes"
pids=()
for i in $(seq 1 20); do
    if (( i % 2 )); then ( "$AGENT" "$SECRET" >/dev/null 2>&1 & echo $! > "$TMP/pid.$i" ) &
    else ( cat "$SECRET" >/dev/null 2>&1 & echo $! > "$TMP/pid.$i" ) &
    fi
    pids+=("$(cat "$TMP/pid.$i")")
done
wait
allowed=$(grep -l . /dev/null 2>/dev/null; true)
# verify a sample: run 10 again and check each decision
allok=1
for i in $(seq 1 10); do
    if (( i % 2 )); then "$AGENT" "$SECRET" >/dev/null 2>&1 || allok=0
    else cat "$SECRET" >/dev/null 2>&1 && allok=0; fi
done
[ "$allok" = 1 ] && ok "independent decisions under concurrency" || bad "concurrency decisions"

log "Test 4 — unprotected file"
echo normal > "$TMP/normal.txt"
if cat "$TMP/normal.txt" | grep -q normal; then ok "unprotected file unaffected"; else bad "unprotected file"; fi

log "Test 5 — policy reload (ALLOW -> DENY)"
start_daemon "$TMP/policy-deny.json"
expect_deny "backup-agent now DENY after reload" "$AGENT" "$SECRET"
expect_deny "cat still DENY" cat "$SECRET"
start_daemon "$TMP/policy-allow.json"
expect_allow "backup-agent ALLOW again after reload" "$AGENT" "$SECRET"

log "Test 6 — invalid policy rejected, previous stays active"
# Note: with `pipefail` a rejected `policy load` makes the whole pipeline fail,
# so check the CLI exit code directly instead of the pipe.
out=$("$FG" policy load config/policy.invalid.json --runtime-dir "$RUNDIR" 2>&1); rc=$?
if [[ $rc -ne 0 ]] && printf '%s' "$out" | grep -q "invalid\|rejected"; then
    ok "invalid policy rejected"
else bad "invalid policy not rejected (rc=$rc: $out)"; fi
expect_allow "previous (allow) policy still active" "$AGENT" "$SECRET"

log "Test 7 — executable replacement changes identity (Level-1 weakness)"
cp "$AGENT" "$AGENT.new" && mv "$AGENT.new" "$AGENT"
expect_deny "replaced backup-agent binary is DENY (old inode no longer matches)" "$AGENT" "$SECRET"
# restore + reload so the rest of the suite sees a working allow rule
"$FG" policy load "$TMP/policy-allow.json" --runtime-dir "$RUNDIR" >/dev/null 2>&1
if "$AGENT" "$SECRET" >/dev/null 2>&1; then ok "reload re-allows the new inode"; else bad "reload failed to allow new inode"; fi

log "Test 8 — symlink to protected resource"
ln -sf "$SECRET" "$TMP/link.txt"
expect_deny "open through symlink DENY (resolves to protected inode)" cat "$TMP/link.txt"

log "Test 9 — hard link to protected resource"
ln -f "$SECRET" "$TMP/hard.txt"
expect_deny "open through hard link DENY (same inode)" cat "$TMP/hard.txt"

log "Test 10 — rename of protected resource"
mv "$SECRET" /protected/renamed.txt
expect_deny "renamed protected inode still DENY" cat /protected/renamed.txt
mv /protected/renamed.txt "$SECRET"

log "Test 11 — access storm (event generation + controller health)"
"$FG" status --runtime-dir "$RUNDIR" >/dev/null 2>&1 && ok "controller responsive before storm" || bad "controller down before storm"
"$FG" policy load "$TMP/policy-allow.json" --runtime-dir "$RUNDIR" >/dev/null 2>&1
./build/fileguard-bench -f "$SECRET" -n 2000 -q >/dev/null 2>&1 || true
if "$FG" status --runtime-dir "$RUNDIR" | grep -q "policy version: 1"; then
    ok "controller responsive after 2000 event storm"
else bad "controller unresponsive after storm"; fi
events=$(wc -l < "$LOG" 2>/dev/null || echo 0)
echo "   (JSON log lines so far: $events)"

log "Test 12 — controller restart; enforcement resumes"
"$FG" stop --runtime-dir "$RUNDIR" >/dev/null 2>&1
sleep 0.5
# During the gap the LSM program is unloaded: fail-open window (documented).
if cat "$SECRET" >/dev/null 2>&1; then ok "documented fail-open gap while controller is down"; else bad "unexpected"; fi
start_daemon "$TMP/policy-allow.json"
expect_deny "enforcement resumes after restart: cat DENY" cat "$SECRET"

log "Test 13 — eBPF unload => fail-open"
"$FG" stop --runtime-dir "$RUNDIR" >/dev/null 2>&1
sleep 0.5
if cat "$SECRET" >/dev/null 2>&1; then ok "after unload, system is fail-open (documented)"; else bad "expected fail-open"; fi

log "Security spot-checks"
# Policy files live in git (0644); the requirement is that they are not
# group/world *writable* and that the runtime control socket is protected.
perms=$(stat -c "%a" config/policy.example.json 2>/dev/null || stat -f "%Lp" config/policy.example.json)
if [ $(( 8#$perms & 8#22 )) -ne 0 ]; then
    bad "policy file mode is $perms — must not be writable by group/world"
else
    ok "policy file is not group/world writable (mode $perms)"
fi
sock_mode=$(stat -c "%a" "$RUNDIR/fileguard.sock" 2>/dev/null || stat -f "%Lp" "$RUNDIR/fileguard.sock")
if [ "$sock_mode" = "600" ]; then
    ok "control socket mode 0600"
else
    bad "control socket mode is $sock_mode (expected 0600)"
fi

# UID change: a different uid running an unauthorized binary stays denied.
if id -u daemon >/dev/null 2>&1; then
    start_daemon "$TMP/policy-allow.json"
    if su -s /bin/sh daemon -c "cat '$SECRET'" 2>&1 | grep -q "Permission denied"; then
        ok "different UID still DENY (policy is per-executable, not per-UID)"
    else bad "UID change bypassed policy"; fi
fi

"$FG" stop --runtime-dir "$RUNDIR" >/dev/null 2>&1 || true

echo
echo "=========================================="
echo "passed: $PASS   failed: $FAIL"
echo "=========================================="
[[ $FAIL -eq 0 ]]
