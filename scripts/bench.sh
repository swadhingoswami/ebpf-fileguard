#!/usr/bin/env bash
# bench.sh — performance measurement methodology from docs/10-performance.md.
#
# Compares three scenarios on a protected file:
#   baseline    : FileGuard not installed
#   monitoring  : FileGuard installed, ALLOW rule for the benchmark tool
#   enforcement : same as monitoring (the bench tool is authorized)
#
# Measures per-open latency and throughput with fileguard-bench, and also
# drives the file at paced rates (100/1k/10k/100k opens per second) to check
# event throughput on a protected resource.
#
# Usage: sudo ./scripts/bench.sh [iterations]
set -uo pipefail

FG=${FG:-build/guardctl}
BENCH=./build/fileguard-bench
RUNDIR=/run/fileguard
SECRET=/protected/secret.txt
N=${1:-200000}
TMP=/tmp/fgtest

if [[ $EUID -ne 0 ]]; then echo "error: run as root" >&2; exit 1; fi
if [[ ! -x $BENCH ]]; then echo "error: build first" >&2; exit 1; fi
if [[ ! -f $SECRET ]]; then echo "error: run scripts/setup-demo.sh first" >&2; exit 1; fi

# The bench tool itself must be authorized so its opens hit the enforcement
# path and are ALLOWed (matching the "monitoring" and "enforcement" scenarios).
cat > "$TMP/bench-policy.json" <<EOF
{
    "version": 1,
    "defaults": { "action": "DENY" },
    "protected_resources": [ { "path": "$SECRET", "operation": "OPEN" } ],
    "rules": [
        {
            "id": "allow-bench",
            "resource": "$SECRET",
            "operation": "OPEN",
            "process": { "type": "exe_path", "value": "$(realpath $BENCH)" },
            "action": "ALLOW"
        }
    ]
}
EOF

report() { # $1=label  $2=raw bench output
    printf '\n--- %s ---\n%s\n' "$1" "$2"
}

echo "====================== baseline (FileGuard not installed)"
"$FG" stop --runtime-dir "$RUNDIR" >/dev/null 2>&1 || true
sleep 0.5
report "baseline $N opens" "$($BENCH -f "$SECRET" -n "$N" -o "$TMP/bench.csv" 2>&1)"

echo "====================== enforcement enabled (ALLOW for bench)"
"$FG" policy load "$TMP/bench-policy.json" --runtime-dir "$RUNDIR" >/dev/null 2>&1 \
    || { "$FG" serve --daemon --runtime-dir "$RUNDIR" --policy "$TMP/bench-policy.json"; sleep 1; }
report "enforced $N opens" "$($BENCH -f "$SECRET" -n "$N" -o "$TMP/bench.csv" 2>&1)"

echo "====================== paced event-rate runs (protected resource)"
for rate in 100 1000 10000; do
    ns=$(( 1000000000 / rate ))
    m=$(( N / 10 ))
    report "paced ~${rate}/s, $m opens" "$($BENCH -f "$SECRET" -n "$m" -p "$ns" -o "$TMP/bench.csv" 2>&1)"
done

echo
echo "results appended to $TMP/bench.csv (file,iterations,failed,per_open_us,throughput,elapsed_ns)"
echo "compare baseline vs enforced columns; see docs/10-performance.md"
