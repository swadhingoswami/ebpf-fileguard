# 10 — Performance

Goal: measure — not assert — the cost of observation and enforcement.

## Methodology

Three scenarios on a **protected** file, same host, same iteration count:

| Scenario | State |
|---|---|
| **baseline** | FileGuard not installed |
| **monitoring** | FileGuard enforcing with an ALLOW rule for the benchmark tool |
| **enforcement** | same as monitoring (the tool is authorized), plus a separate run with an *unauthorized* tool to measure the DENY path |

Tool: `fileguard-bench` (`tools/bench.cc`) — a warm-up phase followed by N
`open(2)`+`close(2)` iterations, reporting:

```
total_time  avg_per_open (µs)  throughput (opens/s)  failed
```

Metrics captured per run:
- latency (avg per open), throughput,
- CPU overhead (compare `perf stat` / `pidstat` on the bench process),
- memory (RSS of `guardctl` via `ps`),
- event rate and **dropped events** (ring-buffer loss is visible as fewer
  JSON-log lines than opens on a protected file).

## Script

`sudo ./scripts/bench.sh [iterations]` runs baseline, enforced, and paced
runs at ~100/s, ~1k/s, ~10k/s (and 100k/s on fast hosts) and appends rows to
`/tmp/fgtest/bench.csv`:

```
file,iterations,failed,per_open_us,throughput,elapsed_ns
```

## Reporting template (fill in on the Linux test host)

```
scenario        opens     per_open(µs)   throughput/s   failed   guardctl RSS
baseline        200000    <record>       <record>       0        -
monitoring      200000    <record>       <record>       0        <record>
enforcement     200000    <record>       <record>       0        <record>
deny-path       200000    <record>       <record>   200000        <record>

event rate (protected file, allowed tool):
  paced 100/s    -> events logged  100/s, dropped 0
  paced 1k/s     -> events logged ~1k/s,  dropped 0
  paced 10k/s    -> events logged ~10k/s, dropped <...>
  paced 100k/s   -> events logged ~100k/s, dropped <...>   (if host allows)
```

## Interpretation guide

- Expect `per_open` to rise only by a few microseconds with enforcement: the
  LSM program is two hash lookups + a ring-buffer write on the protected
  path, and a single lookup + early return on the hot/unprotected path.
- **Unprotected opens are nearly free**: `in protected map? → miss → allow`
  before any event work.
- Ring-buffer loss under 100k+ events/s shows up as a *gap between opens and
  logged events*; that is observability loss, not enforcement loss (the
  decision is returned regardless).

> **No benchmark numbers are claimed in this repository.** The project
> explicitly refuses to fabricate results; run `scripts/bench.sh` on the
> target kernel and record the output here.
