# Simulation_TAPS_TT_P

A benchmark simulation of Parallel TAPS_TT (`../TAPS_TT_P`). The actors are
the Authority, `n` signers, one combiner and `j` tracers. Each actor runs as a
separate process, and they talk over localhost TCP. This crate is a copy of
`Simulation_TAPS_TT`, with the same timing boundaries and the same thresholds:

- `t = ⌊n/2⌋ + 1` (signers)
- `t_e = ⌊2j/3⌋ + 1` (tracers)

All commands below run from **this directory**, always with `--release`,
which uses the same (default) release profile as the baseline measurements.

## Single scenario

```powershell
cargo run --release --bin benchmark -- 10 5 20
```

The arguments are `<n signers> <j tracers> <repeats>`. The `--` is required.
At startup the benchmark prints the number of physical and logical cores and
the effective `RAYON_NUM_THREADS`.

Output files:

| File | Content |
|---|---|
| `benchmark_summary.csv` | per-operation statistics (µs) — **same columns as the baseline's** `benchmark_results_summary.csv` |
| `benchmark_results_{signers,combiner,tracer}.csv` | raw per-run timings (µs) |

Each run of `benchmark` overwrites these files.

### Tracer operations

| Operation | Meaning |
|---|---|
| `Setup`, `TracerDkg`, `VerifySigma` | as in the baseline |
| `VerifyProof` | accountability-proof verification (**parallel**); same boundaries as the baseline |
| `VerifySign` | the whole tracing step. Same boundaries as the baseline, so it also includes exchanging the partial decryptions over the tracer mesh. Use this row to compare against the baseline. |
| `ShareDec` | *new, crypto only:* this tracer's partial decryption and proofs |
| `ShareVerify` | *new, crypto only:* recompute each `vk_k` and verify every share and proof |
| `Rec` | *new, crypto only:* Lagrange recombination, bit decoding and the `g^z` check |

### Threads per tracer

All `j` tracer processes run on this one machine at the same time. By
default, each tracer therefore uses **max(1, ⌊logical cores / j⌋)** rayon
threads. For example, on 8 logical cores: j = 1 → 8 threads, j = 5 → 1
thread, j = 50 → 1 thread.

Without this budget, every tracer would start one thread per core
(j × cores threads in total). In the n = 500, j = 50 run this made the
parallel version about 25% slower than TAPS_TT, because of oversubscription.
When the co-located tracers already use every core, the multi-process
benchmark can't show a parallel speedup. With the budget, it runs at about
the baseline's speed.

Setting `RAYON_NUM_THREADS` overrides the budget. The benchmark prints the
per-tracer thread count at startup, and each tracer logs its own.

## Single-tracer benchmark (the speedup measurement)

In a deployment each tracer runs on its own machine. `trace_bench` measures
what one tracer computes there. It runs in a single process with no
networking; the other tracers' partial decryptions are prepared beforehand
and not timed. It runs the same library code as the tracer process at
several thread counts:

```powershell
cargo run --release --bin trace_bench -- 500 50 20
cargo run --release --bin trace_bench -- 500 50 20 1,2,4,8
```

The arguments are `<n> <j> <repeats> [<thread counts>]`. By default the
thread counts are 1, 2, 4, … up to the logical core count. Each thread count
gets one untimed warm-up run, followed by `<repeats>` timed runs, and every
run checks that the traced quorum is exactly the signing quorum.

The output file is `trace_bench_summary.csv`, with these columns:
`N,N3,Threads,Operation,Samples,Mean_Microseconds,Std_Dev_Microseconds,Min_Microseconds,Max_Microseconds,Speedup,Efficiency`.

| Operation | Meaning |
|---|---|
| `VerifyProof` | accountability-proof verification |
| `ShareDec`, `ShareVerify`, `Rec` | as in the multi-process benchmark |
| `Tracing` | ShareDec + ShareVerify + Rec: the crypto part of `VerifySign`, without network |
| `Total` | VerifyProof + Tracing |

Speedup is `mean(1 thread) / mean(p threads)`, and efficiency is
`speedup / p`. The 1-thread run does the same work as sequential TAPS_TT, so
it is the sequential reference.

## Experiments (PowerShell)

**Tracer count** (n = 10, j = 1 and 5). The per-`j` summaries are merged into
`results\tracer_count_summary.csv`:

```powershell
.\scripts\run_tracer_count.ps1 -N 10 -Tracers "1,5" -Repeats 20
```

**Speedup** (n = 10, j = 5; `RAYON_NUM_THREADS` = 1, 2, 4, … up to the
logical core count). This writes `results\speedup.csv` with the mean runtime,
the speedup `T(1)/T(p)` and the efficiency `speedup/p` for each thread count
and tracer operation:

```powershell
.\scripts\run_speedup.ps1 -N 10 -J 5 -Repeats 20
```

If script execution is blocked, run the script with
`powershell -ExecutionPolicy Bypass -File .\scripts\run_speedup.ps1 ...`.

For a clean speedup curve, use `trace_bench` (above). `run_speedup.ps1`
measures the multi-process setting, where tracers share the CPU.

> **Interpreting the speedup:** all `j` tracer processes, plus the signers and
> the combiner, run on the same machine, and during tracing the `j` tracers
> work at the same time. Each tracer has its own pool of `p` threads, so they
> compete for the same cores. Expect the speedup to level off around
> *logical cores ÷ j*. For example, on 8 logical cores with j = 5 that is
> about 1.6×. For small `n` the per-tracer work is only a few milliseconds, so
> thread overhead is also significant.
