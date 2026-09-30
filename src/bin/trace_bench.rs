//! Single-tracer benchmark: the cryptographic runtime of ONE tracer that has
//! the machine to itself, for several rayon thread counts.
//!
//! `trace_bench <n> <n3> <repeats> [<threads>]`, e.g.
//! `cargo run --release --bin trace_bench -- 500 50 20 1,2,4,8`.
//! Results go to `trace_bench_summary.csv`.

use rayon::ThreadPoolBuilder;
use simulation_taps_tt_p::bench_config::Hardware;
use simulation_taps_tt_p::trace_bench::{
    self, Stats, TraceBenchArgs, TraceFixture, TracerSample, TRACE_BENCH_USAGE,
};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::Write;
use std::time::Instant;

const SUMMARY: &str = "trace_bench_summary.csv";

/// Runs one warm-up and `repeats` timed executions in a pool of `threads`.
fn measure(fixture: &TraceFixture, threads: usize, repeats: usize) -> Result<Vec<TracerSample>, String> {
    let pool = ThreadPoolBuilder::new()
        .num_threads(threads)
        .build()
        .map_err(|e| format!("cannot build a pool of {} threads: {}", threads, e))?;
    pool.install(|| -> Result<Vec<TracerSample>, String> {
        fixture.run_once()?; // warm-up, not recorded
        (0..repeats).map(|_| fixture.run_once()).collect()
    })
}

fn main() {
    let cli_args: Vec<String> = std::env::args().skip(1).collect();
    let args: TraceBenchArgs = match trace_bench::parse_trace_bench_args(&cli_args) {
        Ok(args) => args,
        Err(e) => {
            eprintln!("{}\n\n{}", e, TRACE_BENCH_USAGE);
            std::process::exit(2);
        }
    };

    let hardware: Hardware = Hardware::detect();
    let threads: Vec<usize> = args
        .threads
        .clone()
        .unwrap_or_else(|| trace_bench::default_thread_counts(hardware.logical_cores));

    println!("==================================================");
    println!("   TAPS_TT_P SINGLE-TRACER BENCHMARK");
    println!("==================================================");
    println!("Physical cores: {}", hardware.physical_cores);
    println!("Logical cores:  {}", hardware.logical_cores);
    println!(
        "n={} n3={} t={} t_e={} repeats={} threads={:?}",
        args.n,
        args.n3,
        trace_bench::signer_threshold(args.n),
        trace_bench::tracer_threshold(args.n3),
        args.repeats,
        threads
    );
    if threads[0] != 1 {
        println!("Note: speedup is relative to {} thread(s), not 1.", threads[0]);
    }

    println!("\nPreparing signature and the other tracers' partial decryptions (untimed)...");
    let start_prepare = Instant::now();
    let fixture: TraceFixture = match trace_bench::prepare(args.n, args.n3) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Preparation failed: {}", e);
            std::process::exit(1);
        }
    };
    println!("Prepared in {:.1} s.", start_prepare.elapsed().as_secs_f64());

    let mut file = File::create(SUMMARY).unwrap_or_else(|e| panic!("Cannot open {}: {}", SUMMARY, e));
    writeln!(
        file,
        "N,N3,Threads,Operation,Samples,Mean_Microseconds,Std_Dev_Microseconds,\
         Min_Microseconds,Max_Microseconds,Speedup,Efficiency"
    )
    .unwrap();

    // Mean per operation for the first thread count: the speedup reference.
    let mut reference: BTreeMap<&'static str, f64> = BTreeMap::new();

    println!(
        "\n{:>7}  {:<12} {:>14} {:>12} {:>8} {:>10}",
        "Threads", "Operation", "Mean (us)", "StdDev", "Speedup", "Efficiency"
    );
    for &p in &threads {
        let samples: Vec<TracerSample> = match measure(&fixture, p, args.repeats) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Run with {} thread(s) failed: {}", p, e);
                std::process::exit(1);
            }
        };

        let operations: Vec<&'static str> = samples[0].operations().iter().map(|(op, _)| *op).collect();
        for (k, op) in operations.iter().enumerate() {
            let values: Vec<u128> = samples.iter().map(|s| s.operations()[k].1).collect();
            let st: Stats = trace_bench::stats(&values);
            let base: f64 = *reference.entry(op).or_insert(st.mean);
            let speedup: f64 = if st.mean > 0.0 { base / st.mean } else { 0.0 };
            let efficiency: f64 = speedup / p as f64;

            writeln!(
                file,
                "{},{},{},{},{},{:.2},{:.2},{},{},{:.3},{:.3}",
                args.n, args.n3, p, op, st.samples, st.mean, st.std_dev, st.min, st.max, speedup, efficiency
            )
            .unwrap();
            println!(
                "{:>7}  {:<12} {:>14.1} {:>12.1} {:>8.3} {:>10.3}",
                p, op, st.mean, st.std_dev, speedup, efficiency
            );
        }
        file.flush().unwrap();
        println!();
    }

    println!("Every run traced exactly the signing quorum.");
    println!("Summary: {}", SUMMARY);
}
