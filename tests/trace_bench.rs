use rayon::ThreadPoolBuilder;
use simulation_taps_tt_p::bench_config::tracer_thread_budget;
use simulation_taps_tt_p::trace_bench::{
    TraceBenchArgs, TraceFixture, TracerSample, default_thread_counts, parse_trace_bench_args,
    prepare, stats,
};

fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|s| s.to_string()).collect()
}

#[test]
fn thread_budget_shares_logical_cores_among_tracers() {
    assert_eq!(tracer_thread_budget(8, 1, None), 8);
    assert_eq!(tracer_thread_budget(8, 3, None), 2);
    assert_eq!(tracer_thread_budget(8, 5, None), 1);
    assert_eq!(tracer_thread_budget(8, 50, None), 1);
    assert_eq!(tracer_thread_budget(16, 4, None), 4);
}

#[test]
fn thread_budget_respects_a_valid_rayon_num_threads() {
    assert_eq!(tracer_thread_budget(8, 50, Some("4")), 4);
    assert_eq!(tracer_thread_budget(8, 1, Some(" 2 ")), 2);
    // Invalid values fall back to the automatic budget.
    assert_eq!(tracer_thread_budget(8, 2, Some("0")), 4);
    assert_eq!(tracer_thread_budget(8, 2, Some("many")), 4);
}

#[test]
fn default_thread_counts_are_powers_of_two_plus_the_core_count() {
    assert_eq!(default_thread_counts(8), vec![1, 2, 4, 8]);
    assert_eq!(default_thread_counts(12), vec![1, 2, 4, 8, 12]);
    assert_eq!(default_thread_counts(1), vec![1]);
}

#[test]
fn trace_bench_arguments_are_parsed() {
    assert_eq!(
        parse_trace_bench_args(&args(&["500", "50", "20"])).expect("valid"),
        TraceBenchArgs { n: 500, n3: 50, repeats: 20, threads: None }
    );
    assert_eq!(
        parse_trace_bench_args(&args(&["10", "5", "3", "1,2,4,8"])).expect("valid"),
        TraceBenchArgs { n: 10, n3: 5, repeats: 3, threads: Some(vec![1, 2, 4, 8]) }
    );
    assert!(parse_trace_bench_args(&args(&["10", "5"])).is_err());
    assert!(parse_trace_bench_args(&args(&["10", "0", "3"])).is_err());
    assert!(parse_trace_bench_args(&args(&["10", "5", "3", "1,0"])).is_err());
    assert!(parse_trace_bench_args(&args(&["10", "5", "3", ","])).is_err());
}

#[test]
fn stats_match_hand_computed_values() {
    let s = stats(&[10, 20, 30]);
    assert_eq!(s.samples, 3);
    assert!((s.mean - 20.0).abs() < 1e-9);
    assert!((s.std_dev - 10.0).abs() < 1e-9);
    assert_eq!((s.min, s.max), (10, 30));
}

#[test]
fn single_tracer_run_traces_the_quorum_for_every_thread_count() {
    for &(n, n3) in &[(10usize, 5usize), (7, 1), (12, 4)] {
        let fixture: TraceFixture = prepare(n, n3).expect("prepare");
        assert_eq!(fixture.peer_partials.len(), n3 - 1);
        for threads in [1usize, 2, 4] {
            let pool = ThreadPoolBuilder::new().num_threads(threads).build().expect("pool");
            let sample: TracerSample = pool
                .install(|| fixture.run_once())
                .unwrap_or_else(|e| panic!("n={} n3={} threads={}: {}", n, n3, threads, e));
            assert_eq!(
                sample.tracing_us(),
                sample.share_dec_us + sample.share_verify_us + sample.rec_us
            );
            assert_eq!(sample.total_us(), sample.verify_proof_us + sample.tracing_us());
        }
    }
}
