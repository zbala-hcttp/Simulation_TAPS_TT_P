//! Command-line configuration of the benchmark suite (`bin/benchmark.rs`).

/// One `(n_1, n_3)` scenario and how many times to run it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Scenario {
    /// Number of signers `n_1`.
    pub n: usize,
    /// Number of tracers `n_3`.
    pub n3: usize,
    /// How many times the scenario is run back to back.
    pub repeats: usize,
}

pub const USAGE: &str = "Usage: benchmark [<n> <n3> [<repeats>]]\n\
     \n  <n>        number of signers (n_1), at least 1\
     \n  <n3>       number of tracers (n_3), at least 1\
     \n  <repeats>  how many times to run the scenario (default 1)\
     \n\nWith no arguments, runs the default suite once per scenario.";

/// The suite run when no arguments are given, each scenario once.
pub fn default_scenarios() -> Vec<Scenario> {
    [
        (10, 1),
        (10, 5),
        (25, 1),
        (25, 5),
        (50, 1),
        (50, 5),
        (100, 1),
        (100, 5),
    ]
    .into_iter()
    .map(|(n, n3)| Scenario { n, n3, repeats: 1 })
    .collect()
}

/// Physical and logical core counts of this machine, and the rayon thread
/// count every actor process will use (they inherit `RAYON_NUM_THREADS`
/// from the benchmark process).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hardware {
    pub physical_cores: usize,
    pub logical_cores: usize,
    /// Raw `RAYON_NUM_THREADS` value, if set.
    pub rayon_env: Option<String>,
    /// Threads rayon actually uses in this process.
    pub rayon_threads: usize,
}

impl Hardware {
    pub fn detect() -> Hardware {
        Hardware {
            physical_cores: num_cpus::get_physical(),
            logical_cores: num_cpus::get(),
            rayon_env: std::env::var("RAYON_NUM_THREADS").ok(),
            rayon_threads: rayon::current_num_threads(),
        }
    }

    pub fn describe(&self) -> String {
        let threads: String = match &self.rayon_env {
            Some(value) => format!("{} (every tracer uses {} threads)", value, self.rayon_threads),
            None => "<unset> (each tracer uses max(1, logical cores / n3) threads)".to_string(),
        };
        format!(
            "Physical cores: {}\nLogical cores:  {}\nRAYON_NUM_THREADS: {}",
            self.physical_cores, self.logical_cores, threads
        )
    }
}

/// Rayon threads each tracer process should use.
///
/// All `n3` tracers run on this machine at once, so by default each gets an
/// equal share of the logical cores, `max(1, floor(logical / n3))`: this
/// keeps the machine from being oversubscribed with `n3 * logical` threads,
/// whose contention made the parallel code slower than the baseline. An
/// explicit, valid `RAYON_NUM_THREADS` (e.g. from the speedup script) wins.
pub fn tracer_thread_budget(logical_cores: usize, n3: usize, rayon_env: Option<&str>) -> usize {
    if let Some(value) = rayon_env {
        if let Ok(threads) = value.trim().parse::<usize>() {
            if threads >= 1 {
                return threads;
            }
        }
    }
    (logical_cores / n3.max(1)).max(1)
}

/// Sizes rayon's global pool for a tracer process according to
/// [`tracer_thread_budget`]. Must run before the tracer's first parallel
/// operation. Returns the number of threads rayon uses.
pub fn apply_tracer_thread_budget(n3: usize) -> usize {
    let env: Option<String> = std::env::var("RAYON_NUM_THREADS").ok();
    let threads: usize = tracer_thread_budget(num_cpus::get(), n3, env.as_deref());
    if let Err(e) = rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build_global()
    {
        eprintln!("[Tracer] Could not size the rayon pool ({}); using the default", e);
    }
    rayon::current_num_threads()
}

fn parse_positive(value: &str, name: &str) -> Result<usize, String> {
    match value.parse::<usize>() {
        Ok(v) if v >= 1 => Ok(v),
        _ => Err(format!("Invalid {}: '{}' (expected an integer >= 1)", name, value)),
    }
}

/// Parses the arguments after the program name.
///
/// - no arguments: the default suite;
/// - `<n> <n3>`: that scenario, once;
/// - `<n> <n3> <repeats>`: that scenario, `repeats` times.
pub fn parse_args(args: &[String]) -> Result<Vec<Scenario>, String> {
    match args {
        [] => Ok(default_scenarios()),
        [n, n3] => Ok(vec![Scenario {
            n: parse_positive(n, "n")?,
            n3: parse_positive(n3, "n3")?,
            repeats: 1,
        }]),
        [n, n3, repeats] => Ok(vec![Scenario {
            n: parse_positive(n, "n")?,
            n3: parse_positive(n3, "n3")?,
            repeats: parse_positive(repeats, "repeats")?,
        }]),
        _ => Err(format!("Expected 0, 2 or 3 arguments, got {}", args.len())),
    }
}
