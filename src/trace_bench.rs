//! Single-tracer benchmark (`bin/trace_bench.rs`).
//!
//! The multi-process benchmark co-locates all `n3` tracers on one machine,
//! so it measures them competing for the same cores. In a deployment every
//! tracer has its own machine. This module measures what one tracer computes
//! there, in one process, without networking: the other tracers' partial
//! decryptions are prepared beforehand (untimed), and the timed code is the
//! very same library code the tracer process runs (`Proofs::verify`,
//! `dkg::partial_decrypt`, `tracer::verify_and_trace`).
//!
//! Running it inside a rayon pool of 1 thread gives the sequential
//! reference (the same work as TAPS_TT); larger pools give the speedup.

use crate::tracer::{TraceContext, TraceTimings, verify_and_trace};
use rand::seq::SliceRandom;
use rand::thread_rng;
use rayon::prelude::*;
use secp256k1::{PublicKey, Scalar};
use std::collections::BTreeMap;
use std::time::Instant;
use taps_tt_p::protocol::dkg::{
    self, DecryptionInput, DkgBroadcast, DkgParticipant, PartialDecryption, TracerKeyShare,
};
use taps_tt_p::protocol::field::Fq;
use taps_tt_p::protocol::taps_tt_p::*;

/// Signer threshold `t = floor(n/2)+1`, as the Authority derives it.
pub fn signer_threshold(n: usize) -> usize {
    crate::authority::signer_threshold(n)
}

/// Tracer threshold `t_e = floor(2*n3/3)+1`, as the Authority derives it.
pub fn tracer_threshold(n3: usize) -> usize {
    crate::authority::tracer_threshold(n3)
}

/// Everything tracer #1 holds when the tracing step starts.
pub struct TraceFixture {
    pub n: usize,
    pub n3: usize,
    pub t: usize,
    pub te: usize,
    pub pk: PK,
    pub message: Vec<u8>,
    pub t_cipher: ElGamalCiphertext,
    pub v0: Vec<PublicKey>,
    pub v1: Vec<PublicKey>,
    pub proofs: Proofs,
    pub sigma: Sigma,
    /// DKG output of every tracer; index 0 is the benchmarked tracer.
    pub shares: Vec<TracerKeyShare>,
    /// Round-1 DKG broadcasts, keyed by 1-based tracer index.
    pub broadcasts: BTreeMap<usize, DkgBroadcast>,
    pub qual: Vec<usize>,
    /// Partial decryptions tracer #1 receives from tracers 2..=n3.
    pub peer_partials: Vec<PartialDecryption>,
    /// The quorum that signed, as 0-based signer indices.
    pub expected_quorum: Vec<usize>,
}

/// One timed execution of a tracer's cryptographic work, in microseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TracerSample {
    pub verify_proof_us: u128,
    pub share_dec_us: u128,
    pub share_verify_us: u128,
    pub rec_us: u128,
}

impl TracerSample {
    /// The cryptographic part of the baseline's `VerifySign` window.
    pub fn tracing_us(&self) -> u128 {
        self.share_dec_us + self.share_verify_us + self.rec_us
    }

    /// `VerifyProof` plus tracing.
    pub fn total_us(&self) -> u128 {
        self.verify_proof_us + self.tracing_us()
    }

    /// `(operation, microseconds)` pairs in reporting order.
    pub fn operations(&self) -> [(&'static str, u128); 6] {
        [
            ("VerifyProof", self.verify_proof_us),
            ("ShareDec", self.share_dec_us),
            ("ShareVerify", self.share_verify_us),
            ("Rec", self.rec_us),
            ("Tracing", self.tracing_us()),
            ("Total", self.total_us()),
        ]
    }
}

fn scalar_from_usize(value: usize) -> Scalar {
    let mut bytes: [u8; 32] = [0u8; 32];
    bytes[24..32].copy_from_slice(&(value as u64).to_be_bytes());
    Scalar::from_be_bytes(bytes).expect("small integer is a valid scalar")
}

/// Runs the tracers' DKG in memory, keeping the round-1 broadcasts (tracers
/// recompute every `vk_k` from them during ShareVerify).
fn run_dkg_with_broadcasts(
    te: usize,
    n3: usize,
) -> Result<(Vec<TracerKeyShare>, BTreeMap<usize, DkgBroadcast>, Vec<usize>), String> {
    let participants: Vec<DkgParticipant> = (1..=n3)
        .map(|index| DkgParticipant::new(index, te, n3))
        .collect::<Result<Vec<DkgParticipant>, String>>()?;
    let broadcasts: BTreeMap<usize, DkgBroadcast> = participants
        .iter()
        .map(|p| (p.index, p.broadcast.clone()))
        .collect();
    let qual: Vec<usize> = (1..=n3).collect();

    let shares: Vec<TracerKeyShare> = participants
        .iter()
        .map(|receiver| {
            let received: BTreeMap<usize, Fq> = participants
                .iter()
                .map(|dealer| (dealer.index, dealer.share_for(receiver.index)))
                .collect();
            receiver.finalize(&qual, &broadcasts, &received)
        })
        .collect::<Result<Vec<TracerKeyShare>, String>>()?;

    Ok((shares, broadcasts, qual))
}

/// Builds a signed run for `n` signers (a random quorum of exactly `t`
/// signs, as `Quorum::choose` does) and `n3` tracers, plus the partial
/// decryptions of tracers 2..=n3. Nothing here is timed.
pub fn prepare(n: usize, n3: usize) -> Result<TraceFixture, String> {
    if n == 0 || n3 == 0 {
        return Err("n and n3 must be at least 1".to_string());
    }
    let t: usize = signer_threshold(n);
    let te: usize = tracer_threshold(n3);

    let (shares, broadcasts, qual) = run_dkg_with_broadcasts(te, n3)?;
    let pk_e: PublicKey = shares[0].pk_e_as_public_key();

    let signers: Vec<KeyPair> = (0..n).map(|_| KeyPair::create()).collect();
    let kp_cs: KeyPair = KeyPair::create();
    let pk: PK = PK::set(&signers, &kp_cs, pk_e);

    let mut indices: Vec<usize> = (0..n).collect();
    indices.shuffle(&mut thread_rng());
    let mut bits: Vec<u8> = vec![0u8; n];
    for &i in indices.iter().take(t) {
        bits[i] = 1;
    }
    let expected_quorum: Vec<usize> = (0..n).filter(|&i| bits[i] == 1).collect();
    let quo: Quorum = Quorum::set(&pk, &bits);

    let commits: Vec<Commit> = (0..n).map(|_| Commit::commit()).collect();
    let commitments: Vec<Commitment> = commits.iter().map(Commitment::set).collect();
    let r_agg: PublicKey =
        Commitment::aggregate(&commitments, &quo).map_err(|e| format!("aggregate R: {}", e))?;

    let psi: Secret = Secret::create();
    let t_cipher: ElGamalCiphertext =
        ElGamalCiphertext::encrypt_value(&psi, &scalar_from_usize(t));
    let message: Vec<u8> = b"TAPS_TT_P single-tracer benchmark".to_vec();
    let c: Scalar = compute_challenge_c(&pk, &t_cipher, &r_agg, &message);

    let sign_shares: Vec<Sign> = signers
        .iter()
        .zip(commits.iter())
        .map(|(kp, comm)| Sign::sign(comm, kp, &c))
        .collect();
    let z: Sign = Sign::aggregate(&sign_shares, &quo);

    let rho: Secret = Secret::create();
    let ct: ElGamalCiphertext = ElGamalCiphertext::encrypt(&rho, &z, &pk);
    let (gammas, ciphertexts): (Vec<Secret>, Vec<ElGamalCiphertext>) =
        encrypt_bits_threshold(&quo, &pk_e);
    let v0: Vec<PublicKey> = ciphertexts.iter().map(|cipher| cipher.c0).collect();
    let v1: Vec<PublicKey> = ciphertexts.iter().map(|cipher| cipher.c1).collect();

    let (alpha, beta, proofs, blinds): (Scalar, Scalar, Proofs, Blinds) = {
        let stmt: Statement = Statement {
            pk: &pk,
            T: &t_cipher,
            R: &r_agg,
            m: &message,
            ct: &ct,
            v0: &v0,
            v: &v1,
        };
        let alpha: Scalar = stmt.alpha(&c);
        let blinds: Blinds = Blinds::set(n);
        let proofs: Proofs = Proofs::compute_proofs(&blinds, &pk, &pk_e, &v1, &c, &alpha);
        let beta: Scalar = stmt.beta(&alpha, &proofs);
        (alpha, beta, proofs, blinds)
    };
    let phis: Phis = Phis::set(&alpha, &gammas, &quo);
    let witnesses: Witnesses = Witnesses::set(z, rho, &gammas, psi, &quo, &phis);
    let hats: Hats = Hats::set(&beta, &witnesses, &blinds);
    let sigma: Sigma = Sigma::sign(&kp_cs, &message, &r_agg, &ct, Pi { beta, hats });

    let input: DecryptionInput = DecryptionInput::from_public_keys(&ct.c0, &ct.c1, &v0, &v1);
    let peer_partials: Vec<PartialDecryption> = shares[1..]
        .par_iter()
        .map(|share: &TracerKeyShare| dkg::partial_decrypt(share, &input))
        .collect();

    Ok(TraceFixture {
        n,
        n3,
        t,
        te,
        pk,
        message,
        t_cipher,
        v0,
        v1,
        proofs,
        sigma,
        shares,
        broadcasts,
        qual,
        peer_partials,
        expected_quorum,
    })
}

impl TraceFixture {
    fn statement(&self) -> Statement<'_> {
        Statement {
            pk: &self.pk,
            T: &self.t_cipher,
            R: &self.sigma.R,
            m: &self.message,
            ct: &self.sigma.ct,
            v0: &self.v0,
            v: &self.v1,
        }
    }

    fn decryption_input(&self) -> DecryptionInput {
        DecryptionInput::from_public_keys(&self.sigma.ct.c0, &self.sigma.ct.c1, &self.v0, &self.v1)
    }

    /// Tracer #1's cryptographic work once, in the current rayon pool:
    /// VerifyProof, ShareDec, ShareVerify and Rec, timed exactly like the
    /// tracer process times them. Fails if verification rejects or the
    /// traced quorum differs from the signing quorum.
    pub fn run_once(&self) -> Result<TracerSample, String> {
        let stmt: Statement = self.statement();

        let start_verify_proof = Instant::now();
        let proof_ok: bool = Proofs::verify(&self.proofs, &self.sigma, &stmt)?;
        let verify_proof_us: u128 = start_verify_proof.elapsed().as_micros();
        if !proof_ok {
            return Err("accountability proof rejected".to_string());
        }

        let start_share_dec = Instant::now();
        let input: DecryptionInput = self.decryption_input();
        let own_partial: PartialDecryption = dkg::partial_decrypt(&self.shares[0], &input);
        let share_dec_us: u128 = start_share_dec.elapsed().as_micros();

        // Same order as the tracer process: peers' partials, then its own.
        let mut partials: Vec<PartialDecryption> = self.peer_partials.clone();
        partials.push(own_partial);

        let context: TraceContext = TraceContext {
            input,
            qual: &self.qual,
            broadcasts: &self.broadcasts,
            te: self.te,
            t: self.t,
            pk: &self.pk,
            R: &self.sigma.R,
            c: stmt.c(),
        };
        let (quorum, timings): (Vec<usize>, TraceTimings) = verify_and_trace(&context, partials)?;
        if quorum != self.expected_quorum {
            return Err("traced quorum differs from the signing quorum".to_string());
        }

        Ok(TracerSample {
            verify_proof_us,
            share_dec_us,
            share_verify_us: timings.share_verify_us,
            rec_us: timings.rec_us,
        })
    }
}

/// Mean, sample standard deviation, min and max of a set of timings.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Stats {
    pub samples: usize,
    pub mean: f64,
    pub std_dev: f64,
    pub min: u128,
    pub max: u128,
}

pub fn stats(values: &[u128]) -> Stats {
    let count: usize = values.len();
    if count == 0 {
        return Stats {
            samples: 0,
            mean: 0.0,
            std_dev: 0.0,
            min: 0,
            max: 0,
        };
    }
    let mean: f64 = values.iter().map(|&v| v as f64).sum::<f64>() / count as f64;
    let std_dev: f64 = if count > 1 {
        let squares: f64 = values.iter().map(|&v| (v as f64 - mean).powi(2)).sum();
        (squares / (count - 1) as f64).sqrt()
    } else {
        0.0
    };
    Stats {
        samples: count,
        mean,
        std_dev,
        min: *values.iter().min().expect("non-empty"),
        max: *values.iter().max().expect("non-empty"),
    }
}

/// 1, 2, 4, ... up to `logical_cores`, plus `logical_cores` itself.
pub fn default_thread_counts(logical_cores: usize) -> Vec<usize> {
    let mut counts: Vec<usize> = Vec::new();
    let mut p: usize = 1;
    while p <= logical_cores.max(1) {
        counts.push(p);
        p *= 2;
    }
    if !counts.contains(&logical_cores) && logical_cores > 0 {
        counts.push(logical_cores);
    }
    counts
}

/// `trace_bench <n> <n3> <repeats> [<threads>]` arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceBenchArgs {
    pub n: usize,
    pub n3: usize,
    pub repeats: usize,
    /// `None` = [`default_thread_counts`].
    pub threads: Option<Vec<usize>>,
}

pub const TRACE_BENCH_USAGE: &str = "Usage: trace_bench <n> <n3> <repeats> [<threads>]\n\
     \n  <n>        number of signers, at least 1\
     \n  <n3>       number of tracers, at least 1\
     \n  <repeats>  timed runs per thread count, at least 1\
     \n  <threads>  comma-separated rayon thread counts, e.g. 1,2,4,8\
     \n             (default: 1, 2, 4, ... up to the logical core count)";

fn parse_count(value: &str, name: &str) -> Result<usize, String> {
    match value.trim().parse::<usize>() {
        Ok(v) if v >= 1 => Ok(v),
        _ => Err(format!("Invalid {}: '{}' (expected an integer >= 1)", name, value)),
    }
}

pub fn parse_trace_bench_args(args: &[String]) -> Result<TraceBenchArgs, String> {
    if args.len() != 3 && args.len() != 4 {
        return Err(format!("Expected 3 or 4 arguments, got {}", args.len()));
    }
    let threads: Option<Vec<usize>> = match args.get(3) {
        None => None,
        Some(list) => Some(
            list.split(',')
                .filter(|item| !item.trim().is_empty())
                .map(|item| parse_count(item, "thread count"))
                .collect::<Result<Vec<usize>, String>>()?,
        ),
    };
    if let Some(list) = &threads {
        if list.is_empty() {
            return Err("The thread list is empty".to_string());
        }
    }
    Ok(TraceBenchArgs {
        n: parse_count(&args[0], "n")?,
        n3: parse_count(&args[1], "n3")?,
        repeats: parse_count(&args[2], "repeats")?,
        threads,
    })
}
