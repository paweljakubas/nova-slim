//! Synthetic NovaSlim benchmark -- copy-state step circuit.
//!
//! Generates a synthetic step circuit and random witnesses in memory,
//! then benchmarks the full slim IVC flow (fold -> compress -> verify).
//!
//! Usage:
//!   cargo run --release --bin benchmark_synthetic -- --curve bls12-381 --state-width N --steps M [--opt-parallel] [--commitment pedersen|sis|hash|module-sis] [--module-sis-params IDX] [--batch-size N] [--bound-bits B] [--write-circuit step.r1cs] [--write-steps DIR]

use std::sync::OnceLock;

use ark_ff::Zero;
use ark_serialize::CanonicalSerialize;
use blake2::Digest;
use prover::circuit::{r1cs_to_bytes_sparse, SparseCircuit};
use prover::codec;
use prover::commitment::{
    CommitmentScheme, HashCommitment, ModuleSisCommitment, PedersenCommitment, SisCommitment,
};
use prover::nifs;
use prover::norm;
use prover::{
    curve::{NovaCurve, ScalarField},
    fr_to_string, prove_level1, prove_sumcheck_compression_opt, prove_windows, verify_full,
    verify_slim, verify_slim_level1, verify_sumcheck_compression_opt, verify_windows,
    NifsBundle, NifsFinalInstance, NifsFoldOutput, NifsSumcheckProof, OptFlags,
    DEFAULT_SIS_PARAM, DEFAULT_WINDOW_SIZE, NIFS_PARAMS_SEED, NIFS_TRANSCRIPT_PREFIX,
};
use std::time::Instant;

/// Optional `--write-circuit`/`--write-steps` output paths (set once in `main`),
/// used to export the in-memory canonical-io circuit + witnesses for
/// `benchmark_nova` / the CLI.
static WRITE_CIRCUIT: OnceLock<Option<std::path::PathBuf>> = OnceLock::new();
static WRITE_STEPS: OnceLock<Option<std::path::PathBuf>> = OnceLock::new();

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let opt_parallel = args.iter().any(|a| a == "--opt-parallel");
    let curve = args
        .iter()
        .position(|a| a == "--curve")
        .map(|i| args[i + 1].clone());
    let commitment = args
        .iter()
        .position(|a| a == "--commitment")
        .map(|i| args[i + 1].clone());
    let state_width = args
        .windows(2)
        .find(|w| w[0] == "--state-width")
        .map(|w| {
            w[1].parse::<usize>()
                .expect("--state-width must be a positive integer")
        })
        .unwrap_or(2);
    let n_steps = args
        .windows(2)
        .find(|w| w[0] == "--steps")
        .map(|w| {
            w[1].parse::<usize>()
                .expect("--steps must be a positive integer")
        })
        .unwrap_or(100);
    let sis_param = args
        .windows(2)
        .find(|w| w[0] == "--sis-param")
        .map(|w| {
            w[1].parse::<usize>()
                .expect("--sis-param must be a positive integer")
        })
        .unwrap_or(DEFAULT_SIS_PARAM);
    let batch_size = args
        .windows(2)
        .find(|w| w[0] == "--batch-size")
        .map(|w| {
            w[1].parse::<usize>()
                .expect("--batch-size must be a positive integer")
        })
        .unwrap_or(0);
    let bound_bits = args
        .windows(2)
        .find(|w| w[0] == "--bound-bits")
        .map(|w| {
            w[1].parse::<u32>()
                .expect("--bound-bits must be a positive integer")
        })
        .unwrap_or(256);
    let module_sis_params = args
        .windows(2)
        .find(|w| w[0] == "--module-sis-params")
        .map(|w| {
            w[1].parse::<usize>()
                .expect("--module-sis-params must be a positive integer")
        })
        .unwrap_or(0);
    WRITE_CIRCUIT
        .set(
            args.windows(2)
                .find(|w| w[0] == "--write-circuit")
                .map(|w| std::path::PathBuf::from(&w[1])),
        )
        .ok();
    WRITE_STEPS
        .set(
            args.windows(2)
                .find(|w| w[0] == "--write-steps")
                .map(|w| std::path::PathBuf::from(&w[1])),
        )
        .ok();

    let curve = curve.as_deref().unwrap_or("bls12-381");
    let commitment = commitment.as_deref().unwrap_or("pedersen");
    match (curve, commitment) {
        ("bls12-381", "pedersen") => benchmark::<
            prover::curve::Bls12_381,
            PedersenCommitment<prover::curve::Bls12_381>,
        >(state_width, n_steps, opt_parallel, sis_param, batch_size, bound_bits),
        #[cfg(feature = "bn254")]
        ("bn254", "pedersen") => benchmark::<
            prover::curve::Bn254,
            PedersenCommitment<prover::curve::Bn254>,
        >(state_width, n_steps, opt_parallel, sis_param, batch_size, bound_bits),
        #[cfg(feature = "pallas")]
        ("pallas", "pedersen") => benchmark::<
            prover::curve::Pallas,
            PedersenCommitment<prover::curve::Pallas>,
        >(state_width, n_steps, opt_parallel, sis_param, batch_size, bound_bits),
        #[cfg(feature = "vesta")]
        ("vesta", "pedersen") => benchmark::<
            prover::curve::Vesta,
            PedersenCommitment<prover::curve::Vesta>,
        >(state_width, n_steps, opt_parallel, sis_param, batch_size, bound_bits),
        #[cfg(feature = "grumpkin")]
        ("grumpkin", "pedersen") => benchmark::<
            prover::curve::Grumpkin,
            PedersenCommitment<prover::curve::Grumpkin>,
        >(state_width, n_steps, opt_parallel, sis_param, batch_size, bound_bits),
        #[cfg(feature = "bandersnatch")]
        ("bandersnatch", "pedersen") => benchmark::<
            prover::curve::Bandersnatch,
            PedersenCommitment<prover::curve::Bandersnatch>,
        >(state_width, n_steps, opt_parallel, sis_param, batch_size, bound_bits),
        ("bls12-381", "sis") => benchmark::<
            prover::curve::Bls12_381,
            SisCommitment<prover::curve::Bls12_381>,
        >(state_width, n_steps, opt_parallel, sis_param, batch_size, bound_bits),
        #[cfg(feature = "bn254")]
        ("bn254", "sis") => benchmark::<prover::curve::Bn254, SisCommitment<prover::curve::Bn254>>(
            state_width,
            n_steps,
            opt_parallel,
            sis_param,
        ),
        #[cfg(feature = "pallas")]
        ("pallas", "sis") => {
            benchmark::<prover::curve::Pallas, SisCommitment<prover::curve::Pallas>>(
                state_width,
                n_steps,
                opt_parallel,
                sis_param,
            )
        }
        #[cfg(feature = "vesta")]
        ("vesta", "sis") => benchmark::<prover::curve::Vesta, SisCommitment<prover::curve::Vesta>>(
            state_width,
            n_steps,
            opt_parallel,
            sis_param,
        ),
        #[cfg(feature = "grumpkin")]
        ("grumpkin", "sis") => benchmark::<
            prover::curve::Grumpkin,
            SisCommitment<prover::curve::Grumpkin>,
        >(state_width, n_steps, opt_parallel, sis_param, batch_size, bound_bits),
        #[cfg(feature = "bandersnatch")]
        ("bandersnatch", "sis") => benchmark::<
            prover::curve::Bandersnatch,
            SisCommitment<prover::curve::Bandersnatch>,
        >(state_width, n_steps, opt_parallel, sis_param, batch_size, bound_bits),
        ("bls12-381", "module-sis") => benchmark::<
            prover::curve::Bls12_381,
            ModuleSisCommitment<prover::curve::Bls12_381>,
        >(state_width, n_steps, opt_parallel, module_sis_params, batch_size, bound_bits),
        #[cfg(feature = "bn254")]
        ("bn254", "module-sis") => benchmark::<
            prover::curve::Bn254,
            ModuleSisCommitment<prover::curve::Bn254>,
        >(state_width, n_steps, opt_parallel, module_sis_params, batch_size, bound_bits),
        #[cfg(feature = "pallas")]
        ("pallas", "module-sis") => benchmark::<
            prover::curve::Pallas,
            ModuleSisCommitment<prover::curve::Pallas>,
        >(state_width, n_steps, opt_parallel, module_sis_params, batch_size, bound_bits),
        #[cfg(feature = "vesta")]
        ("vesta", "module-sis") => benchmark::<
            prover::curve::Vesta,
            ModuleSisCommitment<prover::curve::Vesta>,
        >(state_width, n_steps, opt_parallel, module_sis_params, batch_size, bound_bits),
        #[cfg(feature = "grumpkin")]
        ("grumpkin", "module-sis") => benchmark::<
            prover::curve::Grumpkin,
            ModuleSisCommitment<prover::curve::Grumpkin>,
        >(state_width, n_steps, opt_parallel, module_sis_params, batch_size, bound_bits),
        #[cfg(feature = "bandersnatch")]
        ("bandersnatch", "module-sis") => benchmark::<
            prover::curve::Bandersnatch,
            ModuleSisCommitment<prover::curve::Bandersnatch>,
        >(state_width, n_steps, opt_parallel, module_sis_params, batch_size, bound_bits),
        ("bls12-381", "hash") => benchmark::<
            prover::curve::Bls12_381,
            HashCommitment<prover::curve::Bls12_381>,
        >(state_width, n_steps, opt_parallel, sis_param, batch_size, bound_bits),
        #[cfg(feature = "bn254")]
        ("bn254", "hash") => {
            benchmark::<prover::curve::Bn254, HashCommitment<prover::curve::Bn254>>(
                state_width,
                n_steps,
                opt_parallel,
                sis_param,
            )
        }
        #[cfg(feature = "pallas")]
        ("pallas", "hash") => benchmark::<
            prover::curve::Pallas,
            HashCommitment<prover::curve::Pallas>,
        >(state_width, n_steps, opt_parallel, sis_param, batch_size, bound_bits),
        #[cfg(feature = "vesta")]
        ("vesta", "hash") => {
            benchmark::<prover::curve::Vesta, HashCommitment<prover::curve::Vesta>>(
                state_width,
                n_steps,
                opt_parallel,
                sis_param,
            )
        }
        #[cfg(feature = "grumpkin")]
        ("grumpkin", "hash") => benchmark::<
            prover::curve::Grumpkin,
            HashCommitment<prover::curve::Grumpkin>,
        >(state_width, n_steps, opt_parallel, sis_param, batch_size, bound_bits),
        #[cfg(feature = "bandersnatch")]
        ("bandersnatch", "hash") => benchmark::<
            prover::curve::Bandersnatch,
            HashCommitment<prover::curve::Bandersnatch>,
        >(state_width, n_steps, opt_parallel, sis_param, batch_size, bound_bits),
        _ => {
            eprintln!("unknown curve/commitment: {curve}/{commitment} — valid curves: bls12-381, bn254, pallas, vesta, grumpkin, bandersnatch; valid commitments: pedersen, sis, hash, module-sis");
            std::process::exit(2);
        }
    }
}

fn benchmark<C: NovaCurve, CS: CommitmentScheme<Scalar = ScalarField<C>>>(
    state_width: usize,
    n_steps: usize,
    opt_parallel: bool,
    sis_param: usize,
    batch_size: usize,
    bound_bits: u32,
)
where
    CS::Scalar: ark_ff::PrimeField,
{
    let type_name = std::any::type_name::<CS>();
    let scheme_name = if type_name.contains("ModuleSis") {
        "module-sis"
    } else if type_name.contains("Sis") {
        "sis"
    } else if type_name.contains("Hash") {
        "hash"
    } else {
        "pedersen"
    };
    println!(
        "synthetic benchmark: state_width={state_width}, steps={n_steps}, curve={}, commitment={scheme_name} (sis param / module-sis index = {sis_param})",
        std::any::type_name::<C>()
    );
    if scheme_name == "module-sis" {
        let base =
            prover::module_sis::ModuleSisParams::ALL[sis_param % prover::module_sis::ModuleSisParams::ALL.len()];
        println!(
            "module-sis parameter set: {} (n={}, q={}, d={}, m={}, beta=2^{})",
            base.label(),
            base.n,
            base.q,
            base.d,
            base.m,
            base.beta_bits
        );
    }

    let n_wires = 1 + 2 * state_width;
    let n_pub_out = state_width as u32;
    let n_pub_in = state_width as u32;
    let n_prv_in = 0u32;
    let mut l = Vec::new();
    let mut r = Vec::new();
    let mut o = Vec::new();
    for i in 0..state_width {
        l.push(vec![(
            (1 + state_width + i) as u32,
            ScalarField::<C>::from(1u64),
        )]);
        r.push(vec![(0u32, ScalarField::<C>::from(1u64))]);
        o.push(vec![((1 + i) as u32, ScalarField::<C>::from(1u64))]);
    }

    let r1cs_bytes =
        r1cs_to_bytes_sparse(n_wires as u32, n_pub_out, n_pub_in, n_prv_in, &l, &r, &o);
    let mut circuit = SparseCircuit::<ScalarField<C>>::from_bytes(&r1cs_bytes)
        .expect("failed to parse synthetic r1cs");

    let mut witnesses: Vec<Vec<ScalarField<C>>> = Vec::with_capacity(n_steps);
    let state: Vec<u64> = (0..state_width).map(|i| (i + 1) as u64).collect();
    for _ in 0..n_steps {
        let mut w = vec![ScalarField::<C>::from(1u64)];
        for &s in &state {
            w.push(ScalarField::<C>::from(s));
        }
        for &s in &state {
            w.push(ScalarField::<C>::from(s));
        }
        witnesses.push(w);
    }

    if let Some(p) = WRITE_CIRCUIT.get().unwrap().as_ref() {
        std::fs::write(p, &r1cs_bytes).expect("failed to write step circuit");
        println!("step circuit written to {}", p.display());
    }
    if let Some(d) = WRITE_STEPS.get().unwrap().as_ref() {
        std::fs::create_dir_all(d).expect("failed to create steps dir");
        for (i, w) in witnesses.iter().enumerate() {
            std::fs::write(
                d.join(format!("step_{i:04}.wtns")),
                wtns_bytes_from_le(&w),
            )
            .expect("failed to write step witness");
        }
        println!("step witnesses written to {} ({} files)", d.display(), n_steps);
    }

    let opt = if opt_parallel {
        OptFlags::PARALLEL
    } else {
        OptFlags::NONE
    };
    let mode = if opt_parallel { "parallel" } else { "baseline" };

    let t = Instant::now();
    let folded = if batch_size > 0 {
        nifs_fold_in_memory_batch::<C, CS>(&mut circuit, &witnesses, sis_param, batch_size, bound_bits)
    } else {
        nifs_fold_in_memory::<C, CS>(&mut circuit, &witnesses, opt_parallel, sis_param)
    };
    let fold_s = t.elapsed().as_secs_f64();
    let mode_str = if batch_size > 0 {
        format!("batch (size={batch_size})")
    } else {
        mode.to_string()
    };
    println!(
        "nifs fold ({mode_str}): {fold_s:.3} s total, {:.3} ms/step over {n_steps} steps",
        fold_s * 1000.0 / n_steps as f64
    );

    // Ring-residue folds (Module-SIS) are NOT field-homomorphic: a sumcheck
    // over the folded accumulator is not a valid relation there, because the
    // folded instance is a canonical mod-q residue, not the field-linear
    // combination.  The production artifact for ring folds is the window
    // model (W1 transport fold + per-window W2 verification), so verify that
    // instead of the field-only compress/level-1 chain below.
    let ring_fold = CS::ring_modulus(&CS::params_from_seed(
        NIFS_PARAMS_SEED,
        1 + 2 * state_width,
        state_width,
        sis_param,
    ))
    .is_some();
    if ring_fold {
        println!("mode: NIFS fold + window-model verify (ring fold)");
        let t = Instant::now();
        let ws = prove_windows::<C, CS>(&circuit, &folded, DEFAULT_WINDOW_SIZE, opt)
            .unwrap_or_else(|e| panic!("failed to build window proof: {e}"));
        let windows_prove_s = t.elapsed().as_secs_f64();
        let n_windows = ws.windows.len();

        let t = Instant::now();
        verify_windows::<C, CS>(&folded.bundle, &ws, sis_param, &circuit)
            .unwrap_or_else(|e| panic!("window verification failed: {e}"));
        let windows_verify_s = t.elapsed().as_secs_f64();

        let bundle_cbor = folded
            .bundle
            .to_cbor::<ScalarField<C>>()
            .expect("bundle serialization should not fail");
        let ws_cbor = codec::windows_proof_encode::<ScalarField<C>>(&ws)
            .expect("window proof serialization should not fail");
        let base = prover::module_sis::ModuleSisParams::ALL
            [sis_param % prover::module_sis::ModuleSisParams::ALL.len()];
        println!(
            "windows compress: {windows_prove_s:.3} s ({n_windows} windows of <= {DEFAULT_WINDOW_SIZE} steps)"
        );
        println!(
            "verify (windows): {windows_verify_s:.4} s (W2 per-window sumcheck + canonical-lift + binding)"
        );
        println!(
            "nifs bundle: {} B ({:.1} KiB cbor), O(1) in the step count",
            bundle_cbor.len(),
            bundle_cbor.len() as f64 / 1024.0
        );
        println!(
            "windows proof: {} B ({:.1} KiB cbor) — production on-chain artifact",
            ws_cbor.len(),
            ws_cbor.len() as f64 / 1024.0
        );
        println!(
            "w_commit/e_commit (ring) size: {} B each ({} B total on-chain) [{}]",
            base.commitment_size(),
            base.commitment_size() * 2,
            base.label()
        );
        println!("all verifications OK");
        return;
    }
    println!("mode: NIFS fold + sumcheck compress ({mode})");

    let mut rng = rand::thread_rng();
    let t = Instant::now();
    let sc_proof = prove_sumcheck_compression_opt::<C, CS>(&circuit, &folded, &mut rng, opt)
        .unwrap_or_else(|e| panic!("failed to build sumcheck compression proof: {e}"));
    let compress_s = t.elapsed().as_secs_f64();
    println!("sumcheck compress: {:.3} s", compress_s);

    let t = Instant::now();
    verify_sumcheck_compression_opt::<C, CS>(&folded.bundle, &sc_proof, sis_param, Some(&circuit))
        .unwrap_or_else(|e| panic!("full verification failed: {e}"));
    println!("verify (full): {:.4} s", t.elapsed().as_secs_f64());

    let slim = sc_proof.to_slim();
    let t = Instant::now();
    verify_slim::<C, CS>(&folded.bundle, &slim)
        .unwrap_or_else(|e| panic!("slim verification failed: {e}"));
    println!("verify (slim): {:.4} s", t.elapsed().as_secs_f64());

    // ── Level-1 proof: generate, serialize, verify_full ──────────────
    let t = Instant::now();
    let l1_proof = prove_level1::<C, CS>(&circuit, &folded, opt, norm::NormMode::None, 64)
        .unwrap_or_else(|e| panic!("failed to build level-1 proof: {e}"));
    let l1_prove_s = t.elapsed().as_secs_f64();
    println!("prove (level-1): {:.3} s", l1_prove_s);

    let l1_cbor = codec::level1_proof_encode::<ScalarField<C>>(&l1_proof).unwrap();
    let l1_cbor_len = l1_cbor.len();
    println!(
        "level-1 proof: {} B ({:.1} KiB cbor)",
        l1_cbor_len,
        l1_cbor_len as f64 / 1024.0
    );

    let t = Instant::now();
    verify_slim_level1::<C, CS>(&folded.bundle, &l1_proof, sis_param, Some(&circuit))
        .unwrap_or_else(|e| panic!("level-1 verification failed: {e}"));
    println!("verify (level-1): {:.4} s", t.elapsed().as_secs_f64());

    let t = Instant::now();
    verify_full::<C, CS>(
        &folded.bundle,
        &l1_proof,
        sis_param,
        Some(&circuit),
        norm::NormMode::None,
        None,
        None,
        64,
        opt,
    )
    .unwrap_or_else(|e| panic!("verify_full failed: {e}"));
    println!("verify (full): {:.4} s", t.elapsed().as_secs_f64());

    let bundle_cbor = folded.bundle.to_cbor::<ScalarField<C>>().unwrap();
    let slim_cbor = slim.to_cbor::<ScalarField<C>>().unwrap();
    println!(
        "nifs bundle: {} B ({:.1} KiB cbor), O(1) in step count",
        bundle_cbor.len(),
        bundle_cbor.len() as f64 / 1024.0
    );
    println!(
        "slim proof: {} B ({:.1} KiB cbor)",
        slim_cbor.len(),
        slim_cbor.len() as f64 / 1024.0
    );
    println!("all verifications OK");

    // Memory scaling: print peak RSS.
    if let Some(rss_kb) = read_rss_kb() {
        println!("peak RSS: {rss_kb} KiB ({:.1} MiB)", rss_kb as f64 / 1024.0);
    }
}

fn read_rss_kb() -> Option<usize> {
    std::fs::read_to_string("/proc/self/status")
        .ok()?
        .lines()
        .find(|l| l.starts_with("VmRSS:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|n| n.parse().ok())
}

fn nifs_fold_in_memory<C: NovaCurve, CS: CommitmentScheme<Scalar = ScalarField<C>>>(
    circuit: &mut SparseCircuit<ScalarField<C>>,
    witnesses: &[Vec<ScalarField<C>>],
    parallel: bool,
    sis_param: usize,
) -> NifsFoldOutput<CS> {
    let n_pub_out = circuit.n_pub_out as usize;
    let n_pub_in = circuit.n_pub_in as usize;
    let n_wires = circuit.n_wires as usize;
    let n_constraints = circuit.n_constraints as usize;

    let params = CS::params_from_seed(NIFS_PARAMS_SEED, n_wires, n_constraints, sis_param);
    let zero_e = vec![ScalarField::<C>::zero(); n_constraints];

    let mut acc_hash: Option<Vec<u8>> = None;
    let mut prev_out: Option<Vec<String>> = None;
    let mut initial_state: Vec<String> = Vec::new();
    let mut acc_u: Option<nifs::RelaxedR1csInstance<CS>> = None;
    let mut acc_w: Option<nifs::RelaxedR1csWitness<CS>> = None;
    let mut step_witnesses: Vec<(Vec<String>, Vec<String>)> = Vec::new();

    for w in witnesses {
        circuit.witness = w.clone();
        let out_fr = &w[1..1 + n_pub_out];
        let in_fr = &w[1 + n_pub_out..1 + n_pub_out + n_pub_in];
        let state_in: Vec<String> = in_fr.iter().map(fr_to_string).collect();
        let state_out: Vec<String> = out_fr.iter().map(fr_to_string).collect();
        if let Some(prev) = &prev_out {
            assert_eq!(
                &state_in, prev,
                "state_in does not chain to previous state_out"
            );
        } else {
            initial_state = state_in.clone();
            acc_hash = Some(transcript_nifs_init::<C>(in_fr));
        }

        let x = w[1..1 + n_pub_out + n_pub_in].to_vec();
        let step_u = nifs::RelaxedR1csInstance {
            x,
            u: ScalarField::<C>::from(1u64),
            w_commit: CS::commit_witness(&params, w),
            e_commit: CS::zero(sis_param),
        };
        let step_w = nifs::RelaxedR1csWitness {
            w: w.to_vec(),
            e: zero_e.clone(),
        };
        step_witnesses.push((
            step_w.w.iter().map(fr_to_string).collect(),
            step_w.e.iter().map(fr_to_string).collect(),
        ));

        match acc_u.take() {
            None => {
                acc_u = Some(step_u);
                acc_w = Some(step_w);
            }
            Some(u_acc) => {
                let w_acc = acc_w.take().expect("running witness must exist");
                let acc = acc_hash.as_ref().expect("transcript initialized");
                let challenge = nifs::fold_challenge::<CS>(acc, &u_acc, &step_u);
                let (u3, w3) = nifs::fold_with_opts::<CS>(
                    &params, &circuit.l, &circuit.r, &circuit.o, &u_acc, &w_acc, &step_u, &step_w,
                    challenge, parallel,
                );
                acc_u = Some(u3);
                acc_w = Some(w3);
            }
        }

        acc_hash = Some(transcript_nifs_step::<C, CS>(
            acc_hash.as_ref().expect("transcript initialized"),
            acc_u.as_ref().expect("running instance"),
        ));
        prev_out = Some(state_out);
    }

    let final_u = acc_u.expect("no step witnesses folded");
    let final_w = acc_w.expect("final witness present");
    let transcript_final = hex::encode(acc_hash.expect("transcript finalized"));

    let bundle = NifsBundle {
        circuit: String::new(),
        n_wires: circuit.n_wires,
        n_constraints: circuit.n_constraints,
        n_pub_out: circuit.n_pub_out,
        n_pub_in: circuit.n_pub_in,
        initial_state,
        n_steps: witnesses.len(),
        final_instance: NifsFinalInstance {
            x: final_u.x.iter().map(fr_to_string).collect(),
            u: fr_to_string(&final_u.u),
            w_commit: commitment_hex(&final_u.w_commit),
            e_commit: commitment_hex(&final_u.e_commit),
        },
        transcript_final,
    };

    NifsFoldOutput {
        bundle,
        final_instance: final_u,
        final_witness: final_w,
        step_witnesses,
        fold_log: None,
        checkpoints: None,
    }
}

fn nifs_fold_in_memory_batch<C: NovaCurve, CS: CommitmentScheme<Scalar = ScalarField<C>>>(
    circuit: &mut SparseCircuit<ScalarField<C>>,
    witnesses: &[Vec<ScalarField<C>>],
    sis_param: usize,
    batch_size: usize,
    bound_bits: u32,
) -> NifsFoldOutput<CS>
where
    CS::Scalar: ark_ff::PrimeField,
{
    let n_pub_out = circuit.n_pub_out as usize;
    let n_pub_in = circuit.n_pub_in as usize;
    let n_wires = circuit.n_wires as usize;
    let n_constraints = circuit.n_constraints as usize;

    let params = CS::params_from_seed(NIFS_PARAMS_SEED, n_wires, n_constraints, sis_param);
    let zero_e = vec![ScalarField::<C>::zero(); n_constraints];

    let mut acc_hash: Option<Vec<u8>> = None;
    let mut prev_out: Option<Vec<String>> = None;
    let mut initial_state: Vec<String> = Vec::new();
    let mut instances: Vec<nifs::RelaxedR1csInstance<CS>> = Vec::with_capacity(witnesses.len());
    let mut step_witnesses: Vec<(Vec<String>, Vec<String>)> = Vec::new();

    for w in witnesses {
        circuit.witness = w.clone();
        let out_fr = &w[1..1 + n_pub_out];
        let in_fr = &w[1 + n_pub_out..1 + n_pub_out + n_pub_in];
        let state_in: Vec<String> = in_fr.iter().map(fr_to_string).collect();
        let state_out: Vec<String> = out_fr.iter().map(fr_to_string).collect();
        if let Some(prev) = &prev_out {
            assert_eq!(
                &state_in, prev,
                "state_in does not chain to previous state_out"
            );
        } else {
            initial_state = state_in.clone();
            acc_hash = Some(transcript_nifs_init::<C>(in_fr));
        }

        let x = w[1..1 + n_pub_out + n_pub_in].to_vec();
        let step_u = nifs::RelaxedR1csInstance {
            x,
            u: ScalarField::<C>::from(1u64),
            w_commit: CS::commit_witness(&params, w),
            e_commit: CS::zero(sis_param),
        };
        let step_w: nifs::RelaxedR1csWitness<CS> = nifs::RelaxedR1csWitness {
            w: w.to_vec(),
            e: zero_e.clone(),
        };
        step_witnesses.push((
            step_w.w.iter().map(fr_to_string).collect(),
            step_w.e.iter().map(fr_to_string).collect(),
        ));
        instances.push(step_u);
        prev_out = Some(state_out);
    }

    let hash = acc_hash.expect("no step witnesses folded");
    let (final_u, final_w, checkpoints) = nifs::batch_fold_with_checkpoints::<CS>(
        &params,
        &circuit.l,
        &circuit.r,
        &circuit.o,
        &instances,
        &witnesses
            .iter()
            .map(|w| nifs::RelaxedR1csWitness {
                w: w.to_vec(),
                e: zero_e.clone(),
            })
            .collect::<Vec<_>>(),
        &hash,
        batch_size,
        bound_bits,
    )
    .expect("batch fold failed");

    let transcript_final = {
        let mut running_hash = hash.clone();
        for u in &instances {
            running_hash = {
                let mut h = blake2::Blake2b512::new();
                h.update(&running_hash);
                h.update(nifs::instance_to_bytes::<CS>(u).expect("serialize"));
                h.finalize().to_vec()
            };
        }
        hex::encode(&running_hash)
    };

    let bundle = NifsBundle {
        circuit: String::new(),
        n_wires: circuit.n_wires,
        n_constraints: circuit.n_constraints,
        n_pub_out: circuit.n_pub_out,
        n_pub_in: circuit.n_pub_in,
        initial_state,
        n_steps: witnesses.len(),
        final_instance: NifsFinalInstance {
            x: final_u.x.iter().map(fr_to_string).collect(),
            u: fr_to_string(&final_u.u),
            w_commit: commitment_hex(&final_u.w_commit),
            e_commit: commitment_hex(&final_u.e_commit),
        },
        transcript_final,
    };

    NifsFoldOutput {
        bundle,
        final_instance: final_u,
        final_witness: final_w,
        step_witnesses,
        fold_log: None,
        checkpoints: Some(checkpoints),
    }
}

fn transcript_nifs_init<C: NovaCurve>(initial_state: &[ScalarField<C>]) -> Vec<u8> {
    let mut h = blake2::Blake2b512::new();
    h.update(NIFS_TRANSCRIPT_PREFIX);
    for f in initial_state {
        let mut buf = Vec::new();
        f.serialize_compressed(&mut buf).expect("Fr serialize");
        h.update(&buf);
    }
    h.finalize().to_vec()
}

fn transcript_nifs_step<C: NovaCurve, CS: CommitmentScheme>(
    acc: &[u8],
    u: &nifs::RelaxedR1csInstance<CS>,
) -> Vec<u8> {
    let mut h = blake2::Blake2b512::new();
    h.update(NIFS_TRANSCRIPT_PREFIX);
    h.update(acc);
    h.update(nifs::instance_to_bytes::<CS>(u).expect("serialize instance"));
    h.finalize().to_vec()
}

fn commitment_hex<T: CanonicalSerialize>(value: &T) -> String {
    let mut buf = Vec::new();
    value
        .serialize_compressed(&mut buf)
        .expect("commitment serialize");
    hex::encode(buf)
}

/// Serialize a step witness into the `.wtns` file format the CLI/benchmarks
/// load via `SparseCircuit::load_witness`.  Each field element is written
/// little-endian over 32 bytes (u64 + 24 zero bytes), so only values `< 2^64`
/// are representable — which is exactly the canonical-residue regime Module-SIS
/// requires.
fn wtns_bytes_from_le<F: ark_ff::PrimeField>(witness: &[F]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"wtns");
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&2u32.to_le_bytes());

    let mut header = Vec::new();
    header.extend_from_slice(&32u32.to_le_bytes());
    header.extend_from_slice(&[0u8; 32]);
    header.extend_from_slice(&(witness.len() as u32).to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&(header.len() as u64).to_le_bytes());
    out.extend_from_slice(&header);

    let mut data = Vec::new();
    for v in witness {
        let big = v.clone().into_bigint();
        let low = big.as_ref()[0];
        data.extend_from_slice(&low.to_le_bytes());
        data.extend_from_slice(&[0u8; 24]);
    }
    out.extend_from_slice(&2u32.to_le_bytes());
    out.extend_from_slice(&(data.len() as u64).to_le_bytes());
    out.extend_from_slice(&data);
    out
}
