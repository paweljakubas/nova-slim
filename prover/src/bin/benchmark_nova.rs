//! NovaSlim benchmarks — NIFS folding + sumcheck compression + slim proofs
//! for a compiled step circuit and a directory of chained step witnesses.
//!
//! Measures the three phases of the slim IVC flow:
//!
//!   1. nifs fold          — per-step Relaxed-R1CS NIFS fold (two O(step)-sized
//!      MSMs), averaged
//!   2. sumcheck compress  — one sumcheck proof + HashPC opening proofs
//!      (transparent — no trusted setup)
//!   3. verify             — sumcheck verification + HashPC checks (full),
//!      or the slim on-chain verification
//!
//! All phases keep the witnesses in memory (no disk I/O beyond the initial
//! read) and exclude transcript hashing.  Usage:
//!
//!   cargo run --release --bin benchmark_nova -- --curve bls12-381 --circuit step.r1cs --steps DIR [--limit N] [--opt-parallel] [--commitment pedersen|sis]

use ark_ff::Zero;
use ark_serialize::CanonicalSerialize;
use blake2::{Blake2b512, Digest};
use prover::circuit::SparseCircuit;
use prover::commitment::{CommitmentScheme, HashCommitment, PedersenCommitment, SisCommitment};
use prover::nifs;
use prover::norm;
use prover::{
    curve::{NovaCurve, ScalarField},
    fr_to_string, frs_from_strings, prove_level1, prove_sumcheck_compression_opt, verify_slim,
    verify_slim_level1, verify_sumcheck_compression, NifsBundle, NifsFinalInstance, NifsFoldOutput,
    OptFlags, DEFAULT_SIS_PARAM, NIFS_PARAMS_SEED, NIFS_TRANSCRIPT_PREFIX,
};
use std::fs;
use std::path::PathBuf;
use std::time::Instant;

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
    let circuit_path = args
        .windows(2)
        .find(|w| w[0] == "--circuit")
        .map(|w| w[1].clone());
    let steps_dir = args
        .windows(2)
        .find(|w| w[0] == "--steps")
        .map(|w| w[1].clone());
    let (Some(circuit_path), Some(steps_dir)) = (circuit_path, steps_dir) else {
        eprintln!(
            "usage: benchmark_nova [--curve bls12-381|bn254|pallas|vesta|grumpkin|bandersnatch] [--commitment pedersen|sis|hash] [--opt-parallel] --circuit <step.r1cs> --steps <witness-dir> [--limit N]"
        );
        std::process::exit(2);
    };
    let limit = args.windows(2).find(|w| w[0] == "--limit").map(|w| {
        w[1].parse::<usize>()
            .expect("--limit must be a positive integer")
    });
    let sis_param = args
        .windows(2)
        .find(|w| w[0] == "--sis-param")
        .map(|w| {
            w[1].parse::<usize>()
                .expect("--sis-param must be a positive integer")
        })
        .unwrap_or(DEFAULT_SIS_PARAM);

    let curve = curve.as_deref().unwrap_or("bls12-381");
    let commitment = commitment.as_deref().unwrap_or("pedersen");
    match (curve, commitment) {
        ("bls12-381", "pedersen") => benchmark::<
            prover::curve::Bls12_381,
            PedersenCommitment<prover::curve::Bls12_381>,
        >(
            &circuit_path, &steps_dir, limit, opt_parallel, sis_param
        ),
        #[cfg(feature = "bn254")]
        ("bn254", "pedersen") => benchmark::<
            prover::curve::Bn254,
            PedersenCommitment<prover::curve::Bn254>,
        >(
            &circuit_path, &steps_dir, limit, opt_parallel, sis_param
        ),
        #[cfg(feature = "pallas")]
        ("pallas", "pedersen") => benchmark::<
            prover::curve::Pallas,
            PedersenCommitment<prover::curve::Pallas>,
        >(
            &circuit_path, &steps_dir, limit, opt_parallel, sis_param
        ),
        #[cfg(feature = "vesta")]
        ("vesta", "pedersen") => benchmark::<
            prover::curve::Vesta,
            PedersenCommitment<prover::curve::Vesta>,
        >(
            &circuit_path, &steps_dir, limit, opt_parallel, sis_param
        ),
        #[cfg(feature = "grumpkin")]
        ("grumpkin", "pedersen") => benchmark::<
            prover::curve::Grumpkin,
            PedersenCommitment<prover::curve::Grumpkin>,
        >(
            &circuit_path, &steps_dir, limit, opt_parallel, sis_param
        ),
        #[cfg(feature = "bandersnatch")]
        ("bandersnatch", "pedersen") => benchmark::<
            prover::curve::Bandersnatch,
            PedersenCommitment<prover::curve::Bandersnatch>,
        >(
            &circuit_path, &steps_dir, limit, opt_parallel, sis_param
        ),
        ("bls12-381", "sis") => benchmark::<
            prover::curve::Bls12_381,
            SisCommitment<prover::curve::Bls12_381>,
        >(&circuit_path, &steps_dir, limit, opt_parallel, sis_param),
        #[cfg(feature = "bn254")]
        ("bn254", "sis") => benchmark::<prover::curve::Bn254, SisCommitment<prover::curve::Bn254>>(
            &circuit_path,
            &steps_dir,
            limit,
            opt_parallel,
            sis_param,
        ),
        #[cfg(feature = "pallas")]
        ("pallas", "sis") => {
            benchmark::<prover::curve::Pallas, SisCommitment<prover::curve::Pallas>>(
                &circuit_path,
                &steps_dir,
                limit,
                opt_parallel,
                sis_param,
            )
        }
        #[cfg(feature = "vesta")]
        ("vesta", "sis") => benchmark::<prover::curve::Vesta, SisCommitment<prover::curve::Vesta>>(
            &circuit_path,
            &steps_dir,
            limit,
            opt_parallel,
            sis_param,
        ),
        #[cfg(feature = "grumpkin")]
        ("grumpkin", "sis") => benchmark::<
            prover::curve::Grumpkin,
            SisCommitment<prover::curve::Grumpkin>,
        >(&circuit_path, &steps_dir, limit, opt_parallel, sis_param),
        #[cfg(feature = "bandersnatch")]
        ("bandersnatch", "sis") => benchmark::<
            prover::curve::Bandersnatch,
            SisCommitment<prover::curve::Bandersnatch>,
        >(
            &circuit_path, &steps_dir, limit, opt_parallel, sis_param
        ),
        ("bls12-381", "hash") => benchmark::<
            prover::curve::Bls12_381,
            HashCommitment<prover::curve::Bls12_381>,
        >(
            &circuit_path, &steps_dir, limit, opt_parallel, sis_param
        ),
        #[cfg(feature = "bn254")]
        ("bn254", "hash") => {
            benchmark::<prover::curve::Bn254, HashCommitment<prover::curve::Bn254>>(
                &circuit_path,
                &steps_dir,
                limit,
                opt_parallel,
                sis_param,
            )
        }
        #[cfg(feature = "pallas")]
        ("pallas", "hash") => benchmark::<
            prover::curve::Pallas,
            HashCommitment<prover::curve::Pallas>,
        >(&circuit_path, &steps_dir, limit, opt_parallel, sis_param),
        #[cfg(feature = "vesta")]
        ("vesta", "hash") => {
            benchmark::<prover::curve::Vesta, HashCommitment<prover::curve::Vesta>>(
                &circuit_path,
                &steps_dir,
                limit,
                opt_parallel,
                sis_param,
            )
        }
        #[cfg(feature = "grumpkin")]
        ("grumpkin", "hash") => benchmark::<
            prover::curve::Grumpkin,
            HashCommitment<prover::curve::Grumpkin>,
        >(&circuit_path, &steps_dir, limit, opt_parallel, sis_param),
        #[cfg(feature = "bandersnatch")]
        ("bandersnatch", "hash") => benchmark::<
            prover::curve::Bandersnatch,
            HashCommitment<prover::curve::Bandersnatch>,
        >(
            &circuit_path, &steps_dir, limit, opt_parallel, sis_param
        ),
        _ => {
            eprintln!("unknown curve/commitment: {curve}/{commitment} — valid curves: bls12-381, bn254, pallas, vesta, grumpkin, bandersnatch; valid commitments: pedersen, sis, hash");
            std::process::exit(2);
        }
    }
}

fn benchmark<C: NovaCurve, CS: CommitmentScheme<Scalar = ScalarField<C>>>(
    circuit_path: &str,
    steps_dir: &str,
    limit: Option<usize>,
    opt_parallel: bool,
    sis_param: usize,
) {
    use std::path::Path;
    let mut circuit = prover::load_circuit::<C>(Path::new(circuit_path))
        .unwrap_or_else(|e| panic!("failed to load circuit {circuit_path}: {e}"));
    if circuit.n_pub_in != circuit.n_pub_out {
        panic!(
            "not a step circuit: n_pub_in ({}) != n_pub_out ({})",
            circuit.n_pub_in, circuit.n_pub_out
        );
    }

    let mut wtns: Vec<PathBuf> = fs::read_dir(steps_dir)
        .expect("failed to read steps dir")
        .map(|e| e.expect("steps dir entry").path())
        .filter(|p| p.extension().and_then(|x| x.to_str()) == Some("wtns"))
        .collect();
    wtns.sort();
    if let Some(n) = limit {
        wtns.truncate(n);
    }
    assert!(!wtns.is_empty(), "no .wtns files in steps dir");

    let n_steps = wtns.len();
    let scheme_name = {
        let tn = std::any::type_name::<CS>();
        if tn.contains("Sis") {
            "sis"
        } else if tn.contains("Hash") {
            "hash"
        } else {
            "pedersen"
        }
    };

    println!(
        "step circuit: {} wires, {} constraints, pub {} out + {} in, private {}",
        circuit.n_wires,
        circuit.n_constraints,
        circuit.n_pub_out,
        circuit.n_pub_in,
        circuit.n_prv_in
    );
    println!("step witnesses: {n_steps} (from {steps_dir})");
    println!("commitment scheme: {scheme_name}");

    benchmark_slim::<C, CS>(&mut circuit, &wtns, opt_parallel, sis_param);
}

/// Slim flow: NIFS fold → sumcheck compression → full/slim verify.
fn benchmark_slim<C: NovaCurve, CS: CommitmentScheme<Scalar = ScalarField<C>>>(
    circuit: &mut SparseCircuit<ScalarField<C>>,
    wtns: &[PathBuf],
    parallel: bool,
    sis_param: usize,
) {
    let n_steps = wtns.len();
    let opt = if parallel { "parallel" } else { "baseline" };
    println!(
        "mode: NIFS fold + sumcheck compress ({opt}), curve: {}",
        std::any::type_name::<C>()
    );

    // Starting norm bound B (bit-length); the per-mode loop below increases it
    // until the honest witness actually fits, so this is just a lower bound.
    let bound_bits = 64u32;

    // 1. NIFS fold.
    let t = Instant::now();
    let folded = nifs_fold::<C, CS>(circuit, wtns, parallel, sis_param);
    let fold_s = t.elapsed().as_secs_f64();
    println!(
        "nifs fold: {fold_s:.3} s total, {:.3} ms/step over {n_steps} steps",
        fold_s * 1000.0 / n_steps as f64
    );

    // 2. Sumcheck compress — one sumcheck proof + HashPC opening proofs
    //    (no trusted setup needed).
    let mut rng = rand::thread_rng();
    let t = Instant::now();
    let sc_proof = prove_sumcheck_compression_opt::<C, CS>(
        circuit,
        &folded,
        &mut rng,
        if parallel {
            OptFlags::PARALLEL
        } else {
            OptFlags::NONE
        },
    )
    .unwrap_or_else(|e| panic!("failed to build sumcheck compression proof: {e}"));
    let compress_s = t.elapsed().as_secs_f64();
    println!(
        "sumcheck compress: {:.3} s (transparent, O(log N) sumcheck rounds)",
        compress_s
    );

    // 3a. Verify — sumcheck verification + HashPC checks (audit-grade).
    let t = Instant::now();
    verify_sumcheck_compression::<C, CS>(&folded.bundle, &sc_proof)
        .unwrap_or_else(|e| panic!("sumcheck compression verification failed: {e}"));
    let verify_s = t.elapsed().as_secs_f64();
    println!("verify (full): {verify_s:.4} s (sumcheck + HashPC checks)");

    // 3b. Verify — slim on-chain path (openings stripped).
    let slim = sc_proof.to_slim();
    let t = Instant::now();
    verify_slim::<C, CS>(&folded.bundle, &slim)
        .unwrap_or_else(|e| panic!("slim verification failed: {e}"));
    let verify_slim_s = t.elapsed().as_secs_f64();

    // 4. Level-1 path — degree-2 sumcheck + W/E opening proofs +
    //    final-claim-zero check.  Closes the "free E" / all-zeros gap;
    //    carries the commitment openings so it is auditable.
    let opts = if parallel {
        OptFlags::PARALLEL
    } else {
        OptFlags::NONE
    };

    // 4a. Plain level-1 (no norm enforcement).
    let t = Instant::now();
    let l1 = prove_level1::<C, CS>(circuit, &folded, opts, norm::NormMode::None, bound_bits)
        .unwrap_or_else(|e| panic!("failed to build Level-1 proof: {e}"));
    let level1_compress_s = t.elapsed().as_secs_f64();
    println!(
        "level1 compress: {:.3} s (degree-2 sumcheck + W/E openings + final-claim-zero)",
        level1_compress_s
    );

    let t = Instant::now();
    verify_slim_level1::<C, CS>(&folded.bundle, &l1, sis_param, Some(circuit))
        .unwrap_or_else(|e| panic!("Level-1 verification failed: {e}"));
    let verify_level1_s = t.elapsed().as_secs_f64();
    println!(
        "verify (level-1): {verify_level1_s:.4} s (degree-2 sumcheck + openings + final-claim-zero)"
    );

    // 4b. Norm-enforced level-1, both Option A (range) and Option B (JL).
    let mut range_level1_bytes = 0usize;
    let mut jl_level1_bytes = 0usize;
    for (mode, label) in [(norm::NormMode::Range, "range"), (norm::NormMode::Jl, "jl")] {
        // Ensure the honest witness actually fits B, else pick a larger bound.
        let mut b = bound_bits;
        while prove_level1::<C, CS>(circuit, &folded, opts, mode, b).is_err() {
            b *= 2;
        }
        let t = Instant::now();
        let l1n = prove_level1::<C, CS>(circuit, &folded, opts, mode, b)
            .unwrap_or_else(|e| panic!("failed to build norm-{label} Level-1 proof: {e}"));
        let norm_compress_s = t.elapsed().as_secs_f64();
        let t = Instant::now();
        verify_slim_level1::<C, CS>(&folded.bundle, &l1n, sis_param, Some(circuit))
            .unwrap_or_else(|e| panic!("norm-{label} Level-1 base verification failed: {e}"));
        let step_w: Vec<(Vec<ScalarField<C>>, Vec<ScalarField<C>>)> = folded
            .step_witnesses
            .iter()
            .map(|(z, e)| {
                (
                    frs_from_strings::<ScalarField<C>>(z)
                        .unwrap_or_else(|_| panic!("norm-{label} parse Z")),
                    frs_from_strings::<ScalarField<C>>(e)
                        .unwrap_or_else(|_| panic!("norm-{label} parse E")),
                )
            })
            .collect();
        let carried = l1n
            .norm
            .as_ref()
            .unwrap_or_else(|| panic!("norm-{label} proof carries no record"));
        let recomputed = norm::StepNormRecord::recompute(mode, &step_w, b, b.min(128))
            .unwrap_or_else(|| panic!("norm-{label} exceeds bound"));
        if !carried.verify_against(&recomputed, b) {
            panic!("norm-{label} audit mismatch");
        }
        let norm_verify_s = t.elapsed().as_secs_f64();
        let bytes = l1n
            .to_cbor::<ScalarField<C>>()
            .map(|c| c.len())
            .unwrap_or(0);
        if mode == norm::NormMode::Range {
            range_level1_bytes = bytes;
        } else {
            jl_level1_bytes = bytes;
        }
        println!(
            "norm-{label} level1 compress: {norm_compress_s:.4} s | verify: {norm_verify_s:.4} s | proof: {bytes} B (B = 2^{b})"
        );
    }

    // Sizes: the bundle is O(1) in N; the slim proof is what lands on-chain.
    let bundle_json =
        serde_json::to_string_pretty(&folded.bundle).expect("bundle serialization should not fail");
    let full_json =
        serde_json::to_string_pretty(&sc_proof).expect("proof serialization should not fail");
    let json_slim_len = serde_json::to_string_pretty(&slim)
        .expect("slim proof serialization should not fail")
        .len();
    let slim_cbor = slim
        .to_cbor::<ScalarField<C>>()
        .expect("slim proof serialization should not fail");
    let bundle_cbor = folded
        .bundle
        .to_cbor::<ScalarField<C>>()
        .expect("bundle serialization should not fail");
    let level1_cbor = l1
        .to_cbor::<ScalarField<C>>()
        .expect("level-1 proof serialization should not fail");
    let level1_json =
        serde_json::to_string_pretty(&l1).expect("level-1 proof serialization should not fail");
    println!(
        "nifs bundle: {} B ({:.1} KiB cbor / {:.1} KiB json), O(1) in the step count",
        bundle_cbor.len(),
        bundle_cbor.len() as f64 / 1024.0,
        bundle_json.len() as f64 / 1024.0
    );
    println!(
        "sumcheck proof (full): {} B ({:.1} KiB cbor / {:.1} KiB json) — off-chain audit variant",
        sc_proof.to_cbor::<ScalarField<C>>().unwrap().len(),
        sc_proof.to_cbor::<ScalarField<C>>().unwrap().len() as f64 / 1024.0,
        full_json.len() as f64 / 1024.0
    );
    println!(
        "slim proof: {} B ({:.1} KiB cbor / {:.1} KiB json) — on-chain variant",
        slim_cbor.len(),
        slim_cbor.len() as f64 / 1024.0,
        json_slim_len as f64 / 1024.0
    );
    println!(
        "level1 proof: {} B ({:.1} KiB cbor / {:.1} KiB json) — sound slim variant (openings + final-claim-zero)",
        level1_cbor.len(),
        level1_cbor.len() as f64 / 1024.0,
        level1_json.len() as f64 / 1024.0
    );
    println!(
        "level1 proof (+norm range): {range_level1_bytes} B — per-step Option-A range/bit-decomposition certificates"
    );
    println!(
        "level1 proof (+norm jl): {jl_level1_bytes} B — per-step Option-B JL/sketch certificates"
    );
    println!("verify (slim): {verify_slim_s:.4} s");
    println!("verify (level-1): {:.4} s", verify_level1_s);
    println!("all verifications OK");
}

/// Fold every step witness into one Relaxed-R1CS running instance, exactly as
/// `nova-slim fold` does (same transparent params, FOLD_PREFIX challenge,
/// and NIFS_TRANSCRIPT_PREFIX chain), but fully in memory.
fn nifs_fold<C: NovaCurve, CS: CommitmentScheme<Scalar = ScalarField<C>>>(
    circuit: &mut SparseCircuit<ScalarField<C>>,
    wtns: &[PathBuf],
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

    for p in wtns {
        circuit
            .load_witness(p.to_str().expect("witness path is not valid UTF-8"))
            .unwrap_or_else(|e| panic!("failed to load witness {}: {e}", p.display()));
        let w = &circuit.witness;

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
        n_steps: wtns.len(),
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
    }
}

/// `H(NIFS_TRANSCRIPT_PREFIX ‖ initial_state)`, matching `nova-slim fold`.
fn transcript_nifs_init<C: NovaCurve>(initial_state: &[ScalarField<C>]) -> Vec<u8> {
    let mut h = Blake2b512::new();
    h.update(NIFS_TRANSCRIPT_PREFIX);
    h.update(frs_bytes::<C>(initial_state));
    h.finalize().to_vec()
}

/// `H(NIFS_TRANSCRIPT_PREFIX ‖ acc ‖ instance_bytes)`, matching `nova-slim fold`.
fn transcript_nifs_step<C: NovaCurve, CS: CommitmentScheme>(
    acc: &[u8],
    u: &nifs::RelaxedR1csInstance<CS>,
) -> Vec<u8> {
    let mut h = Blake2b512::new();
    h.update(NIFS_TRANSCRIPT_PREFIX);
    h.update(acc);
    h.update(nifs::instance_to_bytes::<CS>(u).expect("serialize instance"));
    h.finalize().to_vec()
}

fn frs_bytes<C: NovaCurve>(frs: &[ScalarField<C>]) -> Vec<u8> {
    let mut buf = Vec::new();
    for f in frs {
        f.serialize_compressed(&mut buf).expect("Fr serialize");
    }
    buf
}

fn commitment_hex<T: CanonicalSerialize>(value: &T) -> String {
    let mut buf = Vec::new();
    value
        .serialize_compressed(&mut buf)
        .expect("commitment serialize");
    hex::encode(buf)
}
