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
//!   cargo run --release --bin benchmark_nova -- --circuit step.r1cs --steps DIR [--limit N] [--opt-parallel]

use ark_bls12_381::{Fr, G1Affine};
use ark_ec::AffineRepr;
use ark_ff::Zero;
use ark_serialize::CanonicalSerialize;
use blake2::{Blake2b512, Digest};
use groth16_prover::circom_adapter::SparseCircomCircuit;
use prover::nifs;
use prover::{
    fr_to_string, prove_sumcheck_compression_opt, verify_slim, verify_sumcheck_compression,
    NifsBundle, NifsFinalInstance, NifsFoldOutput, OptFlags, NIFS_PARAMS_SEED,
    NIFS_TRANSCRIPT_PREFIX,
};
use std::fs;
use std::path::PathBuf;
use std::time::Instant;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let opt_parallel = args.iter().any(|a| a == "--opt-parallel");
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
            "usage: benchmark_nova [--opt-parallel] --circuit <step.r1cs> --steps <witness-dir> [--limit N]"
        );
        std::process::exit(2);
    };
    let limit = args.windows(2).find(|w| w[0] == "--limit").map(|w| {
        w[1].parse::<usize>()
            .expect("--limit must be a positive integer")
    });

    let mut circuit = SparseCircomCircuit::from_r1cs(&circuit_path)
        .unwrap_or_else(|e| panic!("failed to load circuit {circuit_path}: {e}"));
    if circuit.n_pub_in != circuit.n_pub_out {
        panic!(
            "not a step circuit: n_pub_in ({}) != n_pub_out ({})",
            circuit.n_pub_in, circuit.n_pub_out
        );
    }

    let mut wtns: Vec<PathBuf> = fs::read_dir(&steps_dir)
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

    println!(
        "step circuit: {} wires, {} constraints, pub {} out + {} in, private {}",
        circuit.n_wires,
        circuit.n_constraints,
        circuit.n_pub_out,
        circuit.n_pub_in,
        circuit.n_prv_in
    );
    println!("step witnesses: {n_steps} (from {steps_dir})");

    benchmark_slim(&mut circuit, &wtns, opt_parallel);
}

/// Slim flow: NIFS fold → sumcheck compression → full/slim verify.
fn benchmark_slim(circuit: &mut SparseCircomCircuit, wtns: &[PathBuf], parallel: bool) {
    let n_steps = wtns.len();
    let opt = if parallel { "parallel" } else { "baseline" };
    println!("mode: NIFS fold + sumcheck compress ({opt})");

    // 1. NIFS fold.
    let t = Instant::now();
    let folded = nifs_fold(circuit, wtns, parallel);
    let fold_s = t.elapsed().as_secs_f64();
    println!(
        "nifs fold: {fold_s:.3} s total, {:.3} ms/step over {n_steps} steps (2 O(step)-sized MSMs)",
        fold_s * 1000.0 / n_steps as f64
    );

    // 2. Sumcheck compress — one sumcheck proof + HashPC opening proofs
    //    (no trusted setup needed).
    let mut rng = rand::thread_rng();
    let t = Instant::now();
    let sc_proof = prove_sumcheck_compression_opt(
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
    verify_sumcheck_compression(&folded.bundle, &sc_proof)
        .unwrap_or_else(|e| panic!("sumcheck compression verification failed: {e}"));
    let verify_s = t.elapsed().as_secs_f64();
    println!("verify (full): {verify_s:.4} s (sumcheck + HashPC checks)");

    // 3b. Verify — slim on-chain path (openings stripped).
    let slim = sc_proof.to_slim();
    let t = Instant::now();
    verify_slim(&folded.bundle, &slim)
        .unwrap_or_else(|e| panic!("slim verification failed: {e}"));
    let verify_slim_s = t.elapsed().as_secs_f64();

    // Sizes: the bundle is O(1) in N; the slim proof is what lands on-chain.
    // Compact CBOR vs decimal/hex JSON shown for both.
    let bundle_json =
        serde_json::to_string_pretty(&folded.bundle).expect("bundle serialization should not fail");
    let full_json =
        serde_json::to_string_pretty(&sc_proof).expect("proof serialization should not fail");
    let json_slim_len = serde_json::to_string_pretty(&slim)
        .expect("slim proof serialization should not fail")
        .len();
    let slim_cbor = slim
        .to_cbor()
        .expect("slim proof serialization should not fail");
    let bundle_cbor = folded
        .bundle
        .to_cbor()
        .expect("bundle serialization should not fail");
    println!(
        "nifs bundle: {} B ({:.1} KiB cbor / {:.1} KiB json), O(1) in the step count",
        bundle_cbor.len(),
        bundle_cbor.len() as f64 / 1024.0,
        bundle_json.len() as f64 / 1024.0
    );
    println!(
        "sumcheck proof (full): {} B ({:.1} KiB cbor / {:.1} KiB json) — off-chain audit variant",
        sc_proof.to_cbor().unwrap().len(),
        sc_proof.to_cbor().unwrap().len() as f64 / 1024.0,
        full_json.len() as f64 / 1024.0
    );
    println!(
        "slim proof: {} B ({:.1} KiB cbor / {:.1} KiB json) — on-chain variant",
        slim_cbor.len(),
        slim_cbor.len() as f64 / 1024.0,
        json_slim_len as f64 / 1024.0
    );
    println!("verify (slim): {verify_slim_s:.4} s");
    println!("all verifications OK");
}

/// Fold every step witness into one Relaxed-R1CS running instance, exactly as
/// `nova-slim fold` does (same transparent Pedersen params, FOLD_PREFIX challenge,
/// and NIFS_TRANSCRIPT_PREFIX chain), but fully in memory.
fn nifs_fold(circuit: &mut SparseCircomCircuit, wtns: &[PathBuf], parallel: bool) -> NifsFoldOutput {
    let n_pub_out = circuit.n_pub_out as usize;
    let n_pub_in = circuit.n_pub_in as usize;
    let n_wires = circuit.n_wires as usize;
    let n_constraints = circuit.n_constraints as usize;

    let params = nifs::PedersenParams::from_seed(NIFS_PARAMS_SEED, n_wires, n_constraints);
    let zero_e = vec![Fr::zero(); n_constraints];

    let mut acc_hash: Option<Vec<u8>> = None;
    let mut prev_out: Option<Vec<String>> = None;
    let mut initial_state: Vec<String> = Vec::new();
    let mut acc_u: Option<nifs::RelaxedR1csInstance> = None;
    let mut acc_w: Option<nifs::RelaxedR1csWitness> = None;

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
            acc_hash = Some(transcript_nifs_init(in_fr));
        }

        let x = w[1..1 + n_pub_out + n_pub_in].to_vec();
        let step_u = nifs::RelaxedR1csInstance {
            x,
            u: Fr::from(1u64),
            w_commit: nifs::commit(&params.basis_w, w),
            e_commit: G1Affine::zero(),
        };
        let step_w = nifs::RelaxedR1csWitness {
            w: w.to_vec(),
            e: zero_e.clone(),
        };

        match acc_u.take() {
            None => {
                acc_u = Some(step_u);
                acc_w = Some(step_w);
            }
            Some(u_acc) => {
                let w_acc = acc_w.take().expect("running witness must exist");
                let acc = acc_hash.as_ref().expect("transcript initialized");
                let challenge = nifs::fold_challenge(acc, &u_acc, &step_u);
                let (u3, w3) = nifs::fold_with_opts(
                    &params, &circuit.l, &circuit.r, &circuit.o, &u_acc, &w_acc, &step_u, &step_w,
                    challenge, parallel,
                );
                acc_u = Some(u3);
                acc_w = Some(w3);
            }
        }

        acc_hash = Some(transcript_nifs_step(
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
            w_commit: g1_hex(&final_u.w_commit),
            e_commit: g1_hex(&final_u.e_commit),
        },
        transcript_final,
    };

    NifsFoldOutput {
        bundle,
        final_instance: final_u,
        final_witness: final_w,
    }
}

/// `H(NIFS_TRANSCRIPT_PREFIX ‖ initial_state)`, matching `nova-slim fold`.
fn transcript_nifs_init(initial_state: &[Fr]) -> Vec<u8> {
    let mut h = Blake2b512::new();
    h.update(NIFS_TRANSCRIPT_PREFIX);
    h.update(frs_bytes(initial_state));
    h.finalize().to_vec()
}

/// `H(NIFS_TRANSCRIPT_PREFIX ‖ acc ‖ instance_bytes)`, matching `nova-slim fold`.
fn transcript_nifs_step(acc: &[u8], u: &nifs::RelaxedR1csInstance) -> Vec<u8> {
    let mut h = Blake2b512::new();
    h.update(NIFS_TRANSCRIPT_PREFIX);
    h.update(acc);
    h.update(nifs::instance_to_bytes(u).expect("serialize instance"));
    h.finalize().to_vec()
}

fn frs_bytes(frs: &[Fr]) -> Vec<u8> {
    let mut buf = Vec::new();
    for f in frs {
        f.serialize_compressed(&mut buf).expect("Fr serialize");
    }
    buf
}

fn g1_hex(p: &G1Affine) -> String {
    let mut buf = Vec::new();
    p.serialize_compressed(&mut buf).expect("G1 serialize");
    hex::encode(buf)
}
