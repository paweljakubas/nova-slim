//! Synthetic NovaSlim benchmark -- copy-state step circuit.
//!
//! Generates a synthetic step circuit and random witnesses in memory,
//! then benchmarks the full slim IVC flow (fold -> compress -> verify).
//!
//! Usage:
//!   cargo run --release --bin benchmark_synthetic -- --state-width N --steps M [--opt-parallel]

use ark_bls12_381::Fr;
use ark_ec::AffineRepr;
use ark_ff::Zero;
use ark_serialize::CanonicalSerialize;
use blake2::Digest;
use prover::circuit::{r1cs_to_bytes_sparse, SparseCircuit};
use prover::{
    prove_sumcheck_compression_opt, verify_slim, verify_sumcheck_compression,
    NifsBundle, NifsFinalInstance, NifsFoldOutput, OptFlags, NIFS_PARAMS_SEED,
    NIFS_TRANSCRIPT_PREFIX, fr_to_string,
};
use prover::nifs;
use std::time::Instant;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let opt_parallel = args.iter().any(|a| a == "--opt-parallel");
    let state_width = args.windows(2).find(|w| w[0] == "--state-width").map(|w| {
        w[1].parse::<usize>().expect("--state-width must be a positive integer")
    }).unwrap_or(2);
    let n_steps = args.windows(2).find(|w| w[0] == "--steps").map(|w| {
        w[1].parse::<usize>().expect("--steps must be a positive integer")
    }).unwrap_or(100);

    println!("synthetic benchmark: state_width={state_width}, steps={n_steps}");

    let n_wires = 1 + 2 * state_width;
    let n_pub_out = state_width as u32;
    let n_pub_in = state_width as u32;
    let n_prv_in = 0u32;
    let mut l = Vec::new();
    let mut r = Vec::new();
    let mut o = Vec::new();
    for i in 0..state_width {
        l.push(vec![((1 + state_width + i) as u32, Fr::from(1u64))]);
        r.push(vec![(0u32, Fr::from(1u64))]);
        o.push(vec![((1 + i) as u32, Fr::from(1u64))]);
    }

    let r1cs_bytes = r1cs_to_bytes_sparse(
        n_wires as u32, n_pub_out, n_pub_in, n_prv_in, &l, &r, &o,
    );
    let mut circuit = SparseCircuit::<Fr>::from_bytes(&r1cs_bytes)
        .expect("failed to parse synthetic r1cs");

    let mut witnesses: Vec<Vec<Fr>> = Vec::with_capacity(n_steps);
    let state: Vec<u64> = (0..state_width).map(|i| (i + 1) as u64).collect();
    for _ in 0..n_steps {
        let mut w = vec![Fr::from(1u64)];
        for &s in &state {
            w.push(Fr::from(s));
        }
        for &s in &state {
            w.push(Fr::from(s));
        }
        witnesses.push(w);
    }

    let opt = if opt_parallel { OptFlags::PARALLEL } else { OptFlags::NONE };
    let mode = if opt_parallel { "parallel" } else { "baseline" };
    println!("mode: NIFS fold + sumcheck compress ({mode})");

    let t = Instant::now();
    let folded = nifs_fold_in_memory(&mut circuit, &witnesses, opt_parallel);
    let fold_s = t.elapsed().as_secs_f64();
    println!(
        "nifs fold: {fold_s:.3} s total, {:.3} ms/step over {n_steps} steps",
        fold_s * 1000.0 / n_steps as f64
    );

    let mut rng = rand::thread_rng();
    let t = Instant::now();
    let sc_proof = prove_sumcheck_compression_opt::<prover::curve::Bls12_381>(
        &circuit, &folded, &mut rng, opt,
    )
    .unwrap_or_else(|e| panic!("failed to build sumcheck compression proof: {e}"));
    let compress_s = t.elapsed().as_secs_f64();
    println!("sumcheck compress: {:.3} s", compress_s);

    let t = Instant::now();
    verify_sumcheck_compression::<prover::curve::Bls12_381>(&folded.bundle, &sc_proof)
        .unwrap_or_else(|e| panic!("full verification failed: {e}"));
    println!("verify (full): {:.4} s", t.elapsed().as_secs_f64());

    let slim = sc_proof.to_slim();
    let t = Instant::now();
    verify_slim::<prover::curve::Bls12_381>(&folded.bundle, &slim)
        .unwrap_or_else(|e| panic!("slim verification failed: {e}"));
    println!("verify (slim): {:.4} s", t.elapsed().as_secs_f64());

    let bundle_cbor = folded.bundle.to_cbor::<Fr>().unwrap();
    let slim_cbor = slim.to_cbor::<Fr>().unwrap();
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
}

fn nifs_fold_in_memory(
    circuit: &mut SparseCircuit<Fr>,
    witnesses: &[Vec<Fr>],
    parallel: bool,
) -> NifsFoldOutput<prover::curve::Bls12_381> {
    let n_pub_out = circuit.n_pub_out as usize;
    let n_pub_in = circuit.n_pub_in as usize;
    let n_wires = circuit.n_wires as usize;
    let n_constraints = circuit.n_constraints as usize;

    let params = nifs::PedersenParams::<prover::curve::Bls12_381>::from_seed(NIFS_PARAMS_SEED, n_wires, n_constraints);
    let zero_e = vec![Fr::zero(); n_constraints];

    let mut acc_hash: Option<Vec<u8>> = None;
    let mut prev_out: Option<Vec<String>> = None;
    let mut initial_state: Vec<String> = Vec::new();
    let mut acc_u: Option<nifs::RelaxedR1csInstance<prover::curve::Bls12_381>> = None;
    let mut acc_w: Option<nifs::RelaxedR1csWitness<prover::curve::Bls12_381>> = None;

    for w in witnesses {
        circuit.witness = w.clone();
        let out_fr = &w[1..1 + n_pub_out];
        let in_fr = &w[1 + n_pub_out..1 + n_pub_out + n_pub_in];
        let state_in: Vec<String> = in_fr.iter().map(fr_to_string).collect();
        let state_out: Vec<String> = out_fr.iter().map(fr_to_string).collect();
        if let Some(prev) = &prev_out {
            assert_eq!(&state_in, prev, "state_in does not chain to previous state_out");
        } else {
            initial_state = state_in.clone();
            acc_hash = Some(transcript_nifs_init(in_fr));
        }

        let x = w[1..1 + n_pub_out + n_pub_in].to_vec();
        let step_u = nifs::RelaxedR1csInstance {
            x,
            u: Fr::from(1u64),
            w_commit: nifs::commit::<prover::curve::Bls12_381>(&params.basis_w, w),
            e_commit: ark_bls12_381::G1Affine::zero(),
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
                let challenge = nifs::fold_challenge::<prover::curve::Bls12_381>(acc, &u_acc, &step_u);
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
        n_steps: witnesses.len(),
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

fn transcript_nifs_init(initial_state: &[Fr]) -> Vec<u8> {
    let mut h = blake2::Blake2b512::new();
    h.update(NIFS_TRANSCRIPT_PREFIX);
    for f in initial_state {
        let mut buf = Vec::new();
        f.serialize_compressed(&mut buf).expect("Fr serialize");
        h.update(&buf);
    }
    h.finalize().to_vec()
}

fn transcript_nifs_step(acc: &[u8], u: &nifs::RelaxedR1csInstance<prover::curve::Bls12_381>) -> Vec<u8> {
    let mut h = blake2::Blake2b512::new();
    h.update(NIFS_TRANSCRIPT_PREFIX);
    h.update(acc);
    h.update(nifs::instance_to_bytes::<prover::curve::Bls12_381>(u).expect("serialize instance"));
    h.finalize().to_vec()
}

fn g1_hex(p: &ark_bls12_381::G1Affine) -> String {
    let mut buf = Vec::new();
    p.serialize_compressed(&mut buf).expect("G1 serialize");
    hex::encode(buf)
}
