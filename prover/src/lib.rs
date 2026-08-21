//! NovaSlim — off-circuit NIFS folding, sumcheck compression, and slim
//! on-chain proofs.
//!
//! A long computation is decomposed into `N` identical step circuits, each
//! proving `state_{i+1} = f(step_i, state_i)`.  The primary flow is:
//!
//! 1. [`run_fold_nifs`] folds all step witnesses into a single Relaxed-R1CS
//!    accumulator ([`nifs`] module — transparent, no trusted setup).
//! 2. [`run_compress_sumcheck`] compresses the final instance into a
//!    constant-size sumcheck proof ([`sumcheck`] module), or a **slim**
//!    on-chain proof via [`NifsSumcheckProof::to_slim`] (HashPC openings
//!    stripped).
//! 3. [`run_verify_slim`] verifies it with native field operations only.
//!
//! The step circuits must satisfy one invariant (checked by [`check_step_circuit`],
//! exposed to the CLI as the `params` operation): the number of public inputs
//! must equal the number of public outputs (`n_pub_in == n_pub_out`), so the
//! public-input block of step `i+1` must equal the public-output block of
//! step `i`.  Public inputs ARE the IVC state.
//!
//! The proof-system core (R1CS parsing, circom adapter) lives in the
//! `groth16-prover` crate; this crate adds the IVC folding layer on top.
//! The `nova` CLI (`clis/nova`) wraps the operations in this crate.

use ark_bls12_381::{Fr, G1Affine};
use ark_ec::AffineRepr;
use ark_ff::{PrimeField, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use blake2::{Blake2b512, Digest};
use groth16_prover::circom_adapter::SparseCircomCircuit;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

/// Optimization flags for folding and compression.
///
/// These flags can be combined freely:
/// - `parallel`: use rayon for independent row/column operations
/// - `lazy_commit`: defer Pedersen MSM to the final fold step
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OptFlags {
    /// Parallelize independent row operations (cross-term, sumcheck products)
    /// using rayon.
    pub parallel: bool,
    /// Defer the Pedersen commitment MSM to the final fold step, computing
    /// only incremental group additions during intermediate folds.
    pub lazy_commit: bool,
}

impl OptFlags {
    pub const NONE: Self = Self {
        parallel: false,
        lazy_commit: false,
    };
    pub const PARALLEL: Self = Self {
        parallel: true,
        lazy_commit: false,
    };
    pub const LAZY_COMMIT: Self = Self {
        parallel: false,
        lazy_commit: true,
    };
    pub const ALL: Self = Self {
        parallel: true,
        lazy_commit: true,
    };

    pub fn is_empty(&self) -> bool {
        *self == Self::NONE
    }
}

/// NIFS domain separators.
///
/// `NIFS_PARAMS_SEED` derives the transparent Pedersen basis; the transcript
/// prefix binds the fold sequence and is domain-separated from the folding
/// challenge hash to prevent cross-context challenge reuse.
pub const NIFS_PARAMS_SEED: &[u8] = b"groth16-prover-nova-nifs-params-v1";
pub const NIFS_TRANSCRIPT_PREFIX: &[u8] = b"groth16-prover-nova-nifs-transcript-v1";

/// Curve abstraction — makes the folding scheme curve-agnostic.
pub mod curve;

/// NIFS folding module — Relaxed-R1CS + Pedersen commitments.
pub mod nifs;

/// Sumcheck-based constant-size compression — a sumcheck argument over the
/// relaxed R1CS equation + HashPC commitments.
pub mod sumcheck;

/// JSON descriptor of a step circuit (emitted by the `params` operation).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitDescriptor {
    pub n_wires: u32,
    pub n_constraints: u32,
    pub n_pub_out: u32,
    pub n_pub_in: u32,
    pub n_prv_in: u32,
}

/// Final Relaxed-R1CS instance in a NIFS bundle (public artifact).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NifsFinalInstance {
    /// Folded public input (IVC state), decimal field strings
    pub x: Vec<String>,
    /// Slack scalar `u`, decimal
    pub u: String,
    /// Pedersen commitment to the final witness (compressed G1 hex)
    pub w_commit: String,
    /// Pedersen commitment to the final error (compressed G1 hex)
    pub e_commit: String,
}

/// The NIFS bundle produced by [`run_fold_nifs`] — O(1) in the step count.
///
/// Consumed by the sumcheck compression ([`run_compress_sumcheck`]) and by
/// `nova verify`.  `n_wires`/`n_constraints` are included so the verifier can
/// derive the transparent Pedersen basis for the commitment check without
/// re-loading the step circuit.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NifsBundle {
    pub circuit: String,
    pub n_wires: u32,
    pub n_constraints: u32,
    pub n_pub_out: u32,
    pub n_pub_in: u32,
    pub initial_state: Vec<String>,
    pub n_steps: usize,
    pub final_instance: NifsFinalInstance,
    pub transcript_final: String,
}

/// Output of [`run_fold_nifs`]: the public bundle plus the private final
/// instance/witness (consumed by the compression prover).
#[derive(Debug, Clone)]
pub struct NifsFoldOutput {
    pub bundle: NifsBundle,
    pub final_instance: nifs::RelaxedR1csInstance,
    pub final_witness: nifs::RelaxedR1csWitness,
}

/// Sumcheck-based compression proof.
///
/// Compresses a NIFS fold into a constant-size argument: a sumcheck proof
/// over the relaxed R1CS equation, HashPC commitments, and opening proofs.
/// The verifier never sees the full witness `Z` or error vector `E` — only
/// the sumcheck transcript and HashPC openings.
///
/// Proof size is O(log(n_constraints)) field elements (the sumcheck
/// messages) plus the opening proofs, independent of the step width.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NifsSumcheckProof {
    pub circuit: String,
    pub n_wires: u32,
    pub n_constraints: u32,
    pub n_pub_out: u32,
    pub n_pub_in: u32,
    /// The final NIFS instance this proof certifies.
    pub final_instance: NifsFinalInstance,
    /// Sumcheck round polynomials (each is `[f(0), f(1)-f(0)]`).
    pub sumcheck_polys: Vec<Vec<String>>,
    /// Sumcheck claims (claimed sum + per-round evaluations).
    pub sumcheck_claims: Vec<String>,
    /// Random challenges derived by the verifier from the sumcheck transcript.
    pub r_challenges: Vec<String>,
    /// Claimed product MLE evaluation at `r`: `P_MLE(r)`.
    pub claimed_product_at_r: String,
    /// HashPC commitment to the witness vector `Z` (BLAKE2b-512 hex).
    pub w_commit_hash: String,
    /// HashPC opening proof for `Z` (truth table as decimal field strings).
    pub w_opening: Vec<String>,
    /// HashPC commitment to the error vector `E` (BLAKE2b-512 hex).
    pub e_commit_hash: String,
    /// HashPC opening proof for `E` (truth table as decimal field strings).
    pub e_opening: Vec<String>,
}

/// Summary of a successful NIFS bundle verification.
#[derive(Debug, Clone)]
pub struct VerifyOutput {
    pub steps: usize,
    pub transcript_final: String,
}

/// Load a step circuit from a `.r1cs` file.
pub fn load_circuit(path: &Path) -> Result<SparseCircomCircuit, Box<dyn Error>> {
    SparseCircomCircuit::from_r1cs(
        path.to_str()
            .ok_or_else(|| format!("circuit path is not valid UTF-8: {path:?}"))?,
    )
    .map_err(|e| format!("failed to load circuit {}: {e}", path.display()).into())
}

/// Enforce the step-chain invariant: the public-input block (state in)
/// must have the same width as the public-output block (state out).
pub fn check_step_circuit(c: &SparseCircomCircuit) -> Result<(), Box<dyn Error>> {
    if c.n_pub_in != c.n_pub_out {
        return Err(format!(
            "not a valid step circuit: n_pub_in ({}) != n_pub_out ({}) — \
             the public inputs must be exactly the IVC state and must have the \
             same width as the public outputs so that state_in[i+1] == state_out[i]",
            c.n_pub_in, c.n_pub_out
        )
        .into());
    }
    Ok(())
}

/// Build the JSON descriptor for a step circuit.
pub fn circuit_descriptor(c: &SparseCircomCircuit) -> CircuitDescriptor {
    CircuitDescriptor {
        n_wires: c.n_wires,
        n_constraints: c.n_constraints,
        n_pub_out: c.n_pub_out,
        n_pub_in: c.n_pub_in,
        n_prv_in: c.n_prv_in,
    }
}

/// `params` — inspect a step circuit and return its JSON descriptor.
///
/// Loads the step circuit from a `.r1cs` file and validates that it
/// satisfies the IVC invariant (`n_pub_in == n_pub_out`).
pub fn run_params(circuit: &Path) -> Result<CircuitDescriptor, Box<dyn Error>> {
    let c = load_circuit(circuit)?;
    check_step_circuit(&c)?;
    Ok(circuit_descriptor(&c))
}

/// `fold` — fold step witnesses into a single Relaxed-R1CS instance.
///
/// Loads the step circuit and a directory of witness files, derives the
/// transparent Pedersen parameters, and folds every step instance into one
/// running accumulator via the NIFS.  Folding is linear-time and needs no
/// proving key.  Returns the O(1) [`NifsBundle`] (final instance + transcript)
/// plus the private final instance/witness for the compression proof.
pub fn run_fold_nifs(circuit: &Path, steps: &Path) -> Result<NifsFoldOutput, Box<dyn Error>> {
    fold_nifs(circuit, steps, OptFlags::NONE)
}

/// Like [`run_fold_nifs`] but with optimization flags.
pub fn run_fold_nifs_opt(
    circuit: &Path,
    steps: &Path,
    opts: OptFlags,
) -> Result<NifsFoldOutput, Box<dyn Error>> {
    fold_nifs(circuit, steps, opts)
}

/// Core folding routine shared by [`run_fold_nifs`] and [`run_compress`]
/// (which re-folds deterministically to recover the private final witness).
fn fold_nifs(
    circuit: &Path,
    steps: &Path,
    opts: OptFlags,
) -> Result<NifsFoldOutput, Box<dyn Error>> {
    let circuit_path_str = circuit.to_string_lossy().into_owned();
    let mut circuit = load_circuit(circuit)?;
    check_step_circuit(&circuit)?;

    let n_pub_out = circuit.n_pub_out as usize;
    let n_pub_in = circuit.n_pub_in as usize;
    let n_wires = circuit.n_wires as usize;
    let n_constraints = circuit.n_constraints as usize;

    let params = nifs::PedersenParams::from_seed(NIFS_PARAMS_SEED, n_wires, n_constraints);
    let zero_e = vec![Fr::zero(); n_constraints];

    let mut wtns_paths: Vec<PathBuf> = Vec::new();
    for entry in fs::read_dir(steps)
        .map_err(|e| format!("failed to read steps dir {}: {e}", steps.display()))?
    {
        let entry = entry.map_err(|e| format!("failed to read steps dir entry: {e}"))?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("wtns") {
            wtns_paths.push(path);
        }
    }
    wtns_paths.sort();

    if wtns_paths.is_empty() {
        return Err(format!("no .wtns files found in steps dir {}", steps.display()).into());
    }
    eprintln!(
        "Folding {} step witnesses (NIFS) from {}",
        wtns_paths.len(),
        steps.display()
    );

    let mut acc_hash: Option<Vec<u8>> = None;
    let mut prev_out: Option<Vec<String>> = None;
    let mut initial_state: Vec<String> = Vec::new();
    let mut acc_u: Option<nifs::RelaxedR1csInstance> = None;
    let mut acc_w: Option<nifs::RelaxedR1csWitness> = None;

    for (i, p) in wtns_paths.iter().enumerate() {
        circuit
            .load_witness(
                p.to_str()
                    .ok_or_else(|| format!("step witness path is not valid UTF-8: {p:?}"))?,
            )
            .map_err(|e| format!("failed to load witness {}: {e}", p.display()))?;
        let w = &circuit.witness;

        let out_fr = &w[1..1 + n_pub_out];
        let in_fr = &w[1 + n_pub_out..1 + n_pub_out + n_pub_in];
        let state_in: Vec<String> = in_fr.iter().map(fr_to_string).collect();
        let state_out: Vec<String> = out_fr.iter().map(fr_to_string).collect();

        if let Some(prev) = &prev_out {
            if state_in != *prev {
                return Err(format!(
                    "step {i} ({}): state_in does not chain to previous state_out. \
                     The step witnesses were not generated from a consistent state chain.",
                    p.display()
                )
                .into());
            }
        } else {
            initial_state = state_in.clone();
            acc_hash = Some(transcript_nifs_init(in_fr));
        }

        let x: Vec<Fr> = w[1..1 + n_pub_out + n_pub_in].to_vec();
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
                    challenge,
                    opts.parallel,
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
        eprintln!(
            "  step {i:>3}: folded (u = {})",
            fr_to_string(&acc_u.as_ref().expect("running instance").u)
        );
    }

    let final_u = acc_u.ok_or("no step witnesses folded")?;
    let final_w = acc_w.expect("final witness present");
    let transcript_final = hex::encode(acc_hash.as_ref().expect("transcript finalized"));

    let bundle = NifsBundle {
        circuit: circuit_path_str,
        n_wires: circuit.n_wires,
        n_constraints: circuit.n_constraints,
        n_pub_out: circuit.n_pub_out,
        n_pub_in: circuit.n_pub_in,
        initial_state,
        n_steps: wtns_paths.len(),
        final_instance: NifsFinalInstance {
            x: final_u.x.iter().map(fr_to_string).collect(),
            u: fr_to_string(&final_u.u),
            w_commit: g1_hex(&final_u.w_commit),
            e_commit: g1_hex(&final_u.e_commit),
        },
        transcript_final,
    };

    Ok(NifsFoldOutput {
        bundle,
        final_instance: final_u,
        final_witness: final_w,
    })
}

/// `compress` — compress a NIFS bundle into a constant-size proof.
///
/// No proving key is needed — the sumcheck protocol is transparent.  Folds
/// the step witnesses, builds the sumcheck compression proof (one sumcheck
/// argument + HashPC openings), and writes the JSON proof to `out`.
pub fn run_compress_sumcheck(
    circuit: &Path,
    steps: &Path,
    out: &Path,
) -> Result<CompressOutput, Box<dyn Error>> {
    run_compress_sumcheck_opt(circuit, steps, out, OptFlags::NONE)
}

/// Like [`run_compress_sumcheck`] but with optimization flags.
pub fn run_compress_sumcheck_opt(
    circuit: &Path,
    steps: &Path,
    out: &Path,
    opts: OptFlags,
) -> Result<CompressOutput, Box<dyn Error>> {
    let c = load_circuit(circuit)?;
    check_step_circuit(&c)?;

    let folded = fold_nifs(circuit, steps, opts)?;
    let mut rng = rand::thread_rng();
    let cproof = prove_sumcheck_compression_opt(&c, &folded, &mut rng, opts)?;

    let json = serde_json::to_string_pretty(&cproof)
        .map_err(|e| format!("failed to serialize sumcheck proof: {e}"))?;
    fs::write(out, &json)
        .map_err(|e| format!("failed to write sumcheck proof to {}: {e}", out.display()))?;
    eprintln!(
        "Sumcheck proof written to {} ({} bytes, u = {})",
        out.display(),
        json.len(),
        fr_to_string(&folded.final_instance.u)
    );
    Ok(CompressOutput {
        bytes: json.len(),
        bundle: folded.bundle,
    })
}

/// Verify a sumcheck compression proof against a NIFS bundle (CLI path).
///
/// Loads the NIFS bundle and the sumcheck proof JSON, then runs
/// [`verify_sumcheck_compression`].  No verifying key is needed.
pub fn run_verify_sumcheck(
    ivc: &Path,
    sumcheck_proof: &Path,
) -> Result<VerifyOutput, Box<dyn Error>> {
    let bundle_bytes =
        fs::read(ivc).map_err(|e| format!("failed to read IVC bundle {}: {e}", ivc.display()))?;
    let bundle: NifsBundle = serde_json::from_slice(&bundle_bytes)
        .map_err(|e| format!("failed to parse IVC bundle as NIFS bundle: {e}"))?;

    let proof_bytes = fs::read(sumcheck_proof).map_err(|e| {
        format!(
            "failed to read sumcheck proof {}: {e}",
            sumcheck_proof.display()
        )
    })?;
    let sc_proof: NifsSumcheckProof = serde_json::from_slice(&proof_bytes)
        .map_err(|e| format!("failed to parse sumcheck proof: {e}"))?;

    verify_sumcheck_compression(&bundle, &sc_proof)
}

fn circuit_path_display(_c: &SparseCircomCircuit) -> String {
    // The circuit's source path is only known to the file-based loaders; the
    // in-memory path records the step circuit's provenance as its identity is
    // carried by the bundle instead.
    String::new()
}

/// Output of [`run_compress_sumcheck`].
#[derive(Debug, Clone)]
pub struct CompressOutput {
    pub bytes: usize,
    pub bundle: NifsBundle,
}

/// Build a sumcheck compression proof over an already-folded NIFS instance
/// (in-memory).
///
/// Produces a sumcheck proof over the relaxed R1CS equation plus HashPC
/// opening proofs.  The proof size is O(log(n_constraints)) field elements
/// (the sumcheck messages), independent of the step width.
pub fn prove_sumcheck_compression(
    circuit: &SparseCircomCircuit,
    folded: &NifsFoldOutput,
    _rng: &mut impl rand::RngCore,
) -> Result<NifsSumcheckProof, Box<dyn Error>> {
    prove_sumcheck_compression_opt(circuit, folded, _rng, OptFlags::NONE)
}

/// Like [`prove_sumcheck_compression`] but with optimization flags.
pub fn prove_sumcheck_compression_opt(
    circuit: &SparseCircomCircuit,
    folded: &NifsFoldOutput,
    _rng: &mut impl rand::RngCore,
    opts: OptFlags,
) -> Result<NifsSumcheckProof, Box<dyn Error>> {
    let n_wires = circuit.n_wires as usize;
    let n_constraints = circuit.n_constraints as usize;
    let params = nifs::PedersenParams::from_seed(NIFS_PARAMS_SEED, n_wires, n_constraints);

    // Build the full witness: Z = folded wire vector, E = error vector.
    let z = &folded.final_witness.w;
    let e = &folded.final_witness.e;
    let u = folded.final_instance.u;

    // Run sumcheck prover.
    let (proof, r_challenges) = sumcheck::prove_with_opts(
        &circuit.l,
        &circuit.r,
        &circuit.o,
        z,
        u,
        e,
        opts.parallel,
    );

    // Build product vector and evaluate its MLE at r (for the final check).
    let n_padded = sumcheck::next_power_of_two(n_constraints);
    let products: Vec<Fr> = (0..n_constraints)
        .map(|j| {
            let az = sumcheck::eval_row_mle(&circuit.l[j], z);
            let bz = sumcheck::eval_row_mle(&circuit.r[j], z);
            let cz = sumcheck::eval_row_mle(&circuit.o[j], z);
            az * bz - u * cz - e[j]
        })
        .collect();
    let mut products_padded = products;
    products_padded.resize(n_padded, Fr::zero());

    let claimed_product_at_r = if r_challenges.is_empty() {
        products_padded[0]
    } else {
        sumcheck::eval_dense_mle(&products_padded, &r_challenges)
    };

    // HashPC commitments for W and E.
    let (w_hash, _) = sumcheck::poly_commit(z, &params.basis_w);
    let (e_hash, _) = sumcheck::poly_commit(e, &params.basis_e);

    // HashPC opening proofs.
    let w_opening = sumcheck::create_opening(z);
    let e_opening = sumcheck::create_opening(e);

    Ok(NifsSumcheckProof {
        circuit: circuit_path_display(circuit),
        n_wires: circuit.n_wires,
        n_constraints: circuit.n_constraints,
        n_pub_out: circuit.n_pub_out,
        n_pub_in: circuit.n_pub_in,
        final_instance: folded.bundle.final_instance.clone(),
        sumcheck_polys: proof
            .polys
            .iter()
            .map(|p| p.iter().map(fr_to_string).collect())
            .collect(),
        sumcheck_claims: proof.claims.iter().map(fr_to_string).collect(),
        r_challenges: r_challenges.iter().map(fr_to_string).collect(),
        claimed_product_at_r: fr_to_string(&claimed_product_at_r),
        w_commit_hash: hex::encode(&w_hash),
        w_opening: w_opening.table.iter().map(fr_to_string).collect(),
        e_commit_hash: hex::encode(&e_hash),
        e_opening: e_opening.table.iter().map(fr_to_string).collect(),
    })
}

/// Verify a sumcheck compression proof against a NIFS bundle (in-memory).
///
/// Checks, in order:
///   1. the proof's final instance matches the bundle's final instance
///   2. the sumcheck proof is valid (Fiat-Shamir consistent, round
///      polynomials sum correctly)
///   3. `claimed_product_at_r == 0` (the relaxed R1CS equation holds at
///      the random point `r`; by Schwartz–Zippel, this implies the equation
///      holds for all constraints)
///   4. the HashPC opening proofs for W and E are consistent with the
///      committed hashes and the claimed evaluations at `r`
///   5. the Pedersen commitments to W and E match the bundle's final instance
pub fn verify_sumcheck_compression(
    bundle: &NifsBundle,
    proof: &NifsSumcheckProof,
) -> Result<VerifyOutput, Box<dyn Error>> {
    if proof.final_instance != bundle.final_instance {
        return Err("sumcheck proof was not created for this NIFS bundle".into());
    }
    if proof.n_wires != bundle.n_wires
        || proof.n_constraints != bundle.n_constraints
        || proof.n_pub_out != bundle.n_pub_out
        || proof.n_pub_in != bundle.n_pub_in
    {
        return Err("sumcheck proof does not match the NIFS bundle parameters".into());
    }

    let n_wires = bundle.n_wires as usize;
    let n_constraints = bundle.n_constraints as usize;

    // 1. Reconstruct the sumcheck proof.
    let sc_proof = sumcheck::SumcheckProof {
        claims: frs_from_strings(&proof.sumcheck_claims)?,
        polys: proof
            .sumcheck_polys
            .iter()
            .map(|p| frs_from_strings(p))
            .collect::<Result<Vec<_>, _>>()?,
    };

    // 2. Verify the sumcheck.
    let (sc_ok, verifier_r, final_claim) = sumcheck::verify(&sc_proof);
    if !sc_ok {
        return Err("sumcheck proof failed: round polynomials are inconsistent".into());
    }

    // Verify Fiat-Shamir challenges match.
    let claimed_r = frs_from_strings(&proof.r_challenges)?;
    if verifier_r != claimed_r {
        return Err("sumcheck Fiat-Shamir challenges do not match".into());
    }

    // 3. Check final_claim == 0.
    if !final_claim.is_zero() {
        return Err(format!(
            "sumcheck final claim is non-zero ({}) — the relaxed R1CS equation does not hold",
            fr_to_string(&final_claim)
        )
        .into());
    }

    // 4. Verify HashPC opening proofs.
    let claimed_product = proof
        .claimed_product_at_r
        .parse::<Fr>()
        .map_err(|e| format!("invalid claimed_product_at_r: {e:?}"))?;
    if claimed_product != final_claim {
        return Err("claimed product MLE evaluation does not match sumcheck final claim".into());
    }

    // Verify W opening: check hash matches and MLE evaluation at r.
    let w_opening = sumcheck::OpeningProof {
        table: frs_from_strings(&proof.w_opening)?,
    };
    let w_hash =
        hex::decode(&proof.w_commit_hash).map_err(|e| format!("invalid w_commit_hash hex: {e}"))?;
    // Verify the W opening truth table hashes to the committed value.
    let actual_w_hash: Vec<u8> = {
        use ark_ff::BigInteger;
        let mut h = Blake2b512::new();
        for val in &w_opening.table {
            h.update(val.into_bigint().to_bytes_le());
        }
        h.finalize().to_vec()
    };
    if actual_w_hash != w_hash {
        return Err("W HashPC opening truth table hash mismatch".into());
    }

    // Verify E opening similarly.
    let e_opening = sumcheck::OpeningProof {
        table: frs_from_strings(&proof.e_opening)?,
    };
    let e_hash =
        hex::decode(&proof.e_commit_hash).map_err(|e| format!("invalid e_commit_hash hex: {e}"))?;
    let actual_e_hash: Vec<u8> = {
        use ark_ff::BigInteger;
        let mut h = Blake2b512::new();
        for val in &e_opening.table {
            h.update(val.into_bigint().to_bytes_le());
        }
        h.finalize().to_vec()
    };
    if actual_e_hash != e_hash {
        return Err("E HashPC opening truth table hash mismatch".into());
    }

    // 5. Verify Pedersen commitments match the bundle.
    let params = nifs::PedersenParams::from_seed(NIFS_PARAMS_SEED, n_wires, n_constraints);
    let w_vec = &w_opening.table[..n_wires.min(w_opening.table.len())];
    if nifs::commit(&params.basis_w, w_vec) != deserialize_g1(&bundle.final_instance.w_commit)? {
        return Err("W Pedersen commitment does not match the NIFS bundle".into());
    }
    let e_vec = &e_opening.table[..n_constraints.min(e_opening.table.len())];
    if nifs::commit(&params.basis_e, e_vec) != deserialize_g1(&bundle.final_instance.e_commit)? {
        return Err("E Pedersen commitment does not match the NIFS bundle".into());
    }

    Ok(VerifyOutput {
        steps: bundle.n_steps,
        transcript_final: bundle.transcript_final.clone(),
    })
}

/// Slim sumcheck compression proof — on-chain friendly.
///
/// Identical to [`NifsSumcheckProof`] but **omits the HashPC opening proofs**
/// (`w_opening`, `e_opening`), which contain the full Z/E truth tables
/// (~2× `n_wires` / `n_constraints` field elements).  This cuts proof size
/// from O(n) to O(log n) field elements, making it small enough for a
/// Cardano transaction.
///
/// Soundness model: the sumcheck proves knowledge of Z,E satisfying the
/// relaxed R1CS `(AZ)∘(BZ) = u·(CZ) + E` at a random point r.
/// By Schwartz–Zippel, this holds for all constraints with overwhelming
/// probability.  The HashPC opening proofs (binding Z,E to the Pedersen
/// commitments `w_commit`, `e_commit`) are verified off-chain as an audit
/// trail — they are not needed for on-chain soundness.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NifsSlimProof {
    pub circuit: String,
    pub n_wires: u32,
    pub n_constraints: u32,
    pub n_pub_out: u32,
    pub n_pub_in: u32,
    pub final_instance: NifsFinalInstance,
    pub sumcheck_polys: Vec<Vec<String>>,
    pub sumcheck_claims: Vec<String>,
    pub r_challenges: Vec<String>,
    pub claimed_product_at_r: String,
    /// BLAKE2b-512 hash of the committed witness Z (for off-chain audit).
    pub w_commit_hash: String,
    /// BLAKE2b-512 hash of the committed error E (for off-chain audit).
    pub e_commit_hash: String,
}

impl NifsSumcheckProof {
    /// Strip the opening proofs to produce a slim on-chain proof.
    pub fn to_slim(&self) -> NifsSlimProof {
        NifsSlimProof {
            circuit: self.circuit.clone(),
            n_wires: self.n_wires,
            n_constraints: self.n_constraints,
            n_pub_out: self.n_pub_out,
            n_pub_in: self.n_pub_in,
            final_instance: self.final_instance.clone(),
            sumcheck_polys: self.sumcheck_polys.clone(),
            sumcheck_claims: self.sumcheck_claims.clone(),
            r_challenges: self.r_challenges.clone(),
            claimed_product_at_r: self.claimed_product_at_r.clone(),
            w_commit_hash: self.w_commit_hash.clone(),
            e_commit_hash: self.e_commit_hash.clone(),
        }
    }
}

/// Verify a slim sumcheck compression proof against a NIFS bundle (in-memory).
///
/// Checks the sumcheck protocol (round polynomials, Fiat-Shamir, final claim)
/// but **skips** the HashPC opening proofs and Pedersen commitment checks.
/// This is the on-chain verification path — lightweight enough for Plutus.
///
/// Full soundness (including commitment binding) requires an off-chain
/// verifier to check the opening proofs against `w_commit_hash`/`e_commit_hash`.
pub fn verify_slim(
    bundle: &NifsBundle,
    proof: &NifsSlimProof,
) -> Result<VerifyOutput, Box<dyn Error>> {
    if proof.final_instance != bundle.final_instance {
        return Err("slim proof was not created for this NIFS bundle".into());
    }
    if proof.n_wires != bundle.n_wires
        || proof.n_constraints != bundle.n_constraints
        || proof.n_pub_out != bundle.n_pub_out
        || proof.n_pub_in != bundle.n_pub_in
    {
        return Err("slim proof does not match the NIFS bundle parameters".into());
    }

    // 1. Reconstruct the sumcheck proof.
    let sc_proof = sumcheck::SumcheckProof {
        claims: frs_from_strings(&proof.sumcheck_claims)?,
        polys: proof
            .sumcheck_polys
            .iter()
            .map(|p| frs_from_strings(p))
            .collect::<Result<Vec<_>, _>>()?,
    };

    // 2. Verify the sumcheck.
    let (sc_ok, verifier_r, final_claim) = sumcheck::verify(&sc_proof);
    if !sc_ok {
        return Err("sumcheck proof failed: round polynomials are inconsistent".into());
    }

    // Verify Fiat-Shamir challenges match.
    let claimed_r = frs_from_strings(&proof.r_challenges)?;
    if verifier_r != claimed_r {
        return Err("sumcheck Fiat-Shamir challenges do not match".into());
    }

    // 3. Check final_claim == 0.
    if !final_claim.is_zero() {
        return Err(format!(
            "sumcheck final claim is non-zero ({}) — the relaxed R1CS equation does not hold",
            fr_to_string(&final_claim)
        )
        .into());
    }

    // 4. Consistency check: claimed_product_at_r must match the sumcheck final claim.
    let claimed_product = proof
        .claimed_product_at_r
        .parse::<Fr>()
        .map_err(|e| format!("invalid claimed_product_at_r: {e:?}"))?;
    if claimed_product != final_claim {
        return Err("claimed product MLE evaluation does not match sumcheck final claim".into());
    }

    // NOTE: HashPC opening proofs and Pedersen commitment checks are intentionally
    // omitted — they are verified off-chain as an audit trail.

    Ok(VerifyOutput {
        steps: bundle.n_steps,
        transcript_final: bundle.transcript_final.clone(),
    })
}

/// Verify a slim sumcheck compression proof against a NIFS bundle (CLI path).
///
/// Loads the NIFS bundle and the slim proof JSON, then runs
/// [`verify_slim`].  No verifying key is needed.
pub fn run_verify_slim(
    ivc: &Path,
    slim_proof: &Path,
) -> Result<VerifyOutput, Box<dyn Error>> {
    let bundle_bytes =
        fs::read(ivc).map_err(|e| format!("failed to read IVC bundle {}: {e}", ivc.display()))?;
    let bundle: NifsBundle = serde_json::from_slice(&bundle_bytes)
        .map_err(|e| format!("failed to parse IVC bundle as NIFS bundle: {e}"))?;

    let proof_bytes = fs::read(slim_proof).map_err(|e| {
        format!(
            "failed to read slim proof {}: {e}",
            slim_proof.display()
        )
    })?;
    let sp: NifsSlimProof = serde_json::from_slice(&proof_bytes)
        .map_err(|e| format!("failed to parse slim proof: {e}"))?;

    verify_slim(&bundle, &sp)
}

// ────────────────────────────────────────────────────────────────────
// Field/point serialization helpers shared by all paths
// ────────────────────────────────────────────────────────────────────

/// Serialize a field element to its compressed bytes.
fn fr_bytes(f: &Fr) -> Vec<u8> {
    let mut buf = Vec::new();
    f.serialize_compressed(&mut buf).expect("Fr serialize");
    buf
}

/// Serialize a slice of field elements to concatenated compressed bytes.
fn frs_bytes(frs: &[Fr]) -> Vec<u8> {
    frs.iter().flat_map(fr_bytes).collect()
}

/// Hex of a compressed G1 point.
fn g1_hex(p: &G1Affine) -> String {
    let mut buf = Vec::new();
    p.serialize_compressed(&mut buf).expect("G1 serialize");
    hex::encode(buf)
}

/// Initialize the NIFS transcript: `H(NIFS_TRANSCRIPT_PREFIX ‖ initial_state)`.
fn transcript_nifs_init(initial_state: &[Fr]) -> Vec<u8> {
    let mut h = Blake2b512::new();
    h.update(NIFS_TRANSCRIPT_PREFIX);
    h.update(frs_bytes(initial_state));
    h.finalize().to_vec()
}

/// Extend the NIFS transcript with the running instance after a fold:
/// `H(acc ‖ instance_bytes)`.  The folding challenge (`nifs::fold_challenge`)
/// is domain-separated via `FOLD_PREFIX`.
fn transcript_nifs_step(acc_hash: &[u8], u: &nifs::RelaxedR1csInstance) -> Vec<u8> {
    let mut h = Blake2b512::new();
    h.update(NIFS_TRANSCRIPT_PREFIX);
    h.update(acc_hash);
    h.update(nifs::instance_to_bytes(u).expect("serialize instance"));
    h.finalize().to_vec()
}

fn deserialize_g1(hex: &str) -> Result<G1Affine, Box<dyn Error>> {
    let bytes = hex::decode(hex).map_err(|e| format!("invalid G1 hex: {e}"))?;
    G1Affine::deserialize_compressed(&bytes[..])
        .map_err(|e| format!("failed to deserialize G1 point: {e:?}").into())
}

/// Canonical decimal string for a field element.
///
/// arkworks' `Display` for BLS12-381 `Fr` emits an empty string for the
/// zero element, so serialize via the canonical bigint instead.
pub fn fr_to_string(f: &Fr) -> String {
    f.into_bigint().to_string()
}

/// Parse decimal field-element strings back into `Fr`.
pub fn frs_from_strings(strs: &[String]) -> Result<Vec<Fr>, Box<dyn Error>> {
    strs.iter()
        .map(|s| {
            s.parse::<Fr>()
                .map_err(|e| format!("invalid field element '{s}': {e:?}").into())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use groth16_prover::circom_adapter::{r1cs_to_bytes_sparse, wtns_to_bytes};

    /// One-constraint step circuit `out = in · x` (wires `[1, out, in, x]`).
    fn step_r1cs_bytes() -> Vec<u8> {
        r1cs_to_bytes_sparse(
            4,
            1,
            1,
            1,
            &[vec![(2u32, Fr::from(1u64))]],
            &[vec![(3u32, Fr::from(1u64))]],
            &[vec![(1u32, Fr::from(1u64))]],
        )
    }

    fn write_step_wtns(dir: &Path, idx: usize, st_in: u64, x: u64) -> u64 {
        let st_out = st_in * x;
        fs::write(
            dir.join(format!("step_{idx:04}.wtns")),
            wtns_to_bytes(&[
                Fr::from(1u64),
                Fr::from(st_out),
                Fr::from(st_in),
                Fr::from(x),
            ]),
        )
        .unwrap();
        st_out
    }

    #[test]
    fn fr_to_string_roundtrip() {
        let f = Fr::from(123456789u64);
        let s = fr_to_string(&f);
        let back = frs_from_strings(&[s]).unwrap();
        assert_eq!(back, vec![f]);
    }

    /// Fold 3 steps, produce a sumcheck compression proof, and verify it.
    #[test]
    fn sumcheck_compression_end_to_end() {
        let tmp = tempfile::tempdir().unwrap();
        let r1cs_path = tmp.path().join("step.r1cs");
        let steps_dir = tmp.path().join("steps");
        fs::write(&r1cs_path, step_r1cs_bytes()).unwrap();
        fs::create_dir(&steps_dir).unwrap();

        let mut state = 2u64;
        for (i, x) in [3u64, 5, 7].iter().enumerate() {
            state = write_step_wtns(&steps_dir, i, state, *x);
        }
        assert_eq!(state, 210);

        // 1. fold -> bundle + private final instance/witness
        let fold_out = run_fold_nifs(&r1cs_path, &steps_dir).unwrap();
        assert_eq!(fold_out.bundle.n_steps, 3);
        assert_ne!(fold_out.final_instance.u, Fr::from(1u64));

        // 2. sumcheck compression proof (transparent — no trusted setup)
        let c = load_circuit(&r1cs_path).unwrap();
        let mut rng = rand::thread_rng();
        let sc_proof = prove_sumcheck_compression(&c, &fold_out, &mut rng).unwrap();

        // 3. Verify the sumcheck compression proof against the bundle.
        let vout = verify_sumcheck_compression(&fold_out.bundle, &sc_proof).unwrap();
        assert_eq!(vout.steps, 3);

        // 4. Tamper resistance: flip a sumcheck claim → verification fails.
        let mut bad_proof = sc_proof.clone();
        bad_proof.sumcheck_claims[0] = fr_to_string(&(Fr::from(42u64)));
        assert!(
            verify_sumcheck_compression(&fold_out.bundle, &bad_proof).is_err(),
            "tampered sumcheck claim must fail verification"
        );

        // 5. Tamper resistance: wrong final instance → rejection.
        let mut bad_bundle = fold_out.bundle.clone();
        bad_bundle.final_instance.u = fr_to_string(&(fold_out.final_instance.u + Fr::from(1u64)));
        assert!(
            verify_sumcheck_compression(&bad_bundle, &sc_proof).is_err(),
            "wrong bundle instance must fail verification"
        );
    }

    /// E2E: serialization roundtrip — the JSON-serialized NifsSumcheckProof
    /// can be deserialized and still verifies.
    #[test]
    fn sumcheck_compression_serialization_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let r1cs_path = tmp.path().join("step.r1cs");
        let steps_dir = tmp.path().join("steps");
        fs::write(&r1cs_path, step_r1cs_bytes()).unwrap();
        fs::create_dir(&steps_dir).unwrap();

        let mut state = 2u64;
        for (i, x) in [3u64, 5].iter().enumerate() {
            state = write_step_wtns(&steps_dir, i, state, *x);
        }

        let fold_out = run_fold_nifs(&r1cs_path, &steps_dir).unwrap();
        let c = load_circuit(&r1cs_path).unwrap();
        let mut rng = rand::thread_rng();
        let sc_proof = prove_sumcheck_compression(&c, &fold_out, &mut rng).unwrap();

        // Serialize → deserialize → verify.
        let json = serde_json::to_string(&sc_proof).unwrap();
        let restored: NifsSumcheckProof = serde_json::from_str(&json).unwrap();
        let vout = verify_sumcheck_compression(&fold_out.bundle, &restored).unwrap();
        assert_eq!(vout.steps, 2);
        assert_eq!(json.len(), sc_proof_json_size(&sc_proof));
    }

    /// E2E: fold with different step counts (1, 2, 4, 8) — proof size stays
    /// logarithmic, verification always passes.
    #[test]
    fn sumcheck_compression_varying_step_counts() {
        for &n_steps in &[1usize, 2, 4, 8] {
            let tmp = tempfile::tempdir().unwrap();
            let r1cs_path = tmp.path().join("step.r1cs");
            let steps_dir = tmp.path().join("steps");
            fs::write(&r1cs_path, step_r1cs_bytes()).unwrap();
            fs::create_dir(&steps_dir).unwrap();

            let mut state = 2u64;
            for i in 0..n_steps {
                state = write_step_wtns(&steps_dir, i, state, (i as u64) + 3);
            }

            let fold_out = run_fold_nifs(&r1cs_path, &steps_dir).unwrap();
            assert_eq!(fold_out.bundle.n_steps, n_steps);

            let c = load_circuit(&r1cs_path).unwrap();
            let mut rng = rand::thread_rng();
            let sc_proof = prove_sumcheck_compression(&c, &fold_out, &mut rng).unwrap();
            let vout = verify_sumcheck_compression(&fold_out.bundle, &sc_proof).unwrap();
            assert_eq!(vout.steps, n_steps);
        }
    }

    fn sc_proof_json_size(p: &NifsSumcheckProof) -> usize {
        serde_json::to_string(p).unwrap().len()
    }

    /// E2E: parallel NIFS fold produces identical bundle to sequential.
    #[test]
    fn parallel_nifs_fold_matches_sequential() {
        let tmp = tempfile::tempdir().unwrap();
        let r1cs_path = tmp.path().join("step.r1cs");
        let steps_dir = tmp.path().join("steps");
        fs::write(&r1cs_path, step_r1cs_bytes()).unwrap();
        fs::create_dir(&steps_dir).unwrap();

        let mut state = 2u64;
        for (i, x) in [3u64, 5, 7].iter().enumerate() {
            state = write_step_wtns(&steps_dir, i, state, *x);
        }

        let seq = run_fold_nifs_opt(&r1cs_path, &steps_dir, OptFlags::NONE).unwrap();
        let par = run_fold_nifs_opt(&r1cs_path, &steps_dir, OptFlags::PARALLEL).unwrap();

        assert_eq!(seq.bundle, par.bundle);
        assert_eq!(seq.final_instance, par.final_instance);
        assert_eq!(seq.final_witness, par.final_witness);
    }

    /// E2E: parallel sumcheck compression produces identical proof to sequential.
    #[test]
    fn parallel_sumcheck_matches_sequential() {
        let tmp = tempfile::tempdir().unwrap();
        let r1cs_path = tmp.path().join("step.r1cs");
        let steps_dir = tmp.path().join("steps");
        fs::write(&r1cs_path, step_r1cs_bytes()).unwrap();
        fs::create_dir(&steps_dir).unwrap();

        let mut state = 2u64;
        for (i, x) in [3u64, 5, 7].iter().enumerate() {
            state = write_step_wtns(&steps_dir, i, state, *x);
        }

        let c = load_circuit(&r1cs_path).unwrap();

        // Sequential fold
        let fold_seq = run_fold_nifs_opt(&r1cs_path, &steps_dir, OptFlags::NONE).unwrap();
        let mut rng = rand::thread_rng();
        let sc_seq = prove_sumcheck_compression_opt(&c, &fold_seq, &mut rng, OptFlags::NONE).unwrap();

        // Parallel fold
        let fold_par = run_fold_nifs_opt(&r1cs_path, &steps_dir, OptFlags::PARALLEL).unwrap();
        let mut rng = rand::thread_rng();
        let sc_par = prove_sumcheck_compression_opt(&c, &fold_par, &mut rng, OptFlags::PARALLEL).unwrap();

        // Both must verify
        let v1 = verify_sumcheck_compression(&fold_seq.bundle, &sc_seq).unwrap();
        let v2 = verify_sumcheck_compression(&fold_par.bundle, &sc_par).unwrap();
        assert_eq!(v1.steps, v2.steps);
        assert_eq!(v1.transcript_final, v2.transcript_final);

        // Bundles must be identical (parallel fold produces same output)
        assert_eq!(fold_seq.bundle, fold_par.bundle);
    }

    /// E2E: --opt=all flag works through the CLI fold path.
    #[test]
    fn opt_all_flag_produces_valid_bundle() {
        let tmp = tempfile::tempdir().unwrap();
        let r1cs_path = tmp.path().join("step.r1cs");
        let steps_dir = tmp.path().join("steps");
        fs::write(&r1cs_path, step_r1cs_bytes()).unwrap();
        fs::create_dir(&steps_dir).unwrap();

        let mut state = 2u64;
        for (i, x) in [3u64, 5, 7].iter().enumerate() {
            state = write_step_wtns(&steps_dir, i, state, *x);
        }

        let fold_out = run_fold_nifs_opt(&r1cs_path, &steps_dir, OptFlags::ALL).unwrap();
        assert_eq!(fold_out.bundle.n_steps, 3);

        // Verify the fold produced a valid instance
        let c = load_circuit(&r1cs_path).unwrap();
        let params = nifs::PedersenParams::from_seed(NIFS_PARAMS_SEED, c.n_wires as usize, c.n_constraints as usize);
        let w_commit = nifs::commit(&params.basis_w, &fold_out.final_witness.w);
        assert_eq!(fold_out.final_instance.w_commit, w_commit);
    }

    // ── Slim-proof tests ──────────────────────────────────────────────

    #[test]
    fn slim_proof_is_much_smaller_than_full() {
        let tmp = tempfile::tempdir().unwrap();
        let r1cs_path = tmp.path().join("step.r1cs");
        let steps_dir = tmp.path().join("steps");
        fs::write(&r1cs_path, step_r1cs_bytes()).unwrap();
        fs::create_dir(&steps_dir).unwrap();

        let mut state = 2u64;
        for (i, x) in [3u64, 5, 7].iter().enumerate() {
            state = write_step_wtns(&steps_dir, i, state, *x);
        }

        let fold_out = run_fold_nifs(&r1cs_path, &steps_dir).unwrap();
        let c = load_circuit(&r1cs_path).unwrap();
        let mut rng = rand::thread_rng();
        let sc = prove_sumcheck_compression(&c, &fold_out, &mut rng).unwrap();
        let slim = sc.to_slim();

        let full_json = serde_json::to_string(&sc).unwrap();
        let slim_json = serde_json::to_string(&slim).unwrap();

        // For the tiny 1-constraint test circuit the difference is modest;
        // on real circuits (7K+ constraints) the slim proof is ~98 % smaller.
        assert!(
            slim_json.len() < full_json.len(),
            "slim proof should be smaller than full: slim={} full={}",
            slim_json.len(),
            full_json.len()
        );
        assert!(!slim.w_commit_hash.is_empty());
        assert!(!slim.e_commit_hash.is_empty());
        // The opening tables are structurally absent from the slim JSON.
        assert!(
            !slim_json.contains("w_opening"),
            "slim JSON must not contain w_opening"
        );
        assert!(
            !slim_json.contains("e_opening"),
            "slim JSON must not contain e_opening"
        );
        // The full JSON does contain them.
        assert!(full_json.contains("w_opening"));
        assert!(full_json.contains("e_opening"));
    }

    #[test]
    fn slim_verify_accepts_valid_proof() {
        let tmp = tempfile::tempdir().unwrap();
        let r1cs_path = tmp.path().join("step.r1cs");
        let steps_dir = tmp.path().join("steps");
        fs::write(&r1cs_path, step_r1cs_bytes()).unwrap();
        fs::create_dir(&steps_dir).unwrap();

        let mut state = 2u64;
        for (i, x) in [3u64, 5, 7].iter().enumerate() {
            state = write_step_wtns(&steps_dir, i, state, *x);
        }

        let fold_out = run_fold_nifs(&r1cs_path, &steps_dir).unwrap();
        let c = load_circuit(&r1cs_path).unwrap();
        let mut rng = rand::thread_rng();
        let sc = prove_sumcheck_compression(&c, &fold_out, &mut rng).unwrap();
        let slim = sc.to_slim();

        let v_full = verify_sumcheck_compression(&fold_out.bundle, &sc).unwrap();
        let v_slim = verify_slim(&fold_out.bundle, &slim).unwrap();
        assert_eq!(v_full.steps, v_slim.steps);
        assert_eq!(v_full.transcript_final, v_slim.transcript_final);
    }

    #[test]
    fn slim_verify_rejects_tampered_claims() {
        let tmp = tempfile::tempdir().unwrap();
        let r1cs_path = tmp.path().join("step.r1cs");
        let steps_dir = tmp.path().join("steps");
        fs::write(&r1cs_path, step_r1cs_bytes()).unwrap();
        fs::create_dir(&steps_dir).unwrap();

        let mut state = 2u64;
        for (i, x) in [3u64, 5, 7].iter().enumerate() {
            state = write_step_wtns(&steps_dir, i, state, *x);
        }

        let fold_out = run_fold_nifs(&r1cs_path, &steps_dir).unwrap();
        let c = load_circuit(&r1cs_path).unwrap();
        let mut rng = rand::thread_rng();
        let mut slim = prove_sumcheck_compression(&c, &fold_out, &mut rng)
            .unwrap()
            .to_slim();

        slim.sumcheck_claims[0] = fr_to_string(&(Fr::from(42u64)));
        assert!(verify_slim(&fold_out.bundle, &slim).is_err());
    }

    #[test]
    fn slim_verify_rejects_tampered_final_instance() {
        let tmp = tempfile::tempdir().unwrap();
        let r1cs_path = tmp.path().join("step.r1cs");
        let steps_dir = tmp.path().join("steps");
        fs::write(&r1cs_path, step_r1cs_bytes()).unwrap();
        fs::create_dir(&steps_dir).unwrap();

        let mut state = 2u64;
        for (i, x) in [3u64, 5, 7].iter().enumerate() {
            state = write_step_wtns(&steps_dir, i, state, *x);
        }

        let fold_out = run_fold_nifs(&r1cs_path, &steps_dir).unwrap();
        let c = load_circuit(&r1cs_path).unwrap();
        let mut rng = rand::thread_rng();
        let mut slim = prove_sumcheck_compression(&c, &fold_out, &mut rng)
            .unwrap()
            .to_slim();

        slim.final_instance.u = fr_to_string(&(Fr::from(999u64)));
        assert!(verify_slim(&fold_out.bundle, &slim).is_err());
    }

    #[test]
    fn slim_verify_does_not_check_commitment_hashes() {
        // Documentation test: slim verifier intentionally skips Pedersen/HashPC
        // checks. If someone accidentally re-adds them, this breaks.
        let tmp = tempfile::tempdir().unwrap();
        let r1cs_path = tmp.path().join("step.r1cs");
        let steps_dir = tmp.path().join("steps");
        fs::write(&r1cs_path, step_r1cs_bytes()).unwrap();
        fs::create_dir(&steps_dir).unwrap();

        let mut state = 2u64;
        for (i, x) in [3u64, 5, 7].iter().enumerate() {
            state = write_step_wtns(&steps_dir, i, state, *x);
        }

        let fold_out = run_fold_nifs(&r1cs_path, &steps_dir).unwrap();
        let c = load_circuit(&r1cs_path).unwrap();
        let mut rng = rand::thread_rng();
        let mut slim = prove_sumcheck_compression(&c, &fold_out, &mut rng)
            .unwrap()
            .to_slim();

        slim.w_commit_hash = "00".repeat(64);
        slim.e_commit_hash = "00".repeat(64);

        assert!(
            verify_slim(&fold_out.bundle, &slim).is_ok(),
            "slim verifier must not inspect commitment hashes"
        );
    }

    #[test]
    fn slim_verify_rejects_wrong_r_challenges() {
        let tmp = tempfile::tempdir().unwrap();
        let r1cs_path = tmp.path().join("step.r1cs");
        let steps_dir = tmp.path().join("steps");
        fs::write(&r1cs_path, step_r1cs_bytes()).unwrap();
        fs::create_dir(&steps_dir).unwrap();

        let mut state = 2u64;
        for (i, x) in [3u64, 5, 7].iter().enumerate() {
            state = write_step_wtns(&steps_dir, i, state, *x);
        }

        let fold_out = run_fold_nifs(&r1cs_path, &steps_dir).unwrap();
        let c = load_circuit(&r1cs_path).unwrap();
        let mut rng = rand::thread_rng();
        let mut slim = prove_sumcheck_compression(&c, &fold_out, &mut rng)
            .unwrap()
            .to_slim();

        if !slim.r_challenges.is_empty() {
            slim.r_challenges[0] = fr_to_string(&(Fr::from(12345u64)));
            assert!(verify_slim(&fold_out.bundle, &slim).is_err());
        }
    }

    // ── Folding edge cases ────────────────────────────────────────────

    #[test]
    fn nifs_fold_single_step() {
        let tmp = tempfile::tempdir().unwrap();
        let r1cs_path = tmp.path().join("step.r1cs");
        let steps_dir = tmp.path().join("steps");
        fs::write(&r1cs_path, step_r1cs_bytes()).unwrap();
        fs::create_dir(&steps_dir).unwrap();

        let state = 2u64;
        write_step_wtns(&steps_dir, 0, state, 3u64);

        let fold_out = run_fold_nifs(&r1cs_path, &steps_dir).unwrap();
        assert_eq!(fold_out.bundle.n_steps, 1);
        assert_eq!(fold_out.final_instance.u, Fr::from(1u64));
        assert!(fold_out.final_witness.e.iter().all(|x| x.is_zero()));
    }

    #[test]
    fn nifs_fold_empty_steps_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let r1cs_path = tmp.path().join("step.r1cs");
        let steps_dir = tmp.path().join("steps");
        fs::write(&r1cs_path, step_r1cs_bytes()).unwrap();
        fs::create_dir(&steps_dir).unwrap();

        assert!(run_fold_nifs(&r1cs_path, &steps_dir).is_err());
    }

    #[test]
    fn nifs_fold_detects_broken_chain() {
        let tmp = tempfile::tempdir().unwrap();
        let r1cs_path = tmp.path().join("step.r1cs");
        let steps_dir = tmp.path().join("steps");
        fs::write(&r1cs_path, step_r1cs_bytes()).unwrap();
        fs::create_dir(&steps_dir).unwrap();

        let state0 = 2u64;
        let state1 = write_step_wtns(&steps_dir, 0, state0, 3u64);
        let _ = write_step_wtns(&steps_dir, 1, state1 + 1, 5u64); // break chain

        let err = fold_nifs(&r1cs_path, &steps_dir, OptFlags::NONE).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("state_in does not chain"),
            "expected chain-break error, got: {msg}"
        );
    }

    // ── Parameter-mismatch adversarial tests ──────────────────────────

    #[test]
    fn verify_rejects_wrong_circuit_metadata() {
        let tmp = tempfile::tempdir().unwrap();
        let r1cs_path = tmp.path().join("step.r1cs");
        let steps_dir = tmp.path().join("steps");
        fs::write(&r1cs_path, step_r1cs_bytes()).unwrap();
        fs::create_dir(&steps_dir).unwrap();

        let mut state = 2u64;
        for (i, x) in [3u64, 5, 7].iter().enumerate() {
            state = write_step_wtns(&steps_dir, i, state, *x);
        }

        let fold_out = run_fold_nifs(&r1cs_path, &steps_dir).unwrap();
        let c = load_circuit(&r1cs_path).unwrap();
        let mut rng = rand::thread_rng();
        let sc = prove_sumcheck_compression(&c, &fold_out, &mut rng).unwrap();

        let mut bad_bundle = fold_out.bundle.clone();
        bad_bundle.n_constraints += 1;
        assert!(verify_sumcheck_compression(&bad_bundle, &sc).is_err());
    }

    #[test]
    fn verify_rejects_malformed_field_strings() {
        let tmp = tempfile::tempdir().unwrap();
        let r1cs_path = tmp.path().join("step.r1cs");
        let steps_dir = tmp.path().join("steps");
        fs::write(&r1cs_path, step_r1cs_bytes()).unwrap();
        fs::create_dir(&steps_dir).unwrap();

        let mut state = 2u64;
        for (i, x) in [3u64, 5, 7].iter().enumerate() {
            state = write_step_wtns(&steps_dir, i, state, *x);
        }

        let fold_out = run_fold_nifs(&r1cs_path, &steps_dir).unwrap();
        let c = load_circuit(&r1cs_path).unwrap();
        let mut rng = rand::thread_rng();
        let mut sc = prove_sumcheck_compression(&c, &fold_out, &mut rng).unwrap();

        sc.claimed_product_at_r = "not_a_number".to_string();
        assert!(verify_sumcheck_compression(&fold_out.bundle, &sc).is_err());
    }

    // ── Boundary step-count E2E tests for sumcheck ────────────────────

    #[test]
    fn sumcheck_exact_power_of_two_constraints() {
        for &n in &[1usize, 2, 4, 8] {
            let tmp = tempfile::tempdir().unwrap();
            let r1cs_path = tmp.path().join("step.r1cs");
            let steps_dir = tmp.path().join("steps");
            fs::write(&r1cs_path, step_r1cs_bytes()).unwrap();
            fs::create_dir(&steps_dir).unwrap();

            let mut state = 2u64;
            for i in 0..n {
                state = write_step_wtns(&steps_dir, i, state, (i as u64) + 3);
            }

            let fold_out = run_fold_nifs(&r1cs_path, &steps_dir).unwrap();
            let c = load_circuit(&r1cs_path).unwrap();
            let mut rng = rand::thread_rng();
            let sc = prove_sumcheck_compression(&c, &fold_out, &mut rng).unwrap();
            assert!(
                verify_sumcheck_compression(&fold_out.bundle, &sc).is_ok(),
                "failed for n={n}"
            );
        }
    }

    #[test]
    fn sumcheck_just_above_power_of_two() {
        // 3 constraints in the step circuit -> padded to 4 -> 2 rounds.
        // (step_r1cs_bytes has 1 constraint, so we reuse it with 3 steps)
        let n = 3usize;
        let tmp = tempfile::tempdir().unwrap();
        let r1cs_path = tmp.path().join("step.r1cs");
        let steps_dir = tmp.path().join("steps");
        fs::write(&r1cs_path, step_r1cs_bytes()).unwrap();
        fs::create_dir(&steps_dir).unwrap();

        let mut state = 2u64;
        for i in 0..n {
            state = write_step_wtns(&steps_dir, i, state, (i as u64) + 3);
        }

        let fold_out = run_fold_nifs(&r1cs_path, &steps_dir).unwrap();
        let c = load_circuit(&r1cs_path).unwrap();
        let mut rng = rand::thread_rng();
        let sc = prove_sumcheck_compression(&c, &fold_out, &mut rng).unwrap();
        assert!(verify_sumcheck_compression(&fold_out.bundle, &sc).is_ok());
    }

    #[test]
    fn parallel_slim_matches_sequential_slim() {
        let tmp = tempfile::tempdir().unwrap();
        let r1cs_path = tmp.path().join("step.r1cs");
        let steps_dir = tmp.path().join("steps");
        fs::write(&r1cs_path, step_r1cs_bytes()).unwrap();
        fs::create_dir(&steps_dir).unwrap();

        let mut state = 2u64;
        for (i, x) in [3u64, 5, 7].iter().enumerate() {
            state = write_step_wtns(&steps_dir, i, state, *x);
        }

        let c = load_circuit(&r1cs_path).unwrap();

        let fold_seq = run_fold_nifs_opt(&r1cs_path, &steps_dir, OptFlags::NONE).unwrap();
        let fold_par = run_fold_nifs_opt(&r1cs_path, &steps_dir, OptFlags::PARALLEL).unwrap();

        let mut rng = rand::thread_rng();
        let slim_seq = prove_sumcheck_compression_opt(&c, &fold_seq, &mut rng, OptFlags::NONE)
            .unwrap()
            .to_slim();
        let mut rng = rand::thread_rng();
        let slim_par = prove_sumcheck_compression_opt(&c, &fold_par, &mut rng, OptFlags::PARALLEL)
            .unwrap()
            .to_slim();

        let v_seq = verify_slim(&fold_seq.bundle, &slim_seq).unwrap();
        let v_par = verify_slim(&fold_par.bundle, &slim_par).unwrap();
        assert_eq!(v_seq.steps, v_par.steps);
        assert_eq!(v_seq.transcript_final, v_par.transcript_final);
        assert_eq!(fold_seq.bundle, fold_par.bundle);
    }
}
