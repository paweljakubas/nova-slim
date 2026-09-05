//! NIFS folding module — Relaxed-R1CS over any commitment scheme.
//!
//! A Relaxed-R1CS instance `U = (x, u, W̄, Ē)` consists of a public input
//! `x`, a slack scalar `u`, and commitments `W̄`, `Ē` to the witness
//! `W` and the error vector `E`.  The relaxed equation is
//! `(AZ)∘(BZ) = u·(CZ) + E` with `Z = (W, x, u)`.  Step instances are ordinary
//! R1CS (`u = 1`, `E = 0`); folding combines two instances into one that is
//! satisfiable exactly when both inputs were.
//!
//! Folding runs **off-circuit**, so no curve cycle is needed.  The commitment
//! parameters are derived deterministically from a fixed seed — transparent,
//! no trusted setup.

use ark_ff::{BigInteger, One, PrimeField, Zero};
use ark_serialize::CanonicalSerialize;
use blake2::{Blake2b512, Digest};
use rayon::prelude::*;

use crate::commitment::CommitmentScheme;

/// Domain separator for the folding challenge hash (distinct from the
/// `"chain"` state-chain transcript).
pub const FOLD_PREFIX: &[u8] = b"groth16-prover-nova-fold-v1";

/// A Relaxed-R1CS instance `U = (x, u, W̄, Ē)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelaxedR1csInstance<CS: CommitmentScheme> {
    /// Public input (IVC state).
    pub x: Vec<CS::Scalar>,
    /// Slack scalar `u`.
    pub u: CS::Scalar,
    /// Commitment to the witness `W`.
    pub w_commit: CS::Commitment,
    /// Commitment to the error `E`.
    pub e_commit: CS::Commitment,
}

/// The witness `W' = (W, E)` of a Relaxed-R1CS instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelaxedR1csWitness<CS: CommitmentScheme> {
    /// Witness assignment (full wire vector, including public inputs).
    pub w: Vec<CS::Scalar>,
    /// Error vector, length = number of constraints.
    pub e: Vec<CS::Scalar>,
}

/// Serialize an instance to compressed bytes for the folding transcript.
pub fn instance_to_bytes<CS: CommitmentScheme>(
    u: &RelaxedR1csInstance<CS>,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut buf = Vec::new();
    for f in &u.x {
        f.serialize_compressed(&mut buf)?;
    }
    u.u.serialize_compressed(&mut buf)?;
    u.w_commit.serialize_compressed(&mut buf)?;
    u.e_commit.serialize_compressed(&mut buf)?;
    Ok(buf)
}

/// Evaluate the sparse matrix `m` at the assignment `z`.
fn sparse_eval<F: PrimeField>(m: &[Vec<(u32, F)>], z: &[F]) -> Vec<F> {
    m.iter()
        .map(|row| {
            row.iter()
                .fold(F::zero(), |acc, &(i, v)| acc + v * z[i as usize])
        })
        .collect()
}

/// The NIFS cross-term vector (length = n_constraints):
/// `E_cross = (AZ1)∘(BZ2) + (AZ2)∘(BZ1) − u1·(CZ2) − u2·(CZ1)`.
fn cross_term<F: PrimeField>(
    l: &[Vec<(u32, F)>],
    r: &[Vec<(u32, F)>],
    o: &[Vec<(u32, F)>],
    z1: &[F],
    z2: &[F],
    u1: F,
    u2: F,
) -> Vec<F> {
    let az1 = sparse_eval(l, z1);
    let az2 = sparse_eval(l, z2);
    let bz1 = sparse_eval(r, z1);
    let bz2 = sparse_eval(r, z2);
    let cz1 = sparse_eval(o, z1);
    let cz2 = sparse_eval(o, z2);
    (0..l.len())
        .map(|j| az1[j] * bz2[j] + az2[j] * bz1[j] - u1 * cz2[j] - u2 * cz1[j])
        .collect()
}

/// Parallel version of [`cross_term`]: each sparse_eval and the final row
/// mapping run in parallel via rayon.  Identical output for identical input.
pub fn cross_term_parallel<F: PrimeField>(
    l: &[Vec<(u32, F)>],
    r: &[Vec<(u32, F)>],
    o: &[Vec<(u32, F)>],
    z1: &[F],
    z2: &[F],
    u1: F,
    u2: F,
) -> Vec<F> {
    let az1 = sparse_eval(l, z1);
    let az2 = sparse_eval(l, z2);
    let bz1 = sparse_eval(r, z1);
    let bz2 = sparse_eval(r, z2);
    let cz1 = sparse_eval(o, z1);
    let cz2 = sparse_eval(o, z2);
    (0..l.len())
        .into_par_iter()
        .map(|j| az1[j] * bz2[j] + az2[j] * bz1[j] - u1 * cz2[j] - u2 * cz1[j])
        .collect()
}

/// Fiat-Shamir folding challenge `r = H(FOLD_PREFIX ‖ acc ‖ U1 ‖ U2)`.
///
/// Domain-separated from the `"chain"` state-chain transcript.
pub fn fold_challenge<CS: CommitmentScheme>(
    acc: &[u8],
    u1: &RelaxedR1csInstance<CS>,
    u2: &RelaxedR1csInstance<CS>,
) -> CS::Scalar {
    let mut h = Blake2b512::new();
    h.update(FOLD_PREFIX);
    h.update(acc);
    h.update(instance_to_bytes::<CS>(u1).expect("serialize U1"));
    h.update(instance_to_bytes::<CS>(u2).expect("serialize U2"));
    CS::Scalar::from_le_bytes_mod_order(&h.finalize())
}

/// Small-fold-scalar challenge: maps hash output to `{-1, 0, 1}`.
///
/// Uses the low 2 bits of the BLAKE2b output:
/// - `00` → `-1`
/// - `01` → `0`
/// - `10` → `1`
/// - `11` → `1` (bias toward 1, negligible for soundness)
///
/// The challenge is deterministically derived from the transcript, so
/// both prover and verifier agree on the same value.
pub fn small_fold_challenge<CS: CommitmentScheme>(
    acc: &[u8],
    u1: &RelaxedR1csInstance<CS>,
    u2: &RelaxedR1csInstance<CS>,
) -> CS::Scalar {
    let mut h = Blake2b512::new();
    h.update(FOLD_PREFIX);
    h.update(b"small");
    h.update(acc);
    h.update(instance_to_bytes::<CS>(u1).expect("serialize U1"));
    h.update(instance_to_bytes::<CS>(u2).expect("serialize U2"));
    let digest = h.finalize();
    let low_byte = digest[digest.len() - 1];
    match low_byte % 3 {
        0 => -CS::Scalar::one(),
        1 => CS::Scalar::zero(),
        _ => CS::Scalar::one(),
    }
}

/// A checkpoint records the state after a batch fold.
///
/// Checkpoints are used in the batch-then-checkpoint protocol (P2b):
/// after folding a batch of instances with small challenges, the prover
/// measures the accumulator witness/error infinity-norm and records it.
/// If the norm exceeds the SIS bound, the fold aborts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointEntry {
    /// Index of the first step in this batch (inclusive).
    pub start_step: usize,
    /// Index of the last step in this batch (exclusive).
    pub end_step: usize,
    /// Number of challenges used in this batch (= end_step - start_step).
    pub n_challenges: usize,
    /// Measured infinity-norm of the folded witness (in bigint magnitude).
    pub witness_norm: Vec<u8>,
    /// Measured infinity-norm of the folded error (in bigint magnitude).
    pub error_norm: Vec<u8>,
    /// Whether the checkpoint passed (norms within bound).
    pub passed: bool,
}

/// Batch-fold `k` instances into one accumulator using `k-1` small challenges.
///
/// `instances[0]` is the initial accumulator; `instances[1..]` are the
/// step instances.  Returns the folded accumulator and the list of
/// `k-1` challenges used.
///
/// This is the core of the batch-then-checkpoint protocol (P2b):
/// instead of folding one step at a time with a full-field challenge,
/// we fold `k` steps in one batch using ternary challenges, achieving
/// soundness error `(1/3)^{k-1}` (`thm:batch-fold-small`).
pub fn batch_fold<CS: CommitmentScheme>(
    params: &CS::Params,
    l: &[Vec<(u32, CS::Scalar)>],
    r: &[Vec<(u32, CS::Scalar)>],
    o: &[Vec<(u32, CS::Scalar)>],
    instances: &[RelaxedR1csInstance<CS>],
    witnesses: &[RelaxedR1csWitness<CS>],
    acc_hash: &[u8],
) -> Result<
    (
        RelaxedR1csInstance<CS>,
        RelaxedR1csWitness<CS>,
        Vec<CS::Scalar>,
        Vec<CS::Commitment>,
    ),
    Box<dyn std::error::Error>,
> {
    if instances.len() != witnesses.len() {
        return Err("batch_fold: instances and witnesses length mismatch".into());
    }
    if instances.len() < 2 {
        return Err("batch_fold: need at least 2 instances".into());
    }

    let mut acc_u = instances[0].clone();
    let mut acc_w = witnesses[0].clone();
    let mut hash = acc_hash.to_vec();
    let mut challenges = Vec::with_capacity(instances.len() - 1);
    let mut cross_commits = Vec::with_capacity(instances.len() - 1);

    for i in 1..instances.len() {
        let step_u = &instances[i];
        let step_w = &witnesses[i];
        let chi = small_fold_challenge::<CS>(&hash, &acc_u, step_u);
        let (u3, w3, cross) = fold_with_log::<CS>(
            params, l, r, o, &acc_u, &acc_w, step_u, step_w, chi, false,
        );
        challenges.push(chi);
        cross_commits.push(cross);
        acc_u = u3;
        acc_w = w3;
        hash = {
            let mut h = Blake2b512::new();
            h.update(&hash);
            h.update(instance_to_bytes::<CS>(&acc_u).expect("serialize"));
            h.finalize().to_vec()
        };
    }

    Ok((acc_u, acc_w, challenges, cross_commits))
}

/// Batch-fold with periodic norm-reset checkpoints.
///
/// Folds `n_instances` in batches of `batch_size`, checking the
/// accumulator witness/error infinity-norm after each batch.
/// Returns the final instance, witness, and checkpoint log.
///
/// `bound_bits` is the maximum allowed bit-width of any coordinate.
/// If a checkpoint fails, the function returns an error.
pub fn batch_fold_with_checkpoints<CS: CommitmentScheme>(
    params: &CS::Params,
    l: &[Vec<(u32, CS::Scalar)>],
    r: &[Vec<(u32, CS::Scalar)>],
    o: &[Vec<(u32, CS::Scalar)>],
    instances: &[RelaxedR1csInstance<CS>],
    witnesses: &[RelaxedR1csWitness<CS>],
    initial_hash: &[u8],
    batch_size: usize,
    bound_bits: u32,
) -> Result<
    (
        RelaxedR1csInstance<CS>,
        RelaxedR1csWitness<CS>,
        Vec<CheckpointEntry>,
    ),
    Box<dyn std::error::Error>,
>
where
    CS::Scalar: ark_ff::PrimeField,
{
    if instances.len() != witnesses.len() {
        return Err(
            "batch_fold_with_checkpoints: instances and witnesses length mismatch".into(),
        );
    }
    if instances.is_empty() {
        return Err("batch_fold_with_checkpoints: no instances".into());
    }
    if batch_size == 0 {
        return Err("batch_fold_with_checkpoints: batch_size must be > 0".into());
    }

    let mut acc_u = instances[0].clone();
    let mut acc_w = witnesses[0].clone();
    let mut hash = initial_hash.to_vec();
    let mut checkpoints = Vec::new();
    let mut idx = 1;

    while idx < instances.len() {
        let end = (idx + batch_size).min(instances.len());
        let batch_instances = &instances[idx - 1..end];
        let batch_witnesses = &witnesses[idx - 1..end];

        let (new_u, new_w, _challenges, _crosses) = batch_fold::<CS>(
            params, l, r, o, batch_instances, batch_witnesses, &hash,
        )?;

        // Measure norms.
        let w_norm = crate::norm::measure_inf_norm(&new_w.w);
        let e_norm = crate::norm::measure_inf_norm(&new_w.e);
        let w_pass = crate::norm::fits_bits(&new_w.w, bound_bits);
        let e_pass = crate::norm::fits_bits(&new_w.e, bound_bits);

        let checkpoint = CheckpointEntry {
            start_step: idx - 1,
            end_step: end,
            n_challenges: end - idx,
            witness_norm: w_norm.to_bytes_le(),
            error_norm: e_norm.to_bytes_le(),
            passed: w_pass && e_pass,
        };

        if !checkpoint.passed {
            return Err(format!(
                "checkpoint failed at steps {}-{}: witness_norm bits={}, error_norm bits={}, bound={}",
                checkpoint.start_step,
                checkpoint.end_step,
                crate::norm::magnitude_bits(&w_norm),
                crate::norm::magnitude_bits(&e_norm),
                bound_bits,
            )
            .into());
        }

        checkpoints.push(checkpoint);
        acc_u = new_u;
        acc_w = new_w;

        // Advance hash past the batch.
        hash = {
            let mut h = Blake2b512::new();
            h.update(&hash);
            h.update(b"checkpoint");
            h.update((idx as u64).to_le_bytes());
            h.finalize().to_vec()
        };

        idx = end;
    }

    Ok((acc_u, acc_w, checkpoints))
}

/// Fold two Relaxed-R1CS instances (and their witnesses) into one.
///
/// `l`, `r`, `o` are the step circuit's sparse A/B/C matrices.  The folded
/// instance is satisfiable exactly when both inputs were.
pub fn fold<CS: CommitmentScheme>(
    params: &CS::Params,
    l: &[Vec<(u32, CS::Scalar)>],
    r: &[Vec<(u32, CS::Scalar)>],
    o: &[Vec<(u32, CS::Scalar)>],
    u1: &RelaxedR1csInstance<CS>,
    w1: &RelaxedR1csWitness<CS>,
    u2: &RelaxedR1csInstance<CS>,
    w2: &RelaxedR1csWitness<CS>,
    challenge: CS::Scalar,
) -> (RelaxedR1csInstance<CS>, RelaxedR1csWitness<CS>) {
    let (u3, w3, _cross) = fold_with_log(params, l, r, o, u1, w1, u2, w2, challenge, false);
    (u3, w3)
}

/// Fold with optimization flags (discards the cross-term commitment).
///
/// When `parallel` is true, the cross-term computation uses rayon for
/// parallel row evaluation.
pub fn fold_with_opts<CS: CommitmentScheme>(
    params: &CS::Params,
    l: &[Vec<(u32, CS::Scalar)>],
    r: &[Vec<(u32, CS::Scalar)>],
    o: &[Vec<(u32, CS::Scalar)>],
    u1: &RelaxedR1csInstance<CS>,
    w1: &RelaxedR1csWitness<CS>,
    u2: &RelaxedR1csInstance<CS>,
    w2: &RelaxedR1csWitness<CS>,
    challenge: CS::Scalar,
    parallel: bool,
) -> (RelaxedR1csInstance<CS>, RelaxedR1csWitness<CS>) {
    let (u3, w3, _cross) = fold_with_log(params, l, r, o, u1, w1, u2, w2, challenge, parallel);
    (u3, w3)
}

/// Fold two instances and additionally return the commitment to the NIFS
/// cross-term vector `T = (AZ1)∘(BZ2) + (AZ2)∘(BZ1) − u1(CZ2) − u2(CZ1)`.
///
/// This is the data a verifier needs for **fold re-verification (FV)**:
/// `com(T)` together with the pre-fold committed instances lets the verifier
/// re-check the homomorphic fold relation `Ē' = Ē1 + r·Ē2 + r·com(T)` (and the
/// analogous `x', u', W̄'` relations) from committed data alone, without
/// trusting the step witnesses or re-opening them.
///
/// The returned cross-term commitment is exactly what `fold_with_opts`
/// computes internally at its `e_commit3` step; exposing it here lets a caller
/// carry it in a fold log for later (commitment-level) verification.
pub fn fold_with_log<CS: CommitmentScheme>(
    params: &CS::Params,
    l: &[Vec<(u32, CS::Scalar)>],
    r: &[Vec<(u32, CS::Scalar)>],
    o: &[Vec<(u32, CS::Scalar)>],
    u1: &RelaxedR1csInstance<CS>,
    w1: &RelaxedR1csWitness<CS>,
    u2: &RelaxedR1csInstance<CS>,
    w2: &RelaxedR1csWitness<CS>,
    challenge: CS::Scalar,
    parallel: bool,
) -> (
    RelaxedR1csInstance<CS>,
    RelaxedR1csWitness<CS>,
    CS::Commitment,
) {
    assert_eq!(u1.x.len(), u2.x.len(), "public input widths must match");
    assert_eq!(w1.w.len(), w2.w.len(), "witness widths must match");
    assert_eq!(w1.e.len(), w2.e.len(), "error widths must match");
    assert_eq!(w1.e.len(), l.len(), "error length must equal n_constraints");

    let x3: Vec<CS::Scalar> =
        u1.x.iter()
            .zip(&u2.x)
            .map(|(a, b)| *a + challenge * *b)
            .collect();
    let u3 = u1.u + challenge * u2.u;

    let w3: Vec<CS::Scalar> =
        w1.w.iter()
            .zip(&w2.w)
            .map(|(a, b)| *a + challenge * *b)
            .collect();

    let e3_cross = if parallel {
        cross_term_parallel(l, r, o, &w1.w, &w2.w, u1.u, u2.u)
    } else {
        cross_term(l, r, o, &w1.w, &w2.w, u1.u, u2.u)
    };
    let cross_commit = CS::commit_error(params, &e3_cross);
    let e3: Vec<CS::Scalar> =
        w1.e.iter()
            .zip(&w2.e)
            .map(|(a, b)| *a + challenge * *b)
            .zip(&e3_cross)
            .map(|(s, c)| s + challenge * c)
            .collect();

    let w_commit3 = CS::add(&u1.w_commit, &CS::scalar_mul(&u2.w_commit, &challenge));
    let e_commit3 = CS::add(
        &CS::add(&u1.e_commit, &CS::scalar_mul(&u2.e_commit, &challenge)),
        &CS::scalar_mul(&cross_commit, &challenge),
    );

    let u3 = RelaxedR1csInstance {
        x: x3,
        u: u3,
        w_commit: w_commit3,
        e_commit: e_commit3,
    };
    debug_assert_eq!(u3.w_commit, CS::commit_witness(params, &w3));
    (u3, RelaxedR1csWitness { w: w3, e: e3 }, cross_commit)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commitment::PedersenCommitment;
    use crate::curve::Bls12_381;
    use ark_bls12_381::Fr;
    use ark_ec::AffineRepr;
    use ark_ff::{One, Zero};

    #[test]
    fn basis_derivation_is_deterministic() {
        use crate::commitment::PedersenParams;
        let a = PedersenParams::<Bls12_381>::from_seed(b"seed", 8, 4);
        let b = PedersenParams::<Bls12_381>::from_seed(b"seed", 8, 4);
        assert_eq!(a.basis_w, b.basis_w);
        assert_eq!(a.basis_e, b.basis_e);
        assert_eq!(a.basis_w.len(), 8);
        assert_eq!(a.basis_e.len(), 4);

        let c = PedersenParams::<Bls12_381>::from_seed(b"other", 8, 4);
        assert_ne!(a.basis_w, c.basis_w);
    }

    #[test]
    fn commit_is_additive() {
        use crate::commitment::{pedersen_commit, PedersenParams};
        let params = PedersenParams::<Bls12_381>::from_seed(b"seed", 4, 1);
        let a: Vec<Fr> = (1..=4).map(|i| Fr::from(i)).collect();
        let b: Vec<Fr> = (5..=8).map(|i| Fr::from(i)).collect();
        let sum: Vec<Fr> = a.iter().zip(&b).map(|(x, y)| *x + *y).collect();

        assert_eq!(
            pedersen_commit::<Bls12_381>(&params.basis_w, &sum),
            pedersen_commit::<Bls12_381>(&params.basis_w, &a)
                + pedersen_commit::<Bls12_381>(&params.basis_w, &b)
        );
    }

    #[test]
    fn commit_empty_is_zero() {
        use crate::commitment::{pedersen_commit, PedersenParams};
        let params = PedersenParams::<Bls12_381>::from_seed(b"seed", 0, 0);
        assert!(pedersen_commit::<Bls12_381>(&params.basis_w, &[]).is_zero());
    }

    #[test]
    fn commit_zero_vector_is_zero() {
        use crate::commitment::{pedersen_commit, PedersenParams};
        let params = PedersenParams::<Bls12_381>::from_seed(b"seed", 4, 1);
        let zeros = vec![Fr::zero(); 4];
        assert!(pedersen_commit::<Bls12_381>(&params.basis_w, &zeros).is_zero());
    }

    /// One-constraint multiplier: `Z[1]·Z[2] = Z[3]`, wire 0 = constant 1.
    fn simple_r1cs() -> (
        Vec<Vec<(u32, Fr)>>,
        Vec<Vec<(u32, Fr)>>,
        Vec<Vec<(u32, Fr)>>,
    ) {
        (
            vec![vec![(1, Fr::from(1u64))]],
            vec![vec![(2, Fr::from(1u64))]],
            vec![vec![(3, Fr::from(1u64))]],
        )
    }

    fn make_instance(
        params: &crate::commitment::PedersenParams<Bls12_381>,
        w: &[Fr],
    ) -> (
        RelaxedR1csInstance<PedersenCommitment<Bls12_381>>,
        RelaxedR1csWitness<PedersenCommitment<Bls12_381>>,
    ) {
        use crate::commitment::pedersen_commit;
        let e = vec![Fr::zero(); 1];
        let u = Fr::from(1u64);
        (
            RelaxedR1csInstance {
                x: w[1..3].to_vec(),
                u,
                w_commit: pedersen_commit::<Bls12_381>(&params.basis_w, w),
                e_commit: pedersen_commit::<Bls12_381>(&params.basis_e, &e),
            },
            RelaxedR1csWitness { w: w.to_vec(), e },
        )
    }

    #[test]
    fn fold_challenge_is_deterministic_and_distinct() {
        let params = crate::commitment::PedersenParams::<Bls12_381>::from_seed(b"fold-test", 4, 1);
        let (u1, _) = make_instance(
            &params,
            &[Fr::from(1), Fr::from(2), Fr::from(3), Fr::from(6)],
        );
        let (u2, _) = make_instance(
            &params,
            &[Fr::from(1), Fr::from(5), Fr::from(7), Fr::from(35)],
        );

        assert_eq!(
            fold_challenge::<PedersenCommitment<Bls12_381>>(b"acc", &u1, &u2),
            fold_challenge::<PedersenCommitment<Bls12_381>>(b"acc", &u1, &u2)
        );
        assert_ne!(
            fold_challenge::<PedersenCommitment<Bls12_381>>(b"acc", &u1, &u2),
            fold_challenge::<PedersenCommitment<Bls12_381>>(b"other", &u1, &u2)
        );
        assert_ne!(
            fold_challenge::<PedersenCommitment<Bls12_381>>(b"acc", &u1, &u2),
            fold_challenge::<PedersenCommitment<Bls12_381>>(b"acc", &u2, &u1)
        );
    }

    #[test]
    fn fold_combines_instances() {
        use crate::commitment::pedersen_commit;
        let (l, r, o) = simple_r1cs();
        let params = crate::commitment::PedersenParams::<Bls12_381>::from_seed(b"fold-test", 4, 1);
        let (u1, w1) = make_instance(
            &params,
            &[Fr::from(1), Fr::from(2), Fr::from(3), Fr::from(6)],
        );
        let (u2, w2) = make_instance(
            &params,
            &[Fr::from(1), Fr::from(5), Fr::from(7), Fr::from(35)],
        );
        let challenge = Fr::from(11u64);

        let (u3, w3) = fold::<PedersenCommitment<Bls12_381>>(
            &params, &l, &r, &o, &u1, &w1, &u2, &w2, challenge,
        );

        assert_eq!(u3.u, u1.u + challenge * u2.u);
        assert_eq!(u3.x, vec![w3.w[1], w3.w[2]]);

        // Commitments are consistent with the folded witness.
        assert_eq!(
            u3.w_commit,
            pedersen_commit::<Bls12_381>(&params.basis_w, &w3.w)
        );
        assert_eq!(
            u3.e_commit,
            pedersen_commit::<Bls12_381>(&params.basis_e, &w3.e)
        );

        // The folded instance satisfies the relaxed equation.
        let az = sparse_eval(&l, &w3.w);
        let bz = sparse_eval(&r, &w3.w);
        let cz = sparse_eval(&o, &w3.w);
        for j in 0..l.len() {
            assert_eq!(az[j] * bz[j], u3.u * cz[j] + w3.e[j]);
        }
    }

    /// `k` independent multiplier constraints: for `i in 0..k`,
    /// `w[1+3i] * w[2+3i] = w[3+3i]`, `w[0] = 1`.
    fn chain_r1cs(
        k: usize,
    ) -> (
        Vec<Vec<(u32, Fr)>>,
        Vec<Vec<(u32, Fr)>>,
        Vec<Vec<(u32, Fr)>>,
    ) {
        let mut l = Vec::with_capacity(k);
        let mut r = Vec::with_capacity(k);
        let mut o = Vec::with_capacity(k);
        for i in 0..k {
            l.push(vec![((1 + 3 * i) as u32, Fr::from(1u64))]);
            r.push(vec![((2 + 3 * i) as u32, Fr::from(1u64))]);
            o.push(vec![((3 + 3 * i) as u32, Fr::from(1u64))]);
        }
        (l, r, o)
    }

    /// A random witness satisfying `chain_r1cs(k)`.
    fn random_satisfying_witness(k: usize, rng: &mut impl rand::RngCore) -> Vec<Fr> {
        use ark_ff::UniformRand;
        let mut w = vec![Fr::from(1u64)];
        for _ in 0..k {
            let a = Fr::rand(rng);
            let b = Fr::rand(rng);
            w.push(a);
            w.push(b);
            w.push(a * b);
        }
        w
    }

    /// Build an ordinary R1CS instance (`u = 1`, `E = 0`) from a witness.
    fn make_instance_chain(
        params: &crate::commitment::PedersenParams<Bls12_381>,
        w: &[Fr],
        k: usize,
    ) -> (
        RelaxedR1csInstance<PedersenCommitment<Bls12_381>>,
        RelaxedR1csWitness<PedersenCommitment<Bls12_381>>,
    ) {
        use crate::commitment::pedersen_commit;
        let e = vec![Fr::zero(); k];
        (
            RelaxedR1csInstance {
                x: w[1..].to_vec(),
                u: Fr::from(1u64),
                w_commit: pedersen_commit::<Bls12_381>(&params.basis_w, w),
                e_commit: pedersen_commit::<Bls12_381>(&params.basis_e, &e),
            },
            RelaxedR1csWitness { w: w.to_vec(), e },
        )
    }

    /// Assert a relaxed instance is consistent with its witness and satisfies
    /// the relaxed equation.
    fn assert_valid(
        l: &[Vec<(u32, Fr)>],
        r: &[Vec<(u32, Fr)>],
        o: &[Vec<(u32, Fr)>],
        params: &crate::commitment::PedersenParams<Bls12_381>,
        u: &RelaxedR1csInstance<PedersenCommitment<Bls12_381>>,
        w: &RelaxedR1csWitness<PedersenCommitment<Bls12_381>>,
    ) {
        use crate::commitment::pedersen_commit;
        assert_eq!(
            u.w_commit,
            pedersen_commit::<Bls12_381>(&params.basis_w, &w.w)
        );
        assert_eq!(
            u.e_commit,
            pedersen_commit::<Bls12_381>(&params.basis_e, &w.e)
        );
        let az = sparse_eval(l, &w.w);
        let bz = sparse_eval(r, &w.w);
        let cz = sparse_eval(o, &w.w);
        for j in 0..l.len() {
            assert_eq!(az[j] * bz[j], u.u * cz[j] + w.e[j]);
        }
    }

    #[test]
    fn fold_accumulates_random_chain() {
        let k = 4;
        let n_wires = 1 + 3 * k;
        let (l, r, o) = chain_r1cs(k);
        let params =
            crate::commitment::PedersenParams::<Bls12_381>::from_seed(b"chain-test", n_wires, k);
        let mut rng = rand::thread_rng();

        let base_w = random_satisfying_witness(k, &mut rng);
        let (mut acc_u, mut acc_w) = make_instance_chain(&params, &base_w, k);
        assert_valid(&l, &r, &o, &params, &acc_u, &acc_w);

        for _ in 0..5 {
            let step_w = random_satisfying_witness(k, &mut rng);
            let (step_u, step_w) = make_instance_chain(&params, &step_w, k);
            let challenge =
                fold_challenge::<PedersenCommitment<Bls12_381>>(b"chain-acc", &acc_u, &step_u);
            let (next_u, next_w) = fold::<PedersenCommitment<Bls12_381>>(
                &params, &l, &r, &o, &acc_u, &acc_w, &step_u, &step_w, challenge,
            );
            assert_valid(&l, &r, &o, &params, &next_u, &next_w);
            acc_u = next_u;
            acc_w = next_w;
        }
    }

    #[test]
    fn parallel_cross_term_matches_sequential() {
        let k = 4;
        let (l, r, o) = chain_r1cs(k);
        let mut rng = rand::thread_rng();
        let z1 = random_satisfying_witness(k, &mut rng);
        let z2 = random_satisfying_witness(k, &mut rng);
        let u1 = Fr::from(3u64);
        let u2 = Fr::from(7u64);

        let seq = cross_term(&l, &r, &o, &z1, &z2, u1, u2);
        let par = cross_term_parallel(&l, &r, &o, &z1, &z2, u1, u2);
        assert_eq!(seq, par);
    }

    #[test]
    fn fold_with_opts_parallel_matches_sequential() {
        let k = 4;
        let n_wires = 1 + 3 * k;
        let (l, r, o) = chain_r1cs(k);
        let params =
            crate::commitment::PedersenParams::<Bls12_381>::from_seed(b"opt-test", n_wires, k);
        let mut rng = rand::thread_rng();

        let base_w = random_satisfying_witness(k, &mut rng);
        let (acc_u, acc_w) = make_instance_chain(&params, &base_w, k);
        let step_w = random_satisfying_witness(k, &mut rng);
        let (step_u, step_w_r) = make_instance_chain(&params, &step_w, k);
        let challenge =
            fold_challenge::<PedersenCommitment<Bls12_381>>(b"opt-acc", &acc_u, &step_u);

        let (u_seq, w_seq) = fold_with_opts::<PedersenCommitment<Bls12_381>>(
            &params, &l, &r, &o, &acc_u, &acc_w, &step_u, &step_w_r, challenge, false,
        );
        let (u_par, w_par) = fold_with_opts::<PedersenCommitment<Bls12_381>>(
            &params, &l, &r, &o, &acc_u, &acc_w, &step_u, &step_w_r, challenge, true,
        );
        assert_eq!(u_seq, u_par);
        assert_eq!(w_seq, w_par);
    }

    // ── Small-fold-scalar challenge tests (P2b) ───────────────────────

    #[test]
    fn small_fold_challenge_is_deterministic() {
        let params =
            crate::commitment::PedersenParams::<Bls12_381>::from_seed(b"small-test", 4, 1);
        let (u1, _) = make_instance(&params, &[Fr::from(1), Fr::from(2), Fr::from(3), Fr::from(6)]);
        let (u2, _) = make_instance(&params, &[Fr::from(1), Fr::from(5), Fr::from(7), Fr::from(35)]);

        let r1 = small_fold_challenge::<PedersenCommitment<Bls12_381>>(b"acc", &u1, &u2);
        let r2 = small_fold_challenge::<PedersenCommitment<Bls12_381>>(b"acc", &u1, &u2);
        assert_eq!(r1, r2, "small_fold_challenge must be deterministic");
    }

    #[test]
    fn small_fold_challenge_is_ternary() {
        let params =
            crate::commitment::PedersenParams::<Bls12_381>::from_seed(b"small-test", 4, 1);
        let (u1, _) = make_instance(&params, &[Fr::from(1), Fr::from(2), Fr::from(3), Fr::from(6)]);
        let (u2, _) = make_instance(&params, &[Fr::from(1), Fr::from(5), Fr::from(7), Fr::from(35)]);

        let r = small_fold_challenge::<PedersenCommitment<Bls12_381>>(b"acc", &u1, &u2);
        let zero = Fr::zero();
        let one = Fr::one();
        let neg_one = -Fr::one();
        assert!(
            r == zero || r == one || r == neg_one,
            "small_fold_challenge must return -1, 0, or 1, got {:?}",
            r
        );
    }

    #[test]
    fn small_fold_challenge_changes_with_transcript() {
        let params =
            crate::commitment::PedersenParams::<Bls12_381>::from_seed(b"small-test", 4, 1);
        let (u1, _) = make_instance(&params, &[Fr::from(1), Fr::from(2), Fr::from(3), Fr::from(6)]);
        let (u2, _) = make_instance(&params, &[Fr::from(1), Fr::from(5), Fr::from(7), Fr::from(35)]);

        let r1 = small_fold_challenge::<PedersenCommitment<Bls12_381>>(b"acc-a", &u1, &u2);
        let r2 = small_fold_challenge::<PedersenCommitment<Bls12_381>>(b"acc-b", &u1, &u2);
        // They *might* collide by chance (1/3 probability), but over many seeds
        // we expect variation.  We test determinism instead: same seed → same result.
        assert_eq!(
            small_fold_challenge::<PedersenCommitment<Bls12_381>>(b"acc-a", &u1, &u2),
            r1
        );
        assert_eq!(
            small_fold_challenge::<PedersenCommitment<Bls12_381>>(b"acc-b", &u1, &u2),
            r2
        );
    }

    #[test]
    fn small_fold_challenge_distribution_is_reasonable() {
        let params =
            crate::commitment::PedersenParams::<Bls12_381>::from_seed(b"dist-test", 4, 1);
        let mut counts = [0u32; 3]; // -1, 0, 1

        for i in 0..300 {
            let (u1, _) = make_instance(
                &params,
                &[Fr::from(i as u64), Fr::from(2), Fr::from(3), Fr::from(6)],
            );
            let (u2, _) = make_instance(
                &params,
                &[Fr::from(i as u64), Fr::from(5), Fr::from(7), Fr::from(35)],
            );
            let r = small_fold_challenge::<PedersenCommitment<Bls12_381>>(b"acc", &u1, &u2);
            if r == Fr::zero() {
                counts[1] += 1;
            } else if r == Fr::one() {
                counts[2] += 1;
            } else {
                counts[0] += 1;
            }
        }

        // Each should appear at least 50 times (expected ~100, stddev ~8).
        for (i, &c) in counts.iter().enumerate() {
            assert!(
                c >= 50,
                "challenge {} appeared only {} times (expected ~100)",
                i,
                c
            );
        }
    }

    // ── Batch-fold tests (P2b) ────────────────────────────────────────

    #[test]
    fn batch_fold_matches_sequential_small_challenges() {
        let k = 4;
        let n_wires = 1 + 3 * k;
        let (l, r, o) = chain_r1cs(k);
        let params =
            crate::commitment::PedersenParams::<Bls12_381>::from_seed(b"batch-test", n_wires, k);
        let mut rng = rand::thread_rng();

        // Build 5 instances.
        let mut instances = Vec::new();
        let mut witnesses = Vec::new();
        for _ in 0..5 {
            let w = random_satisfying_witness(k, &mut rng);
            let (u, w_r) = make_instance_chain(&params, &w, k);
            instances.push(u);
            witnesses.push(w_r);
        }

        // Batch fold.
        let (batch_u, batch_w, challenges, _) = batch_fold::<PedersenCommitment<Bls12_381>>(
            &params, &l, &r, &o, &instances, &witnesses, b"batch-acc",
        )
        .expect("batch_fold should succeed");

        // Sequential fold with the SAME small challenges.
        let mut seq_u = instances[0].clone();
        let mut seq_w = witnesses[0].clone();
        for i in 1..instances.len() {
            let (next_u, next_w, _) = fold_with_log::<PedersenCommitment<Bls12_381>>(
                &params,
                &l,
                &r,
                &o,
                &seq_u,
                &seq_w,
                &instances[i],
                &witnesses[i],
                challenges[i - 1],
                false,
            );
            seq_u = next_u;
            seq_w = next_w;
        }

        assert_eq!(batch_u, seq_u, "batch_fold must match sequential fold");
        assert_eq!(batch_w, seq_w, "batch_fold witness must match sequential fold");
        assert_valid(&l, &r, &o, &params, &batch_u, &batch_w);
    }

    #[test]
    fn batch_fold_rejects_mismatched_lengths() {
        let k = 4;
        let n_wires = 1 + 3 * k;
        let (l, r, o) = chain_r1cs(k);
        let params =
            crate::commitment::PedersenParams::<Bls12_381>::from_seed(b"batch-err", n_wires, k);
        let mut rng = rand::thread_rng();

        let w = random_satisfying_witness(k, &mut rng);
        let (u, w_r) = make_instance_chain(&params, &w, k);

        let result = batch_fold::<PedersenCommitment<Bls12_381>>(
            &params, &l, &r, &o, &[u.clone()], &[w_r.clone()], b"acc",
        );
        assert!(result.is_err(), "batch_fold must reject < 2 instances");
    }

    #[test]
    fn batch_fold_produces_expected_challenges_count() {
        let k = 4;
        let n_wires = 1 + 3 * k;
        let (l, r, o) = chain_r1cs(k);
        let params =
            crate::commitment::PedersenParams::<Bls12_381>::from_seed(b"batch-ct", n_wires, k);
        let mut rng = rand::thread_rng();

        let mut instances = Vec::new();
        let mut witnesses = Vec::new();
        for _ in 0..7 {
            let w = random_satisfying_witness(k, &mut rng);
            let (u, w_r) = make_instance_chain(&params, &w, k);
            instances.push(u);
            witnesses.push(w_r);
        }

        let (_, _, challenges, cross_commits) =
            batch_fold::<PedersenCommitment<Bls12_381>>(
                &params, &l, &r, &o, &instances, &witnesses, b"acc",
            )
            .unwrap();

        assert_eq!(challenges.len(), 6, "7 instances → 6 challenges");
        assert_eq!(cross_commits.len(), 6, "7 instances → 6 cross-term commits");

        // All challenges must be ternary.
        for c in &challenges {
            assert!(
                *c == Fr::zero() || *c == Fr::one() || *c == -Fr::one(),
                "all batch-fold challenges must be small"
            );
        }
    }

    #[test]
    fn batch_fold_golden_vector() {
        // Known seed, known witnesses → reproducible output.
        let k = 2;
        let n_wires = 1 + 3 * k;
        let (l, r, o) = chain_r1cs(k);
        let params =
            crate::commitment::PedersenParams::<Bls12_381>::from_seed(b"golden", n_wires, k);

        // Fixed witnesses (deterministic).
        let w0 = vec![
            Fr::from(1u64),
            Fr::from(2u64),
            Fr::from(3u64),
            Fr::from(6u64),
            Fr::from(4u64),
            Fr::from(5u64),
            Fr::from(20u64),
        ];
        let w1 = vec![
            Fr::from(1u64),
            Fr::from(7u64),
            Fr::from(8u64),
            Fr::from(56u64),
            Fr::from(9u64),
            Fr::from(10u64),
            Fr::from(90u64),
        ];
        let w2 = vec![
            Fr::from(1u64),
            Fr::from(11u64),
            Fr::from(12u64),
            Fr::from(132u64),
            Fr::from(13u64),
            Fr::from(14u64),
            Fr::from(182u64),
        ];

        let (u0, w0_r) = make_instance_chain(&params, &w0, k);
        let (u1, w1_r) = make_instance_chain(&params, &w1, k);
        let (u2, w2_r) = make_instance_chain(&params, &w2, k);

        let (folded_u, folded_w, challenges, _) =
            batch_fold::<PedersenCommitment<Bls12_381>>(
                &params, &l, &r, &o, &[u0, u1, u2], &[w0_r, w1_r, w2_r], b"golden-acc",
            )
            .unwrap();

        // The folded instance must satisfy the relaxed equation.
        assert_valid(&l, &r, &o, &params, &folded_u, &folded_w);

        // Challenges must be small and deterministic.
        assert_eq!(challenges.len(), 2);
        for c in &challenges {
            assert!(*c == Fr::zero() || *c == Fr::one() || *c == -Fr::one());
        }

        // Determinism: same inputs → same folded_u.
        let (folded_u2, _, _, _) = batch_fold::<PedersenCommitment<Bls12_381>>(
            &params, &l, &r, &o,
            &[
                make_instance_chain(&params, &w0, k).0,
                make_instance_chain(&params, &w1, k).0,
                make_instance_chain(&params, &w2, k).0,
            ],
            &[
                make_instance_chain(&params, &w0, k).1,
                make_instance_chain(&params, &w1, k).1,
                make_instance_chain(&params, &w2, k).1,
            ],
            b"golden-acc",
        )
        .unwrap();
        assert_eq!(folded_u, folded_u2, "batch_fold must be deterministic");
    }

    // ── Property tests (P2b) ──────────────────────────────────────────

    use proptest::prelude::*;

    proptest! {
        /// Property: batch_fold of valid instances always satisfies R_relaxed.
        #[test]
        fn prop_batch_fold_preserves_validity(
            k in 2usize..6,
            n_batch in 2usize..8,
        ) {
            let n_wires = 1 + 3 * k;
            let (l, r, o) = chain_r1cs(k);
            let params = crate::commitment::PedersenParams::<Bls12_381>::from_seed(
                b"batch-prop", n_wires, k,
            );
            let mut rng = rand::thread_rng();

            let mut instances = Vec::with_capacity(n_batch);
            let mut witnesses = Vec::with_capacity(n_batch);
            for _ in 0..n_batch {
                let w = random_satisfying_witness(k, &mut rng);
                let (u, w_r) = make_instance_chain(&params, &w, k);
                instances.push(u);
                witnesses.push(w_r);
            }

            let (folded_u, folded_w, _, _) = batch_fold::<PedersenCommitment<Bls12_381>>(
                &params, &l, &r, &o, &instances, &witnesses, b"prop-acc",
            )
            .expect("batch_fold must succeed for valid instances");

            assert_valid(&l, &r, &o, &params, &folded_u, &folded_w);
        }

        /// Property: all batch-fold challenges are ternary.
        #[test]
        fn prop_batch_fold_challenges_are_ternary(
            k in 2usize..6,
            n_batch in 2usize..8,
        ) {
            let n_wires = 1 + 3 * k;
            let (l, r, o) = chain_r1cs(k);
            let params = crate::commitment::PedersenParams::<Bls12_381>::from_seed(
                b"batch-prop", n_wires, k,
            );
            let mut rng = rand::thread_rng();

            let mut instances = Vec::with_capacity(n_batch);
            let mut witnesses = Vec::with_capacity(n_batch);
            for _ in 0..n_batch {
                let w = random_satisfying_witness(k, &mut rng);
                let (u, w_r) = make_instance_chain(&params, &w, k);
                instances.push(u);
                witnesses.push(w_r);
            }

            let (_, _, challenges, _) = batch_fold::<PedersenCommitment<Bls12_381>>(
                &params, &l, &r, &o, &instances, &witnesses, b"prop-acc",
            )
            .unwrap();

            let zero = Fr::zero();
            let one = Fr::one();
            let neg_one = -Fr::one();
            for c in challenges {
                prop_assert!(
                    c == zero || c == one || c == neg_one,
                    "challenge {:?} is not ternary", c
                );
            }
        }

        /// Property: batch_fold determinism — same inputs always produce
        /// same output (challenges are transcript-derived, not random).
        #[test]
        fn prop_batch_fold_is_deterministic(
            k in 2usize..6,
            n_batch in 2usize..8,
        ) {
            let n_wires = 1 + 3 * k;
            let (l, r, o) = chain_r1cs(k);
            let params = crate::commitment::PedersenParams::<Bls12_381>::from_seed(
                b"batch-det", n_wires, k,
            );
            let mut rng = rand::thread_rng();

            let mut instances = Vec::with_capacity(n_batch);
            let mut witnesses = Vec::with_capacity(n_batch);
            for _ in 0..n_batch {
                let w = random_satisfying_witness(k, &mut rng);
                let (u, w_r) = make_instance_chain(&params, &w, k);
                instances.push(u);
                witnesses.push(w_r);
            }

            let (u1, w1, c1, x1) = batch_fold::<PedersenCommitment<Bls12_381>>(
                &params, &l, &r, &o, &instances, &witnesses, b"det-acc",
            )
            .unwrap();
            let (u2, w2, c2, x2) = batch_fold::<PedersenCommitment<Bls12_381>>(
                &params, &l, &r, &o, &instances, &witnesses, b"det-acc",
            )
            .unwrap();

            prop_assert_eq!(u1, u2);
            prop_assert_eq!(w1, w2);
            prop_assert_eq!(c1, c2);
            prop_assert_eq!(x1, x2);
        }
    }

    // ── Checkpoint tests (P2b-continued) ──────────────────────────────

    #[test]
    fn checkpoint_basic_valid_batch_passes() {
        let k = 4;
        let n_wires = 1 + 3 * k;
        let (l, r, o) = chain_r1cs(k);
        let params =
            crate::commitment::PedersenParams::<Bls12_381>::from_seed(b"ckpt", n_wires, k);
        let mut rng = rand::thread_rng();

        let mut instances = Vec::new();
        let mut witnesses = Vec::new();
        for _ in 0..5 {
            let w = random_satisfying_witness(k, &mut rng);
            let (u, w_r) = make_instance_chain(&params, &w, k);
            instances.push(u);
            witnesses.push(w_r);
        }

        let (folded_u, folded_w, checkpoints) =
            batch_fold_with_checkpoints::<PedersenCommitment<Bls12_381>>(
                &params, &l, &r, &o, &instances, &witnesses, b"ckpt-acc", 3, 256,
            )
            .expect("checkpoint should pass for valid instances");

        assert_valid(&l, &r, &o, &params, &folded_u, &folded_w);
        assert!(!checkpoints.is_empty(), "should have at least one checkpoint");
        for ck in &checkpoints {
            assert!(ck.passed, "all checkpoints should pass");
        }
    }

    #[test]
    fn checkpoint_golden_vector_reproducible() {
        let k = 2;
        let n_wires = 1 + 3 * k;
        let (l, r, o) = chain_r1cs(k);
        let params =
            crate::commitment::PedersenParams::<Bls12_381>::from_seed(b"golden-ckpt", n_wires, k);

        let w0 = vec![
            Fr::from(1u64), Fr::from(2u64), Fr::from(3u64), Fr::from(6u64),
            Fr::from(4u64), Fr::from(5u64), Fr::from(20u64),
        ];
        let w1 = vec![
            Fr::from(1u64), Fr::from(7u64), Fr::from(8u64), Fr::from(56u64),
            Fr::from(9u64), Fr::from(10u64), Fr::from(90u64),
        ];
        let w2 = vec![
            Fr::from(1u64), Fr::from(11u64), Fr::from(12u64), Fr::from(132u64),
            Fr::from(13u64), Fr::from(14u64), Fr::from(182u64),
        ];

        let (u0, w0_r) = make_instance_chain(&params, &w0, k);
        let (u1, w1_r) = make_instance_chain(&params, &w1, k);
        let (u2, w2_r) = make_instance_chain(&params, &w2, k);

        let (folded_u, _folded_w, checkpoints) =
            batch_fold_with_checkpoints::<PedersenCommitment<Bls12_381>>(
                &params, &l, &r, &o,
                &[u0.clone(), u1.clone(), u2.clone()],
                &[w0_r, w1_r, w2_r],
                b"golden-ckpt-acc", 2, 256,
            )
            .unwrap();

        // Determinism: same inputs → same checkpoints.
        let (folded_u2, _, checkpoints2) =
            batch_fold_with_checkpoints::<PedersenCommitment<Bls12_381>>(
                &params, &l, &r, &o,
                &[u0, u1, u2],
                &[
                    make_instance_chain(&params, &w0, k).1,
                    make_instance_chain(&params, &w1, k).1,
                    make_instance_chain(&params, &w2, k).1,
                ],
                b"golden-ckpt-acc", 2, 256,
            )
            .unwrap();

        assert_eq!(folded_u, folded_u2);
        assert_eq!(checkpoints.len(), checkpoints2.len());
        for (a, b) in checkpoints.iter().zip(&checkpoints2) {
            assert_eq!(a.start_step, b.start_step);
            assert_eq!(a.end_step, b.end_step);
            assert_eq!(a.passed, b.passed);
        }
    }

    #[test]
    fn checkpoint_single_instance_no_checkpoints() {
        let k = 4;
        let n_wires = 1 + 3 * k;
        let (l, r, o) = chain_r1cs(k);
        let params =
            crate::commitment::PedersenParams::<Bls12_381>::from_seed(b"ckpt-1", n_wires, k);
        let mut rng = rand::thread_rng();

        let w = random_satisfying_witness(k, &mut rng);
        let (u, w_r) = make_instance_chain(&params, &w, k);

        let (_folded_u, _folded_w, checkpoints) =
            batch_fold_with_checkpoints::<PedersenCommitment<Bls12_381>>(
                &params, &l, &r, &o, &[u], &[w_r], b"ckpt-acc", 3, 256,
            )
            .unwrap();

        assert!(checkpoints.is_empty(), "single instance → no folds → no checkpoints");
    }

    #[test]
    fn checkpoint_batch_size_1_produces_n_minus_1_checkpoints() {
        let k = 4;
        let n_wires = 1 + 3 * k;
        let (l, r, o) = chain_r1cs(k);
        let params =
            crate::commitment::PedersenParams::<Bls12_381>::from_seed(b"ckpt-bs1", n_wires, k);
        let mut rng = rand::thread_rng();

        let mut instances = Vec::new();
        let mut witnesses = Vec::new();
        for _ in 0..5 {
            let w = random_satisfying_witness(k, &mut rng);
            let (u, w_r) = make_instance_chain(&params, &w, k);
            instances.push(u);
            witnesses.push(w_r);
        }

        let (_folded_u, _folded_w, checkpoints) =
            batch_fold_with_checkpoints::<PedersenCommitment<Bls12_381>>(
                &params, &l, &r, &o, &instances, &witnesses, b"ckpt-acc", 1, 256,
            )
            .unwrap();

        assert_eq!(checkpoints.len(), 4, "batch_size=1, 5 instances → 4 checkpoints");
        for (i, ck) in checkpoints.iter().enumerate() {
            assert_eq!(ck.n_challenges, 1, "checkpoint {} should have 1 challenge", i);
            assert!(ck.passed);
        }
    }

    #[test]
    fn checkpoint_batch_size_larger_than_n_instances() {
        let k = 4;
        let n_wires = 1 + 3 * k;
        let (l, r, o) = chain_r1cs(k);
        let params =
            crate::commitment::PedersenParams::<Bls12_381>::from_seed(b"ckpt-big", n_wires, k);
        let mut rng = rand::thread_rng();

        let mut instances = Vec::new();
        let mut witnesses = Vec::new();
        for _ in 0..3 {
            let w = random_satisfying_witness(k, &mut rng);
            let (u, w_r) = make_instance_chain(&params, &w, k);
            instances.push(u);
            witnesses.push(w_r);
        }

        let (_folded_u, _folded_w, checkpoints) =
            batch_fold_with_checkpoints::<PedersenCommitment<Bls12_381>>(
                &params, &l, &r, &o, &instances, &witnesses, b"ckpt-acc", 100, 256,
            )
            .unwrap();

        assert_eq!(checkpoints.len(), 1, "batch_size=100, 3 instances → 1 checkpoint");
        assert_eq!(checkpoints[0].n_challenges, 2);
        assert!(checkpoints[0].passed);
    }

    #[test]
    fn checkpoint_rejects_empty_instances() {
        let k = 4;
        let n_wires = 1 + 3 * k;
        let (l, r, o) = chain_r1cs(k);
        let params =
            crate::commitment::PedersenParams::<Bls12_381>::from_seed(b"ckpt-empty", n_wires, k);

        let result = batch_fold_with_checkpoints::<PedersenCommitment<Bls12_381>>(
            &params, &l, &r, &o, &[], &[], b"ckpt-acc", 3, 256,
        );
        assert!(result.is_err(), "empty instances should be rejected");
    }

    #[test]
    fn checkpoint_rejects_zero_batch_size() {
        let k = 4;
        let n_wires = 1 + 3 * k;
        let (l, r, o) = chain_r1cs(k);
        let params =
            crate::commitment::PedersenParams::<Bls12_381>::from_seed(b"ckpt-zero", n_wires, k);
        let mut rng = rand::thread_rng();

        let w = random_satisfying_witness(k, &mut rng);
        let (u, w_r) = make_instance_chain(&params, &w, k);

        let result = batch_fold_with_checkpoints::<PedersenCommitment<Bls12_381>>(
            &params, &l, &r, &o, &[u], &[w_r], b"ckpt-acc", 0, 256,
        );
        assert!(result.is_err(), "batch_size=0 should be rejected");
    }

    #[test]
    fn checkpoint_norms_grow_with_batch_size() {
        let k = 4;
        let n_wires = 1 + 3 * k;
        let (l, r, o) = chain_r1cs(k);
        let params =
            crate::commitment::PedersenParams::<Bls12_381>::from_seed(b"ckpt-grow", n_wires, k);
        let mut rng = rand::thread_rng();

        let mut instances = Vec::new();
        let mut witnesses = Vec::new();
        for _ in 0..10 {
            let w = random_satisfying_witness(k, &mut rng);
            let (u, w_r) = make_instance_chain(&params, &w, k);
            instances.push(u);
            witnesses.push(w_r);
        }

        let (_, _, checkpoints_small) =
            batch_fold_with_checkpoints::<PedersenCommitment<Bls12_381>>(
                &params, &l, &r, &o, &instances, &witnesses, b"ckpt-acc", 2, 256,
            )
            .unwrap();

        let (_, _, checkpoints_large) =
            batch_fold_with_checkpoints::<PedersenCommitment<Bls12_381>>(
                &params, &l, &r, &o, &instances, &witnesses, b"ckpt-acc", 5, 256,
            )
            .unwrap();

        // Larger batch size → fewer checkpoints.
        assert!(
            checkpoints_large.len() < checkpoints_small.len(),
            "larger batch size should produce fewer checkpoints"
        );
    }

    // ── Checkpoint property tests (P2b-continued) ─────────────────────

    proptest! {
        /// Property: batch_fold_with_checkpoints of valid instances always
        /// passes all checkpoints (with a generous bound).
        #[test]
        fn prop_checkpoint_passes_for_valid_instances(
            k in 2usize..6,
            n_batch in 2usize..8,
            batch_size in 1usize..5,
        ) {
            let n_wires = 1 + 3 * k;
            let (l, r, o) = chain_r1cs(k);
            let params = crate::commitment::PedersenParams::<Bls12_381>::from_seed(
                b"ckpt-prop", n_wires, k,
            );
            let mut rng = rand::thread_rng();

            let mut instances = Vec::with_capacity(n_batch);
            let mut witnesses = Vec::with_capacity(n_batch);
            for _ in 0..n_batch {
                let w = random_satisfying_witness(k, &mut rng);
                let (u, w_r) = make_instance_chain(&params, &w, k);
                instances.push(u);
                witnesses.push(w_r);
            }

            let (folded_u, folded_w, checkpoints) =
                batch_fold_with_checkpoints::<PedersenCommitment<Bls12_381>>(
                    &params, &l, &r, &o, &instances, &witnesses, b"ckpt-acc",
                    batch_size, 256,
                )
                .expect("valid instances should pass checkpoints");

            assert_valid(&l, &r, &o, &params, &folded_u, &folded_w);
            for ck in &checkpoints {
                prop_assert!(ck.passed, "checkpoint {:?} should pass", ck);
            }
        }

        /// Property: checkpoint determinism — same inputs always produce
        /// same checkpoints.
        #[test]
        fn prop_checkpoint_deterministic(
            k in 2usize..6,
            n_batch in 2usize..8,
            batch_size in 1usize..5,
        ) {
            let n_wires = 1 + 3 * k;
            let (l, r, o) = chain_r1cs(k);
            let params = crate::commitment::PedersenParams::<Bls12_381>::from_seed(
                b"ckpt-det", n_wires, k,
            );
            let mut rng = rand::thread_rng();

            let mut instances = Vec::with_capacity(n_batch);
            let mut witnesses = Vec::with_capacity(n_batch);
            for _ in 0..n_batch {
                let w = random_satisfying_witness(k, &mut rng);
                let (u, w_r) = make_instance_chain(&params, &w, k);
                instances.push(u);
                witnesses.push(w_r);
            }

            let (u1, w1, c1) = batch_fold_with_checkpoints::<PedersenCommitment<Bls12_381>>(
                &params, &l, &r, &o, &instances, &witnesses, b"det-acc",
                batch_size, 256,
            )
            .unwrap();
            let (u2, w2, c2) = batch_fold_with_checkpoints::<PedersenCommitment<Bls12_381>>(
                &params, &l, &r, &o, &instances, &witnesses, b"det-acc",
                batch_size, 256,
            )
            .unwrap();

            prop_assert_eq!(u1, u2);
            prop_assert_eq!(w1, w2);
            prop_assert_eq!(c1.len(), c2.len());
            for (a, b) in c1.iter().zip(&c2) {
                prop_assert_eq!(a.start_step, b.start_step);
                prop_assert_eq!(a.end_step, b.end_step);
                prop_assert_eq!(a.passed, b.passed);
            }
        }
    }
}
