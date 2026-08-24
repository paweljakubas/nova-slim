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

use ark_ff::PrimeField;
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
    fold_with_opts(params, l, r, o, u1, w1, u2, w2, challenge, false)
}

/// Fold with optimization flags.
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
    let e3: Vec<CS::Scalar> =
        w1.e.iter()
            .zip(&w2.e)
            .map(|(a, b)| *a + challenge * *b)
            .zip(&e3_cross)
            .map(|(s, c)| s + challenge * c)
            .collect();

    let w_commit3 = CS::add(
        &u1.w_commit,
        &CS::scalar_mul(&u2.w_commit, &challenge),
    );
    let e_commit3 = CS::add(
        &CS::add(
            &u1.e_commit,
            &CS::scalar_mul(&u2.e_commit, &challenge),
        ),
        &CS::scalar_mul(&CS::commit_error(params, &e3_cross), &challenge),
    );

    let u3 = RelaxedR1csInstance {
        x: x3,
        u: u3,
        w_commit: w_commit3,
        e_commit: e_commit3,
    };
    debug_assert_eq!(u3.w_commit, CS::commit_witness(params, &w3));
    (u3, RelaxedR1csWitness { w: w3, e: e3 })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commitment::PedersenCommitment;
    use crate::curve::Bls12_381;
    use ark_bls12_381::Fr;
    use ark_ec::AffineRepr;
    use ark_ff::Zero;

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
            pedersen_commit::<Bls12_381>(&params.basis_w, &a) + pedersen_commit::<Bls12_381>(&params.basis_w, &b)
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
    ) -> (RelaxedR1csInstance<PedersenCommitment<Bls12_381>>, RelaxedR1csWitness<PedersenCommitment<Bls12_381>>) {
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

        let (u3, w3) = fold::<PedersenCommitment<Bls12_381>>(&params, &l, &r, &o, &u1, &w1, &u2, &w2, challenge);

        assert_eq!(u3.u, u1.u + challenge * u2.u);
        assert_eq!(u3.x, vec![w3.w[1], w3.w[2]]);

        // Commitments are consistent with the folded witness.
        assert_eq!(u3.w_commit, pedersen_commit::<Bls12_381>(&params.basis_w, &w3.w));
        assert_eq!(u3.e_commit, pedersen_commit::<Bls12_381>(&params.basis_e, &w3.e));

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
    ) -> (RelaxedR1csInstance<PedersenCommitment<Bls12_381>>, RelaxedR1csWitness<PedersenCommitment<Bls12_381>>) {
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
        assert_eq!(u.w_commit, pedersen_commit::<Bls12_381>(&params.basis_w, &w.w));
        assert_eq!(u.e_commit, pedersen_commit::<Bls12_381>(&params.basis_e, &w.e));
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
        let params = crate::commitment::PedersenParams::<Bls12_381>::from_seed(b"chain-test", n_wires, k);
        let mut rng = rand::thread_rng();

        let base_w = random_satisfying_witness(k, &mut rng);
        let (mut acc_u, mut acc_w) = make_instance_chain(&params, &base_w, k);
        assert_valid(&l, &r, &o, &params, &acc_u, &acc_w);

        for _ in 0..5 {
            let step_w = random_satisfying_witness(k, &mut rng);
            let (step_u, step_w) = make_instance_chain(&params, &step_w, k);
            let challenge = fold_challenge::<PedersenCommitment<Bls12_381>>(b"chain-acc", &acc_u, &step_u);
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
        let params = crate::commitment::PedersenParams::<Bls12_381>::from_seed(b"opt-test", n_wires, k);
        let mut rng = rand::thread_rng();

        let base_w = random_satisfying_witness(k, &mut rng);
        let (acc_u, acc_w) = make_instance_chain(&params, &base_w, k);
        let step_w = random_satisfying_witness(k, &mut rng);
        let (step_u, step_w_r) = make_instance_chain(&params, &step_w, k);
        let challenge = fold_challenge::<PedersenCommitment<Bls12_381>>(b"opt-acc", &acc_u, &step_u);

        let (u_seq, w_seq) = fold_with_opts::<PedersenCommitment<Bls12_381>>(
            &params, &l, &r, &o, &acc_u, &acc_w, &step_u, &step_w_r, challenge, false,
        );
        let (u_par, w_par) = fold_with_opts::<PedersenCommitment<Bls12_381>>(
            &params, &l, &r, &o, &acc_u, &acc_w, &step_u, &step_w_r, challenge, true,
        );
        assert_eq!(u_seq, u_par);
        assert_eq!(w_seq, w_par);
    }
}
