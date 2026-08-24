//! Commitment scheme abstraction for NIFS folding.
//!
//! Defines a generic `CommitmentScheme` trait and a Pedersen implementation
//! over any elliptic curve. Future work: SIS/Ajtai lattice commitment.

use ark_ec::{AffineRepr, Group, VariableBaseMSM};
use ark_ff::{PrimeField, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use blake2::{Blake2b512, Digest};
use std::fmt::Debug;

use crate::curve::{G1Projective, NovaCurve, ScalarField};

/// A generic commitment scheme for NIFS folding.
///
/// The scheme must be homomorphic (addition and scalar multiplication) so
/// that commitments can be folded linearly.
pub trait CommitmentScheme: Clone + Debug + Send + Sync + 'static {
    /// Scalar field over which witness/error vectors are defined.
    type Scalar: PrimeField + CanonicalSerialize + CanonicalDeserialize + Send + Sync;

    /// Commitment value (e.g. a curve point for Pedersen, a vector for SIS).
    type Commitment: Clone
        + Debug
        + PartialEq
        + Eq
        + CanonicalSerialize
        + CanonicalDeserialize
        + Send
        + Sync;

    /// Parameters (basis points, matrices, etc.) derived deterministically.
    type Params: Clone + Debug + Send + Sync;

    /// Derive parameters from a public seed.
    fn params_from_seed(seed: &[u8], n_wires: usize, n_constraints: usize) -> Self::Params;

    /// Commit to a witness vector.
    fn commit_witness(params: &Self::Params, values: &[Self::Scalar]) -> Self::Commitment;

    /// Commit to an error vector.
    fn commit_error(params: &Self::Params, values: &[Self::Scalar]) -> Self::Commitment;

    /// Add two commitments.
    fn add(c1: &Self::Commitment, c2: &Self::Commitment) -> Self::Commitment;

    /// Multiply a commitment by a scalar.
    fn scalar_mul(c: &Self::Commitment, scalar: &Self::Scalar) -> Self::Commitment;

    /// The zero commitment.
    fn zero() -> Self::Commitment;
}

// ------------------------------------------------------------------
// Pedersen commitment implementation
// ------------------------------------------------------------------

/// Pedersen commitment using deterministic elliptic-curve bases.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PedersenCommitment<C: NovaCurve> {
    _phantom: std::marker::PhantomData<C>,
}

/// Pedersen commitment parameters: the deterministic G1 bases for `W` and `E`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PedersenParams<C: NovaCurve> {
    /// Basis for the witness commitment, one point per wire.
    pub basis_w: Vec<C::G1Affine>,
    /// Basis for the error commitment, one point per constraint.
    pub basis_e: Vec<C::G1Affine>,
}

impl<C: NovaCurve> PedersenParams<C> {
    /// Derive the bases deterministically from a seed.
    pub fn from_seed(seed: &[u8], n_wires: usize, n_constraints: usize) -> Self {
        Self {
            basis_w: derive_basis::<C>(seed, b"witness", n_wires),
            basis_e: derive_basis::<C>(seed, b"error", n_constraints),
        }
    }
}

/// Hash `(seed ‖ domain ‖ index)` to a G1 point via scalar multiplication.
fn derive_basis<C: NovaCurve>(seed: &[u8], domain: &[u8], n: usize) -> Vec<C::G1Affine> {
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let mut h = Blake2b512::new();
        h.update(seed);
        h.update(domain);
        h.update(i.to_le_bytes());
        let scalar = ScalarField::<C>::from_le_bytes_mod_order(&h.finalize());
        out.push(C::G1Affine::from(G1Projective::<C>::generator() * scalar));
    }
    out
}

/// Standalone Pedersen commitment (used by HashPC in sumcheck.rs).
pub fn pedersen_commit<C: NovaCurve>(
    basis: &[C::G1Affine],
    values: &[ScalarField<C>],
) -> C::G1Affine {
    if values.is_empty() {
        return C::G1Affine::zero();
    }
    debug_assert_eq!(basis.len(), values.len(), "basis/values length mismatch");
    C::G1Affine::from(
        G1Projective::<C>::msm(basis, values).expect("MSM length mismatch"),
    )
}

impl<C: NovaCurve> CommitmentScheme for PedersenCommitment<C> {
    type Scalar = ScalarField<C>;
    type Commitment = C::G1Affine;
    type Params = PedersenParams<C>;

    fn params_from_seed(seed: &[u8], n_wires: usize, n_constraints: usize) -> Self::Params {
        PedersenParams::from_seed(seed, n_wires, n_constraints)
    }

    fn commit_witness(params: &Self::Params, values: &[Self::Scalar]) -> Self::Commitment {
        pedersen_commit::<C>(&params.basis_w, values)
    }

    fn commit_error(params: &Self::Params, values: &[Self::Scalar]) -> Self::Commitment {
        pedersen_commit::<C>(&params.basis_e, values)
    }

    fn add(c1: &Self::Commitment, c2: &Self::Commitment) -> Self::Commitment {
        C::G1Affine::from(G1Projective::<C>::from(*c1) + G1Projective::<C>::from(*c2))
    }

    fn scalar_mul(c: &Self::Commitment, scalar: &Self::Scalar) -> Self::Commitment {
        C::G1Affine::from(G1Projective::<C>::from(*c) * *scalar)
    }

    fn zero() -> Self::Commitment {
        C::G1Affine::zero()
    }
}

// ------------------------------------------------------------------
// SIS/Ajtai lattice commitment implementation
// ------------------------------------------------------------------

/// Output dimension for SIS commitments (number of rows in the matrix).
/// A small constant is sufficient for the POC; production deployments
/// should scale `m` with the security parameter.
pub const SIS_OUTPUT_DIM: usize = 4;

/// SIS (Ajtai-style) commitment using a deterministic matrix over the
/// scalar field.  The commitment is a short vector `c = A·v`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SisCommitment<C: NovaCurve> {
    _phantom: std::marker::PhantomData<C>,
}

/// SIS commitment parameters: the deterministic matrices for `W` and `E`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SisParams<C: NovaCurve> {
    /// Number of rows (output dimension).
    pub m: usize,
    /// Matrix for witness commitment, `m × n_wires`.
    pub a_w: Vec<Vec<ScalarField<C>>>,
    /// Matrix for error commitment, `m × n_constraints`.
    pub a_e: Vec<Vec<ScalarField<C>>>,
}

impl<C: NovaCurve> SisParams<C> {
    /// Derive the matrices deterministically from a seed.
    pub fn from_seed(seed: &[u8], n_wires: usize, n_constraints: usize) -> Self {
        Self {
            m: SIS_OUTPUT_DIM,
            a_w: derive_matrix::<C>(seed, b"witness", SIS_OUTPUT_DIM, n_wires),
            a_e: derive_matrix::<C>(seed, b"error", SIS_OUTPUT_DIM, n_constraints),
        }
    }
}

/// Hash `(seed ‖ domain ‖ row ‖ col)` to a scalar.
fn derive_matrix<C: NovaCurve>(
    seed: &[u8],
    domain: &[u8],
    m: usize,
    n: usize,
) -> Vec<Vec<ScalarField<C>>> {
    let mut matrix = Vec::with_capacity(m);
    for i in 0..m {
        let mut row = Vec::with_capacity(n);
        for j in 0..n {
            let mut h = Blake2b512::new();
            h.update(seed);
            h.update(domain);
            h.update((i as u64).to_le_bytes());
            h.update((j as u64).to_le_bytes());
            row.push(ScalarField::<C>::from_le_bytes_mod_order(&h.finalize()));
        }
        matrix.push(row);
    }
    matrix
}

/// Matrix-vector multiplication: `A · v`.
fn mat_vec_mul<F: PrimeField>(matrix: &[Vec<F>], vec: &[F]) -> Vec<F> {
    matrix
        .iter()
        .map(|row| {
            row.iter()
                .zip(vec)
                .map(|(a, b)| *a * *b)
                .fold(F::zero(), |acc, x| acc + x)
        })
        .collect()
}

impl<C: NovaCurve> CommitmentScheme for SisCommitment<C> {
    type Scalar = ScalarField<C>;
    type Commitment = Vec<ScalarField<C>>;
    type Params = SisParams<C>;

    fn params_from_seed(seed: &[u8], n_wires: usize, n_constraints: usize) -> Self::Params {
        SisParams::from_seed(seed, n_wires, n_constraints)
    }

    fn commit_witness(params: &Self::Params, values: &[Self::Scalar]) -> Self::Commitment {
        mat_vec_mul(&params.a_w, values)
    }

    fn commit_error(params: &Self::Params, values: &[Self::Scalar]) -> Self::Commitment {
        mat_vec_mul(&params.a_e, values)
    }

    fn add(c1: &Self::Commitment, c2: &Self::Commitment) -> Self::Commitment {
        c1.iter().zip(c2).map(|(a, b)| *a + *b).collect()
    }

    fn scalar_mul(c: &Self::Commitment, scalar: &Self::Scalar) -> Self::Commitment {
        c.iter().map(|a| *a * *scalar).collect()
    }

    fn zero() -> Self::Commitment {
        vec![ScalarField::<C>::zero(); SIS_OUTPUT_DIM]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curve::Bls12_381;
    use ark_bls12_381::Fr;
    use ark_ff::Zero;

    #[test]
    fn sis_params_are_deterministic() {
        let a = SisParams::<Bls12_381>::from_seed(b"seed", 8, 4);
        let b = SisParams::<Bls12_381>::from_seed(b"seed", 8, 4);
        assert_eq!(a.a_w, b.a_w);
        assert_eq!(a.a_e, b.a_e);
        assert_eq!(a.m, SIS_OUTPUT_DIM);
    }

    #[test]
    fn sis_commit_is_homomorphic() {
        let params = SisParams::<Bls12_381>::from_seed(b"seed", 4, 1);
        let a: Vec<Fr> = (1..=4).map(|i| Fr::from(i)).collect();
        let b: Vec<Fr> = (5..=8).map(|i| Fr::from(i)).collect();
        let sum: Vec<Fr> = a.iter().zip(&b).map(|(x, y)| *x + *y).collect();

        let ca = SisCommitment::<Bls12_381>::commit_witness(&params, &a);
        let cb = SisCommitment::<Bls12_381>::commit_witness(&params, &b);
        let csum = SisCommitment::<Bls12_381>::commit_witness(&params, &sum);

        assert_eq!(SisCommitment::<Bls12_381>::add(&ca, &cb), csum);
    }

    #[test]
    fn sis_commit_scalar_mul() {
        let params = SisParams::<Bls12_381>::from_seed(b"seed", 4, 1);
        let a: Vec<Fr> = (1..=4).map(|i| Fr::from(i)).collect();
        let scalar = Fr::from(7u64);

        let ca = SisCommitment::<Bls12_381>::commit_witness(&params, &a);
        let expected = SisCommitment::<Bls12_381>::commit_witness(
            &params,
            &a.iter().map(|x| *x * scalar).collect::<Vec<_>>(),
        );

        assert_eq!(SisCommitment::<Bls12_381>::scalar_mul(&ca, &scalar), expected);
    }

    #[test]
    fn sis_commit_zero_vector_is_zero() {
        let params = SisParams::<Bls12_381>::from_seed(b"seed", 4, 1);
        let zeros = vec![Fr::zero(); 4];
        let cz = SisCommitment::<Bls12_381>::commit_witness(&params, &zeros);
        assert_eq!(cz, SisCommitment::<Bls12_381>::zero());
    }

    #[test]
    fn sis_commit_distinct_seeds_differ() {
        let a = SisParams::<Bls12_381>::from_seed(b"seed-a", 4, 1);
        let b = SisParams::<Bls12_381>::from_seed(b"seed-b", 4, 1);
        assert_ne!(a.a_w, b.a_w);
    }
}
