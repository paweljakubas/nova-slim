//! Commitment scheme abstraction for NIFS folding.
//!
//! Defines a generic `CommitmentScheme` trait and a Pedersen implementation
//! over any elliptic curve. Future work: SIS/Ajtai lattice commitment.

use ark_ec::{AffineRepr, Group, VariableBaseMSM};
use ark_ff::PrimeField;
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
