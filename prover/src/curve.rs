//! Curve abstraction for NovaSlim — makes the folding scheme agnostic to the
//! underlying elliptic curve.
//!
//! The only requirements are:
//!   1. A prime field `ScalarField` for R1CS constraints, witnesses, and
//!      sumcheck arithmetic.
//!   2. A group `G1Affine` for Pedersen commitments (used in NIFS folding).
//!
//! Because our folding is *off-circuit*, we do **not** need a curve cycle,
//! pairings, or a secondary curve. Any curve with hard DLOG works.

use ark_ec::AffineRepr;
use ark_ff::PrimeField;

/// Trait abstracting the elliptic curve used by the Nova IVC scheme.
///
/// Implement this trait for any curve you want to support (e.g. BLS12-381,
/// BN254, Pallas, secp256k1). The folding and compression logic are then
/// completely generic over the curve.
pub trait NovaCurve: 'static + Sized + Clone + Copy {
    /// Scalar field — hosts R1CS constraints, witnesses, Fiat-Shamir
    /// challenges, and all sumcheck arithmetic.
    type ScalarField: PrimeField;

    /// G1 affine group — hosts Pedersen commitment bases and commitment
    /// values.
    type G1Affine: AffineRepr;
}

/// Convenience alias for the projective group associated with a curve's G1.
pub type G1Projective<C> = <<C as NovaCurve>::G1Affine as AffineRepr>::Group;

// ────────────────────────────────────────────────────────────────────
// Concrete implementations
// ────────────────────────────────────────────────────────────────────

/// BLS12-381 — the Cardano-native curve.
#[derive(Debug, Clone, Copy)]
pub struct Bls12_381;

impl NovaCurve for Bls12_381 {
    type ScalarField = ark_bls12_381::Fr;
    type G1Affine = ark_bls12_381::G1Affine;
}
