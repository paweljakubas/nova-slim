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
#[cfg(feature = "grumpkin")]
use ark_ec::{models::CurveConfig, short_weierstrass::{self as sw, SWCurveConfig}};
use ark_ff::PrimeField;
#[cfg(feature = "grumpkin")]
use ark_ff::{Field, MontFp, Zero};

/// Trait abstracting the elliptic curve used by the Nova IVC scheme.
///
/// Implement this trait for any curve you want to support (e.g. BLS12-381,
/// BN254, Pallas, secp256k1). The folding and compression logic are then
/// completely generic over the curve.
pub trait NovaCurve: 'static + Sized + Clone + Copy + PartialEq + Eq + std::fmt::Debug + Send + Sync {
    /// Scalar field — hosts R1CS constraints, witnesses, Fiat-Shamir
    /// challenges, and all sumcheck arithmetic.
    type ScalarField: PrimeField;

    /// G1 affine group — hosts Pedersen commitment bases and commitment
    /// values.  Its scalar field must match `Self::ScalarField` so that
    /// Pedersen MSMs are well-typed.
    type G1Affine: AffineRepr<ScalarField = Self::ScalarField>;
}

/// Convenience alias for the projective group associated with a curve's G1.
pub type G1Projective<C> = <<C as NovaCurve>::G1Affine as AffineRepr>::Group;

/// Convenience alias for the scalar field associated with a curve.
pub type ScalarField<C> = <C as NovaCurve>::ScalarField;

// ────────────────────────────────────────────────────────────────────
// Concrete implementations
// ────────────────────────────────────────────────────────────────────

/// BLS12-381 — the Cardano-native curve.
#[cfg(feature = "bls12-381")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bls12_381;

#[cfg(feature = "bls12-381")]
impl NovaCurve for Bls12_381 {
    type ScalarField = ark_bls12_381::Fr;
    type G1Affine = ark_bls12_381::G1Affine;
}

/// BN254 — widely used in Ethereum zk-rollups.
#[cfg(feature = "bn254")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bn254;

#[cfg(feature = "bn254")]
impl NovaCurve for Bn254 {
    type ScalarField = ark_bn254::Fr;
    type G1Affine = ark_bn254::G1Affine;
}

/// Pallas — the Zcash Orchard curve (prime-order, no pairing).
#[cfg(feature = "pallas")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pallas;

#[cfg(feature = "pallas")]
impl NovaCurve for Pallas {
    type ScalarField = ark_pallas::Fr;
    type G1Affine = ark_pallas::Affine;
}

/// Vesta — the other half of the Pallas/Vesta cycle (prime-order, no pairing).
#[cfg(feature = "vesta")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Vesta;

#[cfg(feature = "vesta")]
impl NovaCurve for Vesta {
    type ScalarField = ark_vesta::Fr;
    type G1Affine = ark_vesta::Affine;
}

/// Grumpkin — the BN254 complement in the BN254/Grumpkin cycle.
/// Defined inline using ark-bn254 fields (no extra dependency).
#[cfg(feature = "grumpkin")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Grumpkin;

#[cfg(feature = "grumpkin")]
#[derive(Copy, Clone, Default, PartialEq, Eq)]
pub struct GrumpkinConfig;

#[cfg(feature = "grumpkin")]
impl CurveConfig for GrumpkinConfig {
    type BaseField = ark_bn254::Fr;   // Grumpkin base field = BN254 scalar field
    type ScalarField = ark_bn254::Fq; // Grumpkin scalar field = BN254 base field

    const COFACTOR: &'static [u64] = &[0x1];
    const COFACTOR_INV: Self::ScalarField = ark_bn254::Fq::ONE;
}

#[cfg(feature = "grumpkin")]
impl SWCurveConfig for GrumpkinConfig {
    const COEFF_A: Self::BaseField = ark_bn254::Fr::ZERO;
    const COEFF_B: Self::BaseField = MontFp!("-17");
    const GENERATOR: sw::Affine<Self> = sw::Affine::new_unchecked(
        MontFp!("1"),
        MontFp!("17631683881184975370165255887551781615748388533673675138860"),
    );

    #[inline(always)]
    fn mul_by_a(_: Self::BaseField) -> Self::BaseField {
        Self::BaseField::zero()
    }
}

#[cfg(feature = "grumpkin")]
impl NovaCurve for Grumpkin {
    type ScalarField = ark_bn254::Fq;
    type G1Affine = sw::Affine<GrumpkinConfig>;
}

/// Bandersnatch — a fast prime-order curve over the BLS12-381 scalar field.
#[cfg(feature = "bandersnatch")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bandersnatch;

#[cfg(feature = "bandersnatch")]
impl NovaCurve for Bandersnatch {
    type ScalarField = ark_ed_on_bls12_381_bandersnatch::Fr;
    type G1Affine = ark_ed_on_bls12_381_bandersnatch::SWAffine;
}
