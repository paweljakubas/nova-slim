//! Verus *contracts* (not proofs) for the ark-typed surface of [`crate::norm`].
//!
//! **These are asserted, not verified.**  Every function here is marked
//! `#[verifier::external]`, which tells Verus to trust the stated
//! postcondition without checking the body.  They exist to document the shape
//! intent of the ark-generic functions and to be usable by other proofs; they
//! are *not* evidence that the production code satisfies them.
//!
//! This mirrors the honest split recorded for the bls repo
//! (`FormalVerification.md` §"What is not verified").  The wall is
//! `ark_ff::PrimeField` / `BigInteger`, which Verus has no model for: even a
//! bare loop over `&[F]` fails to verify, so the loop-shaped guarantees
//! (`make_range` output length, `verify_range` per-coordinate honesty) stay
//! asserted.  The *value* arithmetic these loops implement is separately
//! modelled and proved in [`crate::verus_norm`].
//!
//! Gated behind the `verus` feature.

#![cfg(feature = "verus")]

use vstd::prelude::*;

verus! {

    /// Contract for `norm::signed_magnitude`.
    ///
    /// The signed magnitude of a field element is a canonical representative
    /// magnitude, i.e. a value in the field's bigint range.  The precise value
    /// (`b` if `b <= (p-1)/2`, else `p - b`) is *asserted*, as is the fact that
    /// it lies below the modulus — neither is checked.
    pub uninterp spec fn spec_signed_magnitude<F>(v: F) -> F;

    /// Contract for `norm::measure_inf_norm`.
    ///
    /// The infinity norm is the maximum of the per-coordinate signed
    /// magnitudes, so it is *equal to one of the input magnitudes* (or zero for
    /// the empty vector).  This membership property — the part that makes the
    /// `max` reduction meaningful — is asserted.
    pub uninterp spec fn spec_measure_inf_norm<F>(v: Seq<F>) -> F;

    /// Contract for `norm::make_range`.
    ///
    /// On success the certificate has exactly one recorded bit-length per
    /// coordinate of the truth table.  Stated over lengths only; the body loops
    /// over ark-typed elements, which Verus cannot check.
    pub open spec fn spec_make_range_len(truth_len: nat, cert_len: nat) -> bool {
        cert_len == truth_len
    }

    /// Contract for `norm::verify_range`.
    ///
    /// `verify_range` returns `false` immediately if the recorded lengths do
    /// not line up with the truth table, so acceptance implies the lengths
    /// match.
    pub open spec fn spec_verify_range_accepts_implies_len_match(
        truth_len: nat,
        cert_len: nat,
        accepted: bool,
    ) -> bool {
        accepted ==> cert_len == truth_len
    }
}
