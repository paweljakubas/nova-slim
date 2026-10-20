//! Verus models of the pure-integer norm arithmetic in [`crate::norm`].
//!
//! The production functions in `norm.rs` are generic over
//! `ark_ff::PrimeField` / `BigInteger`, which Verus has no model for (see
//! `FormalVerification.md`).  Following the approach used in the bls repo,
//! this module proves properties of an *integer model* of the same
//! arithmetic — the bit-length of a magnitude, the range-certificate
//! acceptance predicate, and the infinity-norm predicate — rather than
//! annotating ark-typed surface area.
//!
//! Gated behind the `verus` feature.  Ghost code is erased in normal builds.

#![cfg(feature = "verus")]

use vstd::prelude::*;
use vstd::arithmetic::power2::{pow2, lemma_pow2_pos, lemma_pow2_strictly_increases};

verus! {

    // ────────────────────────────────────────────────────────────────
    // Model 1 — magnitude bit-length
    //
    // `norm::magnitude_bits` maps a bigint magnitude `m` to
    // `max(num_bits(m), 1)` = `ceil(log2(m + 1))` clamped to be at least 1.
    // The model below is that value as a non-recursive *specification*: the
    // least `b` with `m < 2^b` (and at least 1).  We do not compute it; we
    // reason about its defining property, which is what the certificate
    // soundness argument needs.
    // ────────────────────────────────────────────────────────────────

    /// Specification of the bit-length: `bit_len(m)` is *the* least `b >= 1`
    /// with `m < 2^b`.  This is `norm::magnitude_bits` on `nat`: since `m <=
    /// 2^b - 1 < 2^b` exactly when `num_bits(m) <= b` (for `m >= 1`), the least
    /// such `b` equals `ceil(log2(m + 1))`, clamped to 1.
    pub open spec fn is_bit_len(m: nat, b: nat) -> bool {
        &&& b >= 1
        &&& m < pow2(b)
        &&& (forall|b2: nat| b2 < b ==> !(m < pow2(b2)))
    }

    /// A magnitude `m` is representable in `bound_bits` bits — the integer
    /// model of `norm::fits_bits`.  Mirrors `coord_fits` with the "0 bits means
    /// only zero" special case.
    pub open spec fn coord_fits(m: nat, bound_bits: nat) -> bool {
        if bound_bits == 0 {
            m == 0
        } else {
            m < pow2(bound_bits)
        }
    }

    /// Soundness of the range certificate's per-coordinate check: if a
    /// coordinate passes `coord_fits`, then it lies strictly below
    /// `2^bound_bits` (for `bound_bits >= 1`).  This is the ground-truth norm
    /// enforcement that `norm::verify_range` relies on.
    proof fn lemma_coord_fits_bound(m: nat, bound_bits: nat)
        requires
            bound_bits >= 1,
            coord_fits(m, bound_bits),
        ensures
            m < pow2(bound_bits),
    {
    }

    /// `pow2` is strictly increasing, so the *least* `b` with `m < 2^b` is
    /// well-behaved: any larger bound also works.  This underpins the
    /// monotonicity of `norm_ok`.
    proof fn lemma_pow2_increases(a: nat, b: nat)
        requires
            a < b,
        ensures
            pow2(a) < pow2(b),
    {
        lemma_pow2_strictly_increases(a, b);
    }


    // ────────────────────────────────────────────────────────────────
    // Model 2 — infinity-norm predicate and its monotonicity
    //
    // `norm::norm_ok` returns `num_bits(measure_inf_norm(v)) <= bound.bits`.
    // Its integer model keeps the *maximum magnitude* directly and checks it
    // against the bound.
    // ────────────────────────────────────────────────────────────────

    /// Model of `norm::norm_ok` for a set of coordinate magnitudes: every
    /// magnitude fits `bound_bits`.
    pub open spec fn inf_norm_fits(max_mag: nat, bound_bits: nat) -> bool {
        coord_fits(max_mag, bound_bits)
    }

    /// `norm_ok` is monotone in the bound: a vector that fits a tighter bound
    /// also fits any looser bound.  This justifies callers passing a larger
    /// `bound.bits` as a conservative relaxation.
    proof fn lemma_inf_norm_monotone(max_mag: nat, b1: nat, b2: nat)
        requires
            b1 <= b2,
            inf_norm_fits(max_mag, b1),
        ensures
            inf_norm_fits(max_mag, b2),
    {
        if b1 == 0 {
            assert(max_mag == 0);
            lemma_pow2_pos(b2);
            assert(coord_fits(0, b2));
        } else {
            assert(max_mag < pow2(b1));
            if b2 == b1 {
                assert(coord_fits(max_mag, b2));
            } else {
                lemma_pow2_strictly_increases(b1, b2);
                assert(pow2(b1) < pow2(b2));
                assert(max_mag < pow2(b2));
                assert(coord_fits(max_mag, b2));
            }
        }
    }

    // ────────────────────────────────────────────────────────────────
    // Model 3 — range-certificate acceptance predicate
    //
    // `norm::verify_range` returns false as soon as some coordinate fails
    // either the "do not undersell" check or the "fits the bound" check.  The
    // model below is a recursive predicate over a sequence of (recorded,
    // true) bit-length pairs; the theorem states that acceptance implies
    // every recorded length is honest (>= the true length) and every true
    // length is within the certificate's bound.
    // ────────────────────────────────────────────────────────────────

    pub open spec fn range_accepts(recorded: Seq<nat>, true_len: Seq<nat>, bound_bits: nat) -> bool
        decreases recorded.len(),
    {
        &&& recorded.len() == true_len.len()
        &&& (if recorded.len() == 0 {
            true
        } else {
            let i = (recorded.len() - 1) as int;
            &&& recorded[i] >= true_len[i]
            &&& true_len[i] <= bound_bits
            &&& range_accepts(recorded.subrange(0, recorded.len() - 1),
                              true_len.subrange(0, true_len.len() - 1), bound_bits)
        })
    }

    /// Soundness: if `range_accepts` holds, then every recorded length is at
    /// least the true length, and every true length is within the bound.
    proof fn lemma_range_accepts_sound(
        recorded: Seq<nat>,
        true_len: Seq<nat>,
        bound_bits: nat,
        i: int,
    )
        requires
            range_accepts(recorded, true_len, bound_bits),
            0 <= i < recorded.len(),
        ensures
            recorded[i] >= true_len[i],
            true_len[i] <= bound_bits,
        decreases recorded.len(),
    {
        if recorded.len() == 0 {
        } else {
            let j = (recorded.len() - 1) as int;
            if i == j {
                // head case
            } else {
                lemma_range_accepts_sound(
                    recorded.subrange(0, recorded.len() - 1),
                    true_len.subrange(0, true_len.len() - 1),
                    bound_bits,
                    i,
                );
            }
        }
    }
}
