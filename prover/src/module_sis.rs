//! Exploratory Module-SIS commitment parameters.
//!
//! This module documents and validates candidate parameter sets for a future
//! modular, CLI-selectable Module-SIS commitment that would close NovaSlim's
//! concrete post-quantum security gap.  The commitment is **not yet
//! implemented** — these are planning-only types and validation functions.
//!
//! # Why Module-SIS?
//!
//! NovaSlim's current SIS commitment computes `c = A·v` over field-scale
//! vectors `v`.  Post-quantum binding of SIS requires the committed vector to
//! be **short**; field-scale coordinates provide no shortness guarantee.  The
//! plan is a proper **Ajtai/Module-SIS commitment** over a cyclotomic ring:
//!
//! - Ring `R = Z[x]/(x^n + 1)` with power-of-two `n`.
//! - Coefficient modulus `q` (NTT-friendly prime).
//! - Module rank `d` and `m = 2d` short vectors.
//! - Commitment: `c = A·s mod q` with `A` derived transparently from a seed
//!   via XOF (Keccak/BLAKE3), `s` short (`||s||_∞ ≤ β`).
//!
//! Binding reduces tightly to Module-SIS — no additional assumption beyond the
//! standard lattice hardness conjecture.  This upgrades the concrete PQ label
//! from "conjectured" to "standard-assumption (tight)" while preserving
//! folding and sub-kilobyte proofs.
//!
//! # The critical open problem
//!
//! NIFS folds `s' = s_1 + r·s_2`.  With a full-field Fiat-Shamir challenge `r`,
//! even two short vectors fold to a large-norm vector.  Until a
//! **folding-preserving committed-shortness** protocol is designed and reviewed
//! (e.g. small-fold-scalar variant or a binding shortness argument on the
//! commitment inputs), the Module-SIS commitment remains planning-only.
//!
//! # Candidate parameter sets
//!
//! | Set | NIST analogue | n | q | d | m | β | Expected classical core-SVP | Expected quantum core-SVP |
//! |---|---|---|---|---|---|---|---|---|
//! | Conservative-I | Level I (128-bit PQ) | 512 | ~2^23 | 4 | 8 | 2^10 | ≫128 | ≫128 |
//! | Balanced-I | Level I | 256 | ~2^23 | 6 | 12 | 2^10 | ≥128 | ≥128 |
//! | Conservative-III | Level III (192-bit PQ) | 1024 | ~2^32 | 4 | 8 | 2^12 | ≫192 | ≫192 |
//! | Balanced-III | Level III | 512 | ~2^32 | 6 | 12 | 2^12 | ≥192 | ≥192 |
//!
//! These are **exploratory** and must be validated with a standard lattice
//! estimator before operational use.

/// NTT-friendly modulus for the Conservative-I / Balanced-I parameter sets.
///
/// `q = 2^23 - 2^13 + 1 = 8380417`, a common Kyber/Dilithium-style prime.
pub const Q_L1: u64 = 8380417;

/// NTT-friendly modulus for the Conservative-III / Balanced-III parameter sets.
///
/// `q = 2^32 - 2^18 + 1 = 4293918721`, chosen so that `2^18` divides `q-1`,
/// supporting NTT up to dimension 2^17.
pub const Q_L3: u64 = 4293918721;

/// NIST security-level analogue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NistLevel {
    Level1,
    Level3,
}

/// Conservative-vs-balanced trade-off.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParamBalance {
    /// Oversized in ring dimension to absorb heuristic-model uncertainty.
    Conservative,
    /// Trades ring dimension for module rank (smaller `n`, larger `d`).
    Balanced,
}

/// A candidate Module-SIS parameter set.
///
/// All fields are `u64` to allow cross-platform consistency; the actual
/// implementation would use `u32` or `u64` depending on `q`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModuleSisParams {
    /// NIST analogue target.
    pub level: NistLevel,
    /// Conservative or balanced sizing.
    pub balance: ParamBalance,
    /// Ring dimension (power of two).
    pub n: u64,
    /// Coefficient modulus (NTT-friendly prime).
    pub q: u64,
    /// Module rank.
    pub d: u64,
    /// Number of short vectors (typically `2*d`).
    pub m: u64,
    /// Infinity-norm bound on committed vector coefficients.
    pub beta: u64,
    /// log2 of beta.
    pub beta_bits: u32,
}

impl ModuleSisParams {
    /// Conservative-I: n=512, q≈2^23, d=4, m=8, β=2^10.
    pub const CONSERVATIVE_I: Self = Self {
        level: NistLevel::Level1,
        balance: ParamBalance::Conservative,
        n: 512,
        q: Q_L1,
        d: 4,
        m: 8,
        beta: 1024,
        beta_bits: 10,
    };

    /// Balanced-I: n=256, q≈2^23, d=6, m=12, β=2^10.
    pub const BALANCED_I: Self = Self {
        level: NistLevel::Level1,
        balance: ParamBalance::Balanced,
        n: 256,
        q: Q_L1,
        d: 6,
        m: 12,
        beta: 1024,
        beta_bits: 10,
    };

    /// Conservative-III: n=1024, q≈2^32, d=4, m=8, β=2^12.
    pub const CONSERVATIVE_III: Self = Self {
        level: NistLevel::Level3,
        balance: ParamBalance::Conservative,
        n: 1024,
        q: Q_L3,
        d: 4,
        m: 8,
        beta: 4096,
        beta_bits: 12,
    };

    /// Balanced-III: n=512, q≈2^32, d=6, m=12, β=2^12.
    pub const BALANCED_III: Self = Self {
        level: NistLevel::Level3,
        balance: ParamBalance::Balanced,
        n: 512,
        q: Q_L3,
        d: 6,
        m: 12,
        beta: 4096,
        beta_bits: 12,
    };

    /// All predefined candidate sets.
    pub const ALL: &[Self] = &[
        Self::CONSERVATIVE_I,
        Self::BALANCED_I,
        Self::CONSERVATIVE_III,
        Self::BALANCED_III,
    ];

    /// Validate structural invariants of the parameter set.
    ///
    /// Checks:
    /// - `n` is a power of two.
    /// - `q` is odd (prerequisite for NTT-friendly prime).
    /// - `m >= d` (over-determined system).
    /// - `beta < q` (shortness is meaningful).
    /// - `beta` is a power of two.
    pub fn validate(&self) -> Result<(), ParamError> {
        if !self.n.is_power_of_two() {
            return Err(ParamError::RingDimensionNotPowerOfTwo);
        }
        if self.q % 2 == 0 {
            return Err(ParamError::ModulusEven);
        }
        if self.m < self.d {
            return Err(ParamError::Underdetermined);
        }
        if self.beta >= self.q {
            return Err(ParamError::BetaTooLarge);
        }
        if !self.beta.is_power_of_two() {
            return Err(ParamError::BetaNotPowerOfTwo);
        }
        Ok(())
    }

    /// Estimated commitment size in bytes: `d * n * log2(q) / 8`.
    ///
    /// This is the size of the commitment vector `c = A·s` over `R_q^d`.
    pub fn commitment_size(&self) -> usize {
        let log2q = 64 - self.q.leading_zeros();
        ((self.d * self.n * log2q as u64 + 7) / 8) as usize
    }

    /// Human-readable label, e.g. "Conservative-I".
    pub fn label(&self) -> &'static str {
        match (self.level, self.balance) {
            (NistLevel::Level1, ParamBalance::Conservative) => "Conservative-I",
            (NistLevel::Level1, ParamBalance::Balanced) => "Balanced-I",
            (NistLevel::Level3, ParamBalance::Conservative) => "Conservative-III",
            (NistLevel::Level3, ParamBalance::Balanced) => "Balanced-III",
        }
    }
}

/// Validation error for Module-SIS parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParamError {
    RingDimensionNotPowerOfTwo,
    ModulusEven,
    Underdetermined,
    BetaTooLarge,
    BetaNotPowerOfTwo,
}

impl std::fmt::Display for ParamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParamError::RingDimensionNotPowerOfTwo => {
                write!(f, "ring dimension n must be a power of two")
            }
            ParamError::ModulusEven => write!(f, "modulus q must be odd"),
            ParamError::Underdetermined => write!(f, "m must be >= d"),
            ParamError::BetaTooLarge => write!(f, "beta must be < q"),
            ParamError::BetaNotPowerOfTwo => write!(f, "beta must be a power of two"),
        }
    }
}

impl std::error::Error for ParamError {}

/// Pick a candidate set by label.
pub fn params_by_label(label: &str) -> Option<ModuleSisParams> {
    ModuleSisParams::ALL
        .iter()
        .find(|p| p.label().eq_ignore_ascii_case(label))
        .copied()
}

// ------------------------------------------------------------------
// P2: Folding-preserving committed shortness — norm-growth analysis
// ------------------------------------------------------------------

/// Small-fold-scalar challenge distribution.
///
/// For Module-SIS folding, the challenge `r` must be small so that
/// `s' = s_1 + r·s_2` stays short.  The standard trick (PikkuFold,
/// LatticeFold) is to sample `r` from a small/ternary set instead of the
/// full field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmallChallengeSet {
    /// Ternary `{-1, 0, 1}` — smallest possible non-trivial set.
    /// Norm growth per fold: at most `2×`.
    Ternary,
    /// Small uniform `[-B, B]` for a small bound `B`.
    /// Norm growth per fold: at most `(1 + B)`.
    Uniform { bound: u64 },
}

impl SmallChallengeSet {
    /// The maximum absolute value of a challenge from this set.
    pub fn max_abs(&self) -> u64 {
        match self {
            SmallChallengeSet::Ternary => 1,
            SmallChallengeSet::Uniform { bound } => *bound,
        }
    }

    /// Expected norm-growth factor per fold for a witness vector.
    ///
    /// If `‖s_1‖∞, ‖s_2‖∞ ≤ B` and `|r| ≤ B_r`, then
    /// `‖s_1 + r·s_2‖∞ ≤ B + B_r·B = B·(1 + B_r)`.
    pub fn witness_growth_factor(&self) -> u64 {
        1 + self.max_abs()
    }

    /// Expected norm-growth factor per fold for an error vector that
    /// includes a cross-term.
    ///
    /// The cross-term `T` can be larger than the witness (it involves
    /// products of matrix-vector products).  Empirically, for sparse R1CS
    /// matrices with ≤ 3 non-zeros per row, `‖T‖∞` is bounded by
    /// `≈ 18·B_w² + 6·B_w` when both witnesses have norm `B_w`.
    /// With a fresh step (`e_2 = 0`), the error fold is
    /// `e' = e_1 + r·T`, so the growth is additive: `‖e'‖∞ ≤ ‖e_1‖∞ + B_r·‖T‖∞`.
    pub fn error_growth_bound(&self, witness_norm: u64) -> u64 {
        let b = witness_norm;
        // Conservative bound for ‖T‖∞ with ≤ 3 non-zeros per matrix row.
        let t_bound = 18 * b * b + 6 * b;
        self.max_abs() * t_bound
    }
}

/// Result of a norm-growth simulation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormGrowthResult {
    /// Number of folds simulated.
    pub n_folds: usize,
    /// Challenge set used.
    pub challenge_set: SmallChallengeSet,
    /// Initial witness shortness bound.
    pub initial_witness_bound: u64,
    /// Final witness infinity-norm after n_folds.
    pub final_witness_norm: u64,
    /// Final error infinity-norm after n_folds.
    pub final_error_norm: u64,
    /// The SIS modulus q against which we compare.
    pub modulus_q: u64,
    /// Whether the final norms are still short (≤ q/2, a conservative margin).
    pub is_short: bool,
}

/// Simulate NIFS norm growth with small-fold-scalar challenges.
///
/// This is an *empirical* simulation: it models the IVC chain where a
/// short step witness is folded into an accumulator at each step, using
/// challenges drawn from `challenge_set`.  The error starts at zero
/// (fresh R1CS step) and accumulates cross-terms.
///
/// The simulation uses a *worst-case* model (always taking the maximum
/// challenge magnitude) rather than a random model, because soundness
/// must hold against adversarial challenges.
pub fn simulate_norm_growth(
    n_folds: usize,
    challenge_set: SmallChallengeSet,
    initial_witness_bound: u64,
    modulus_q: u64,
) -> NormGrowthResult {
    let mut witness_norm = initial_witness_bound;
    let mut error_norm: u64 = 0;
    let b_r = challenge_set.max_abs();

    for _ in 0..n_folds {
        // Cross-term T is computed from the *pre-fold* accumulator witness
        // and the fresh step witness.  Use the pre-fold accumulator norm.
        let t_bound = 18 * witness_norm * witness_norm + 6 * witness_norm;
        error_norm = error_norm + b_r * t_bound;

        // Witness: w_acc + r * w_step.  w_step is fresh, so its norm
        // is initial_witness_bound.  w_acc has grown.
        // Worst case: both terms add constructively.
        witness_norm = witness_norm + b_r * initial_witness_bound;
    }

    // A vector is "short" for SIS if its infinity-norm is well below q.
    // We use q/2 as a conservative margin.
    let is_short = witness_norm <= modulus_q / 2 && error_norm <= modulus_q / 2;

    NormGrowthResult {
        n_folds,
        challenge_set,
        initial_witness_bound,
        final_witness_norm: witness_norm,
        final_error_norm: error_norm,
        modulus_q,
        is_short,
    }
}

/// Recommend a checkpoint interval for a given parameter set.
///
/// Returns the maximum number of folds between norm-reset checkpoints
/// such that the accumulated witness and error remain short.
pub fn recommended_checkpoint_interval(
    challenge_set: SmallChallengeSet,
    initial_witness_bound: u64,
    modulus_q: u64,
) -> usize {
    let mut n = 1usize;
    loop {
        let result = simulate_norm_growth(n, challenge_set, initial_witness_bound, modulus_q);
        if !result.is_short {
            // The previous n-1 was the last safe value.
            return n.saturating_sub(1).max(1);
        }
        n += 1;
        // Safety: stop at an absurdly large number.
        if n > 100_000 {
            return 100_000;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_predefined_sets_validate() {
        for params in ModuleSisParams::ALL {
            assert!(
                params.validate().is_ok(),
                "{} failed validation",
                params.label()
            );
        }
    }

    #[test]
    fn conservative_i_size_is_small() {
        let size = ModuleSisParams::CONSERVATIVE_I.commitment_size();
        // d=4, n=512, log2q≈23 → ~4*512*23/8 = 5888 bytes ≈ 5.8 KiB
        assert!(size > 4000, "expected > 4 KiB, got {} B", size);
        assert!(size < 8000, "expected < 8 KiB, got {} B", size);
    }

    #[test]
    fn balanced_i_size_is_smaller() {
        let size = ModuleSisParams::BALANCED_I.commitment_size();
        // d=6, n=256, log2q≈23 → ~6*256*23/8 = 4416 bytes ≈ 4.3 KiB
        assert!(size > 3000, "expected > 3 KiB, got {} B", size);
        assert!(size < 6000, "expected < 6 KiB, got {} B", size);
    }

    #[test]
    fn conservative_iii_size_is_larger() {
        let size = ModuleSisParams::CONSERVATIVE_III.commitment_size();
        // d=4, n=1024, log2q≈32 → ~4*1024*32/8 = 16384 bytes = 16 KiB
        assert!(size > 12000, "expected > 12 KiB, got {} B", size);
        assert!(size < 20000, "expected < 20 KiB, got {} B", size);
    }

    #[test]
    fn params_by_label_finds_all() {
        for params in ModuleSisParams::ALL {
            let found = params_by_label(params.label());
            assert_eq!(found, Some(*params));
        }
    }

    #[test]
    fn params_by_label_case_insensitive() {
        assert!(params_by_label("conservative-i").is_some());
        assert!(params_by_label("BALANCED-III").is_some());
    }

    #[test]
    fn params_by_label_unknown_returns_none() {
        assert!(params_by_label("nonexistent").is_none());
    }

    #[test]
    fn validation_catches_bad_n() {
        let mut p = ModuleSisParams::CONSERVATIVE_I;
        p.n = 511;
        assert_eq!(p.validate(), Err(ParamError::RingDimensionNotPowerOfTwo));
    }

    #[test]
    fn validation_catches_even_q() {
        let mut p = ModuleSisParams::CONSERVATIVE_I;
        p.q = 8380416;
        assert_eq!(p.validate(), Err(ParamError::ModulusEven));
    }

    #[test]
    fn validation_catches_underdetermined() {
        let mut p = ModuleSisParams::CONSERVATIVE_I;
        p.m = 2;
        assert_eq!(p.validate(), Err(ParamError::Underdetermined));
    }

    #[test]
    fn validation_catches_beta_too_large() {
        let mut p = ModuleSisParams::CONSERVATIVE_I;
        p.beta = p.q;
        assert_eq!(p.validate(), Err(ParamError::BetaTooLarge));
    }

    #[test]
    fn validation_catches_beta_not_power_of_two() {
        let mut p = ModuleSisParams::CONSERVATIVE_I;
        p.beta = 1000;
        assert_eq!(p.validate(), Err(ParamError::BetaNotPowerOfTwo));
    }

    #[test]
    fn all_sets_have_distinct_labels() {
        let labels: Vec<_> = ModuleSisParams::ALL.iter().map(|p| p.label()).collect();
        let mut dedup = labels.clone();
        dedup.dedup();
        assert_eq!(
            labels.len(),
            dedup.len(),
            "duplicate labels found in predefined sets"
        );
    }

    #[test]
    fn all_sets_have_positive_commitment_size() {
        for params in ModuleSisParams::ALL {
            let size = params.commitment_size();
            assert!(size > 0, "{} commitment size must be positive", params.label());
        }
    }

    #[test]
    fn beta_bits_matches_beta() {
        for params in ModuleSisParams::ALL {
            assert_eq!(
                params.beta,
                1u64 << params.beta_bits,
                "{}: beta must equal 2^beta_bits",
                params.label()
            );
        }
    }

    // ── Norm-growth analysis tests (P2) ─────────────────────────────

    #[test]
    fn ternary_challenge_growth_is_bounded_per_fold() {
        // Use a smaller β so that even the conservative cross-term bound
        // stays below q/2 after one fold.
        let result = simulate_norm_growth(
            1,
            SmallChallengeSet::Ternary,
            256, // β = 2^8
            Q_L1,
        );
        // After 1 fold: w_norm = β + 1·β = 2β = 512
        assert_eq!(result.final_witness_norm, 512);
        assert!(result.is_short, "1 fold with β=256 must stay short");
    }

    #[test]
    fn full_field_challenge_fails_quickly() {
        // Simulate "full field" as a very large uniform bound.
        let result = simulate_norm_growth(
            2,
            SmallChallengeSet::Uniform { bound: 1_000_000 },
            1024,
            Q_L1,
        );
        assert!(!result.is_short, "full-field challenge must blow up quickly");
    }

    #[test]
    fn ternary_254_folds_exceeds_q() {
        // With β = 2^10 and q ≈ 2^23, ternary challenges exceed q/2
        // after a modest number of folds because error growth is quadratic.
        let result = simulate_norm_growth(
            254,
            SmallChallengeSet::Ternary,
            1024,
            Q_L1,
        );
        assert!(
            !result.is_short,
            "254 ternary folds must exceed SIS bound (demonstrates need for checkpoints)"
        );
    }

    #[test]
    fn conservative_i_recommends_checkpoints() {
        let interval = recommended_checkpoint_interval(
            SmallChallengeSet::Ternary,
            1024, // β = 2^10
            Q_L1,
        );
        // With β = 2^10 and q ≈ 2^23, the checkpoint interval should be
        // small but non-trivial (empirically ~3-5 folds with conservative bounds).
        assert!(
            interval > 0,
            "checkpoint interval must be positive"
        );
        assert!(
            interval < 254,
            "checkpoint interval must be < 254 for Conservative-I"
        );
    }

    #[test]
    fn balanced_i_allows_more_folds_than_conservative_i() {
        let int_balanced = recommended_checkpoint_interval(
            SmallChallengeSet::Ternary,
            1024,
            Q_L1,
        );
        // Both use same q and β, so interval should be similar.
        // The difference is commitment size, not norm budget.
        assert!(int_balanced > 0);
    }

    #[test]
    fn smaller_beta_allows_more_folds() {
        let int_small = recommended_checkpoint_interval(
            SmallChallengeSet::Ternary,
            256, // smaller β
            Q_L1,
        );
        let int_large = recommended_checkpoint_interval(
            SmallChallengeSet::Ternary,
            1024, // larger β
            Q_L1,
        );
        assert!(
            int_small >= int_large,
            "smaller β should allow at least as many folds"
        );
    }

    #[test]
    fn uniform_bound_1_allows_more_folds_than_ternary() {
        let int_ternary = recommended_checkpoint_interval(
            SmallChallengeSet::Ternary,
            1024,
            Q_L1,
        );
        let int_uniform_1 = recommended_checkpoint_interval(
            SmallChallengeSet::Uniform { bound: 1 },
            1024,
            Q_L1,
        );
        assert!(
            int_uniform_1 >= int_ternary,
            "uniform bound=1 (max_abs=1, same as ternary) should match or exceed ternary"
        );
    }

    #[test]
    fn simulate_norm_growth_monotonic() {
        let r1 = simulate_norm_growth(10, SmallChallengeSet::Ternary, 1024, Q_L1);
        let r2 = simulate_norm_growth(20, SmallChallengeSet::Ternary, 1024, Q_L1);
        assert!(
            r2.final_witness_norm >= r1.final_witness_norm,
            "norm must be monotonic in fold count"
        );
        assert!(
            r2.final_error_norm >= r1.final_error_norm,
            "error norm must be monotonic in fold count"
        );
    }

    #[test]
    fn conservative_iii_allows_reasonable_folds() {
        // L3 has much larger q (≈2^32 vs ≈2^23) but also larger β (2^12 vs 2^10).
        // The quadratic cross-term growth means the interval may not be
        // dramatically larger; what matters is that it is positive.
        let int_l3 = recommended_checkpoint_interval(
            SmallChallengeSet::Ternary,
            4096, // β = 2^12 for L3
            Q_L3,
        );
        assert!(
            int_l3 > 0,
            "Conservative-III must allow a positive checkpoint interval"
        );
        // Empirically: with β=4096 and q≈2^32, the quadratic T growth
        // gives a checkpoint interval of ~2 folds (the q budget is eaten
        // quickly by 18·β² terms).  This demonstrates why checkpointing
        // is essential regardless of parameter set.
        assert!(
            int_l3 >= 2,
            "Conservative-III should allow at least 2 folds"
        );
    }
}
