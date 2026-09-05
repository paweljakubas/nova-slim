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
}
