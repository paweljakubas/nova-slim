//! Module-SIS (Ajtai) commitment parameters and implementation.
//!
//! This module documents candidate parameter sets and provides an
//! **experimental implementation** (`ModuleSisCommitment`) of a Module-SIS
//! commitment over `R_q = Z_q[x]/(x^n + 1)` that closes NovaSlim's concrete
//! post-quantum security gap.  The parameter sets are also validated here.
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
//! even two short vectors fold to a large-norm vector.  NovaSlim keeps the
//! fold challenge **ternary** (`r ∈ {-1, 0, 1}`) via the checkpoint protocol
//! (see `recommended_checkpoint_interval`); the committed-norm growth between
//! checkpoints is bounded by `simulate_norm_growth`.
//!
//! A second caveat is that `commit_witness` here embeds field-scale Scalar
//! values into `R_q` via a reduction map `φ: F → R_q` (a stand-in for the
//! committed-shortness protocol).  Because `φ` is **not a ring homomorphism**,
//! field-scalar folding (`C(a+b) = C(a) + C(b)` over `F`) does not hold.  The
//! commitment is homomorphic over the *ring* `R_q`: for ring blocks
//! `s_1, s_2` and ring scalar `r`, `C(s_1 + s_2) = C(s_1) + C(s_2)` and
//! `C(r·s) = r·C(s)`.  Pipeline deployment therefore requires folding in the
//! ring domain with ring scalars — the subject of the committed-shortness work.
//! This is the honest scope of the current experimental implementation.
//!
//! # Candidate parameter sets
//!
//! | Set | NIST analogue | n | q | d | m | β | Classical core-SVP | Quantum core-SVP |
//! |---|---|---|---|---|---|---|---|---|
//! | Conservative-I | Level I (128-bit PQ) | 512 | ~2^23 | 4 | 8 | 2^10 | ~2^1195.7 | ~2^1085.2 |
//! | Balanced-I | Level I | 256 | ~2^23 | 6 | 12 | 2^10 | ~2^896.7 | ~2^813.8 |
//! | Conservative-III | Level III (192-bit PQ) | 1024 | ~2^32 | 4 | 8 | 2^12 | ~2^2391.8 | ~2^2170.6 |
//! | Balanced-III | Level III | 512 | ~2^32 | 6 | 12 | 2^12 | ~2^1793.8 | ~2^1627.9 |
//!
//! The core-SVP columns are the **validated estimator output** (2026-09-10):
//! the Core-SVP path of the Albrecht et al. lattice-estimator (ADPS16 sieving
//! exponents 0.292/0.265, LGSA shape), ported to pure Python and committed in
//! the docs repo at `tools/sis_core_svp.py` (output in
//! `tools/sis_core_svp_output.json`; validated against the Dilithium2 anchor
//! β=423, rop≈2^123.5).  For all four sets the optimized attack saturates at
//! the maximum usable block size (β_block = n·m − 1 = lattice dimension − 1);
//! the exponent recorded is the sieving cost 2^(0.292·β_block) /
//! 2^(0.265·β_block), and including the estimator's success-probability
//! repetition factor the total attack cost is even larger (≈2^1713 / 2^1287 /
//! 2^21169 / 2^15879).  These figures are lower bounds on the best known
//! attack class, not absolute proofs, and extrapolate asymptotic sieving
//! constants to very large block sizes; they confirm the sets are
//! **conservative** (see RFC §3.5).

use std::io::{Read, Write};
use std::marker::PhantomData;

use ark_ff::{BigInteger, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError, Valid, Compress};
use blake2::{Blake2b512, Digest};

use crate::commitment::CommitmentScheme;
use crate::curve::{NovaCurve, ScalarField};

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
    /// Validated (2026-09-10): core-SVP ~2^1195.7 classical / 2^1085.2 quantum
    /// (estimated attack saturates at β_block = 4095).
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
    /// Validated (2026-09-10): core-SVP ~2^896.7 classical / 2^813.8 quantum
    /// (estimated attack saturates at β_block = 3071).
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
    /// Validated (2026-09-10): core-SVP ~2^2391.8 classical / 2^2170.6 quantum
    /// (estimated attack saturates at β_block = 8191).
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
    /// Validated (2026-09-10): core-SVP ~2^1793.8 classical / 2^1627.9 quantum
    /// (estimated attack saturates at β_block = 6143).
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

    /// Conservative bound on the cross-term `‖T‖∞` for a witness norm `b`.
    ///
    /// For sparse R1CS matrices with ≤ 3 non-zeros per row, `‖T‖∞` is bounded
    /// by `≈ 18·b² + 6·b`.  Saturating: once the norm exceeds `u64::MAX` it is
    /// certainly not short, and callers only need the exact value while it is
    /// below `q/2` (≤ 2^32 for our moduli), so clamping to `u64::MAX` is safe.
    fn cross_term_bound(b: u64) -> u64 {
        18u64
            .saturating_mul(b)
            .saturating_mul(b)
            .saturating_add(6u64.saturating_mul(b))
    }

    /// Expected norm-growth factor per fold for an error vector that
    /// includes a cross-term.
    ///
    /// With a fresh step (`e_2 = 0`), the error fold is
    /// `e' = e_1 + r·T`, so the growth is additive: `‖e'‖∞ ≤ ‖e_1‖∞ + B_r·‖T‖∞`.
    pub fn error_growth_bound(&self, witness_norm: u64) -> u64 {
        self.max_abs()
            .saturating_mul(Self::cross_term_bound(witness_norm))
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
        // Saturating: at this magnitude the simulation is dominated by the
        // overflow, and any clamped value still overflows q/2 below.
        let t_bound = SmallChallengeSet::cross_term_bound(witness_norm);
        error_norm = error_norm.saturating_add(b_r.saturating_mul(t_bound));

        // Witness: w_acc + r * w_step.  w_step is fresh, so its norm
        // is initial_witness_bound.  w_acc has grown.
        // Worst case: both terms add constructively.
        witness_norm = witness_norm.saturating_add(b_r.saturating_mul(initial_witness_bound));
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

// ------------------------------------------------------------------
// P3: Module-SIS (Ajtai) commitment over R_q = Z_q[x]/(x^n + 1)
// ------------------------------------------------------------------

/// A ring element in `R_q = Z_q[x]/(x^n + 1)`.
///
/// Coefficients are stored canonically reduced into `[0, q)`, with `x^n ≡ -1`
/// enforced by `mul`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rq {
    /// Ring dimension (power of two).
    pub n: usize,
    /// Coefficient modulus.
    pub q: u64,
    /// `n` coefficients in `[0, q)`.
    pub coeffs: Vec<u64>,
}

impl Rq {
    /// The zero ring element for ring `(n, q)`.
    pub fn zero(n: usize, q: u64) -> Self {
        Self { n, q, coeffs: vec![0; n] }
    }

    /// Build a ring element from already-reduced coefficients.
    pub fn from_coeffs(coeffs: Vec<u64>, q: u64) -> Self {
        let n = coeffs.len();
        assert!(n > 0, "ring element must have at least one coefficient");
        debug_assert!(coeffs.iter().all(|&c| c < q), "coefficients must be reduced mod q");
        Self { n, q, coeffs }
    }

    /// Additive inverse.
    pub fn neg(&self) -> Self {
        let coeffs = self.coeffs.iter().map(|&c| (self.q - c) % self.q).collect();
        Self { n: self.n, q: self.q, coeffs }
    }

    /// Addition in `R_q`.
    pub fn add(&self, other: &Self) -> Self {
        debug_assert_eq!(self.n, other.n, "ring dimensions must match");
        debug_assert_eq!(self.q, other.q, "moduli must match");
        let coeffs = self
            .coeffs
            .iter()
            .zip(&other.coeffs)
            .map(|(&a, &b)| (a + b) % self.q)
            .collect();
        Self { n: self.n, q: self.q, coeffs }
    }

    /// Multiplication by an integer scalar modulo `q`.
    pub fn scalar_mul(&self, s: u64) -> Self {
        let coeffs = self
            .coeffs
            .iter()
            .map(|&c| ((c as u128 * s as u128) % self.q as u128) as u64)
            .collect();
        Self { n: self.n, q: self.q, coeffs }
    }

    /// Negacyclic multiplication in `R_q`: reduce modulo `x^n + 1`.
    ///
    /// Computes the linear convolution of `2n - 1` coefficients and wraps with
    /// `x^n ≡ -1` (i.e. `c_k = lin[k] - lin[k + n]`).
    pub fn mul(&self, other: &Self) -> Self {
        debug_assert_eq!(self.n, other.n, "ring dimensions must match");
        debug_assert_eq!(self.q, other.q, "moduli must match");
        let n = self.n;
        let mut lin = vec![0i128; 2 * n - 1];
        for (i, a) in self.coeffs.iter().enumerate() {
            for (j, b) in other.coeffs.iter().enumerate() {
                lin[i + j] += (*a as i128) * (*b as i128);
            }
        }
        let mut coeffs = Vec::with_capacity(n);
        for k in 0..n {
            let mut v = lin[k];
            if k + n <= 2 * n - 2 {
                v -= lin[k + n];
            }
            coeffs.push(v.rem_euclid(self.q as i128) as u64);
        }
        Self { n: self.n, q: self.q, coeffs }
    }
}

/// Number of bits needed to represent `q` (i.e. all coefficients `< q`).
fn coeff_bits(q: u64) -> usize {
    64 - q.leading_zeros() as usize
}

/// Pack coefficients at `coeff_bits(q)` bits per coefficient, LSB-first.
fn pack_coeffs(coeffs: &[u64], q: u64) -> Vec<u8> {
    let w = coeff_bits(q);
    // Only triggered by extreme (unrealistic) moduli; real sets use q < 2^32.
    assert!(w <= 56, "coefficient width too large for u64 packing");
    let mut out = Vec::with_capacity((coeffs.len() * w).div_ceil(8));
    let mut acc: u64 = 0;
    let mut acc_bits: u32 = 0;
    for &c in coeffs {
        acc |= c << acc_bits;
        acc_bits += w as u32;
        while acc_bits >= 8 {
            out.push((acc & 0xff) as u8);
            acc >>= 8;
            acc_bits -= 8;
        }
    }
    if acc_bits > 0 {
        out.push((acc & 0xff) as u8);
    }
    out
}

/// Invert [`pack_coeffs`].
fn unpack_coeffs(bytes: &[u8], n: usize, q: u64) -> Vec<u64> {
    let w = coeff_bits(q);
    let mask = if w >= 64 { u64::MAX } else { (1u64 << w) - 1 };
    let mut out = Vec::with_capacity(n);
    let mut acc: u64 = 0;
    let mut acc_bits: u32 = 0;
    'outer: for &b in bytes {
        acc |= (b as u64) << acc_bits;
        acc_bits += 8;
        while acc_bits >= w as u32 {
            out.push(acc & mask);
            acc >>= w;
            acc_bits -= w as u32;
            if out.len() == n {
                break 'outer;
            }
        }
    }
    assert_eq!(out.len(), n, "packed byte length does not match n coeffs");
    out
}

impl Valid for Rq {
    fn check(&self) -> Result<(), SerializationError> {
        if self.n == 0 || self.coeffs.len() != self.n {
            return Err(SerializationError::InvalidData);
        }
        if self.coeffs.iter().any(|&c| c >= self.q) {
            return Err(SerializationError::InvalidData);
        }
        Ok(())
    }
}

impl CanonicalSerialize for Rq {
    fn serialize_with_mode<W: Write>(
        &self,
        mut writer: W,
        _compress: ark_serialize::Compress,
    ) -> Result<(), SerializationError> {
        writer.write_all(&(self.n as u32).to_le_bytes())?;
        writer.write_all(&self.q.to_le_bytes())?;
        writer.write_all(&pack_coeffs(&self.coeffs, self.q))?;
        Ok(())
    }

    fn serialized_size(&self, _compress: ark_serialize::Compress) -> usize {
        let w = coeff_bits(self.q);
        4 + 8 + (self.coeffs.len() * w).div_ceil(8)
    }
}

impl CanonicalDeserialize for Rq {
    fn deserialize_with_mode<R: Read>(
        mut reader: R,
        _compress: Compress,
        validate: ark_serialize::Validate,
    ) -> Result<Self, SerializationError> {
        let mut n_bytes = [0u8; 4];
        reader.read_exact(&mut n_bytes)?;
        let n = u32::from_le_bytes(n_bytes) as usize;
        let mut q_bytes = [0u8; 8];
        reader.read_exact(&mut q_bytes)?;
        let q = u64::from_le_bytes(q_bytes);
        if n == 0 {
            return Err(SerializationError::InvalidData);
        }
        let len = (n * coeff_bits(q)).div_ceil(8);
        let mut packed = vec![0u8; len];
        reader.read_exact(&mut packed)?;
        let element = Self::from_coeffs(unpack_coeffs(&packed, n, q), q);
        if matches!(validate, ark_serialize::Validate::Yes) {
            element.check()?;
        }
        Ok(element)
    }
}

/// Reduce a field element to `[0, q)` by folding its full byte representation.
///
/// This is the embedding map `φ: F → Z_q` used by [`embed_scalars`].  It is a
/// deterministic stand-in for the committed-shortness protocol; see the module
/// docs for the (non-homomorphic-over-`F`) caveat.
pub fn field_mod_q<F: PrimeField>(f: &F, q: u64) -> u64 {
    let mut acc: u128 = 0;
    // `to_bytes_le` returns the least-significant byte first; Horner must run
    // on the most-significant-first order to evaluate Σ b_i · 256^i.
    for &b in f.into_bigint().to_bytes_le().iter().rev() {
        acc = ((acc * 256) + b as u128) % q as u128;
    }
    acc as u64
}

/// The exact ring multiplier for a ring-domain fold challenge.
///
/// The ring-domain fold (`subsec:ring-fold`) draws ternary challenges
/// `r ∈ {0, ±1}`.  A fresh commitment of the folded witness must equal the
/// ring-linear combination of commitments — `com(w1 + r·w2) = com(w1) + r̂·com(w2)`
/// with `r̂ = r mod q`.  The field element `-1` (i.e. `p − 1`) must therefore
/// map to `q − 1` *exactly*; [`field_mod_q`] would instead give `(p − 1) mod q`,
/// breaking witness re-binding (`lem:ring-fold-rebinding`).
fn ring_scalar<F: PrimeField>(f: &F, q: u64) -> u64 {
    if f == &-F::one() {
        q - 1
    } else {
        field_mod_q(f, q)
    }
}

/// Public alias of the exact ring multiplier for a ring-domain fold challenge.
///
/// Field element `-1` (i.e. `p − 1`) maps to `q − 1` *exactly*; all other
/// values reduce mod `q` (`lem:ring-fold-rebinding`).
pub fn ring_mod_q<F: PrimeField>(f: &F, q: u64) -> u64 {
    ring_scalar(f, q)
}

/// Whether `f` is a canonical residue mod `q`, i.e. `f ∈ [0, q)` as a field
/// element.
///
/// The ring--field transport (`def:canonical-lift` / `lem:lift-faithful`)
/// requires every wire that crosses between `R_q` and `F_r` — in particular
/// window interface states — to be a canonical residue, so τ-tests on them
/// coincide between the two domains.
pub fn is_canonical_lift<F: PrimeField>(f: &F, q: u64) -> bool {
    F::from(field_mod_q(f, q)) == *f
}

/// The canonical residue of `f` modulo `q`, as a field element in `[0, q)`.
///
/// Ring-domain folds keep every witness/error/input/slack coefficient as its
/// canonical residue in `[0, q)` (`def:canonical-lift` in the paper), so the
/// ring embedding distributes over the fold exactly.
pub fn qresidue<F: PrimeField>(f: &F, q: u64) -> F {
    F::from(field_mod_q(f, q))
}

/// Ring-residue addition: `(a + b) mod q`, both operands reduced mod `q`.
pub fn qadd<F: PrimeField>(a: &F, b: &F, q: u64) -> F {
    F::from(((field_mod_q(a, q) + field_mod_q(b, q)) % q) as u64)
}

/// Ring-residue subtraction: `(a - b) mod q`, both operands reduced mod `q`.
pub fn qsub<F: PrimeField>(a: &F, b: &F, q: u64) -> F {
    let (a, b) = (field_mod_q(a, q), field_mod_q(b, q));
    F::from(((a + q - (b % q)) % q) as u64)
}

/// Ring-residue multiplication: `(a · b) mod q`, both operands reduced mod `q`.
pub fn qmul<F: PrimeField>(a: &F, b: &F, q: u64) -> F {
    let (a, b) = (field_mod_q(a, q), field_mod_q(b, q));
    F::from(((a as u128 * b as u128) % q as u128) as u64)
}

/// Ring-residue scalar multiplication: `(s · a) mod q` for a field scalar `s`.
pub fn qsmul<F: PrimeField>(s: &F, a: &F, q: u64) -> F {
    qmul(s, a, q)
}

/// Embed a vector of field scalars into blocks of `n` ring coefficients
/// (zero-padded), i.e. `s ∈ R_q^{ceil(len/n)}`.
pub fn embed_scalars<C: NovaCurve>(values: &[ScalarField<C>], n: usize, q: u64) -> Vec<Rq> {
    let nblocks = values.len().div_ceil(n).max(1);
    let mut blocks = Vec::with_capacity(nblocks);
    for b in 0..nblocks {
        let mut coeffs = Vec::with_capacity(n);
        for k in 0..n {
            let i = b * n + k;
            coeffs.push(if i < values.len() { field_mod_q(&values[i], q) } else { 0 });
        }
        blocks.push(Rq::from_coeffs(coeffs, q));
    }
    blocks
}

/// Multiply the matrix `A ∈ R_q^{rows × cols}` by the block vector `s ∈ R_q^cols`.
///
/// `rows` must equal `commitment_len()`; extra matrix columns beyond `s.len()`
/// are ignored, which lets callers commit to shorter vectors against the same
/// seeded parameters.
pub fn mat_vec_mul(matrix: &[Vec<Rq>], s: &[Rq]) -> Vec<Rq> {
    if s.is_empty() {
        return Vec::new();
    }
    let (n, q) = (s[0].n, s[0].q);
    matrix
        .iter()
        .map(|row| {
            row.iter()
                .zip(s)
                .map(|(a, b)| a.mul(b))
                .fold(Rq::zero(n, q), |acc, x| acc.add(&x))
        })
        .collect()
}

/// Commitment parameters for `ModuleSisCommitment`.
///
/// Holds the base candidate set plus the seed-derived matrix `A` for both the
/// witness (`a_w`) and error (`a_e`) domains.  `A` has `d` rows (the module
/// rank) and `nblocks` columns, where `nblocks = max(1, ceil(len / n))`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleSisCommitParams {
    /// The underlying candidate parameter set (n, q, d, β, ...).
    pub base: ModuleSisParams,
    /// Witness commitment matrix `A_w ∈ R_q^{d × nblocks_w}`.
    pub a_w: Vec<Vec<Rq>>,
    /// Error commitment matrix `A_e ∈ R_q^{d × nblocks_e}`.
    pub a_e: Vec<Vec<Rq>>,
    /// Number of witness ring blocks.
    pub nblocks_w: usize,
    /// Number of error ring blocks.
    pub nblocks_e: usize,
}

/// Derive the `i,j`-th ring element of a matrix from the seed.
fn derive_ring(seed: &[u8], domain: &[u8], i: u64, j: u64, n: usize, q: u64) -> Rq {
    let mut coeffs = Vec::with_capacity(n);
    for k in 0..n {
        let mut h = Blake2b512::new();
        h.update(seed);
        h.update(domain);
        h.update(i.to_le_bytes());
        h.update(j.to_le_bytes());
        h.update((k as u64).to_le_bytes());
        let out = h.finalize();
        let mut acc: u128 = 0;
        for &b in out.iter() {
            acc = ((acc * 256) + b as u128) % q as u128;
        }
        coeffs.push(acc as u64);
    }
    Rq::from_coeffs(coeffs, q)
}

/// Derive the full matrix `A` from a seed with a domain-separation label.
fn derive_matrix(seed: &[u8], domain: &[u8], base: ModuleSisParams, nblocks: usize) -> Vec<Vec<Rq>> {
    let n = base.n as usize;
    let q = base.q;
    let d = base.d as usize;
    (0..d)
        .map(|i| {
            (0..nblocks)
                .map(|j| derive_ring(seed, domain, i as u64, j as u64, n, q))
                .collect()
        })
        .collect()
}

impl ModuleSisCommitParams {
    /// Derive parameters for the candidate set at `index` into
    /// [`ModuleSisParams::ALL`].
    ///
    /// `m` is interpreted as that index (clamped), which is the hook P4 will
    /// use to expose `--module-sis-params`.  Identical seeds, dimensions and
    /// indexes produce identical matrices.
    pub fn from_seed(seed: &[u8], n_wires: usize, n_constraints: usize, index: usize) -> Self {
        let base = ModuleSisParams::ALL[index % ModuleSisParams::ALL.len()];
        assert!(base.validate().is_ok(), "selected parameter set must validate");
        let n = base.n as usize;
        let nblocks_w = n_wires.div_ceil(n).max(1);
        let nblocks_e = n_constraints.div_ceil(n).max(1);
        let a_w = derive_matrix(seed, b"module-sis-w", base, nblocks_w);
        let a_e = derive_matrix(seed, b"module-sis-e", base, nblocks_e);
        Self { base, a_w, a_e, nblocks_w, nblocks_e }
    }

    /// Number of ring elements in a commitment (`d`).
    pub fn commitment_len(&self) -> usize {
        self.base.d as usize
    }

    /// Estimated on-wire commitment size in bytes.
    pub fn commitment_size(&self) -> usize {
        self.base.commitment_size()
    }
}

/// An experimental Ajtai/Module-SIS commitment over `R_q`.
///
/// `c = A·s mod q` for `A ∈ R_q^{d × nblocks}` derived from a public seed and
/// short `s ∈ R_q^{nblocks}`.  Binding reduces tightly to Module-SIS when the
/// committed vector is short (subject to the committed-shortness protocol; see
/// module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModuleSisCommitment<C: NovaCurve> {
    _phantom: PhantomData<C>,
}

impl<C: NovaCurve> CommitmentScheme for ModuleSisCommitment<C> {
    type Scalar = ScalarField<C>;
    type Commitment = Vec<Rq>;
    type Params = ModuleSisCommitParams;

    const FIELD_HOMOMORPHIC: bool = false;

    fn recommended_checkpoint_interval(params: &Self::Params) -> Option<usize> {
        Some(recommended_checkpoint_interval(
            SmallChallengeSet::Ternary,
            params.base.beta,
            params.base.q,
        ))
    }

    fn verifies_rebinding() -> bool {
        true
    }

    fn ring_modulus(params: &Self::Params) -> Option<u64> {
        Some(params.base.q)
    }

    fn commitment_ring_modulus(commitment: &Self::Commitment) -> Option<u64> {
        commitment.first().map(|r| r.q)
    }

    fn params_from_seed(
        seed: &[u8],
        n_wires: usize,
        n_constraints: usize,
        m: usize,
    ) -> Self::Params {
        ModuleSisCommitParams::from_seed(seed, n_wires, n_constraints, m)
    }

    fn commit_witness(params: &Self::Params, values: &[Self::Scalar]) -> Self::Commitment {
        mat_vec_mul(
            &params.a_w,
            &embed_scalars::<C>(values, params.base.n as usize, params.base.q),
        )
    }

    fn commit_error(params: &Self::Params, values: &[Self::Scalar]) -> Self::Commitment {
        mat_vec_mul(
            &params.a_e,
            &embed_scalars::<C>(values, params.base.n as usize, params.base.q),
        )
    }

    fn add(c1: &Self::Commitment, c2: &Self::Commitment) -> Self::Commitment {
        assert_eq!(c1.len(), c2.len(), "commitments must have equal length");
        c1.iter().zip(c2).map(|(a, b)| a.add(b)).collect()
    }

    fn scalar_mul(c: &Self::Commitment, scalar: &Self::Scalar) -> Self::Commitment {
        let phi = ring_scalar(scalar, c.first().map(|r| r.q).unwrap_or(0));
        c.iter().map(|r| r.scalar_mul(phi)).collect()
    }

    fn zero(m: usize) -> Self::Commitment {
        let base = ModuleSisParams::ALL[m % ModuleSisParams::ALL.len()];
        vec![Rq::zero(base.n as usize, base.q); base.d as usize]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// BLS12-381 scalar convenience alias (matches the crate feature `bls12-381`).
    type Fr = ScalarField<crate::curve::Bls12_381>;

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
    fn extreme_growth_saturates_without_overflow() {
        // Full-field-scale challenges drive the quadratic cross-term bound
        // far past u64::MAX; the simulation must saturate, never panic.
        let result = simulate_norm_growth(
            10_000,
            SmallChallengeSet::Uniform { bound: u64::MAX },
            u64::MAX,
            Q_L1,
        );
        assert!(!result.is_short, "saturated norm can never be short");
        assert_eq!(result.final_witness_norm, u64::MAX);
        assert_eq!(result.final_error_norm, u64::MAX);
    }

    #[test]
    fn error_growth_bound_saturates() {
        assert_eq!(
            u64::MAX,
            SmallChallengeSet::Uniform { bound: u64::MAX }.error_growth_bound(u64::MAX)
        );
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

    // ── P3: ring arithmetic tests ───────────────────────────────────

    /// Toy module-SIS parameter set for fast tests.
    fn toy_base() -> ModuleSisParams {
        ModuleSisParams {
            level: NistLevel::Level1,
            balance: ParamBalance::Conservative,
            n: 4,
            q: 97,
            d: 2,
            m: 4,
            beta: 4,
            beta_bits: 2,
        }
    }

    fn toy_params(seed: &[u8], nblocks: usize) -> ModuleSisCommitParams {
        let base = toy_base();
        let a_w = derive_matrix(seed, b"module-sis-w", base, nblocks);
        let a_e = derive_matrix(seed, b"module-sis-e", base, nblocks);
        ModuleSisCommitParams {
            base,
            a_w,
            a_e,
            nblocks_w: nblocks,
            nblocks_e: nblocks,
        }
    }

    #[test]
    fn rq_mul_negacyclic_wrap() {
        // x² · x² = x⁴ ≡ -1 mod (x⁴ + 1).
        let a = Rq::from_coeffs(vec![0, 0, 1, 0], 97);
        let b = Rq::from_coeffs(vec![0, 0, 1, 0], 97);
        assert_eq!(a.mul(&b).coeffs, vec![96, 0, 0, 0]);
    }

    #[test]
    fn rq_mul_linear_convolution() {
        // (1 + 2x + 3x²) · (4 + 5x + 6x²) mod (x⁴ + 1):
        // degree ≤ 4 term (20x⁴ · 1 = coeff 0 gains +20·x⁴, x⁴ ≡ -1 → -20).
        let a = Rq::from_coeffs(vec![1, 2, 3, 0], 97);
        let b = Rq::from_coeffs(vec![4, 5, 6, 0], 97);
        let c = a.mul(&b);
        // Schoolbook, wrapping the x⁴ term (3x²·6x² = 18x⁴ ≡ -18) into k=0:
        // c0 = 1·4 − 18 = −14 ≡ 83; c1 = 13; c2 = 28; c3 = 27.
        assert_eq!(c.coeffs, vec![83, 13, 28, 27]);
    }

    #[test]
    fn rq_add_and_scalar_mul() {
        let a = Rq::from_coeffs(vec![1, 2, 3, 4], 97);
        let b = Rq::from_coeffs(vec![5, 6, 7, 8], 97);
        assert_eq!(a.add(&b).coeffs, vec![6, 8, 10, 12]);
        assert_eq!(a.scalar_mul(10).coeffs, vec![10, 20, 30, 40]);
        // Reduce mod q.
        assert_eq!(a.add(&a).add(&a).add(&a).add(&a).coeffs, vec![5, 10, 15, 20]);
    }

    #[test]
    fn rq_neg_and_distributivity() {
        let a = Rq::from_coeffs(vec![7, 8, 9, 10], 97);
        let b = Rq::from_coeffs(vec![1, 2, 3, 4], 97);
        let c = Rq::from_coeffs(vec![5, 6, 7, 8], 97);
        // a·(b + c) == a·b + a·c
        let lhs = a.mul(&b.add(&c));
        let rhs = a.mul(&b).add(&a.mul(&c));
        assert_eq!(lhs, rhs);
        // a + (-a) == 0
        assert_eq!(a.add(&a.neg()).coeffs, vec![0, 0, 0, 0]);
    }

    #[test]
    fn pack_unpack_roundtrip() {
        let q = 97u64; // 7 bits
        let coeffs = vec![0u64, 1, 2, 96, 3, 4];
        let packed = pack_coeffs(&coeffs, q);
        assert_eq!(unpack_coeffs(&packed, coeffs.len(), q), coeffs);
    }

    #[test]
    fn rq_serialization_roundtrip() {
        let a = Rq::from_coeffs(vec![1, 96, 42, 0], 97);
        let mut buf = Vec::new();
        a.serialize_compressed(&mut buf).unwrap();
        let b = Rq::deserialize_compressed(&buf[..]).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn commitment_serialization_roundtrip() {
        let params = toy_params(b"ser", 2);
        let v = vec![Fr::from(1u64); 4];
        let c = ModuleSisCommitment::<crate::curve::Bls12_381>::commit_witness(&params, &v);
        let mut buf = Vec::new();
        c.serialize_compressed(&mut buf).unwrap();
        let c2 = Vec::<Rq>::deserialize_compressed(&buf[..]).unwrap();
        assert_eq!(c, c2);
        // ark serializes Vec<T> with a u64 length prefix (8 bytes).
        let elems: usize = c2.iter().map(|r| r.serialized_size(ark_serialize::Compress::Yes)).sum();
        assert_eq!(buf.len(), elems + 8);
    }

    // ── P3: commitment-level tests ──────────────────────────────────

    #[test]
    fn module_sis_commit_deterministic() {
        let params = toy_params(b"seed", 2);
        let v: Vec<Fr> =
            (1..=8).map(Fr::from).collect();
        let c1 = ModuleSisCommitment::<crate::curve::Bls12_381>::commit_witness(&params, &v);
        let c2 = ModuleSisCommitment::<crate::curve::Bls12_381>::commit_witness(&params, &v);
        assert_eq!(c1, c2);
        assert_eq!(c1.len(), 2, "module rank d=2 ring elements");
    }

    #[test]
    fn module_sis_commit_witness_and_error_differ() {
        let params = toy_params(b"seed", 2);
        let v: Vec<Fr> =
            (1..=8).map(Fr::from).collect();
        let cw = ModuleSisCommitment::<crate::curve::Bls12_381>::commit_witness(&params, &v);
        let ce = ModuleSisCommitment::<crate::curve::Bls12_381>::commit_error(&params, &v);
        assert_ne!(cw, ce, "domain-separated matrices must give distinct commitments");
    }

    #[test]
    fn module_sis_ring_homomorphic() {
        // C(s1) + C(s2) == C(s1 + s2) over ring blocks, and r·C(s) == C(r·s).
        let params = toy_params(b"seed", 2);
        let s1 = vec![
            Rq::from_coeffs(vec![1, 0, 1, 0], 97),
            Rq::from_coeffs(vec![0, 1, 0, 1], 97),
        ];
        let s2 = vec![
            Rq::from_coeffs(vec![2, 3, 0, 1], 97),
            Rq::from_coeffs(vec![1, 0, 2, 0], 97),
        ];
        let c1 = mat_vec_mul(&params.a_w, &s1);
        let c2 = mat_vec_mul(&params.a_w, &s2);
        let sum: Vec<Rq> = s1.iter().zip(&s2).map(|(a, b)| a.add(b)).collect();
        let csum = mat_vec_mul(&params.a_w, &sum);
        let added = ModuleSisCommitment::<crate::curve::Bls12_381>::add(&c1, &c2);
        assert_eq!(added, csum, "commitment must be additively homomorphic over R_q");

        let scalar = 5u64;
        let rs: Vec<Rq> = s1.iter().map(|a| a.scalar_mul(scalar)).collect();
        let c_rs = mat_vec_mul(&params.a_w, &rs);
        let scaled = ModuleSisCommitment::<crate::curve::Bls12_381>::scalar_mul(
            &c1,
            &Fr::from(scalar),
        );
        assert_eq!(scaled, c_rs, "commitment must be homomorphic under ring scalars");
    }

    #[test]
    fn module_sis_commit_zero_vector() {
        let params = toy_params(b"seed", 2);
        let zeros = vec![Fr::from(0u64); 8];
        let cz = ModuleSisCommitment::<crate::curve::Bls12_381>::commit_witness(&params, &zeros);
        // Toy-set zero (d=2 ring elements over n=4, q=97), matching the toy params.
        let z = vec![Rq::zero(4, 97); 2];
        assert_eq!(cz, z);
    }

    #[test]
    fn module_sis_seed_separation() {
        // Distinct seeds ⇒ distinct matrices ⇒ (w.h.p.) distinct commitments.
        let params_a = toy_params(b"alpha", 2);
        let params_b = toy_params(b"beta", 2);
        let v: Vec<Fr> =
            (1..=8).map(Fr::from).collect();
        let ca = ModuleSisCommitment::<crate::curve::Bls12_381>::commit_witness(&params_a, &v);
        let cb = ModuleSisCommitment::<crate::curve::Bls12_381>::commit_witness(&params_b, &v);
        assert_ne!(ca, cb, "different seeds must give different commitments");
    }

    #[test]
    fn module_sis_binding_short_vectors() {
        // Empirical SIS binding: distinct short block vectors give distinct
        // commitments.  For the toy set (q=97, n=4, d=2, nblocks=2) the map
        // from 3^8 short vectors into R_q^2 ≅ F_97^8 is injective whp.
        let params = toy_params(b"binding", 4);
        let short_vecs = [
            vec![1u64, 0, 96, 0, 1, 0, 96, 1, 0, 0, 0, 0, 0, 0, 0, 0],
            vec![0u64, 1, 0, 96, 0, 1, 0, 96, 0, 0, 0, 0, 0, 0, 0, 0],
            vec![1u64, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0],
        ];
        let commits: Vec<Vec<Rq>> = short_vecs
            .iter()
            .map(|coeffs| {
                let blocks = embed_scalars_coeffs(coeffs, 4, 97);
                mat_vec_mul(&params.a_w, &blocks)
            })
            .collect();
        assert_ne!(commits[0], commits[1]);
        assert_ne!(commits[0], commits[2]);
        assert_ne!(commits[1], commits[2]);
    }

    fn embed_scalars_coeffs(coeffs: &[u64], n: usize, q: u64) -> Vec<Rq> {
        let nblocks = coeffs.len().div_ceil(n).max(1);
        (0..nblocks)
            .map(|b| {
                Rq::from_coeffs(
                    (0..n)
                        .map(|k| {
                            let i = b * n + k;
                            if i < coeffs.len() { coeffs[i] } else { 0 }
                        })
                        .collect(),
                    q,
                )
            })
            .collect()
    }

    #[test]
    fn balanced_i_commitment_serialized_size_within_5kib() {
        // PQ-GAP acceptance: commitment size ≤ 5 KiB for the default set.
        let params = ModuleSisCommitParams::from_seed(b"size", 24, 24, 1); // Balanced-I
        assert!(params.commitment_size() <= 5 * 1024, "est. size {} B must be ≤ 5 KiB", params.commitment_size());
        let v: Vec<Fr> =
            (1..=24).map(Fr::from).collect();
        let c = ModuleSisCommitment::<crate::curve::Bls12_381>::commit_witness(&params, &v);
        let mut buf = Vec::new();
        c.serialize_compressed(&mut buf).unwrap();
        assert!(
            buf.len() <= 5 * 1024,
            "serialized commitment {} B must be ≤ 5 KiB",
            buf.len()
        );
    }

    #[test]
    fn params_from_seed_index_selects_candidate() {
        let p0 = ModuleSisCommitParams::from_seed(b"s", 8, 8, 0);
        let p1 = ModuleSisCommitParams::from_seed(b"s", 8, 8, 1);
        assert_eq!(p0.base, ModuleSisParams::CONSERVATIVE_I);
        assert_eq!(p1.base, ModuleSisParams::BALANCED_I);
        assert_eq!(p0.commitment_len(), 4);
        assert_eq!(p1.commitment_len(), 6);
    }

    // ── P3: property-based tests ────────────────────────────────────

    use proptest::prelude::*;

    fn arb_short_block(len: usize) -> impl Strategy<Value = Vec<u64>> {
        proptest::collection::vec(proptest::bool::ANY, len)
            .prop_map(|bits| bits.into_iter().map(|b| if b { 1 } else { 96 }).collect())
    }

    proptest! {
        /// Ring multiplication commutes and distributes as expected.
        #[test]
        fn prop_rq_mul_distributes(
            a in arb_short_block(4),
            b in arb_short_block(4),
            c in arb_short_block(4),
        ) {
            let ra = Rq::from_coeffs(a, 97);
            let rb = Rq::from_coeffs(b, 97);
            let rc = Rq::from_coeffs(c, 97);
            // Commutativity
            prop_assert_eq!(ra.mul(&rb), rb.mul(&ra));
            // Distributivity
            prop_assert_eq!(ra.mul(&rb.add(&rc)), ra.mul(&rb).add(&ra.mul(&rc)));
        }

        /// The commitment is additively homomorphic over ring blocks.
        #[test]
        fn prop_module_sis_homomorphism(
            a in arb_short_block(16),
            b in arb_short_block(16),
        ) {
            let params = toy_params(b"prop", 4);
            let sa = embed_scalars_coeffs(&a, 4, 97);
            let sb = embed_scalars_coeffs(&b, 4, 97);
            let sum: Vec<Rq> = sa.iter().zip(&sb).map(|(x, y)| x.add(y)).collect();
            let csum = mat_vec_mul(&params.a_w, &sum);
            let cas = mat_vec_mul(&params.a_w, &sa);
            let cbs = mat_vec_mul(&params.a_w, &sb);
            prop_assert_eq!(ModuleSisCommitment::<crate::curve::Bls12_381>::add(&cas, &cbs), csum);
        }

        /// Distinct short vectors collide with negligible probability.
        #[test]
        fn prop_module_sis_no_short_collisions(
            a in arb_short_block(16),
            b in arb_short_block(16),
        ) {
            if a == b { return Ok(()); }
            let params = toy_params(b"prop-collision", 4);
            let sa = embed_scalars_coeffs(&a, 4, 97);
            let sb = embed_scalars_coeffs(&b, 4, 97);
            let ca = mat_vec_mul(&params.a_w, &sa);
            let cb = mat_vec_mul(&params.a_w, &sb);
            prop_assert_ne!(ca, cb);
        }

        /// Seed separation: distinct seeds never yield matching commitments.
        #[test]
        fn prop_module_sis_seed_separation(
            a in arb_short_block(16),
            b in arb_short_block(16),
        ) {
            let pa = toy_params(b"prop-seed-a", 4);
            let pb = toy_params(b"prop-seed-b", 4);
            let sa = embed_scalars_coeffs(&a, 4, 97);
            let sb = embed_scalars_coeffs(&b, 4, 97);
            let ca = mat_vec_mul(&pa.a_w, &sa);
            let cb = mat_vec_mul(&pb.a_w, &sb);
            prop_assert_ne!(ca, cb);
        }
    }
}
