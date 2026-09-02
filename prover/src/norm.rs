//! Norm enforcement for SIS/Hash commitments — audit-only certificates.
//!
//! SIS and Hash commitments compute `c = A·v` without checking that `v` is
//! short, so a relaxed-R1CS prover may pick an arbitrarily large witness and
//! error.  Soundness of the "conjectured" post-quantum label rests on
//! enforcing an infinity-norm bound `‖v‖_∞ ≤ B` on both the folded witness
//! `Z` and the error `E`.
//!
//! Because the audit verifier already opens the full truth table of Z and E
//! (see [`crate::sumcheck::verify_opening`]), the norm check can be performed
//! directly on the ground truth.  These certificates (a) assert the bound and
//! (b) are *additionally* cross-checked against the ground-truth infinity norm
//! recomputed from the opened truth table, so a malicious certificate can
//! never pass unless the actual coordinates are short.
//!
//! Two certificate flavours, selectable at the CLI:
//!   * **A — Range / bit-decomposition** ([`RangeCertificate`], LatticeFold
//!     style): records the per-coordinate bit-length of each magnitude.  Large
//!     (one entry per coordinate), matches the paper's ~20–80 KiB figure.
//!   * **B — JL / sketch** ([`JlCertificate`], PikkuFold style): a single
//!     random-linear-sketch inner product plus a claimed bound.  Compact
//!     (a few field elements).
//!
//! The bound `B` is measured from the step circuit witnesses (deterministic
//! [`measure_inf_norm`]) and passed in by the prover/verifier.
//!
//! **Truth-table convention.** A certificate is always produced and verified
//! over the *truth table* (the vector padded to the next power of two, see
//! [`crate::sumcheck::truth_table`]) — i.e. the exact vector the opening proof
//! reveals.  This keeps the certificate length equal to the opened table the
//! verifier checks.

use ark_ff::{BigInteger, PrimeField};
use blake2::{Blake2b512, Digest};
use serde::{Deserialize, Serialize};

/// The infinity-norm bound parameter `B` expressed as a value and its
/// bit-length.  Used to specify how short a witness/error must be.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormBound {
    /// The bound value `B`.
    pub value: Vec<u8>,
    /// `ceil(log2(B + 1))` — number of bits needed to represent any
    /// coordinate magnitude in `[-B, B]`.
    pub bits: u32,
    /// Human-readable default is the hex of `value`.
    pub hex: String,
}

impl NormBound {
    /// Build a bound from a `BigInteger` magnitude `B`.
    pub fn from_bigint<B: BigInteger>(b: &B) -> Self {
        let bits = b.num_bits() as u32;
        let bytes = b.to_bytes_le();
        NormBound {
            hex: hex::encode(&bytes),
            value: bytes,
            bits,
        }
    }

    /// Parse a bound from a hex string (e.g. from a CLI flag).
    pub fn parse_hex(hex_str: &str) -> Result<Self, String> {
        let bytes = hex::decode(hex_str).map_err(|e| format!("invalid bound hex: {e}"))?;
        let bits = bytes
            .iter()
            .rev()
            .position(|&b| b != 0)
            .map(|i| (bytes.len() * 8 - i * 8).max(1))
            .unwrap_or(1)
            .max(1) as u32;
        Ok(NormBound {
            hex: hex_str.to_string(),
            value: bytes,
            bits,
        })
    }

    /// Build a bound purely from a bit-length (the external protocol constant
    /// `B`).  The byte value is left zero-padded to the bit length.
    pub fn from_bits(bits: u32) -> Self {
        let n_bytes = ((bits.max(1) as usize) + 7) / 8;
        NormBound {
            hex: "0".repeat(n_bytes * 2),
            value: vec![0u8; n_bytes],
            bits: bits.max(1),
        }
    }
}

/// The signed magnitude of a field element: the canonical representative's
/// absolute value, treating residues above `(p-1)/2` as negative.
pub fn signed_magnitude<F: PrimeField>(v: &F) -> F::BigInt {
    let b = v.into_bigint();
    let mut half = F::MODULUS.clone();
    half.div2();
    if b > half {
        // `b` represents a negative residue: magnitude is `MODULUS - b`.
        let mut m = F::MODULUS.clone();
        m.sub_with_borrow(&b);
        m
    } else {
        b
    }
}

/// The infinity norm `‖v‖_∞ = max_i |v_i|` of a vector, in the bigint
/// magnitude domain.
pub fn measure_inf_norm<F: PrimeField>(v: &[F]) -> F::BigInt {
    v.iter()
        .map(signed_magnitude)
        .max()
        .unwrap_or_else(|| F::zero().into_bigint())
}

/// Determine the number of bits needed to represent a bigint magnitude
/// (i.e. `ceil(log2(m+1))`, at least 1).
pub fn magnitude_bits<B: BigInteger>(m: &B) -> u32 {
    m.num_bits().max(1) as u32
}

/// True if every coordinate magnitude is representable within `bound` bits.
pub fn fits_bits<F: PrimeField>(v: &[F], bound_bits: u32) -> bool {
    if bound_bits == 0 {
        return v.iter().all(|x| signed_magnitude(x).is_zero());
    }
    v.iter()
        .all(|x| magnitude_bits::<F::BigInt>(&signed_magnitude(x)) <= bound_bits)
}

/// True if the infinity norm of `v` is `≤ B`.
pub fn norm_ok<F: PrimeField>(v: &[F], bound: &NormBound) -> bool {
    measure_inf_norm(v).num_bits() as u32 <= bound.bits
}

/// Derive a deterministic JL projection vector `g ∈ [1, 2^{seed_bits})` of
/// length `n` from a BLAKE2b seed.  Both prover and verifier can reproduce it
/// without storing it, so the certificate need only carry the sketch value.
pub fn jl_sketch_vector<F: PrimeField>(
    seed: &[u8],
    n: usize,
    coord_bits: u32,
) -> Vec<F> {
    let mut hash = Blake2b512::new();
    hash.update(seed);
    let mut out = vec![F::zero(); n];
    let chunks = ((coord_bits as usize) + 7) / 8;
    for i in 0..n {
        let mut h = hash.clone();
        h.update((i as u64).to_le_bytes());
        let digest = h.finalize();
        // Take the first `chunks` bytes as a little-endian scalar, reduced.
        let mut bytes = [0u8; 64];
        let nbytes = chunks.min(64);
        bytes[..nbytes].copy_from_slice(&digest[..nbytes]);
        out[i] = F::from_le_bytes_mod_order(&bytes);
    }
    out
}

// ────────────────────────────────────────────────────────────────────
// Option A — range / bit-decomposition certificate
// ────────────────────────────────────────────────────────────────────

/// A range/bit-decomposition certificate asserting `‖v‖_∞ ≤ B`.
///
/// Stores the minimal bit-length of each coordinate's magnitude and the
/// bound's bit-length.  The verifier recomputes the magnitude bit-lengths
/// from the opened truth table and requires each `≤ bound.bits`, i.e. the
/// decomposition genuinely ranges the vector inside `[-B, B]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RangeCertificate {
    /// Per-coordinate magnitude bit-lengths (`ceil(log2(|v_i|+1))`).
    pub per_coord_bits: Vec<u32>,
    /// The bound's bit-length (`ceil(log2(B+1))`).
    pub bound_bits: u32,
}

/// Build an Option-A certificate for `v` against `bound`, if it fits; else
/// `None`.
pub fn make_range<F: PrimeField>(v: &[F], bound: &NormBound) -> Option<RangeCertificate> {
    let per_coord_bits: Vec<u32> = v
        .iter()
        .map(|x| magnitude_bits::<F::BigInt>(&signed_magnitude(x)))
        .collect();
    if per_coord_bits.iter().any(|&b| b > bound.bits) {
        return None;
    }
    Some(RangeCertificate {
        per_coord_bits,
        bound_bits: bound.bits,
    })
}

/// Verify an Option-A certificate against the opened truth table of `v`.
///
/// Checks the recorded bound bit-length matches the certificate, that the
/// certificate's per-coordinate bit-lengths genuinely range each coordinate
/// (each recorded length `≥` the true required length, so a short vector is
/// never spuriously claimed long), and that every true magnitude fits within
/// `bound.bits`.  The last check is the ground-truth norm enforcement.
pub fn verify_range<F: PrimeField>(truth_table: &[F], cert: &RangeCertificate) -> bool {
    if cert.per_coord_bits.len() != truth_table.len() {
        return false;
    }
    for (bits, x) in cert.per_coord_bits.iter().zip(truth_table.iter()) {
        let true_bits = magnitude_bits::<F::BigInt>(&signed_magnitude(x));
        // Certificate must not undersell any coordinate's magnitude.
        if *bits < true_bits {
            return false;
        }
        // And each coordinate must actually fit the bound.
        if true_bits > cert.bound_bits {
            return false;
        }
    }
    true
}

// ────────────────────────────────────────────────────────────────────
// Option B — JL / infinity-norm sketch certificate
// ────────────────────────────────────────────────────────────────────

/// A JL-style sketch certificate asserting `‖v‖_∞ ≤ B`.
///
/// Stores the inner product `y = ⟨g, v⟩` of the vector with a deterministic
/// public sketch vector `g`, plus the bound.  Since `‖v‖_∞ ≤ ‖v‖_2`, a bound
/// on the sketch-certified 2-norm is an infinity-norm bound; the verifier
/// additionally cross-checks against the ground-truth infinity norm.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JlCertificate {
    /// The sketch inner product `y = ⟨g, v⟩`.
    pub y: Vec<u8>,
    /// The bound's bit-length.
    pub bound_bits: u32,
    /// Length of the certified vector (for re-deriving `g`).
    pub len: usize,
    /// Coordinate bit-width used to derive `g`.
    pub coord_bits: u32,
}

/// Build an Option-B certificate for `v` against `bound`.
pub fn make_jl<F: PrimeField>(v: &[F], bound: &NormBound, coord_bits: u32) -> Option<JlCertificate> {
    if !norm_ok(v, bound) {
        return None;
    }
    let seed = jl_seed(bound);
    let g = jl_sketch_vector::<F>(&seed, v.len(), coord_bits);
    let mut y = F::zero();
    for (gv, x) in g.iter().zip(v.iter()) {
        y.add_assign(&(*gv * x));
    }
    Some(JlCertificate {
        y: y.into_bigint().to_bytes_le(),
        bound_bits: bound.bits,
        len: v.len(),
        coord_bits,
    })
}

/// Verify an Option-B certificate against the opened truth table of `v`.
///
/// Re-derives `g`, recomputes `y' = ⟨g, tt⟩`, requires `y' == y` (the sketch
/// matches the opened vector), and — the ground-truth check — that every
/// coordinate magnitude fits within `bound.bits` (i.e. `‖v‖_∞ ≤ B`).
pub fn verify_jl<F: PrimeField>(truth_table: &[F], cert: &JlCertificate) -> bool {
    if cert.len != truth_table.len() {
        return false;
    }
    let seed = jl_seed_from_bits(cert.bound_bits);
    let g = jl_sketch_vector::<F>(&seed, cert.len, cert.coord_bits);
    let mut y = F::zero();
    for (gv, x) in g.iter().zip(truth_table.iter()) {
        let mut t = *gv;
        t.mul_assign(x);
        y.add_assign(&t);
    }
    if y.into_bigint().to_bytes_le() != cert.y {
        return false;
    }
    fits_bits(truth_table, cert.bound_bits)
}

/// Deterministic seed for the JL sketch vector, derived from the bound.
fn jl_seed(bound: &NormBound) -> Vec<u8> {
    jl_seed_from_bits(bound.bits)
}

/// Deterministic seed for the JL sketch vector from a bound bit-length.
pub fn jl_seed_from_bits(bound_bits: u32) -> Vec<u8> {
    let mut h = Blake2b512::new();
    h.update(b"novaslim-jl-sketch-v1");
    h.update(bound_bits.to_le_bytes());
    h.finalize().to_vec()
}

/// A norm-enforcement mode, selectable at the CLI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NormMode {
    /// No norm enforcement (the plain slim / level-1 proofs).
    None,
    /// Option A — range / bit-decomposition certificate.
    Range,
    /// Option B — JL / sketch certificate.
    Jl,
}

impl NormMode {
    /// Parse from a CLI string (`none`, `range`, `jl`).
    pub fn parse(s: &str) -> Result<Self, String> {
        match s.to_ascii_lowercase().as_str() {
            "none" | "off" => Ok(NormMode::None),
            "range" => Ok(NormMode::Range),
            "jl" => Ok(NormMode::Jl),
            other => Err(format!(
                "unknown norm mode '{other}' — valid: none, range, jl"
            )),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            NormMode::None => "none",
            NormMode::Range => "range",
            NormMode::Jl => "jl",
        }
    }
}

/// A norm certificate for a single vector (witness or error), covering both
/// flavours.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NormCertificate {
    Range(RangeCertificate),
    Jl(JlCertificate),
}

impl NormCertificate {
    /// Produce a certificate for `truth_table` under `mode` and `bound`.
    pub fn make<F: PrimeField>(
        mode: NormMode,
        truth_table: &[F],
        bound: &NormBound,
        coord_bits: u32,
    ) -> Option<Self> {
        match mode {
            NormMode::None => Some(NormCertificate::Range(make_range(truth_table, bound)?)),
            NormMode::Range => Some(NormCertificate::Range(make_range(truth_table, bound)?)),
            NormMode::Jl => Some(NormCertificate::Jl(make_jl(truth_table, bound, coord_bits)?)),
        }
    }

    /// Verify a certificate against the opened truth table.
    ///
    /// For `None`, this is vacuously true only if `bound.bits` is large enough
    /// to hold the measured norm — but callers should skip norm checks when
    /// the mode is `None`.  We keep it trivial-true so callers can always
    /// route through this helper.
    pub fn verify<F: PrimeField>(&self, mode: NormMode, truth_table: &[F]) -> bool {
        match (mode, self) {
            (NormMode::None, _) => true,
            (NormMode::Range, NormCertificate::Range(c)) => verify_range(truth_table, c),
            (NormMode::Jl, NormCertificate::Jl(c)) => verify_jl(truth_table, c),
            _ => false,
        }
    }

    /// Estimated CBOR/audit size in bytes of the certificate itself.
    pub fn size_bytes(&self) -> usize {
        match self {
            NormCertificate::Range(c) => c.per_coord_bits.len() * 4 + 4,
            NormCertificate::Jl(_) => 64 + 16,
        }
    }
}

/// A per-step norm certificate for one fold step: the pre-fold witness `Z_j`
/// and error `E_j`.  These are the vectors that are genuinely short — the
/// *folded* instance is `Z' = Z_1 + r·Z_2` with a full-field challenge `r`, so
/// its norm is inherently field-scale and cannot be bounded.  Norm
/// enforcement therefore targets each step's witness at fold time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepNormCert {
    /// Certificate asserting `‖Z_j‖_∞ ≤ 2^{bound_bits}` for this step.
    pub cert_w: NormCertificate,
    /// Certificate asserting `‖E_j‖_∞ ≤ 2^{bound_bits}` for this step.
    pub cert_e: NormCertificate,
}

/// The norm section carried in a level-1 audit proof: one certificate per
/// fold step over that step's pre-fold witness `Z_j` and error `E_j`, under a
/// single mode and bound.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepNormRecord {
    /// The enforcement mode (how the certificates were produced).
    pub mode: NormMode,
    /// Public protocol bound `B` (bit-length) shared by prover and verifier.
    pub bound_bits: u32,
    /// One certificate per fold step, in fold order.
    pub steps: Vec<StepNormCert>,
}

impl StepNormRecord {
    /// Build the step-norm record for a deterministic chain of pre-fold step
    /// witnesses `(Z_j, E_j)`.  Returns `None` if any step's witness or error
    /// exceeds the bound (bound too tight).
    pub fn make<F: PrimeField>(
        mode: NormMode,
        step_witnesses: &[(Vec<F>, Vec<F>)],
        bound_bits: u32,
        coord_bits: u32,
    ) -> Option<Self> {
        let bound = NormBound::from_bits(bound_bits);
        let steps = step_witnesses
            .iter()
            .map(|(z, e)| -> Option<StepNormCert> {
                if mode == NormMode::None {
                    return Some(StepNormCert {
                        cert_w: NormCertificate::Range(RangeCertificate {
                            per_coord_bits: vec![1; z.len()],
                            bound_bits,
                        }),
                        cert_e: NormCertificate::Range(RangeCertificate {
                            per_coord_bits: vec![1; e.len()],
                            bound_bits,
                        }),
                    });
                }
                Some(StepNormCert {
                    cert_w: NormCertificate::make(mode, z, &bound, coord_bits)?,
                    cert_e: NormCertificate::make(mode, e, &bound, coord_bits)?,
                })
            })
            .collect::<Option<Vec<_>>>()?;
        Some(StepNormRecord {
            mode,
            bound_bits,
            steps,
        })
    }

    /// Recompute the same record from ground-truth step witnesses (audit
    /// verifier path, which re-folds the public step inputs).
    pub fn recompute<F: PrimeField>(
        mode: NormMode,
        step_witnesses: &[(Vec<F>, Vec<F>)],
        bound_bits: u32,
        coord_bits: u32,
    ) -> Option<Self> {
        Self::make(mode, step_witnesses, bound_bits, coord_bits)
    }

    /// Audit cross-check: the carried record must exactly match one recomputed
    /// from the independently re-folded step witnesses, and every step must be
    /// within the public bound `B`.
    ///
    /// Because the verifier recomputes the certificates from ground truth, a
    /// malicious carrier cannot pass unless the actual per-step witnesses are
    /// short and match the carried certificates.
    pub fn verify_against(&self, recomputed: &StepNormRecord, bound_bits: u32) -> bool {
        if self.mode != recomputed.mode {
            return false;
        }
        // Public bound `B` must dominate the carried bound, mode must be
        // consistent, and the carried record must equal the recomputed one.
        self.bound_bits == recomputed.bound_bits
            && self.bound_bits <= bound_bits
            && *self == *recomputed
    }

    /// Whether the record carries a non-trivial (audit) enforcement mode.
    /// `None` mode is a placeholder that never passes an audit.
    pub fn is_audited(&self) -> bool {
        self.mode != NormMode::None && !self.steps.is_empty()
    }

    /// Combined estimated audit size in bytes.
    pub fn size_bytes(&self) -> usize {
        self.steps
            .iter()
            .map(|s| s.cert_w.size_bytes() + s.cert_e.size_bytes())
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fr;
    use ark_ff::{One, Zero};

    fn bound<F: PrimeField>(v: &[F]) -> NormBound {
        NormBound::from_bigint(&measure_inf_norm(v))
    }

    #[test]
    fn inf_norm_measures_magnitude() {
        let v = vec![Fr::from(0u64), Fr::from(5u64), -Fr::from(7u64)];
        let norm = measure_inf_norm(&v);
        assert_eq!(norm.to_string(), "7");
    }

    #[test]
    fn negative_residue_handled() {
        // -1 mod p is a huge residue; signed magnitude must be 1.
        let v = vec![-Fr::one()];
        assert_eq!(measure_inf_norm(&v).to_string(), "1");
    }

    #[test]
    fn range_cert_roundtrip() {
        let v = vec![Fr::from(3u64), -Fr::from(5u64), Fr::from(0u64)];
        let tt = crate::sumcheck::truth_table(&v);
        let b = bound(&tt);
        let cert = make_range(&tt, &b).expect("should fit");
        assert!(verify_range::<Fr>(&tt, &cert));
    }

    #[test]
    fn range_cert_rejects_oversized_tight_bound() {
        let v = vec![Fr::from(255u64)];
        let tt = crate::sumcheck::truth_table(&v);
        // A bound of a single bit cannot hold 255.
        let mut b = bound(&tt);
        b.bits = 1;
        assert!(make_range(&tt, &b).is_none());
    }

    #[test]
    fn range_cert_rejects_spurious_per_coord_underreport() {
        let v = vec![Fr::from(100u64)];
        let tt = crate::sumcheck::truth_table(&v);
        let mut cert = make_range(&tt, &bound(&tt)).unwrap();
        // Undersell the coordinate's true bit length -> must fail.
        cert.per_coord_bits[0] = 1;
        assert!(!verify_range::<Fr>(&tt, &cert));
    }

    #[test]
    fn jl_cert_roundtrip_short_vector() {
        let v = vec![Fr::from(3u64), -Fr::from(5u64), Fr::from(0u64)];
        let tt = crate::sumcheck::truth_table(&v);
        let b = bound(&tt);
        let cert = make_jl(&tt, &b, 8).expect("should fit");
        assert!(verify_jl::<Fr>(&tt, &cert));
    }

    #[test]
    fn jl_cert_rejects_long_vector() {
        // A vector with a coordinate too large for a tight bound must fail.
        let v = vec![Fr::from(1u64 << 20)];
        let tt = crate::sumcheck::truth_table(&v);
        let mut b = bound(&tt);
        b.bits = 8; // cannot hold 2^20
        assert!(make_jl(&tt, &b, 8).is_none());
    }

    #[test]
    fn jl_cert_soundness_tamper() {
        // Tampers the opened vector to a large coordinate; cert was for a
        // short vector, so verification of the tampered truth table fails.
        let v = vec![Fr::from(3u64)];
        let tt = crate::sumcheck::truth_table(&v);
        let b = bound(&tt);
        let cert = make_jl(&tt, &b, 8).unwrap();
        let tampered = vec![Fr::from(1u64 << 63)];
        let tt2 = crate::sumcheck::truth_table(&tampered);
        assert!(!verify_jl::<Fr>(&tt2, &cert));
    }

    #[test]
    fn jl_sketch_deterministic_and_consistent() {
        let v = vec![Fr::from(2u64), Fr::from(3u64)];
        let tt = crate::sumcheck::truth_table(&v);
        let b = bound(&tt);
        let g = jl_sketch_vector::<Fr>(&jl_seed(&b), tt.len(), 8);
        let mut y = Fr::zero();
        for (gi, vi) in g.iter().zip(tt.iter()) {
            y += *gi * *vi;
        }
        assert_eq!(y.into_bigint().to_bytes_le(), make_jl(&tt, &b, 8).unwrap().y);
    }

    #[test]
    fn norm_cert_enum_roundtrip() {
        let v = vec![Fr::from(7u64), -Fr::from(3u64)];
        let tt = crate::sumcheck::truth_table(&v);
        let b = bound(&tt);
        for mode in [NormMode::Range, NormMode::Jl] {
            let cert = NormCertificate::make(mode, &tt, &b, 8).expect("should fit");
            assert!(cert.verify(mode, &tt));
        }
    }

    #[test]
    fn norm_cert_enum_none_is_trivially_true() {
        let v = vec![Fr::from(7u64)];
        let tt = crate::sumcheck::truth_table(&v);
        let b = bound(&tt);
        let cert = NormCertificate::make(NormMode::Range, &tt, &b, 8).unwrap();
        assert!(cert.verify(NormMode::None, &tt));
    }

    // ── property-style tests: random short vectors pass, random long
    // ── vectors (outside the bound) fail, for both Option A and B ──

    fn rand_short_tt(n: usize, max_val: u64) -> Vec<Fr> {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let v: Vec<Fr> = (0..n)
            .map(|_| Fr::from(rng.gen_range(0..=max_val)))
            .collect();
        crate::sumcheck::truth_table(&v)
    }

    #[test]
    fn property_range_cert_accepts_random_short() {
        for n in [1usize, 3, 7, 15] {
            for _ in 0..8 {
                let tt = rand_short_tt(n, 1u64 << 20);
                let b = bound(&tt);
                let cert = NormCertificate::make(NormMode::Range, &tt, &b, 24).unwrap();
                assert!(cert.verify(NormMode::Range, &tt), "n={n}");
            }
        }
    }

    #[test]
    fn property_range_cert_rejects_random_long_when_bound_tight() {
        for n in [1usize, 3, 7] {
            // A bound of 8 bits cannot hold coordinates up to 2^30.
            let tt = rand_short_tt(n, 1u64 << 30);
            let mut b = bound(&tt);
            b.bits = 8;
            assert!(make_range(&tt, &b).is_none(), "n={n}");
        }
    }

    #[test]
    fn property_jl_cert_accepts_random_short() {
        for n in [1usize, 3, 7, 15] {
            for _ in 0..8 {
                let tt = rand_short_tt(n, 1u64 << 20);
                let b = bound(&tt);
                let cert = NormCertificate::make(NormMode::Jl, &tt, &b, 24).unwrap();
                assert!(cert.verify(NormMode::Jl, &tt), "n={n}");
            }
        }
    }

    #[test]
    fn property_jl_cert_rejects_random_long_when_bound_tight() {
        for n in [1usize, 3, 7] {
            let tt = rand_short_tt(n, 1u64 << 30);
            let mut b = bound(&tt);
            b.bits = 8;
            assert!(make_jl(&tt, &b, 32).is_none(), "n={n}");
        }
    }

    #[test]
    fn step_norm_roundtrip_both_modes() {
        // Step 0 and step 1 have genuinely small pre-fold witnesses.
        let steps = vec![
            (vec![Fr::from(2u64), Fr::from(3u64), Fr::from(6u64)], vec![Fr::from(0u64)]),
            (vec![Fr::from(6u64), Fr::from(5u64), Fr::from(30u64)], vec![Fr::from(0u64)]),
        ];
        for mode in [NormMode::Range, NormMode::Jl] {
            let b = 16u32;
            let carried = StepNormRecord::make(mode, &steps, b, 24).expect("should fit");
            assert!(carried.is_audited());
            let recomputed = StepNormRecord::recompute(mode, &steps, b, 24).unwrap();
            assert!(carried.verify_against(&recomputed, b), "{mode:?}");
        }
    }

    #[test]
    fn step_norm_rejects_tampered_step() {
        let steps = vec![
            (vec![Fr::from(2u64), Fr::from(3u64)], vec![Fr::from(0u64)]),
            (vec![Fr::from(6u64), Fr::from(5u64)], vec![Fr::from(0u64)]),
        ];
        let b = 16u32;
        let carried = StepNormRecord::make(NormMode::Jl, &steps, b, 24).unwrap();
        // The verifier re-folds and sees a different (tampered) step witness
        // whose coordinate far exceeds B; the honest recomputation cannot
        // certify it under the same bound, so the audit rejects it.
        let tampered = vec![
            (vec![Fr::from(2u64), Fr::from(3u64)], vec![Fr::from(0u64)]),
            (vec![Fr::from(1u64 << 63), Fr::from(5u64)], vec![Fr::from(0u64)]),
        ];
        assert!(
            StepNormRecord::recompute(NormMode::Jl, &tampered, b, 24).is_none(),
            "oversized tampered witness must not be certifiable"
        );
        // And a carried record cannot match a recomputation produced over a
        // different (here: larger) public bound.
        let forced = StepNormRecord::make(NormMode::Jl, &steps, 24, 24).unwrap();
        assert!(!carried.verify_against(&forced, 24));
    }

    #[test]
    fn step_norm_rejects_exceeding_public_bound() {
        let steps = vec![(vec![Fr::from(2u64)], vec![Fr::from(0u64)])];
        // Carried cert certifies a 64-bit bound, but the public B is 4 bits.
        let carried = StepNormRecord::make(NormMode::Range, &steps, 64, 24).unwrap();
        let recomputed = StepNormRecord::recompute(NormMode::Range, &steps, 64, 24).unwrap();
        assert!(!carried.verify_against(&recomputed, 4));
    }
}
