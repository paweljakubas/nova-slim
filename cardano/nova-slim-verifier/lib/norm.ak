//// NovaSlim — on-chain norm-certificate verification.
////
//// SIS and Hash commitments are only post-quantum sound if the committed
//// witness/error is *short* (low infinity-norm).  The Rust prover enforces
//// this off-chain with per-step certificates (Option A range / Option B JL,
//// see `prover/src/norm.rs`):
////   * **A — Range / bit-decomposition** ([`RangeCertificate`]): one
////     per-coordinate bit-length plus a bound bit-length.
////   * **B — JL / sketch** ([`JlCertificate`]): a random-linear-sketch inner
////     product plus a claimed bound, seed, and length.
////
//// **On-chain scope (certificate-consistency model).** The on-chain verifier
//// deliberately carries *no* full per-step witness vectors — that is what keeps
//// the redeemer slim (see `README.md`, "On-chain norm verifier plan").  It
//// therefore checks that a carried norm record is *structurally consistent*:
//// every mode/bound/bit-width field is a valid level within protocol caps, and
//// every certificate's per-coordinate claims are internally coherent (each
//// claimed bit-length within the recorded bound).  It does **not** recompute
//// the ground-truth infinity norm — that requires the per-step witnesses and is
//// done off-chain by the Rust `verify_level1_norm` audit verifier.

use aiken/collection/list
use aiken/primitive/bytearray

/// Protocol cap on `bound_bits` (BLS12-381 scalar is 255 bits; a bound must be
/// strictly below a field element, so ≤ 254).
const max_bound_bits = 254

/// Protocol cap on the coordinate bit-width used to derive the JL sketch.
const max_coord_bits = 255

/// ---------------------------------------------------------------------------
/// Types (mirror `prover/src/norm.rs`)
/// ---------------------------------------------------------------------------

/// The norm-enforcement mode.  Constructor names are prefixed to avoid clashes
/// in the module namespace.
pub type NormMode {
  NormNone
  NormRange
  NormJl
}

/// Option A — range / bit-decomposition certificate: per-coordinate magnitude
/// bit-lengths and the public bound's bit-length.
pub type RangeCertificate {
  per_coord_bits: List<Int>,
  bound_bits: Int,
}

/// Option B — JL / sketch certificate: sketch inner product `y`, the public
/// bound's bit-length, the vector length, and the coordinate bit-width used to
/// derive the deterministic sketch vector `g`.
pub type JlCertificate {
  y: ByteArray,
  bound_bits: Int,
  len: Int,
  coord_bits: Int,
}

/// A single certificate over a witness or error vector.
pub type NormCertificate {
  RangeCert(RangeCertificate)
  JlCert(JlCertificate)
}

/// A per-step norm certificate: one for the pre-fold witness `Z_j` and one for
/// the pre-fold error `E_j`.
pub type StepNormCert {
  cert_w: NormCertificate,
  cert_e: NormCertificate,
}

/// The norm record carried with a level-1 proof: a mode, a public bound, and
/// one certificate per fold step.
pub type NormRecord {
  mode: NormMode,
  bound_bits: Int,
  steps: List<StepNormCert>,
}

/// ---------------------------------------------------------------------------
/// Verification
/// ---------------------------------------------------------------------------

/// A valid public bound bit-length: at least 1 and within the protocol cap.
fn valid_bound(bound_bits: Int) -> Bool {
  bound_bits >= 1 && bound_bits <= max_bound_bits
}

/// A valid non-trivial mode (audit modes only; `NormNone` never passes).
fn valid_mode(mode: NormMode) -> Bool {
  when mode is {
    NormNone -> False
    NormRange -> True
    NormJl -> True
  }
}

/// A single per-coordinate claimed bit-length is sound if it is a positive
/// length that does not exceed the certificate's bound.
fn valid_coord_bits(bits: Int, bound_bits: Int) -> Bool {
  bits >= 1 && bits <= bound_bits
}

/// Verify an Option A (range) certificate structure: it must witness at least
/// one coordinate, every claimed per-coordinate bit-length must be within the
/// recorded bound, and the bound itself must be protocol-valid.
pub fn verify_range_cert(cert: RangeCertificate) -> Bool {
  valid_bound(cert.bound_bits)
    && !list.is_empty(cert.per_coord_bits)
    && list.all(
      cert.per_coord_bits,
      fn(bits) {
        valid_coord_bits(bits, cert.bound_bits)
      },
    )
}

/// Verify an Option B (JL) certificate structure: a non-empty sketch, a
/// positive vector length, and protocol-valid bound/coordinate bit-widths.
pub fn verify_jl_cert(cert: JlCertificate) -> Bool {
  valid_bound(cert.bound_bits)
    && cert.coord_bits >= 1
    && cert.coord_bits <= max_coord_bits
    && cert.len >= 1
    && bytearray.length(cert.y) > 0
    && bytearray.length(cert.y) <= 64
}

/// Verify a single certificate of either flavour.
pub fn verify_cert(cert: NormCertificate) -> Bool {
  when cert is {
    RangeCert(range_cert) -> verify_range_cert(range_cert)
    JlCert(jl_cert) -> verify_jl_cert(jl_cert)
  }
}

/// Verify one fold step's pair of certificates (witness + error).
pub fn verify_step_norm(step: StepNormCert) -> Bool {
  verify_cert(step.cert_w) && verify_cert(step.cert_e)
}

/// Verify the whole carried norm record: a real audit mode, a valid public
/// bound, at least one step, and every step's certificates structurally sound.
pub fn verify_norm(norm: NormRecord) -> Bool {
  valid_mode(norm.mode)
    && valid_bound(norm.bound_bits)
    && !list.is_empty(norm.steps)
    && list.all(norm.steps, verify_step_norm)
}

/// True when the record carries a real (audit) enforcement mode with at least
/// one step — the on-chain analogue of `StepNormRecord::is_audited`.
pub fn norm_is_audited(norm: NormRecord) -> Bool {
  valid_mode(norm.mode) && !list.is_empty(norm.steps)
}