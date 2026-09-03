use aiken/builtin
use aiken/fuzz
use norm.{
  JlCertificate, NormCertificate, NormMode, NormRecord, RangeCertificate,
  StepNormCert, verify_cert, verify_jl_cert, verify_norm, verify_range_cert,
  verify_step_norm,
}
use verifier.{
  NifsBundle, RoundPoly, SlimProof, derive_challenges, verify_slim,
  verify_slim_with_norm,
}

/// Field prime, mirrored from verifier.ak so well-formed test transcripts are
/// built with the same modular arithmetic the validator enforces.
const field_prime =
  52435875175126190479447740508185965837690552500527637822603658699938581184513

/// Modular arithmetic helpers, mirroring verifier.ak.
fn add_mod(a: Int, b: Int) -> Int {
  builtin.mod_integer(a + b, field_prime)
}

fn mul_mod(a: Int, b: Int) -> Int {
  builtin.mod_integer(a * b, field_prime)
}

fn neg_mod(a: Int) -> Int {
  builtin.mod_integer(-a, field_prime)
}

fn sub_mod(a: Int, b: Int) -> Int {
  builtin.mod_integer(a - b, field_prime)
}

fn inv2() -> Int {
  // (field_prime + 1) / 2  =  2^{-1} mod field_prime
  26217937587563095239723870254092982918845276250268918911301829349969290592257
}

/// Degree-2 polynomial evaluation, mirroring verifier.ak's eval_poly.
fn eval_poly_mod(c0: Int, c1: Int, c2: Int, x: Int) -> Int {
  let t0 = mul_mod(add_mod(x, neg_mod(1)), add_mod(x, neg_mod(2)))
  let term0 = mul_mod(c0, mul_mod(t0, inv2()))

  let t1 = mul_mod(x, add_mod(add_mod(1, 1), neg_mod(x)))
  let term1 = mul_mod(c1, t1)

  let t2 = mul_mod(x, add_mod(x, neg_mod(1)))
  let term2 = mul_mod(c2, mul_mod(t2, inv2()))

  add_mod(term0, add_mod(term1, term2))
}

/// A minimal NIFS bundle used throughout the tests.
fn test_bundle() -> NifsBundle {
  NifsBundle {
    com_w_hash: #"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    com_e_hash: #"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    transcript_hash: #"abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234",
  }
}

/// Build a well-formed 3-round proof for arbitrary (a, b, c).  Each round
/// polynomial and the final error term are derived so the transcript is
/// internally consistent and must verify.
fn well_formed_proof(a: Int, b: Int, c: Int) -> SlimProof {
  // Round 1 must sum to the initial claim (0).
  let e0_1 = a
  let e1_1 = neg_mod(e0_1)
  let e2_1 = b
  let challenge = c
  let claim_1 = eval_poly_mod(e0_1, e1_1, e2_1, challenge)

  // Round 2 must sum to claim_1.
  let e0_2 = b
  let e1_2 = sub_mod(claim_1, e0_2)
  let e2_2 = a
  let claim_2 = eval_poly_mod(e0_2, e1_2, e2_2, challenge)

  // Round 3 must sum to claim_2 and yield the final claim.
  let e0_3 = a + 1
  let e1_3 = sub_mod(claim_2, e0_3)
  let e2_3 = b + 1
  let claim_3 = eval_poly_mod(e0_3, e1_3, e2_3, challenge)

  let rounds =
    [
      RoundPoly { eval_at_0: e0_1, eval_at_1: e1_1, eval_at_2: e2_1 },
      RoundPoly { eval_at_0: e0_2, eval_at_1: e1_2, eval_at_2: e2_2 },
      RoundPoly { eval_at_0: e0_3, eval_at_1: e1_3, eval_at_2: e2_3 },
    ]

  let az = a
  let bz = b
  let cz = c
  // er  such that  az * bz - cz - er == claim_3 (mod field_prime).
  let er = sub_mod(sub_mod(mul_mod(az, bz), cz), claim_3)

  SlimProof {
    rounds,
    challenges: [challenge, challenge, challenge],
    az_r: az,
    bz_r: bz,
    cz_r: cz,
    er_r: er,
    public_input: #"00",
    u: 1,
  }
}

// ---------------------------------------------------------------------------
// End-to-end test: a toy 4-round circuit
// ---------------------------------------------------------------------------

test e2e_4_rounds() {
  let rounds =
    [
      RoundPoly { eval_at_0: 0, eval_at_1: 0, eval_at_2: 0 },
      RoundPoly { eval_at_0: 0, eval_at_1: 0, eval_at_2: 0 },
      RoundPoly { eval_at_0: 0, eval_at_1: 0, eval_at_2: 0 },
      RoundPoly { eval_at_0: 0, eval_at_1: 0, eval_at_2: 0 },
    ]

  let challenges = derive_challenges(test_bundle(), rounds, #"00")

  let proof =
    SlimProof {
      rounds,
      challenges,
      az_r: 0,
      bz_r: 0,
      cz_r: 0,
      er_r: 0,
      public_input: #"00",
      u: 1,
    }

  verify_slim(test_bundle(), proof)
}

// ---------------------------------------------------------------------------
// Negative tests: degenerate proofs
// ---------------------------------------------------------------------------

test empty_proof_rejected() {
  let proof =
    SlimProof {
      rounds: [],
      challenges: [],
      az_r: 0,
      bz_r: 0,
      cz_r: 0,
      er_r: 0,
      public_input: #"00",
      u: 1,
    }

  !verify_slim(test_bundle(), proof)
}

test challenges_without_rounds_rejected() {
  let proof =
    SlimProof {
      rounds: [],
      challenges: [0],
      az_r: 0,
      bz_r: 0,
      cz_r: 0,
      er_r: 0,
      public_input: #"00",
      u: 1,
    }

  !verify_slim(test_bundle(), proof)
}

test mismatch_counts_fails() {
  let rounds = [RoundPoly { eval_at_0: 0, eval_at_1: 0, eval_at_2: 0 }]

  let proof =
    SlimProof {
      rounds,
      challenges: [0, 0],
      az_r: 0,
      bz_r: 0,
      cz_r: 0,
      er_r: 0,
      public_input: #"00",
      u: 1,
    }

  !verify_slim(test_bundle(), proof)
}

// ---------------------------------------------------------------------------
// Unit tests: challenge derivation
// ---------------------------------------------------------------------------

test derive_challenges_is_deterministic() {
  let rounds = [RoundPoly { eval_at_0: 1, eval_at_1: 2, eval_at_2: 3 }]
  derive_challenges(test_bundle(), rounds, #"00") == derive_challenges(
    test_bundle(),
    rounds,
    #"00",
  )
}

test derive_challenges_depends_on_rounds() {
  let rounds_a = [RoundPoly { eval_at_0: 1, eval_at_1: 2, eval_at_2: 3 }]
  let rounds_b = [RoundPoly { eval_at_0: 4, eval_at_1: 2, eval_at_2: 3 }]
  derive_challenges(test_bundle(), rounds_a, #"00") != derive_challenges(
    test_bundle(),
    rounds_b,
    #"00",
  )
}

test derive_challenges_depends_on_public_input() {
  let rounds = [RoundPoly { eval_at_0: 1, eval_at_1: 2, eval_at_2: 3 }]
  derive_challenges(test_bundle(), rounds, #"00") != derive_challenges(
    test_bundle(),
    rounds,
    #"01",
  )
}

// ---------------------------------------------------------------------------
// Property tests (aiken-lang/fuzz)
// ---------------------------------------------------------------------------

test valid_transcript_always_verifies(
  abc via fuzz.tuple3(fuzz.int(), fuzz.int(), fuzz.int()),
) {
  let (a, b, c) = abc
  verify_slim(test_bundle(), well_formed_proof(a, b, c))
}

test tampered_round_poly_fails(
  abc via fuzz.tuple3(fuzz.int(), fuzz.int(), fuzz.int()),
) {
  let (a, b, c) = abc
  let proof = well_formed_proof(a, b, c)
  when proof.rounds is {
    [first, ..rest] -> {
      let tampered_first = RoundPoly { ..first, eval_at_1: first.eval_at_1 + 1 }
      let tampered = SlimProof { ..proof, rounds: [tampered_first, ..rest] }
      !verify_slim(test_bundle(), tampered)
    }
    _ -> True
  }
}

test tampered_final_value_fails(
  abc via fuzz.tuple3(fuzz.int(), fuzz.int(), fuzz.int()),
) {
  let (a, b, c) = abc
  let proof = well_formed_proof(a, b, c)
  let tampered = SlimProof { ..proof, er_r: proof.er_r + 1 }
  !verify_slim(test_bundle(), tampered)
}

// ---------------------------------------------------------------------------
// Norm-certificate tests
// ---------------------------------------------------------------------------

/// A well-formed Option A (range) certificate: two coordinates of 4 and 6 bits
/// under a 8-bit bound.
fn good_range_cert() -> RangeCertificate {
  RangeCertificate { per_coord_bits: [4, 6], bound_bits: 8 }
}

/// A well-formed Option B (JL) certificate.
fn good_jl_cert() -> JlCertificate {
  JlCertificate {
    y: #"00112233445566778899aabbccddeeff",
    bound_bits: 16,
    len: 4,
    coord_bits: 8,
  }
}

test range_cert_valid_accepts() {
  verify_range_cert(good_range_cert())
}

test range_cert_coord_invalid_rejected() {
  // A per-coordinate bit-length above the bound must fail.
  let cert = RangeCertificate { per_coord_bits: [4, 12], bound_bits: 8 }
  !verify_range_cert(cert)
}

test range_cert_empty_rejected() {
  let cert = RangeCertificate { per_coord_bits: [], bound_bits: 8 }
  !verify_range_cert(cert)
}

test range_cert_bound_zero_rejected() {
  let cert = RangeCertificate { per_coord_bits: [4, 6], bound_bits: 0 }
  !verify_range_cert(cert)
}

test jl_cert_valid_accepts() {
  verify_jl_cert(good_jl_cert())
}

test jl_cert_empty_sketch_rejected() {
  let cert = JlCertificate { y: #"", bound_bits: 16, len: 4, coord_bits: 8 }
  !verify_jl_cert(cert)
}

test jl_cert_bad_coord_bits_rejected() {
  let cert =
    JlCertificate {
      y: #"00112233445566778899aabbccddeeff",
      bound_bits: 16,
      len: 4,
      coord_bits: 256,
    }
  !verify_jl_cert(cert)
}

test cert_enum_both_flavours_verify() {
  verify_cert(NormCertificate.RangeCert(good_range_cert())) && verify_cert(
    NormCertificate.JlCert(good_jl_cert()),
  )
}

test norm_record_audit_accepts() {
  let step =
    StepNormCert {
      cert_w: NormCertificate.RangeCert(good_range_cert()),
      cert_e: NormCertificate.RangeCert(good_range_cert()),
    }
  let rec =
    NormRecord { mode: NormMode.NormRange, bound_bits: 8, steps: [step] }
  verify_norm(rec) && verify_step_norm(step)
}

test norm_record_none_mode_rejected() {
  let step =
    StepNormCert {
      cert_w: NormCertificate.RangeCert(good_range_cert()),
      cert_e: NormCertificate.RangeCert(good_range_cert()),
    }
  let rec = NormRecord { mode: NormMode.NormNone, bound_bits: 8, steps: [step] }
  !verify_norm(rec)
}

test norm_record_empty_steps_rejected() {
  let rec = NormRecord { mode: NormMode.NormJl, bound_bits: 8, steps: [] }
  !verify_norm(rec)
}

test norm_record_bad_step_rejected() {
  let bad_step =
    StepNormCert {
      cert_w: NormCertificate.JlCert(good_jl_cert()),
      cert_e: NormCertificate.RangeCert(
        RangeCertificate { per_coord_bits: [9], bound_bits: 4 },
      ),
    }
  let rec =
    NormRecord { mode: NormMode.NormRange, bound_bits: 4, steps: [bad_step] }
  !verify_norm(rec)
}

test verify_slim_with_norm_accepts() {
  let proof = well_formed_proof(3, 5, 2)
  let step =
    StepNormCert {
      cert_w: NormCertificate.RangeCert(good_range_cert()),
      cert_e: NormCertificate.RangeCert(good_range_cert()),
    }
  let rec =
    NormRecord { mode: NormMode.NormRange, bound_bits: 8, steps: [step] }
  verify_slim_with_norm(test_bundle(), proof, rec)
}

test verify_slim_with_norm_rejects_bad_norm() {
  // A valid slim proof but a malformed norm record must be rejected.
  let proof = well_formed_proof(3, 5, 2)
  let rec = NormRecord { mode: NormMode.NormNone, bound_bits: 8, steps: [] }
  !verify_slim_with_norm(test_bundle(), proof, rec)
}
