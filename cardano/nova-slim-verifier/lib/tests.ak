use aiken/builtin
use aiken/collection/list
use aiken/fuzz
use norm.{
  JlCertificate, NormCertificate, NormMode, NormRecord, RangeCertificate,
  StepNormCert, verify_cert, verify_jl_cert, verify_norm, verify_range_cert,
  verify_step_norm,
}
use verifier.{
  NifsBundle, NovaSlimDatum, RoundPoly, SlimProof, derive_challenges,
  verify_slim, verify_slim_with_norm,
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
  26217937587563095239723870254092982918845276250263818911301829349969290592257
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
/// internally consistent and must verify.  The Fiat-Shamir challenges are
/// re-derived on-chain, so the rounds are rolled against the *actual* derived
/// challenges (not a fixed choice): the (e0, e1) pair of each round sums to the
/// previous claim, where the claim is the previous round evaluated at the
/// challenge that its own transcript prefix yields.
///
/// The free inputs are normalized to canonical field elements in
/// [0, field_prime): round evaluations are serialized to 32 bytes as part of
/// the transcript, so every stored scalar must be a well-defined encoding.
fn well_formed_proof(a: Int, b: Int, c: Int) -> SlimProof {
  let bundle = test_bundle()
  let public_input = #"00"
  let ra = builtin.mod_integer(a, field_prime)
  let rb = builtin.mod_integer(b, field_prime)
  let rc = builtin.mod_integer(c, field_prime)

  // Round 1: e0 + e1 == claim_0 (== 0).
  let h1 = RoundPoly { eval_at_0: ra, eval_at_1: neg_mod(ra), eval_at_2: rb }
  let c1 = last_challenge(bundle, [h1], public_input)
  let claim_1 = eval_poly_mod(ra, neg_mod(ra), rb, c1)

  // Round 2: e0 + e1 == claim_1.
  let h2 =
    RoundPoly { eval_at_0: rb, eval_at_1: sub_mod(claim_1, rb), eval_at_2: ra }
  let c2 = last_challenge(bundle, [h1, h2], public_input)
  let claim_2 = eval_poly_mod(rb, sub_mod(claim_1, rb), ra, c2)

  // Round 3: e0 + e1 == claim_2 and yield the final claim.
  let ra1 = add_mod(ra, 1)
  let rb1 = add_mod(rb, 1)
  let h3 =
    RoundPoly {
      eval_at_0: ra1,
      eval_at_1: sub_mod(claim_2, ra1),
      eval_at_2: rb1,
    }
  let rounds = [h1, h2, h3]
  let challenges = derive_challenges(bundle, rounds, public_input)
  let c3 = last_challenge(bundle, rounds, public_input)
  let claim_3 = eval_poly_mod(ra1, sub_mod(claim_2, ra1), rb1, c3)

  // er  such that  az * bz - u * cz - er == claim_3 (mod field_prime).
  let er = sub_mod(sub_mod(mul_mod(ra, rb), rc), claim_3)
  // fr_r satisfies the level-1 equation  fr_r - u * cz - er == 0, i.e.
  // fr_r == u*cz + er (u := 1 here).
  let fr_r = add_mod(rc, er)

  SlimProof {
    rounds,
    challenges,
    az_r: ra,
    bz_r: rb,
    cz_r: rc,
    er_r: er,
    fr_r,
    public_input,
    u: 1,
  }
}

/// The last challenge in the FS-derived list for a transcript prefix (the
/// challenge for the just-appended round).  Used while rolling a valid proof.
fn last_challenge(
  bundle: NifsBundle,
  rounds: List<RoundPoly>,
  public_input: ByteArray,
) -> Int {
  when list.last(derive_challenges(bundle, rounds, public_input)) is {
    Some(c) -> c
    None -> 0
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
      fr_r: 0,
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
      fr_r: 0,
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
      fr_r: 0,
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
      fr_r: 0,
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

test carried_wrong_challenges_rejected() {
  // A transcript that is otherwise internally consistent but carries
  // self-serving challenges must be rejected: the on-chain verifier re-derives
  // the Fiat-Shamir challenges from the bundle, rounds, and public input
  // instead of trusting the ones in the redeemer.
  let proof = well_formed_proof(3, 5, 2)
  let tampered = SlimProof { ..proof, challenges: [7, 8, 9] }
  !verify_slim(test_bundle(), tampered)
}

test single_wrong_challenge_rejected() {
  // Even a single altered challenge among otherwise correct ones fails: the
  // re-derived challenge list must match the carried one element for element.
  let proof = well_formed_proof(3, 5, 2)
  when proof.challenges is {
    [first, second, third] -> {
      let tampered = SlimProof { ..proof, challenges: [first, second, third + 1] }
      !verify_slim(test_bundle(), tampered)
    }
    _ -> False
  }
}

// ---------------------------------------------------------------------------
// Level-1 (fr_r) unit tests
// ---------------------------------------------------------------------------

test l1_check_rejects_bad_fr_r() {
  // The level-1 equation  fr_r == u*cz_r + er_r  must hold.  A one-off
  // deviation in fr_r is enough to fail verification.
  let proof = well_formed_proof(3, 5, 2)
  let tampered = SlimProof { ..proof, fr_r: proof.fr_r + 1 }
  !verify_slim(test_bundle(), tampered)
}

test l1_check_rejects_zero_fr_r_with_terms() {
  // With u = 1 and a non-trivial honest transcript the residual fr_r =
  // cz_r + er_r is a large field element.  Forcing fr_r = 0 breaks the
  // level-1 equation — this is the "free-E" case the check is meant to
  // close (the all-zero tautology fr_r = cz = er = 0 would pass trivially).
  let proof = well_formed_proof(3, 5, 2)
  let tampered = SlimProof { ..proof, fr_r: 0 }
  !verify_slim(test_bundle(), tampered)
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
// Fiat-Shamir property tests
// ---------------------------------------------------------------------------

test fs_tampered_challenge_fails(
  abc via fuzz.tuple3(fuzz.int(), fuzz.int(), fuzz.int()),
) {
  let (a, b, c) = abc
  let proof = well_formed_proof(a, b, c)
  when proof.challenges is {
    [first, ..rest] -> {
      let tampered = SlimProof { ..proof, challenges: [first + 1, ..rest] }
      !verify_slim(test_bundle(), tampered)
    }
    _ -> True
  }
}

test fs_tampered_public_input_fails(
  abc via fuzz.tuple3(fuzz.int(), fuzz.int(), fuzz.int()),
) {
  let (a, b, c) = abc
  let proof = well_formed_proof(a, b, c)
  let tampered = SlimProof { ..proof, public_input: #"01" }
  !verify_slim(test_bundle(), tampered)
}

test fs_tampered_bundle_fails(
  abc via fuzz.tuple3(fuzz.int(), fuzz.int(), fuzz.int()),
) {
  let (a, b, c) = abc
  let proof = well_formed_proof(a, b, c)
  let other = NifsBundle {
    ..test_bundle(),
    com_e_hash:
      #"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001",
  }
  !verify_slim(other, proof)
}

// ---------------------------------------------------------------------------
// Level-1 (fr_r) property tests
// ---------------------------------------------------------------------------

test fs_l1_tampered_fr_r_fails(
  abc via fuzz.tuple3(fuzz.int(), fuzz.int(), fuzz.int()),
) {
  // A well-formed transcript satisfies  fr_r == u*cz_r + er_r; any single
  // deviation in fr_r must therefore be rejected.
  let (a, b, c) = abc
  let proof = well_formed_proof(a, b, c)
  let tampered = SlimProof { ..proof, fr_r: proof.fr_r + 1 }
  !verify_slim(test_bundle(), tampered)
}

test fs_l1_tampered_u_fails(
  abc via fuzz.tuple3(fuzz.int(), fuzz.int(), fuzz.int()),
) {
  // The relaxation factor u enters the level-1 equation via the u*cz_r term.
  // c+1 keeps cz_r non-zero so the deviation is always observable.
  let (a, b, c) = abc
  let proof = well_formed_proof(a, b, c + 1)
  let tampered = SlimProof { ..proof, u: proof.u + 1 }
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

// ---------------------------------------------------------------------------
// NovaSlimDatum / validator-level tests
// ---------------------------------------------------------------------------

/// A well-formed norm record for use in datum-level tests.
fn good_norm_record() -> NormRecord {
  let step =
    StepNormCert {
      cert_w: NormCertificate.RangeCert(good_range_cert()),
      cert_e: NormCertificate.RangeCert(good_range_cert()),
    }
  NormRecord { mode: NormMode.NormRange, bound_bits: 8, steps: [step] }
}

/// SumOnly datum: the validator should dispatch to verify_slim (sumcheck only).
test datum_sum_only_accepts() {
  let proof = well_formed_proof(3, 5, 2)
  let datum = NovaSlimDatum.SumOnly(test_bundle())
  when datum is {
    NovaSlimDatum.SumOnly(bundle) -> verify_slim(bundle, proof)
    _ -> False
  }
}

/// WithNorm datum: the validator should dispatch to verify_slim_with_norm.
test datum_with_norm_accepts() {
  let proof = well_formed_proof(3, 5, 2)
  let datum = NovaSlimDatum.WithNorm(test_bundle(), good_norm_record())
  when datum is {
    NovaSlimDatum.WithNorm(bundle, norm) ->
      verify_slim_with_norm(bundle, proof, norm)
    _ -> False
  }
}

/// WithNorm datum but bad norm: must be rejected.
test datum_with_norm_rejects_bad_norm() {
  let proof = well_formed_proof(3, 5, 2)
  let bad_norm = NormRecord { mode: NormMode.NormNone, bound_bits: 8, steps: [] }
  let datum = NovaSlimDatum.WithNorm(test_bundle(), bad_norm)
  when datum is {
    NovaSlimDatum.WithNorm(bundle, norm) ->
      !verify_slim_with_norm(bundle, proof, norm)
    _ -> False
  }
}

// ---------------------------------------------------------------------------
// Fiat-Shamir golden tests
// ---------------------------------------------------------------------------
// These pin the exact output of derive_challenges for known inputs so any
// regression in the hash-based derivation (e.g. transcript byte order,
// integer_to_bytearray width, or blake2b_256) is immediately caught.

test golden_derive_single_round() {
  // A single round with fixed evals.
  let rounds = [RoundPoly { eval_at_0: 1, eval_at_1: 2, eval_at_2: 3 }]
  derive_challenges(test_bundle(), rounds, #"00") ==
    [16929951500751571981113663996273193905068373582928884364803637547339592859593]
}

test golden_derive_four_zero_rounds() {
  // Four zero-eval rounds: tests sequential transcript accumulation.
  let rounds =
    [
      RoundPoly { eval_at_0: 0, eval_at_1: 0, eval_at_2: 0 },
      RoundPoly { eval_at_0: 0, eval_at_1: 0, eval_at_2: 0 },
      RoundPoly { eval_at_0: 0, eval_at_1: 0, eval_at_2: 0 },
      RoundPoly { eval_at_0: 0, eval_at_1: 0, eval_at_2: 0 },
    ]
  derive_challenges(test_bundle(), rounds, #"00") == [
    40567697305796473729143549081855633355917758540772945690797250625174332769881,
    15818634843063192224941180539463993825982369414957740001887078341341578380200,
    11583516624017853094539122299782969582435528202371229216294397029342260051647,
    23019355995932246789385748719099435175264769341681124507214830553552729314158,
  ]
}

test golden_derive_three_zero_rounds_prefix() {
  // The first three challenges of the four-round zero vector must match the
  // three-round derivation — prefix consistency of the hash chain.
  let three =
    [
      RoundPoly { eval_at_0: 0, eval_at_1: 0, eval_at_2: 0 },
      RoundPoly { eval_at_0: 0, eval_at_1: 0, eval_at_2: 0 },
      RoundPoly { eval_at_0: 0, eval_at_1: 0, eval_at_2: 0 },
    ]
  derive_challenges(test_bundle(), three, #"00") == [
    40567697305796473729143549081855633355917758540772945690797250625174332769881,
    15818634843063192224941180539463993825982369414957740001887078341341578380200,
    11583516624017853094539122299782969582435528202371229216294397029342260051647,
  ]
}

// ---------------------------------------------------------------------------
// Level-1 (fr_r) golden tests
// ---------------------------------------------------------------------------
// Pin the exact fr_r (MLE-of-product residual) that the Python mirror
// computed for well_formed_proof(2, 3, 5) so any regression in the
// sumcheck-circuit arithmetic or field-element encoding is caught.

/// Verify that the well-formed proof for (2, 3, 5) still passes the full
/// verification pipeline with the pinned fr_r value.
test golden_l1_fixed_proof() {
  let proof = well_formed_proof(2, 3, 5)
  let l1_rhs = add_mod(mul_mod(proof.u, proof.cz_r), proof.er_r)
  proof.fr_r == l1_rhs && verify_slim(test_bundle(), proof)
}

/// Pin the exact constants for well_formed_proof(2, 3, 5).
/// Transcript bytes use 32-byte big-endian field elements; the challenge is
/// blake2b_256 of the transcript interpreted as an unsigned integer
/// (bytearray_to_integer(True, _) = big-endian unsigned) reduced mod p,
/// matching scalar_from_bytes in verifier.ak.
test golden_l1_fixed_proof_constants() {
  let proof = well_formed_proof(2, 3, 5)
  // challenges — pinned via the unsigned Python mirror.
  proof.challenges == [
    23574925186820971314618738110825202861113776913549720541346685721924983188440,
    36840350308506967840401952273097443865780992173629607707919934450147480186009,
    8454087999455834781016495474894335786902418218811582330836954262107643381658,
  ] &&
  // er and fr_r — derived from the same challenge chain above.
  proof.er_r == 41184818356760088113659243961088770423705944737169497952831624572171875390003 &&
  proof.fr_r == 41184818356760088113659243961088770423705944737169497952831624572171875390008 &&
  // level-1 equation holds
  proof.fr_r == add_mod(mul_mod(proof.u, proof.cz_r), proof.er_r)
}

/// A golden proof with the pinned fr_r rejected when fr_r is incremented by 1.
test golden_l1_fixed_proof_tampered_rejected() {
  let proof = well_formed_proof(2, 3, 5)
  let tampered = SlimProof { ..proof, fr_r: 41184818356760088113659243961088770423705944737169497952831624572171875390009 }
  !verify_slim(test_bundle(), tampered)
}

/// All-zero four-round proof must carry fr_r = 0 (the zero residual is the
/// only value consistent with u = 1, cz = 0, er = 0).
test golden_l1_all_zero_proof() {
  let proof =
    SlimProof {
      rounds: [
        RoundPoly { eval_at_0: 0, eval_at_1: 0, eval_at_2: 0 },
        RoundPoly { eval_at_0: 0, eval_at_1: 0, eval_at_2: 0 },
        RoundPoly { eval_at_0: 0, eval_at_1: 0, eval_at_2: 0 },
        RoundPoly { eval_at_0: 0, eval_at_1: 0, eval_at_2: 0 },
      ],
      challenges: [
        40567697305796473729143549081855633355917758540772945690797250625174332769881,
        15818634843063192224941180539463993825982369414957740001887078341341578380200,
        11583516624017853094539122299782969582435528202371229216294397029342260051647,
        23019355995932246789385748719099435175264769341681124507214830553552729314158,
      ],
      az_r: 0,
      bz_r: 0,
      cz_r: 0,
      er_r: 0,
      fr_r: 0,
      public_input: #"00",
      u: 1,
    }

  proof.fr_r == 0 &&
  proof.fr_r == add_mod(mul_mod(proof.u, proof.cz_r), proof.er_r) &&
  verify_slim(test_bundle(), proof)
}
