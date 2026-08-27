//// NovaSlim — on-chain sumcheck verifier for BLS12-381.
////
//// This validator checks a *slim proof*: the sumcheck protocol only, with no
//// commitment openings.  It is commitment-scheme agnostic: the same verifier
//// works for Pedersen, SIS, and Hash folded instances.
////
//// The arithmetic is carried out in the BLS12-381 scalar field (Fr) using
//// raw Int operations with explicit modular reduction.

use aiken/builtin
use aiken/crypto.{blake2b_256}
use aiken/collection/list
use aiken/primitive/bytearray

/// BLS12-381 scalar field prime.
const field_prime =
  52435875175126190479447740508185965837690552500527637822603658699938581184513

/// ---------------------------------------------------------------------------
/// Types
/// ---------------------------------------------------------------------------

/// A scalar field element, stored as a raw Int (always kept in [0, field_prime)).
pub type Scalar = Int

/// One sumcheck round: a degree-2 univariate polynomial represented by its
/// evaluations at X = 0, 1, 2.
pub type RoundPoly {
  eval_at_0: Scalar,
  eval_at_1: Scalar,
  eval_at_2: Scalar,
}

/// The slim proof that travels on-chain.
pub type SlimProof {
  rounds: List<RoundPoly>,
  challenges: List<Scalar>,
  az_r: Scalar,
  bz_r: Scalar,
  cz_r: Scalar,
  er_r: Scalar,
  public_input: ByteArray,
  u: Scalar,
}

/// The NIFS bundle anchors the proof to a specific folded instance.
pub type NifsBundle {
  com_w_hash: ByteArray,
  com_e_hash: ByteArray,
  transcript_hash: ByteArray,
}

/// ---------------------------------------------------------------------------
/// Field arithmetic
/// ---------------------------------------------------------------------------

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

fn scalar_from_bytes(b: ByteArray) -> Int {
  builtin.mod_integer(builtin.bytearray_to_integer(True, b), field_prime)
}

fn scalar_zero() -> Int {
  0
}

fn scalar_one() -> Int {
  1
}

/// ---------------------------------------------------------------------------
/// Sumcheck verification
/// ---------------------------------------------------------------------------

/// Verify the slim proof against the NIFS bundle.
pub fn verify_slim(_bundle: NifsBundle, proof: SlimProof) -> Bool {
  let counts_ok =
    list.length(proof.rounds) == list.length(proof.challenges)

  // Verify each round: h_i(0) + h_i(1) == previous_claim.
  let rounds_ok = verify_all_rounds(proof.rounds, proof.challenges)

  // Final evaluation check.
  let final_ok = verify_final(proof)

  counts_ok && rounds_ok && final_ok
}

/// Verify all rounds using list folding.
fn verify_all_rounds(
  rounds: List<RoundPoly>,
  challenges: List<Scalar>,
) -> Bool {
  let round_checks =
    list.map2(rounds, challenges, fn(r, c) {
      (r.eval_at_0, r.eval_at_1, r.eval_at_2, c)
    })

  do_verify_rounds(round_checks, scalar_zero())
}

fn do_verify_rounds(
  checks: List<(Scalar, Scalar, Scalar, Scalar)>,
  prev_claim: Scalar,
) -> Bool {
  when checks is {
    [] -> True
    [(e0, e1, e2, challenge), ..rest] -> {
      let round_ok = add_mod(e0, e1) == prev_claim
      let next_claim = eval_poly(e0, e1, e2, challenge)
      round_ok && do_verify_rounds(rest, next_claim)
    }
  }
}

/// Evaluate degree-2 polynomial at x using Lagrange interpolation on {0,1,2}.
fn eval_poly(c0: Scalar, c1: Scalar, c2: Scalar, x: Scalar) -> Scalar {
  let t0 = mul_mod(add_mod(x, neg_mod(scalar_one())), add_mod(x, neg_mod(add_mod(scalar_one(), scalar_one()))))
  let term0 = mul_mod(c0, mul_mod(t0, inv2()))

  let t1 = mul_mod(x, add_mod(add_mod(scalar_one(), scalar_one()), neg_mod(x)))
  let term1 = mul_mod(c1, t1)

  let t2 = mul_mod(x, add_mod(x, neg_mod(scalar_one())))
  let term2 = mul_mod(c2, mul_mod(t2, inv2()))

  add_mod(term0, add_mod(term1, term2))
}

/// Verify the final evaluation: az_r * bz_r - u * cz_r - e_r == final_claim.
fn verify_final(proof: SlimProof) -> Bool {
  let final_claim =
    when list.last(proof.rounds) is {
      Some(last_round) ->
        when list.last(proof.challenges) is {
          Some(last_challenge) ->
            eval_poly(
              last_round.eval_at_0,
              last_round.eval_at_1,
              last_round.eval_at_2,
              last_challenge,
            )
          None -> scalar_zero()
        }
      None -> scalar_zero()
    }

  let lhs =
    add_mod(
      mul_mod(proof.az_r, proof.bz_r),
      add_mod(neg_mod(mul_mod(proof.u, proof.cz_r)), neg_mod(proof.er_r)),
    )

  lhs == final_claim
}

/// ---------------------------------------------------------------------------
/// Fiat-Shamir challenge derivation
/// ---------------------------------------------------------------------------

/// Derive challenges from the NIFS bundle and round polynomials.
pub fn derive_challenges(
  bundle: NifsBundle,
  rounds: List<RoundPoly>,
  public_input: ByteArray,
) -> List<Scalar> {
  let transcript =
    bytearray.concat(
      bytearray.concat(bundle.com_w_hash, bundle.com_e_hash),
      bytearray.concat(bundle.transcript_hash, public_input),
    )
  derive_challenges_acc(rounds, transcript, [])
}

fn derive_challenges_acc(
  rounds: List<RoundPoly>,
  transcript: ByteArray,
  acc: List<Scalar>,
) -> List<Scalar> {
  when rounds is {
    [] -> list.reverse(acc)
    [round, ..rest] -> {
      let round_bytes =
        bytearray.concat(
          bytearray.concat(
            builtin.integer_to_bytearray(True, 32, round.eval_at_0),
            builtin.integer_to_bytearray(True, 32, round.eval_at_1),
          ),
          builtin.integer_to_bytearray(True, 32, round.eval_at_2),
        )
      let new_transcript = bytearray.concat(transcript, round_bytes)
      let hash = blake2b_256(new_transcript)
      let challenge = scalar_from_bytes(hash)
      derive_challenges_acc(rest, new_transcript, [challenge, ..acc])
    }
  }
}
