use nova_slim/verifier.{
  NifsBundle, RoundPoly, SlimProof, derive_challenges, verify_slim,
}

// ---------------------------------------------------------------------------
// End-to-end test: a toy 4-round circuit
// ---------------------------------------------------------------------------

test e2e_4_rounds() {
  let bundle =
    NifsBundle {
      com_w_hash: #"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
      com_e_hash: #"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
      transcript_hash: #"abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234",
    }

  let rounds = [
    RoundPoly { eval_at_0: 0, eval_at_1: 0, eval_at_2: 0 },
    RoundPoly { eval_at_0: 0, eval_at_1: 0, eval_at_2: 0 },
    RoundPoly { eval_at_0: 0, eval_at_1: 0, eval_at_2: 0 },
    RoundPoly { eval_at_0: 0, eval_at_1: 0, eval_at_2: 0 },
  ]

  let challenges = derive_challenges(bundle, rounds, #"00")

  let proof =
    SlimProof {
      rounds: rounds,
      challenges: challenges,
      az_r: 0,
      bz_r: 0,
      cz_r: 0,
      er_r: 0,
      public_input: #"00",
      u: 1,
    }

  verify_slim(bundle, proof)
}

// ---------------------------------------------------------------------------
// Negative test: tampered challenge should fail
// ---------------------------------------------------------------------------

test tampered_challenge_fails() {
  let bundle =
    NifsBundle {
      com_w_hash: #"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
      com_e_hash: #"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
      transcript_hash: #"abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234",
    }

  let rounds = [
    RoundPoly { eval_at_0: 0, eval_at_1: 0, eval_at_2: 0 },
  ]

  let wrong_challenges = [
    52435875175126190479447740508185965837690552500527637822603658699938581184512,
  ]

  let proof =
    SlimProof {
      rounds: rounds,
      challenges: wrong_challenges,
      az_r: 0,
      bz_r: 0,
      cz_r: 0,
      er_r: 0,
      public_input: #"00",
      u: 1,
    }

  !verify_slim(bundle, proof)
}
