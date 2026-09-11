# NovaSlim On-Chain Verifier (Aiken)

An Aiken eUTXO validator for verifying NovaSlim slim proofs on Cardano.

## What this verifier does

This validator checks a **slim proof** — the sumcheck protocol only, with no
commitment openings.  It is **commitment-scheme agnostic**: the same on-chain
verifier works for all three NovaSlim commitment schemes (Pedersen, SIS, Hash)
because the on-chain check is purely the sumcheck protocol.  The commitment
binding is verified off-chain by auditors who check the HashPC truth tables
against the commitment hashes stored in the datum.

For **level-1 proofs** (SIS and Hash commitments), the validator additionally
enforces **norm-certificate structural consistency** via the `WithNorm` datum
variant.  The on-chain check validates mode, bound, and per-certificate fields;
the ground-truth infinity-norm re-computation stays off-chain (Rust
`verify_level1_norm`).

## Architecture

```
┌─────────────┐      ┌──────────────────┐      ┌─────────────────┐
│  NovaSlim   │      │   Aiken Validator │      │  Cardano Chain  │
│   (Rust)    │─────▶│  (this project)   │─────▶│  (eUTXO script) │
│             │      │                   │      │                 │
│ Fold +      │      │  • Sumcheck verify│      │  • Verify slim  │
│ Compress    │      │  • Fiat-Shamir    │      │    proof        │
│             │      │  • Final eval     │      │  • No openings  │
└─────────────┘      └──────────────────┘      └─────────────────┘
```

## Prerequisites

- [Aiken](https://aiken-lang.org) v1.1.19 or later
- A Cardano node or wallet for deployment (e.g., `cardano-cli`, `demeter.run`)

## Quick start

```bash
# Type-check and run tests
aiken check

# Build the validator (produces a Plutus blueprint)
aiken build
```

## Test Results

`aiken check` runs 35 tests: unit, property (100 fuzz cases each), and golden:

```
   Collecting all tests scenarios across all modules
      Testing ...
    ┍━ tests ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    │ PASS [mem: 460.49 K, cpu: 191.27 M] e2e_4_rounds
    │ PASS [mem:  31.41 K, cpu:  10.18 M] empty_proof_rejected
    │ PASS [mem:  22.49 K, cpu:   7.28 M] challenges_without_rounds_rejected
    │ PASS [mem:  42.53 K, cpu:  18.73 M] mismatch_counts_fails
    │ PASS [mem:  51.82 K, cpu:  26.97 M] derive_challenges_is_deterministic
    │ PASS [mem:  52.42 K, cpu:  27.15 M] derive_challenges_depends_on_rounds
    │ PASS [mem:  52.42 K, cpu:  27.15 M] derive_challenges_depends_on_public_input
    │ PASS [mem: 373.23 K, cpu: 183.16 M] carried_wrong_challenges_rejected
    │ PASS [mem: 383.11 K, cpu: 186.65 M] single_wrong_challenge_rejected
    │ PASS [after 100 tests] valid_transcript_always_verifies
    │ PASS [after 100 tests] tampered_round_poly_fails
    │ PASS [after 100 tests] tampered_final_value_fails
    │ PASS [after 100 tests] fs_tampered_challenge_fails
    │ PASS [after 100 tests] fs_tampered_public_input_fails
    │ PASS [after 100 tests] fs_tampered_bundle_fails
    │ PASS [mem:  23.77 K, cpu:   6.99 M] range_cert_valid_accepts
    │ PASS [mem:  22.70 K, cpu:   6.69 M] range_cert_coord_invalid_rejected
    │ PASS [mem:   9.72 K, cpu:   2.71 M] range_cert_empty_rejected
    │ PASS [mem:   6.46 K, cpu:   1.61 M] range_cert_bound_zero_rejected
    │ PASS [mem:  17.78 K, cpu:   5.82 M] jl_cert_valid_accepts
    │ PASS [mem:  16.85 K, cpu:   5.43 M] jl_cert_empty_sketch_rejected
    │ PASS [mem:  12.31 K, cpu:   3.79 M] jl_cert_bad_coord_bits_rejected
    │ PASS [mem:  48.91 K, cpu:  15.29 M] cert_enum_both_flavours_verify
    │ PASS [mem: 129.67 K, cpu:  40.47 M] norm_record_audit_accepts
    │ PASS [mem:  14.38 K, cpu:   3.59 M] norm_record_none_mode_rejected
    │ PASS [mem:  16.55 K, cpu:   4.68 M] norm_record_empty_steps_rejected
    │ PASS [mem:  63.91 K, cpu:  20.29 M] norm_record_bad_step_rejected
    │ PASS [mem: 695.78 K, cpu: 289.16 M] verify_slim_with_norm_accepts
    │ PASS [mem: 627.16 K, cpu: 267.26 M] verify_slim_with_norm_rejects_bad_norm
    │ PASS [mem: 623.72 K, cpu: 266.57 M] datum_sum_only_accepts
    │ PASS [mem: 700.00 K, cpu: 290.66 M] datum_with_norm_accepts
    │ PASS [mem: 631.38 K, cpu: 268.76 M] datum_with_norm_rejects_bad_norm
    │ PASS [mem:  26.26 K, cpu:  14.15 M] golden_derive_single_round
    │ PASS [mem:  67.57 K, cpu:  44.43 M] golden_derive_four_zero_rounds
    │ PASS [mem:  53.79 K, cpu:  34.23 M] golden_derive_three_zero_rounds_prefix
    ┕━━━━━━━━━━━━━━━━━━━━━━ with --seed=<seed> → 35 tests | 35 passed | 0 failed
      Summary 629 checks, 0 errors, 0 warnings
```

What they cover:

- **`e2e_4_rounds`** — an end-to-end happy path: `verify_slim` accepts a
  well-formed 4-round proof whose challenges come from `derive_challenges`.
- **`empty_proof_rejected`** / **`challenges_without_rounds_rejected`** /
  **`mismatch_counts_fails`** — degenerate proofs (no rounds, or rounds vs
  challenges count mismatch) are rejected.
- **`derive_challenges_*`** — challenge derivation is deterministic, and
  depends on both the round polynomials and the public input.
- **`carried_wrong_challenges_rejected`** /
  **`single_wrong_challenge_rejected`** — challenges carried in the redeemer
  that do not match the on-chain Fiat-Shamir re-derivation are rejected; even a
  single altered challenge among otherwise correct ones fails.
- **`valid_transcript_always_verifies`** — for *any* randomly generated
  transcript that is internally consistent, `verify_slim` accepts it.
- **`tampered_round_poly_fails`** / **`tampered_final_value_fails`** — a
  single one-line deviation in a round polynomial or in `er_r` is enough for
  `verify_slim` to reject the proof.
- **`fs_tampered_challenge_fails`** / **`fs_tampered_public_input_fails`** /
  **`fs_tampered_bundle_fails`** — fuzz-driven: tampering a challenge, the
  public input, or the NIFS bundle is enough to break Fiat-Shamir binding and
  get the proof rejected.
- **`golden_derive_*`** — golden vectors pin the exact `derive_challenges`
  output for fixed transcripts (single round, sequential zero rounds, prefix
  consistency) so any regression in the derivation is caught.
- **`range_cert_*`** / **`jl_cert_*`** / **`cert_enum_*`** — norm certificate
  structural checks: valid certs accepted, out-of-bounds/empty/zero certs
  rejected, both Range and JL flavours verified.
- **`norm_record_*`** — `NormRecord` structural validation: audit modes
  accepted, `NormNone` and empty steps rejected, bad per-step certs rejected.
- **`verify_slim_with_norm_*`** — combined sumcheck + norm-certificate
  verification: valid proof+norm accepted, valid proof+bad norm rejected.
- **`datum_sum_only_accepts`** / **`datum_with_norm_accepts`** /
  **`datum_with_norm_rejects_bad_norm`** — `NovaSlimDatum` dispatch: `SumOnly`
  routes to sumcheck-only, `WithNorm` routes to combined check, bad norm in
  `WithNorm` is rejected.

## Validator API

The validator checks a `spend` redemption where:
- **Datum** = `Option<NovaSlimDatum>` (backward-compatible tagged enum)
- **Redeemer** = `SlimProof` (the slim sumcheck proof)

```aiken
validator nova_slim {
  spend(datum: Option<NovaSlimDatum>, redeemer: SlimProof, _utxo: OutputReference, _self: Transaction) {
    when datum is {
      Some(SumOnly(bundle)) -> verify_slim(bundle, redeemer)
      Some(WithNorm(bundle, norm)) -> verify_slim_with_norm(bundle, redeemer, norm)
      None -> False
    }
  }
}
```

### Datum (`NovaSlimDatum`)

| Variant | Fields | Description |
|---|---|---|
| `SumOnly(NifsBundle)` | `NifsBundle` | Sumcheck-only proof (backward-compatible) |
| `WithNorm(NifsBundle, NormRecord)` | `NifsBundle`, `NormRecord` | Level-1 proof with norm-certificate consistency check |

### `NifsBundle`

| Field | Type | Description |
|---|---|---|
| `com_w_hash` | `ByteArray` | BLAKE2b-256 hash of witness commitment |
| `com_e_hash` | `ByteArray` | BLAKE2b-256 hash of error commitment |
| `transcript_hash` | `ByteArray` | Fiat-Shamir transcript hash from folding |

### `NormRecord`

| Field | Type | Description |
|---|---|---|
| `mode` | `NormMode` | `NormRange` or `NormJl` (audit modes; `NormNone` rejected) |
| `bound_bits` | `Int` | Public norm bound in bits (1–254) |
| `steps` | `List<StepNormCert>` | Per-step certificates (witness + error) |

### Redeemer (`SlimProof`)

| Field | Type | Description |
|---|---|---|
| `rounds` | `List<RoundPoly>` | Sumcheck round polynomials (degree-2) |
| `challenges` | `List<Scalar>` | Fiat-Shamir challenges r₁…rₖ |
| `az_r` | `Scalar` | Claimed A·Z evaluation at r |
| `bz_r` | `Scalar` | Claimed B·Z evaluation at r |
| `cz_r` | `Scalar` | Claimed C·Z evaluation at r |
| `er_r` | `Scalar` | Claimed error E evaluation at r |
| `public_input` | `ByteArray` | Public input x |
| `u` | `Scalar` | Slack scalar (usually 1) |

## How it works

1. **Round verification**: For each round *i*, check that
   `hᵢ(0) + hᵢ(1) == hᵢ₋₁(rᵢ₋₁)`. At least one round is required — degenerate
   proofs with zero rounds are rejected.

2. **Fiat-Shamir**: The challenges carried in the proof are enforced:
   `derive_challenges` re-derives the BLAKE2b-256 challenges from the NIFS
   bundle, the round polynomials, and the public input, and `verify_slim`
   requires them to match the proof's `challenges` element for element.  A
   prover cannot smuggle in self-serving challenges.

3. **Final evaluation**: Check that
   `azᵣ · bzᵣ - u · czᵣ - eᵣ == hₖ(rₖ)`.

All arithmetic is performed in the **BLS12-381 scalar field** (`Fr`), which
Plutus V3 supports natively.

## Supported curves and commitments

This verifier is **field-agnostic at the type level** — it operates on
raw `Int` values modulo the BLS12-381 prime.  In practice, it is designed for
BLS12-381 (Cardano's native curve).  The same verifier works for slim proofs
produced with any of NovaSlim's three commitment schemes:

| Commitment | On-chain verifier | Off-chain audit |
|---|---|---|
| Pedersen | ✅ Sumcheck only (`SumOnly`) | Pedersen opening check |
| SIS | ✅ Sumcheck + norm cert (`WithNorm`) | SIS opening check + norm audit |
| Hash | ✅ Sumcheck + norm cert (`WithNorm`) | Hash opening check + norm audit |

## Deployment

1. Build the validator:
```bash
aiken build
```

2. The blueprint is written to `plutus.json` (the validator has no parameters,
   so no `aiken apply` step is needed).

3. Submit the compiled validator (UPLC) to the Cardano chain via `cardano-cli`
   or your preferred wallet integration.

## Integration with NovaSlim

The Rust prover (`nova-slim`) outputs a slim proof as a CBOR-encoded byte
array.  Convert it to the Aiken `SlimProof` type before submitting:

```rust
// In your Rust off-chain code
let slim_proof_bytes = nova_slim_prover.generate_slim_proof(...);
// Serialize to Aiken's expected format (CBOR map)
```

A `nova-slim export --format aiken` conversion command is **planned** for the
NovaSlim CLI but not yet implemented.

## Project structure

```
.
├── aiken.toml              # Project manifest (aiken-lang/stdlib, aiken-lang/fuzz)
├── lib/
│   ├── verifier.ak         # Core sumcheck verification library + NovaSlimDatum
│   ├── norm.ak             # On-chain norm-certificate verification (level-1)
│   └── tests.ak            # Unit and property-based tests
├── validators/
│   └── nova_slim.ak        # On-chain validator script
└── README.md               # This file
```

## License

Apache-2.0

## See also

- **NovaSlim prover** (Rust): `https://github.com/paweljakubas/nova-slim`
- **Aiken language**: `https://aiken-lang.org`
- **Cardano eUTXO model**: `https://docs.cardano.org`
