# NovaSlim On-Chain Verifier (Aiken)

An Aiken eUTXO validator for verifying NovaSlim slim proofs on Cardano.

## What this verifier does

The verifier exposes four datum flavours.  `SumOnly` checks a **slim proof** —
the sumcheck protocol only — and is **commitment-scheme agnostic**: it works for
all three NovaSlim commitment schemes (Pedersen, SIS, Hash) because the on-chain
check is purely the sumcheck protocol.  `WithNorm` (for level-1 proofs)
additionally enforces **norm-certificate structural consistency**: the on-chain
check validates mode, bound, and per-certificate fields; the ground-truth
infinity-norm re-computation stays off-chain (Rust `verify_level1_norm`).

`WithOpening` / `WithOpeningNorm` add the **commitment-opening (OP) check
(P12)**: the datum carries an `OpeningProof` (one salt per evaluation) and
`verify_slim_level1` recomputes the salted BLAKE2b-256 Merkle tree over the
claimed evaluations `(az_r, bz_r, cz_r, fr_r)` and `(er_r)`, comparing the roots
against the `com_w_hash` / `com_e_hash` from the datum.  The on-chain sumcheck
transcript is thereby bound to the committed witness and error.  Because the
Fiat-Shamir challenges are derived **commit-free** (from the transcript hash and
public input only), a well-formed proof is self-consistent by construction: the
commitment hashes are openings over the exact evaluations the sumcheck binds, so
there is no evals↔challenges fixed-point to resolve.

## Architecture

```
┌─────────────┐      ┌──────────────────┐      ┌─────────────────┐
│  NovaSlim   │      │   Aiken Validator │      │  Cardano Chain  │
│   (Rust)    │─────▶│  (this project)   │─────▶│  (eUTXO script) │
│             │      │                   │      │                 │
│ Fold +      │      │  • Sumcheck verify│      │  • Verify slim  │
│ Compress    │      │  • Fiat-Shamir    │      │    proof        │
│             │      │  • Final eval     │      │  • OP opening   │
│             │      │  • Level-1        │      │    check (P12)  │
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

`aiken check` runs 68 tests: unit, property (100 fuzz cases each), and golden
(seed `1070914076`):

```
   Collecting all tests scenarios across all modules
      Testing ...
    ┍━ tests ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    │ PASS [mem: 470.17 K, cpu: 194.06 M] e2e_4_rounds
    │ PASS [mem:  29.02 K, cpu:   9.29 M] empty_proof_rejected
    │ PASS [mem:  20.10 K, cpu:   6.39 M] challenges_without_rounds_rejected
    │ PASS [mem:  40.55 K, cpu:  17.85 M] mismatch_counts_fails
    │ PASS [mem:  44.44 K, cpu:  24.37 M] derive_challenges_is_deterministic
    │ PASS [mem:  45.04 K, cpu:  24.54 M] derive_challenges_depends_on_rounds
    │ PASS [mem:  45.04 K, cpu:  24.54 M] derive_challenges_depends_on_public_input
    │ PASS [mem: 360.12 K, cpu: 176.97 M] carried_wrong_challenges_rejected
    │ PASS [mem: 370.00 K, cpu: 180.46 M] single_wrong_challenge_rejected
    │ PASS [mem: 408.83 K, cpu: 194.48 M] l1_check_rejects_bad_fr_r
    │ PASS [mem: 406.27 K, cpu: 193.25 M] l1_check_rejects_zero_fr_r_with_terms
    │ PASS [after 100 tests] valid_transcript_always_verifies
    │ PASS [after 100 tests] tampered_round_poly_fails
    │ PASS [after 100 tests] tampered_final_value_fails
    │ PASS [after 100 tests] fs_tampered_challenge_fails
    │ PASS [after 100 tests] fs_tampered_public_input_fails
    │ PASS [after 100 tests] fs_tampered_transcript_hash_fails
    │ PASS [mem: 353.62 K, cpu: 176.03 M] fs_tampered_commit_modifies_derived_challenges_rejected
    │ PASS [after 100 tests] fs_l1_tampered_fr_r_fails
    │ PASS [after 100 tests] fs_l1_tampered_u_fails
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
    │ PASS [mem: 697.66 K, cpu: 288.75 M] verify_slim_with_norm_accepts
    │ PASS [mem: 629.05 K, cpu: 266.86 M] verify_slim_with_norm_rejects_bad_norm
    │ PASS [mem: 625.61 K, cpu: 266.16 M] datum_sum_only_accepts
    │ PASS [mem: 701.88 K, cpu: 290.25 M] datum_with_norm_accepts
    │ PASS [mem: 633.27 K, cpu: 268.36 M] datum_with_norm_rejects_bad_norm
    │ PASS [mem:  22.42 K, cpu:  12.82 M] golden_derive_single_round
    │ PASS [mem:  62.78 K, cpu:  42.55 M] golden_derive_four_zero_rounds
    │ PASS [mem:  49.31 K, cpu:  32.54 M] golden_derive_three_zero_rounds_prefix
    │ PASS [mem: 637.35 K, cpu: 270.77 M] golden_l1_fixed_proof
    │ PASS [mem: 320.34 K, cpu: 150.78 M] golden_l1_fixed_proof_constants
    │ PASS [mem: 406.27 K, cpu: 193.26 M] golden_l1_fixed_proof_tampered_rejected
    │ PASS [mem: 418.55 K, cpu: 158.62 M] golden_l1_all_zero_proof
    │ PASS [mem:   9.85 K, cpu:   6.75 M] golden_opening_leaf_values
    │ PASS [mem:  70.89 K, cpu:  23.95 M] golden_opening_root_single_and_two_leaves
    │ PASS [mem:  92.21 K, cpu:  31.71 M] golden_opening_root_padding
    │ PASS [mem: 181.61 K, cpu:  62.95 M] opening_root_is_deterministic
    │ PASS [mem:   5.73 K, cpu:   4.30 M] opening_leaf_is_salt_sensitive
    │ PASS [mem:   5.73 K, cpu:   4.30 M] opening_leaf_is_eval_sensitive
    │ PASS [mem:  90.82 K, cpu:  31.65 M] opening_root_is_order_sensitive
    │ PASS [mem:  28.94 K, cpu:  10.27 M] opening_root_single_leaf_is_leaf
    │ PASS [mem: 903.09 K, cpu: 367.76 M] golden_level1_fixed_proof
    │ PASS [mem: 897.90 K, cpu: 366.14 M] level1_valid_accepts
    │ PASS [mem: 861.23 K, cpu: 353.56 M] level1_tampered_w_salt_rejected
    │ PASS [mem: 900.69 K, cpu: 367.05 M] level1_tampered_e_salt_rejected
    │ PASS [mem: 777.56 K, cpu: 321.85 M] level1_empty_salts_rejected
    │ PASS [mem: 855.98 K, cpu: 351.77 M] level1_wrong_commit_roots_rejected
    │ PASS [mem: 971.48 K, cpu: 389.57 M] level1_with_norm_accepts
    │ PASS [mem: 902.87 K, cpu: 367.68 M] level1_with_norm_rejects_bad_norm
    │ PASS [mem: 907.11 K, cpu: 368.78 M] level1_with_norm_rejects_bad_opening
    │ PASS [mem: 902.42 K, cpu: 367.69 M] datum_with_opening_accepts
    │ PASS [mem: 977.10 K, cpu: 391.52 M] datum_with_opening_norm_accepts
    │ PASS [mem: 865.45 K, cpu: 355.06 M] datum_with_opening_rejects_bad_opening
    │ PASS [after 100 tests] level1_valid_always_verifies
    │ PASS [after 100 tests] level1_tampered_salt_fails
    │ PASS [after 100 tests] level1_wrong_commits_fail
    │ PASS [after 100 tests] level1_tampered_fr_r_fails
    ┕━━━━━━━━━━━━━━━━━━━━━━ with --seed=1070914076 → 68 tests | 68 passed | 0 failed
      Summary 1256 checks, 0 errors, 0 warnings
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
  **`fs_tampered_transcript_hash_fails`** — fuzz-driven: tampering a challenge,
  the public input, or the transcript hash is enough to break Fiat-Shamir
  binding and get the proof rejected.
- **`fs_tampered_commit_modifies_derived_challenges_rejected`** — changing a
  commitment hash does **not** change the derived challenges (Fiat-Shamir is
  commit-free), yet the proof still fails because the opening root no longer
  matches the datum.
- **`fs_l1_tampered_fr_r_fails`** / **`fs_l1_tampered_u_fails`** — fuzz-driven:
  altering the level-1 residual `fr_r` or the slack scalar `u` breaks the
  `fr_r == u·cz_r + er_r` check and the proof is rejected.
- **`golden_derive_*`** — golden vectors pin the exact `derive_challenges`
  output for fixed transcripts (single round, sequential zero rounds, prefix
  consistency) so any regression in the derivation is caught.
- **`golden_l1_fixed_proof`** / **`golden_l1_fixed_proof_constants`** —
  golden vectors pin `challenges`, `er_r`, and `fr_r` for
  `well_formed_proof(2, 3, 5)`.
- **`golden_l1_fixed_proof_tampered_rejected`** — a golden proof with `fr_r`
  incremented by 1 is rejected.
- **`golden_l1_all_zero_proof`** — the all-zero four-round proof carries
  `fr_r = 0`, consistent with `u = 1`, `cz = 0`, `er = 0`.
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

Opening (P12) tests — bind the sumcheck evaluations to the committed witness:

- **`golden_opening_leaf_values`** / **`golden_opening_root_single_and_two_leaves`**
  / **`golden_opening_root_padding`** — golden vectors pin `opening_leaf(_, _)`,
  the two/three-leaf roots, and the empty-leaf-padded root for the `(2, 3, 5)`
  canonical evals.
- **`opening_root_*`** / **`opening_leaf_*`** — property tests: the Merkle root
  is deterministic, order-sensitive (leaf order matters), salt-sensitive and
  eval-sensitive (distinct salts/evals ⇒ distinct leaves), and a single-eval
  root equals its leaf.
- **`golden_level1_fixed_proof`** — pins the exact `com_w_hash` / `com_e_hash`
  (Merkle roots) that a self-consistent `(2, 3, 5)` proof must commit to.
- **`level1_valid_accepts`** / **`level1_tampered_w_salt_rejected`** /
  **`level1_tampered_e_salt_rejected`** / **`level1_empty_salts_rejected`** /
  **`level1_wrong_commit_roots_rejected`** — `verify_slim_level1` accepts a
  well-formed opening and rejects any deviation in the W-salts, the E-salt,
  empty salt lists, or swapped commitment roots (the underlying sumcheck can
  still pass — only the OP layer fails).
- **`level1_with_norm_accepts`** / **`level1_with_norm_rejects_bad_norm`** /
  **`level1_with_norm_rejects_bad_opening`** — `WithOpeningNorm` dispatch:
  opening+norm accepted, bad norm rejected, bad opening rejected.
- **`datum_with_opening_accepts`** / **`datum_with_opening_norm_accepts`** /
  **`datum_with_opening_rejects_bad_opening`** — `NovaSlimDatum` dispatch for
  `WithOpening` / `WithOpeningNorm`; a bad opening in either is rejected.
- **`level1_valid_always_verifies`** / **`level1_tampered_salt_fails`** /
  **`level1_wrong_commits_fail`** / **`level1_tampered_fr_r_fails`** —
  fuzz-driven: any internally consistent level-1 proof with a matching opening
  verifies; tampering a salt, swapping the commitment roots, or altering `fr_r`
  each fail.

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
      Some(WithOpening(bundle, opening)) -> verify_slim_level1(bundle, redeemer, opening)
      Some(WithOpeningNorm(bundle, opening, norm)) -> verify_slim_level1_with_norm(bundle, redeemer, opening, norm)
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
| `WithOpening(NifsBundle, OpeningProof)` | `NifsBundle`, `OpeningProof` | Level-1 proof with commitment-opening (OP) check |
| `WithOpeningNorm(NifsBundle, OpeningProof, NormRecord)` | `NifsBundle`, `OpeningProof`, `NormRecord` | Level-1 proof with OP + norm-certificate checks |

### `NifsBundle`

| Field | Type | Description |
|---|---|---|
| `com_w_hash` | `ByteArray` | BLAKE2b-256 Merkle root over the witness-commitment leaves |
| `com_e_hash` | `ByteArray` | BLAKE2b-256 Merkle root over the error-commitment leaves |
| `transcript_hash` | `ByteArray` | Fiat-Shamir transcript hash from folding |

The `com_w_hash` / `com_e_hash` fields double as **commitment-opening roots**
(P12): when the datum uses a `WithOpening(..)` variant they are recomputed
on-chain from the level-1 evaluations and the `OpeningProof` salts, so the same
32-byte hashes that bind the transcript also bind the witness/error.

### `OpeningProof`

| Field | Type | Description |
|---|---|---|
| `w_salts` | `List<ByteArray>` | One salt per W-side evaluation `(az_r, bz_r, cz_r, fr_r)` |
| `e_salt` | `ByteArray` | Salt for the E-side evaluation `(er_r)` |

Each leaf is `blake2b_256(integer_to_bytearray(True, 32, eval mod p) || salt)`;
`opening_root` pads the leaf list to the next power of two with `empty_leaf()`
(hash of 32 zero bytes) and folds pairs with `blake2b_256(left || right)` until
one node remains.  A single-eval root is just its leaf.  The salts alone are the
opening proof — the Merkle tree is re-derived on-chain, so no explicit Merkle
paths travel in the datum.

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
| `fr_r` | `Scalar` | Claimed u·C·Z residual at r (level-1) |
| `public_input` | `ByteArray` | Public input x |
| `u` | `Scalar` | Slack scalar (usually 1) |

## How it works

1. **Round verification**: For each round *i*, check that
   `hᵢ(0) + hᵢ(1) == hᵢ₋₁(rᵢ₋₁)`. At least one round is required — degenerate
   proofs with zero rounds are rejected.

2. **Fiat-Shamir**: The challenges carried in the proof are enforced:
   `derive_challenges` re-derives the BLAKE2b-256 challenges from the NIFS
   bundle's `transcript_hash`, the round polynomials, and the public input,
   and `verify_slim` requires them to match the proof's `challenges` element
   for element.  A prover cannot smuggle in self-serving challenges.

   **Commit-free.** Challenge derivation does **not** include the commitment
   hashes `com_w_hash` / `com_e_hash`.  If it did, those hashes (roots over the
   proof's own evaluations) would have to feed the derivation of the challenges
   that determine those evaluations — a circular fixed-point with no stable
   solution.  With commit-free Fiat-Shamir, the commitment roots are instead
   *openings over the final evaluations*, and the whole proof is consistent by
   construction.  This matches the Rust prover, whose internal sumcheck
   Fiat-Shamir also hashes only the claims and round polynomials.

3. **Final evaluation**: Check that
   `azᵣ · bzᵣ - u · czᵣ - eᵣ == hₖ(rₖ)`.

4. **Level-1 residual**: For level-1 proofs, check that
   `fr_r == u · cz_r + er_r`, i.e. the residual `fr_r` of the MLE-of-product
   `u·C·Z` is exactly the combination of the slack scalar, the claimed `C·Z`
   evaluation, and the error evaluation.  This embeds the level-1 bound check
   into the sumcheck circuit; `fr_r` is committed to by the Fiat-Shamir
   boundary just like `er_r`.

5. **Commitment opening (OP, `verify_slim_level1`)**: For `WithOpening(..)`
   datum variants, recompute the Merkle roots
   `opening_root([az_r, bz_r, cz_r, fr_r], opening.w_salts)` and
   `opening_root([er_r], [opening.e_salt])` and require them to equal the
   datum's `com_w_hash` and `com_e_hash`.  This binds the claimed evaluations
   to the committed witness/error, closing the free-`E` attack that a bare
   sumcheck leaves open.

All arithmetic is performed in the **BLS12-381 scalar field** (`Fr`), which
Plutus V3 supports natively.  Field elements are encoded on the wire as
32-byte big-endian integers; byte strings are interpreted unsigned (the
`bytearray_to_integer(True, _)` / `integer_to_bytearray(True, 32, _)` builtins
use big-endian unsigned encoding, not two's-complement).

## Supported curves and commitments

This verifier is **field-agnostic at the type level** — it operates on
raw `Int` values modulo the BLS12-381 prime.  In practice, it is designed for
BLS12-381 (Cardano's native curve).  The same verifier works for slim proofs
produced with any of NovaSlim's three commitment schemes:

| Commitment | On-chain verifier | Off-chain audit |
|---|---|---|
| Pedersen | ✅ Sumcheck only (`SumOnly`) | Pedersen opening check |
| SIS | ✅ Sumcheck + norm cert (`WithNorm`) | SIS opening check + norm audit |
| Hash | ✅ Sumcheck + norm cert + OP opening (`WithOpening`) | Hash opening check + norm audit |

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
NovaSlim CLI but not yet implemented.  For P12, emitting the `OpeningProof`
salts (matching the leaf/root construction above) from the Rust prover is the
remaining integration step; today the salts are produced by the reference
Python mirror (`/tmp/opencode/p12_mirror.py`) and pinned by the golden tests.

## Project structure

```
.
├── aiken.toml              # Project manifest (aiken-lang/stdlib, aiken-lang/fuzz)
├── lib/
│   ├── verifier.ak         # Core sumcheck verification library + NovaSlimDatum + opening proofs
│   ├── norm.ak             # On-chain norm-certificate verification (level-1)
│   └── tests.ak            # Unit, property and golden tests
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
