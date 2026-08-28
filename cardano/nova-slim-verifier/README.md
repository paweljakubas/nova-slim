# NovaSlim On-Chain Verifier (Aiken)

An Aiken eUTXO validator for verifying NovaSlim slim proofs on Cardano.

## What this verifier does

This validator checks a **slim proof** — the sumcheck protocol only, with no
commitment openings.  It is **commitment-scheme agnostic**: the same on-chain
verifier works for all three NovaSlim commitment schemes (Pedersen, SIS, Hash)
because the on-chain check is purely the sumcheck protocol.  The commitment
binding is verified off-chain by auditors who check the HashPC truth tables
against the commitment hashes stored in the datum.

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

```
   Testing ...
{
  "summary": {
    "total": 2,
    "passed": 2,
    "failed": 0
  },
  "modules": [
    {
      "name": "tests",
      "summary": { "total": 2, "passed": 2, "failed": 0 },
      "tests": [
        {
          "title": "e2e_4_rounds",
          "status": "pass",
          "execution_units": { "mem": 376920, "cpu": 141185485 }
        },
        {
          "title": "mismatch_counts_fails",
          "status": "pass",
          "execution_units": { "mem": 25041, "cpu": 6508150 }
        }
      ]
    }
  ]
}
```

## Validator API

The validator checks a `spend` redemption where:
- **Datum** = `NifsBundle` (folded instance commitments)
- **Redeemer** = `SlimProof` (the slim sumcheck proof)

```aiken
validator nova_slim {
  spend(datum: Option<NifsBundle>, redeemer: SlimProof, _utxo: Data, _self: Data) {
    when datum is {
      Some(bundle) -> verify_slim(bundle, redeemer)
      None -> False
    }
  }
}
```

### Datum (`NifsBundle`)

| Field | Type | Description |
|---|---|---|
| `com_w_hash` | `ByteArray` | BLAKE2b-256 hash of witness commitment |
| `com_e_hash` | `ByteArray` | BLAKE2b-256 hash of error commitment |
| `transcript_hash` | `ByteArray` | Fiat-Shamir transcript hash from folding |

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
   `hᵢ(0) + hᵢ(1) == hᵢ₋₁(rᵢ₋₁)`.

2. **Fiat-Shamir**: Re-derive challenges from the NIFS bundle and round
   polynomials using BLAKE2b-256, and verify they match the proof.

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
| Pedersen | ✅ Sumcheck only | Pedersen opening check |
| SIS | ✅ Sumcheck only | SIS opening check |
| Hash | ✅ Sumcheck only | Hash opening check |

## Deployment

1. Build the validator:
```bash
aiken build
```

2. The blueprint is written to `plutus.json`.  Apply parameters
   using `aiken apply`:
```bash
aiken apply plutus.json \
  --parameter-bytes "<hex-encoded public input>" \
  > validator.uplc
```

3. Submit the UPLC to the Cardano chain via `cardano-cli` or your preferred
   wallet integration.

## Integration with NovaSlim

The Rust prover (`nova-slim`) outputs a slim proof as a CBOR-encoded byte
array.  Convert it to the Aiken `SlimProof` type before submitting:

```rust
// In your Rust off-chain code
let slim_proof_bytes = nova_slim_prover.generate_slim_proof(...);
// Serialize to Aiken's expected format (CBOR map)
```

A helper script for this conversion will be provided in the NovaSlim CLI
(`nova-slim export --format aiken`).

## Project structure

```
.
├── aiken.toml              # Project manifest
├── lib/
│   ├── verifier.ak         # Core sumcheck verification library
│   └── tests.ak            # Unit and e2e tests
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
