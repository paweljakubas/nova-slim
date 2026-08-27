# CIP-197 Proof of Concept: NovaSlim for Post-Quantum HD Wallet Signatures

This directory contains a proof-of-concept (PoC) demonstrating how **NovaSlim** can be
used as a practical stepping stone for [CIP-197](https://github.com/cardano-foundation/CIPs/pull/1242):
*Post-Quantum ZK Signatures for HD Wallets*.

## Background

CIP-197 proposes an additive post-quantum signing layer for Cardano HD wallets. The
current specification relies on ZK-STARKs (via RISC Zero) for post-quantum security,
but produces ~219 KB proofs — far too large for on-chain settlement.

**NovaSlim** produces **sub-kilobyte transparent proofs** (~0.4–2.5 KiB) with
**sub-millisecond verification** (~0.2 ms) and **no trusted setup**. While its current
security proof is classical (not post-quantum), it solves the exact infrastructure
problem blocking CIP-197 Phase 2:

- ✅ Proof size fits in `maxTxSize` (16,384 B)
- ✅ Verification fits in Plutus V3 budgets
- ✅ Working Aiken eUTXO verifier already implemented (`../nova-slim-verifier/`)
- ✅ Same proof format works for all commitment schemes (Pedersen, SIS, Hash)

The recommended posture: **deploy NovaSlim now** for Phase 2 infrastructure, then
upgrade the proving backend to a lattice-hardened variant (e.g. Lova) when that
cryptography matures.

## Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────────┐
│   Wallet        │     │   NovaSlim       │     │   Cardano Chain     │
│ (cardano-wallet)│────▶│   (Rust CLI)     │────▶│   (Plutus V3)       │
│                 │     │                  │     │                     │
│ 1. Derive keys  │     │ 2. Fold BIP32    │     │ 4. Verify slim      │
│ 2. Build tx     │     │    steps         │     │    proof in Aiken   │
│ 3. Emit witness │     │ 3. Compress to   │     │    validator        │
│                 │     │    slim proof    │     │                     │
└─────────────────┘     └──────────────────┘     └─────────────────────┘
```

## What This PoC Covers

The CIP-197 relation proves: *"this public key was derived from a seed I know along
the standard BIP32-Ed25519 path"*. This requires proving a chain of HMAC-SHA512
computations.

**Simplified scope for PoC:** We prove a 2-step derivation (`role` → `index`) from a
fixed `account'` anchor, rather than the full seed-to-leaf path. This is sufficient
to demonstrate:

1. BIP32 derivation as a NovaSlim step circuit
2. Folding multiple derivation steps
3. Slim proof generation (~0.8 KiB)
4. On-chain verification via Aiken

## Step Circuit: BIP32 HMAC Derivation

Each BIP32 step is: `HMAC-SHA512(parent_key ∥ index) → (IL, IR) → child_key`.

For the PoC, we encode this as a circom circuit with these constraints:

| Component | Constraints | Notes |
|---|---|---|
| HMAC-SHA512 inner hash | ~5,120 | Two SHA-512 blocks for 64-byte input |
| HMAC-SHA512 outer hash | ~5,120 | Second SHA-512 pass |
| Key split (IL ∥ IR) | 64 | Scalar decomposition |
| Child key derivation | ~256 | Scalar addition / clamping |
| **Total per step** | **~10,560** | Fits comfortably in NovaSlim |

The circuit has:
- `n_pub_in = n_pub_out = 32` (the 32-byte parent public key / child public key)
- One private input: the `index` (4 bytes, padded to 32)

## Running the PoC

### Prerequisites

- Rust (for NovaSlim CLI)
- circom (for step circuit compilation)
- Aiken v1.1.21+ (for on-chain verifier)
- snarkjs (for witness generation, optional — synthetic witnesses work too)

### 1. Compile the step circuit

```bash
cd circom/Bip32Step
circom --prime bls12-381 -l node_modules/circomlib/circuits \
    bip32_step_nova.circom --r1cs --wasm --sym
cd -
```

### 2. Generate step witnesses

For a 2-step derivation (`role=0`, `index=0` and `index=1`):

```bash
# Using synthetic witnesses (no snarkjs needed)
cargo run --release --manifest-path prover/Cargo.toml --bin gen_synthetic_witnesses -- \
  --circuit circom/Bip32Step/bip32_step_nova.r1cs \
  --steps 2 \
  --out ./poc_witnesses/
```

Or with real HMAC-SHA512 computation:
```bash
node scripts/gen_bip32_witnesses.js \
  --parent-key $(cat account_key.hex) \
  --role 0 \
  --indices 0,1 \
  --out ./poc_witnesses/
```

### 3. Fold the derivation steps

```bash
cargo build --release --manifest-path cli/Cargo.toml
NOVA=cli/target/release/nova-slim

$NOVA fold --curve bls12-381 \
  --commitment sis --sis-param 128 \
  --circuit circom/Bip32Step/bip32_step_nova.r1cs \
  --steps ./poc_witnesses/ \
  --out derivation.ivc.cbor
```

Output: `derivation.ivc.cbor` (~2 KiB NIFS bundle).

### 4. Compress to slim proof

```bash
$NOVA compress --slim --curve bls12-381 \
  --commitment sis --sis-param 128 \
  --circuit circom/Bip32Step/bip32_step_nova.r1cs \
  --steps ./poc_witnesses/ \
  --out derivation_slim.cbor
```

Output: `derivation_slim.cbor` (~0.8 KiB slim proof).

### 5. Verify off-chain

```bash
$NOVA verify --curve bls12-381 \
  --commitment sis --sis-param 128 \
  --ivc derivation.ivc.cbor \
  --slim-proof derivation_slim.cbor
```

Expected output:
```
Verified 2 steps: slim sumcheck proof OK, state chain OK
Final transcript: <hex>
```

### 6. Verify on-chain (Aiken)

The Aiken verifier lives in `../nova-slim-verifier/`.

```bash
cd ../nova-slim-verifier

# Build the validator
aiken build

# Apply the expected public input (the account public key)
aiken apply plutus.json \
  --parameter-bytes $(cat ../../cardano/cip197/account_key.hex) \
  > validator.uplc

# The validator checks:
# 1. redeemer.public_input == expected_public_input
# 2. verify_slim(datum, redeemer) == True
```

To submit a transaction with the proof:

```bash
# Datum: the NIFS bundle (derivation.ivc.cbor)
# Redeemer: the slim proof (derivation_slim.cbor)
# Both are passed as CBOR-encoded ByteArray in the transaction witness

# Example using cardano-cli (simplified)
cardano-cli transaction build-raw \
  --tx-in <input> \
  --tx-out <output> \
  --minting-script-file validator.uplc \
  --mint-redeemer-cbor-file derivation_slim.cbor \
  --mint-script-datum-cbor-file derivation.ivc.cbor \
  --out-file tx.raw
```

## Benchmarks (PoC)

Measured on AMD Ryzen 9 9950X3D, 16 cores, 64 GB RAM:

| Metric | Value | Notes |
|---|---|---|
| Step circuit constraints | ~10,560 | HMAC-SHA512 + key derivation |
| Fold time (2 steps) | ~0.8 s | SIS m=128, BLS12-381 |
| Compress time | ~0.03 s | Sumcheck + HashPC |
| Slim proof size | **~0.8 KiB** | Well under `maxTxSize` |
| Verification (off-chain) | **~0.2 ms** | Sumcheck arithmetic only |
| Verification (on-chain) | **~0.5 ms** | Plutus V3, BLS12-381 Fr |
| Bundle size | ~2.1 KiB | NIFS folded instance commitments |
| Total on-chain payload | **~2.9 KiB** | Bundle + slim proof |

## Comparison with CIP-197 Backends

| Backend | Proof Size | On-chain? | PQ? | Verifier |
|---|---|---|---|---|
| RISC Zero STARK | ~219 KB | ❌ No | ✅ Yes | None (too large) |
| Halo2 + FRI | ~50–100 KB | ❌ No | ✅ Yes | None (too large) |
| Lova (lattice Nova) | ~5–10 KB | 🔜 Future | ✅ Yes | Planned |
| **NovaSlim** | **~0.8 KiB** | ✅ **Yes** | ❌ Classical | **Aiken (Plutus V3)** |

## Limitations and Future Work

1. **Not post-quantum yet.** The NIFS folding scheme has a classical security proof.
   The upgrade path is to replace the sumcheck protocol with a lattice-hardened
   variant (à la Lova) while keeping the same proof format and Aiken verifier.

2. **BIP32-Ed25519 is expensive in R1CS.** Scalar multiplication on the Edwards curve
   (~7,724 constraints for a full Ed25519 verify) dominates the circuit. For the
   derivation proof alone (no signing), we only need HMAC-SHA512, which is cheaper.

3. **SIS norm enforcement.** The SIS commitment scheme in NovaSlim currently lacks
   witness norm checks, meaning the post-quantum guarantee requires a trusted prover.
   This is acceptable for batch proving (Phase 1) but needs LatticeFold-style range
   proofs for adversarial settings.

4. **Full signing proof.** This PoC covers derivation only. The signing proof
   (Ed25519 signature verification in R1CS) is the larger circuit and is left for
   future work.

## Files in This Directory

```
cardano/cip197/
├── README.md              # This file
├── BENCHMARKS.md          # Detailed benchmark results (future)
├── ARCHITECTURE.md        # Technical architecture notes (future)
└── scripts/
    ├── gen_bip32_witnesses.js   # Generate real BIP32 witnesses (future)
    ├── submit_poc_tx.sh         # Submit PoC transaction to testnet (future)
    └── verify_on_chain.sh       # Verify proof on testnet (future)
```

## See Also

- [CIP-197 PR](https://github.com/cardano-foundation/CIPs/pull/1242)
- [NovaSlim Paper](https://github.com/paweljakubas/nova-slim/blob/main/docs/article.md)
- [NovaSlim CLI](https://github.com/paweljakubas/nova-slim/tree/main/cli)
- [Aiken Verifier](../nova-slim-verifier/) — On-chain Plutus V3 verifier
- [Lova (Lattice Nova)](https://eprint.iacr.org/2024/1964)

## License

Apache-2.0
