# CIP-197 Proof of Concept: NovaSlim for Post-Quantum HD Wallet Signatures

> 🚀 **Quick start:** See [E2E.md](E2E.md) for a step-by-step walkthrough with
> mermaid diagrams, copy-paste commands, and file-size expectations at every stage.
> To prove the two demonstration ways (E2E.md vs this README) are equivalent,
> run `bash scripts/e2e_equivalence.sh`.

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

**Runnable today — the VRF stand-in.** The full BIP32-Ed25519 step circuit is not
built yet (see below). The runnable PoC instead steps a small circuit — one bit of
JubJub scalar multiplication, `circom/VRF/vrf_verify_nova.circom` — which exercises
the exact infrastructure CIP-197 needs:

1. Real BIP32 key derivation on an HD wallet via `cardano-address` (the account
   and address public keys are the values a final BIP32 circuit would certify)
2. Folding multiple derivation steps with NovaSlim
3. Slim proof generation (~0.4 KiB)
4. Off-chain and on-chain (Aiken, Plutus V3) verification

**Future — the BIP32 derivation circuit.** Proving `role → index` BIP32-Ed25519
derivation (HMAC-SHA512 in R1CS) directly. Until it exists, the VRF circuit is the
stand-in that exercises the same NovaSlim pipeline. See "Step Circuit" below.

## Step Circuit (Future): BIP32 HMAC Derivation

Each BIP32 step is: `HMAC-SHA512(parent_key ∥ index) → (IL, IR) → child_key`.

For the PoC, we intend to encode this as a circom circuit with these constraints:

| Component | Constraints | Notes |
|---|---|---|
| HMAC-SHA512 inner hash | ~5,120 | Two SHA-512 blocks for 64-byte input |
| HMAC-SHA512 outer hash | ~5,120 | Second SHA-512 pass |
| Key split (IL ∥ IR) | 64 | Scalar decomposition |
| Child key derivation | ~256 | Scalar addition / clamping |
| **Total per step** | **~10,560** | Fits comfortably in NovaSlim |

The circuit would have:
- `n_pub_in = n_pub_out = 32` (the 32-byte parent public key / child public key)
- One private input: the `index` (4 bytes, padded to 32)

> **Not yet implemented.** `circom/Bip32Step/` does not exist yet. The runnable
> stand-in circuit is `circom/VRF/vrf_verify_nova.circom` (4 public I/O, ~0
> constraints, one JubJub ladder bit per step) — see E2E.md and the two ways
> below.

## Running the PoC — Two Equivalent Ways

There are two documented ways to demonstrate the PoC. They compile the **same
step circuit**, feed the **same NovaSlim pipeline**, and differ only in a few
interchangeable flags:

| | **Way II — E2E.md** | **Way I — this README** |
|---|---|---|
| Step circuit | `circom/VRF/vrf_verify_nova.circom` | same |
| Key provenance | real `cardano-address` BIP32 keys | synthetic step witnesses |
| circom prime | default (`bn128`) | `--prime bls12381` |
| `--curve` | `bn254` | `bls12-381` |
| Commitment | SIS m=128 | SIS m=128 (or Pedersen) |
| Proof size | ~0.4 KiB slim | ~0.4 KiB slim |
| On-chain (Aiken) | not supported¹ | ✅ `../nova-slim-verifier` |

¹ The Aiken verifier (`../nova-slim-verifier/`) is written for the **BLS12-381
scalar field**. Way I is therefore the on-chain flavour; Way II exists for the
off-chain demo (same pipeline, faster constants).

### Equivalence test

```bash
bash cardano/cip197/scripts/e2e_equivalence.sh 5
```

This script runs **both** ways end-to-end (`circom` compile → witness generation →
`fold` → `compress --slim` → `verify`) — 5 steps each — and asserts that:

- every stage succeeds for **both** ways, producing identical-size artifacts,
- tampered inputs (corrupted step witness, flipped proof byte) are rejected in
  **both** ways,
- the knobs the two docs pick are **interchangeable**: Pedersen instead of SIS,
  full sumcheck proof instead of slim, and a proof never verifies a bundle it was
  not created for.

It prints e.g. `Way I (bls12-381): bundle 8845 B, slim 388 B | Way II (bn254):
bundle 8845 B, slim 388 B` and a `RESULT: N passed, 0 failed` verdict.

The same equivalence is enforced by the repo's test suite:
`cargo test --manifest-path cli/Cargo.toml --test cli -- cip197_e2e_ways_are_equivalent_and_interchangeable`
(synthetic circuit, no circom needed).

### At a glance (both ways use these steps)

```bash
cd cardano/cip197

# 1. Compile the step circuit (Way II: default prime; Way I: add --prime bls12381)
circom -l ../../circom/Ed25519Verify/node_modules/circomlib/circuits \
  ../../circom/VRF/vrf_verify_nova.circom --r1cs --wasm --sym

# 2. Generate the step-witness chain
python3 ../../benchmarks/gen_vrf_witnesses.py \
  --wasm vrf_verify_nova_js/vrf_verify_nova.wasm --steps 5 --dir poc_witnesses

# 3. Fold → compress --slim → verify (Way I uses --curve bls12-381)
nova-slim fold     --curve bn254 --commitment sis --sis-param 128 \
  --circuit vrf_verify_nova.r1cs --steps poc_witnesses --out vrf.ivc.cbor
nova-slim compress --slim --curve bn254 --commitment sis --sis-param 128 \
  --circuit vrf_verify_nova.r1cs --steps poc_witnesses --out vrf_slim.cbor
nova-slim verify   --curve bn254 --commitment sis --sis-param 128 \
  --ivc vrf.ivc.cbor --slim-proof vrf_slim.cbor
# → "Verified 5 steps: slim sumcheck proof OK, state chain OK"
```

### Prerequisites

- Rust (for NovaSlim CLI, built from `cli/` with `cargo build --release`)
- circom
- snarkjs (witness generation via `benchmarks/gen_vrf_witnesses.py`)
- Aiken v1.1.19+ (on-chain verifier, `../nova-slim-verifier/`)
- `cardano-address` v4.0.0+ (optional — real key derivation, Way II only)

## Benchmarks (PoC)

**Actual results** from running the VRF step circuit (5 steps, BN254, SIS m=128).

| Metric | Value | Notes |
|---|---|---|
| Step circuit | VRF scalar mul (JubJub) | 0 linear constraints, 4 public I/O |
| Fold time (5 steps) | **78 ms** | SIS m=128, BN254 |
| Compress time (slim) | **127 ms** | Sumcheck + HashPC |
| Slim proof size | **388 bytes** | 96% reduction from full (9,770 B) |
| Verification (slim, off-chain) | **8 ms** | Sumcheck arithmetic only |
| Verification (full, off-chain) | **57 ms** | Includes commitment checks |
| Bundle size | 8.7 KiB | NIFS folded instance commitments |
| **Total on-chain payload** | **~9.1 KiB** | Bundle + slim proof |

**Key finding:** The total on-chain payload is **~9.1 KiB**, well under Cardano's
`maxTxSize` (16,384 B). This proves Phase 2 is feasible with NovaSlim today.

*Projected BIP32-Ed25519 figures (based on constraint count estimates):*

| Metric | Projected | Basis |
|---|---|---|
| Step circuit constraints | ~10,560 | HMAC-SHA512 + key derivation |
| Fold time (2 steps) | ~0.3 s | SIS m=128, BLS12-381 |
| Slim proof size | ~0.8 KiB | Sumcheck rounds = log₂(10,560) ≈ 14 |
| Total on-chain payload | ~3–4 KiB | Bundle (~2 KiB) + slim proof |

## Comparison with CIP-197 Backends

| Backend | Proof Size | On-chain? | PQ? | Verifier |
|---|---|---|---|---|
| RISC Zero STARK | ~219 KB | ❌ No | ✅ Yes | None (too large) |
| Halo2 + FRI | ~50–100 KB | ❌ No | ✅ Yes | None (too large) |
| Lova (lattice Nova) | ~5–10 KB | 🔜 Future | ✅ Yes | Planned |
| **NovaSlim** | **~0.8 KiB** | ✅ **Yes** | ⚠️ **Conjectured** (SIS/Hash) | **Aiken (Plutus V3)** |

## Limitations and Future Work

1. **BIP32 step circuit not implemented yet.** The runnable PoC uses the VRF
   stand-in circuit (`circom/VRF/vrf_verify_nova.circom`) to exercise the
   pipeline; the actual derivation circuit is the next build step.

2. **Not post-quantum yet.** The NIFS folding scheme has a classical security proof.
   The upgrade path is to replace the sumcheck protocol with a lattice-hardened
   variant (à la Lova) while keeping the same proof format and Aiken verifier.

3. **BIP32-Ed25519 is expensive in R1CS.** Scalar multiplication on the Edwards curve
   (~7,724 constraints for a full Ed25519 verify) dominates the circuit. For the
   derivation proof alone (no signing), we only need HMAC-SHA512, which is cheaper.

4. **SIS norm enforcement.** The SIS commitment scheme in NovaSlim currently lacks
   witness norm checks, meaning the post-quantum guarantee requires a trusted prover.
   This is acceptable for batch proving (Phase 1) but needs LatticeFold-style range
   proofs for adversarial settings.

5. **Full signing proof.** This PoC covers derivation only. The signing proof
   (Ed25519 signature verification in R1CS) is the larger circuit and is left for
   future work.

## Files in This Directory

```
cardano/cip197/
├── README.md              # This file (concept + benchmarks + two ways)
├── E2E.md                 # 🚀 Step-by-step walkthrough with mermaid diagrams
├── scripts/
│   └── e2e_equivalence.sh # Equivalence test for the two demonstration ways
├── cardano_keys/          # Real BIP32 key derivations via cardano-address
│   ├── DERIVATION.md      # Key derivation log (paths + public key hex)
│   ├── acct.xpub          # Account extended public key (m/1852'/1815'/0')
│   ├── addr.xpub          # Address extended public key (m/1852'/1815'/0'/0/0)
│   └── (root/acct/addr xprv + recovery phrase — git-ignored, not committed)
```

*Planned but not yet present: `BENCHMARKS.md`, `ARCHITECTURE.md`, and the true
BIP32 step circuit (`circom/Bip32Step/`).*

## See Also

- [CIP-197 PR](https://github.com/cardano-foundation/CIPs/pull/1242)
- [NovaSlim CLI](https://github.com/paweljakubas/nova-slim/tree/main/cli)
- [Aiken Verifier](../nova-slim-verifier/) — On-chain Plutus V3 verifier
- [Lova (Lattice Nova)](https://eprint.iacr.org/2024/1964)

## License

Apache-2.0
