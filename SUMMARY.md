# NovaSlim — Summary

> **Sub-kilobyte transparent proofs for on-chain verification. No trusted setup. No curve cycle.**

## What is NovaSlim?

NovaSlim is a folding proof system that compresses long computations into tiny proofs
(~0.4–2.5 KiB) that verify on-chain in under 1 ms.

It works on a **single standard curve** (e.g. BLS12-381, BN254) — no need for a curve
cycle or second curve to verify folding steps in-circuit.

## What problem does it solve?

| Problem | NovaSlim fix |
|---|---|
| zkSNARK proofs are too big for blockchains | Slim proofs: **~0.4–1.5 KiB** |
| zkSNARKs need trusted setup | **No trusted setup** — transparent |
| Folding schemes need a curve cycle | **Single curve** — off-circuit folding |
| On-chain verification is expensive | **0.1–1.0 ms** — just sumcheck arithmetic |
| Post-quantum proofs are ~219 KB | SIS commitment: **~10–12 KiB** (conjectured PQ) |

## Key numbers

| Metric | Value |
|---|---|
| Slim proof size | **0.4–1.5 KiB** (Pedersen / Hash) |
| Total on-chain payload | **~3–4 KiB** (bundle + slim proof) |
| Verification time (off-chain) | **0.1–1.0 ms** |
| Verification time (on-chain, Plutus V3) | **~377K mem / ~141M CPU** |
| Fold time (2 steps, BLS12-381, SIS m=128) | **~0.3 s** |
| No trusted setup | ✅ |
| No curve cycle | ✅ |
| Fits Cardano `maxTxSize` (16,384 B) | ✅ |

## Quick start (30 seconds)

```bash
# Clone
git clone https://github.com/paweljakubas/nova-slim.git
cd nova-slim

# Build
cargo build --release --manifest-path cli/Cargo.toml

# Check a circuit
./cli/target/release/nova-slim params \
  --curve bls12-381 \
  --circuit circom/VRF/vrf_verify_nova.circom

# Run fold → compress → verify
./cli/target/release/nova-slim fold \
  --curve bls12-381 --commitment sis --sis-param 128 \
  --circuit <circuit.r1cs> --steps <witness-dir>/ \
  --out bundle.ivc.cbor

./cli/target/release/nova-slim compress --slim \
  --curve bls12-381 --commitment sis --sis-param 128 \
  --circuit <circuit.r1cs> --steps <witness-dir>/ \
  --out slim.proof.cbor

./cli/target/release/nova-slim verify \
  --curve bls12-381 --commitment sis --sis-param 128 \
  --ivc bundle.ivc.cbor --slim-proof slim.proof.cbor
```

**See [E2E.md](cardano/cip197/E2E.md) for the complete step-by-step walkthrough.**

## What's in this repo?

```
nova-slim/
├── README.md              ← Main project README (this is at root)
├── SUMMARY.md             ← This file
├── LICENSE                ← Apache-2.0
├──
├── cli/                   ← Command-line interface (Rust)
│   ├── src/               ← CLI source code
│   └── README.md          ← CLI usage guide
│
├── prover/                ← Core proving library (Rust)
│   └── src/               ← NIFS, sumcheck, commitment schemes
│
├── circom/                ← Step circuits
│   ├── VRF/               ← VRF scalar multiplication (9 constraints)
│   ├── Ed25519Verify/     ← Ed25519 verification (7,724 constraints)
│   ├── Sha256Step/        ← SHA-256 step circuits
│   ├── PoseidonSponge/    ← Poseidon hash circuits
│   └── PoseidonMerkle/    ← Poseidon Merkle tree circuits
│
├── benchmarks/            ← Benchmark scripts
│   ├── run_benchmarks.py  ← Main benchmark runner
│   ├── gen_vrf_witnesses.py
│   └── gen_sha256_witnesses.py
│
└── cardano/               ← Cardano / CIP-197 integration
    ├── cip197/
    │   ├── README.md      ← CIP-197 PoC documentation
    │   ├── E2E.md         ← End-to-end walkthrough with mermaid diagrams
    │   └── cardano_keys/  ← Real BIP32 key derivations (public keys only)
    └── nova-slim-verifier/  ← Aiken on-chain verifier (Plutus V3)
        ├── lib/           ← Sumcheck verification library
        ├── validators/    ← On-chain validator
        └── README.md      ← Aiken verifier docs
```

## Supported curves (6)

| Curve | Prime bits | Use case |
|---|---|---|
| **BLS12-381** | 381 | Cardano, Filecoin |
| **BN254** | 254 | Ethereum, Polygon |
| **Pallas** | 255 | Zcash Orchard |
| **Vesta** | 255 | Pasta cycle (Pallas complement) |
| **Grumpkin** | 254 | BN254 complement |
| **Bandersnatch** | 255 | BLS12-381 companion |

## Supported commitment schemes (3)

| Scheme | Speed | Size | PQ? |
|---|---|---|---|
| **Pedersen** | Baseline | ~0.4 KiB | ❌ Classical |
| **SIS (m=4)** | **~8× faster** than Pedersen | ~0.4 KiB | ⚠️ Conjectured |
| **SIS (m=128)** | ~1.2× faster than Pedersen | larger | ⚠️ Conjectured |
| **Hash** | ~1× Pedersen (no faster) | ~0.4 KiB | ⚠️ Conjectured |

Freshly measured on this box (4-core; bls12-381, 254 steps):
Pedersen 4.1, SIS m=4 0.53, Hash 4.8, SIS m=128 3.3 ms/step fold. The
previously-published "14×  / 7× faster" figures came from the old 16-core
machine and are not reproduced — Hash is *not* faster than Pedersen here.

## How to navigate

| Goal | Go to |
|---|---|
| Run the CLI | `cli/README.md` |
| See end-to-end walkthrough | `cardano/cip197/E2E.md` |
| Build the Aiken verifier | `cardano/nova-slim-verifier/README.md` |
| Reproduce benchmarks | `benchmarks/run_benchmarks.py` |
| See CIP-197 PoC | `cardano/cip197/README.md` |

## Paper

- **Title:** NovaSlim: Practical Folding Proofs with Slim On-Chain Proofs and Post-Quantum Commitment Modularity
- **Venue:** Targeting IACR CiC (Volume 3, Issue 4, Oct 26 2026)
- **Status:** Paper source is maintained in a separate private repository
- **Length:** ~25–30 pages (long paper, up to 40 pages allowed)

## Security

- ✅ **Classical security proof** (Theorem 1 in ROM) — complete
- ⚠️ **Post-quantum** — conjectured for SIS/Hash commitments; QROM proof is future work
- ℹ️ **SIS norm caveat** — witness norm checks not enforced (acceptable for batch proving)

## License

Apache-2.0 — Copyright 2026 Pawel Jakubas

## Contact

- GitHub: `github.com/paweljakubas/nova-slim`
- CIP-197 PR: `github.com/cardano-foundation/CIPs/pull/1242`
