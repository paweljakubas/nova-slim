# NovaSlim

Transparent folding-scheme proofs sized for on-chain verification:
NIFS-fold a chain of identical step circuits into one accumulator, compress
with a sumcheck argument, and verify a **~2.5 KiB** proof with **no pairing,
no trusted setup, and sub-millisecond verification**.

Supports **BLS12-381** (Cardano), **BN254** (Ethereum), **Pallas** (Zcash), and **Vesta** (the other half of the Pallas/Vesta cycle).

```
nova-slim params   → inspect a step circuit (n_pub_in must equal n_pub_out)
nova-slim fold     → NIFS-fold N step witnesses into one O(1) bundle
nova-slim compress → sumcheck compression (--slim for the on-chain variant)
nova-slim verify   → check bundle + proof (slim: ~0.5 ms)
```

Step circuits are bundled locally in `circom/CardanoKeyOwnership` and
`circom/Ed25519Verify` (originally from [cardano-foundation/bls](https://github.com/cardano-foundation/bls)).

## Layout

| Path | What |
|---|---|
| `prover/` | Core library: R1CS loading, NIFS folding, sumcheck compression, slim proofs ([README](prover/README.md)) |
| `cli/` | The `nova-slim` CLI ([README](cli/README.md)) |
| `benchmarks/` | Benchmark harness over real circom circuits |
| `docs/article.md` | NovaSlim paper draft |

## End-to-end run

Prerequisites: Rust, [circom](https://github.com/iden3/circom) (only if the
`.r1cs` is not compiled yet), [snarkjs](https://github.com/iden3/snarkjs) (witness generation), Node.js.

```bash
# 1. Build the CLI
cargo build --release --manifest-path cli/Cargo.toml
NOVA=cli/target/release/nova-slim

# 2. Compile the step circuit (once; pre-compiled .r1cs is shipped in circom/)
#    Choose the curve: bls12381, bn128, pallas, or vesta
cd circom/Ed25519Verify
circom --prime bn128 -l node_modules/circomlib/circuits \
    ed25519_verify_nova.circom --r1cs --wasm --sym
cd -

# 3. Generate chained step witnesses (see benchmarks/gen_step_witnesses.py)

# 4. Inspect the step circuit — must report n_pub_in == n_pub_out == 24
$NOVA params --curve bn254 --circuit circom/Ed25519Verify/ed25519_verify_nova.r1cs

# 5. Fold 255 steps into one transparent bundle (~2 min)
$NOVA fold --curve bn254 --circuit circom/Ed25519Verify/ed25519_verify_nova.r1cs \
    --steps <witness-dir> --out ed25519.ivc.cbor

# 6a. On-chain path: slim proof (~2.5 KiB CBOR, no openings)
$NOVA compress --slim --curve bn254 --circuit ... --steps <witness-dir> --out ed25519_slim.proof.cbor
$NOVA verify --curve bn254 --ivc ed25519.ivc.cbor --slim-proof ed25519_slim.proof.cbor

# 6b. Audit path: full sumcheck proof (~240 KiB, includes HashPC openings)
$NOVA compress --curve bn254 --circuit ... --steps <witness-dir> --out ed25519_full.proof.cbor
$NOVA verify --curve bn254 --ivc ed25519.ivc.cbor --sumcheck-proof ed25519_full.proof.cbor
```

## Testing

<details>
<summary><b>How to run the test suites</b></summary>

```bash
# Library tests (65 tests)
cargo test --release --manifest-path prover/Cargo.toml

# CLI integration tests (15 tests; includes real-circuit end-to-end flows)
cargo test --release --manifest-path cli/Cargo.toml
```

Notes:

- **Use `--release`** — debug builds are impractically slow on the real
  7,724-constraint step circuits (>10 min vs ~90 s).
- Witness generation inside tests uses `snarkjs`; without it only the
  synthetic-circuit tests run.

</details>

## Benchmarks

<details>
<summary><b>Measured numbers and how to reproduce them</b></summary>

We provide two kinds of benchmarks:

| Kind | What it measures | Curves available |
|---|---|---|
| **Traditional** (real circom circuits) | Full end-to-end flow: compile → generate witnesses with snarkjs → fold → compress → verify | **BLS12-381, BN254** |
| **Synthetic** (in-memory random witnesses) | Fold → compress → verify only (no snarkjs) | **BLS12-381, BN254, Pallas, Vesta** |

### Traditional benchmarks (real circuits)

These use the bundled `circom/` step circuits and snarkjs for witness
generation. Pallas and Vesta are **not available** here because snarkjs does
not yet support pasta-curve witness generation.

Latest run (2026-08-24, 4-core desktop, release build, 255 chained steps):

| Step circuit | Curve | Constraints | Steps | Fold total | Fold/step | Compress | Verify (full) | Verify (slim) | Slim proof | Bundle |
|---|---|---|---|---|---|---|---|---|---|---|
| `cardano_ed25519_ownership_nova` | bls12-381 | 7,724 | 255 | 141.2 / 139.1 s | 554 / 546 ms | 28.02 / 21.62 s | 26.77 / 21.84 s | **0.9 ms** | **2.5 KiB** | 2.2 KiB |
| `ed25519_verify_nova` | bls12-381 | 7,724 | 255 | 138.5 / 145.7 s | 543 / 571 ms | 25.44 / 24.30 s | 28.59 / 25.49 s | **0.7 ms** | **2.5 KiB** | 2.2 KiB |
| `ed25519_verify_nova` | bn254 | 7,724 | 255 | 74.2 / 66.7 s | 347 / 312 ms | 12.23 / 11.14 s | 12.22 / 11.53 s | **0.6 ms** | **2.4 KiB** | 2.2 KiB |

*Each cell shows baseline / `--opt-parallel` where two values are shown.
The slim proof is constant in step count and step width. Artifacts use a
compact CBOR encoding (field elements as 32-byte little-endian values,
sizes shown for CBOR; the legacy decimal/hex JSON encoding is ~2.6× larger).*

Run them with:

```bash
python3 benchmarks/run_benchmarks.py                    # all families, 255 steps
python3 benchmarks/run_benchmarks.py --family ed25519_verify_nova_bls12_381
python3 benchmarks/run_benchmarks.py --curve bn254      # specific curve
python3 benchmarks/run_benchmarks.py --steps 32         # shorter chains
```

The harness compiles circuits from `circom/` if needed, generates resumable
step witnesses via snarkjs, then measures baseline and parallel passes of
`benchmark_nova --release`. Raw logs land in `benchmarks/results/<timestamp>/`.

### Synthetic benchmarks (all curves)

These skip circom/snarkjs entirely and generate random in-memory witnesses.
Useful for comparing curve performance when real-circuit witnesses are not
available (e.g. Pallas / Vesta).

```bash
# BLS12-381
cargo run --release --manifest-path prover/Cargo.toml --bin benchmark_synthetic -- --curve bls12-381 --state-width 24 --steps 255

# BN254
cargo run --release --manifest-path prover/Cargo.toml --bin benchmark_synthetic -- --curve bn254 --state-width 24 --steps 255

# Pallas
cargo run --release --manifest-path prover/Cargo.toml --bin benchmark_synthetic -- --curve pallas --state-width 24 --steps 255

# Vesta
cargo run --release --manifest-path prover/Cargo.toml --bin benchmark_synthetic -- --curve vesta --state-width 24 --steps 255
```

All four curves complete fold → compress → verify end-to-end in the synthetic
harness.

</details>
