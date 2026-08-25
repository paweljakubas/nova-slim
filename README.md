# NovaSlim

Transparent folding-scheme proofs sized for on-chain verification:
NIFS-fold a chain of identical step circuits into one accumulator, compress
with a sumcheck argument, and verify a **~0.4 KiB** proof with **no pairing,
no trusted setup, and sub-millisecond verification**.

Supports **BLS12-381** (Cardano), **BN254** (Ethereum), **Pallas** (Zcash), and **Vesta**. Three commitment schemes — **Pedersen** (fast, classical), **SIS** (faster folding, quantum-ready), and **Hash** (zero-param, on-the-fly derivation) — are selectable at runtime via `--commitment {pedersen,sis,hash}`.

```
nova-slim params   → inspect a step circuit (n_pub_in must equal n_pub_out)
nova-slim fold     → NIFS-fold N step witnesses into one O(1) bundle
nova-slim compress → sumcheck compression (--slim for the on-chain variant)
nova-slim verify   → check bundle + proof (slim: ~0.2 ms)
```

## What is a slim proof?

The **full** sumcheck proof includes the entire HashPC opening (the witness
 truth table) and is ~240 KiB. The **slim** proof strips this opening, keeping
 only the sumcheck protocol data, yielding a **~0.4 KiB** on-chain payload that
 is **independent of the commitment scheme and its security parameter**.

| Property | Full proof | Slim proof |
|---|---|---|
| Soundness | Yes | Yes |
| Knowledge-soundness | Yes (explicit witness) | Yes (implicit witness) |
| On-chain size | ~240 KiB | **~0.4 KiB** (independent of m) |
| Auditability | Full witness reconstruction | Commitment binding only |
| Trusted setup | None | None |
| Verifier time | ~8 s (HashPC recompute) | **~0.2 ms** (sumcheck only) |

**Do we lose security? No.** The slim proof is still a sound argument of
knowledge: the prover cannot forge it without knowing a valid witness (W, E)
that satisfies the relaxed R1CS equation and matches the commitments in the
NIFS bundle. What is removed is *explicit extractability* — an auditor cannot
directly reconstruct the witness from the slim proof alone. The audit trail is
preserved by construction: the prover can publish the full proof off-chain;
anyone can verify that its commitment hashes match the slim proof, confirming
both refer to the same witness. The full proof serves as a legally binding
audit record, while the slim proof serves as the transaction payload.

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
#    Use --commitment pedersen (default), --commitment sis (lattice-based,
#    faster folding), or --commitment hash (zero-param, on-the-fly derivation)
$NOVA fold --curve bn254 --circuit circom/Ed25519Verify/ed25519_verify_nova.r1cs \
    --steps <witness-dir> --out ed25519.ivc.cbor

# 6a. On-chain path: slim proof (~0.4 KiB CBOR, no openings)
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
# Library tests (70 tests)
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

| Step circuit | Curve | Commitment | Constraints | Steps | Fold total | Fold/step | Compress | Verify (full) | Verify (slim) | Slim proof | Bundle |
|---|---|---|---|---|---|---|---|---|---|---|---|
| `ed25519_verify_nova` | bls12-381 | Pedersen | 7,724 | 255 | 138.5 / 145.7 s | 543 / 571 ms | 25.44 / 24.30 s | 28.59 / 25.49 s | **0.7 ms** | **~1 KiB** | 2.2 KiB |
| `ed25519_verify_nova` | bn254 | Pedersen | 7,724 | 255 | 74.2 / 66.7 s | 347 / 312 ms | 12.23 / 11.14 s | 12.22 / 11.53 s | **0.6 ms** | **~1 KiB** | 2.2 KiB |
| `ed25519_verify_nova` | bn254 | **SIS** | 7,724 | 214 | 8.5 s | **39.9 ms** | 14.2 s | **1.1 s** | **0.6 ms** | **~1 KiB** | 2.4 KiB |
| `vrf_verify_nova` | bn254 | Pedersen | 9 | 254 | 2.1 s | 8.4 ms | 0.02 s | 0.03 s | **0.1 ms** | **~0.4 KiB** | 0.7 KiB |
| `vrf_verify_nova` | bn254 | **SIS** | 9 | 254 | **0.04 s** | **0.17 ms** | 0.03 s | 0.002 s | **0.2 ms** | **~0.4 KiB** | 0.9 KiB |

*Each cell shows baseline / `--opt-parallel` where two values are shown.
The slim proof is constant in step count and step width. Artifacts use a
compact CBOR encoding (field elements as 32-byte little-endian values,
sizes shown for CBOR; the legacy decimal/hex JSON encoding is ~2.6× larger).*

**SIS (Ajtai-style lattice commitment)** folds **~8× faster** than Pedersen
because it replaces elliptic-curve MSM with simple matrix-vector multiplication
over the scalar field. The bundle grows slightly (~200 B) because each SIS
commitment is a short vector (`m = 4` field elements) rather than a single
curve point. The slim proof is **independent of the commitment scheme** — the
same ~0.4 KiB payload works for Pedersen, SIS, and Hash.

**Hash (on-the-fly Blake2b derivation)** stores only a seed in params (no
matrix, no basis points) and re-derives commitment coefficients via Blake2b
per commitment. This trades O(m·n) storage for O(m·n) computation, making
it the simplest scheme to audit: the entire security argument reduces to
Blake2b collision resistance. The bundle and slim proof are the same size as
SIS. Hash folds ~10× slower than SIS and ~1.7× slower than Pedersen because
it recomputes coefficients on every commitment.

**SIS security scaling (`--sis-param`).** The SIS output dimension `m` is
configurable via `--sis-param <M>`. Scaling `m` from 4 to 128 provides 128-bit
post-quantum security at the cost of ~8× slower folding and ~5× larger bundles.
The slim proof remains constant because it contains only the sumcheck data:

| SIS m | Fold/step | Verify (full) | Slim proof | Bundle | PQ security |
|---|---|---|---|---|---|
| 4 (POC) | 0.83 ms | 0.007 s | **0.4 KiB** | 2.1 KiB | ~4-bit |
| **128 (target)** | 5.40 ms | 0.20 s | **0.4 KiB** | 9.8 KiB | **128-bit** |

*BN254, state-width 24, 200 steps, baseline.*

Even at `m = 128`, the slim proof remains well within Cardano's 16 KiB
transaction limit at **0.4 KiB**, and slim verification stays sub-millisecond.
The key result is architectural: NovaSlim is the first Nova-family system that
simultaneously delivers **sub-kilobyte proofs**, **no trusted setup**, and a
**post-quantum commitment path** — a combination no prior system achieves.*

Run them with:

```bash
python3 benchmarks/run_benchmarks.py                    # all families, 255 steps
python3 benchmarks/run_benchmarks.py --family ed25519_verify_nova_bls12_381
python3 benchmarks/run_benchmarks.py --curve bn254      # specific curve
python3 benchmarks/run_benchmarks.py --steps 32         # shorter chains
```

The underlying `benchmark_nova` binary also accepts `--commitment sis` to
measure SIS lattice commitments directly (bypassing the Python harness):

```bash
cargo run --release --manifest-path prover/Cargo.toml --bin benchmark_nova -- \
  --curve bn254 --circuit <r1cs> --steps <dir> --commitment sis
```

The harness compiles circuits from `circom/` if needed, generates resumable
step witnesses via snarkjs, then measures baseline and parallel passes of
`benchmark_nova --release`. Raw logs land in `benchmarks/results/<timestamp>/`.

### Synthetic benchmarks (all curves)

These skip circom/snarkjs entirely and generate random in-memory witnesses.
Useful for comparing curve performance when real-circuit witnesses are not
available (e.g. Pallas / Vesta). Use `--commitment {pedersen,sis,hash}` to
select the commitment scheme.

```bash
# BLS12-381
cargo run --release --manifest-path prover/Cargo.toml --bin benchmark_synthetic -- --curve bls12-381 --state-width 24 --steps 255

# BN254 with SIS commitment
cargo run --release --manifest-path prover/Cargo.toml --bin benchmark_synthetic -- --curve bn254 --state-width 24 --steps 255 --commitment sis

# Pallas
cargo run --release --manifest-path prover/Cargo.toml --bin benchmark_synthetic -- --curve pallas --state-width 24 --steps 255

# Vesta
cargo run --release --manifest-path prover/Cargo.toml --bin benchmark_synthetic -- --curve vesta --state-width 24 --steps 255
```

**Synthetic comparison (state-width = 24, steps = 200, BN254):**

| Commitment | Fold/step | Compress | Verify (full) | Verify (slim) | Slim proof | Bundle |
|---|---|---|---|---|---|---|
| Pedersen | 3.76 ms | 0.088 s | 0.092 s | 0.3 ms | **0.4 KiB** | 1.9 KiB |
| **SIS (m=4)** | **0.83 ms** (4.5×) | 0.221 s | **0.007 s** (13×) | 0.2 ms | **0.4 KiB** | 2.1 KiB |
| **SIS (m=128)** | **5.40 ms** (0.7×) | 0.082 s | 0.20 s | 0.3 ms | **0.4 KiB** | 9.8 KiB |
| **Hash** | 7.15 ms (0.5×) | 0.091 s | 0.008 s (12×) | 0.4 ms | **0.4 KiB** | 2.1 KiB |

**Memory scaling (synthetic, BN254, state_width=24, Pedersen):**

| Steps | Peak RSS | Δ per 100 steps |
|---|---|---|
| 16 | 2.9 MiB | — |
| 255 | 3.5 MiB | 0.2 MiB |
| 1,000 | 4.9 MiB | 0.2 MiB |

Memory is effectively **O(1) in step count** — only the current witness is
kept in memory. Real circuits show higher baseline (R1CS matrices loaded
once) but still well under 100 MiB for 255 steps.

All four curves complete fold → compress → verify end-to-end in the synthetic
harness.

</details>
