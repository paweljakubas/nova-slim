# NovaSlim

Transparent folding-scheme proofs sized for on-chain verification:
NIFS-fold a chain of identical step circuits into one accumulator, compress
with a sumcheck argument, and verify a **~0.4–2.5 KiB** proof with **no pairing,
no trusted setup, and sub-millisecond verification**.

Supports **BLS12-381** (Cardano), **BN254** (Ethereum), **Pallas** (Zcash), **Vesta**, **Grumpkin**, and **Bandersnatch**. Three commitment schemes — **Pedersen** (fast, classical), **SIS** (faster folding, quantum-ready), and **Hash** (zero-param, on-the-fly derivation, post-quantum) — are selectable at runtime via `--commitment {pedersen,sis,hash}`.

## Disclaimer

This project is in an **experimental stage**. It has **not been audited** and
should be used **at your own risk**. While the author strives to make it
correct to the best of his knowledge and skill, no warranty of correctness
or security is provided.

## Overview

A long computation is decomposed into `N` **identical step circuits** forming a
chain, where each step proves `state_{i+1} = f(step_i, state_i)`. The pipeline
has four phases:

1. **`params`** — inspect a step circuit and validate the IVC invariant
   (`n_pub_in == n_pub_out`);
2. **`fold`** — NIFS-fold all step witnesses into one Relaxed-R1CS accumulator,
   producing an **O(1) bundle** independent of `N`;
3. **`compress`** — sumcheck-compress the accumulator into a single
   constant-size proof (`--slim` strips the commitment openings for the
   on-chain variant, leaving ~0.4–2.5 KiB);
4. **`verify`** — verify the bundle against the proof using native field
   operations only (~0.2 ms for slim proofs).

Everything is **transparent**: no trusted setup, no pairings, and no proving or
verifying key — only the step circuit and its witnesses are needed. The fold is
off-circuit (the prover runs it), so no curve cycle and no in-circuit
verification are required.

```
nova-slim params   → inspect a step circuit (n_pub_in must equal n_pub_out)
nova-slim fold     → NIFS-fold N step witnesses into one O(1) bundle
nova-slim compress → sumcheck compression (--slim for the on-chain variant)
nova-slim verify   → check bundle + proof (slim: ~0.2 ms)
```

## Roadmap

| Feature | Status | Notes |
|---|---|---|
| **Slim proofs** (~0.4–2.5 KiB, commitment-agnostic) | ✅ 0.2.0 | Strips HashPC openings; formal knowledge-soundness guarantee (Theorem 1) |
| **3 commitment schemes** (Pedersen, SIS, Hash) | ✅ 0.2.0 | Selectable at runtime via `--commitment`; two are post-quantum |
| **6 elliptic curves** (BLS12-381, BN254, Pallas, Vesta, Grumpkin, Bandersnatch) | ✅ 0.2.0 | Full CLI support; BLS12-381 & BN254 have real-circuit benchmarks |
| **Sumcheck compression** (transparent, no trusted setup) | ✅ 0.2.0 | O(log n) proof size; full + slim variants |
| **CLI** (`params`, `fold`, `compress`, `verify`, `help`) | ✅ 0.2.0 | Curve- and commitment-agnostic; built-in help with examples |
| **Compact CBOR serialization** | ✅ 0.2.0 | ~2.6× smaller than JSON; versioned format |
| **Parallel optimizations** (`--opt parallel`) | ✅ 0.2.0 | Rayon-based; 3–5× speedup on large circuits |
| **Aiken eUTXO verifier** | ✅ 0.2.0 | On-chain Plutus-compatible verifier (`cardano/nova-slim-verifier/`) |
| **Cross-system comparison** (Sonobe, STARK, LatticeFold) | ✅ 0.2.0 | Benchmarked against Nova+CycleFold and theoretical baselines |
| **Formal security proof** | ✅ 0.2.0 | 4-game knowledge-soundness proof; generic over commitment scheme |
| In-circuit recursive folding (full IVC security) | 🔜 Future | Each step proves correctness of all previous steps |
| Fixed-base MSM optimization (Pedersen only) | 🔜 Future | ~2× speedup by precomputing doubling ladder |
| SIS norm enforcement / LatticeFold range proofs | 🔜 Future | Required for post-quantum guarantee under adversarial witnesses |
| zk-SNARK decider (Groth16) for constant-size verification | 🔜 Future | Sub-200 B on-chain proofs with one-time trusted setup |
| Bandersnatch real-circuit support | 🔜 Future | circom does not yet support Bandersnatch prime |
| Grumpkin / Pallas / Vesta real-circuit VRF benchmarks | 🔜 Future | snarkjs witness generation for non-standard primes is slow |
| Additional hash functions (SHA-3, Keccak) for Hash commitment | 🔜 Future | Currently Blake2b only; diversify audit surface |
| STARK-based compression (FRI instead of sumcheck) | 🔜 Future | Remove reliance on random oracle; transparent + post-quantum |
| Multi-chain deployment helpers | 🔜 Future | Cardano (Plutus), Ethereum (Solidity), Zcash (Halo2) verifiers |

## What is a slim proof?

The **full** sumcheck proof includes the entire HashPC opening (the witness
 truth table) and is ~240 KiB. The **slim** proof strips this opening, keeping
 only the sumcheck protocol data, yielding a **~0.4–2.5 KiB** on-chain payload
 (depending on $k = \log_2 n_{constraints}$) that is **independent of the
 commitment scheme and its security parameter**.

| Property | Full proof | Slim proof |
|---|---|---|
| Soundness | Yes | Yes |
| Knowledge-soundness | Yes (explicit witness) | Yes (implicit witness) |
| On-chain size | ~240 KiB | **~0.4–2.5 KiB** (independent of m) |
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

Step circuits are bundled in `circom/`:
- `Ed25519Verify/` — Ed25519 signature verification (~7.7K constraints)
- `PoseidonSponge/` — Poseidon hash chain (~633 constraints, comparable to Sonobe)
- `Sha256Step/` — SHA-256 hash chain (~29K–59K constraints, small/medium/big)
- `VRF/` — VRF ladder step (~9 constraints)
- `PoseidonMerkle/` — Merkle path verification (~639 constraints)
- `PoseidonPreimage/` — Poseidon hash pre-image (secret → public commitment)

## Layout

| Path | What |
|---|---|
| `prover/` | Core library: R1CS loading, NIFS folding, sumcheck compression, slim proofs ([README](prover/README.md)) |
| `cli/` | The `nova-slim` CLI ([README](cli/README.md)) |
| `circom/` | Step circuits: Ed25519, SHA-256, VRF, Poseidon (sponge, Merkle, pre-image) |
| `benchmarks/` | Benchmark harness over real circom circuits |
| `cardano/` | CIP-197 PoC and Aiken on-chain verifier ([README](cardano/cip197/README.md)); two-doc equivalence test at `cardano/cip197/scripts/e2e_equivalence.sh` |
| `docs/article.md` | NovaSlim paper draft |

## End-to-end run

Prerequisites: Rust, [circom](https://github.com/iden3/circom) (only if the
`.r1cs` is not compiled yet), [snarkjs](https://github.com/iden3/snarkjs) (witness generation), Node.js.

```bash
# 1. Build the CLI
cargo build --release --manifest-path cli/Cargo.toml
NOVA=cli/target/release/nova-slim

# 2. Compile the step circuit (.r1cs is git-ignored, so it must be compiled
#    from source; the .wasm witness calculator is needed for step 3)
#    circom prime ↔ CLI curve:
#      bls12381 ↔ bls12-381   bn128 ↔ bn254   pallas ↔ pallas   vesta ↔ vesta
cd circom/Ed25519Verify
circom --prime bn128 -l node_modules/circomlib/circuits \
    ed25519_verify_nova.circom --r1cs --wasm --sym
cd -

# 3. Generate 255 chained step witnesses (snarkjs-driven, resumable):
#    python3 benchmarks/gen_step_witnesses.py --wasm \
#      circom/Ed25519Verify/ed25519_verify_nova_js/ed25519_verify_nova.wasm \
#      --initial <input.json> --outputs <in_sig=out_sig,...> \
#      --steps 255 --dir <witness-dir>

# 4. Inspect the step circuit — must report n_pub_in == n_pub_out == 24
$NOVA params --curve bn254 --circuit circom/Ed25519Verify/ed25519_verify_nova.r1cs

# 5. Fold 255 steps into one transparent bundle (~1–2 min)
#    Use --commitment pedersen (default), --commitment sis (lattice-based,
#    faster folding), or --commitment hash (zero-param, on-the-fly derivation)
$NOVA fold --curve bn254 --circuit circom/Ed25519Verify/ed25519_verify_nova.r1cs \
    --steps <witness-dir> --out ed25519.ivc.cbor

# 6a. On-chain path: slim proof (~1.5 KiB CBOR for Ed25519, no openings)
$NOVA compress --slim --curve bn254 \
    --circuit circom/Ed25519Verify/ed25519_verify_nova.r1cs \
    --steps <witness-dir> --out ed25519_slim.proof.cbor
$NOVA verify --curve bn254 --ivc ed25519.ivc.cbor --slim-proof ed25519_slim.proof.cbor

# 6b. Audit path: full sumcheck proof (~240 KiB, includes HashPC openings)
$NOVA compress --curve bn254 \
    --circuit circom/Ed25519Verify/ed25519_verify_nova.r1cs \
    --steps <witness-dir> --out ed25519_full.proof.cbor
$NOVA verify --curve bn254 --ivc ed25519.ivc.cbor --sumcheck-proof ed25519_full.proof.cbor
```

## Testing

<details>
<summary><b>How to run the test suites</b></summary>

```bash
# Library tests (97 tests)
cargo test --release --manifest-path prover/Cargo.toml

# CLI integration tests (25 tests; includes real-circuit end-to-end flows)
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

All numbers below come from a single machine (16-core CPU, 64 GiB RAM) with
release builds, and are documented in detail in
[the paper](docs/article.md) (§6.3). Two harnesses are provided:

1. **`benchmark_nova`** — real circom step circuits (`.r1cs` compiled from
   `circom/`, chained witnesses via snarkjs). Supports BLS12-381, BN254,
   Grumpkin, Pallas, Vesta.
2. **`benchmark_synthetic`** — random in-memory witnesses, no circom/snarkjs.
   Supports all six curves; Bandersnatch is available here only (circom has no
   Bandersnatch scalar-field prime).

### How to run

1. **All circuit families in one shot** (compiles circuits if needed, generates
   or resumes witnesses, runs baseline + `--opt-parallel` passes, writes raw
   logs and a markdown summary under `benchmarks/results/`):

   ```bash
   python3 benchmarks/run_benchmarks.py                     # all families, default steps
   python3 benchmarks/run_benchmarks.py --curve grumpkin    # filter by curve
   python3 benchmarks/run_benchmarks.py --family ed25519_verify_nova_bls12_381
   python3 benchmarks/run_benchmarks.py --steps 32 --commitment sis --sis-param 4
   ```

2. **One real circuit directly** (`benchmark_nova`; needs the compiled `.r1cs`
   and a directory of step witnesses):

   ```bash
   cargo run --release --manifest-path prover/Cargo.toml --bin benchmark_nova -- \
     --curve bls12-381 --commitment pedersen \
     --circuit circom/Ed25519Verify/ed25519_verify_nova.r1cs --steps /tmp/steps/
   ```

3. **Synthetic circuit on any curve** (`benchmark_synthetic`; no snarkjs):

   ```bash
   cargo run --release --manifest-path prover/Cargo.toml --bin benchmark_synthetic -- \
     --curve bandersnatch --state-width 24 --steps 255
   ```

### Measured results

**1. Proof sizes.** The slim proof depends only on `k = log2 n_constraints` —
not on step count nor step width:

| Circuit | Constr. | NIFS bundle | Full sumcheck | Slim proof | Slim ver. |
|---|---|---|---|---|---|
| `vrf_verify_nova` | 9 | 0.7 KiB | ~1.6 KiB | **~0.4 KiB** | **0.2 ms** |
| `poseidon_sponge_nova` | 633 | 0.4 KiB | ~31 KiB | **~0.6 KiB** | **0.4 ms** |
| `poseidon_merkle_nova` | 639 | 0.4 KiB | ~31 KiB | **~0.6 KiB** | **0.5 ms** |
| `ed25519_verify_nova` | 7,724 | 2.2 KiB | ~240 KiB | **~1.0 KiB** | **0.7 ms** |
| `sha256_step_small_nova` | 31,584 | 2.5 KiB | ~1.2 MiB | **~0.8 KiB** | **0.6 ms** |
| `sha256_step_big_nova` | 58,973 | 2.5 KiB | ~2.3 MiB | **~1.0 KiB** | **~1.0 ms** |

- 160–600× smaller than the full sumcheck proof; no opening proofs on-chain.
- The bundle is O(1) in step count and circuit size (≤ 2.5 KiB everywhere).

**2. End-to-end timing.** Header circuits, across curves:

| Circuit | Curve | Constr. | Steps | Fold total | Fold/step | Compress | Ver. full | Ver. slim |
|---|---|---|---|---|---|---|---|---|
| `vrf_verify_nova` | BLS12-381 | 9 | 254 | 3.5 s | 14 ms | 0.04 s | 0.05 s | **0.2 ms** |
| `vrf_verify_nova` | BN254 | 9 | 254 | 2.2 s | 9 ms | 0.03 s | 0.02 s | **0.1 ms** |
| `poseidon_sponge_nova` | BLS12-381 | 633 | 255 | 46.2 s | 181 ms | 1.86 s | 1.85 s | **0.4 ms** |
| `poseidon_merkle_nova` | BLS12-381 | 639 | 32 | 10.0 s | 314 ms | 3.13 s | 2.69 s | **0.5 ms** |
| `ed25519_verify_nova` | BLS12-381 | 7,724 | 255 | 138.5 s | 543 ms | 25.44 s | 28.59 s | **0.7 ms** |

- Verification scales logarithmically with `n_constraints` and is independent
  of step count: 0.1–0.2 ms (VRF), 0.4–0.5 ms (Poseidon), 0.7 ms (Ed25519).
- Pasta curves (Pallas/Vesta) are the fastest fold (2.3–2.8 ms/step); the
  ultra-light `vrf_verify_nova` (9 constraints) isolates protocol overhead.
- The slim proof size is identical across curves for the same circuit —
  the sumcheck protocol is field-agnostic.

**3. Commitment-scheme modularity** (VRF, BLS12-381, 254 steps). The
commitment scheme is swappable at runtime without changing the proof format:

- **Pedersen** — 14 ms/step fold, 0.2 ms slim verification.
- **SIS (m=4)** — **1 ms/step fold (14× faster)**: MSM is replaced by
  matrix–vector products over the scalar field.
- **Hash** — 2 ms/step fold (7× faster; Blake2b coefficients derived on the
  fly), simplest to audit.
- Slim proof is **~0.4 KiB for all three** — independent of the scheme.
- At cryptographic parameters (SIS m=128) fold rises to 5.4 ms/step but the
  slim proof stays ~0.4 KiB.

**4. SHA-256 scaling (small/medium/big)** — state_out = SHA256(state_in),
BLS12-381, Pedersen). Per-step costs from shorter runs after setup overhead
stabilises:

- small (~29K cstr): ~3,100 ms/step fold, **0.6 ms** slim ver., **~0.8 KiB**.
- medium (~31K cstr): ~3,200 ms/step fold, **0.7 ms** slim ver., **~0.8 KiB**.
- big (~59K cstr): ~5,600 ms/step fold, **1.0 ms** slim ver., **~1.0 KiB**.
- A full 32-step fold of SHA-256 big takes ~30 min (~3 min with 16-core
  parallel compression — the biggest parallel gain here, ~3–5×).

**5. Parallel speedup.** Visible mainly in the compress step (sumcheck
processes `n_constraints` rows in parallel). At small sizes (≤7K constraints)
thread overhead dominates and parallel mode is neutral to slightly slower.

**6. Memory.** Prover memory is **O(1) in step count** — only the current
witness is kept in memory; R1CS matrices are loaded once (well under 100 MiB
even for 59K-constraint circuits). This is the key advantage over monolithic
SNARKs, which materialise the full N×C system.

**7. Versus Sonobe** (Nova + CycleFold + Groth16 decider) on PoseidonSponge,
633 constraints, 32 steps:

- Fold: **7.6 s vs 111.5 s — 14.7× faster** (off-circuit NIFS vs in-circuit
  Spartan verification).
- Verify: **0.7 ms (slim) vs 5.4 s (Groth16) — ~7,700× faster**.
- Proof: 1.6 KiB transparent (slim) vs 192 B (Groth16, needs 2 ceremonies +
  a curve cycle + EVM precompiles).
- NovaSlim has **no preprocessing and no keygen** (0 s vs 7.7 s / 7.6 s).

</details>
