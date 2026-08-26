# prover

NovaSlim IVC folding core for BLS12-381, BN254, Pallas, and Vesta (arkworks): NIFS folding + sumcheck
compression + **slim on-chain proofs**.

A long computation is split into `N` identical step circuits, each proving
`state_{i+1} = f(step_i, state_i)`. The `fold` operation transparently accumulates
all steps into one Relaxed-R1CS instance; `compress` produces a constant-size
sumcheck proof; and `verify` checks it with native field operations — no
pairings, no trusted setup, and a **~0.4--2.5 KiB** on-chain footprint with the
slim proof.

| | Full sumcheck proof | **Slim proof** |
|---|---|---|
| Per-step work | NIFS fold (2 MSMs) | NIFS fold (2 MSMs) |
| Proof bundle | O(1) — sumcheck + HashPC openings | **O(1) — sumcheck only** |
| On-chain verify | sumcheck + HashPC (pairing-free) | **sumcheck only (pairing-free)** |
| Trusted setup | **none** | **none** |
| ZK | Yes (full proof) | **No** (slim proof reveals sumcheck data, but not the witness directly) |
| On-chain size | ~240 KiB | **~2.5 KiB** (CBOR) |

The R1CS parsing / circom adapter lives in the `groth16-prover` crate; this
crate adds the IVC folding layer. The `nova-slim` CLI (`cli`) wraps this
crate's operations.

---

## Module map

| Module | Purpose |
|---|---|
| [`src/lib.rs`](src/lib.rs) | Orchestration: `params`, `fold`, `compress`, `verify`; JSON proof formats |
| [`src/nifs.rs`](src/nifs.rs) | Relaxed-R1CS NIFS folding with transparent Pedersen commitments |
| [`src/sumcheck.rs`](src/sumcheck.rs) | Sumcheck argument over the relaxed R1CS equation + HashPC openings |
| [`src/curve.rs`](src/curve.rs) | Curve abstraction — folding is agnostic to the underlying curve |

---

## Quick start

```bash
# 1. Inspect the step circuit (must satisfy n_pub_in == n_pub_out)
nova-slim params --curve bls12-381 --circuit step_circuit.r1cs

# 2. Fold step witnesses into a single Relaxed-R1CS instance
nova-slim fold --curve bls12-381 --circuit step_circuit.r1cs \
  --steps ./step_witnesses/ --out bundle.ivc.cbor

# 3. Compress into a slim on-chain proof (~2.5 KiB)
nova-slim compress --slim --curve bls12-381 --circuit step_circuit.r1cs \
  --steps ./step_witnesses/ --out slim.proof.cbor

# 4. Verify (no verifying key needed)
nova-slim verify --curve bls12-381 --ivc bundle.ivc.cbor --slim-proof slim.proof.cbor
# → Verified N steps: slim sumcheck proof OK, state chain OK
# → Final transcript: <64-byte hex>
```

The slim proof strips the HashPC opening proofs (`w_opening`, `e_opening`)
from the full sumcheck proof. Soundness is preserved because the sumcheck
protocol itself proves knowledge of a witness consistent with the committed
instance; the opening proofs are only needed for an off-chain audit trail.

### Full sumcheck proof (with openings, for audit)

Omit `--slim` to produce the full sumcheck proof (includes HashPC opening
proofs for off-chain verification):

```bash
nova-slim compress --curve bls12-381 --circuit step_circuit.r1cs --steps ./step_witnesses/ --out sumcheck.proof.cbor
nova-slim verify --curve bls12-381 --ivc bundle.ivc.cbor --sumcheck-proof sumcheck.proof.cbor
```

### Parallel mode

Add `--opt parallel` to the fold or compress phases for rayon-parallelized
cross-term, sumcheck row, and sumcheck compression computation:

```bash
nova-slim fold --opt parallel --curve bls12-381 --circuit step_circuit.r1cs --steps ./step_witnesses/ --out bundle.ivc.cbor
nova-slim compress --slim --opt parallel --curve bls12-381 --circuit step_circuit.r1cs --steps ./step_witnesses/ --out slim.proof.cbor
```

### Supported curves

| Curve | CLI flag | Typical use |
|---|---|---|
| BLS12-381 | `--curve bls12-381` | Cardano-native |
| BN254 | `--curve bn254` | Ethereum zk-rollups |
| Pallas | `--curve pallas` | Zcash Orchard |
| Vesta | `--curve vesta` | Pallas/Vesta cycle (Nova-Scotia) |

---

## Why slim proofs are safe

The sumcheck protocol proves knowledge of `Z, E` such that the relaxed R1CS
equation `(AZ)∘(BZ) = u·(CZ) + E` holds at a random point `r`. By
Schwartz–Zippel, this implies the equation holds for all constraints with
overwhelming probability. The HashPC opening proofs (truth tables) bind `Z`
and `E` to the committed hashes for an *audit trail*; they are not required
for on-chain soundness.

| Component | Full proof | Slim proof |
|---|---|---|
| Sumcheck proof | ~200 B | ~200 B |
| Fiat–Shamir transcript | ~2 KiB | ~0.8 KiB (binary) |
| HashPC openings (Z + E) | ~240 KiB | **off-chain** |
| Commitment hashes | — | 128 B |
| Final IVC state | ~1 KiB | ~0.4 KiB (binary) |
| **On-chain total** | **~240 KiB** | **~0.4--2.5 KiB** (CBOR) |

---

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
| `ed25519_verify_nova` | bls12-381 | 7,724 | 255 | 138.5 / 145.7 s | 543 / 571 ms | 25.44 / 24.30 s | 28.59 / 25.49 s | **0.7 ms** | **2.5 KiB** | 2.2 KiB |
| `ed25519_verify_nova` | bn254 | 7,724 | 255 | 74.2 / 66.7 s | 347 / 312 ms | 12.23 / 11.14 s | 12.22 / 11.53 s | **0.6 ms** | **2.4 KiB** | 2.2 KiB |

*Each cell shows baseline / `--opt-parallel` where two values are shown.
The slim proof is constant in both step count and step width.*

Run them with:

```bash
python3 benchmarks/run_benchmarks.py                    # all families, 255 steps
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

---

## Tests

```bash
cargo test
```

Covers end-to-end fold → compress → verify flows, tamper resistance (claims,
final instance, r-challenges), broken state chains, parameter mismatches,
serialization roundtrips, varying step counts, power-of-two boundary cases,
and property tests for sumcheck/HashPC determinism.

---

## References

1. Jens Groth. *On the Size of Pairing-Based Non-interactive Arguments.* EUROCRYPT 2016. IACR ePrint [2016/260](https://eprint.iacr.org/2016/260).
2. Abhiram Kothapalli, Srinath Setty, Ioanna Tzialla. *Nova: Recursive Zero-Knowledge Arguments from Folding Schemes.* CRYPTO 2022. IACR ePrint [2021/370](https://eprint.iacr.org/2021/370).
3. Abhiram Kothapalli, Srinath Setty. *SuperNova: Proving Universal Machine Executions without Universal Circuits.* IACR ePrint [2022/1758](https://eprint.iacr.org/2022/1758).
4. Abhiram Kothapalli, Srinath Setty. *CycleFold: Folding-Scheme-Based Recursive Arguments over a Cycle of Elliptic Curves.* IACR ePrint [2023/1192](https://eprint.iacr.org/2023/1192).
5. Abhiram Kothapalli, Srinath Setty. *HyperNova: Recursive Arguments for Customizable Constraint Systems.* CRYPTO 2024. IACR ePrint [2023/573](https://eprint.iacr.org/2023/573).
6. Cyprian Omukhwaya Sakwa, Anyembe Andrew Omala, Fagen Li. *A Survey of Folding-Based Zero-Knowledge Proofs.* Information Sciences 724 (2026) 122698. DOI [10.1016/j.ins.2025.122698](https://doi.org/10.1016/j.ins.2025.122698); [SSRN 5293078](https://doi.org/10.2139/ssrn.5293078).
7. Ryan Lavin, Xuekai Liu, Hardhik Mohanty, Logan Norman, Giovanni Zaarour, Bhaskar Krishnamachari. *A Survey on the Applications of Zero-Knowledge Proofs.* arXiv [2408.00243](https://arxiv.org/abs/2408.00243) (2024).
8. Sean Bowe, Jack Grigg, Daira Hopwood. *Recursive Proof Composition without a Trusted Setup* (Halo / Halo2). IACR ePrint [2019/1021](https://eprint.iacr.org/2019/1021).
9. Liam Eagen. *Bulletproofs++: Next Generation Confidential Transactions Based on Proofs of Statement and Knowledge.* IACR ePrint [2022/510](https://eprint.iacr.org/2022/510).

### Software

- [Nova (Microsoft Research)](https://github.com/microsoft/Nova) — Rust implementation of the Nova folding scheme.
- [Nova-Scotia](https://github.com/nalinbhardwaj/Nova-Scotia) — middleware compiling Circom circuits to the Nova prover.
- [Sonobe](https://github.com/privacy-scaling-explorations/sonobe) — experimental arkworks-based folding-schemes library.
- [arkworks](https://arkworks.rs/) — Rust ecosystem for pairing-based cryptography.

For the full write-up of the scheme and its evaluation on Cardano-relevant
circuits, see [`../docs/article.md`](../docs/article.md).

---

## License

Apache-2.0
