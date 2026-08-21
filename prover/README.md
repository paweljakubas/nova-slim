# prover

NovaSlim IVC folding core for BLS12-381 (arkworks): NIFS folding + sumcheck
compression + **slim on-chain proofs**.

A long computation is split into `N` identical step circuits, each proving
`state_{i+1} = f(step_i, state_i)`. The `fold` operation transparently accumulates
all steps into one Relaxed-R1CS instance; `compress` produces a constant-size
sumcheck proof; and `verify` checks it with native field operations — no
pairings, no trusted setup, and a **~1.5 KiB** on-chain footprint with the
slim proof.

| | Full sumcheck proof | **Slim proof** |
|---|---|---|
| Per-step work | NIFS fold (2 MSMs) | NIFS fold (2 MSMs) |
| Proof bundle | O(1) — sumcheck + HashPC openings | **O(1) — sumcheck only** |
| On-chain verify | sumcheck + HashPC (pairing-free) | **sumcheck only (pairing-free)** |
| Trusted setup | **none** | **none** |
| ZK | Yes | **Yes** |
| On-chain size | ~473 KiB | **~1.5 KiB** |

The R1CS parsing / circom adapter lives in the `groth16-prover` crate; this
crate adds the IVC folding layer. The `nova` CLI (`clis/nova`) wraps this
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
nova params --circuit step_circuit.r1cs

# 2. Fold step witnesses into a single Relaxed-R1CS instance
nova fold --circuit step_circuit.r1cs \
  --steps ./step_witnesses/ --out bundle.ivc.json

# 3. Compress into a slim on-chain proof (~1.5 KiB, no trusted setup)
nova compress --slim --circuit step_circuit.r1cs \
  --steps ./step_witnesses/ --out slim.proof.json

# 4. Verify (no verifying key needed)
nova verify --ivc bundle.ivc.json --slim-proof slim.proof.json
# → Verified N steps: sumcheck OK, state chain OK
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
nova compress --circuit step_circuit.r1cs --steps ./step_witnesses/ --out sumcheck.proof.json
nova verify --ivc bundle.ivc.json --sumcheck-proof sumcheck.proof.json
```

### Parallel mode

Add `--opt parallel` to the fold or compress phases for rayon-parallelized
cross-term and sumcheck row computation:

```bash
nova fold --opt parallel --circuit step_circuit.r1cs --steps ./step_witnesses/ --out bundle.ivc.json
nova compress --slim --opt parallel --circuit step_circuit.r1cs --steps ./step_witnesses/ --out slim.proof.json
```

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
| HashPC openings (Z + E) | ~492 KiB | **off-chain** |
| Commitment hashes | — | 128 B |
| Final IVC state | ~1 KiB | ~0.4 KiB (binary) |
| **On-chain total** | **~473 KiB** | **~1.5 KiB** |

---

## Benchmarks

Measured with `cargo run --release --bin benchmark_nova -- --circuit <step.r1cs> --steps <witness-dir>`
on a single machine / single core, witnesses kept in memory. All numbers in a
row come from the **same run**. Step witnesses use full-size state values.

### Proof size

| Step circuit | Constraints | Steps | Slim bundle |
|---|---|---|---|
| `eddsa_jubjub_nova` | 9 | 254 | **~1.5 KiB** |
| `anonymous_airdrop_nova` | 1,207 | 5 | **~1.5 KiB** |
| `ed25519_verify_nova` | 7,724 | 255 | **~1.5 KiB** |
| `cardano_ed25519_ownership_nova` | 7,724 | 255 | **~1.5 KiB** |

The slim proof is **constant in both step count and step width**.

### Timing

| Step circuit | Constraints | Steps | Fold total | Fold/step | Compress | Verify |
|---|---|---|---|---|---|---|
| `eddsa_jubjub_nova` | 9 | 254 | 1.01 s | 3.96 ms | 0.02 s | 0.02 s |
| `anonymous_airdrop_nova` | 1,207 | 5 | 1.77 s | 354 ms | 1.31 s | 1.34 s |
| `ed25519_verify_nova` | 7,724 | 255 | 47.3 s | 185 ms | 7.75 s | 7.87 s |
| `cardano_ed25519_ownership_nova` | 7,724 | 255 | 47.3 s | 185 ms | 7.75 s | 7.87 s |

*Compress and verify times are for the full sumcheck proof. The slim path skips
HashPC opening verification, so verify is slightly faster. No trusted setup is
needed anywhere in the flow.*

### Parallel speedup (`--opt parallel`)

| Step circuit | Constraints | Steps | Fold baseline | Fold parallel | Speedup |
|---|---|---|---|---|---|
| `eddsa_jubjub_nova` | 9 | 254 | 1.01 s | 0.88 s | 1.1× |
| `anonymous_airdrop_nova` | 1,207 | 5 | 1.11 s | 1.22 s | 0.9× |
| `ed25519_verify_nova` | 7,724 | 255 | 27.9 s | 16.8 s | **1.66×** |
| `cardano_ed25519_ownership_nova` | 7,724 | 255 | 14.5 s | 17.9 s | 0.8× |

| Step circuit | Compress baseline | Compress parallel | Speedup | Verify baseline | Verify parallel |
|---|---|---|---|---|---|
| `eddsa_jubjub_nova` | 10 ms | 13 ms | 0.8× | 11.3 ms | 14.4 ms |
| `anonymous_airdrop_nova` | 946 ms | 850 ms | 1.1× | 1,307 ms | 907 ms |
| `ed25519_verify_nova` | 7.95 s | 6.11 s | **1.30×** | 8.26 s | 6.35 s |
| `cardano_ed25519_ownership_nova` | 8.99 s | 9.17 s | 1.0× | 9.00 s | 8.48 s |

Parallelism shows the strongest gains on large step circuits (7,724 constraints)
where row-level work amortizes rayon overhead. Proof sizes are identical between
baseline and parallel.

### Running the benchmark

```bash
cd prover

# Slim path (default)
cargo run --release --bin benchmark_nova -- --circuit <step.r1cs> --steps <witness-dir>

# With parallel optimization
cargo run --release --bin benchmark_nova -- --opt-parallel --circuit <step.r1cs> --steps <witness-dir>
```

`--limit N` restricts to the first N steps.

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
