# prover

NovaSlim IVC folding core for BLS12-381, BN254, Grumpkin, Pallas, Vesta, and Bandersnatch (arkworks): NIFS folding + sumcheck
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

For the full write-up of the scheme and its evaluation on Cardano-relevant
circuits, see [`../docs/article.md`](../docs/article.md).

---

## License

Apache-2.0
