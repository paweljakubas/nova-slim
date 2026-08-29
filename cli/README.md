# nova-slim-cli

Command-line interface for NovaSlim — curve-agnostic IVC folding with slim
on-chain proofs. Supports BLS12-381 (Cardano), BN254 (Ethereum), Pallas (Zcash), Vesta, Grumpkin, and Bandersnatch.

A long computation is split into `N` identical step circuits, each proving
`state_{i+1} = f(step_i, state_i)`. The CLI covers one flow:

| | |
|---|---|
| **Path** | `fold` → `compress --slim` → `verify --slim-proof` |
| **Proof size** | **O(1) — ~0.4–2.5 KiB on-chain (CBOR)** |
| **Trusted setup** | **None** |
| **On-chain verify** | **Pairing-free** — native field sumcheck |
| **ZK** | **No** — the slim proof reveals sumcheck round polynomials and the claimed product evaluation, but not the witness directly |

No ceremony, no proving key, no verifying key — only the step circuit and
witnesses are needed.

The core IVC logic lives in [`prover`](../../prover/README.md); this crate is
the thin CLI wrapper.

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
# → Verified N steps: slim sumcheck proof OK
```

The `--slim` flag strips HashPC opening proofs from the sumcheck bundle. The
sumcheck protocol itself proves knowledge of a witness consistent with the
committed instance, so soundness is preserved. Opening proofs are only needed
for an off-chain audit trail.

### With parallel optimization

```bash
nova-slim fold --opt parallel --curve bls12-381 --circuit step_circuit.r1cs --steps ./step_witnesses/ --out bundle.ivc.cbor
nova-slim compress --slim --opt parallel --curve bls12-381 --circuit step_circuit.r1cs --steps ./step_witnesses/ --out slim.proof.cbor
```

### Full sumcheck proof (with openings, for audit)

Omit `--slim` to keep the HashPC opening proofs:

```bash
nova-slim compress --curve bls12-381 --circuit step_circuit.r1cs --steps ./step_witnesses/ --out sumcheck.proof.cbor
nova-slim verify --curve bls12-381 --ivc bundle.ivc.cbor --sumcheck-proof sumcheck.proof.cbor
```

---

## Command reference

Run any command with `--help` for full flag details:

```bash
nova-slim --help
nova-slim --version
nova-slim params --help
nova-slim fold --help
nova-slim compress --help
nova-slim verify --help
```

`nova-slim --version` prints the release version and the git commit the binary
was built from, e.g. `nova-slim 0.2.0 (5d6761b)`.

Top-level help:

```
NovaSlim — folding + slim on-chain proofs CLI

Usage: nova-slim <COMMAND>

Commands:
  params    Inspect a step circuit and emit a JSON descriptor
  fold      Fold step witnesses into a single Relaxed-R1CS instance
  compress  Compress a NIFS bundle into a single constant-size proof
  verify    Verify a folded NIFS bundle against its compression proof
  help      Print this message or the help of the given subcommand(s)
```

### `params` — inspect a step circuit

Validates the IVC invariant `n_pub_in == n_pub_out`.

```bash
nova-slim params --curve bls12-381 --circuit step_circuit.r1cs
nova-slim params --curve bls12-381 --circuit step_circuit.r1cs --out step_circuit.desc.json
```

### `fold` — fold step witnesses

Transparent folding, no proving key, O(1) bundle.

```bash
nova-slim fold --curve bls12-381 --circuit step_circuit.r1cs \
  --steps ./step_witnesses/ --out bundle.ivc.cbor
```

Add `--opt parallel` for rayon-parallelized cross-term computation and
sumcheck compression (MLE evaluation, round sums, fold steps).

### `compress` — compress into one proof

**Default:** full sumcheck compression (transparent, includes HashPC openings
for off-chain audit).

```bash
nova-slim compress --curve bls12-381 --circuit step_circuit.r1cs --steps ./step_witnesses/ --out sumcheck.proof.cbor
```

**Slim on-chain proof:** strips HashPC openings (~98% smaller).

```bash
nova-slim compress --slim --curve bls12-381 --circuit step_circuit.r1cs --steps ./step_witnesses/ --out slim.proof.cbor
```

### `verify` — verify a folded bundle

**Slim proof (on-chain path):**

```bash
nova-slim verify --curve bls12-381 --ivc bundle.ivc.cbor --slim-proof slim.proof.cbor
```

**Full sumcheck proof (audit-grade):**

```bash
nova-slim verify --curve bls12-381 --ivc bundle.ivc.cbor --sumcheck-proof sumcheck.proof.cbor
```

---

## Complete workflow

```bash
# 1. Fold (transparent, no proving key)
nova-slim fold --curve bls12-381 --circuit step_circuit.r1cs --steps ./step_witnesses/ --out bundle.ivc.cbor

# 2. Compress to slim proof (~0.4--2.5 KiB depending on circuit size)
nova-slim compress --slim --curve bls12-381 --circuit step_circuit.r1cs --steps ./step_witnesses/ --out slim.proof.cbor

# 3. Verify (pairing-free, no VK)
nova-slim verify --curve bls12-381 --ivc bundle.ivc.cbor --slim-proof slim.proof.cbor
```

---

## Example: Ed25519Verify circuit

> **Note:** `ed25519_verify_nova` is the primary step circuit used for
> benchmarking. The same commands work for any step circuit satisfying
> `n_pub_in == n_pub_out`.

This circuit decomposes Ed25519 base-point scalar multiplication into 255 steps
of 7,724 constraints each (24 public inputs / 24 public outputs).

```bash
nova-slim params --curve bls12-381 --circuit ed25519_verify_nova.r1cs
nova-slim fold --curve bls12-381 --circuit ed25519_verify_nova.r1cs --steps <witness-dir> --out bundle.ivc.cbor
nova-slim compress --slim --curve bls12-381 --circuit ed25519_verify_nova.r1cs --steps <witness-dir> --out slim.proof.cbor
nova-slim verify --curve bls12-381 --ivc bundle.ivc.cbor --slim-proof slim.proof.cbor
```

---

## License

Apache-2.0
