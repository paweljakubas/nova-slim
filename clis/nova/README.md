# nova-cli

Command-line interface for NovaSlim — IVC folding on BLS12-381 with slim
on-chain proofs.

A long computation is split into `N` identical step circuits, each proving
`state_{i+1} = f(step_i, state_i)`. The CLI covers one flow:

| | |
|---|---|
| **Path** | `fold` → `compress --slim` → `verify --slim-proof` |
| **Proof size** | **O(1) — ~1.5 KiB on-chain** |
| **Trusted setup** | **None** |
| **On-chain verify** | **Pairing-free** — native field sumcheck |
| **ZK** | **Yes** — witness-hiding |

No ceremony, no proving key, no verifying key — only the step circuit and
witnesses are needed.

The core IVC logic lives in [`prover`](../../prover/README.md); this crate is
the thin CLI wrapper.

---

## Quick start

```bash
# 1. Inspect the step circuit (must satisfy n_pub_in == n_pub_out)
nova params --circuit step_circuit.r1cs

# 2. Fold step witnesses into a single Relaxed-R1CS instance
nova fold --circuit step_circuit.r1cs \
  --steps ./step_witnesses/ --out bundle.ivc.json

# 3. Compress into a slim on-chain proof (~1.5 KiB)
nova compress --slim --circuit step_circuit.r1cs \
  --steps ./step_witnesses/ --out slim.proof.json

# 4. Verify (no verifying key needed)
nova verify --ivc bundle.ivc.json --slim-proof slim.proof.json
# → Verified N steps: slim sumcheck proof OK
```

The `--slim` flag strips HashPC opening proofs from the sumcheck bundle. The
sumcheck protocol itself proves knowledge of a witness consistent with the
committed instance, so soundness is preserved. Opening proofs are only needed
for an off-chain audit trail.

### With parallel optimization

```bash
nova fold --opt parallel --circuit step_circuit.r1cs --steps ./step_witnesses/ --out bundle.ivc.json
nova compress --slim --opt parallel --circuit step_circuit.r1cs --steps ./step_witnesses/ --out slim.proof.json
```

### Full sumcheck proof (with openings, for audit)

Omit `--slim` to keep the HashPC opening proofs:

```bash
nova compress --circuit step_circuit.r1cs --steps ./step_witnesses/ --out sumcheck.proof.json
nova verify --ivc bundle.ivc.json --sumcheck-proof sumcheck.proof.json
```

---

## Command reference

Run any command with `--help` for full flag details:

```bash
nova --help
nova params --help
nova fold --help
nova compress --help
nova verify --help
```

Top-level help:

```
NovaSlim — folding + slim on-chain proofs CLI

Usage: nova <COMMAND>

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
nova params --circuit step_circuit.r1cs
nova params --circuit step_circuit.r1cs --out step_circuit.desc.json
```

### `fold` — fold step witnesses

Transparent folding, no proving key, O(1) bundle.

```bash
nova fold --circuit step_circuit.r1cs \
  --steps ./step_witnesses/ --out bundle.ivc.json
```

Add `--opt parallel` for rayon-parallelized cross-term computation.

### `compress` — compress into one proof

**Default:** full sumcheck compression (transparent, includes HashPC openings
for off-chain audit).

```bash
nova compress --circuit step_circuit.r1cs --steps ./step_witnesses/ --out sumcheck.proof.json
```

**Slim on-chain proof:** strips HashPC openings (~98% smaller).

```bash
nova compress --slim --circuit step_circuit.r1cs --steps ./step_witnesses/ --out slim.proof.json
```

### `verify` — verify a folded bundle

**Slim proof (on-chain path):**

```bash
nova verify --ivc bundle.ivc.json --slim-proof slim.proof.json
```

**Full sumcheck proof (audit-grade):**

```bash
nova verify --ivc bundle.ivc.json --sumcheck-proof sumcheck.proof.json
```

---

## Complete workflow

```bash
# 1. Fold (transparent, no proving key)
nova fold --circuit step_circuit.r1cs --steps ./step_witnesses/ --out bundle.ivc.json

# 2. Compress to slim proof (~1.5 KiB)
nova compress --slim --circuit step_circuit.r1cs --steps ./step_witnesses/ --out slim.proof.json

# 3. Verify (pairing-free, no VK)
nova verify --ivc bundle.ivc.json --slim-proof slim.proof.json
```

---

## Example: CardanoKeyOwnership circuit

> **Note:** `cardano_ed25519_ownership_nova` is an **example step circuit** — one
> of several circuits the CLI has been tested on. The same commands work for any
> step circuit satisfying `n_pub_in == n_pub_out`.

This circuit decomposes Ed25519 base-point scalar multiplication into 255 steps
of 7,724 constraints each (24 public inputs / 24 public outputs).

```bash
nova params --circuit cardano_ed25519_ownership_nova.r1cs
nova fold --circuit cardano_ed25519_ownership_nova.r1cs --steps <witness-dir> --out bundle.ivc.json
nova compress --slim --circuit cardano_ed25519_ownership_nova.r1cs --steps <witness-dir> --out slim.proof.json
nova verify --ivc bundle.ivc.json --slim-proof slim.proof.json
```

---

## License

Apache-2.0
