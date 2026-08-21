# NovaSlim

Transparent folding-scheme proofs sized for Cardano on-chain verification:
NIFS-fold a chain of identical step circuits into one accumulator, compress
with a sumcheck argument, and verify a **~6.6 KiB** proof with **no pairing,
no trusted setup, and sub-millisecond verification**.

```
nova params   → inspect a step circuit (n_pub_in must equal n_pub_out)
nova fold     → NIFS-fold N step witnesses into one O(1) bundle
nova compress → sumcheck compression (--slim for the on-chain variant)
nova verify   → check bundle + proof (slim: ~0.5 ms)
```

Step circuits come from the [cardano-foundation/bls](https://github.com/cardano-foundation/bls)
repo (`circom/CardanoKeyOwnership`, `circom/Ed25519Verify`, …). Clone it next
to this repository (`../bls`) or point `BLS_REPO_DIR` at a checkout — tests,
e2e runs and benchmarks all resolve fixtures from there.

## Layout

| Path | What |
|---|---|
| `prover/` | Core library: R1CS loading, NIFS folding, sumcheck compression, slim proofs ([README](prover/README.md)) |
| `clis/nova/` | The `nova` CLI ([README](clis/nova/README.md)) |
| `benchmarks/` | Benchmark harness over real bls-repo circuits |
| `docs/article.md` | NovaSlim paper draft |

## End-to-end run

Prerequisites: Rust, [circom](https://github.com/iden3/circom) (only if the
`.r1cs` is not compiled yet), [snarkjs] (witness generation), Node.js.

```bash
# 1. Build the CLI
cargo build --release --manifest-path clis/nova/Cargo.toml
NOVA=clis/nova/target/release/nova

# 2. Compile the step circuit (once; skip if ../bls already ships the .r1cs)
cd ../bls/circom/CardanoKeyOwnership
circom --prime bls12381 -l ../Ed25519Verify/node_modules/circomlib/circuits \
    cardano_ed25519_ownership_nova.circom --r1cs --wasm --sym
cd -

# 3. Generate chained step witnesses (see benchmarks/gen_step_witnesses.py)

# 4. Inspect the step circuit — must report n_pub_in == n_pub_out == 24
$NOVA params --circuit ../bls/circom/CardanoKeyOwnership/cardano_ed25519_ownership_nova.r1cs

# 5. Fold 255 steps into one transparent bundle (~2 min)
$NOVA fold --circuit ../bls/circom/CardanoKeyOwnership/cardano_ed25519_ownership_nova.r1cs \
    --steps <witness-dir> --out cko.json

# 6a. On-chain path: slim proof (~6.6 KiB, no openings)
$NOVA compress --slim --circuit ... --steps <witness-dir> --out cko_slim.json
$NOVA verify --ivc cko.json --slim-proof cko_slim.json

# 6b. Audit path: full sumcheck proof (~670 KiB, includes HashPC openings)
$NOVA compress --circuit ... --steps <witness-dir> --out cko_full.json
$NOVA verify --ivc cko.json --sumcheck-proof cko_full.json
```

## Testing

<details>
<summary><b>How to run the test suites</b></summary>

```bash
# Library tests (65 tests)
cargo test --release --manifest-path prover/Cargo.toml

# CLI integration tests (15 tests; includes real-circuit end-to-end flows)
cargo test --release --manifest-path clis/nova/Cargo.toml
```

Notes:

- **Use `--release`** — debug builds are impractically slow on the real
  7,724-constraint step circuits (>10 min vs ~90 s).
- Fixture resolution: `$BLS_REPO_DIR` if set, otherwise the sibling checkout
  `../bls` (i.e. `cardano-foundation/bls` cloned next to this repo).
  Tests needing missing fixtures skip themselves gracefully.
- Witness generation inside tests uses `snarkjs`; without it only the
  synthetic-circuit tests run.
- The monolithic-circuit rejection test loads a 267 MB `.r1cs`; it needs the
  pre-compiled `cardano_ed25519_ownership.r1cs` from the bls checkout.

</details>

## Benchmarks

<details>
<summary><b>Measured numbers and how to reproduce them</b></summary>

Fresh numbers live in `benchmarks/results/<timestamp>/summary.md`. Latest run
(2026-08-21, 4-core desktop, release build, 255 chained steps):

| Step circuit | Constraints | Steps | Fold total | Fold/step | Compress | Verify (full) | Verify (slim) | Slim proof | Bundle |
|---|---|---|---|---|---|---|---|---|---|
| `cardano_ed25519_ownership_nova` | 7,724 | 255 | 122.2 / 120.1 s | 479 / 471 ms | 20.0 / 19.9 s | 20.4 / 20.4 s | **0.5 ms** | **6.6 KiB** | 5.1 KiB |
| `ed25519_verify_nova` | 7,724 | 255 | 120.7 / 116.9 s | 473 / 458 ms | 20.0 / 19.9 s | 20.1 / 19.8 s | **0.3 ms** | **6.6 KiB** | 5.1 KiB |

*Each cell shows baseline / `--opt-parallel` where two values are shown.
The slim proof is constant in step count and step width.*

Re-run after any folding/compression change and paste the new summary here:

```bash
python3 benchmarks/run_benchmarks.py                    # all families, 255 steps
python3 benchmarks/run_benchmarks.py --family cardano_ed25519_ownership_nova
python3 benchmarks/run_benchmarks.py --steps 32         # shorter chains
```

The harness locates the bls checkout, compiles circuits if needed, generates
(resumable) step witnesses via snarkjs, then measures baseline and parallel
passes of `benchmark_nova --release`. Raw logs land in
`benchmarks/results/<timestamp>/`.

</details>
