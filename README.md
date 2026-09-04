# NovaSlim

A **Nova-family (IVC) solution** that NIFS-folds a chain of identical step
circuits into one accumulator and compresses it with a transparent sumcheck
argument, then verifies on-chain with **no pairing, no trusted setup, and
sub-millisecond verification**.

NovaSlim is deliberately **multi-faceted in the commitment-size-versus-security
trade-off**: one pipeline exposes a ladder of proof modes, from a **~0.4 KiB
on-chain slim proof** up to **norm-enforced post-quantum certificates of tens of
KiB** (see [Proof modes and their guarantees](#proof-modes-and-their-guarantees)
below) — so the operator chooses the guarantee appropriate to the adversary and
application. It is **modular in commitment** (Pedersen classical; SIS/Ajtai and
Hash post-quantum candidates, selectable at runtime via `--commitment
{pedersen,sis,hash}`) and **modular in elliptic curves** (BLS12-381 for Cardano,
BN254 for Ethereum, Pallas, Vesta, Grumpkin, Bandersnatch — one common proof
format across all six). It **aspires to be performant and correct**: the
prover/verifier are benchmarked against real circom circuits, and the security
claims are backed by a formal (conditional) QROM analysis rather than asserted.

📄 **Technical specification/whitepaper** — formal
description of the protocol, security proofs, and benchmark analysis.

**Hash is operationally SIS/Ajtai in disguise** ($c = A \cdot v$ with
Blake2b-derived matrix entries), not a separate hash-based binding mechanism; it
inherits the same missing-norm-enforcement caveat as SIS.

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

<details>
<summary><b>Feature status and research directions</b></summary>

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
| **Formal security proof** | ✅ 0.2.0 | 4-game knowledge-soundness proof; generic over commitment scheme **(batch-proving model only)** |
| **Level 1 — Algebraic consistency check** | 🔜 0.3.0 | Add `fr_r` (MLE of `AZ⊙BZ`), `cz_r`, `er_r` to the Rust slim proof and verify `fr_r - u·cz_r - er_r == final_claim`, requiring `final_claim == 0` (Level-1 residual check, `verify_slim_level1`). Sumchecks the MLE-of-product so the residual vanishes for honest relaxed witnesses (fixes the earlier `az_r·bz_r` reconstruction that rejected every honest fold). Implemented off-chain; **not** part of the deployed on-chain verifier. |
| **Level 2 — Sumcheck-based matrix evaluation** | 🔜 0.4.0 | Three extra sumchecks proving `az_r`, `bz_r`, `cz_r` are the *correct* evaluations of the matrix-vector products at the random point. Restores knowledge soundness under an untrusted prover and is what actually closes the all-zero/free-`E` transcript gap (the Level-1 `final_claim == 0` check is honest-consistent but does not, by itself, bind the sumcheck to the committed witness). Estimated honest proof size: ~3–5 KiB for Ed25519 (k=13). |
| **Toward quantum proofs** | 🔜 Research | Close gaps (i) and (ii) for a complete post-quantum argument: (i) QROM Fiat–Shamir soundness via multi-round measure-and-reprogram (`thm:qrom-fs`); (ii) quantum extraction via commitment collapsing (`thm:qrom-2`). These layer on top of a classically sound verifier (Level 2). |
| In-circuit recursive folding (full IVC security) | 🔜 Future | Each step proves correctness of all previous steps; requires curve cycle (e.g. BLS12-381 + Bandersnatch) |
| Fixed-base MSM optimization (Pedersen only) | 🔜 Future | ~2× speedup by precomputing doubling ladder |
| SIS norm enforcement / LatticeFold range proofs | 🔜 Future | Required for post-quantum guarantee under adversarial witnesses; also applies to Hash (SIS in disguise) |
| zk-SNARK decider (Groth16) for constant-size verification | 🔜 Future | Sub-200 B on-chain proofs with one-time trusted setup |
| Bandersnatch real-circuit support | 🔜 Future | circom does not yet support Bandersnatch prime |
| Grumpkin / Pallas / Vesta real-circuit VRF benchmarks | 🔜 Future | snarkjs witness generation for non-standard primes is slow |
| Additional hash functions (SHA-3, Keccak) for Hash commitment | 🔜 Future | Currently Blake2b only; diversify audit surface |
| STARK-based compression (FRI instead of sumcheck) | 🔜 Future | Remove reliance on random oracle; transparent + post-quantum |
| Multi-chain deployment helpers | 🔜 Future | Cardano (Plutus), Ethereum (Solidity), Zcash (Halo2) verifiers |

### Research work

<details>
<summary><b>Paper take-aways: PikkuFold (eprint 2026/1809) and FLIP-and-prove R1CS (eprint 2024/1364)</b></summary>

**PikkuFold** (Osadnik) — lattice-based folding. Per-step communication is
**~5.5 KB** (vs ≥31.8 KB Cyclo, 62.25 KB SALSAA, ~83–250 KB LatticeFold+ / Neo /
ProtogaLattice) and it is the **first lattice folding to send no in-protocol
commitments beyond those of the fresh inputs**. Take-aways:

- **Layered random projections** ship a short final image instead of
  decomposition/extension commitments (Cyclo's extension commitment alone is
  ~10 KB of its 31.8 KB).
- **One batched ring sumcheck** verifies the factorised matrix–vector product
  of the projection → verifier 3.7–8.9 ms.
- **JL-style norm certificates** replace range proofs entirely.
- **Fixed-weight ternary challenges + operator-norm rejection sampling** (~60
  trials) cut the growth bound from 21 to ~8.4 at degree 128, target 2⁻¹⁰⁰.
- **Periodic norm reset** (exact norm check + base-*b* decomposition) makes the
  number of folds unbounded; an **AIR reduction** lets the scheme fold AIR/
  zkVM traces, with batched sumchecks.
- Caveat: prover is far heavier than Nova-style NIFS (ms to ~80 s per fold vs
  ~5.4 ms/step for our SIS fold).

**FLIP-and-prove R1CS** (Nitulescu, Paslis, Ràfols) — folding **k independent**
R1CS instances. FLIP (Fold-Inner-Product) folds all *k* instance-witness pairs
in **log k rounds** with **O(log k)** group elements (homomorphic two-tier
commitments); r-Groth is a commit-and-prove Groth16 for relaxed R1CS keeping
3-element proofs + 2 pairing checks with a slightly modified,
instance-independent setup. Together they replace the k−1 extra Groth16 proofs
of aggregation-style schemes (apps: rollups, Proof-of-Space,
proving-as-a-service) — but both rely on **pairings and a trusted setup**,
the two things NovaSlim deliberately removes for eUTXO chains.

**Ideas for the NovaSlim roadmap:**

1. **Batch / multi-instance folding** — FLIP's log-*k* shape for folding *k*
   independent instances (e.g. several wallet transactions) into one slim proof,
   instantiated with our DLOG/SIS/Hash commitments instead of pairings.
2. **Drop derived-witness commitments** — PikkuFold's "commit only fresh
   inputs" principle to shrink the SIS payload (currently the ~10–12 KiB mode).
3. **Sumcheck-based on-chain verification** — PikkuFold's single batched ring
   sumcheck as a template for cheap Plutus-like verification (hash/sumcheck ops
   instead of group MSMs).
4. **Short-challenge engineering** — fixed-weight + operator-norm rejection
   sampling for tighter SIS norm growth → smaller proofs, more folds per budget.
5. **Norm-reset checkpoints** — unbounded SIS folding (currently capped by
   additive norm growth).
6. **AIR / zkVM trace folding** — extend beyond R1CS toward Cairo/RISC Zero
   workloads.
7. **Keep transparency as a hard boundary** — both papers frame the
   pairing/trusted-setup trade space; we stay on the lattice/hash path.

</details>

</details>

## What is a slim proof?

<details>
<summary><b>Slim vs full proof: size, security, and audit trail</b></summary>

The **full** sumcheck proof includes the entire HashPC opening (the witness
 truth table) and is ~240 KiB. The **slim** proof strips this opening, keeping
 only the sumcheck protocol data, yielding a **~0.4–2.5 KiB** on-chain payload
 (depending on $k = \log_2 n_{constraints}$) that is **independent of the
 commitment scheme and its security parameter**.

| Property | Full proof | Slim proof (batch-proving) |
|---|---|---|
| Soundness | Yes | Yes *in the batch-proving model* |
| Knowledge-soundness | Yes (explicit witness) | Yes (implicit witness) |
| On-chain size | ~240 KiB | **~0.4–2.5 KiB** (independent of m) |
| Honest sound size | — | **~5–12 KiB** (classical) / **~30–100+ KiB** (PQ) |
| Auditability | Full witness reconstruction | Commitment binding only |
| Trusted setup | None | None |
| Verifier time | ~8 s (HashPC recompute) | **~0.2 ms** (sumcheck only, no MLE eval) |

**Do we lose security?** The slim proof preserves knowledge soundness *in the
batch-proving model* where the prover is trusted during folding. The level-1
verifier (`verify_slim_level1`/`verify_full`) closes two of the earlier gaps: it
asserts the final residual vanishes (no more all-zeros free-`E` transcript), and
it verifies the circuit-backed PCS openings, binding the final instance to a
committed short witness. The remaining folding gap is closed at the
*commitment level* by **fold re-verification (FV)**: with a fold log carrying
the pre-fold committed instances and cross-term commitments `com(T)`, the
verifier recomputes the per-step Fiat-Shamir challenges and re-checks the
homomorphic fold relation `Ē' = Ē_acc + r·Ē_step + r·com(T)` (+ `x', u', W̄'`)
for every fold step from committed data, binding the chain to the bundle's
final instance and transcript. FV does **not** re-open every per-step witness to
check each `com(T)` against the R1CS cross-term relation — that would be full
recursive verification. Acceptance therefore attests honest pipeline execution
plus a commitment-level-checked fold chain; under a fully untrusted prover the
per-step witness re-opening remains the residual (small) assumption.

**Honest sizing.** The headline ~0.4–2.5 KiB omits the parts a sound system
must carry:
1. **PCS openings** (~1–4 KiB if succinct),
2. **Fold verification log** (in the fold-log design: the per-fold-pre-instance
   commitments + `com(T)` entries, ~3–5 KiB amortised for typical fold counts),
3. **Norm proofs** (~20–80 KiB for SIS/Hash post-quantum).

Closing these gaps yields estimated honest sizes of **~5–12 KiB**
(classical) and **~30–100+ KiB** (post-quantum).

The audit trail is preserved by construction: the prover can publish the full
proof off-chain; anyone can verify that its commitment hashes match the slim
proof, confirming both refer to the same witness. The full proof serves as a
legally binding audit record, while the slim proof serves as the transaction
payload.

**Positioning.** Because the verifier gap remains open, NovaSlim is best
positioned as a **fund-recovery mechanism** — verified by a Plutus contract
once classical signatures are disabled on Cardano — rather than as a day-to-day
signing scheme.

Step circuits are bundled in `circom/`:
- `Ed25519Verify/` — Ed25519 signature verification (~7.7K constraints)
- `PoseidonSponge/` — Poseidon hash chain (~633 constraints, comparable to Sonobe)
- `Sha256Step/` — SHA-256 hash chain (~29K–59K constraints, small/medium/big)
- `VRF/` — VRF ladder step (~9 constraints)
- `PoseidonMerkle/` — Merkle path verification (~639 constraints)
- `PoseidonPreimage/` — Poseidon hash pre-image (secret → public commitment)

</details>

## Proof modes and their guarantees

<details>
<summary><b>Slim vs full vs level-1 vs norm modes: what each proves, adversary
risk, and PQ status</b></summary>

All proof modes are produced by `nova-slim compress` and consumed by
`nova-slim verify`. The guarantees they carry differ substantially.

| Mode | `compress` | `verify` | Proof content | Size (254 steps) |
|---|---|---|---|---|
| **slim** | `--slim` | `--slim-proof` | sumcheck transcript only (no openings) | ~0.4 KiB (on-chain) |
| **full sumcheck** | default | `--sumcheck-proof` | sumcheck + W/E HashPC openings + commitments | ~1.6 KiB |
| **level-1** | `--level1` | `--level1-proof` | degree-2 sumcheck + openings + final-claim-zero (+ OP with `--circuit`) | ~1.4 KiB |
| **level-1 + norm-range** | `--level1 --norm-range` | `--level1-proof --norm-range --circuit --steps` | level-1 + per-step range certs | ~34 KiB |
| **level-1 + norm-jl** | `--level1 --norm-jl` | `--level1-proof --norm-jl --circuit --steps` | level-1 + per-step JL certs | ~42 KiB |

**What each proves (and does not):**

- **slim (level-0, on-chain).** Checks the sumcheck transcript over the relaxed
  R1CS; it does **not** open the committed witness/error, evaluate the MLEs at
  the random point, or verify the fold. An all-zero polynomial transcript passes
  against any bundle, because relaxed R1CS has a free error vector `E`.
  Accepting a slim proof therefore attests *honest pipeline execution*, not
  knowledge of a valid witness against an untrusted prover.
  **Adversary risk:** a malicious prover can pick a free `E` and pass trivially;
  sound only in the batch-proving model (verifier trusts the prover during
  folding). **PQ:** commitment scheme may be Pedersen (classical, DLP-based),
  SIS/Ajtai, or Hash.

- **full sumcheck (off-chain audit).** Adds the HashPC opening proofs and
  commitment checks, so it binds the transcript to a witness. It is the legacy
  `verify_sumcheck_compression` path that relies on `claimed_product_at_r`
  alone; it is auditable but not the preferred sound verifier.

- **level-1 — the sound verifier.** Runs the complete verifier: the degree-2
  sumcheck, the **final-claim-zero** check on the MLE-of-product residual
  (`fr_r − u·cz_r − er_r == 0`), commitment consistency, and — when a circuit
  is supplied — the **circuit-backed PCS opening** predicate (recompute
  `AZ/BZ/CZ/fr` from the opened truth table and check `MLE(tt_E)(r) == er_r`).
  This **closes the free-E attack** that breaks slim at level-0.
  **Adversary risk:** without `--circuit`, the OP (opening) check is skipped;
  pass `--circuit` on verify (or use `verify_full` with a circuit) for the full
  OP-backed guarantees. **PQ:** as with slim; commitment scheme dependent.

- **level-1 + norm-range / norm-jl.** Adds an **audit-only norm certificate**
  that each fold step's *pre-fold* witness satisfies `∥Z_j∥_∞, ∥E_j∥_∞ ≤ 2^B`.
  Verification re-folds `--circuit --steps` and cross-checks the carried record.
  **PQ:** this is what moves the SIS/Hash instantiations toward a *fully sound*
  post-quantum guarantee, at 34–42 KiB. It is *audit-only*: it does not change
  the on-chain verifier.

**PQ note.** None of the modes changes the fundamental status:
- **Protocol-level QROM security** is **proven** (Fiat–Shamir under a quantum
  random oracle, `thm:qrom-fs`; quantum extraction via commitment collapsing,
  `thm:qrom-2`), conditional on flagged ideal-primitive and norm-enforcement
  assumptions.
- **Concrete bit-security** for the post-quantum (SIS/Hash) instantiations is
  **conjectured**: it composes (SIS/Hash hardness) × (heuristic BKZ/sieving cost
  model) × (non-tight reduction margin `Δκ ≈ 2k·log₂q`). Norm enforcement
  narrows but does not fully close this conjectured label.
- **Pedersen (classical)** is secure against classical adversaries under the
  DLP assumption; it is **not** post-quantum.

</details>

## Layout

<details>
<summary><b>Where things live in the repo</b></summary>

| Path | What |
|---|---|
| `prover/` | Core library: R1CS loading, NIFS folding, sumcheck compression, slim proofs ([README](prover/README.md)) |
| `cli/` | The `nova-slim` CLI ([README](cli/README.md)) |
| `circom/` | Step circuits: Ed25519, SHA-256, VRF, Poseidon (sponge, Merkle, pre-image) |
| `benchmarks/` | Benchmark harness over real circom circuits |
| `cardano/` | CIP-197 PoC and Aiken on-chain verifier ([README](cardano/cip197/README.md)); two-doc equivalence test at `cardano/cip197/scripts/e2e_equivalence.sh` |
| `whitepaper.pdf` | Technical specification: protocol design, security proofs, and benchmarks |

</details>

## End-to-end run

<details>
<summary><b>Full pipeline: from circuit to on-chain proof</b></summary>

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

</details>

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

## Release

<details>
<summary><b>How to cut a new release</b></summary>

### Prerequisite

Make sure the `RELEASE_TOKEN` secret exists in GitHub (Settings → Secrets and
variables → Actions). It must be a fine-grained PAT with *Workflows* (read+write)
and *Contents* (read+write) permissions on this repo — GitHub's hardened
Releases API rejects the default `GITHUB_TOKEN` for releases whose target
commit touches `.github/workflows/`.

### Step 1 — Bump the version

Update these files from the old version to the new one:

- `cli/Cargo.toml` → `version`
- `prover/Cargo.toml` → `version`
- `cardano/nova-slim-verifier/aiken.toml` → `version`
- `cli/tests/cli.rs` → the `--version` test assertion (lines ~630 & ~646)

Also add a matching `## [X.Y.Z]` section in `ChangeLog.txt`. Merge to
`master`. (The release workflow has no separate version setting — the
release body and tag come from the tag you push in Step 2.)

### Step 2 — Create and push the tag

```bash
git tag v0.3.0 && git push origin v0.3.0
```

Pushing the tag triggers the release workflow, which builds `nova-slim` and
creates a **draft** release with the binary (`tar.gz` + `sha256sums`) attached
and the `ChangeLog.txt` section as release notes.

### Step 3 — Publish

Open the **draft** release in GitHub → inspect it → click **Publish release**.

</details>

## Benchmarks

<details>
<summary><b>Measured numbers and how to reproduce them</b></summary>

Unless a figure is explicitly labelled **prior reference**, the numbers below
were freshly measured on this machine (4 logical cores, Intel i7-7500U @ 2.7 GHz,
31 GiB RAM) with release builds.  Two harnesses are provided:

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

**0. All verifications OK.** Every run — full sumcheck, slim, **Level-1
(final-claim-zero residual)**, and both norm certificates (Option A range /
Option B JL) — reports `all verifications OK`.  This includes the real `VRF`
circuit, the smallest possible step circuit (9 constraints), which exercises
the full Level-1 + norm path end to end.

**1. Proof sizes.** The slim/on-chain proof depends only on
`k = log2 n_constraints` — not on step count nor step width:

| Circuit | Constr. | NIFS bundle | Slim proof | Level-1 proof | Slim ver. |
|---|---|---|---|---|---|
| `vrf_verify_nova` (bls12-381) | 9 | 0.7 KiB | **0.4 KiB** (388 B) | 1.4 KiB | **0.1 ms** |
| synthetic (state-width 24) | — | 1.9 KiB | **0.4 KiB** (425 B) | — | **~0.2 ms** |

- The bundle is O(1) in step count and circuit size (≤ 2.5 KiB everywhere).
- Level-1 adds the commitment openings + final-claim-zero residual check
  (1.4 KiB for VRF), keeping the proof well within on-chain budgets.

**2. End-to-end timing — real `VRF` circuit** (bls12-381, Pedersen, 254 steps):

| Metric | baseline | `--opt-parallel` |
|---|---|---|
| NIFS fold | 4.7 s (18 ms/step) | 5.0 s (20 ms/step) |
| Sumcheck compress | 0.07 s | 0.07 s |
| Verify (full) | 0.06 s | 0.05 s |
| Verify (slim) | **0.1 ms** | **0.1 ms** |
| Level-1 compress / verify | 0.06 s / 57 ms | 0.06 s / 57 ms |
| Norm A (range) L1 verify / size | 0.18 s / 33.2 KiB | — |
| Norm B (JL) L1 verify / size | 0.24 s / 41.4 KiB | — |

- The 9-constraint VRF circuit isolates protocol overhead; it shows the slim
  verifier is sub-millisecond and independent of step count.
- Norm certificates carry one entry per fold step (254 here), so their proofs
  (33–41 KiB) grow with step count — they are an off-chain/audit payload, not
  the on-chain slim proof.

**3. Commitment-scheme modularity** (synthetic, bls12-381, 254 steps,
state-width 24). The commitment scheme is swappable at runtime without
changing the proof format:

- **Pedersen** — 4.1 ms/step fold, slim **0.4 KiB** (0.2 ms verify).
- **SIS (m=4)** — **0.53 ms/step fold (~8× faster than Pedersen)**: MSM is
  replaced by matrix–vector products over the scalar field.
- **Hash** — 4.8 ms/step fold (Blake2b coefficients derived on the fly),
  simplest to audit.
- **SIS (m=128)** — 3.3 ms/step fold (cryptographic parameters).
- Slim proof is **~0.4 KiB for all three** — independent of the scheme.

**4. Curve comparison** (synthetic, Pedersen, state-width 24, 254 steps.
Fold ms/step):

| Curve | Fold/step | Slim proof |
|---|---|---|
| Pallas | **2.06 ms** | 0.4 KiB |
| Vesta | 2.17 ms | 0.4 KiB |
| Grumpkin | 2.34 ms | 0.4 KiB |
| BN254 | 2.47 ms | 0.4 KiB |
| Bandersnatch | 2.66 ms | 0.4 KiB |
| BLS12-381 | 4.11 ms | 0.4 KiB |

- The slim proof size is identical across curves — the sumcheck protocol is
  field-agnostic.

**5. Parallel speedup.** Visible mainly in the compress step (sumcheck
processes `n_constraints` rows in parallel). At small sizes (≤7K constraints)
thread overhead dominates and parallel mode is neutral to slightly slower;
for state-width-24 synthetic circuits the fold scales with available cores.

**6. Memory.** Prover memory is **O(1) in step count** — only the current
witness is kept in memory; R1CS matrices are loaded once (synthetic runs peak
~5 MiB; well under 100 MiB even for 59K-constraint circuits).

---

**Prior reference — original 16-core / 64 GiB machine.** These heavier
circuits were **not** re-measured on this box (they take tens of minutes to
hours on 4 cores); the figures below are retained from the original 16-core
machine for continuity and should not be read as current:

| Circuit | Curve | Constr. | Steps | Fold/step | Slim proof | Slim ver. |
|---|---|---|---|---|---|---|
| `vrf_verify_nova` | BN254 | 9 | 254 | 9 ms | 0.4 KiB | 0.1 ms |
| `poseidon_sponge_nova` | BLS12-381 | 633 | 255 | 181 ms | 0.6 KiB | 0.4 ms |
| `poseidon_merkle_nova` | BLS12-381 | 639 | 32 | 314 ms | 0.6 KiB | 0.5 ms |
| `ed25519_verify_nova` | BLS12-381 | 7,724 | 255 | 543 ms | 1.0 KiB | 0.7 ms |
| `sha256_step_small_nova` | BLS12-381 | 31,584 | — | ~3,100 ms | 0.8 KiB | 0.6 ms |
| `sha256_step_big_nova` | BLS12-381 | 58,973 | — | ~5,600 ms | 1.0 KiB | 1.0 ms |

- Versus Sonobe (PoseidonSponge, 633 cstr, 32 steps, prior reference): fold
  **~14.7× faster** than Nova+CycleFold+Groth16, verify **~7,700× faster**
  (0.7 ms slim vs 5.4 s), with no preprocessing / no keygen.
- A full 32-step SHA-256-big fold was ~30 min on the 16-core machine (~3 min
  with parallel compression).

</details>
