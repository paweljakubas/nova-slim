# NovaSlim End-to-End Guide

A step-by-step walkthrough of the complete NovaSlim flow, from circuit compilation
to on-chain verification.

## What You Need

- `nova-slim` CLI (build from `cli/` with `cargo build --release`)
- `circom` compiler
- `snarkjs` (for witness generation)
- `aiken` v1.1.19+ (for on-chain verifier)
- `cardano-address` v4.0.0+ (for BIP32 key derivation)

## The Flow (Big Picture)

```mermaid
flowchart LR
    A[BIP32 Derive Keys] --> B[Compile Circuit]
    B --> C[Generate Witnesses]
    C --> D[Fold Steps]
    D --> E[Compress to Slim Proof]
    E --> F[Verify Off-Chain]
    F --> G[Verify On-Chain]

    style A fill:#87CEEB
    style D fill:#90EE90
    style E fill:#90EE90
    style F fill:#FFD700
    style G fill:#FF6B6B
```

**Blue** = key derivation. **Green** = prover work. **Yellow** = off-chain verifier. **Red** = on-chain verifier.

---

## Step 0: Derive BIP32 Keys (cardano-address)

Before compiling the circuit, generate the actual Cardano keys that the proof
will certify. This uses the standard BIP32-Ed25519 derivation (Khovratovich).

```bash
cd cardano/cip197

# 1. Generate recovery phrase
cardano-address recovery-phrase generate --size 15 > recovery-phrase.txt

# 2. Derive root key
cardano-address key from-recovery-phrase Shelley < recovery-phrase.txt > root.xprv

# 3. Derive account key (m/1852'/1815'/0')
cardano-address key child 1852H/1815H/0H < root.xprv > acct.xprv
cardano-address key public --with-chain-code < acct.xprv > acct.xpub

# 4. Derive address key (m/1852'/1815'/0'/0/0)
cardano-address key child 0/0 < acct.xprv > addr.xprv
cardano-address key public --with-chain-code < addr.xprv > addr.xpub

# Extract public key hex for circuit public input
cardano-address key inspect < addr.xpub
```

**What this does:** Generates a real HD wallet key hierarchy. The account public
key and address public key are the **public inputs/outputs** that the NovaSlim
circuit proves were correctly derived.

**For the PoC:** We use the VRF circuit (Step 1–5) as a stand-in because the
full BIP32-Ed25519 circuit (~10K constraints per step) is still under
construction. The key derivation above shows the real keys that the final
circuit will certify.

---

## Step 1: Compile the Circuit

A step circuit defines one iteration of your computation. For this guide we use the
VRF scalar-multiplication step (JubJub curve, 4 public I/O signals).

```bash
cd cardano/cip197

# Compile the circom circuit
circom -l ../../circom/Ed25519Verify/node_modules/circomlib/circuits -l . \
  ../../circom/VRF/vrf_verify_nova.circom \
  --r1cs --wasm --sym

# You now have:
#   vrf_verify_nova.r1cs      ← circuit constraints
#   vrf_verify_nova_js/       ← WASM witness generator
```

**What this does:** Converts the circom source into a binary R1CS file that
NovaSlim can load.

---

## Step 2: Generate Witnesses

Each step needs a witness file (`step_0000.wtns`, `step_0001.wtns`, …) that assigns
concrete values to every wire in the circuit.

```bash
# Generate 5 step witnesses using snarkjs
python3 ../../benchmarks/gen_vrf_witnesses.py \
  --wasm vrf_verify_nova_js/vrf_verify_nova.wasm \
  --steps 5 \
  --dir poc_witnesses

# You now have:
#   poc_witnesses/step_0000.wtns
#   poc_witnesses/step_0001.wtns
#   …
```

**What this does:** For each step, runs the WASM circuit with concrete inputs
(public + private) and records every intermediate wire value.

**Important:** Witness files must form a valid state chain — the public outputs of
step `i` must equal the public inputs of step `i+1`. NovaSlim checks this during
folding.

---

## Step 3: Fold the Steps

Folding combines all step witnesses into one constant-size bundle.

```bash
nova-slim fold \
  --curve bn254 \
  --commitment sis --sis-param 128 \
  --circuit vrf_verify_nova.r1cs \
  --steps poc_witnesses/ \
  --out vrf.ivc.cbor
```

**What this does:**
- Loads the R1CS circuit
- Reads every `.wtns` file in `poc_witnesses/`
- Checks the state chain is valid (output → input)
- Folds all steps into one Relaxed-R1CS instance
- Writes the NIFS bundle to `vrf.ivc.cbor`

**Output:** `vrf.ivc.cbor` (~8–9 KiB) — the folded instance + transcript.

---

## Step 4: Compress to Slim Proof

Compression turns the folded instance into a small proof using the sumcheck protocol.
With `--slim`, the HashPC opening proofs are stripped for on-chain use.

```bash
# Slim proof (on-chain variant)
nova-slim compress --slim \
  --curve bn254 \
  --commitment sis --sis-param 128 \
  --circuit vrf_verify_nova.r1cs \
  --steps poc_witnesses/ \
  --out vrf_slim.cbor
```

**What this does:**
- Re-folds the witnesses deterministically (same result as Step 3)
- Runs the sumcheck prover on the final relaxed instance
- Strips the HashPC opening proofs
- Writes the slim proof to `vrf_slim.cbor`

**Output:** `vrf_slim.cbor` (~0.4 KiB) — sumcheck data only.

**Without `--slim`** you get a full proof (~9–10 KiB) that includes HashPC openings
for off-chain audit.

---

## Step 5: Verify Off-Chain

### Slim verification (fast, no openings)

```bash
nova-slim verify \
  --curve bn254 \
  --commitment sis --sis-param 128 \
  --ivc vrf.ivc.cbor \
  --slim-proof vrf_slim.cbor
```

**What this checks:**
- The slim proof's sumcheck protocol is valid
- Fiat-Shamir challenges match the transcript
- The final claim is zero (relaxed R1CS satisfied)
- The proof is bound to this specific NIFS bundle

**Time:** ~8 ms

### Full verification (audit-grade, with openings)

```bash
nova-slim verify \
  --curve bn254 \
  --commitment sis --sis-param 128 \
  --ivc vrf.ivc.cbor \
  --sumcheck-proof vrf_full.cbor
```

**What this additionally checks:**
- HashPC opening proofs for witness W and error E
- Pedersen/SIS/Hash commitments match the bundle

**Time:** ~50–60 ms

---

## Step 6: Verify On-Chain (Aiken)

The Aiken verifier is at `../nova-slim-verifier/`.

```bash
cd ../nova-slim-verifier

# 1. Build the validator
aiken build

# Output:
#   Compiling paweljakubas/nova-slim 0.0.0 (.)
#   Compiling aiken-lang/stdlib v3.1.0 (./build/packages/aiken-lang-stdlib)
#  Generating project's blueprint (./plutus.json)

# 2. Run tests
aiken check

# Output:
#      Testing ...
#   {
#     "summary": {
#       "total": 2,
#       "passed": 2,
#       "failed": 0
#     },
#     "modules": [
#       {
#         "name": "tests",
#         "summary": { "total": 2, "passed": 2, "failed": 0 },
#         "tests": [
#           { "title": "e2e_4_rounds", "status": "pass",
#             "execution_units": { "mem": 376920, "cpu": 141185485 } },
#           { "title": "mismatch_counts_fails", "status": "pass",
#             "execution_units": { "mem": 25041, "cpu": 6508150 } }
#         ]
#       }
#     ]
#   }

# 3. Apply the expected public input parameter
aiken apply plutus.json \
  --parameter-bytes <hex-encoded-public-input> \
  > validator.uplc

# 4. Submit to Cardano (example using cardano-cli)
cardano-cli transaction build-raw \
  --tx-in <your-input> \
  --tx-out <your-output> \
  --minting-script-file validator.uplc \
  --mint-redeemer-cbor-file ../../cardano/cip197/vrf_slim.cbor \
  --mint-script-datum-cbor-file ../../cardano/cip197/vrf.ivc.cbor \
  --out-file tx.raw
```

**What the validator checks:**
- `redeemer.public_input == expected_public_input`
- `verify_slim(datum, redeemer) == True`

The validator runs entirely in Plutus V3 using BLS12-381 scalar arithmetic.
**Execution units:** ~377K mem / ~141M CPU for a 4-round sumcheck.

---

## Mermaid: Complete Sequence

```mermaid
sequenceDiagram
    autonumber
    actor U as User
    participant CA as cardano-address
    participant C as circom compiler
    participant S as snarkjs
    participant NS as nova-slim CLI
    participant A as Aiken validator
    participant CH as Cardano Chain

    U->>CA: recovery-phrase generate
    CA-->>U: recovery-phrase.txt
    U->>CA: key from-recovery-phrase
    CA-->>U: root.xprv
    U->>CA: key child 1852H/1815H/0H
    CA-->>U: acct.xprv / acct.xpub
    U->>CA: key child 0/0
    CA-->>U: addr.xprv / addr.xpub

    U->>C: vrf_verify_nova.circom
    C-->>U: vrf_verify_nova.r1cs + .wasm

    U->>S: generate inputs per step
    S-->>U: step_0000.wtns … step_0004.wtns

    U->>NS: fold --circuit .r1cs --steps/ --out .ivc.cbor
    NS->>NS: check state chain
    NS->>NS: NIFS fold all steps
    NS-->>U: vrf.ivc.cbor (bundle)

    U->>NS: compress --slim --circuit .r1cs --steps/ --out .cbor
    NS->>NS: re-fold + sumcheck
    NS->>NS: strip HashPC openings
    NS-->>U: vrf_slim.cbor (slim proof)

    U->>NS: verify --ivc .cbor --slim-proof .cbor
    NS->>NS: sumcheck verify
    NS-->>U: ✅ Verified N steps

    U->>A: build + apply parameter
    A-->>U: validator.uplc

    U->>CH: submit tx with datum=.ivc.cbor redeemer=.slim.cbor
    CH->>CH: Plutus V3 verify_slim()
    CH-->>U: ✅ On-chain verification
```

---

## Files at Each Stage

| Stage | Input | Output | Size (typical) |
|---|---|---|---|
| Compile | `.circom` | `.r1cs`, `.wasm` | ~1–50 KiB |
| Witness | `.wasm` + inputs | `step_####.wtns` | ~1–50 KiB each |
| Fold | `.r1cs` + `step_*.wtns` | `.ivc.cbor` | ~2–10 KiB |
| Compress | `.r1cs` + `step_*.wtns` | `_slim.cbor` | **~0.4 KiB** |
| Verify | `.ivc.cbor` + `.cbor` | pass/fail | — |

---

## Common Flags

| Flag | Meaning | Example |
|---|---|---|
| `--curve` | Elliptic curve (determines scalar field) | `bls12-381`, `bn254` |
| `--commitment` | Commitment scheme | `pedersen`, `sis`, `hash` |
| `--sis-param` | SIS output dimension (only for `--commitment sis`) | `4` (fast), `128` (PQ) |
| `--opt` | Optimizations | `parallel`, `lazy`, `all`, `none` |
| `--slim` | Strip openings for on-chain proof | — |

---

## Quick Test (Copy-Paste)

```bash
cd cardano/cip197

# 0. Derive BIP32 keys (optional for VRF PoC, required for real BIP32 circuit)
cardano-address recovery-phrase generate --size 15 > recovery-phrase.txt
cardano-address key from-recovery-phrase Shelley < recovery-phrase.txt > root.xprv
cardano-address key child 1852H/1815H/0H < root.xprv > acct.xprv
cardano-address key public --with-chain-code < acct.xprv > acct.xpub
cardano-address key child 0/0 < acct.xprv > addr.xprv
cardano-address key public --with-chain-code < addr.xprv > addr.xpub

# 1. Compile
circom -l ../../circom/Ed25519Verify/node_modules/circomlib/circuits -l . \
  ../../circom/VRF/vrf_verify_nova.circom --r1cs --wasm --sym

# 2. Witnesses (5 steps)
python3 ../../benchmarks/gen_vrf_witnesses.py \
  --wasm vrf_verify_nova_js/vrf_verify_nova.wasm \
  --steps 5 --dir poc_witnesses

# 3. Fold
nova-slim fold --curve bn254 --commitment sis --sis-param 128 \
  --circuit vrf_verify_nova.r1cs --steps poc_witnesses --out vrf.ivc.cbor

# 4. Compress (slim)
nova-slim compress --slim --curve bn254 --commitment sis --sis-param 128 \
  --circuit vrf_verify_nova.r1cs --steps poc_witnesses --out vrf_slim.cbor

# 5. Verify
nova-slim verify --curve bn254 --commitment sis --sis-param 128 \
  --ivc vrf.ivc.cbor --slim-proof vrf_slim.cbor

# 6. Build Aiken verifier
cd ../nova-slim-verifier
aiken check  # run tests
aiken build  # generate plutus.json
```

**Expected total time:** < 1 second for steps 1–5 (VRF, 5 steps).
