# PoC Results: NovaSlim for CIP-197

**Date:** 2026-08-27
**Circuit:** VRF scalar multiplication step (JubJub, BN254)
**Steps:** 5
**Commitment:** SIS (m=128)

## End-to-end Flow

### 1. Compile circuit
```bash
circom -l ../Ed25519Verify/node_modules/circomlib/circuits -l . \
  vrf_verify_nova.circom --r1cs --wasm --sym
```
- **Circuit:** 0 linear constraints, 4 public inputs, 1 private input, 4 public outputs
- **Prime:** BN254 (0x30644e72...)

### 2. Generate witnesses
```bash
python3 benchmarks/gen_vrf_witnesses.py \
  --wasm vrf_verify_nova_js/vrf_verify_nova.wasm \
  --steps 5 --dir poc_witnesses
```
- Generated 5 step witnesses (Montgomery ladder bits)
- **Time:** ~1s total

### 3. Fold
```bash
nova-slim fold --curve bn254 --commitment sis --sis-param 128 \
  --circuit vrf_verify_nova.r1cs --steps poc_witnesses \
  --out vrf.ivc.cbor
```
- **Time:** 78ms
- **Output:** vrf.ivc.cbor (8.7 KiB)

### 4. Compress (slim)
```bash
nova-slim compress --slim --curve bn254 --commitment sis --sis-param 128 \
  --circuit vrf_verify_nova.r1cs --steps poc_witnesses \
  --out vrf_slim.cbor
```
- **Time:** 127ms
- **Full proof:** 9,770 bytes
- **Slim proof:** 388 bytes
- **Reduction:** 96%

### 5. Verify off-chain (slim)
```bash
nova-slim verify --curve bn254 --commitment sis --sis-param 128 \
  --ivc vrf.ivc.cbor --slim-proof vrf_slim.cbor
```
- **Time:** 8ms
- **Result:** ✅ Verified 5 steps: slim sumcheck proof OK, state chain OK

### 6. Verify off-chain (full)
```bash
nova-slim verify --curve bn254 --commitment sis --sis-param 128 \
  --ivc vrf.ivc.cbor --sumcheck-proof vrf_full.cbor
```
- **Time:** 57ms
- **Result:** ✅ Verified 5 steps: sumcheck compression proof OK, commitments OK, state chain OK

## File Sizes

| File | Size |
|---|---|
| NIFS bundle (vrf.ivc.cbor) | 8.7 KiB |
| Full proof (vrf_full.cbor) | 9.6 KiB |
| **Slim proof (vrf_slim.cbor)** | **388 bytes** |
| **Total on-chain payload** | **~9.1 KiB** |

The total on-chain payload (bundle + slim proof) is **~9.1 KiB**, well under Cardano's
`maxTxSize` of 16,384 bytes.

## Key Observations

1. **Slim proof is 96% smaller** than the full proof (388 B vs 9.6 KiB)
2. **Slim verification is 7× faster** than full verification (8ms vs 57ms)
3. **Total payload fits on-chain** today, no protocol changes needed
4. **SIS m=128** provides post-quantum commitment hardness (with norm caveat)

## On-chain Verification (Aiken)

The Aiken verifier at `../nova-slim-verifier/` can verify these proofs in Plutus V3.
See the verifier README for build and deploy instructions.

## Limitations

- This PoC uses the VRF circuit (JubJub scalar mul), not BIP32-Ed25519 derivation.
  The BIP32 circuit would require HMAC-SHA512 (~10K constraints per step).
- BN254 was used because JubJub is defined over BN254's scalar field. BLS12-381
  would require a BLS12-381-friendly curve (e.g. Bandersnatch) for the step circuit.
- 5 steps is tiny; real BIP32 derivation needs 2 steps (role → index) from account'.
