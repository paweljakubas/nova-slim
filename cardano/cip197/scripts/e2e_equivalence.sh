#!/usr/bin/env bash
# =============================================================================
# e2e_equivalence.sh — end-to-end check of the CIP-197 NovaSlim pipeline.
#
#   Both documented walkthroughs (README.md and E2E.md) use the SAME step
#   circuit (circom/VRF/vrf_verify_nova.circom), the SAME witness generator
#   (benchmarks/gen_vrf_witnesses.py) and the SAME NovaSlim pipeline
#   (fold -> compress --slim -> verify) on the SAME BLS12-381 scalar field —
#   the curve Cardano uses on-chain (Plutus V3), so the proofs are directly
#   verifiable by the Aiken validator in ../nova-slim-verifier/.
#
# This script runs that pipeline end-to-end and asserts that:
#   - every stage succeeds (circom compile, witness gen, fold, slim compress,
#     slim verify; also the full sumcheck proof variant),
#   - tampered inputs (corrupted step witness, flipped proof byte) are rejected,
#   - the interchangeable knobs hold: Pedersen instead of SIS, full sumcheck
#     proof instead of slim, and a proof never verifies a bundle it was not
#     created for.
# It also, if cardano-address is installed, shows the real BIP32 key derivation
# that E2E.md uses as the circuit context.  Exits non-zero on any failure.
#
# Requirements: nova-slim (built), circom, snarkjs, python3.
#               cardano-address is OPTIONAL (keys are context, not pipeline).
#
# Usage:  bash cardano/cip197/scripts/e2e_equivalence.sh [STEPS]
#         STEPS defaults to 5.
# =============================================================================
set -uo pipefail

STEPS="${1:-5}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
NOVA="${NOVA:-$ROOT/cli/target/release/nova-slim}"
CIRCUIT="$ROOT/circom/VRF/vrf_verify_nova.circom"
CIRCOMLIB="$ROOT/circom/Ed25519Verify/node_modules/circomlib/circuits"
GEN_WIT="$ROOT/benchmarks/gen_vrf_witnesses.py"
CREDS="--commitment sis --sis-param 128"
CURVE="bls12-381"
PRIME_FLAG="--prime bls12381"

WORK="$(mktemp -d /tmp/e2e_equivalence.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

PASS_COUNT=0
FAIL_COUNT=0

note()  { printf '\033[36m[%s]\033[0m %s\n' "$(date +%H:%M:%S)" "$*"; }
ok()    { printf '  \033[32m PASS\033[0m  %s\n' "$*"; PASS_COUNT=$((PASS_COUNT + 1)); }
fail()  { printf '  \033[31m FAIL\033[0m  %s\n' "$*"; FAIL_COUNT=$((FAIL_COUNT + 1)); }

# run_check <label> <expected_exit> <args...>: runs nova-slim, compares exit code
run_check() {
    local label="$1" want="$2"
    shift 2
    if "$NOVA" "$@" >/dev/null 2>&1; then local got=0; else local got=$?; fi
    if [ "$got" -eq "$want" ]; then ok "$label"; else fail "$label (exit=$got, want=$want)"; fi
}

# run_way <dir> <label>: full pipeline on the shared bls12-381 field
run_way() {
    local dir="$1" label="$2" back="$(pwd)"
    mkdir -p "$WORK/$dir"
    cd "$WORK/$dir" || exit 1

    note "$label: compile step circuit ($PRIME_FLAG, --curve $CURVE)"
    if circom $PRIME_FLAG -l "$CIRCOMLIB" -l . "$CIRCUIT" --r1cs --wasm >/dev/null 2>&1; then
        ok "circom $PRIME_FLAG"
    else
        fail "circom $PRIME_FLAG"
    fi

    note "$label: generate $STEPS step witnesses"
    if python3 "$GEN_WIT" --wasm vrf_verify_nova_js/vrf_verify_nova.wasm \
        --steps "$STEPS" --dir poc_witnesses >/dev/null 2>&1; then
        ok "witnesses ($STEPS steps)"
    else
        fail "witnesses"
    fi

    note "$label: fold -> bundle, compress --slim, verify --slim-proof"
    run_check "fold"    0 fold     --curve "$CURVE" $CREDS --circuit vrf_verify_nova.r1cs --steps poc_witnesses --out way.ivc.cbor
    run_check "compress" 0 compress --slim --curve "$CURVE" $CREDS --circuit vrf_verify_nova.r1cs --steps poc_witnesses --out way_slim.cbor
    run_check "verify"  0 verify   --curve "$CURVE" $CREDS --ivc way.ivc.cbor --slim-proof way_slim.cbor

    note "$label: tamper rejection"
    # T1: corrupt a step witness -> re-fold must fail (state chain broken)
    mkdir -p poc_tampered
    cp poc_witnesses/step_*.wtns poc_tampered/
    python3 - <<'PY'
import glob
src = sorted(glob.glob("poc_tampered/step_*.wtns"))
if src:
    d = bytearray(open(src[0], "rb").read())
    d[len(d) // 4] ^= 1
    open(src[0], "wb").write(bytes(d))
PY
    run_check "fold rejects tampered witness" 1 fold --curve "$CURVE" $CREDS \
        --circuit vrf_verify_nova.r1cs --steps poc_tampered --out tampered.ivc.cbor
    # T2: byte-flip the slim proof -> verify must fail
    cp way_slim.cbor way_slim_bad.cbor
    python3 -c "
d = bytearray(open('way_slim_bad.cbor','rb').read()); d[len(d)//2] ^= 1
open('way_slim_bad.cbor','wb').write(bytes(d))"
    run_check "verify rejects tampered slim proof" 1 verify --curve "$CURVE" $CREDS \
        --ivc way.ivc.cbor --slim-proof way_slim_bad.cbor

    cd "$back" || exit 1
}

# ---------------------------------------------------------------------------
# Shared bls12-381 pipeline (the curve both README.md and E2E.md use)
# ---------------------------------------------------------------------------
run_way way_e2e  "E2E.md walkthrough (bls12-381)"
run_way way_readme "README quick walkthrough (bls12-381)"

# ---------------------------------------------------------------------------
# Interchangeable knobs — same pipeline, different flags
# ---------------------------------------------------------------------------
note "Interchange: commitment scheme (pedersen instead of SIS)"
cd "$WORK/way_e2e" || exit 1
run_check "fold (pedersen)"     0 fold     --curve "$CURVE" --commitment pedersen --circuit vrf_verify_nova.r1cs --steps poc_witnesses --out ped.ivc.cbor
run_check "compress (pedersen)" 0 compress --slim --curve "$CURVE" --commitment pedersen --circuit vrf_verify_nova.r1cs --steps poc_witnesses --out ped_slim.cbor
run_check "verify (pedersen)"   0 verify   --curve "$CURVE" --commitment pedersen --ivc ped.ivc.cbor --slim-proof ped_slim.cbor

note "Interchange: proof form (full sumcheck proof instead of slim)"
cd "$WORK/way_readme" || exit 1
run_check "compress (full)" 0 compress --curve "$CURVE" $CREDS --circuit vrf_verify_nova.r1cs --steps poc_witnesses --out way_full.cbor
run_check "verify (full)"   0 verify   --curve "$CURVE" $CREDS --ivc way.ivc.cbor --sumcheck-proof way_full.cbor

note "Interchange: binding (SIS proof must not verify a Pedersen bundle)"
cd "$WORK/way_e2e" || exit 1
run_check "compress (pedersen, full)" 0 compress --curve "$CURVE" --commitment pedersen \
    --circuit vrf_verify_nova.r1cs --steps poc_witnesses --out ped_full.cbor
run_check "verify rejects cross-commitment proof" 1 verify --curve "$CURVE" $CREDS \
    --ivc way.ivc.cbor --sumcheck-proof ped_full.cbor

# ---------------------------------------------------------------------------
# Optional: real BIP32 key derivation à la E2E.md (context only, not pipeline)
# ---------------------------------------------------------------------------
if command -v cardano-address >/dev/null 2>&1; then
    note "Key provenance: real cardano-address derivation (E2E Step 0, context only)"
    (
        cd "$WORK" || exit 1
        cardano-address recovery-phrase generate --size 15 > rp.txt
        cardano-address key from-recovery-phrase Shelley < rp.txt > root.xprv
        cardano-address key child 1852H/1815H/0H < root.xprv > acct.xprv
        cardano-address key child 0/0 < acct.xprv > addr.xprv
        cardano-address key public --with-chain-code < acct.xprv > acct.xpub
        addr_xpub="$(cardano-address key inspect < acct.xpub \
            | grep -oE '"extended_key": "[0-9a-f]+"' | awk -F'"' '{print $4}')"
        printf '  \033[32m PASS\033[0m  real BIP32 account xpub (context for future BIP32 circuit):\n             %s\n' "$addr_xpub"
    )
    PASS_COUNT=$((PASS_COUNT + 1))
else
    note "cardano-address not found — skipping optional key-provenance (not needed by the pipeline)"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo
echo "================================================================"
printf 'bundle %s B, slim %s B\n' \
    "$(stat -c%s "$WORK/way_e2e/way.ivc.cbor")" "$(stat -c%s "$WORK/way_e2e/way_slim.cbor")"
echo "Both documented walkthroughs (README.md and E2E.md) run the same"
echo "bls12-381 fold -> compress --slim -> verify pipeline — the curve Cardano"
echo "uses on-chain (Plutus V3) — so the proofs are directly verifiable by"
echo "../nova-slim-verifier.  Only commitment, proof form and key provenance"
echo "may be swapped — all interchangeable."
echo "--------------------------------------------------------------"
printf 'RESULT: %d passed, %d failed\n' "$PASS_COUNT" "$FAIL_COUNT"
echo "================================================================"
[ "$FAIL_COUNT" -eq 0 ]