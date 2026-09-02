#!/usr/bin/env python3
"""NovaSlim **traditional** benchmark runner — real circom circuits + snarkjs.

Curves supported: BLS12-381, BN254, Grumpkin, Pallas, Vesta.
Bandersnatch is NOT available here because circom does not support the
Bandersnatch scalar field prime. For Bandersnatch, use the synthetic
benchmark instead:

    cargo run --release --manifest-path prover/Cargo.toml --bin benchmark_synthetic -- --curve bandersnatch --state-width 24 --steps 255

For each circuit family this script:

  1. compiles the step circuit with circom if the .r1cs/.wasm are missing,
  2. generates (or resumes) chained step witnesses with snarkjs,
  3. builds `benchmark_nova --release`,
  4. runs baseline and --opt-parallel passes,
  5. writes raw logs plus a markdown summary under benchmarks/results/.

Usage:
    python3 benchmarks/run_benchmarks.py                 # all families
    python3 benchmarks/run_benchmarks.py --steps 32      # shorter chains
    python3 benchmarks/run_benchmarks.py --curve grumpkin
    python3 benchmarks/run_benchmarks.py --family ed25519_verify_nova_bls12_381
"""
import argparse
import datetime
import glob
import json
import os
import subprocess
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_DIR = os.path.dirname(SCRIPT_DIR)
RESULTS_DIR = os.path.join(SCRIPT_DIR, "results")
WORK_DIR = os.path.join(SCRIPT_DIR, "work")
CIRCOM_DIR = os.path.join(REPO_DIR, "circom")

# Curve25519 base point G in extended coordinates, base-2^85 limbs, and the
# Edwards identity — the initial IVC state of both Ed25519 step circuits.
ED25519_BASE_POINT_G = [
    ["6836562328990639286768922", "21231440843933962135602345", "10097852978535018773096760"],
    ["7737125245533626718119512", "23211375736600880154358579", "30948500982134506872478105"],
    ["1", "0", "0"],
    ["20943500354259764865654179", "24722277920680796426601402", "31289658119428895172835987"],
]
EDWARDS_IDENTITY = [["0", "0", "0"], ["1", "0", "0"], ["1", "0", "0"], ["0", "0", "0"]]


CIRCOM_PRIMES = {
    "bls12-381": "bls12381",
    "bn254": "bn128",
    "grumpkin": "grumpkin",
    "pallas": "pallas",
    "vesta": "vesta",
    "bandersnatch": "bls12381",
}


def ed25519_step_family(dir_name):
    """Both Ed25519 scalar-mul step circuits share the same signal layout.

    The witness JSON from snarkjs places public outputs in signal-declaration
    order: all dblOut[4][3] first (indices 1..12), then all addOut[4][3]
    (indices 13..24).  The outputs list must match this order so that
    gen_step_witnesses.py maps prev_vals[i] → the correct input signal.
    """
    inputs = {}
    outputs = []
    for i in range(4):
        for j in range(3):
            inputs[f"dbl_in_{i}_{j}"] = ED25519_BASE_POINT_G[i][j]
            inputs[f"add_in_{i}_{j}"] = EDWARDS_IDENTITY[i][j]
    # dbl outputs come first in the witness (indices 1..12)
    for i in range(4):
        for j in range(3):
            outputs.append(f"dbl_in_{i}_{j}=dbl_out_{i}_{j}")
    # add outputs come next (indices 13..24)
    for i in range(4):
        for j in range(3):
            outputs.append(f"add_in_{i}_{j}=add_out_{i}_{j}")
    inputs["sel"] = "1"
    return {"inputs": inputs, "outputs": ",".join(outputs), "dir": dir_name}


# Supported benchmark configurations for the TRADITIONAL benchmark runner.
# Pallas and Vesta are EXCLUDED because snarkjs does not generate valid
# witnesses for pasta curves ("Curve not supported"). Use the synthetic
# benchmark for Pallas / Vesta:
#   cargo run --release --manifest-path prover/Cargo.toml --bin benchmark_synthetic -- --curve pallas --state-width 24 --steps 255
FAMILIES = {
    # Ed25519 verify — medium circuit (7,724 constraints), the primary benchmark
    "ed25519_verify_nova_bls12_381": {
        **ed25519_step_family("Ed25519Verify"),
        "circuit_name": "ed25519_verify_nova",
        "curve": "bls12-381",
        "default_steps": 255,
    },
    "ed25519_verify_nova_bn254": {
        **ed25519_step_family("Ed25519Verify"),
        "circuit_name": "ed25519_verify_nova",
        "curve": "bn254",
        "default_steps": 255,
    },
    # Ed25519 scaling series — same circuit, varying step counts
    "ed25519_verify_nova_bls12_381_16": {
        **ed25519_step_family("Ed25519Verify"),
        "circuit_name": "ed25519_verify_nova",
        "curve": "bls12-381",
        "default_steps": 16,
    },
    "ed25519_verify_nova_bls12_381_64": {
        **ed25519_step_family("Ed25519Verify"),
        "circuit_name": "ed25519_verify_nova",
        "curve": "bls12-381",
        "default_steps": 64,
    },
    "ed25519_verify_nova_bls12_381_1024": {
        **ed25519_step_family("Ed25519Verify"),
        "circuit_name": "ed25519_verify_nova",
        "curve": "bls12-381",
        "default_steps": 1024,
    },
    "ed25519_verify_nova_bn254_16": {
        **ed25519_step_family("Ed25519Verify"),
        "circuit_name": "ed25519_verify_nova",
        "curve": "bn254",
        "default_steps": 16,
    },
    "ed25519_verify_nova_bn254_64": {
        **ed25519_step_family("Ed25519Verify"),
        "circuit_name": "ed25519_verify_nova",
        "curve": "bn254",
        "default_steps": 64,
    },
    "ed25519_verify_nova_bn254_1024": {
        **ed25519_step_family("Ed25519Verify"),
        "circuit_name": "ed25519_verify_nova",
        "curve": "bn254",
        "default_steps": 1024,
    },
    # Grumpkin, Pallas, Vesta variants (real circom circuits supported)
    "ed25519_verify_nova_grumpkin": {
        **ed25519_step_family("Ed25519Verify"),
        "circuit_name": "ed25519_verify_nova",
        "curve": "grumpkin",
        "default_steps": 255,
    },
    "ed25519_verify_nova_pallas": {
        **ed25519_step_family("Ed25519Verify"),
        "circuit_name": "ed25519_verify_nova",
        "curve": "pallas",
        "default_steps": 255,
    },
    "ed25519_verify_nova_vesta": {
        **ed25519_step_family("Ed25519Verify"),
        "circuit_name": "ed25519_verify_nova",
        "curve": "vesta",
        "default_steps": 255,
    },
    # VRF — tiny circuit (9 constraints), isolates protocol overhead
    "vrf_verify_nova_bls12_381": {
        "circuit_name": "vrf_verify_nova",
        "curve": "bls12-381",
        "default_steps": 254,
        "dir": "VRF",
        "witness_script": "gen_vrf_witnesses.py",
    },
    "vrf_verify_nova_bn254": {
        "circuit_name": "vrf_verify_nova",
        "curve": "bn254",
        "default_steps": 254,
        "dir": "VRF",
        "witness_script": "gen_vrf_witnesses.py",
    },
    "vrf_verify_nova_grumpkin": {
        "circuit_name": "vrf_verify_nova",
        "curve": "grumpkin",
        "default_steps": 254,
        "dir": "VRF",
        "witness_script": "gen_vrf_witnesses.py",
    },
    "vrf_verify_nova_pallas": {
        "circuit_name": "vrf_verify_nova",
        "curve": "pallas",
        "default_steps": 254,
        "dir": "VRF",
        "witness_script": "gen_vrf_witnesses.py",
    },
    "vrf_verify_nova_vesta": {
        "circuit_name": "vrf_verify_nova",
        "curve": "vesta",
        "default_steps": 254,
        "dir": "VRF",
        "witness_script": "gen_vrf_witnesses.py",
    },
    # PoseidonMerkle — hash-heavy circuit (~639 constraints), blockchain-relevant
    "poseidon_merkle_nova_bls12_381": {
        "circuit_name": "poseidon_merkle_nova",
        "curve": "bls12-381",
        "default_steps": 32,
        "dir": "PoseidonMerkle",
        "witness_script": "gen_poseidon_merkle_witnesses.py",
    },
    "poseidon_merkle_nova_bn254": {
        "circuit_name": "poseidon_merkle_nova",
        "curve": "bn254",
        "default_steps": 32,
        "dir": "PoseidonMerkle",
        "witness_script": "gen_poseidon_merkle_witnesses.py",
    },
    "poseidon_merkle_nova_grumpkin": {
        "circuit_name": "poseidon_merkle_nova",
        "curve": "grumpkin",
        "default_steps": 32,
        "dir": "PoseidonMerkle",
        "witness_script": "gen_poseidon_merkle_witnesses.py",
    },
    "poseidon_merkle_nova_pallas": {
        "circuit_name": "poseidon_merkle_nova",
        "curve": "pallas",
        "default_steps": 32,
        "dir": "PoseidonMerkle",
        "witness_script": "gen_poseidon_merkle_witnesses.py",
    },
    "poseidon_merkle_nova_vesta": {
        "circuit_name": "poseidon_merkle_nova",
        "curve": "vesta",
        "default_steps": 32,
        "dir": "PoseidonMerkle",
        "witness_script": "gen_poseidon_merkle_witnesses.py",
    },
    # PoseidonSponge — comparable to Sonobe hash_chain, ~633 constraints
    "poseidon_sponge_nova_bls12_381": {
        "circuit_name": "poseidon_sponge_nova",
        "curve": "bls12-381",
        "default_steps": 255,
        "dir": "PoseidonSponge",
        "witness_script": "gen_poseidon_sponge_witnesses.py",
    },
    "poseidon_sponge_nova_bn254": {
        "circuit_name": "poseidon_sponge_nova",
        "curve": "bn254",
        "default_steps": 255,
        "dir": "PoseidonSponge",
        "witness_script": "gen_poseidon_sponge_witnesses.py",
    },
    "poseidon_sponge_nova_grumpkin": {
        "circuit_name": "poseidon_sponge_nova",
        "curve": "grumpkin",
        "default_steps": 255,
        "dir": "PoseidonSponge",
        "witness_script": "gen_poseidon_sponge_witnesses.py",
    },
    "poseidon_sponge_nova_pallas": {
        "circuit_name": "poseidon_sponge_nova",
        "curve": "pallas",
        "default_steps": 255,
        "dir": "PoseidonSponge",
        "witness_script": "gen_poseidon_sponge_witnesses.py",
    },
    "poseidon_sponge_nova_vesta": {
        "circuit_name": "poseidon_sponge_nova",
        "curve": "vesta",
        "default_steps": 255,
        "dir": "PoseidonSponge",
        "witness_script": "gen_poseidon_sponge_witnesses.py",
    },
    # SHA-256 step circuits — small (8 bytes, ~29K constraints), medium (32 bytes, ~31K), big (32 bytes + 256-bit padding, ~59K)
    "sha256_small_nova_bls12_381": {
        "circuit_name": "sha256_step_small_nova",
        "curve": "bls12-381",
        "default_steps": 32,
        "dir": "Sha256Step",
        "witness_script": "gen_sha256_witnesses.py",
        "witness_script_args": ["--state-size", "8"],
        "build_subdir": "build_bls12381",
    },
    "sha256_small_nova_bn254": {
        "circuit_name": "sha256_step_small_nova",
        "curve": "bn254",
        "default_steps": 32,
        "dir": "Sha256Step",
        "witness_script": "gen_sha256_witnesses.py",
        "witness_script_args": ["--state-size", "8"],
        "build_subdir": "build_bn128",
    },
    "sha256_small_nova_grumpkin": {
        "circuit_name": "sha256_step_small_nova",
        "curve": "grumpkin",
        "default_steps": 32,
        "dir": "Sha256Step",
        "witness_script": "gen_sha256_witnesses.py",
        "witness_script_args": ["--state-size", "8"],
    },
    "sha256_small_nova_pallas": {
        "circuit_name": "sha256_step_small_nova",
        "curve": "pallas",
        "default_steps": 32,
        "dir": "Sha256Step",
        "witness_script": "gen_sha256_witnesses.py",
        "witness_script_args": ["--state-size", "8"],
        "build_subdir": "build_pallas",
    },
    "sha256_small_nova_vesta": {
        "circuit_name": "sha256_step_small_nova",
        "curve": "vesta",
        "default_steps": 32,
        "dir": "Sha256Step",
        "witness_script": "gen_sha256_witnesses.py",
        "witness_script_args": ["--state-size", "8"],
        "build_subdir": "build_vesta",
    },
    "sha256_medium_nova_bls12_381": {
        "circuit_name": "sha256_step_nova",
        "curve": "bls12-381",
        "default_steps": 32,
        "dir": "Sha256Step",
        "witness_script": "gen_sha256_witnesses.py",
        "witness_script_args": ["--state-size", "32"],
        "build_subdir": "build_bls12381",
    },
    "sha256_medium_nova_bn254": {
        "circuit_name": "sha256_step_nova",
        "curve": "bn254",
        "default_steps": 32,
        "dir": "Sha256Step",
        "witness_script": "gen_sha256_witnesses.py",
        "witness_script_args": ["--state-size", "32"],
        "build_subdir": "build_bn128",
    },
    "sha256_medium_nova_grumpkin": {
        "circuit_name": "sha256_step_nova",
        "curve": "grumpkin",
        "default_steps": 32,
        "dir": "Sha256Step",
        "witness_script": "gen_sha256_witnesses.py",
        "witness_script_args": ["--state-size", "32"],
    },
    "sha256_medium_nova_pallas": {
        "circuit_name": "sha256_step_nova",
        "curve": "pallas",
        "default_steps": 32,
        "dir": "Sha256Step",
        "witness_script": "gen_sha256_witnesses.py",
        "witness_script_args": ["--state-size", "32"],
        "build_subdir": "build_pallas",
    },
    "sha256_medium_nova_vesta": {
        "circuit_name": "sha256_step_nova",
        "curve": "vesta",
        "default_steps": 32,
        "dir": "Sha256Step",
        "witness_script": "gen_sha256_witnesses.py",
        "witness_script_args": ["--state-size", "32"],
        "build_subdir": "build_vesta",
    },
    "sha256_big_nova_bls12_381": {
        "circuit_name": "sha256_step_big_nova",
        "curve": "bls12-381",
        "default_steps": 32,
        "dir": "Sha256Step",
        "witness_script": "gen_sha256_witnesses.py",
        "witness_script_args": ["--state-size", "32"],
        "build_subdir": "build_bls12381",
    },
    "sha256_big_nova_bn254": {
        "circuit_name": "sha256_step_big_nova",
        "curve": "bn254",
        "default_steps": 32,
        "dir": "Sha256Step",
        "witness_script": "gen_sha256_witnesses.py",
        "witness_script_args": ["--state-size", "32"],
        "build_subdir": "build_bn128",
    },
    "sha256_big_nova_grumpkin": {
        "circuit_name": "sha256_step_big_nova",
        "curve": "grumpkin",
        "default_steps": 32,
        "dir": "Sha256Step",
        "witness_script": "gen_sha256_witnesses.py",
        "witness_script_args": ["--state-size", "32"],
    },
    "sha256_big_nova_pallas": {
        "circuit_name": "sha256_step_big_nova",
        "curve": "pallas",
        "default_steps": 32,
        "dir": "Sha256Step",
        "witness_script": "gen_sha256_witnesses.py",
        "witness_script_args": ["--state-size", "32"],
        "build_subdir": "build_pallas",
    },
    "sha256_big_nova_vesta": {
        "circuit_name": "sha256_step_big_nova",
        "curve": "vesta",
        "default_steps": 32,
        "dir": "Sha256Step",
        "witness_script": "gen_sha256_witnesses.py",
        "witness_script_args": ["--state-size", "32"],
        "build_subdir": "build_vesta",
    },
    # Bandersnatch: scalar field not supported by circom. Use benchmark_synthetic.
}


def ensure_compiled(family, name, steps_dir):
    """Compile or copy the circom circuit for the target curve if missing."""
    circuit_name = family["circuit_name"]
    curve = family["curve"]
    r1cs = os.path.join(steps_dir, f"{circuit_name}.r1cs")
    wasm = os.path.join(steps_dir, f"{circuit_name}_js", f"{circuit_name}.wasm")
    if os.path.exists(r1cs) and os.path.exists(wasm):
        return r1cs, wasm

    # Some circuits are pre-compiled in build_subdir
    if "build_subdir" in family:
        build_dir = os.path.join(CIRCOM_DIR, family["dir"], family["build_subdir"])
        src_r1cs = os.path.join(build_dir, f"{circuit_name}.r1cs")
        src_wasm = os.path.join(build_dir, f"{circuit_name}_js", f"{circuit_name}.wasm")
        if os.path.exists(src_r1cs) and os.path.exists(src_wasm):
            import shutil
            shutil.copy(src_r1cs, r1cs)
            js_dir = os.path.join(steps_dir, f"{circuit_name}_js")
            os.makedirs(js_dir, exist_ok=True)
            shutil.copy(src_wasm, wasm)
            print(f"copied pre-built {circuit_name} from {build_dir}")
            return r1cs, wasm

    src = os.path.join(CIRCOM_DIR, family["dir"], f"{circuit_name}.circom")
    if not os.path.exists(src):
        sys.exit(f"circuit source missing: {src}")
    prime = CIRCOM_PRIMES[curve]
    cmd = ["circom", "--prime", prime]
    # Ed25519Verify circomlib
    inc1 = os.path.join(CIRCOM_DIR, "Ed25519Verify", "node_modules", "circomlib", "circuits")
    if os.path.isdir(inc1):
        cmd += ["-l", inc1]
    cmd += [src, "--r1cs", "--wasm", "--sym", "--output", steps_dir]
    print(f"compiling {circuit_name}.circom for {curve} (prime={prime}) ...")
    run(cmd)
    return r1cs, wasm


def prune_witness_intermediates(steps_dir):
    """Free disk after generation: keep step_*.wtns plus the newest wit_*.json
    (the resume anchor for interrupted runs); drop the rest."""
    if not os.path.isdir(steps_dir):
        return
    wits = sorted(glob.glob(os.path.join(steps_dir, "wit_*.json")))
    for p in wits[:-1]:
        os.remove(p)
    for p in glob.glob(os.path.join(steps_dir, "input_*.json")):
        os.remove(p)


def parse_bench_log(path):
    out = {}
    for line in open(path):
        if line.startswith("nifs fold:"):
            parts = line.split()
            out["fold_s"], out["fold_ms_per_step"] = float(parts[2]), float(parts[5])
        elif line.startswith("sumcheck compress:"):
            out["compress_s"] = float(line.split()[2])
        elif line.startswith("level1 compress:"):
            out["level1_compress_s"] = float(line.split()[2])
        elif line.startswith("verify (full):"):
            out["verify_full_s"] = float(line.split()[2])
        elif line.startswith("verify (slim):"):
            out["verify_slim_s"] = float(line.split()[2])
        elif line.startswith("verify (level-1):"):
            # "verify (level-1): 0.0123 s ..."  -> 0.0123
            out["verify_level1_s"] = float(line.split()[2])
        elif line.startswith("nifs bundle:"):
            out["bundle_bytes"] = int(line.split()[2])
        elif line.startswith("slim proof:"):
            out["slim_proof_bytes"] = int(line.split()[2])
        elif line.startswith("level1 proof:"):
            out["level1_proof_bytes"] = int(line.split()[2])
        elif line.startswith("norm-range level1 compress:"):
            parts = line.split()
            # "norm-range level1 compress: 0.0100 s | verify: 0.0090 s | proof: 8192 B (B = 2^64)"
            out["norm_range_compress_s"] = float(parts[3])
            out["norm_range_verify_s"] = float(parts[7])
            out["norm_range_proof_bytes"] = int(parts[11])
        elif line.startswith("norm-jl level1 compress:"):
            parts = line.split()
            out["norm_jl_compress_s"] = float(parts[3])
            out["norm_jl_verify_s"] = float(parts[7])
            out["norm_jl_proof_bytes"] = int(parts[11])
        elif line.startswith("sumcheck proof (full):"):
            out["full_proof_bytes"] = int(line.split()[3])
    return out


def _strip_ansi(s):
    """Remove ANSI escape sequences from a string."""
    import re
    return re.sub(r"\x1b\[[0-9;]*m", "", s)


def r1cs_constraint_count(path):
    """Extract constraint count from an R1CS file using snarkjs."""
    try:
        r = subprocess.run(["snarkjs", "r1cs", "info", path],
                           capture_output=True, text=True)
        for line in r.stdout.splitlines():
            clean = _strip_ansi(line)
            if "# of Constraints:" in clean:
                # Line format: "[INFO]  snarkJS: # of Constraints: 7724"
                parts = clean.rsplit(":", 1)
                if len(parts) >= 2:
                    return int(parts[1].strip().replace(",", ""))
    except Exception as e:
        print(f"warning: could not parse constraint count from {path}: {e}")
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--family", choices=sorted(FAMILIES), action="append",
                    help="circuit to benchmark (default: all)")
    ap.add_argument("--steps", type=int, help="override chain length")
    ap.add_argument("--curve", choices=list(CIRCOM_PRIMES.keys()), action="append",
                    help="filter families by curve (default: all)")
    ap.add_argument("--commitment", choices=["pedersen", "sis", "hash"], default="pedersen",
                    help="commitment scheme for folding (default: pedersen)")
    ap.add_argument("--sis-param", type=int, default=4,
                    help="SIS parameter m (default: 4)")
    ap.add_argument("--skip-witness-gen", action="store_true")
    args = ap.parse_args()

    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    out_dir = os.path.join(RESULTS_DIR, stamp)
    os.makedirs(out_dir, exist_ok=True)

    manifest = os.path.join(REPO_DIR, "prover", "Cargo.toml")
    run(["cargo", "build", "--release", "--manifest-path", manifest,
         "--features", "bls12-381 bn254 pallas vesta bandersnatch grumpkin",
         "--bin", "benchmark_nova"])
    bench_bin = os.path.join(REPO_DIR, "prover", "target", "release", "benchmark_nova")

    rows = []
    selected = args.family or sorted(FAMILIES)
    if args.curve:
        selected = [f for f in selected if FAMILIES[f]["curve"] in args.curve]

    for name in selected:
        fam = FAMILIES[name]
        n_steps = args.steps or fam["default_steps"]
        work = os.path.join(WORK_DIR, name)
        os.makedirs(work, exist_ok=True)

        r1cs, wasm = ensure_compiled(fam, name, work)
        constraints = r1cs_constraint_count(r1cs)

        steps_dir = os.path.join(work, "steps")
        if not args.skip_witness_gen:
            if "witness_script" in fam:
                # Custom witness generator (VRF, PoseidonMerkle, SHA-256, PoseidonSponge)
                cmd = [sys.executable, os.path.join(SCRIPT_DIR, fam["witness_script"]),
                       "--wasm", wasm, "--steps", str(n_steps), "--dir", steps_dir]
                if "witness_script_args" in fam:
                    cmd.extend(fam["witness_script_args"])
                run(cmd)
            else:
                # Standard chained-witness generator (Ed25519)
                initial = os.path.join(work, "initial.json")
                json.dump(fam["inputs"], open(initial, "w"))
                run([sys.executable, os.path.join(SCRIPT_DIR, "gen_step_witnesses.py"),
                     "--wasm", wasm, "--initial", initial, "--outputs", fam["outputs"],
                     "--steps", str(n_steps), "--dir", steps_dir])
        prune_witness_intermediates(steps_dir)

        row = {"family": name, "constraints": constraints, "steps": n_steps, "curve": fam["curve"],
               "commitment": args.commitment}
        commit_args = ["--commitment", args.commitment]
        if args.commitment == "sis":
            commit_args += ["--sis-param", str(args.sis_param)]
        for mode, flag in (("base", []), ("parallel", ["--opt-parallel"])):
            log = os.path.join(out_dir, f"{name}-{args.commitment}-{mode}.log")
            run([bench_bin, "--curve", fam["curve"], *flag, *commit_args, "--circuit", r1cs, "--steps", steps_dir], log)
            row[mode] = parse_bench_log(log)
        rows.append(row)

    summary = render_summary(stamp, rows)
    with open(os.path.join(out_dir, "summary.md"), "w") as f:
        f.write(summary)
    print("\n" + summary)


def render_summary(stamp, rows):
    lines = [
        f"# NovaSlim benchmark — {stamp}",
        "",
        "Measured with `benchmark_nova --release` (prover crate); slim IVC flow:",
        "NIFS fold → sumcheck compress → verify. Witnesses pre-generated.",
        "",
        "| Step circuit | Curve | Commitment | Constraints | Steps | Fold total | Fold/step | Compress | Verify (full) | Verify (slim) | Level-1 compress | Verify (level-1) | Slim proof | Level-1 proof | Norm A (range) proof | Norm B (jl) proof | Bundle |",
        "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for r in rows:
        b, p = r["base"], r["parallel"]
        constraints_str = f"{r['constraints']:,}" if r['constraints'] else "?"
        commit = r.get("commitment", "pedersen")
        l1c = b.get("level1_compress_s", "—")
        l1v = b.get("verify_level1_s", "—")
        l1s = b.get("level1_proof_bytes", "—")
        nr = b.get("norm_range_proof_bytes", "—")
        nj = b.get("norm_jl_proof_bytes", "—")
        if l1c != "—":
            l1c = f"{b['level1_compress_s']:.2f} s / {p['level1_compress_s']:.2f} s"
            l1v = f"{b['verify_level1_s']*1000:.1f} ms"
            l1s = f"{b['level1_proof_bytes']/1024:.1f} KiB"
        if nr != "—":
            nr = f"{b['norm_range_proof_bytes']/1024:.1f} KiB"
            nj = f"{b['norm_jl_proof_bytes']/1024:.1f} KiB"
        lines.append(
            f"| `{r['family']}` | {r['curve']} | {commit} | {constraints_str} | {r['steps']} "
            f"| {b['fold_s']:.1f} s / {p['fold_s']:.1f} s "
            f"| {b['fold_ms_per_step']:.0f} ms / {p['fold_ms_per_step']:.0f} ms "
            f"| {b['compress_s']:.2f} s / {p['compress_s']:.2f} s "
            f"| {b['verify_full_s']:.2f} s / {p['verify_full_s']:.2f} s "
            f"| {b['verify_slim_s']*1000:.1f} ms "
            f"| {l1c} | {l1v} "
            f"| {b['slim_proof_bytes']/1024:.1f} KiB "
            f"| {l1s} | {nr} | {nj} "
            f"| {b['bundle_bytes']/1024:.1f} KiB |"
        )
    lines += ["", "*Each cell shows baseline / --opt-parallel where two values are shown.*", ""]
    return "\n".join(lines)


def run(cmd, log_path=None):
    print("+ " + " ".join(map(str, cmd)), flush=True)
    if log_path:
        with open(log_path, "w") as f:
            r = subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT, text=True)
    else:
        r = subprocess.run(cmd)
    if r.returncode != 0:
        sys.exit(f"command failed ({r.returncode}); see {log_path or 'output above'}")


if __name__ == "__main__":
    main()
