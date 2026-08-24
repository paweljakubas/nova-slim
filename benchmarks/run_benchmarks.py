#!/usr/bin/env python3
"""NovaSlim **traditional** benchmark runner — real circom circuits + snarkjs.

This is the "traditional" benchmark: for each circuit family it compiles the
step circuit with circom, generates chained step witnesses with snarkjs, then
measures fold → compress → verify via `benchmark_nova --release`.

Curves supported: BLS12-381, BN254.
Pallas and Vesta are **NOT** available here because snarkjs does not yet
support pasta-curve witness generation. For Pallas / Vesta, use the synthetic
benchmark instead:

    cargo run --release --manifest-path prover/Cargo.toml --bin benchmark_synthetic -- --curve pallas --state-width 24 --steps 255

For each circuit family this script:

  1. compiles the step circuit with circom if the .r1cs/.wasm are missing,
  2. generates (or resumes) chained step witnesses with snarkjs,
  3. builds `benchmark_nova --release`,
  4. runs baseline and --opt-parallel passes,
  5. writes raw logs plus a markdown summary under benchmarks/results/.

Usage:
    python3 benchmarks/run_benchmarks.py                 # all families, 255 steps
    python3 benchmarks/run_benchmarks.py --steps 32      # shorter chains
    python3 benchmarks/run_benchmarks.py --curve bn254   # specific curve
    python3 benchmarks/run_benchmarks.py --family ed25519_verify_nova_bls12_381

Re-run this whenever the folding/compression code changes and paste the
summary into the Benchmarks section of prover/README.md.
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
    "pallas": "pallas",
    "vesta": "vesta",
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
}


def ensure_compiled(family, name, steps_dir):
    """Compile the circom circuit for the target curve if missing."""
    circuit_name = family["circuit_name"]
    curve = family["curve"]
    r1cs = os.path.join(steps_dir, f"{circuit_name}.r1cs")
    wasm = os.path.join(steps_dir, f"{circuit_name}_js", f"{circuit_name}.wasm")
    if os.path.exists(r1cs) and os.path.exists(wasm):
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
        elif line.startswith("verify (full):"):
            out["verify_full_s"] = float(line.split()[2])
        elif line.startswith("verify (slim):"):
            out["verify_slim_s"] = float(line.split()[2])
        elif line.startswith("nifs bundle:"):
            out["bundle_bytes"] = int(line.split()[2])
        elif line.startswith("slim proof:"):
            out["slim_proof_bytes"] = int(line.split()[2])
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
    ap.add_argument("--skip-witness-gen", action="store_true")
    args = ap.parse_args()

    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    out_dir = os.path.join(RESULTS_DIR, stamp)
    os.makedirs(out_dir, exist_ok=True)

    manifest = os.path.join(REPO_DIR, "prover", "Cargo.toml")
    run(["cargo", "build", "--release", "--manifest-path", manifest,
         "--features", "bls12-381 bn254 pallas vesta",
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
                # Custom witness generator (VRF, PoseidonMerkle)
                run([sys.executable, os.path.join(SCRIPT_DIR, fam["witness_script"]),
                     "--wasm", wasm, "--steps", str(n_steps), "--dir", steps_dir])
            else:
                # Standard chained-witness generator (Ed25519)
                initial = os.path.join(work, "initial.json")
                json.dump(fam["inputs"], open(initial, "w"))
                run([sys.executable, os.path.join(SCRIPT_DIR, "gen_step_witnesses.py"),
                     "--wasm", wasm, "--initial", initial, "--outputs", fam["outputs"],
                     "--steps", str(n_steps), "--dir", steps_dir])
        prune_witness_intermediates(steps_dir)

        row = {"family": name, "constraints": constraints, "steps": n_steps, "curve": fam["curve"]}
        for mode, flag in (("base", []), ("parallel", ["--opt-parallel"])):
            log = os.path.join(out_dir, f"{name}-{mode}.log")
            run([bench_bin, "--curve", fam["curve"], *flag, "--circuit", r1cs, "--steps", steps_dir], log)
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
        "| Step circuit | Curve | Constraints | Steps | Fold total | Fold/step | Compress | Verify (full) | Verify (slim) | Slim proof | Bundle |",
        "|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for r in rows:
        b, p = r["base"], r["parallel"]
        constraints_str = f"{r['constraints']:,}" if r['constraints'] else "?"
        lines.append(
            f"| `{r['family']}` | {r['curve']} | {constraints_str} | {r['steps']} "
            f"| {b['fold_s']:.1f} s / {p['fold_s']:.1f} s "
            f"| {b['fold_ms_per_step']:.0f} ms / {p['fold_ms_per_step']:.0f} ms "
            f"| {b['compress_s']:.2f} s / {p['compress_s']:.2f} s "
            f"| {b['verify_full_s']:.2f} s / {p['verify_full_s']:.2f} s "
            f"| {b['verify_slim_s']*1000:.1f} ms "
            f"| {b['slim_proof_bytes']/1024:.1f} KiB "
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
