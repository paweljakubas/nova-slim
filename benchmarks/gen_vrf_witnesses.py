#!/usr/bin/env python3
"""Generate VRF step witnesses for Nova IVC.

Each step is one Montgomery-ladder bit for [scalar]*G on JubJub.
We start with G in Montgomery form and use random sel bits to generate
a valid witness chain.  For benchmarking purposes the scalar need not be
cryptographically meaningful — any sequence of valid ladder steps works.

Usage:
    python3 gen_vrf_witnesses.py --wasm <vrf_verify_nova.wasm> --steps <N> --dir <output-dir>
"""
import argparse
import json
import os
import subprocess
import sys
import secrets

# JubJub base point in Montgomery form (from Zcash spec)
G_MONT_U = "11077623725758003269991025605663803638577"
G_MONT_V = "2027383065985370677102215522065430936403"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--wasm", required=True)
    ap.add_argument("--steps", type=int, required=True)
    ap.add_argument("--dir", required=True)
    args = ap.parse_args()

    os.makedirs(args.dir, exist_ok=True)

    state = {
        "dbl_in_0": G_MONT_U,
        "dbl_in_1": G_MONT_V,
        "add_in_0": G_MONT_U,
        "add_in_1": G_MONT_V,
    }

    for i in range(args.steps):
        inp = dict(state)
        inp["sel"] = str(secrets.randbelow(2))

        in_file = os.path.join(args.dir, f"input_{i:04}.json")
        wtns = os.path.join(args.dir, f"step_{i:04}.wtns")
        json.dump(inp, open(in_file, "w"))

        r = subprocess.run(
            ["snarkjs", "wtns", "calculate", args.wasm, in_file, wtns],
            capture_output=True, text=True
        )
        if r.returncode != 0:
            print(f"  FAILED at step {i}: {r.stderr[-300:]}", file=sys.stderr)
            sys.exit(1)

        # Export witness to JSON to read outputs
        wit_json = os.path.join(args.dir, f"_wit_{i:04}.json")
        subprocess.run(
            ["snarkjs", "wtns", "export", "json", wtns, wit_json],
            capture_output=True, check=True
        )
        with open(wit_json) as f:
            wit = json.load(f)
        os.remove(wit_json)

        # Update state from outputs: signal order is dbl_out_0, dbl_out_1, add_out_0, add_out_1
        state["dbl_in_0"] = str(int(wit[1]))
        state["dbl_in_1"] = str(int(wit[2]))
        state["add_in_0"] = str(int(wit[3]))
        state["add_in_1"] = str(int(wit[4]))

        if (i + 1) % 50 == 0 or i + 1 == args.steps:
            print(f"  step {i + 1}/{args.steps}")

    print(f"  wrote {args.steps} step witnesses to {args.dir}")


if __name__ == "__main__":
    main()
