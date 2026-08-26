#!/usr/bin/env python3
"""Generate SHA-256 step witnesses for Nova IVC.

Each step computes state_out = SHA256(state_in) (or SHA256(state_in || padding)).
We generate a random initial state and chain the witnesses step by step.

Usage:
    python3 gen_sha256_witnesses.py --wasm <circuit.wasm> \
        --state-size <N> --steps <N> --dir <output-dir>

--state-size: number of bytes in the public state (8 for small, 32 for medium/big).
"""
import argparse
import json
import os
import subprocess
import sys
import secrets


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--wasm", required=True)
    ap.add_argument("--state-size", type=int, required=True,
                    help="Number of bytes in state_in / state_out")
    ap.add_argument("--steps", type=int, required=True)
    ap.add_argument("--dir", required=True)
    args = ap.parse_args()

    os.makedirs(args.dir, exist_ok=True)

    # Random initial state (bytes)
    state = [secrets.randbelow(256) for _ in range(args.state_size)]

    for i in range(args.steps):
        inp = {f"state_in[{j}]": str(state[j]) for j in range(args.state_size)}

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

        # Update state from outputs: public outputs start at index 1
        state = [int(wit[1 + j]) for j in range(args.state_size)]

        if (i + 1) % 10 == 0 or i + 1 == args.steps:
            print(f"  step {i + 1}/{args.steps}")

    print(f"  wrote {args.steps} step witnesses to {args.dir}")


if __name__ == "__main__":
    main()
