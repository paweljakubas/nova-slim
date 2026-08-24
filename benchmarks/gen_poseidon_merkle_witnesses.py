#!/usr/bin/env python3
"""Generate PoseidonMerkle step witnesses for Nova IVC.

Each step is one Merkle tree level: state_out = Poseidon(switch(state_in, sibling, direction)).
We generate a random chain of siblings and directions, then use snarkjs to compute
valid witnesses step by step.

Usage:
    python3 gen_poseidon_merkle_witnesses.py --wasm <poseidon_merkle_nova.wasm> \
        --steps <depth> --dir <output-dir>
"""
import argparse
import json
import os
import subprocess
import sys


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--wasm", required=True)
    ap.add_argument("--steps", type=int, required=True)
    ap.add_argument("--dir", required=True)
    args = ap.parse_args()

    os.makedirs(args.dir, exist_ok=True)

    # BLS12-381 scalar field prime (for random values)
    P = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001

    # Random initial state
    import secrets
    state = str(secrets.randbelow(P))

    for i in range(args.steps):
        sibling = str(secrets.randbelow(P))
        direction = str(secrets.randbelow(2))

        inp = {"state_in": state, "sibling": sibling, "direction": direction}
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

        # Update state: state_out is the first public output signal.
        # In circom witness ordering: idx0=1, idx1=state_out (public output),
        # idx2=state_in (public input), idx3=sibling, idx4=direction, ...
        state = str(int(wit[1]))

        if (i + 1) % 10 == 0 or i + 1 == args.steps:
            print(f"  step {i + 1}/{args.steps}")

    print(f"  wrote {args.steps} step witnesses to {args.dir}")


if __name__ == "__main__":
    main()
