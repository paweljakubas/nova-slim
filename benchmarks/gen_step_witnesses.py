#!/usr/bin/env python3
"""Resumable chained step-witness generator for Nova step circuits.

Drives a circuit's wasm one step at a time (via snarkjs), feeding each step's
public outputs back as the next step's public inputs so the IVC state chain
invariant holds by construction.  Inspired by circom/gen_nova_steps.py in the
cardano-foundation/bls repo, but resumable: an interrupted run continues from
the last complete witness instead of starting over.

Usage:
    python3 gen_step_witnesses.py --wasm <circuit.wasm> \
        --initial <input.json> --outputs <in_sig=out_sig,...> \
        --steps N --dir <output-dir>
"""
import argparse
import glob
import json
import os
import subprocess
import sys


def run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print(f"FAILED: {' '.join(map(str, cmd))}\n{r.stderr[-500:]}", file=sys.stderr)
        sys.exit(1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--wasm", required=True)
    ap.add_argument("--initial", required=True,
                    help="JSON with the first step's inputs (public state + private)")
    ap.add_argument("--outputs", required=True,
                    help="comma-separated 'input_signal=output_signal' pairs")
    ap.add_argument("--steps", type=int, required=True)
    ap.add_argument("--dir", required=True)
    ap.add_argument("--snarkjs", default="snarkjs")
    args = ap.parse_args()

    os.makedirs(args.dir, exist_ok=True)
    pairs = []
    for tok in args.outputs.split(","):
        if not tok.strip():
            continue
        in_sig, _, out_sig = tok.strip().partition("=")
        if not out_sig:
            sys.exit(f"expected 'input=output', got '{tok.strip()}'")
        pairs.append((in_sig.strip(), out_sig.strip()))
    if not pairs:
        sys.exit("no output mappings given")
    n_pub = len(pairs)

    # Resume: walk back to the newest witness whose JSON parses and whose
    # .wtns exists; its public outputs seed the next step's inputs.
    start, prev_vals = 0, None
    for wit_path in sorted(glob.glob(os.path.join(args.dir, "wit_*.json")), reverse=True):
        idx = int(os.path.basename(wit_path)[4:8])
        if not os.path.exists(os.path.join(args.dir, f"step_{idx:04}.wtns")):
            continue
        try:
            wit = json.load(open(wit_path))
            prev_vals = [str(v) for v in wit[1 : 1 + n_pub]]
            start = idx + 1
            break
        except Exception:
            print(f"skipping corrupt {wit_path}")

    base_inputs = json.load(open(args.initial))
    for sig, _ in pairs:
        if sig not in base_inputs:
            sys.exit(f"input signal '{sig}' is not in the initial input JSON")

    print(f"generating {args.steps} steps into {args.dir}"
          + (f" (resuming at {start})" if start else ""))
    for i in range(start, args.steps):
        inputs = dict(base_inputs)
        if prev_vals is not None:
            inputs.update(dict(zip((sig for sig, _ in pairs), prev_vals)))
        ip = os.path.join(args.dir, f"input_{i:04}.json")
        wp = os.path.join(args.dir, f"step_{i:04}.wtns")
        jp = os.path.join(args.dir, f"wit_{i:04}.json")
        json.dump(inputs, open(ip, "w"))
        run([args.snarkjs, "wtns", "calculate", args.wasm, ip, wp])
        run([args.snarkjs, "wtns", "export", "json", wp, jp])
        wit = json.load(open(jp))
        prev_vals = [str(v) for v in wit[1 : 1 + n_pub]]
        if (i + 1) % 25 == 0:
            print(f"  {i+1}/{args.steps}", flush=True)
    print("DONE")


if __name__ == "__main__":
    main()
