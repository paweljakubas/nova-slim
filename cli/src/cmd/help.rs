//! `help` subcommand — detailed help for commitments, curves, and usage examples.

use clap::Parser;
use std::error::Error;

/// Arguments for the `help` subcommand
#[derive(Debug, Parser)]
pub struct Args {
    /// Topic to get detailed help for
    #[arg(value_name = "TOPIC")]
    pub topic: Option<String>,
}

/// Run the `help` subcommand.
pub fn run(args: Args) -> Result<(), Box<dyn Error>> {
    match args.topic.as_deref() {
        Some("commitment") | Some("commitments") => print_commitment_help(),
        Some("curve") | Some("curves") => print_curve_help(),
        Some(other) => {
            eprintln!("Unknown help topic: '{other}'");
            eprintln!("Available topics: commitment, curve");
            eprintln!("Run `nova-slim help` for general usage.");
            std::process::exit(1);
        }
        None => print_general_help(),
    }
    Ok(())
}

fn print_general_help() {
    println!(r#"NovaSlim — Folding + Slim On-Chain Proofs CLI

USAGE:
    nova-slim <COMMAND> [OPTIONS]

COMMANDS:
    params      Inspect a step circuit and emit a JSON descriptor
    fold        Fold step witnesses into a single Relaxed-R1CS instance
    compress    Compress a NIFS bundle into a constant-size proof
    verify      Verify a folded NIFS bundle against its compression proof
    help        Show detailed help for commitments, curves, or general usage

GLOBAL OPTIONS:
    --curve <CURVE>          Elliptic curve (default: bls12-381)
    --commitment <SCHEME>    Commitment scheme (default: pedersen)
    --sis-param <M>          SIS output dimension, only for --commitment sis (default: 4)

Get detailed help:
    nova-slim help commitment    # Commitment schemes explained
    nova-slim help curve         # Elliptic curves explained

EXAMPLE — Full slim flow (default curve + Pedersen):

    # 1. Inspect the step circuit
    nova-slim params --circuit step.r1cs

    # 2. Fold 255 steps into one bundle (~2 min for Ed25519)
    nova-slim fold --circuit step.r1cs --steps ./witnesses/ --out bundle.ivc.cbor

    # 3. Compress to a slim on-chain proof (~1.5 KiB)
    nova-slim compress --slim --circuit step.r1cs --steps ./witnesses/ --out slim.proof.cbor

    # 4. Verify the slim proof (~0.2 ms)
    nova-slim verify --ivc bundle.ivc.cbor --slim-proof slim.proof.cbor

For more examples, see:
    nova-slim help commitment
    nova-slim help curve
"#);
}

fn print_commitment_help() {
    println!(r#"COMMITMENT SCHEMES

NovaSlim supports three commitment schemes, selectable at runtime via
--commitment {{pedersen,sis,hash}}. All schemes are transparent (no trusted setup).

1. Pedersen (default) — Classical elliptic-curve commitments
   * Speed: Baseline (~350 ms/step for Ed25519 on BN254)
   * Security: DLOG hardness (classical)
   * Bundle size: ~2 KiB
   * Best for: Production deployments on standard curves

2. SIS (Ajtai-style lattice commitments) — Quantum-resistant option
   * Speed: Up to 14x faster folding than Pedersen on BLS12-381
   * Security: SIS hardness (post-quantum with large m)
   * Bundle size: ~2–10 KiB (grows with m)
   * Configurable: --sis-param <m> (default 4, use 128 for 128-bit PQ security)
   * Best for: Future-proofing against quantum computers

3. Hash (on-the-fly Blake2b derivation) — Minimal storage
   * Speed: ~1.7x slower than Pedersen (recomputes coefficients per commitment)
   * Security: Blake2b collision resistance (post-quantum)
   * Bundle size: ~2 KiB
   * Storage: Zero param storage (seed only)
   * Best for: Auditable deployments, minimal trusted code

EXAMPLES

# Pedersen (default) — no extra flags needed
nova-slim fold --circuit step.r1cs --steps ./w/ --out bundle.ivc.cbor

# SIS with default m=4 (fast, low security — for testing)
nova-slim fold --commitment sis --circuit step.r1cs --steps ./w/ --out bundle.ivc.cbor

# SIS with m=128 (128-bit post-quantum security)
nova-slim fold --commitment sis --sis-param 128 \
    --circuit step.r1cs --steps ./w/ --out bundle.ivc.cbor

# Hash commitment
nova-slim fold --commitment hash --circuit step.r1cs --steps ./w/ --out bundle.ivc.cbor

# Full slim flow with SIS m=128
nova-slim fold --commitment sis --sis-param 128 --circuit step.r1cs --steps ./w/ --out b.ivc.cbor
nova-slim compress --slim --commitment sis --sis-param 128 --circuit step.r1cs --steps ./w/ --out slim.cbor
nova-slim verify --commitment sis --sis-param 128 --ivc b.ivc.cbor --slim-proof slim.cbor
"#);
}

fn print_curve_help() {
    println!(r#"ELLIPTIC CURVES

NovaSlim supports six elliptic curves, selectable via --curve <NAME>.
The curve determines the scalar field used for R1CS constraints.

1. bls12-381 (default) — Cardano-native curve
   * Field: BLS12-381 scalar field (≈ 2^381)
   * Use for: Cardano, Algorand, Chia
   * Speed: ~540 ms/step (Ed25519, Pedersen)

2. bn254 — Ethereum zk-rollups
   * Field: BN254 scalar field (≈ 2^254)
   * Use for: Ethereum, Polygon, zkSync
   * Speed: ~350 ms/step (Ed25519, Pedersen) — fastest for real circuits

3. pallas — Zcash Orchard
   * Field: Pallas scalar field (≈ 2^255)
   * Use for: Zcash, Filecoin
   * Speed: ~2.3 ms/step (synthetic) — fastest overall

4. vesta — Pallas complement (Pasta cycle)
   * Field: Vesta scalar field (≈ 2^255)
   * Use for: Zcash (cycle with Pallas)
   * Speed: ~2.8 ms/step (synthetic)

5. grumpkin — BN254 complement
   * Field: Grumpkin scalar field (≈ 2^254)
   * Use for: BN254/Grumpkin cycle (e.g. Aztec)
   * Speed: ~4.4 ms/step (synthetic)

6. bandersnatch — BLS12-381 companion
   * Field: Bandersnatch scalar field (≈ 2^255)
   * Use for: Fast scalar mul over BLS12-381 field
   * Speed: ~2.7 ms/step (synthetic)
   * Note: circom does not support this prime; synthetic-only

EXAMPLES

# Default curve (BLS12-381)
nova-slim fold --circuit step.r1cs --steps ./w/ --out bundle.ivc.cbor

# BN254 — faster for Ethereum-compatible deployments
nova-slim fold --curve bn254 --circuit step.r1cs --steps ./w/ --out bundle.ivc.cbor

# Full slim flow on BN254
nova-slim params --curve bn254 --circuit step.r1cs
nova-slim fold --curve bn254 --circuit step.r1cs --steps ./w/ --out b.ivc.cbor
nova-slim compress --slim --curve bn254 --circuit step.r1cs --steps ./w/ --out slim.cbor
nova-slim verify --curve bn254 --ivc b.ivc.cbor --slim-proof slim.cbor

# Pallas (synthetic benchmark — no snarkjs support yet)
cargo run --release --manifest-path prover/Cargo.toml --bin benchmark_synthetic \
    -- --curve pallas --state-width 24 --steps 255

NOTES
* Real-circuit witness generation (via snarkjs) is only available for BLS12-381 and BN254.
* For Pallas, Vesta, Grumpkin, and Bandersnatch, use synthetic benchmarks or provide
  pre-generated witness files.
"#);
}
