//! `params` subcommand — inspect a step circuit and emit a JSON descriptor.

use crate::Curve;
use clap::Parser;
use prover::{
    curve::{Bandersnatch, Bls12_381, Bn254, Grumpkin, Pallas, Vesta},
    run_params,
};
use std::error::Error;
use std::fs;
use std::path::PathBuf;

/// Arguments for the `params` subcommand
#[derive(Debug, Parser)]
pub struct Args {
    /// Path to the step circuit `.r1cs` file
    #[arg(long, value_name = "FILE")]
    pub circuit: PathBuf,

    /// Elliptic curve to use.
    #[arg(long, value_enum, default_value = "bls12-381")]
    pub curve: Curve,

    /// Optional JSON output path.
    /// If omitted, the descriptor is printed to stdout.
    #[arg(long, value_name = "FILE")]
    pub out: Option<PathBuf>,
}

/// Run the `params` subcommand.
pub fn run(args: Args) -> Result<(), Box<dyn Error>> {
    let desc = match args.curve {
        Curve::Bls12_381 => run_params::<Bls12_381>(&args.circuit)?,
        Curve::Bn254 => run_params::<Bn254>(&args.circuit)?,
        Curve::Pallas => run_params::<Pallas>(&args.circuit)?,
        Curve::Vesta => run_params::<Vesta>(&args.circuit)?,
        Curve::Grumpkin => run_params::<Grumpkin>(&args.circuit)?,
        Curve::Bandersnatch => run_params::<Bandersnatch>(&args.circuit)?,
    };
    let json = serde_json::to_string_pretty(&desc)?;

    if let Some(out) = &args.out {
        fs::write(out, &json)
            .map_err(|e| format!("failed to write descriptor to {}: {e}", out.display()))?;
        eprintln!(
            "Step circuit {}: {} wires, {} constraints ({} out + {} in public, {} private) — OK",
            args.circuit.display(),
            desc.n_wires,
            desc.n_constraints,
            desc.n_pub_out,
            desc.n_pub_in,
            desc.n_prv_in
        );
        eprintln!("Descriptor written to {}", out.display());
    } else {
        println!("{json}");
    }
    Ok(())
}
