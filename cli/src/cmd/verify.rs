//! `verify` subcommand — verify a NIFS bundle against a compression proof.

use clap::Parser;
use prover::{run_verify_slim, run_verify_sumcheck, curve::{Bls12_381, Bn254}};
use std::error::Error;
use std::path::PathBuf;
use crate::Curve;

/// Arguments for the `verify` subcommand
#[derive(Debug, Parser)]
pub struct Args {
    /// Path to the NIFS bundle produced by `nova-slim fold`
    #[arg(long, value_name = "FILE")]
    pub ivc: PathBuf,

    /// Path to the full sumcheck compression proof from `nova-slim compress`
    /// (default).  Verifies the sumcheck protocol plus the HashPC opening
    /// proofs and Pedersen commitments (audit-grade).
    #[arg(long, value_name = "FILE", conflicts_with_all = ["slim_proof"])]
    pub sumcheck_proof: Option<PathBuf>,

    /// Path to the slim on-chain proof from `nova-slim compress --slim`.
    /// Verifies the sumcheck protocol without the HashPC opening proofs
    /// (lightweight, Plutus-ready).
    #[arg(long, value_name = "FILE", conflicts_with_all = ["sumcheck_proof"])]
    pub slim_proof: Option<PathBuf>,

    /// Elliptic curve to use.
    #[arg(long, value_enum, default_value = "bls12-381")]
    pub curve: Curve,
}

/// Run the `verify` subcommand.
pub fn run(args: Args) -> Result<(), Box<dyn Error>> {
    if let Some(ref sp) = args.slim_proof {
        let out = match args.curve {
            Curve::Bls12_381 => run_verify_slim::<Bls12_381>(&args.ivc, sp)?,
            Curve::Bn254 => run_verify_slim::<Bn254>(&args.ivc, sp)?,
        };
        eprintln!(
            "Verified {} steps: slim sumcheck proof OK, state chain OK (no opening proofs — off-chain audit trail)",
            out.steps
        );
        eprintln!("Final transcript: {}", out.transcript_final);
        return Ok(());
    }

    if let Some(ref sc_proof) = args.sumcheck_proof {
        let out = match args.curve {
            Curve::Bls12_381 => run_verify_sumcheck::<Bls12_381>(&args.ivc, sc_proof)?,
            Curve::Bn254 => run_verify_sumcheck::<Bn254>(&args.ivc, sc_proof)?,
        };
        eprintln!(
            "Verified {} steps: sumcheck compression proof OK, commitments OK, state chain OK",
            out.steps
        );
        eprintln!("Final transcript: {}", out.transcript_final);
        return Ok(());
    }

    Err("nothing to verify — pass --slim-proof or --sumcheck-proof".into())
}
