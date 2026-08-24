//! `fold` subcommand — fold step witnesses into a single Relaxed-R1CS
//! instance (NIFS) and emit the O(1) bundle.

use clap::Parser;
use prover::{run_fold_nifs_opt, OptFlags, NifsBundle, commitment::{PedersenCommitment, SisCommitment}, curve::{Bls12_381, Bn254, Pallas, Vesta, NovaCurve, ScalarField}};
use std::error::Error;
use std::fs;
use std::path::PathBuf;
use crate::Curve;

/// Arguments for the `fold` subcommand
#[derive(Debug, Parser)]
pub struct Args {
    /// Path to the step circuit `.r1cs` file
    #[arg(long, value_name = "FILE")]
    pub circuit: PathBuf,

    /// Directory containing the step witness files
    /// (`step_0000.wtns`, `step_0001.wtns`, …).  Files are
    /// processed in sorted order.
    #[arg(long, value_name = "DIR")]
    pub steps: PathBuf,

    /// Output path for the NIFS bundle (compact CBOR;
    /// `.ivc.cbor` extension recommended).
    #[arg(long, value_name = "FILE")]
    pub out: PathBuf,

    /// Elliptic curve to use.
    #[arg(long, value_enum, default_value = "bls12-381")]
    pub curve: Curve,

    /// Commitment scheme to use.
    #[arg(long, value_enum, default_value = "pedersen")]
    pub commitment: crate::CommitmentSchemeArg,

    /// Optimizations (comma-separated):
    ///   parallel  — use rayon for independent row/column operations
    ///   lazy      — defer Pedersen MSM to final step
    ///   all       — enable all optimizations
    #[arg(long, value_name = "OPTS", default_value = "none")]
    pub opt: String,
}

fn parse_opt_flags(s: &str) -> Result<OptFlags, Box<dyn Error>> {
    let mut flags = OptFlags::NONE;
    for part in s.split(',') {
        match part.trim() {
            "none" | "" => {}
            "parallel" | "p" => flags.parallel = true,
            "lazy" | "l" => flags.lazy_commit = true,
            "all" | "a" => flags = OptFlags::ALL,
            other => return Err(format!("unknown optimization: '{other}' — valid: parallel, lazy, all, none").into()),
        }
    }
    Ok(flags)
}

fn write_bundle<C: NovaCurve>(out: &NifsBundle, path: &std::path::Path, opts: OptFlags) -> Result<(), Box<dyn Error>> {
    let cbor = out
        .to_cbor::<ScalarField<C>>()
        .map_err(|e| format!("failed to serialize NIFS bundle: {e}"))?;
    fs::write(path, &cbor)
        .map_err(|e| format!("failed to write NIFS bundle to {}: {e}", path.display()))?;
    eprintln!(
        "NIFS bundle written to {} ({} steps → one instance, u = {}, opt: {:?})",
        path.display(),
        out.n_steps,
        out.final_instance.u,
        opts,
    );
    Ok(())
}

/// Run the `fold` subcommand.
pub fn run(args: Args) -> Result<(), Box<dyn Error>> {
    let opts = parse_opt_flags(&args.opt)?;
    match (args.curve, args.commitment) {
        (Curve::Bls12_381, crate::CommitmentSchemeArg::Pedersen) => {
            let out = run_fold_nifs_opt::<Bls12_381, PedersenCommitment<Bls12_381>>(&args.circuit, &args.steps, opts)?;
            write_bundle::<Bls12_381>(&out.bundle, &args.out, opts)?;
        }
        (Curve::Bls12_381, crate::CommitmentSchemeArg::Sis) => {
            let out = run_fold_nifs_opt::<Bls12_381, SisCommitment<Bls12_381>>(&args.circuit, &args.steps, opts)?;
            write_bundle::<Bls12_381>(&out.bundle, &args.out, opts)?;
        }
        (Curve::Bn254, crate::CommitmentSchemeArg::Pedersen) => {
            let out = run_fold_nifs_opt::<Bn254, PedersenCommitment<Bn254>>(&args.circuit, &args.steps, opts)?;
            write_bundle::<Bn254>(&out.bundle, &args.out, opts)?;
        }
        (Curve::Bn254, crate::CommitmentSchemeArg::Sis) => {
            let out = run_fold_nifs_opt::<Bn254, SisCommitment<Bn254>>(&args.circuit, &args.steps, opts)?;
            write_bundle::<Bn254>(&out.bundle, &args.out, opts)?;
        }
        (Curve::Pallas, crate::CommitmentSchemeArg::Pedersen) => {
            let out = run_fold_nifs_opt::<Pallas, PedersenCommitment<Pallas>>(&args.circuit, &args.steps, opts)?;
            write_bundle::<Pallas>(&out.bundle, &args.out, opts)?;
        }
        (Curve::Pallas, crate::CommitmentSchemeArg::Sis) => {
            let out = run_fold_nifs_opt::<Pallas, SisCommitment<Pallas>>(&args.circuit, &args.steps, opts)?;
            write_bundle::<Pallas>(&out.bundle, &args.out, opts)?;
        }
        (Curve::Vesta, crate::CommitmentSchemeArg::Pedersen) => {
            let out = run_fold_nifs_opt::<Vesta, PedersenCommitment<Vesta>>(&args.circuit, &args.steps, opts)?;
            write_bundle::<Vesta>(&out.bundle, &args.out, opts)?;
        }
        (Curve::Vesta, crate::CommitmentSchemeArg::Sis) => {
            let out = run_fold_nifs_opt::<Vesta, SisCommitment<Vesta>>(&args.circuit, &args.steps, opts)?;
            write_bundle::<Vesta>(&out.bundle, &args.out, opts)?;
        }
    }
    Ok(())
}
