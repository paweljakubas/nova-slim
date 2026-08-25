//! `compress` subcommand — compress a NIFS bundle into one constant-size
//! proof.
//!
//! Default: full sumcheck proof (sumcheck argument + HashPC opening proofs,
//! transparent, no trusted setup) — the off-chain audit variant.
//! With `--slim`, strips the HashPC opening proofs to produce the
//! on-chain-friendly slim proof (~2.4 KiB for 7,724-constraint steps).
//!
//! Artifacts use a compact CBOR encoding (field elements as 32-byte
//! little-endian values).

use clap::Parser;
use prover::{run_compress_sumcheck_opt, NifsSumcheckProof, OptFlags, DEFAULT_SIS_PARAM, commitment::{PedersenCommitment, SisCommitment}, curve::{Bls12_381, Bn254, Pallas, Vesta, NovaCurve, ScalarField}};
use std::error::Error;
use std::fs;
use std::path::PathBuf;
use crate::Curve;

/// Arguments for the `compress` subcommand
#[derive(Debug, Parser)]
pub struct Args {
    /// Path to the step circuit `.r1cs` file
    #[arg(long, value_name = "FILE")]
    pub circuit: PathBuf,

    /// Directory containing the step witness files
    /// (`step_0000.wtns`, `step_0001.wtns`, …).  The fold is re-run
    /// deterministically to recover the private final witness.
    #[arg(long, value_name = "DIR")]
    pub steps: PathBuf,

    /// Output path for the compression proof (compact CBOR;
    /// `.proof.cbor` extension recommended)
    #[arg(long, value_name = "FILE")]
    pub out: PathBuf,

    /// Strip HashPC opening proofs to produce a slim on-chain proof.
    /// Cuts proof size from ~270 KiB to ~2.4 KiB for 7,724-constraint
    /// steps.  The opening proofs are verified off-chain as an audit
    /// trail.
    #[arg(long)]
    pub slim: bool,

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

    /// SIS output dimension (m).  Only used with --commitment sis.
    /// A value of 128 provides 128-bit post-quantum security.
    #[arg(long, value_name = "M", default_value_t = DEFAULT_SIS_PARAM)]
    pub sis_param: usize,
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

fn strip_and_write<C: NovaCurve>(full_bytes: &[u8], out: &std::path::Path) -> Result<(), Box<dyn Error>> {
    let full_proof = NifsSumcheckProof::from_cbor::<ScalarField<C>>(full_bytes)?;
    let slim_proof = full_proof.to_slim();
    let slim_cbor = slim_proof.to_cbor::<ScalarField<C>>()?;
    fs::write(out, &slim_cbor)?;
    eprintln!(
        "Slim proof written to {} ({} bytes, down from {} bytes — {:.0}% reduction)",
        out.display(),
        slim_cbor.len(),
        full_bytes.len(),
        100.0 * (1.0 - slim_cbor.len() as f64 / full_bytes.len() as f64),
    );
    Ok(())
}

/// Run the `compress` subcommand.
pub fn run(args: Args) -> Result<(), Box<dyn Error>> {
    let opts = parse_opt_flags(&args.opt)?;
    if args.slim {
        // Sumcheck compress, then strip opening proofs for on-chain proof.
        let tmp = args.out.with_extension("full.cbor");
        match (args.curve, args.commitment) {
            (Curve::Bls12_381, crate::CommitmentSchemeArg::Pedersen) => run_compress_sumcheck_opt::<Bls12_381, PedersenCommitment<Bls12_381>>(&args.circuit, &args.steps, &tmp, opts, args.sis_param)?,
            (Curve::Bls12_381, crate::CommitmentSchemeArg::Sis) => run_compress_sumcheck_opt::<Bls12_381, SisCommitment<Bls12_381>>(&args.circuit, &args.steps, &tmp, opts, args.sis_param)?,
            (Curve::Bn254, crate::CommitmentSchemeArg::Pedersen) => run_compress_sumcheck_opt::<Bn254, PedersenCommitment<Bn254>>(&args.circuit, &args.steps, &tmp, opts, args.sis_param)?,
            (Curve::Bn254, crate::CommitmentSchemeArg::Sis) => run_compress_sumcheck_opt::<Bn254, SisCommitment<Bn254>>(&args.circuit, &args.steps, &tmp, opts, args.sis_param)?,
            (Curve::Pallas, crate::CommitmentSchemeArg::Pedersen) => run_compress_sumcheck_opt::<Pallas, PedersenCommitment<Pallas>>(&args.circuit, &args.steps, &tmp, opts, args.sis_param)?,
            (Curve::Pallas, crate::CommitmentSchemeArg::Sis) => run_compress_sumcheck_opt::<Pallas, SisCommitment<Pallas>>(&args.circuit, &args.steps, &tmp, opts, args.sis_param)?,
            (Curve::Vesta, crate::CommitmentSchemeArg::Pedersen) => run_compress_sumcheck_opt::<Vesta, PedersenCommitment<Vesta>>(&args.circuit, &args.steps, &tmp, opts, args.sis_param)?,
            (Curve::Vesta, crate::CommitmentSchemeArg::Sis) => run_compress_sumcheck_opt::<Vesta, SisCommitment<Vesta>>(&args.circuit, &args.steps, &tmp, opts, args.sis_param)?,
        };
        let full_bytes = fs::read(&tmp)?;
        match args.curve {
            Curve::Bls12_381 => strip_and_write::<Bls12_381>(&full_bytes, &args.out)?,
            Curve::Bn254 => strip_and_write::<Bn254>(&full_bytes, &args.out)?,
            Curve::Pallas => strip_and_write::<Pallas>(&full_bytes, &args.out)?,
            Curve::Vesta => strip_and_write::<Vesta>(&full_bytes, &args.out)?,
        };
        fs::remove_file(&tmp).ok();
    } else {
        // Default: full sumcheck compression (transparent, O(log N)).
        match (args.curve, args.commitment) {
            (Curve::Bls12_381, crate::CommitmentSchemeArg::Pedersen) => run_compress_sumcheck_opt::<Bls12_381, PedersenCommitment<Bls12_381>>(&args.circuit, &args.steps, &args.out, opts, args.sis_param)?,
            (Curve::Bls12_381, crate::CommitmentSchemeArg::Sis) => run_compress_sumcheck_opt::<Bls12_381, SisCommitment<Bls12_381>>(&args.circuit, &args.steps, &args.out, opts, args.sis_param)?,
            (Curve::Bn254, crate::CommitmentSchemeArg::Pedersen) => run_compress_sumcheck_opt::<Bn254, PedersenCommitment<Bn254>>(&args.circuit, &args.steps, &args.out, opts, args.sis_param)?,
            (Curve::Bn254, crate::CommitmentSchemeArg::Sis) => run_compress_sumcheck_opt::<Bn254, SisCommitment<Bn254>>(&args.circuit, &args.steps, &args.out, opts, args.sis_param)?,
            (Curve::Pallas, crate::CommitmentSchemeArg::Pedersen) => run_compress_sumcheck_opt::<Pallas, PedersenCommitment<Pallas>>(&args.circuit, &args.steps, &args.out, opts, args.sis_param)?,
            (Curve::Pallas, crate::CommitmentSchemeArg::Sis) => run_compress_sumcheck_opt::<Pallas, SisCommitment<Pallas>>(&args.circuit, &args.steps, &args.out, opts, args.sis_param)?,
            (Curve::Vesta, crate::CommitmentSchemeArg::Pedersen) => run_compress_sumcheck_opt::<Vesta, PedersenCommitment<Vesta>>(&args.circuit, &args.steps, &args.out, opts, args.sis_param)?,
            (Curve::Vesta, crate::CommitmentSchemeArg::Sis) => run_compress_sumcheck_opt::<Vesta, SisCommitment<Vesta>>(&args.circuit, &args.steps, &args.out, opts, args.sis_param)?,
        };
    }
    Ok(())
}
