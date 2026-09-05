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

use crate::Curve;
use clap::Parser;
use prover::{
    commitment::{HashCommitment, ModuleSisCommitment, PedersenCommitment, SisCommitment},
    curve::{Bandersnatch, Bls12_381, Bn254, Grumpkin, NovaCurve, Pallas, ScalarField, Vesta},
    norm, run_compress_level1_batch_opt, run_compress_level1_opt, run_compress_sumcheck_batch_opt,
    run_compress_sumcheck_opt, NifsSumcheckProof, OptFlags, DEFAULT_SIS_PARAM,
};
use std::error::Error;
use std::fs;
use std::path::PathBuf;

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

    /// Produce a Level-1 proof (degree-2 sumcheck + W/E opening proofs +
    /// final-claim-zero check).  Carries the commitment openings and the
    /// explicit `az_r/bz_r/cz_r/er_r` evaluations so the verifier can close
    /// the "free E" / all-zeros soundness gap; larger than the plain slim
    /// proof but auditable.  Conflicts with `--slim`.
    #[arg(long, conflicts_with = "slim")]
    pub level1: bool,

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

    /// Module-SIS parameter-set index (0 = Conservative-I, 1 = Balanced-I,
    /// 2 = Compact-I), used only with --commitment module-sis.  Selects the
    /// ring/on-chain size; defaults to 0.  Must match across fold, compress
    /// and verify.
    #[arg(long, value_name = "IDX")]
    pub module_sis_params: Option<usize>,

    /// (Audit-only) enforce an ∞-norm bound on every fold step's *pre-fold*
    /// witness `Z_j` and error `E_j` using Option A — a per-coordinate
    /// range/bit-decomposition certificate.  Only meaningful with `--level1`;
    /// the proof carries one certificate per step and the size grows linearly
    /// in the circuit width.
    #[arg(long, requires = "level1")]
    pub norm_range: bool,

    /// (Audit-only) enforce an ∞-norm bound on every fold step's *pre-fold*
    /// witness `Z_j` and error `E_j` using Option B — a single JL/sketch
    /// inner-product certificate.  Only meaningful with `--level1`; proof size
    /// is constant per step (a few field elements).  Conflicts with
    /// `--norm-range`.
    #[arg(long, requires = "level1", conflicts_with = "norm_range")]
    pub norm_jl: bool,

    /// Public ∞-norm bound `B` (bit-length) used by the norm certificates.
    /// The prover fails up front if any honest step witness/error exceeds
    /// `2^B`.  Only meaningful with `--norm-range`/`--norm-jl`.
    #[arg(long, value_name = "BITS", default_value_t = 64)]
    pub norm_bits: u32,

    /// Batch size for batch-then-checkpoint folding (P2b) during compression.
    /// When set, re-folds deterministically in batches with norm-reset
    /// checkpoints.  Defaults to 0 (standard step-by-step folding).
    #[arg(long, value_name = "N", default_value_t = 0)]
    pub batch_size: usize,

    /// Infinity-norm bound in bits for checkpoint shortness checks.
    /// Only used when --batch-size is set.
    #[arg(long, value_name = "BITS", default_value_t = 256)]
    pub bound_bits: u32,
}

fn parse_opt_flags(s: &str) -> Result<OptFlags, Box<dyn Error>> {
    let mut flags = OptFlags::NONE;
    for part in s.split(',') {
        match part.trim() {
            "none" | "" => {}
            "parallel" | "p" => flags.parallel = true,
            "lazy" | "l" => flags.lazy_commit = true,
            "all" | "a" => flags = OptFlags::ALL,
            other => {
                return Err(format!(
                    "unknown optimization: '{other}' — valid: parallel, lazy, all, none"
                )
                .into())
            }
        }
    }
    Ok(flags)
}

fn strip_and_write<C: NovaCurve>(
    full_bytes: &[u8],
    out: &std::path::Path,
) -> Result<(), Box<dyn Error>> {
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
    let m = crate::cmd::effective_m(args.commitment, args.sis_param, args.module_sis_params);
    let batch = args.batch_size > 0;
    if args.level1 {
        // (audit-only) norm enforcement mode, if any.
        let norm_mode = if args.norm_range {
            norm::NormMode::Range
        } else if args.norm_jl {
            norm::NormMode::Jl
        } else {
            norm::NormMode::None
        };
        dispatch!(args.curve, args.commitment, {
            if batch {
                run_compress_level1_batch_opt::<C, CS>(
                    &args.circuit,
                    &args.steps,
                    &args.out,
                    opts,
                    m,
                    norm_mode,
                    args.norm_bits,
                    args.batch_size,
                    args.bound_bits,
                )
            } else {
                run_compress_level1_opt::<C, CS>(
                    &args.circuit,
                    &args.steps,
                    &args.out,
                    opts,
                    m,
                    norm_mode,
                    args.norm_bits,
                )
            }
        })?;
        return Ok(());
    }
    if args.slim {
        let tmp = args.out.with_extension("full.cbor");
        dispatch!(args.curve, args.commitment, {
            if batch {
                run_compress_sumcheck_batch_opt::<C, CS>(
                    &args.circuit,
                    &args.steps,
                    &tmp,
                    opts,
                    m,
                    args.batch_size,
                    args.bound_bits,
                )
            } else {
                run_compress_sumcheck_opt::<C, CS>(&args.circuit, &args.steps, &tmp, opts, m)
            }
        })?;
        let full_bytes = fs::read(&tmp)?;
        match args.curve {
            Curve::Bls12_381 => strip_and_write::<Bls12_381>(&full_bytes, &args.out)?,
            Curve::Bn254 => strip_and_write::<Bn254>(&full_bytes, &args.out)?,
            Curve::Pallas => strip_and_write::<Pallas>(&full_bytes, &args.out)?,
            Curve::Vesta => strip_and_write::<Vesta>(&full_bytes, &args.out)?,
            Curve::Grumpkin => strip_and_write::<Grumpkin>(&full_bytes, &args.out)?,
            Curve::Bandersnatch => strip_and_write::<Bandersnatch>(&full_bytes, &args.out)?,
        };
        fs::remove_file(&tmp).ok();
    } else {
        dispatch!(args.curve, args.commitment, {
            if batch {
                run_compress_sumcheck_batch_opt::<C, CS>(
                    &args.circuit,
                    &args.steps,
                    &args.out,
                    opts,
                    m,
                    args.batch_size,
                    args.bound_bits,
                )
            } else {
                run_compress_sumcheck_opt::<C, CS>(&args.circuit, &args.steps, &args.out, opts, m)
            }
        })?;
    }
    Ok(())
}
