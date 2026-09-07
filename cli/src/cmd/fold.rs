//! `fold` subcommand — fold step witnesses into a single Relaxed-R1CS
//! instance (NIFS) and emit the O(1) bundle.

use crate::Curve;
use clap::Parser;
use prover::{
    commitment::{HashCommitment, ModuleSisCommitment, PedersenCommitment, SisCommitment},
    curve::{Bandersnatch, Bls12_381, Bn254, Grumpkin, NovaCurve, Pallas, ScalarField, Vesta},
    run_fold_nifs_batch_opt, run_fold_nifs_opt, NifsBundle, OptFlags, DEFAULT_SIS_PARAM,
    DEFAULT_WINDOW_SIZE,
};
use std::error::Error;
use std::fs;
use std::path::PathBuf;

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

    /// Batch size for batch-then-checkpoint folding (P2b).
    /// When set, folds instances in batches of this size using small
    /// ternary challenges, with norm-reset checkpoints after each batch.
    /// Defaults to 0 (disabled, standard step-by-step folding).  For
    /// `--commitment module-sis` a zero batch size defaults to the window
    /// size (`DEFAULT_WINDOW_SIZE`), so the fold matches the transport
    /// assumed by the window-model verifier.
    #[arg(long, value_name = "N", default_value_t = 0)]
    pub batch_size: usize,

    /// Infinity-norm bound in bits for checkpoint shortness checks.
    /// Only used when --batch-size is set.  Coordinates exceeding this
    /// bit-width abort the fold.
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

fn write_bundle<C: NovaCurve>(
    out: &NifsBundle,
    path: &std::path::Path,
    opts: OptFlags,
) -> Result<(), Box<dyn Error>> {
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
    let m = crate::cmd::effective_m(args.commitment, args.sis_param, args.module_sis_params);
    // Module-SIS defaults to batch+checkpoint folding with the window size so
    // the transport (batch-folded bundle) matches the window-model verifier.
    let batch_size = if args.batch_size > 0 {
        args.batch_size
    } else if args.commitment == crate::CommitmentSchemeArg::ModuleSis {
        DEFAULT_WINDOW_SIZE
    } else {
        0
    };
    dispatch!(args.curve, args.commitment, {
        let out = if batch_size > 0 {
            run_fold_nifs_batch_opt::<C, CS>(
                &args.circuit,
                &args.steps,
                opts,
                m,
                batch_size,
                args.bound_bits,
            )?
        } else {
            run_fold_nifs_opt::<C, CS>(&args.circuit, &args.steps, opts, m)?
        };
        write_bundle::<C>(&out.bundle, &args.out, opts)
    })
}
