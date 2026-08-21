//! `fold` subcommand — fold step witnesses into a single Relaxed-R1CS
//! instance (NIFS) and emit the O(1) bundle.

use clap::Parser;
use prover::{run_fold_nifs_opt, OptFlags};
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

    /// Output path for the NIFS bundle JSON
    /// (`.ivc.json` extension recommended).
    #[arg(long, value_name = "FILE")]
    pub out: PathBuf,

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

/// Run the `fold` subcommand.
pub fn run(args: Args) -> Result<(), Box<dyn Error>> {
    let opts = parse_opt_flags(&args.opt)?;
    let out = run_fold_nifs_opt(&args.circuit, &args.steps, opts)?;
    let json = serde_json::to_string_pretty(&out.bundle)
        .map_err(|e| format!("failed to serialize NIFS bundle: {e}"))?;
    fs::write(&args.out, &json)
        .map_err(|e| format!("failed to write NIFS bundle to {}: {e}", args.out.display()))?;
    eprintln!(
        "NIFS bundle written to {} ({} steps → one instance, u = {}, opt: {:?})",
        args.out.display(),
        out.bundle.n_steps,
        out.bundle.final_instance.u,
        opts,
    );
    Ok(())
}
