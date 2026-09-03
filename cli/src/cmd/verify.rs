//! `verify` subcommand — verify a NIFS bundle against a compression proof.

use crate::Curve;
use clap::Parser;
use prover::{
    commitment::{HashCommitment, PedersenCommitment, SisCommitment},
    curve::{Bandersnatch, Bls12_381, Bn254, Grumpkin, Pallas, Vesta},
    run_verify_slim, run_verify_slim_level1, run_verify_sumcheck_opt, OptFlags, DEFAULT_SIS_PARAM,
};
use std::error::Error;
use std::path::PathBuf;

/// Arguments for the `verify` subcommand
#[derive(Debug, Parser)]
pub struct Args {
    /// Path to the NIFS bundle produced by `nova-slim fold`
    #[arg(long, value_name = "FILE")]
    pub ivc: PathBuf,

    /// Path to the full sumcheck compression proof from `nova-slim compress`
    /// (default).  Verifies the sumcheck protocol plus the HashPC opening
    /// proofs and Pedersen commitments (audit-grade).
    #[arg(long, value_name = "FILE", conflicts_with_all = ["slim_proof", "level1_proof"])]
    pub sumcheck_proof: Option<PathBuf>,

    /// Path to the slim on-chain proof from `nova-slim compress --slim`.
    /// Verifies the sumcheck protocol without the HashPC opening proofs
    /// (lightweight, Plutus-ready).
    #[arg(long, value_name = "FILE", conflicts_with_all = ["sumcheck_proof", "level1_proof"])]
    pub slim_proof: Option<PathBuf>,

    /// Path to a Level-1 proof from `nova-slim compress --level1`.
    /// Verifies the degree-2 sumcheck, the final-claim-zero check, the W/E
    /// opening proofs, and Pedersen commitment consistency — closing the
    /// "free E" / all-zeros soundness gap.
    #[arg(long, value_name = "FILE", conflicts_with_all = ["sumcheck_proof", "slim_proof"])]
    pub level1_proof: Option<PathBuf>,

    /// Elliptic curve to use.
    #[arg(long, value_enum, default_value = "bls12-381")]
    pub curve: Curve,

    /// Commitment scheme to use.
    #[arg(long, value_enum, default_value = "pedersen")]
    pub commitment: crate::CommitmentSchemeArg,

    /// SIS output dimension (m).  Only used with --commitment sis.
    /// Must match the value used during compress.
    #[arg(long, value_name = "M", default_value_t = DEFAULT_SIS_PARAM)]
    pub sis_param: usize,

    /// (Audit-only) expect the level-1 proof to carry an Option-A
    /// range/bit-decomposition norm certificate and enforce ∥Z_j∥_∞,∥E_j∥_∞
    /// ≤ B on every fold step's pre-fold witness.  Must match the mode used
    /// during compress.  Requires --circuit and --steps to re-fold and
    /// recompute the ground-truth step witnesses.
    #[arg(long, requires = "level1_proof")]
    pub norm_range: bool,

    /// (Audit-only) expect the level-1 proof to carry an Option-B JL/sketch
    /// norm certificate and enforce ∥Z_j∥_∞,∥E_j∥_∞ ≤ B on every fold step's
    /// pre-fold witness.  Must match the mode used during compress.  Requires
    /// --circuit and --steps to re-fold.  Conflicts with --norm-range.
    #[arg(long, requires = "level1_proof", conflicts_with = "norm_range")]
    pub norm_jl: bool,

    /// Public ∞-norm bound `B` (bit-length) to enforce.  Must match the
    /// value used during compress.
    #[arg(long, value_name = "BITS", default_value_t = 64)]
    pub norm_bits: u32,

    /// Circuit file (`.r1cs`) — required to re-fold step witnesses for the
    /// norm audit.  Ignored unless --norm-range/--norm-jl is set.
    #[arg(long, value_name = "FILE")]
    pub circuit: Option<PathBuf>,

    /// Directory of per-step witness files (`.wtns`) — required to re-fold
    /// step witnesses for the norm audit.  Ignored unless
    /// --norm-range/--norm-jl is set.
    #[arg(long, value_name = "DIR")]
    pub steps: Option<PathBuf>,
}

/// Run the `verify` subcommand.
pub fn run(args: Args) -> Result<(), Box<dyn Error>> {
    if let Some(ref l1) = args.level1_proof {
        let norm_mode = if args.norm_range {
            prover::norm::NormMode::Range
        } else if args.norm_jl {
            prover::norm::NormMode::Jl
        } else {
            prover::norm::NormMode::None
        };
        let out = dispatch!(args.curve, args.commitment, {
            run_verify_slim_level1::<C, CS>(
                &args.ivc,
                l1,
                args.sis_param,
                norm_mode,
                args.norm_bits,
                args.circuit.as_deref(),
                args.steps.as_deref(),
                OptFlags::NONE,
            )
        })?;
        eprintln!(
            "Verified {} steps: Level-1 degree-2 sumcheck proof OK, final-claim-zero OK, \
             W/E openings OK, commitments OK, state chain OK",
            out.steps
        );
        if norm_mode != prover::norm::NormMode::None {
            eprintln!(
                "Per-step norm audit OK: every fold step's ∥Z_j∥_∞, ∥E_j∥_∞ ≤ 2^{} ({})",
                args.norm_bits,
                norm_mode.as_str()
            );
        }
        eprintln!("Final transcript: {}", out.transcript_final);
        return Ok(());
    }

    if let Some(ref sp) = args.slim_proof {
        let out = dispatch!(args.curve, args.commitment, {
            run_verify_slim::<C, CS>(&args.ivc, sp)
        })?;
        eprintln!(
            "Verified {} steps: slim sumcheck proof OK, state chain OK (no opening proofs — off-chain audit trail)",
            out.steps
        );
        eprintln!("Final transcript: {}", out.transcript_final);
        return Ok(());
    }

    if let Some(ref sc_proof) = args.sumcheck_proof {
        let out = dispatch!(args.curve, args.commitment, {
            run_verify_sumcheck_opt::<C, CS>(&args.ivc, sc_proof, args.sis_param)
        })?;
        eprintln!(
            "Verified {} steps: sumcheck compression proof OK, commitments OK, state chain OK",
            out.steps
        );
        eprintln!("Final transcript: {}", out.transcript_final);
        return Ok(());
    }

    Err("nothing to verify — pass --slim-proof or --sumcheck-proof".into())
}
