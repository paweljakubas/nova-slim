//! `verify` subcommand — verify a NIFS bundle against a compression proof.

use clap::Parser;
use prover::{run_verify_slim, run_verify_sumcheck_opt, DEFAULT_SIS_PARAM, commitment::{PedersenCommitment, SisCommitment, HashCommitment}, curve::{Bls12_381, Bn254, Pallas, Vesta, Grumpkin, Bandersnatch}};
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

    /// Commitment scheme to use.
    #[arg(long, value_enum, default_value = "pedersen")]
    pub commitment: crate::CommitmentSchemeArg,

    /// SIS output dimension (m).  Only used with --commitment sis.
    /// Must match the value used during compress.
    #[arg(long, value_name = "M", default_value_t = DEFAULT_SIS_PARAM)]
    pub sis_param: usize,
}

/// Run the `verify` subcommand.
pub fn run(args: Args) -> Result<(), Box<dyn Error>> {
    if let Some(ref sp) = args.slim_proof {
        let out = match (args.curve, args.commitment) {
            (Curve::Bls12_381, crate::CommitmentSchemeArg::Pedersen) => run_verify_slim::<Bls12_381, PedersenCommitment<Bls12_381>>(&args.ivc, sp)?,
            (Curve::Bls12_381, crate::CommitmentSchemeArg::Sis) => run_verify_slim::<Bls12_381, SisCommitment<Bls12_381>>(&args.ivc, sp)?,
            (Curve::Bls12_381, crate::CommitmentSchemeArg::Hash) => run_verify_slim::<Bls12_381, HashCommitment<Bls12_381>>(&args.ivc, sp)?,
            (Curve::Bn254, crate::CommitmentSchemeArg::Pedersen) => run_verify_slim::<Bn254, PedersenCommitment<Bn254>>(&args.ivc, sp)?,
            (Curve::Bn254, crate::CommitmentSchemeArg::Sis) => run_verify_slim::<Bn254, SisCommitment<Bn254>>(&args.ivc, sp)?,
            (Curve::Bn254, crate::CommitmentSchemeArg::Hash) => run_verify_slim::<Bn254, HashCommitment<Bn254>>(&args.ivc, sp)?,
            (Curve::Pallas, crate::CommitmentSchemeArg::Pedersen) => run_verify_slim::<Pallas, PedersenCommitment<Pallas>>(&args.ivc, sp)?,
            (Curve::Pallas, crate::CommitmentSchemeArg::Sis) => run_verify_slim::<Pallas, SisCommitment<Pallas>>(&args.ivc, sp)?,
            (Curve::Pallas, crate::CommitmentSchemeArg::Hash) => run_verify_slim::<Pallas, HashCommitment<Pallas>>(&args.ivc, sp)?,
            (Curve::Vesta, crate::CommitmentSchemeArg::Pedersen) => run_verify_slim::<Vesta, PedersenCommitment<Vesta>>(&args.ivc, sp)?,
            (Curve::Vesta, crate::CommitmentSchemeArg::Sis) => run_verify_slim::<Vesta, SisCommitment<Vesta>>(&args.ivc, sp)?,
            (Curve::Vesta, crate::CommitmentSchemeArg::Hash) => run_verify_slim::<Vesta, HashCommitment<Vesta>>(&args.ivc, sp)?,
            (Curve::Grumpkin, crate::CommitmentSchemeArg::Pedersen) => run_verify_slim::<Grumpkin, PedersenCommitment<Grumpkin>>(&args.ivc, sp)?,
            (Curve::Grumpkin, crate::CommitmentSchemeArg::Sis) => run_verify_slim::<Grumpkin, SisCommitment<Grumpkin>>(&args.ivc, sp)?,
            (Curve::Grumpkin, crate::CommitmentSchemeArg::Hash) => run_verify_slim::<Grumpkin, HashCommitment<Grumpkin>>(&args.ivc, sp)?,
            (Curve::Bandersnatch, crate::CommitmentSchemeArg::Pedersen) => run_verify_slim::<Bandersnatch, PedersenCommitment<Bandersnatch>>(&args.ivc, sp)?,
            (Curve::Bandersnatch, crate::CommitmentSchemeArg::Sis) => run_verify_slim::<Bandersnatch, SisCommitment<Bandersnatch>>(&args.ivc, sp)?,
            (Curve::Bandersnatch, crate::CommitmentSchemeArg::Hash) => run_verify_slim::<Bandersnatch, HashCommitment<Bandersnatch>>(&args.ivc, sp)?,
        };
        eprintln!(
            "Verified {} steps: slim sumcheck proof OK, state chain OK (no opening proofs — off-chain audit trail)",
            out.steps
        );
        eprintln!("Final transcript: {}", out.transcript_final);
        return Ok(());
    }

    if let Some(ref sc_proof) = args.sumcheck_proof {
        let out = match (args.curve, args.commitment) {
            (Curve::Bls12_381, crate::CommitmentSchemeArg::Pedersen) => run_verify_sumcheck_opt::<Bls12_381, PedersenCommitment<Bls12_381>>(&args.ivc, sc_proof, args.sis_param)?,
            (Curve::Bls12_381, crate::CommitmentSchemeArg::Sis) => run_verify_sumcheck_opt::<Bls12_381, SisCommitment<Bls12_381>>(&args.ivc, sc_proof, args.sis_param)?,
            (Curve::Bls12_381, crate::CommitmentSchemeArg::Hash) => run_verify_sumcheck_opt::<Bls12_381, HashCommitment<Bls12_381>>(&args.ivc, sc_proof, args.sis_param)?,
            (Curve::Bn254, crate::CommitmentSchemeArg::Pedersen) => run_verify_sumcheck_opt::<Bn254, PedersenCommitment<Bn254>>(&args.ivc, sc_proof, args.sis_param)?,
            (Curve::Bn254, crate::CommitmentSchemeArg::Sis) => run_verify_sumcheck_opt::<Bn254, SisCommitment<Bn254>>(&args.ivc, sc_proof, args.sis_param)?,
            (Curve::Bn254, crate::CommitmentSchemeArg::Hash) => run_verify_sumcheck_opt::<Bn254, HashCommitment<Bn254>>(&args.ivc, sc_proof, args.sis_param)?,
            (Curve::Pallas, crate::CommitmentSchemeArg::Pedersen) => run_verify_sumcheck_opt::<Pallas, PedersenCommitment<Pallas>>(&args.ivc, sc_proof, args.sis_param)?,
            (Curve::Pallas, crate::CommitmentSchemeArg::Sis) => run_verify_sumcheck_opt::<Pallas, SisCommitment<Pallas>>(&args.ivc, sc_proof, args.sis_param)?,
            (Curve::Pallas, crate::CommitmentSchemeArg::Hash) => run_verify_sumcheck_opt::<Pallas, HashCommitment<Pallas>>(&args.ivc, sc_proof, args.sis_param)?,
            (Curve::Vesta, crate::CommitmentSchemeArg::Pedersen) => run_verify_sumcheck_opt::<Vesta, PedersenCommitment<Vesta>>(&args.ivc, sc_proof, args.sis_param)?,
            (Curve::Vesta, crate::CommitmentSchemeArg::Sis) => run_verify_sumcheck_opt::<Vesta, SisCommitment<Vesta>>(&args.ivc, sc_proof, args.sis_param)?,
            (Curve::Vesta, crate::CommitmentSchemeArg::Hash) => run_verify_sumcheck_opt::<Vesta, HashCommitment<Vesta>>(&args.ivc, sc_proof, args.sis_param)?,
            (Curve::Grumpkin, crate::CommitmentSchemeArg::Pedersen) => run_verify_sumcheck_opt::<Grumpkin, PedersenCommitment<Grumpkin>>(&args.ivc, sc_proof, args.sis_param)?,
            (Curve::Grumpkin, crate::CommitmentSchemeArg::Sis) => run_verify_sumcheck_opt::<Grumpkin, SisCommitment<Grumpkin>>(&args.ivc, sc_proof, args.sis_param)?,
            (Curve::Grumpkin, crate::CommitmentSchemeArg::Hash) => run_verify_sumcheck_opt::<Grumpkin, HashCommitment<Grumpkin>>(&args.ivc, sc_proof, args.sis_param)?,
            (Curve::Bandersnatch, crate::CommitmentSchemeArg::Pedersen) => run_verify_sumcheck_opt::<Bandersnatch, PedersenCommitment<Bandersnatch>>(&args.ivc, sc_proof, args.sis_param)?,
            (Curve::Bandersnatch, crate::CommitmentSchemeArg::Sis) => run_verify_sumcheck_opt::<Bandersnatch, SisCommitment<Bandersnatch>>(&args.ivc, sc_proof, args.sis_param)?,
            (Curve::Bandersnatch, crate::CommitmentSchemeArg::Hash) => run_verify_sumcheck_opt::<Bandersnatch, HashCommitment<Bandersnatch>>(&args.ivc, sc_proof, args.sis_param)?,
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
