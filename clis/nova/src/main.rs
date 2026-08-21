//! CLI for NovaSlim — off-circuit NIFS folding + sumcheck compression + slim
//! on-chain proofs.
//!
//! A long computation is decomposed into `N` identical step circuits, each
//! proving `state_{i+1} = f(step_i, state_i)`. The CLI covers the slim flow:
//!   1. `params` — inspect a step circuit and validate the IVC invariant
//!   2. `fold --nifs` — fold step witnesses into one Relaxed-R1CS instance
//!   3. `compress` — sumcheck-compress (with `--slim` for the ~1.5 KiB
//!      on-chain proof)
//!   4. `verify` — verify the folded bundle against the proof
//!
//! No trusted setup is needed anywhere in this flow.
//!
//! The core IVC logic lives in the `prover` crate; this crate only
//! adds the command-line interface on top of it.

use clap::{Parser, Subcommand};
use std::error::Error;

mod cmd;

/// CLI commands available
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Inspect a step circuit and emit a JSON descriptor
    ///
    /// Loads the step circuit from a `.r1cs` file, validates that it
    /// satisfies the IVC invariant (`n_pub_in == n_pub_out`), and prints
    /// or writes a JSON descriptor containing the circuit's wire and
    /// constraint counts.
    ///
    /// Example:
    ///
    ///   $ nova params --circuit step_circuit.r1cs
    Params(cmd::params::Args),

    /// Fold step witnesses into an IVC bundle
    ///
    /// Loads the step circuit, the per-step proving key, and a directory
    /// of witness files (`step_0000.wtns`, `step_0001.wtns`, …), then
    /// produces a Groth16 proof for each step and binds them together
    /// with a BLAKE2b transcript.
    ///
    /// With `--nifs` (Implementation 9) no proving key is needed: the step
    /// instances are folded into a single Relaxed-R1CS instance instead of
    /// producing one Groth16 proof per step.
    ///
    /// The output bundle (`.ivc.json`) contains all step proofs, the
    /// initial state, and the final transcript hash.  It is consumed by
    /// the `verify` subcommand.
    ///
    /// Example:
    ///
    ///   $ nova fold --circuit step_circuit.r1cs --proving-key step.pk --steps ./step_witnesses/ --out bundle.ivc.json
    ///   $ nova fold --nifs --circuit step_circuit.r1cs --steps ./step_witnesses/ --out bundle.ivc.json
    ///   $ nova fold --nifs --circuit step_circuit.r1cs --steps ./step_witnesses/ --out bundle.ivc.json --compression-r1cs compression.r1cs
    Fold(cmd::fold::Args),

    /// Compress a NIFS bundle into a single proof
    ///
    /// Re-folds the step witnesses deterministically, then compresses the
    /// final relaxed instance into one proof:
    ///
    /// - **Implementation 9** (default): Groth16 compression proof, needs
    ///   a one-time trusted setup for the compression circuit.
    /// - **Implementation 10** (`--sumcheck`): transparent sumcheck proof,
    ///   no trusted setup, O(log N) proof size.
    ///
    /// The result is consumed by `nova verify` on the NIFS bundle.
    ///
    /// Examples:
    ///
    ///   $ nova compress --circuit step_circuit.r1cs --steps ./step_witnesses/ --proving-key compression.pk --out compression.proof.json
    ///   $ nova compress --sumcheck --circuit step_circuit.r1cs --steps ./step_witnesses/ --out sumcheck.proof.json
    Compress(cmd::compress::Args),

    /// Verify a folded IVC bundle
    ///
    /// Loads an IVC bundle (`.ivc.json`) and checks:
    ///   - For step-chain bundles: Groth16 pairings + state chain + transcript
    ///   - For NIFS bundles: compression proof verification + commitments
    ///
    /// For a NIFS bundle (Implementation 9), pass the Groth16 compression
    /// proof and verifying key:
    ///
    ///   $ nova verify --ivc bundle.ivc.json --compression-proof compression.proof.json --compression-vk compression.vk
    ///
    /// For a NIFS bundle (Implementation 10), pass the sumcheck proof
    /// instead — no verifying key needed:
    ///
    ///   $ nova verify --ivc bundle.ivc.json --sumcheck-proof sumcheck.proof.json
    ///
    /// Examples:
    ///
    ///   $ nova verify --ivc bundle.ivc.json --verifying-key step.vk
    ///   $ nova verify --ivc bundle.ivc.json --sumcheck-proof sumcheck.proof.json
    Verify(cmd::verify::Args),
}

#[derive(Parser)]
#[clap(bin_name = "nova")]
#[clap(author = "HAL Team <hal@cardanofoundation.org>")]
#[clap(version = env!("CARGO_PKG_VERSION"))]
#[clap(
    about = "NovaSlim — folding + slim on-chain proofs CLI",
    long_about = "A command-line interface for NovaSlim: off-circuit NIFS folding with transparent\n\
sumcheck compression and slim on-chain proofs.\n\n\
A long computation is decomposed into N identical step circuits. The steps are folded into\n\
one Relaxed-R1CS instance (`fold --nifs`), compressed into a constant-size sumcheck proof\n\
(`compress --slim`), and verified with native field operations only — no pairings, no\n\
trusted setup (`verify --slim-proof`).\n\n\
The core IVC logic lives in the `prover` crate."
)]
pub struct Cli {
    #[command(subcommand)]
    command: Command,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Cli::parse();

    match args.command {
        Command::Params(args) => cmd::params::run(args),
        Command::Fold(args) => cmd::fold::run(args),
        Command::Compress(args) => cmd::compress::run(args),
        Command::Verify(args) => cmd::verify::run(args),
    }
}
