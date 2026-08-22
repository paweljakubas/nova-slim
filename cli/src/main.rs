//! CLI for NovaSlim — off-circuit NIFS folding + sumcheck compression + slim
//! on-chain proofs.
//!
//! A long computation is decomposed into `N` identical step circuits, each
//! proving `state_{i+1} = f(step_i, state_i)`. The CLI covers the slim flow:
//!   1. `params` — inspect a step circuit and validate the IVC invariant
//!   2. `fold` — fold step witnesses into one Relaxed-R1CS instance
//!   3. `compress` — sumcheck-compress (with `--slim` for the ~1.5 KiB
//!      on-chain proof)
//!   4. `verify` — verify the folded bundle against the proof
//!
//! No trusted setup is needed anywhere in this flow.
//!
//! The core IVC logic lives in the `prover` crate; this crate only
//! adds the command-line interface on top of it.

use clap::{Parser, Subcommand, ValueEnum};
use std::error::Error;

mod cmd;

/// Supported elliptic curves.
#[derive(Debug, Clone, Copy, Default, ValueEnum)]
pub enum Curve {
    /// BLS12-381 (Cardano-native).
    #[default]
    Bls12_381,
    /// BN254 (Ethereum zk-rollups).
    Bn254,
}

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
    ///   $ nova-slim params --circuit step_circuit.r1cs
    Params(cmd::params::Args),

    /// Fold step witnesses into a single Relaxed-R1CS instance
    ///
    /// Loads the step circuit and a directory of witness files
    /// (`step_0000.wtns`, `step_0001.wtns`, …), then folds every step
    /// instance into one running Relaxed-R1CS accumulator via the NIFS.
    /// Folding is linear-time, transparent, and needs no proving key.
    ///
    /// The output bundle (compact CBOR, `.ivc.cbor`) contains the final
    /// folded instance, the initial state, and the final transcript hash.
    /// It is consumed by the `compress` and `verify` subcommands.
    ///
    /// Example:
    ///
    ///   $ nova-slim fold --circuit step_circuit.r1cs --steps ./step_witnesses/ --out bundle.ivc.cbor
    Fold(cmd::fold::Args),

    /// Compress a NIFS bundle into a single constant-size proof
    ///
    /// Re-folds the step witnesses deterministically, then compresses the
    /// final relaxed instance into one sumcheck proof — transparent, no
    /// trusted setup.  With `--slim`, strips the HashPC opening proofs to
    /// produce the on-chain-friendly slim proof (~2.4 KiB for
    /// 7,724-constraint steps).  Artifacts are compact CBOR.
    ///
    /// The result is consumed by `nova-slim verify` on the NIFS bundle.
    ///
    /// Examples:
    ///
    ///   $ nova-slim compress --circuit step_circuit.r1cs --steps ./step_witnesses/ --out sumcheck.proof.cbor
    ///   $ nova-slim compress --slim --circuit step_circuit.r1cs --steps ./step_witnesses/ --out slim.proof.cbor
    Compress(cmd::compress::Args),

    /// Verify a folded NIFS bundle against its compression proof
    ///
    /// Loads a NIFS bundle (`.ivc.cbor`) and checks the compression proof:
    /// sumcheck protocol + commitments (`--sumcheck-proof`, audit-grade) or
    /// the slim on-chain path (`--slim-proof`, no opening proofs).
    ///
    /// Examples:
    ///
    ///   $ nova-slim verify --ivc bundle.ivc.cbor --sumcheck-proof sumcheck.proof.cbor
    ///   $ nova-slim verify --ivc bundle.ivc.cbor --slim-proof slim.proof.cbor
    Verify(cmd::verify::Args),
}

#[derive(Parser)]
#[clap(bin_name = "nova-slim")]
#[clap(author = "HAL Team <hal@cardanofoundation.org>")]
#[clap(version = env!("CARGO_PKG_VERSION"))]
#[clap(
    about = "NovaSlim — folding + slim on-chain proofs CLI",
    long_about = "A command-line interface for NovaSlim: off-circuit NIFS folding with transparent\n\
sumcheck compression and slim on-chain proofs.\n\n\
A long computation is decomposed into N identical step circuits. The steps are folded into\n\
one Relaxed-R1CS instance (`fold`), compressed into a constant-size sumcheck proof\n\
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
