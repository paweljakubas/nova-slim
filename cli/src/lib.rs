//! Library exports for the nova CLI

/// Re-export common types from prover for downstream use
pub use prover::{
    run_fold_nifs, run_params, run_verify_slim, run_verify_sumcheck, CircuitDescriptor, NifsBundle,
    NifsSlimProof, NifsSumcheckProof, VerifyOutput,
};
