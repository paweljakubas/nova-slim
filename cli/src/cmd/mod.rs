pub mod compress;
pub mod fold;
pub mod help;
pub mod params;
pub mod verify;

use crate::CommitmentSchemeArg;

/// Effective lattice-commitment dimension `m`.
///
/// For the experimental Module-SIS commitment the parameter is an index into
/// `prover::module_sis::ModuleSisParams::ALL` (the per-commitment on-chain
/// size is fixed by that entry), not a raw dimension.  For every other scheme
/// it is the raw SIS `m` dimension.
pub fn effective_m(
    commitment: CommitmentSchemeArg,
    sis_param: usize,
    module_sis_params: Option<usize>,
) -> usize {
    if matches!(commitment, CommitmentSchemeArg::ModuleSis) {
        module_sis_params.unwrap_or(0)
    } else {
        sis_param
    }
}
