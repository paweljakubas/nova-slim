//! Domain-aware folding protocol (P8 / `subsec:ring-fold`).
//!
//! Classical NIFS folding runs over the *scalar field* `F_r` of the
//! commitment scheme: challenges are drawn from the full field and
//! commitments satisfy the field-homomorphism `com(w1 + r·w2) =
//! com(w1) + r·com(w2)` exactly (`FIELD_HOMOMORPHIC = true`).
//!
//! Module-SIS is different.  Its commitments live over the ring
//! `R_q = Z_q[x]/(x^n + 1)` and the scalar embedding `φ: F_r → R_q` is not a
//! ring homomorphism (`FIELD_HOMOMORPHIC = false`).  Folding such a scheme
//! over the field domain would produce an accumulator whose commitment is the
//! *ring*-homomorphic fold — unrelated to a fresh commitment of the folded
//! *field* witness, so verification-time re-binding would be unsound.
//!
//! The ring-domain fold fixes this: with **ternary challenges** `r ∈ {0, ±1}`
//! the embedding is exact (`r̂ = r mod q`) and
//! `com(w1 + r·w2) = com(w1) + r̂·com(w2)`, so the accumulated commitment
//! *equals* a fresh commitment of the folded witness (`lem:ring-fold-rebinding`
//! in the paper).
//!
//! [`FoldProtocol`] is a blanket extension of [`CommitmentScheme`] that
//! dispatches between the two domains automatically from each scheme's
//! `FIELD_HOMOMORPHIC` flag.

use crate::commitment::CommitmentScheme;
use crate::nifs::{fold_challenge, small_fold_challenge, RelaxedR1csInstance};

/// Which algebraic domain a scheme's NIFS folds run over.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FoldDomain {
    /// Field-homomorphic folding over `F_r` with full-field challenges.
    Field,
    /// Ring-homomorphic folding over `R_q` with ternary challenges `{0, ±1}`.
    Ring,
}

/// Domain-aware folding protocol.
///
/// Blanket-implemented for every [`CommitmentScheme`] from its
/// `FIELD_HOMOMORPHIC` flag; folding/verification code calls
/// `<CS as FoldProtocol>::…` instead of hard-coding the challenge derivation.
pub trait FoldProtocol: CommitmentScheme {
    /// The folding domain for this scheme.
    const FOLD_DOMAIN: FoldDomain;

    /// The Fiat-Shamir folding challenge `r = H(FoldPrefix ‖ acc ‖ U1 ‖ U2)`
    /// in this scheme's domain.
    ///
    /// Field domain — full-field `r ∈ F_r` (sound against arbitrary scalar
    /// queries).
    /// Ring domain — ternary `r ∈ {0, ±1}` (exact ring-linearity, so the
    /// accumulated commitment stays the commitment of the folded witness).
    fn fold_challenge(
        acc: &[u8],
        u1: &RelaxedR1csInstance<Self>,
        u2: &RelaxedR1csInstance<Self>,
    ) -> Self::Scalar;

    /// Whether a fresh commitment of the *folded field witness* can be
    /// compared for equality with the homomorphically folded commitment.
    ///
    /// True for every scheme currently supported: field-homomorphic schemes
    /// satisfy it under full-field challenges, and the ring-domain fold
    /// satisfies it exactly under ternary challenges.
    fn verifies_rebinding() -> bool {
        true
    }
}

impl<CS: CommitmentScheme> FoldProtocol for CS {
    const FOLD_DOMAIN: FoldDomain = if CS::FIELD_HOMOMORPHIC {
        FoldDomain::Field
    } else {
        FoldDomain::Ring
    };

    fn fold_challenge(
        acc: &[u8],
        u1: &RelaxedR1csInstance<Self>,
        u2: &RelaxedR1csInstance<Self>,
    ) -> Self::Scalar {
        match Self::FOLD_DOMAIN {
            FoldDomain::Field => fold_challenge::<Self>(acc, u1, u2),
            FoldDomain::Ring => small_fold_challenge::<Self>(acc, u1, u2),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commitment::{ModuleSisCommitment, PedersenCommitment};
    use crate::curve::Bls12_381;
    use ark_ff::{One, Zero};

    type P = PedersenCommitment<Bls12_381>;
    type MS = ModuleSisCommitment<Bls12_381>;

    fn mv<CS: CommitmentScheme>(params: &CS::Params) -> RelaxedR1csInstance<CS> {
        let z = vec![CS::Scalar::zero(); 3];
        RelaxedR1csInstance {
            x: z.clone(),
            u: CS::Scalar::one(),
            w_commit: CS::commit_witness(params, &z),
            e_commit: CS::commit_error(params, &z),
        }
    }

    #[test]
    fn assigns_domains_from_homomorphism_flag() {
        let p = P::params_from_seed(b"t", 3, 3, 0);
        let up = mv::<P>(&p);
        let acc: Vec<u8> = vec![1, 2, 3];
        assert_eq!(P::FOLD_DOMAIN, FoldDomain::Field);
        assert_eq!(MS::FOLD_DOMAIN, FoldDomain::Ring);
        assert!(P::verifies_rebinding());
        assert!(MS::verifies_rebinding());
        // A Pedersen challenge matches the classical full-field derivation.
        assert_eq!(
            <P as FoldProtocol>::fold_challenge(&acc, &up, &up),
            fold_challenge::<P>(&acc, &up, &up),
        );
    }

    #[test]
    fn ring_domain_uses_ternary_challenges() {
        type S = <MS as CommitmentScheme>::Scalar;
        let m = MS::params_from_seed(b"t", 3, 3, 0);
        let u1 = mv::<MS>(&m);
        let u2 = mv::<MS>(&m);
        for acc in [&b"acc-a"[..], &b"acc-b"[..], &b"acc-c"[..]] {
            let r = <MS as FoldProtocol>::fold_challenge(acc, &u1, &u2);
            assert!(
                r == -S::one() || r == S::zero() || r == S::one(),
                "ring-domain challenge must be ternary, got {:?}",
                r,
            );
        }
    }
}