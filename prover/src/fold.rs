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
use crate::nifs::{
    fold_challenge, small_fold_challenge, RelaxedR1csInstance, RelaxedR1csWitness,
};

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
    /// Ring domain — ternary `r ∈ {0, ±1}` (small-challenge NIFS; the exact
    /// ring-linearity that enables commitment re-binding is achieved by the
    /// ring-residue fold of `subsec:ring-fold`).
    fn fold_challenge(
        acc: &[u8],
        u1: &RelaxedR1csInstance<Self>,
        u2: &RelaxedR1csInstance<Self>,
    ) -> Self::Scalar;
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
    use blake2::Digest;

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
        // Field schemes rebind under full-field challenges; Module-SIS needs
        // the (not-yet-implemented) ring-residue fold, so it reports false.
        assert!(P::verifies_rebinding());
        assert!(!MS::verifies_rebinding());
        // A Pedersen challenge matches the classical full-field derivation.
        assert_eq!(
            <P as FoldProtocol>::fold_challenge(&acc, &up, &up),
            fold_challenge::<P>(&acc, &up, &up),
        );
    }

    #[test]
    fn checkpoint_interval_defaults_off_for_field_schemes() {
        let p = P::params_from_seed(b"t", 3, 3, 0);
        assert_eq!(P::recommended_checkpoint_interval(&p), None);
    }

    #[test]
    fn module_sis_recommends_checkpoint_cadence() {
        let m = MS::params_from_seed(b"t", 3, 3, 0);
        let interval = MS::recommended_checkpoint_interval(&m)
            .expect("module-sis must recommend a norm-reset cadence");
        assert!(interval > 0, "checkpoint interval must be positive");
    }

    #[test]
    fn ring_domain_field_fold_chain_is_consistent() {
        type CS = MS;
        type S = <CS as CommitmentScheme>::Scalar;
        let params = CS::params_from_seed(b"p8-rebind", 4, 1, 0);
        let l = vec![vec![(1u32, S::one())]];
        let r = vec![vec![(2u32, S::one())]];
        let o = vec![vec![(3u32, S::one())]];

        fn mk<CS: CommitmentScheme>(
            params: &CS::Params,
            w: &[CS::Scalar],
        ) -> (RelaxedR1csInstance<CS>, RelaxedR1csWitness<CS>) {
            let e = vec![CS::Scalar::zero()];
            (
                RelaxedR1csInstance {
                    x: w[1..3].to_vec(),
                    u: CS::Scalar::one(),
                    w_commit: CS::commit_witness(params, w),
                    e_commit: CS::commit_error(params, &e),
                },
                RelaxedR1csWitness {
                    w: w.to_vec(),
                    e,
                },
            )
        }

        let (u0, w0) = mk::<CS>(&params, &[S::one(), S::from(2), S::from(3), S::from(6)]);
        let mut u_acc = u0.clone();
        let mut w_acc = w0.clone();
        let mut acc: Vec<u8> = b"chain".to_vec();
        for (a, b) in [(7u64, 42u64), (11u64, 462u64), (13u64, 6006u64)] {
            let (u_step, w_step) = mk::<CS>(
                &params,
                &[S::one(), S::from(a), S::from(b / a), S::from(b)],
            );
            let chi = <CS as FoldProtocol>::fold_challenge(&acc, &u_acc, &u_step);
            assert!(
                chi == -S::one() || chi == S::zero() || chi == S::one(),
                "ring-domain challenge must be ternary"
            );
            let (u3, w3, _cross) = crate::nifs::fold_with_log::<CS>(
                &params, &l, &r, &o, &u_acc, &w_acc, &u_step, &w_step, chi, false,
            );
            u_acc = u3;
            w_acc = w3;
            let mut h = blake2::Blake2b512::new();
            h.update(&acc);
            h.update(crate::nifs::instance_to_bytes::<CS>(&u_acc).unwrap());
            acc = h.finalize().to_vec();
        }
    }

    /// The naive field-linear fold cannot bind Module-SIS commitments: folding
    /// the *field* witness `w1 − w2` wraps negative coefficients mod `p`, and
    /// `emb` is not a group homomorphism over that wrap (`lem:ring-fold-rebinding`
    /// only applies to the ring-residue fold of `subsec:ring-fold`).  This test
    /// pins the exact gap so it is not silently "fixed" by reintroducing the
    /// equality check for Module-SIS before the ring-residue fold lands.
    #[test]
    fn module_sis_field_fold_does_not_rebind_on_coefficient_wrap() {
        type CS = MS;
        type S = <CS as CommitmentScheme>::Scalar;
        let params = CS::params_from_seed(b"p8-rebind", 4, 1, 0);
        let l = vec![vec![(1u32, S::one())]];
        let r = vec![vec![(2u32, S::one())]];
        let o = vec![vec![(3u32, S::one())]];

        let e = vec![S::zero()];
        let (w1, w2) = (
            vec![S::one(), S::from(2), S::from(3), S::from(6)],
            vec![S::one(), S::from(7), S::from(6), S::from(42)],
        );
        let u1 = RelaxedR1csInstance {
            x: w1[1..3].to_vec(),
            u: S::one(),
            w_commit: CS::commit_witness(&params, &w1),
            e_commit: CS::commit_error(&params, &e),
        };
        let u2 = RelaxedR1csInstance {
            x: w2[1..3].to_vec(),
            u: S::one(),
            w_commit: CS::commit_witness(&params, &w2),
            e_commit: CS::commit_error(&params, &e),
        };
        let w1 = RelaxedR1csWitness { w: w1, e: e.clone() };
        let w2 = RelaxedR1csWitness { w: w2, e: e };
        let (u3, w3, _cross) = crate::nifs::fold_with_log::<CS>(
            &params, &l, &r, &o, &u1, &w1, &u2, &w2, -S::one(), false,
        );
        assert_ne!(
            u3.w_commit,
            CS::commit_witness(&params, &w3.w),
            "folded field witness w1 − w2 wraps mod p (e.g. 2 − 7), so naive field \
             folding cannot rebind the Module-SIS commitment; must use the ring-residue fold"
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