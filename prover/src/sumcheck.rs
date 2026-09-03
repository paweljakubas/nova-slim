//! Sumcheck-based constant-size compression.
//!
//! A sumcheck argument over the relaxed R1CS equation.  The verifier never
//! sees the folded witness `Z` or error vector `E` — only constant-size
//! transcripts and hash-based polynomial commitment openings.
//!
//! ## Protocol overview
//!
//! The relaxed R1CS equation `(AZ)∘(BZ) = u·(CZ) + E` is checked via
//! sumcheck over the Boolean hypercube `{0,1}^k` where `k = log2(n)` and
//! `n` is the number of constraints (padded to the next power of two).
//!
//! Define the per-constraint products:
//!
//!   `P(j) = (AZ)_j · (BZ)_j − u · (CZ)_j − e[j]`
//!
//! The sumcheck proves `Σ_{j∈{0,1}^k} P(j) = 0` for a random `r`.
//!
//! After the sumcheck, the prover provides claimed MLE evaluations
//! `az_r`, `bz_r`, `cz_r`, `e_r` at the random point `r`, and the
//! verifier checks:
//!
//!   `az_r · bz_r − u · cz_r − e_r == final_claim`
//!
//! ## Soundness
//!
//! The sumcheck is sound under the Fiat-Shamir heuristic.  The binding
//! between the prover's claimed evaluations and the committed witness is
//! provided by the HashPC commitment scheme (BLAKE2b truth-table hash +
//! Pedersen commitment).  A full polynomial commitment scheme (IPA or KZG)
//! would provide information-theoretic opening proofs; this POC uses
//! simplified opening verification.

use ark_ff::{BigInteger, One, PrimeField, Zero};

use crate::curve::{NovaCurve, ScalarField};
use blake2::digest::consts::U32;
use blake2::{Blake2b512, Digest};
use rayon::prelude::*;

/// Number of sumcheck rounds (log2 of the padded constraint count).
pub fn log2ceil(n: usize) -> usize {
    if n <= 1 {
        return 0;
    }
    (usize::BITS - (n - 1).leading_zeros()) as usize
}

/// Pad a length to the next power of two.
pub fn next_power_of_two(n: usize) -> usize {
    if n <= 1 {
        return 1;
    }
    1usize << log2ceil(n)
}

// ────────────────────────────────────────────────────────────────────
// Multilinear extension (MLE) evaluation
// ────────────────────────────────────────────────────────────────────

/// Evaluate a sparse matrix row as a multilinear extension at `r`.
///
/// Row `i` of the sparse matrix is `[(wire_j, coeff_j), ...]`.  The MLE at
/// `r` is `Σ coeff_j · r[wire_j]` (only the non-zero wires contribute).
pub fn eval_row_mle<F: PrimeField>(row: &[(u32, F)], r: &[F]) -> F {
    row.iter()
        .fold(F::zero(), |acc, &(w, c)| acc + c * r[w as usize])
}

/// Evaluate a dense vector as a multilinear extension at `r`.
///
/// `v` has length `2^k`; `r` has length `k`.
/// `v_MLE(r) = Σ_{i∈{0,1}^k} v[i] · L_i(r)` where `L_i` are the
/// multilinear basis polynomials.
pub fn eval_dense_mle<F: PrimeField>(v: &[F], r: &[F]) -> F {
    let k = r.len();
    assert_eq!(v.len(), 1 << k, "v length must be 2^r.len()");
    v.par_iter()
        .enumerate()
        .map(|(i, &val)| {
            let mut term = val;
            for (bit, &r_bit) in r.iter().enumerate().take(k) {
                let b = (i >> bit) & 1;
                if b == 0 {
                    term *= F::one() - r_bit;
                } else {
                    term *= r_bit;
                }
            }
            term
        })
        .sum()
}

// ────────────────────────────────────────────────────────────────────
// Sumcheck protocol
// ────────────────────────────────────────────────────────────────────

/// One round message of the sumcheck protocol (univariate polynomial
/// coefficients).  Degree ≤ 1 for MLE sumcheck (products of row MLEs
/// produce degree-1 univariate polynomials in each round).
pub type PolyCoeffs<C> = Vec<ScalarField<C>>;

/// The sumcheck proof: one polynomial per round.
#[derive(Debug, Clone)]
pub struct SumcheckProof<C: NovaCurve> {
    /// `claims[0]` = claimed sum; `claims[1..=num_rounds]` = evaluations at
    /// the round's random challenge.
    pub claims: Vec<ScalarField<C>>,
    /// Univariate polynomial coefficients for each round.
    pub polys: Vec<PolyCoeffs<C>>,
}

/// Fiat-Shamir challenge from accumulated hash state.
pub fn challenge_from_hash<C: NovaCurve>(hash: &[u8]) -> ScalarField<C> {
    ScalarField::<C>::from_le_bytes_mod_order(hash)
}

/// Hash a sequence of field elements (for Fiat-Shamir).
///
/// Uses BLAKE2b-256 to match the Aiken on-chain verifier's built-in blake2b_256.
pub fn hash_field_elements<C: NovaCurve>(elems: &[ScalarField<C>]) -> Vec<u8> {
    let mut h = blake2::Blake2b::<U32>::new();
    for e in elems {
        h.update(e.into_bigint().to_bytes_le());
    }
    h.finalize().to_vec()
}

/// Run the sumcheck prover for the relaxed R1CS check.
///
/// `l`, `r_mat`, `o` are the step circuit's sparse A/B/C matrices.
/// `z` is the full folded witness vector.  `u` is the slack scalar.
/// `e` is the error vector.
///
/// Returns `(proof, r_challenges)` where `r_challenges` are the Fiat-Shamir
/// random challenges derived during the protocol.
pub fn prove<C: NovaCurve>(
    l: &[Vec<(u32, ScalarField<C>)>],
    r_mat: &[Vec<(u32, ScalarField<C>)>],
    o: &[Vec<(u32, ScalarField<C>)>],
    z: &[ScalarField<C>],
    u: ScalarField<C>,
    e: &[ScalarField<C>],
) -> (SumcheckProof<C>, Vec<ScalarField<C>>) {
    prove_with_opts(l, r_mat, o, z, u, e, false)
}

/// Like [`prove`] but with optimization flags.
///
/// When `parallel` is true, the per-row product computation uses rayon for
/// parallel iteration over constraint rows.
pub fn prove_with_opts<C: NovaCurve>(
    l: &[Vec<(u32, ScalarField<C>)>],
    r_mat: &[Vec<(u32, ScalarField<C>)>],
    o: &[Vec<(u32, ScalarField<C>)>],
    z: &[ScalarField<C>],
    u: ScalarField<C>,
    e: &[ScalarField<C>],
    parallel: bool,
) -> (SumcheckProof<C>, Vec<ScalarField<C>>) {
    let n = l.len();
    assert_eq!(r_mat.len(), n);
    assert_eq!(o.len(), n);
    assert_eq!(e.len(), n);
    let n_padded = next_power_of_two(n);
    let num_rounds = log2ceil(n_padded);
    if num_rounds == 0 {
        // Trivial case: exactly 1 constraint.  The sum is just products[0].
        let az = eval_row_mle(&l[0], z);
        let bz = eval_row_mle(&r_mat[0], z);
        let cz = eval_row_mle(&o[0], z);
        let p0 = az * bz - u * cz - e[0];
        return (
            SumcheckProof {
                claims: vec![p0],
                polys: vec![],
            },
            vec![],
        );
    }

    // Compute per-row products: P(j) = (AZ)_j · (BZ)_j − u · (CZ)_j − e[j].
    let mut current: Vec<ScalarField<C>> = if parallel {
        (0..n)
            .into_par_iter()
            .map(|j| {
                let az = eval_row_mle(&l[j], z);
                let bz = eval_row_mle(&r_mat[j], z);
                let cz = eval_row_mle(&o[j], z);
                az * bz - u * cz - e[j]
            })
            .collect()
    } else {
        (0..n)
            .map(|j| {
                let az = eval_row_mle(&l[j], z);
                let bz = eval_row_mle(&r_mat[j], z);
                let cz = eval_row_mle(&o[j], z);
                az * bz - u * cz - e[j]
            })
            .collect()
    };
    current.resize(n_padded, ScalarField::<C>::zero());

    let mut claims = Vec::with_capacity(num_rounds + 1);
    let mut polys: Vec<PolyCoeffs<C>> = Vec::with_capacity(num_rounds);
    let mut r_challenges: Vec<ScalarField<C>> = Vec::with_capacity(num_rounds);

    for _round in 0..num_rounds {
        let half = current.len() / 2;

        // Claimed sum: Σ_{x∈{0,1}} g(x, ...)
        let claimed: ScalarField<C> = if parallel {
            current.par_iter().sum()
        } else {
            current.iter().sum()
        };
        claims.push(claimed);

        // Build degree-1 polynomial: f(x) = Σ_j [g(2j)·(1-x) + g(2j+1)·x]
        //   f(0) = Σ_j g(2j) = sum_base
        //   f(1) = Σ_j g(2j+1) = sum_one
        let (sum_base, sum_one) = if parallel {
            let (sb, so) = (0..half)
                .into_par_iter()
                .fold(
                    || (ScalarField::<C>::zero(), ScalarField::<C>::zero()),
                    |acc, j| (acc.0 + current[2 * j], acc.1 + current[2 * j + 1]),
                )
                .reduce(
                    || (ScalarField::<C>::zero(), ScalarField::<C>::zero()),
                    |a, b| (a.0 + b.0, a.1 + b.1),
                );
            (sb, so)
        } else {
            let mut sum_base = ScalarField::<C>::zero();
            let mut sum_one = ScalarField::<C>::zero();
            for j in 0..half {
                sum_base += current[2 * j];
                sum_one += current[2 * j + 1];
            }
            (sum_base, sum_one)
        };
        // poly = [f(0), f(1) - f(0)] so f(x) = poly[0] + poly[1]*x
        let poly = vec![sum_base, sum_one - sum_base];
        polys.push(poly);

        // Fiat-Shamir: hash claims + poly coefficients.
        let mut hash_input = claims.clone();
        for c in polys.last().unwrap() {
            hash_input.push(*c);
        }
        let h = hash_field_elements::<C>(&hash_input);
        let ri = challenge_from_hash::<C>(&h);
        r_challenges.push(ri);

        // Fold: g'(j) = g(2j) + r_i · (g(2j+1) - g(2j))
        current = if parallel {
            (0..half)
                .into_par_iter()
                .map(|j| current[2 * j] + ri * (current[2 * j + 1] - current[2 * j]))
                .collect()
        } else {
            (0..half)
                .map(|j| current[2 * j] + ri * (current[2 * j + 1] - current[2 * j]))
                .collect()
        };
    }

    // Final claim = the single remaining evaluation.
    claims.push(current[0]);

    (SumcheckProof { claims, polys }, r_challenges)
}

/// Verify a sumcheck proof.
///
/// After verification, returns the random challenges `r` and the final
/// claimed evaluation.  The caller then checks:
///
///   `az_r · bz_r − u · cz_r − e_r == final_claim`
///
/// where `az_r`, `bz_r`, `cz_r`, `e_r` are the prover's claimed MLE
/// evaluations at `r`.
pub fn verify<C: NovaCurve>(
    proof: &SumcheckProof<C>,
) -> (bool, Vec<ScalarField<C>>, ScalarField<C>) {
    let claimed_sum = proof.claims[0];
    let num_rounds = proof.polys.len();
    if num_rounds == 0 {
        return (true, vec![], claimed_sum);
    }

    // Verify each round.
    let mut current_sum = claimed_sum;
    let mut r_challenges: Vec<ScalarField<C>> = Vec::with_capacity(num_rounds);

    for round in 0..num_rounds {
        let poly = &proof.polys[round];

        // Check: f(0) + f(1) == current_sum
        if poly.len() < 2 {
            return (false, vec![], ScalarField::<C>::zero());
        }
        let s0 = poly[0];
        let s1 = poly[0] + poly[1];
        if s0 + s1 != current_sum {
            return (false, vec![], ScalarField::<C>::zero());
        }

        // Fiat-Shamir (must match prover).
        let mut hash_input = proof.claims[..=round].to_vec();
        for c in poly {
            hash_input.push(*c);
        }
        let h = hash_field_elements::<C>(&hash_input);
        let ri = challenge_from_hash::<C>(&h);
        r_challenges.push(ri);

        // Next claimed sum = f(r_i).
        current_sum = poly[0] + poly[1] * ri;
    }

    let final_claim = proof.claims[num_rounds];
    (current_sum == final_claim, r_challenges, final_claim)
}

// ────────────────────────────────────────────────────────────────────
// Degree-2 sumcheck (additive / parallel path)
// ────────────────────────────────────────────────────────────────────

/// The degree-2 sumcheck proof.
///
/// Sums the raw relaxed-R1CS expression `Āz·B̄z − u·C̄z − Ē` over the
/// constraint-index hypercube, keeping the four MLE components separate
/// (degree-2 in each round variable).
#[derive(Debug, Clone)]
pub struct SumcheckProofDegree2<C: NovaCurve> {
    /// `claims[0]` = claimed sum; `claims[1..=num_rounds]` = evaluations
    /// at the round's random challenge.
    pub claims: Vec<ScalarField<C>>,
    /// Round polynomials `[g(0), g(1), g(2)]` (degree-2, three evaluations).
    pub polys: Vec<[ScalarField<C>; 3]>,
    /// Claimed MLE evaluations at the final random point `r`.
    /// `az_r`, `bz_r` are the MLEs of `AZ`/`BZ` at `r`; `fr_r` is the MLE of
    /// the *product* `AZ⊙BZ` at `r` (used by `verify_slim_level1` instead of
    /// `az_r·bz_r`, which is NOT the MLE-of-product).
    pub az_r: ScalarField<C>,
    pub bz_r: ScalarField<C>,
    pub fr_r: ScalarField<C>,
    pub cz_r: ScalarField<C>,
    pub er_r: ScalarField<C>,
}

/// Output of degree-2 sumcheck verification.
#[derive(Debug, Clone)]
pub struct Degree2VerifyOutput<C: NovaCurve> {
    pub ok: bool,
    pub r_challenges: Vec<ScalarField<C>>,
    pub az_r: ScalarField<C>,
    pub bz_r: ScalarField<C>,
    pub fr_r: ScalarField<C>,
    pub cz_r: ScalarField<C>,
    pub er_r: ScalarField<C>,
    pub final_claim: ScalarField<C>,
}

/// Evaluate a degree-2 polynomial given its values at `{0, 1, 2}` via
/// Lagrange interpolation.
///
/// `g(x) = c0·L0(x) + c1·L1(x) + c2·L2(x)` where `L0, L1, L2` are the
/// Lagrange basis polynomials on the nodes `{0, 1, 2}`.
pub fn eval_poly_deg2<F: PrimeField>(c0: F, c1: F, c2: F, x: F) -> F {
    let two_inv = F::from(2u64).inverse().expect("2 must have an inverse");
    let one = F::one();
    let two = one + one;
    // L0(x) = (x-1)(x-2) / 2
    let l0 = (x - one) * (x - two) * two_inv;
    // L1(x) = -x(x-2)
    let l1 = x * (x - two) * (-one);
    // L2(x) = x(x-1) / 2
    let l2 = x * (x - one) * two_inv;
    c0 * l0 + c1 * l1 + c2 * l2
}

/// Run the degree-2 sumcheck prover (sequential).
pub fn prove_degree2<C: NovaCurve>(
    l: &[Vec<(u32, ScalarField<C>)>],
    r_mat: &[Vec<(u32, ScalarField<C>)>],
    o: &[Vec<(u32, ScalarField<C>)>],
    z: &[ScalarField<C>],
    u: ScalarField<C>,
    e: &[ScalarField<C>],
) -> (SumcheckProofDegree2<C>, Vec<ScalarField<C>>) {
    prove_degree2_opts(l, r_mat, o, z, u, e, false)
}

/// Run the degree-2 sumcheck prover with optimization flags.
///
/// When `parallel` is true, per-row MLE evaluations and round sums use
/// rayon for parallel iteration.
pub fn prove_degree2_opts<C: NovaCurve>(
    l: &[Vec<(u32, ScalarField<C>)>],
    r_mat: &[Vec<(u32, ScalarField<C>)>],
    o: &[Vec<(u32, ScalarField<C>)>],
    z: &[ScalarField<C>],
    u: ScalarField<C>,
    e: &[ScalarField<C>],
    parallel: bool,
) -> (SumcheckProofDegree2<C>, Vec<ScalarField<C>>) {
    let n = l.len();
    assert_eq!(r_mat.len(), n);
    assert_eq!(o.len(), n);
    assert_eq!(e.len(), n);
    let n_padded = next_power_of_two(n);
    let num_rounds = log2ceil(n_padded);

    let zero = ScalarField::<C>::zero();
    let one = ScalarField::<C>::one();
    let two = one + one;

    if num_rounds == 0 {
        let az = eval_row_mle(&l[0], z);
        let bz = eval_row_mle(&r_mat[0], z);
        let cz = eval_row_mle(&o[0], z);
        let er = e[0];
        let fr = az * bz;
        // final_claim is the *residual* at the (empty) point: MLE(az⊙bz) − u·MLE(cz) − MLE(e).
        let final_claim = fr - u * cz - er;
        return (
            SumcheckProofDegree2 {
                claims: vec![final_claim],
                polys: vec![],
                az_r: az,
                bz_r: bz,
                cz_r: cz,
                er_r: er,
                fr_r: fr,
            },
            vec![],
        );
    }

    // Compute per-row MLEs for the four components.
    let mut az_vec: Vec<ScalarField<C>> = if parallel {
        (0..n)
            .into_par_iter()
            .map(|j| eval_row_mle(&l[j], z))
            .collect()
    } else {
        (0..n).map(|j| eval_row_mle(&l[j], z)).collect()
    };
    az_vec.resize(n_padded, zero);

    let mut bz_vec: Vec<ScalarField<C>> = if parallel {
        (0..n)
            .into_par_iter()
            .map(|j| eval_row_mle(&r_mat[j], z))
            .collect()
    } else {
        (0..n).map(|j| eval_row_mle(&r_mat[j], z)).collect()
    };
    bz_vec.resize(n_padded, zero);

    let mut cz_vec: Vec<ScalarField<C>> = if parallel {
        (0..n)
            .into_par_iter()
            .map(|j| eval_row_mle(&o[j], z))
            .collect()
    } else {
        (0..n).map(|j| eval_row_mle(&o[j], z)).collect()
    };
    cz_vec.resize(n_padded, zero);

    let mut e_vec: Vec<ScalarField<C>> = e.to_vec();
    e_vec.resize(n_padded, zero);

    // `f = az ⊙ bz` (componentwise product).  The residual vector is
    // `r = az⊙bz − u·cz − e`; its MLE is folded as a single entity so the
    // round polynomial g(2) equals MLE(r)@2.  (Sumchecking the *product* via
    // the separately-folded MLEs would make `final_claim` the product-of-MLEs,
    // which is non-zero even for honest relaxed witnesses — see level-1 bug.)
    let mut f_vec: Vec<ScalarField<C>> = az_vec
        .iter()
        .zip(bz_vec.iter())
        .map(|(a, b)| *a * *b)
        .collect();

    let mut claims = Vec::with_capacity(num_rounds + 1);
    let mut polys: Vec<[ScalarField<C>; 3]> = Vec::with_capacity(num_rounds);
    let mut r_challenges: Vec<ScalarField<C>> = Vec::with_capacity(num_rounds);

    for _round in 0..num_rounds {
        let half = az_vec.len() / 2;

        // Compute round polynomial evaluations g(0), g(1), g(2).
        let (g0, g1, g2) = if parallel {
            let (sg0, sg1, sg2) = (0..half)
                .into_par_iter()
                .fold(
                    || (zero, zero, zero),
                    |acc, j| {
                        let f_e = f_vec[2 * j];
                        let f_o = f_vec[2 * j + 1];
                        let cz_e = cz_vec[2 * j];
                        let cz_o = cz_vec[2 * j + 1];
                        let e_e = e_vec[2 * j];
                        let e_o = e_vec[2 * j + 1];

                        // g(0): X=0 → even siblings (leftmost = az_e·bz_e)
                        let gj0 = f_e - u * cz_e - e_e;
                        // g(1): X=1 → odd siblings
                        let gj1 = f_o - u * cz_o - e_o;
                        // g(2): X=2 → MLE of the *product* f at 2 (2·f_o − f_e)
                        let f_2 = two * f_o - f_e;
                        let cz_2 = two * cz_o - cz_e;
                        let er_2 = two * e_o - e_e;
                        let gj2 = f_2 - u * cz_2 - er_2;

                        (acc.0 + gj0, acc.1 + gj1, acc.2 + gj2)
                    },
                )
                .reduce(
                    || (zero, zero, zero),
                    |a, b| (a.0 + b.0, a.1 + b.1, a.2 + b.2),
                );
            (sg0, sg1, sg2)
        } else {
            let mut sg0 = zero;
            let mut sg1 = zero;
            let mut sg2 = zero;
            for j in 0..half {
                let f_e = f_vec[2 * j];
                let f_o = f_vec[2 * j + 1];
                let cz_e = cz_vec[2 * j];
                let cz_o = cz_vec[2 * j + 1];
                let e_e = e_vec[2 * j];
                let e_o = e_vec[2 * j + 1];

                sg0 += f_e - u * cz_e - e_e;
                sg1 += f_o - u * cz_o - e_o;
                let f_2 = two * f_o - f_e;
                let cz_2 = two * cz_o - cz_e;
                let er_2 = two * e_o - e_e;
                sg2 += f_2 - u * cz_2 - er_2;
            }
            (sg0, sg1, sg2)
        };

        // Claimed sum = g(0) + g(1) (sum over the sub-hypercube).
        claims.push(g0 + g1);
        polys.push([g0, g1, g2]);

        // Fiat-Shamir: hash claims[..=round] ++ [g(0), g(1), g(2)].
        let mut hash_input = claims.clone();
        for c in polys.last().unwrap() {
            hash_input.push(*c);
        }
        let h = hash_field_elements::<C>(&hash_input);
        let ri = challenge_from_hash::<C>(&h);
        r_challenges.push(ri);

        // Fold all vectors with challenge ri (MLE folding).
        let fold = |vec: &[ScalarField<C>]| -> Vec<ScalarField<C>> {
            (0..half)
                .map(|j| (one - ri) * vec[2 * j] + ri * vec[2 * j + 1])
                .collect()
        };
        az_vec = fold(&az_vec);
        bz_vec = fold(&bz_vec);
        cz_vec = fold(&cz_vec);
        e_vec = fold(&e_vec);
        f_vec = fold(&f_vec);
    }

    // Final scalar values. `fr_r` is the MLE of `az⊙bz` at the folded point r;
    // `final_claim = MLE(residual)@r = fr_r − u·cz_r − er_r` vanishes for an
    // honest relaxed witness (residual ≡ 0 componentwise ⇒ MLE(residual) ≡ 0).
    let az_f = az_vec[0];
    let bz_f = bz_vec[0];
    let cz_f = cz_vec[0];
    let er_f = e_vec[0];
    let fr_f = f_vec[0];
    let final_claim = fr_f - u * cz_f - er_f;
    claims.push(final_claim);

    (
        SumcheckProofDegree2 {
            claims,
            polys,
            az_r: az_f,
            bz_r: bz_f,
            cz_r: cz_f,
            er_r: er_f,
            fr_r: fr_f,
        },
        r_challenges,
    )
}

/// Verify a degree-2 sumcheck proof.
///
/// Checks internal consistency (round polynomial sums, Fiat-Shamir
/// challenges, final claim).  Returns the scalar evaluations
/// `az_r, bz_r, fr_r, cz_r, er_r` and the `final_claim`, where `fr_r` is the
/// MLE of the product `AZ⊙BZ` at `r`.  The caller checks
/// `fr_r − u·cz_r − er_r == final_claim` and `final_claim == 0` (residual
/// vanishes) — closing the all-zeros / "free E" gap.  Note `fr_r` is what the
/// sumcheck bounds; `az_r·bz_r` does NOT equal `fr_r` for relaxed witnesses.
pub fn verify_degree2<C: NovaCurve>(proof: &SumcheckProofDegree2<C>) -> Degree2VerifyOutput<C> {
    let zero = ScalarField::<C>::zero();
    let claimed_sum = proof.claims[0];
    let num_rounds = proof.polys.len();

    // Sanity: claims.len() == polys.len() + 1
    if proof.claims.len() != num_rounds + 1 {
        return Degree2VerifyOutput {
            ok: false,
            r_challenges: vec![],
            az_r: zero,
            bz_r: zero,
            fr_r: zero,
            cz_r: zero,
            er_r: zero,
            final_claim: zero,
        };
    }

    if num_rounds == 0 {
        return Degree2VerifyOutput {
            ok: true,
            r_challenges: vec![],
            az_r: proof.az_r,
            bz_r: proof.bz_r,
            fr_r: proof.fr_r,
            cz_r: proof.cz_r,
            er_r: proof.er_r,
            final_claim: claimed_sum,
        };
    }

    let mut current_sum = claimed_sum;
    let mut r_challenges: Vec<ScalarField<C>> = Vec::with_capacity(num_rounds);

    for round in 0..num_rounds {
        let poly = &proof.polys[round];
        let [g0, g1, g2] = *poly;

        // Check: g(0) + g(1) == current_sum.
        if g0 + g1 != current_sum {
            return Degree2VerifyOutput {
                ok: false,
                r_challenges: vec![],
                az_r: zero,
                bz_r: zero,
                fr_r: zero,
                cz_r: zero,
                er_r: zero,
                final_claim: zero,
            };
        }

        // Fiat-Shamir (must match prover).
        let mut hash_input = proof.claims[..=round].to_vec();
        for c in poly {
            hash_input.push(*c);
        }
        let h = hash_field_elements::<C>(&hash_input);
        let ri = challenge_from_hash::<C>(&h);
        r_challenges.push(ri);

        // Next claimed sum = g(r_i) via Lagrange interpolation on {0,1,2}.
        current_sum = eval_poly_deg2(g0, g1, g2, ri);
    }

    let final_claim = proof.claims[num_rounds];
    let ok = current_sum == final_claim;

    Degree2VerifyOutput {
        ok,
        r_challenges,
        az_r: proof.az_r,
        bz_r: proof.bz_r,
        fr_r: proof.fr_r,
        cz_r: proof.cz_r,
        er_r: proof.er_r,
        final_claim,
    }
}

// ────────────────────────────────────────────────────────────────────
// HashPC commitment scheme
// ────────────────────────────────────────────────────────────────────

/// Commitment to a polynomial: hash of its truth-table evaluations
/// (MLE at all Boolean hypercube points) plus a Pedersen commitment
/// to the coefficient vector.
#[derive(Debug, Clone)]
pub struct PolyCommitment<C: NovaCurve> {
    /// Hash of the truth table (BLAKE2b-512).
    pub hash: Vec<u8>,
    /// Pedersen commitment to the original coefficient vector.
    pub pedersen: C::G1Affine,
}

/// Build the truth table (MLE at all `{0,1}^k` points) for a vector.
///
/// For a multilinear extension, MLE at a Boolean point is just the value
/// at that point.  The truth table is the vector padded to the next power
/// of two.
pub fn truth_table<F: PrimeField>(v: &[F]) -> Vec<F> {
    let n = next_power_of_two(v.len());
    let mut padded = v.to_vec();
    padded.resize(n, F::zero());
    padded
}

/// Commit to a vector: hash its truth table + Pedersen commitment.
pub fn poly_commit<C: NovaCurve>(
    v: &[ScalarField<C>],
    pedersen_basis: &[C::G1Affine],
) -> (Vec<u8>, C::G1Affine) {
    let tt = truth_table(v);
    let hash: Vec<u8> = {
        let mut h = Blake2b512::new();
        for val in &tt {
            h.update(val.into_bigint().to_bytes_le());
        }
        h.finalize().to_vec()
    };
    let ped = crate::commitment::pedersen_commit::<C>(pedersen_basis, v);
    (hash, ped)
}

/// Opening proof for a HashPC commitment at a random point.
///
/// Contains the full truth table (so the verifier can reconstruct the MLE
/// and check the hash).
#[derive(Debug, Clone)]
pub struct OpeningProof<C: NovaCurve> {
    /// The truth table evaluations (full MLE table).
    pub table: Vec<ScalarField<C>>,
}

/// Create an opening proof for a vector.
pub fn create_opening<C: NovaCurve>(v: &[ScalarField<C>]) -> OpeningProof<C> {
    OpeningProof::<C> {
        table: truth_table(v),
    }
}

/// Verify an opening proof against a commitment.
///
/// Checks:
/// 1. Hash of the truth table matches the committed hash.
/// 2. `table_MLE(r) == claimed_eval`.
pub fn verify_opening<C: NovaCurve>(
    commitment_hash: &[u8],
    proof: &OpeningProof<C>,
    claimed_eval: &ScalarField<C>,
    r: &[ScalarField<C>],
) -> bool {
    // 1. Hash check.
    let actual_hash: Vec<u8> = {
        let mut h = Blake2b512::new();
        for val in &proof.table {
            h.update(val.into_bigint().to_bytes_le());
        }
        h.finalize().to_vec()
    };
    if actual_hash != commitment_hash {
        return false;
    }

    // 2. MLE evaluation check.
    let eval = eval_dense_mle(&proof.table, r);
    eval == *claimed_eval
}

/// Recompute the claimed circuit-derived MLE evaluations `az_r`, `bz_r`,
/// `cz_r`, `fr_r` at the random point `r` from the *opened* witness truth
/// table `tt_w`.
///
/// This is the circuit-backed PCS opening (the `(OP)` predicate of the
/// paper's complete verifier): the HashPC opening exposes `MLE(W)` (the
/// witness itself, padded), and the verifier re-derives `AZ = L·W`,
/// `BZ = R·W`, `CZ = O·W` and `fr = AZ ⊙ BZ` using the **public** circuit,
/// then evaluates each MLE at `r`.  Matching these against the prover's
/// claimed `az_r, bz_r, cz_r, fr_r` binds the claimed evaluations to the
/// opened witness for every wire and constraint.
///
/// `tt_w` is the opened witness truth table (`MLE(W)` with `W[0..n_wires]`
/// at the low indices, zero-padded).  `l`, `r_mat`, `o` are the public
/// sparse row representations of the circuit; `n_constraints` is the number
/// of (un-padded) constraints.  `r` is the final random challenge point
/// (length `k = log2ceil(next_power_of_two(n_constraints))`).
pub fn recompute_circuit_evals<C: NovaCurve>(
    l: &[Vec<(u32, ScalarField<C>)>],
    r_mat: &[Vec<(u32, ScalarField<C>)>],
    o: &[Vec<(u32, ScalarField<C>)>],
    tt_w: &[ScalarField<C>],
    n_constraints: usize,
    r: &[ScalarField<C>],
) -> (
    ScalarField<C>,
    ScalarField<C>,
    ScalarField<C>,
    ScalarField<C>,
) {
    let n_padded = next_power_of_two(n_constraints);
    assert_eq!(
        n_padded,
        1usize << r.len(),
        "r length must equal log2(n_padded)"
    );

    // The truth table of MLE(W) has W[0..n_wires] at its low indices; rows
    // index wires via eval_row_mle, i.e. they read tt_w[w].  Build per-row
    // MLEs AZ, BZ, CZ (zero-padded) and the componentwise product fr.
    let mut azv: Vec<ScalarField<C>> = (0..n_constraints)
        .map(|j| eval_row_mle(&l[j], tt_w))
        .collect();
    azv.resize(n_padded, ScalarField::<C>::zero());

    let mut bzv: Vec<ScalarField<C>> = (0..n_constraints)
        .map(|j| eval_row_mle(&r_mat[j], tt_w))
        .collect();
    bzv.resize(n_padded, ScalarField::<C>::zero());

    let mut czv: Vec<ScalarField<C>> = (0..n_constraints)
        .map(|j| eval_row_mle(&o[j], tt_w))
        .collect();
    czv.resize(n_padded, ScalarField::<C>::zero());

    let fv: Vec<ScalarField<C>> = azv.iter().zip(bzv.iter()).map(|(a, b)| *a * *b).collect();

    let az = eval_dense_mle(&azv, r);
    let bz = eval_dense_mle(&bzv, r);
    let cz = eval_dense_mle(&czv, r);
    let fr = eval_dense_mle(&fv, r);

    (az, bz, cz, fr)
}

/// Hash a `SumcheckProof` to produce a deterministic digest for tests.
pub fn proof_hash<C: NovaCurve>(p: &SumcheckProof<C>) -> Vec<u8> {
    let mut h = Blake2b512::new();
    for c in &p.claims {
        h.update(c.into_bigint().to_bytes_le());
    }
    for poly in &p.polys {
        for c in poly {
            h.update(c.into_bigint().to_bytes_le());
        }
    }
    h.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commitment::PedersenParams;
    use ark_bls12_381::Fr;
    use ark_ff::{One, Zero};

    /// One-constraint multiplier: Z[1]·Z[2] = Z[3], wire 0 = constant 1.
    fn simple_r1cs() -> (
        Vec<Vec<(u32, Fr)>>,
        Vec<Vec<(u32, Fr)>>,
        Vec<Vec<(u32, Fr)>>,
    ) {
        (
            vec![vec![(1u32, Fr::from(1u64))]],
            vec![vec![(2u32, Fr::from(1u64))]],
            vec![vec![(3u32, Fr::from(1u64))]],
        )
    }

    #[test]
    fn log2ceil_basic() {
        assert_eq!(log2ceil(0), 0);
        assert_eq!(log2ceil(1), 0);
        assert_eq!(log2ceil(2), 1);
        assert_eq!(log2ceil(3), 2);
        assert_eq!(log2ceil(4), 2);
        assert_eq!(log2ceil(5), 3);
        assert_eq!(log2ceil(8), 3);
        assert_eq!(log2ceil(9), 4);
    }

    #[test]
    fn next_power_of_two_basic() {
        assert_eq!(next_power_of_two(0), 1);
        assert_eq!(next_power_of_two(1), 1);
        assert_eq!(next_power_of_two(2), 2);
        assert_eq!(next_power_of_two(3), 4);
        assert_eq!(next_power_of_two(5), 8);
    }

    #[test]
    fn eval_row_mle_matches_direct() {
        let row = vec![(1u32, Fr::from(3u64)), (3u32, Fr::from(5u64))];
        let r = vec![
            Fr::from(2u64),
            Fr::from(7u64),
            Fr::from(11u64),
            Fr::from(13u64),
        ];
        // MLE = 3·r[1] + 5·r[3] = 3·7 + 5·13 = 21 + 65 = 86
        let expected = Fr::from(86u64);
        assert_eq!(eval_row_mle(&row, &r), expected);
    }

    #[test]
    fn eval_dense_mle_at_boolean_point() {
        let v = vec![
            Fr::from(10u64),
            Fr::from(20u64),
            Fr::from(30u64),
            Fr::from(40u64),
        ];
        assert_eq!(
            eval_dense_mle(&v, &[Fr::zero(), Fr::zero()]),
            Fr::from(10u64)
        );
        assert_eq!(
            eval_dense_mle(&v, &[Fr::one(), Fr::zero()]),
            Fr::from(20u64)
        );
        assert_eq!(
            eval_dense_mle(&v, &[Fr::zero(), Fr::one()]),
            Fr::from(30u64)
        );
        assert_eq!(eval_dense_mle(&v, &[Fr::one(), Fr::one()]), Fr::from(40u64));
    }

    // ── Helper: full sumcheck prove + verify for a relaxed R1CS ──────

    /// Run the full protocol: prover sends proof, verifier checks sumcheck
    /// then checks `final_claim == 0` (the relaxed R1CS equation must hold
    /// at the random point `r`; by Schwartz–Zippel, `P(r) = 0` at a random
    /// `r` implies `P ≡ 0`, i.e. all per-constraint products are zero).
    fn full_protocol(
        l: &[Vec<(u32, Fr)>],
        r_mat: &[Vec<(u32, Fr)>],
        o: &[Vec<(u32, Fr)>],
        z: &[Fr],
        u: Fr,
        e: &[Fr],
    ) -> bool {
        let n = l.len();

        // Prover side.
        let (proof, r_challenges) = prove::<crate::curve::Bls12_381>(l, r_mat, o, z, u, e);

        // Verifier side: check sumcheck.
        let (sc_ok, verifier_r, final_claim) = verify::<crate::curve::Bls12_381>(&proof);
        if !sc_ok {
            return false;
        }
        assert_eq!(
            r_challenges, verifier_r,
            "Fiat-Shamir challenges must match"
        );

        // Additionally, verify the product evaluations at r are consistent.
        // Build the products vector and evaluate its MLE at r.
        let n_padded = next_power_of_two(n);
        let products: Vec<Fr> = (0..n)
            .map(|j| {
                let az = eval_row_mle(&l[j], z);
                let bz = eval_row_mle(&r_mat[j], z);
                let cz = eval_row_mle(&o[j], z);
                az * bz - u * cz - e[j]
            })
            .collect();
        let mut products_padded = products;
        products_padded.resize(n_padded, Fr::zero());

        let k = log2ceil(n_padded);
        if k == 0 {
            // Single constraint: products_padded = [p0], r is empty.
            // products_MLE(()) = p0. Check it matches final_claim.
            return products_padded[0] == final_claim && final_claim.is_zero();
        }

        let products_at_r = eval_dense_mle(&products_padded, &verifier_r);
        products_at_r == final_claim && final_claim.is_zero()
    }

    #[test]
    fn sumcheck_satisfying_witness() {
        let (l, r, o) = simple_r1cs();
        let z = vec![
            Fr::from(1u64),
            Fr::from(3u64),
            Fr::from(5u64),
            Fr::from(15u64),
        ];
        let u = Fr::from(1u64);
        let e = vec![Fr::zero()];
        assert!(full_protocol(&l, &r, &o, &z, u, &e));
    }

    #[test]
    fn sumcheck_unsatisfying_witness_fails() {
        let (l, r, o) = simple_r1cs();
        // 3·5 = 15 but z[3] = 20 → product = 15 - 20 = -5 ≠ 0
        let z = vec![
            Fr::from(1u64),
            Fr::from(3u64),
            Fr::from(5u64),
            Fr::from(20u64),
        ];
        let u = Fr::from(1u64);
        let e = vec![Fr::zero()];
        assert!(!full_protocol(&l, &r, &o, &z, u, &e));
    }

    #[test]
    fn sumcheck_with_nonzero_error() {
        let (l, r, o) = simple_r1cs();
        // 3·5 = 15, u = 0, e = 15 → 15 = 0 + 15 ✓
        let z = vec![
            Fr::from(1u64),
            Fr::from(3u64),
            Fr::from(5u64),
            Fr::from(15u64),
        ];
        let u = Fr::from(0u64);
        let e = vec![Fr::from(15u64)];
        assert!(full_protocol(&l, &r, &o, &z, u, &e));
    }

    #[test]
    fn sumcheck_with_folded_slack() {
        let (l, r, o) = simple_r1cs();
        // 3·5 = 15, u = 2, e = -15 → 15 = 2·15 + (-15) ✓
        let z = vec![
            Fr::from(1u64),
            Fr::from(3u64),
            Fr::from(5u64),
            Fr::from(15u64),
        ];
        let u = Fr::from(2u64);
        let e = vec![Fr::from(-15i64)];
        assert!(full_protocol(&l, &r, &o, &z, u, &e));
    }

    #[test]
    fn sumcheck_two_constraints() {
        // Two independent multipliers: w[1]*w[2]=w[3], w[4]*w[5]=w[6]
        let l = vec![vec![(1u32, Fr::from(1u64))], vec![(4u32, Fr::from(1u64))]];
        let r = vec![vec![(2u32, Fr::from(1u64))], vec![(5u32, Fr::from(1u64))]];
        let o = vec![vec![(3u32, Fr::from(1u64))], vec![(6u32, Fr::from(1u64))]];
        let z = vec![
            Fr::from(1u64),
            Fr::from(3u64),
            Fr::from(5u64),
            Fr::from(15u64),
            Fr::from(7u64),
            Fr::from(11u64),
            Fr::from(77u64),
        ];
        let u = Fr::from(1u64);
        let e = vec![Fr::zero(); 2];
        assert!(full_protocol(&l, &r, &o, &z, u, &e));
    }

    #[test]
    fn sumcheck_four_constraints() {
        // Four multipliers: w[1+3i]*w[2+3i]=w[3+3i] for i=0..3
        let k = 4;
        let n_wires = 1 + 3 * k;
        let mut l = Vec::new();
        let mut r = Vec::new();
        let mut o = Vec::new();
        for i in 0..k {
            l.push(vec![((1 + 3 * i) as u32, Fr::from(1u64))]);
            r.push(vec![((2 + 3 * i) as u32, Fr::from(1u64))]);
            o.push(vec![((3 + 3 * i) as u32, Fr::from(1u64))]);
        }
        let mut z = vec![Fr::from(1u64)]; // wire 0 = constant
        for i in 0..k {
            let a = Fr::from((i + 2) as u64);
            let b = Fr::from((i + 3) as u64);
            z.push(a);
            z.push(b);
            z.push(a * b);
        }
        assert_eq!(z.len(), n_wires);
        let u = Fr::from(1u64);
        let e = vec![Fr::zero(); k];
        assert!(full_protocol(&l, &r, &o, &z, u, &e));
    }

    /// Golden test: 1-constraint multiplier (3 × 5 = 15).
    ///
    /// This is a regression snapshot.  If any change to the sumcheck prover
    /// or Fiat-Shamir hash modifies the proof, this test will break — which
    /// forces a deliberate review of the change.
    #[test]
    fn golden_single_multiplier_3x5() {
        let (l, r_mat, o) = simple_r1cs();
        let z = vec![
            Fr::from(1u64),  // constant
            Fr::from(3u64),  // wire 1
            Fr::from(5u64),  // wire 2
            Fr::from(15u64), // wire 3 = 3×5
        ];
        let u = Fr::from(1u64);
        let e = vec![Fr::zero()];

        let (proof, r_challenges) = prove::<crate::curve::Bls12_381>(&l, &r_mat, &o, &z, u, &e);

        // 1 constraint → 0 sumcheck rounds (trivial case).
        assert_eq!(proof.polys.len(), 0, "1-constraint must have 0 rounds");
        assert!(
            r_challenges.is_empty(),
            "no Fiat-Shamir challenges for 0 rounds"
        );

        // The single claimed product is az*bz - u*cz - e = 3*5 - 1*15 - 0 = 0.
        assert_eq!(proof.claims.len(), 1);
        assert_eq!(
            proof.claims[0],
            Fr::zero(),
            "product must be zero for satisfied constraint"
        );

        // Verify passes.
        let (ok, v_r, final_claim) = verify::<crate::curve::Bls12_381>(&proof);
        assert!(ok, "sumcheck verification must pass");
        assert!(v_r.is_empty());
        assert_eq!(final_claim, Fr::zero());

        // Golden snapshot: the proof hash must match.
        let golden_hash = "9ab7a73a97a1a3031406b6c169634a9c06cfb81dec3323bb4de5ce6f4b7ca107de534442a7eaeafbaf366ccfdde1cb97d7c884e4344cd0a23039de71a56d630a";
        let h = hex::encode(proof_hash::<crate::curve::Bls12_381>(&proof));
        assert_eq!(
            h, golden_hash,
            "golden hash mismatch — proof has changed since this snapshot was recorded"
        );

        // Structural golden checks.
        assert_eq!(proof.claims.len(), 1);
        assert_eq!(proof.polys.len(), 0);
    }

    /// Golden test: 2-constraint circuit (3×5 + 7×11).
    ///
    /// This exercises the sumcheck with exactly 1 round (2 constraints →
    /// padded to 2 → log2ceil(2) = 1 round).
    #[test]
    fn golden_two_constraints_3x5_7x11() {
        let l = vec![vec![(1u32, Fr::from(1u64))], vec![(4u32, Fr::from(1u64))]];
        let r_mat = vec![vec![(2u32, Fr::from(1u64))], vec![(5u32, Fr::from(1u64))]];
        let o = vec![vec![(3u32, Fr::from(1u64))], vec![(6u32, Fr::from(1u64))]];
        let z = vec![
            Fr::from(1u64),
            Fr::from(3u64),
            Fr::from(5u64),
            Fr::from(15u64),
            Fr::from(7u64),
            Fr::from(11u64),
            Fr::from(77u64),
        ];
        let u = Fr::from(1u64);
        let e = vec![Fr::zero(); 2];

        let (proof, r_challenges) = prove::<crate::curve::Bls12_381>(&l, &r_mat, &o, &z, u, &e);

        // 2 constraints → 1 round.
        assert_eq!(proof.polys.len(), 1, "2-constraint must have 1 round");
        assert_eq!(r_challenges.len(), 1);

        // Both products are zero (3×5=15 and 7×11=77).
        assert_eq!(proof.claims.len(), 2, "2 constraints → 2 initial claims");
        assert_eq!(proof.claims[0], Fr::zero());
        assert_eq!(proof.claims[1], Fr::zero());

        // Verify passes.
        let (ok, v_r, final_claim) = verify::<crate::curve::Bls12_381>(&proof);
        assert!(ok);
        assert_eq!(v_r.len(), 1);
        assert_eq!(final_claim, Fr::zero());

        // Golden snapshot.
        let golden_hash = "865939e120e6805438478841afb739ae4250cf372653078a065cdcfffca4caf798e6d462b65d658fc165782640eded70963449ae1500fb0f24981d7727e22c41";
        let h = hex::encode(proof_hash::<crate::curve::Bls12_381>(&proof));
        assert_eq!(
            h, golden_hash,
            "golden hash mismatch — proof has changed since this snapshot was recorded"
        );

        // Round polynomial structure: f(0) + f(1) = 0.
        let poly = &proof.polys[0];
        assert_eq!(poly.len(), 2);
        assert_eq!(
            poly[0] + poly[1],
            Fr::zero(),
            "f(0)+f(1) must equal the claimed sum (0)"
        );
    }

    /// Golden test: HashPC commitment for a known vector.
    #[test]
    fn golden_hashpc_commitment() {
        use crate::commitment::PedersenParams;
        let v = vec![
            Fr::from(10u64),
            Fr::from(20u64),
            Fr::from(30u64),
            Fr::from(40u64),
        ];
        let params = PedersenParams::<crate::curve::Bls12_381>::from_seed(b"golden-test", 4, 1);
        let (hash, _point) = poly_commit::<crate::curve::Bls12_381>(&v, &params.basis_w);

        // BLAKE2b-512 truth-table hash of [10,20,30,40].
        let golden_hash_hex = "98ffc304e408f37324d82098fd13b60d603a4428c1113a45d748e4737ae90f43ada23f608676b3ab02ed2a3b0d7b8da7c010f37f57e825f8ef8734df1bf69174";
        assert_eq!(
            hex::encode(&hash),
            golden_hash_hex,
            "HashPC commitment hash mismatch"
        );

        // Opening proof.
        let opening = create_opening::<crate::curve::Bls12_381>(&v);
        assert_eq!(
            opening.table, v,
            "opening truth table must equal the vector"
        );

        // Verify opening.
        let r = vec![Fr::from(3u64), Fr::from(7u64)];
        let claimed = eval_dense_mle(&v, &r);
        assert!(verify_opening::<crate::curve::Bls12_381>(
            &hash, &opening, &claimed, &r
        ));
    }

    #[test]
    fn proof_deterministic_for_same_witness() {
        let (l, r, o) = simple_r1cs();
        let z = vec![
            Fr::from(1u64),
            Fr::from(3u64),
            Fr::from(5u64),
            Fr::from(15u64),
        ];
        let u = Fr::from(1u64);
        let e = vec![Fr::zero()];

        let (p1, _) = prove::<crate::curve::Bls12_381>(&l, &r, &o, &z, u, &e);
        let (p2, _) = prove::<crate::curve::Bls12_381>(&l, &r, &o, &z, u, &e);
        assert_eq!(
            proof_hash::<crate::curve::Bls12_381>(&p1),
            proof_hash::<crate::curve::Bls12_381>(&p2)
        );
    }

    #[test]
    fn proof_size_grows_logarithmically() {
        // 1 constraint → 0 rounds, 2 → 1 round, 4 → 2 rounds
        let make_k = |k: usize| {
            let mut l = Vec::new();
            let mut r = Vec::new();
            let mut o = Vec::new();
            for i in 0..k {
                l.push(vec![((1 + 3 * i) as u32, Fr::from(1u64))]);
                r.push(vec![((2 + 3 * i) as u32, Fr::from(1u64))]);
                o.push(vec![((3 + 3 * i) as u32, Fr::from(1u64))]);
            }
            let mut z = vec![Fr::from(1u64)];
            for i in 0..k {
                z.push(Fr::from((i + 2) as u64));
                z.push(Fr::from((i + 3) as u64));
                z.push(Fr::from(((i + 2) * (i + 3)) as u64));
            }
            let e = vec![Fr::zero(); k];
            let (proof, _) = prove::<crate::curve::Bls12_381>(&l, &r, &o, &z, Fr::from(1u64), &e);
            proof
        };

        let p1 = make_k(1);
        let p2 = make_k(2);
        let p4 = make_k(4);
        let p8 = make_k(8);

        assert_eq!(p1.polys.len(), 0); // 0 rounds
        assert_eq!(p2.polys.len(), 1); // 1 round
        assert_eq!(p4.polys.len(), 2); // 2 rounds
        assert_eq!(p8.polys.len(), 3); // 3 rounds
    }

    // ── HashPC tests ────────────────────────────────────────────────

    #[test]
    fn hashpc_commit_deterministic() {
        let v = vec![
            Fr::from(1u64),
            Fr::from(2u64),
            Fr::from(3u64),
            Fr::from(4u64),
        ];
        let params = PedersenParams::<crate::curve::Bls12_381>::from_seed(b"test", 4, 1);
        let (h1, p1) = poly_commit::<crate::curve::Bls12_381>(&v, &params.basis_w);
        let (h2, p2) = poly_commit::<crate::curve::Bls12_381>(&v, &params.basis_w);
        assert_eq!(h1, h2);
        assert_eq!(p1, p2);
    }

    #[test]
    fn hashpc_opening_verifies() {
        let v = vec![
            Fr::from(10u64),
            Fr::from(20u64),
            Fr::from(30u64),
            Fr::from(40u64),
        ];
        let params = PedersenParams::<crate::curve::Bls12_381>::from_seed(b"test", 4, 1);
        let (hash, _) = poly_commit::<crate::curve::Bls12_381>(&v, &params.basis_w);

        let proof = create_opening::<crate::curve::Bls12_381>(&v);
        let r = vec![Fr::from(7u64), Fr::from(11u64)];
        let claimed = eval_dense_mle(&v, &r);

        assert!(verify_opening::<crate::curve::Bls12_381>(
            &hash, &proof, &claimed, &r
        ));
    }

    #[test]
    fn hashpc_opening_rejects_tampered() {
        let v = vec![
            Fr::from(10u64),
            Fr::from(20u64),
            Fr::from(30u64),
            Fr::from(40u64),
        ];
        let params = PedersenParams::<crate::curve::Bls12_381>::from_seed(b"test", 4, 1);
        let (hash, _) = poly_commit::<crate::curve::Bls12_381>(&v, &params.basis_w);

        let mut proof = create_opening::<crate::curve::Bls12_381>(&v);
        proof.table[0] += Fr::from(1u64);

        let r = vec![Fr::from(7u64), Fr::from(11u64)];
        let claimed = eval_dense_mle(&v, &r);

        assert!(!verify_opening::<crate::curve::Bls12_381>(
            &hash, &proof, &claimed, &r
        ));
    }

    #[test]
    fn hashpc_opening_rejects_wrong_eval() {
        let v = vec![
            Fr::from(10u64),
            Fr::from(20u64),
            Fr::from(30u64),
            Fr::from(40u64),
        ];
        let params = PedersenParams::<crate::curve::Bls12_381>::from_seed(b"test", 4, 1);
        let (hash, _) = poly_commit::<crate::curve::Bls12_381>(&v, &params.basis_w);

        let proof = create_opening::<crate::curve::Bls12_381>(&v);
        let r = vec![Fr::from(7u64), Fr::from(11u64)];
        let wrong_eval = Fr::from(999u64);

        assert!(!verify_opening::<crate::curve::Bls12_381>(
            &hash,
            &proof,
            &wrong_eval,
            &r
        ));
    }

    // ── HashPC boundary / edge cases ────────────────────────────────

    #[test]
    fn hashpc_empty_vector() {
        let params = PedersenParams::<crate::curve::Bls12_381>::from_seed(b"empty", 0, 0);
        let v: Vec<Fr> = vec![];
        let (hash, pt) = poly_commit::<crate::curve::Bls12_381>(&v, &params.basis_w);
        assert_eq!(
            hash,
            poly_commit::<crate::curve::Bls12_381>(&v, &params.basis_w).0
        );
        assert_eq!(pt, ark_bls12_381::G1Affine::identity());
    }

    #[test]
    fn hashpc_single_element() {
        let v = vec![Fr::from(42u64)];
        let params = PedersenParams::<crate::curve::Bls12_381>::from_seed(b"single", 1, 1);
        let (hash, _) = poly_commit::<crate::curve::Bls12_381>(&v, &params.basis_w);
        let opening = create_opening::<crate::curve::Bls12_381>(&v);
        let r: Vec<Fr> = vec![];
        assert!(verify_opening::<crate::curve::Bls12_381>(
            &hash,
            &opening,
            &Fr::from(42u64),
            &r
        ));
    }

    #[test]
    fn hashpc_opening_rejects_tampered_hash() {
        let v = vec![
            Fr::from(10u64),
            Fr::from(20u64),
            Fr::from(30u64),
            Fr::from(40u64),
        ];
        let params = PedersenParams::<crate::curve::Bls12_381>::from_seed(b"tamper-hash", 4, 1);
        let (hash, _) = poly_commit::<crate::curve::Bls12_381>(&v, &params.basis_w);
        let mut opening = create_opening::<crate::curve::Bls12_381>(&v);
        opening.table[0] += Fr::from(1u64);
        let r = vec![Fr::from(7u64), Fr::from(11u64)];
        let claimed = eval_dense_mle(&v, &r);
        assert!(!verify_opening::<crate::curve::Bls12_381>(
            &hash, &opening, &claimed, &r
        ));
    }

    #[test]
    fn eval_dense_mle_rejects_mismatched_r_length() {
        // table length 4 -> k=2, so r must have length 2.
        let v = vec![
            Fr::from(10u64),
            Fr::from(20u64),
            Fr::from(30u64),
            Fr::from(40u64),
        ];
        let r_ok = vec![Fr::from(1u64), Fr::from(2u64)];
        let _ = eval_dense_mle(&v, &r_ok);
        // r with 3 bits should panic (assertion in eval_dense_mle).
        let r_bad = vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
        let result = std::panic::catch_unwind(|| eval_dense_mle(&v, &r_bad));
        assert!(result.is_err());
    }

    #[test]
    fn sumcheck_zero_constraints_trivial_case() {
        // 1 constraint -> 0 rounds, already golden-tested; this is an explicit
        // boundary reminder that 1 constraint is the minimum.
        let (l, r_mat, o) = simple_r1cs();
        let z = vec![
            Fr::from(1u64),
            Fr::from(3u64),
            Fr::from(5u64),
            Fr::from(15u64),
        ];
        let (proof, r_challenges) =
            prove::<crate::curve::Bls12_381>(&l, &r_mat, &o, &z, Fr::from(1u64), &[Fr::zero()]);
        assert_eq!(proof.polys.len(), 0);
        assert!(r_challenges.is_empty());
        let (ok, _, final_claim) = verify::<crate::curve::Bls12_381>(&proof);
        assert!(ok);
        assert_eq!(final_claim, Fr::zero());
    }

    // ── Degree-2 sumcheck tests ────────────────────────────────────

    /// Degree-2 sumcheck final claim matches degree-1 for a satisfying witness.
    ///
    /// Both sumcheck protocols prove the same equation; for a satisfying
    /// witness, both final claims must be zero (the R1CS equation holds
    /// at any random point).
    #[test]
    fn degree2_matches_degree1_final_claim() {
        let k = 4;
        let n_wires = 1 + 3 * k;
        let mut l = Vec::new();
        let mut r_mat = Vec::new();
        let mut o = Vec::new();
        for i in 0..k {
            l.push(vec![((1 + 3 * i) as u32, Fr::from(1u64))]);
            r_mat.push(vec![((2 + 3 * i) as u32, Fr::from(1u64))]);
            o.push(vec![((3 + 3 * i) as u32, Fr::from(1u64))]);
        }
        let mut z = vec![Fr::from(1u64)];
        for i in 0..k {
            let a = Fr::from((i + 2) as u64);
            let b = Fr::from((i + 3) as u64);
            z.push(a);
            z.push(b);
            z.push(a * b);
        }
        assert_eq!(z.len(), n_wires);
        let u = Fr::from(1u64);
        let e = vec![Fr::zero(); k];

        // Degree-1
        let (proof1, _r1) = prove::<crate::curve::Bls12_381>(&l, &r_mat, &o, &z, u, &e);
        let (ok1, _, final1) = verify::<crate::curve::Bls12_381>(&proof1);
        assert!(ok1, "degree-1 sumcheck must pass");
        assert!(
            final1.is_zero(),
            "degree-1 final claim must be zero for satisfying witness"
        );

        // Degree-2
        let (proof2, _r2) = prove_degree2::<crate::curve::Bls12_381>(&l, &r_mat, &o, &z, u, &e);
        let out2 = verify_degree2::<crate::curve::Bls12_381>(&proof2);
        assert!(out2.ok, "degree-2 sumcheck must pass");

        // Both have the same number of rounds.
        assert_eq!(proof1.polys.len(), proof2.polys.len());

        // The degree-2 final claim equals the residual MLE at r:
        //   final_claim == fr_r − u·cz_r − er_r == MLE(residual)@r.
        assert_eq!(
            out2.fr_r - u * out2.cz_r - out2.er_r,
            out2.final_claim,
            "degree-2 final claim must equal fr_r - u*cz_r - er_r"
        );

        // For this perfectly-satisfied (`u=1, e=0`) witness the residual is
        // identically zero, so the level-1 final claim vanishes.
        assert!(
            out2.final_claim.is_zero(),
            "degree-2 final claim must be zero for satisfying witness"
        );

        // Both expose the same claimed initial sum: Σ_j P_j = 0.
        assert_eq!(proof1.claims[0], proof2.claims[0]);
    }

    /// REGRESSION (level-1): an *honest relaxed* witness (`u != 1`, `e != 0`)
    /// with componentwise residual exactly zero must yield a zero level-1
    /// final claim.  The old degree-2 sumcheck folded `AZ`/`BZ` separately and
    /// set the final claim to `az_r·bz_r − u·cz_r − er_r`, which is non-zero
    /// for relaxed witnesses and wrongly rejected every honest fold.
    #[test]
    fn degree2_relaxed_honest_final_claim_zero() {
        let k = 4;
        let n_wires = 1 + 3 * k;
        let mut l = Vec::new();
        let mut r_mat = Vec::new();
        let mut o = Vec::new();
        for i in 0..k {
            l.push(vec![((1 + 3 * i) as u32, Fr::from(1u64))]);
            r_mat.push(vec![((2 + 3 * i) as u32, Fr::from(1u64))]);
            o.push(vec![((3 + 3 * i) as u32, Fr::from(1u64))]);
        }
        let mut z = vec![Fr::from(1u64)];
        for i in 0..k {
            let a = Fr::from((i + 2) as u64);
            let b = Fr::from((i + 3) as u64);
            z.push(a);
            z.push(b);
            z.push(a * b);
        }
        // Relaxed: u != 1, e set so the componentwise residual is exactly zero.
        let u = Fr::from(2u64);
        let mut e = Vec::new();
        for i in 0..k {
            let az = Fr::from((i + 2) as u64);
            let bz = Fr::from((i + 3) as u64);
            let cz = az * bz;
            e.push(az * bz - u * cz);
        }

        let (proof2, _r2) = prove_degree2::<crate::curve::Bls12_381>(&l, &r_mat, &o, &z, u, &e);
        let out2 = verify_degree2::<crate::curve::Bls12_381>(&proof2);
        assert!(
            out2.ok,
            "degree-2 sumcheck must pass for honest relaxed witness"
        );
        // MLE-of-product sumcheck: level-1 equation + residual vanishes.
        assert_eq!(out2.final_claim, out2.fr_r - u * out2.cz_r - out2.er_r);
        assert!(
            out2.final_claim.is_zero(),
            "level-1 final claim must be zero for an honest relaxed witness"
        );
    }

    /// Degree-2 sumcheck rejects a tampered proof.
    #[test]
    fn degree2_rejects_bad() {
        let k = 4;
        let n_wires = 1 + 3 * k;
        let mut l = Vec::new();
        let mut r_mat = Vec::new();
        let mut o = Vec::new();
        for i in 0..k {
            l.push(vec![((1 + 3 * i) as u32, Fr::from(1u64))]);
            r_mat.push(vec![((2 + 3 * i) as u32, Fr::from(1u64))]);
            o.push(vec![((3 + 3 * i) as u32, Fr::from(1u64))]);
        }
        let mut z = vec![Fr::from(1u64)];
        for i in 0..k {
            let a = Fr::from((i + 2) as u64);
            let b = Fr::from((i + 3) as u64);
            z.push(a);
            z.push(b);
            z.push(a * b);
        }
        let u = Fr::from(1u64);
        let e = vec![Fr::zero(); k];

        let (proof, _) = prove_degree2::<crate::curve::Bls12_381>(&l, &r_mat, &o, &z, u, &e);

        // Tamper initial claim.
        let mut bad = proof.clone();
        bad.claims[0] += Fr::from(42u64);
        let out = verify_degree2::<crate::curve::Bls12_381>(&bad);
        assert!(!out.ok, "tampered initial claim must be rejected");

        // Tamper a poly coefficient.
        let mut bad = proof.clone();
        if !bad.polys.is_empty() {
            bad.polys[0][0] += Fr::from(1u64);
            let out = verify_degree2::<crate::curve::Bls12_381>(&bad);
            assert!(!out.ok, "tampered poly coefficient must be rejected");
        }
    }

    /// Degree-2 sumcheck handles the single-constraint edge case (k=0).
    #[test]
    fn degree2_single_constraint() {
        let (l, r_mat, o) = simple_r1cs();
        let z = vec![
            Fr::from(1u64),
            Fr::from(3u64),
            Fr::from(5u64),
            Fr::from(15u64),
        ];
        let u = Fr::from(1u64);
        let e = vec![Fr::zero()];

        let (proof, r_challenges) =
            prove_degree2::<crate::curve::Bls12_381>(&l, &r_mat, &o, &z, u, &e);
        assert!(proof.polys.is_empty(), "1 constraint must have 0 rounds");
        assert!(r_challenges.is_empty());

        let out = verify_degree2::<crate::curve::Bls12_381>(&proof);
        assert!(out.ok);
        assert!(out.r_challenges.is_empty());
        assert_eq!(out.az_r, Fr::from(3u64));
        assert_eq!(out.bz_r, Fr::from(5u64));
        assert_eq!(out.cz_r, Fr::from(15u64));
        assert_eq!(out.er_r, Fr::zero());
        assert_eq!(out.fr_r, out.az_r * out.bz_r);
        assert_eq!(out.final_claim, out.fr_r - u * out.cz_r - out.er_r);
        assert!(out.final_claim.is_zero());
    }

    /// Degree-2 sumcheck with two constraints (1 round).
    #[test]
    fn degree2_two_constraints() {
        let l = vec![vec![(1u32, Fr::from(1u64))], vec![(4u32, Fr::from(1u64))]];
        let r_mat = vec![vec![(2u32, Fr::from(1u64))], vec![(5u32, Fr::from(1u64))]];
        let o = vec![vec![(3u32, Fr::from(1u64))], vec![(6u32, Fr::from(1u64))]];
        let z = vec![
            Fr::from(1u64),
            Fr::from(3u64),
            Fr::from(5u64),
            Fr::from(15u64),
            Fr::from(7u64),
            Fr::from(11u64),
            Fr::from(77u64),
        ];
        let u = Fr::from(1u64);
        let e = vec![Fr::zero(); 2];

        let (proof, r_challenges) =
            prove_degree2::<crate::curve::Bls12_381>(&l, &r_mat, &o, &z, u, &e);
        assert_eq!(proof.polys.len(), 1, "2 constraints → 1 round");
        assert_eq!(r_challenges.len(), 1);

        let out = verify_degree2::<crate::curve::Bls12_381>(&proof);
        assert!(out.ok);
        // The degree-2 final claim equals fr_r - u*cz_r - er_r (level-1).
        assert_eq!(out.final_claim, out.fr_r - u * out.cz_r - out.er_r);
        assert!(out.final_claim.is_zero());
    }

    /// Parallel degree-2 prover produces the same result as sequential.
    #[test]
    fn degree2_parallel_matches_sequential() {
        let k = 4;
        let n_wires = 1 + 3 * k;
        let mut l = Vec::new();
        let mut r_mat = Vec::new();
        let mut o = Vec::new();
        for i in 0..k {
            l.push(vec![((1 + 3 * i) as u32, Fr::from(1u64))]);
            r_mat.push(vec![((2 + 3 * i) as u32, Fr::from(1u64))]);
            o.push(vec![((3 + 3 * i) as u32, Fr::from(1u64))]);
        }
        let mut z = vec![Fr::from(1u64)];
        for i in 0..k {
            let a = Fr::from((i + 2) as u64);
            let b = Fr::from((i + 3) as u64);
            z.push(a);
            z.push(b);
            z.push(a * b);
        }
        let u = Fr::from(1u64);
        let e = vec![Fr::zero(); k];

        let (seq_proof, seq_r) =
            prove_degree2_opts::<crate::curve::Bls12_381>(&l, &r_mat, &o, &z, u, &e, false);
        let (par_proof, par_r) =
            prove_degree2_opts::<crate::curve::Bls12_381>(&l, &r_mat, &o, &z, u, &e, true);

        // Both must verify.
        let out_seq = verify_degree2::<crate::curve::Bls12_381>(&seq_proof);
        let out_par = verify_degree2::<crate::curve::Bls12_381>(&par_proof);
        assert!(out_seq.ok, "sequential degree-2 proof must verify");
        assert!(out_par.ok, "parallel degree-2 proof must verify");

        // Fiat-Shamir challenges must match.
        assert_eq!(seq_r, par_r);
        assert_eq!(out_seq.r_challenges, out_par.r_challenges);

        // Final claims must match.
        assert_eq!(out_seq.final_claim, out_par.final_claim);
    }

    /// eval_poly_deg2 correctness: evaluates to the correct values at 0, 1, 2.
    #[test]
    fn eval_poly_deg2_basic() {
        let c0 = Fr::from(10u64);
        let c1 = Fr::from(20u64);
        let c2 = Fr::from(30u64);
        assert_eq!(eval_poly_deg2(c0, c1, c2, Fr::from(0u64)), c0);
        assert_eq!(eval_poly_deg2(c0, c1, c2, Fr::from(1u64)), c1);
        assert_eq!(eval_poly_deg2(c0, c1, c2, Fr::from(2u64)), c2);
    }
}

// ── Property-based tests (proptest) ────────────────────────────────

#[cfg(test)]
mod proptests {
    use super::*;
    use crate::commitment::PedersenParams;
    use ark_bls12_381::Fr;
    use proptest::prelude::*;

    fn arb_fr() -> impl Strategy<Value = Fr> {
        any::<u64>().prop_map(Fr::from)
    }

    proptest! {
        /// Property: for k independent multipliers with random witness values,
        /// if we compute E correctly, the sumcheck prover+verifier always accepts.
        #[test]
        fn prop_sumcheck_satisfying_witness_accepted(
            a1 in 1u64..1000,
            b1 in 1u64..1000,
            a2 in 1u64..1000,
            b2 in 1u64..1000,
        ) {
            // Two multipliers: w[1]*w[2]=w[3], w[4]*w[5]=w[6]
            let l = vec![
                vec![(1u32, Fr::from(1u64))],
                vec![(4u32, Fr::from(1u64))],
            ];
            let r_mat = vec![
                vec![(2u32, Fr::from(1u64))],
                vec![(5u32, Fr::from(1u64))],
            ];
            let o = vec![
                vec![(3u32, Fr::from(1u64))],
                vec![(6u32, Fr::from(1u64))],
            ];
            let z = vec![
                Fr::from(1u64),
                Fr::from(a1),
                Fr::from(b1),
                Fr::from(a1) * Fr::from(b1),
                Fr::from(a2),
                Fr::from(b2),
                Fr::from(a2) * Fr::from(b2),
            ];
            let u = Fr::from(1u64);
            let e = vec![Fr::zero(); 2];

            let (proof, r_challenges) = prove::<crate::curve::Bls12_381>(&l, &r_mat, &o, &z, u, &e);
            let (ok, v_r, final_claim) = verify::<crate::curve::Bls12_381>(&proof);
            prop_assert!(ok, "sumcheck verifier rejected for satisfying witness");
            prop_assert_eq!(&v_r, &r_challenges);

            let products: Vec<Fr> = (0..2).map(|j| {
                let az = eval_row_mle(&l[j], &z);
                let bz = eval_row_mle(&r_mat[j], &z);
                let cz = eval_row_mle(&o[j], &z);
                az * bz - u * cz - e[j]
            }).collect();
            let mut products_padded = products;
            products_padded.resize(next_power_of_two(2), Fr::zero());
            let expected_at_r = if v_r.is_empty() {
                products_padded[0]
            } else {
                eval_dense_mle(&products_padded, &v_r)
            };
            prop_assert_eq!(final_claim, expected_at_r);
        }

        /// Property: for a single multiplier with random witness,
        /// u=1, e=0, the sumcheck roundtrip always succeeds.
        #[test]
        fn prop_sumcheck_single_multiplier(
            a in 1u64..10000,
            b in 1u64..10000,
        ) {
            let l = vec![vec![(1u32, Fr::from(1u64))]];
            let r_mat = vec![vec![(2u32, Fr::from(1u64))]];
            let o = vec![vec![(3u32, Fr::from(1u64))]];
            let z = vec![
                Fr::from(1u64),
                Fr::from(a),
                Fr::from(b),
                Fr::from(a) * Fr::from(b),
            ];
            let u = Fr::from(1u64);
            let e = vec![Fr::zero()];

            let (proof, _) = prove::<crate::curve::Bls12_381>(&l, &r_mat, &o, &z, u, &e);
            let (ok, _, _) = verify::<crate::curve::Bls12_381>(&proof);
            prop_assert!(ok);
        }

        /// Property: with random nonzero error, the prover+verifier roundtrip
        /// still accepts (error absorbs the slack).
        #[test]
        fn prop_sumcheck_with_arbitrary_error(
            a in 1u64..500,
            b in 1u64..500,
            u_val in 1u64..10,
            _e_val in 0u64..500,
        ) {
            let l = vec![vec![(1u32, Fr::from(1u64))]];
            let r_mat = vec![vec![(2u32, Fr::from(1u64))]];
            let o = vec![vec![(3u32, Fr::from(1u64))]];
            let az = Fr::from(a);
            let bz = Fr::from(b);
            let cz = az * bz;
            // E = az*bz - u*cz => the equation (AZ)∘(BZ) = u·(CZ) + E holds by construction
            let e_actual = az * bz - Fr::from(u_val) * cz;
            let z = vec![
                Fr::from(1u64),
                az,
                bz,
                cz,
            ];
            let e = vec![e_actual];

            let (proof, _) = prove::<crate::curve::Bls12_381>(&l, &r_mat, &o, &z, Fr::from(u_val), &e);
            let (ok, _, _) = verify::<crate::curve::Bls12_381>(&proof);
            prop_assert!(ok);
        }

        /// Property: tampered sumcheck proof is always rejected.
        #[test]
        fn prop_sumcheck_tamper_rejects(
            a1 in 1u64..500,
            b1 in 1u64..500,
            a2 in 1u64..500,
            b2 in 1u64..500,
            flip_val in 1u64..1000,
        ) {
            let l = vec![
                vec![(1u32, Fr::from(1u64))],
                vec![(4u32, Fr::from(1u64))],
            ];
            let r_mat = vec![
                vec![(2u32, Fr::from(1u64))],
                vec![(5u32, Fr::from(1u64))],
            ];
            let o = vec![
                vec![(3u32, Fr::from(1u64))],
                vec![(6u32, Fr::from(1u64))],
            ];
            let z = vec![
                Fr::from(1u64),
                Fr::from(a1),
                Fr::from(b1),
                Fr::from(a1) * Fr::from(b1),
                Fr::from(a2),
                Fr::from(b2),
                Fr::from(a2) * Fr::from(b2),
            ];
            let u = Fr::from(1u64);
            let e = vec![Fr::zero(); 2];

            let (proof, _) = prove::<crate::curve::Bls12_381>(&l, &r_mat, &o, &z, u, &e);
            let mut bad_proof = proof.clone();
            // Flip claimed sum.
            bad_proof.claims[0] += Fr::from(flip_val);
            let (ok, _, _) = verify::<crate::curve::Bls12_381>(&bad_proof);
            prop_assert!(!ok, "tampered sumcheck proof must be rejected");
        }

        /// Property: two different vectors produce different HashPC commitments.
        #[test]
        fn prop_hashpc_binding(
            v1 in proptest::collection::vec(arb_fr(), 4),
            v2 in proptest::collection::vec(arb_fr(), 4),
        ) {
            prop_assume!(v1 != v2, "need distinct vectors");
            let params = PedersenParams::<crate::curve::Bls12_381>::from_seed(b"binding-test", 4, 1);
            let (h1, _) = poly_commit::<crate::curve::Bls12_381>(&v1, &params.basis_w);
            let (h2, _) = poly_commit::<crate::curve::Bls12_381>(&v2, &params.basis_w);
            prop_assert_ne!(h1, h2, "different vectors must produce different commitments");
        }

        /// Property: HashPC commitment is deterministic.
        #[test]
        fn prop_hashpc_deterministic(
            v in proptest::collection::vec(arb_fr(), 4),
        ) {
            let params = PedersenParams::<crate::curve::Bls12_381>::from_seed(b"det-test", 4, 1);
            let (h1, p1) = poly_commit::<crate::curve::Bls12_381>(&v, &params.basis_w);
            let (h2, p2) = poly_commit::<crate::curve::Bls12_381>(&v, &params.basis_w);
            prop_assert_eq!(h1, h2);
            prop_assert_eq!(p1, p2);
        }

        /// Property: HashPC opening verifies for random vectors and random r.
        #[test]
        fn prop_hashpc_opening_verifies(
            v in proptest::collection::vec(arb_fr(), 4),
        ) {
            let params = PedersenParams::<crate::curve::Bls12_381>::from_seed(b"opening-test", 4, 1);
            let (hash, _) = poly_commit::<crate::curve::Bls12_381>(&v, &params.basis_w);
            let proof = create_opening::<crate::curve::Bls12_381>(&v);
            let r = vec![Fr::from(3u64), Fr::from(5u64)];
            let claimed = eval_dense_mle(&v, &r);
            prop_assert!(verify_opening::<crate::curve::Bls12_381>(&hash, &proof, &claimed, &r));
        }

        /// Property: HashPC opening rejects tampered table.
        #[test]
        fn prop_hashpc_tamper_rejects(
            v in proptest::collection::vec(arb_fr(), 4),
            flip in 1u64..1000,
        ) {
            let params = PedersenParams::<crate::curve::Bls12_381>::from_seed(b"tamper-test", 4, 1);
            let (hash, _) = poly_commit::<crate::curve::Bls12_381>(&v, &params.basis_w);
            let mut proof = create_opening::<crate::curve::Bls12_381>(&v);
            proof.table[0] += Fr::from(flip);
            let r = vec![Fr::from(3u64), Fr::from(5u64)];
            let claimed = eval_dense_mle(&v, &r);
            prop_assert!(!verify_opening::<crate::curve::Bls12_381>(&hash, &proof, &claimed, &r));
        }

        /// Property: eval_dense_mle at a Boolean point matches direct index access.
        #[test]
        fn prop_dense_mle_boolean_point(
            vals in proptest::collection::vec(arb_fr(), 4),
        ) {
            // For index i, the Boolean point r has r[bit] = (i >> bit) & 1.
            // i=0 → [0,0], i=1 → [1,0], i=2 → [0,1], i=3 → [1,1]
            let r0 = vec![Fr::from(0u64), Fr::from(0u64)];
            let r1 = vec![Fr::from(1u64), Fr::from(0u64)];
            let r2 = vec![Fr::from(0u64), Fr::from(1u64)];
            let r3 = vec![Fr::from(1u64), Fr::from(1u64)];
            prop_assert_eq!(eval_dense_mle(&vals, &r0), vals[0]);
            prop_assert_eq!(eval_dense_mle(&vals, &r1), vals[1]);
            prop_assert_eq!(eval_dense_mle(&vals, &r2), vals[2]);
            prop_assert_eq!(eval_dense_mle(&vals, &r3), vals[3]);
        }

        /// Property: sumcheck proof round count = log2ceil(next_power_of_two(n_constraints)).
        #[test]
        fn prop_proof_round_count(
            n_constraints in 1usize..32,
        ) {
            let mut l = Vec::new();
            let mut r_mat = Vec::new();
            let mut o = Vec::new();
            for i in 0..n_constraints {
                l.push(vec![((1 + 3 * i) as u32, Fr::from(1u64))]);
                r_mat.push(vec![((2 + 3 * i) as u32, Fr::from(1u64))]);
                o.push(vec![((3 + 3 * i) as u32, Fr::from(1u64))]);
            }
            let mut z = vec![Fr::from(1u64)];
            for i in 0..n_constraints {
                let a = Fr::from((i + 2) as u64);
                let b = Fr::from((i + 3) as u64);
                z.push(a);
                z.push(b);
                z.push(a * b);
            }
            let e = vec![Fr::zero(); n_constraints];
            let (proof, _) = prove::<crate::curve::Bls12_381>(&l, &r_mat, &o, &z, Fr::from(1u64), &e);

            let expected_rounds = log2ceil(next_power_of_two(n_constraints));
            prop_assert_eq!(proof.polys.len(), expected_rounds);
        }

        /// Property: parallel sumcheck prover produces identical proof to sequential.
        #[test]
        fn prop_parallel_sumcheck_matches_sequential(
            a1 in 1u64..500,
            b1 in 1u64..500,
            a2 in 1u64..500,
            b2 in 1u64..500,
        ) {
            let l = vec![
                vec![(1u32, Fr::from(1u64))],
                vec![(4u32, Fr::from(1u64))],
            ];
            let r_mat = vec![
                vec![(2u32, Fr::from(1u64))],
                vec![(5u32, Fr::from(1u64))],
            ];
            let o = vec![
                vec![(3u32, Fr::from(1u64))],
                vec![(6u32, Fr::from(1u64))],
            ];
            let z = vec![
                Fr::from(1u64),
                Fr::from(a1),
                Fr::from(b1),
                Fr::from(a1) * Fr::from(b1),
                Fr::from(a2),
                Fr::from(b2),
                Fr::from(a2) * Fr::from(b2),
            ];
            let u = Fr::from(1u64);
            let e = vec![Fr::zero(); 2];

            let (seq_proof, seq_r) = prove_with_opts::<crate::curve::Bls12_381>(&l, &r_mat, &o, &z, u, &e, false);
            let (par_proof, par_r) = prove_with_opts::<crate::curve::Bls12_381>(&l, &r_mat, &o, &z, u, &e, true);

            prop_assert_eq!(proof_hash::<crate::curve::Bls12_381>(&seq_proof), proof_hash::<crate::curve::Bls12_381>(&par_proof));
            prop_assert_eq!(seq_r, par_r);

            let (ok_seq, _, _) = verify::<crate::curve::Bls12_381>(&seq_proof);
            let (ok_par, _, _) = verify::<crate::curve::Bls12_381>(&par_proof);
            prop_assert!(ok_seq, "sequential proof must verify");
            prop_assert!(ok_par, "parallel proof must verify");
        }
    }
}
