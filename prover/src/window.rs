//! Uniformized per-window full verification (P9, `subsec:per-window-ring`).
//!
//! A *window* of `C` consecutive IVC steps is merged into a single
//! "uniformized" circuit: each step copy is laid out block-diagonally over
//! its own wire block `[k·n_wires, (k+1)·n_wires)` and consecutive copies are
//! joined by explicit interface-equality rows `in_j(k+1) == out_j(k)` (as R1CS
//! rows `in·1 = out`, so that no sharing of wire indices is needed).  A single
//! degree-2 sumcheck with full-entropy Fiat–Shamir inner challenges then
//! covers every constraint of every step *and* every chain link (`W2`,
//! `thm:per-window-ring`), closing the field/ring sumcheck gap described in
//! the paper.  The opened window truth table is checked for (a) residual-zero
//! re-evaluation at the Fiat–Shamir point, and (b) canonical-lift interface
//! states (`def:canonical-lift` / `lem:lift-faithful`) whenever an explicit
//! ring modulus `q` is supplied.

use crate::commitment::PedersenParams;
use crate::curve::{NovaCurve, ScalarField};
use crate::module_sis::is_canonical_lift;
use crate::sumcheck::{
    create_opening, eval_dense_mle, poly_commit, prove_degree2_opts, recompute_circuit_evals,
    verify_degree2, SumcheckProofDegree2,
};
use crate::NIFS_PARAMS_SEED;
use ark_ff::{BigInteger, One, PrimeField, Zero};
use blake2::{Blake2b512, Digest};

/// A uniformized window circuit: `C` copies of one step circuit joined by
/// interface-equality rows.
#[derive(Clone, Debug)]
pub struct ChainCircuit<F: PrimeField> {
    /// Per-step wire count (`n_wires`).
    pub n_wires: usize,
    /// Number of steps in the window.
    pub n_steps: usize,
    /// Interface width (`n_pub_in == n_pub_out`).
    pub n_pub: usize,
    /// Per-step constraint count.
    pub n_constraints_step: usize,
    /// Combined sparse L/R/O matrices (block-diagonal copies + chain rows).
    pub l: Vec<Vec<(u32, F)>>,
    pub r: Vec<Vec<(u32, F)>>,
    pub o: Vec<Vec<(u32, F)>>,
}

impl<F: PrimeField> ChainCircuit<F> {
    /// Total wire count of the uniformized circuit (block-diagonal, so simply
    /// `n_steps · n_wires`).
    pub fn wire_count(&self) -> usize {
        self.n_steps * self.n_wires
    }

    /// Total constraint count: per-step copies plus `(n_steps−1)·n_pub` chain
    /// equality rows.
    pub fn constraint_count(&self) -> usize {
        self.n_steps * self.n_constraints_step + (self.n_steps - 1) * self.n_pub
    }

    /// Global wire index range of step `k`'s public-output region.
    pub fn step_out_range(&self, k: usize) -> std::ops::Range<usize> {
        let base = k * self.n_wires;
        base + 1..base + 1 + self.n_pub
    }

    /// Global wire index range of step `k`'s public-input region.
    pub fn step_in_range(&self, k: usize) -> std::ops::Range<usize> {
        let base = k * self.n_wires;
        base + 1 + self.n_pub..base + 1 + 2 * self.n_pub
    }

    /// Build the uniformized window circuit.
    ///
    /// Requires `n_pub_out == n_pub_in` (the public inputs of a step are
    /// exactly its IVC state, matching `check_step_circuit`).  Each original
    /// constraint `(l_j, r_j, o_j)` is copied once per step with wire indices
    /// shifted by `k·n_wires`; then `(n_steps−1)·n_pub` rows of the form
    /// `in_j(k+1)·1 = out_j(k)` link the chain.
    pub fn uniformize(
        n_wires: u32,
        n_pub_out: u32,
        n_pub_in: u32,
        n_steps: usize,
        l: &[Vec<(u32, F)>],
        r: &[Vec<(u32, F)>],
        o: &[Vec<(u32, F)>],
    ) -> Result<Self, String> {
        if n_pub_out != n_pub_in {
            return Err(format!(
                "uniformize: n_pub_out ({n_pub_out}) != n_pub_in ({n_pub_in})"
            ));
        }
        let n_w = n_wires as usize;
        let n_p = n_pub_out as usize;
        if n_w < 1 + 2 * n_p {
            return Err(format!(
                "uniformize: n_wires ({n_w}) < 1 + 2·n_pub ({})",
                1 + 2 * n_p
            ));
        }
        let n_c = l.len();
        debug_assert_eq!(n_c, r.len());
        debug_assert_eq!(n_c, o.len());

        let n_rows = n_steps * n_c + (n_steps - 1) * n_p;
        let mut cl = Vec::with_capacity(n_rows);
        let mut cr = Vec::with_capacity(n_rows);
        let mut co = Vec::with_capacity(n_rows);

        for k in 0..n_steps {
            let base = (k * n_w) as u32;
            for j in 0..n_c {
                cl.push(l[j].iter().map(|&(w, c)| (w + base, c)).collect());
                cr.push(r[j].iter().map(|&(w, c)| (w + base, c)).collect());
                co.push(o[j].iter().map(|&(w, c)| (w + base, c)).collect());
            }
        }

        // Chain-equality rows across consecutive steps:
        //   in_j of step k+1  ==  out_j of step k        (as  in·1 = out )
        for k in 0..n_steps - 1 {
            let out_base = (k * n_w + 1) as u32;
            let in_base = ((k + 1) * n_w + 1 + n_p) as u32;
            for j in 0..n_p {
                cl.push(vec![(in_base + j as u32, F::one())]);
                cr.push(vec![(0u32, F::one())]);
                co.push(vec![(out_base + j as u32, F::one())]);
            }
        }

        Ok(Self {
            n_wires: n_w,
            n_steps,
            n_pub: n_p,
            n_constraints_step: n_c,
            l: cl,
            r: cr,
            o: co,
        })
    }

    /// Concatenate per-step witnesses into the uniformized window witness.
    ///
    /// Each `z_k` must have length `n_wires`; the blocks are disjoint so the
    /// combined witness is a plain concatenation and interface equality is
    /// enforced by the chain rows added in [`Self::uniformize`].
    pub fn witness(&self, z_steps: &[Vec<F>]) -> Vec<F> {
        assert_eq!(z_steps.len(), self.n_steps);
        let z_len = self.n_steps * self.n_wires;
        let mut z = Vec::with_capacity(z_len);
        for zk in z_steps {
            assert_eq!(zk.len(), self.n_wires, "each step witness has n_wires entries");
            z.extend_from_slice(zk);
        }
        z
    }

    /// Extract a step's interface output from a combined witness.
    pub fn io_out(&self, z: &[F], k: usize) -> Vec<F> {
        z[self.step_out_range(k)].to_vec()
    }

    /// Extract a step's interface input from a combined witness.
    pub fn io_in(&self, z: &[F], k: usize) -> Vec<F> {
        z[self.step_in_range(k)].to_vec()
    }

    /// Whether consecutive step witnesses satisfy `in(k+1) == out(k)` — the
    /// chain condition that the equality rows enforce in-circuit.
    pub fn is_io_chained(&self, z_steps: &[Vec<F>]) -> bool {
        for k in 0..self.n_steps - 1 {
            if self.io_out(&z_steps[k], 0) != self.io_in(&z_steps[k + 1], 0) {
                return false;
            }
        }
        true
    }
}

/// Window sumcheck proof (`W2`), over the uniformized circuit with `u = 1`
/// and a zero error vector (fresh window).
#[derive(Clone, Debug)]
pub struct WindowProof<C: NovaCurve> {
    pub n_steps: usize,
    pub n_pub: usize,
    /// The degree-2 sumcheck proof over the uniformized circuit.
    pub sumcheck: SumcheckProofDegree2<C>,
    /// The prover-side Fiat–Shamir challenges (the verifier reproduces these;
    /// the enclosing protocol binds them as the opening point).
    pub r_challenges: Vec<ScalarField<C>>,
    /// Asserted interface input of the window (step 0's input).
    pub window_io_in: Vec<ScalarField<C>>,
    /// Asserted interface output (last step's output = next window's input).
    pub window_io_out: Vec<ScalarField<C>>,
    pub w_commit_hash: Vec<u8>,
    pub w_opening: Vec<ScalarField<C>>,
    pub e_commit_hash: Vec<u8>,
    pub e_opening: Vec<ScalarField<C>>,
}

/// Prove a window of `n_steps` chained step witnesses.
///
/// `z_steps[k]` is the full `n_wires`-long witness of step `k`.  The window is
/// verified (by the caller, at fold level) with `u = 1`, `e = 0`: a fresh
/// window must satisfy standard R1CS, and the interface equality between
/// steps is enforced by the uniformized circuit itself.
pub fn prove_window<C: NovaCurve>(
    chain: &ChainCircuit<ScalarField<C>>,
    z_steps: &[Vec<ScalarField<C>>],
    parallel: bool,
) -> WindowProof<C> {
    let z = chain.witness(z_steps);
    let n_c = chain.constraint_count();
    let e = vec![ScalarField::<C>::zero(); n_c];
    let u = ScalarField::<C>::one();

    let (proof, r_challenges) =
        prove_degree2_opts::<C>(&chain.l, &chain.r, &chain.o, &z, u, &e, parallel);

    let params = PedersenParams::<C>::from_seed(
        NIFS_PARAMS_SEED,
        chain.wire_count(),
        chain.constraint_count(),
    );
    let (w_hash, _) = poly_commit::<C>(&z, &params.basis_w);
    let (e_hash, _) = poly_commit::<C>(&e, &params.basis_e);
    let w_open = create_opening::<C>(&z);
    let e_open = create_opening::<C>(&e);

    WindowProof {
        n_steps: chain.n_steps,
        n_pub: chain.n_pub,
        sumcheck: proof,
        r_challenges,
        window_io_in: chain.io_in(&z, 0),
        window_io_out: chain.io_out(&z, chain.n_steps - 1),
        w_commit_hash: w_hash,
        w_opening: w_open.table,
        e_commit_hash: e_hash,
        e_opening: e_open.table,
    }
}

/// Output of a window verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WindowVerifyOutput<C: NovaCurve> {
    pub ok: bool,
    pub final_claim: ScalarField<C>,
    pub r_challenges: Vec<ScalarField<C>>,
    /// Interface input of the window (from the opened truth table).
    pub window_io_in: Vec<ScalarField<C>>,
    /// Interface output of the window.
    pub window_io_out: Vec<ScalarField<C>>,
}

/// Verify a window sumcheck proof against its uniformized circuit.
///
/// Checks, in order:
///   1. degree-2 sumcheck validity (Fiat–Shamir consistent round polynomials),
///      with the r-challenges reproduced by the verifier,
///   2. the residual vanishes: `final_claim == fr_r − u·cz_r − er_r` and
///      `final_claim == 0` (u = 1, e = 0 must be standard R1CS satisfaction),
///   3. the HashPC opening tables for W and E hash to the committed digests,
///   4. the OP check: `az_r, bz_r, cz_r, fr_r` recomputed from the *opened*
///      witness truth table at `r` match the claimed evaluations,
///   5. `MLE(E)@r == er_r` from the opened E table,
///   6. the interface of the opened window equals the asserted `window_io_in`
///      (first step input) and `window_io_out` (last step output),
///   7. canonical-lift: if a ring modulus `q` is supplied, every asserted
///      interface wire is a canonical residue in `[0, q)` so τ-tests on the
///      window boundaries coincide between `R_q` and `F_r`
///      (`def:canonical-lift` / `lem:lift-faithful`).
///
/// `q = None` disables the residue test (field scheme, e.g. `Bls12_381::Fr`).
pub fn verify_window<C: NovaCurve>(
    chain: &ChainCircuit<ScalarField<C>>,
    proof: &WindowProof<C>,
    q: Option<u64>,
) -> WindowVerifyOutput<C> {
    let zero = ScalarField::<C>::zero();

    if proof.n_steps != chain.n_steps || proof.n_pub != chain.n_pub {
        return reject(proof, zero, None);
    }

    // (1) Degree-2 sumcheck + r-challenge binding.
    let d = verify_degree2::<C>(&proof.sumcheck);
    if !d.ok || d.r_challenges != proof.r_challenges {
        return reject(proof, zero, None);
    }

    // (2) Residual zero (u = 1, e = 0).
    if d.final_claim != zero || d.fr_r - d.cz_r - d.er_r != zero {
        return reject(proof, d.final_claim, Some(&d.r_challenges));
    }

    // (3) Opening digests.
    if blake2b_512_hash(&proof.w_opening) != proof.w_commit_hash
        || blake2b_512_hash(&proof.e_opening) != proof.e_commit_hash
    {
        return reject(proof, d.final_claim, Some(&d.r_challenges));
    }

    // (4) OP check: circuit-backed re-evaluation from the opened witness.
    let (az_r, bz_r, cz_r, fr_r) = recompute_circuit_evals::<C>(
        &chain.l,
        &chain.r,
        &chain.o,
        &proof.w_opening,
        chain.constraint_count(),
        &d.r_challenges,
    );
    if az_r != proof.sumcheck.az_r
        || bz_r != proof.sumcheck.bz_r
        || cz_r != proof.sumcheck.cz_r
        || fr_r != proof.sumcheck.fr_r
    {
        return reject(proof, d.final_claim, Some(&d.r_challenges));
    }

    // (5) MLE(E)@r == er_r.
    let er = if d.r_challenges.is_empty() {
        proof.e_opening[0]
    } else {
        eval_dense_mle(&proof.e_opening, &d.r_challenges)
    };
    if er != proof.sumcheck.er_r {
        return reject(proof, d.final_claim, Some(&d.r_challenges));
    }

    // (6) Interface of the opened window.
    let io_in = chain.io_in(&proof.w_opening, 0);
    let io_out = chain.io_out(&proof.w_opening, chain.n_steps - 1);
    if io_in != proof.window_io_in || io_out != proof.window_io_out {
        return reject(proof, d.final_claim, Some(&d.r_challenges));
    }

    // (7) Canonical-lift boundary (ring schemes only).
    if let Some(q) = q {
        for v in proof.window_io_in.iter().chain(proof.window_io_out.iter()) {
            if !is_canonical_lift(v, q) {
                return reject(proof, d.final_claim, Some(&d.r_challenges));
            }
        }
    }

    WindowVerifyOutput {
        ok: true,
        final_claim: d.final_claim,
        r_challenges: d.r_challenges,
        window_io_in: io_in,
        window_io_out: io_out,
    }
}

fn reject<C: NovaCurve>(
    _proof: &WindowProof<C>,
    final_claim: ScalarField<C>,
    r: Option<&[ScalarField<C>]>,
) -> WindowVerifyOutput<C> {
    WindowVerifyOutput {
        ok: false,
        final_claim,
        r_challenges: r.map(|r| r.to_vec()).unwrap_or_default(),
        window_io_in: vec![],
        window_io_out: vec![],
    }
}

/// Cross-window chaining: the output of window `a` must be exactly the input
/// of window `b` (equality tests in `F_r`; with both sides canonical lifts
/// this coincides with the `R_q` test by `lem:lift-faithful`).
pub fn windows_chain_ok<C: NovaCurve>(a: &WindowVerifyOutput<C>, b: &WindowVerifyOutput<C>) -> bool {
    a.ok && b.ok && a.window_io_out == b.window_io_in
}

/// Deterministic BLAKE2b-512 digest over a window proof (claims + round
/// polynomials + interface), used for golden tests and as the transcript
/// binding for cross-window chaining.
pub fn proof_hash<C: NovaCurve>(p: &WindowProof<C>) -> Vec<u8> {
    let mut h = Blake2b512::new();
    for c in &p.sumcheck.claims {
        h.update(c.into_bigint().to_bytes_le());
    }
    for poly in &p.sumcheck.polys {
        for c in poly {
            h.update(c.into_bigint().to_bytes_le());
        }
    }
    for v in &p.window_io_in {
        h.update(v.into_bigint().to_bytes_le());
    }
    for v in &p.window_io_out {
        h.update(v.into_bigint().to_bytes_le());
    }
    h.finalize().to_vec()
}

fn blake2b_512_hash<F: PrimeField>(values: &[F]) -> Vec<u8> {
    let mut h = Blake2b512::new();
    for v in values {
        h.update(v.into_bigint().to_bytes_le());
    }
    h.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::SparseCircuit;
    use crate::curve::Bls12_381;
    use crate::module_sis::ModuleSisParams;
    use ark_bls12_381::Fr;
    use proptest::prelude::*;

    // The single-constraint synthetic step circuit: wires `[1, out, in, x]`
    // with `in · x = out` (mirrors `cli/tests/cli.rs`).
    fn synthetic_step_r1cs_bytes() -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"r1cs");
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&2u32.to_le_bytes());

        let field_size = 32u32;
        let n_wires = 4u32;
        let n_pub_out = 1u32;
        let n_pub_in = 1u32;
        let n_prv_in = 1u32;
        let n_labels = 4u64;
        let n_constraints = 1u32;

        let mut header = Vec::new();
        header.extend_from_slice(&field_size.to_le_bytes());
        header.extend_from_slice(&[0u8; 32]);
        header.extend_from_slice(&n_wires.to_le_bytes());
        header.extend_from_slice(&n_pub_out.to_le_bytes());
        header.extend_from_slice(&n_pub_in.to_le_bytes());
        header.extend_from_slice(&n_prv_in.to_le_bytes());
        header.extend_from_slice(&n_labels.to_le_bytes());
        header.extend_from_slice(&n_constraints.to_le_bytes());

        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&(header.len() as u64).to_le_bytes());
        out.extend_from_slice(&header);

        let mut constraints = Vec::new();
        let mut write_vec = |terms: &[(u32, u64)]| {
            constraints.extend_from_slice(&(terms.len() as u32).to_le_bytes());
            for &(w, v) in terms {
                constraints.extend_from_slice(&w.to_le_bytes());
                constraints.push(v as u8);
                constraints.extend_from_slice(&vec![0u8; field_size as usize - 1]);
            }
        };
        // in * x = out
        write_vec(&[(2, 1)]);
        write_vec(&[(3, 1)]);
        write_vec(&[(1, 1)]);

        out.extend_from_slice(&2u32.to_le_bytes());
        out.extend_from_slice(&(constraints.len() as u64).to_le_bytes());
        out.extend_from_slice(&constraints);
        out
    }

    fn step_circuit() -> SparseCircuit<Fr> {
        SparseCircuit::from_bytes(&synthetic_step_r1cs_bytes()).unwrap()
    }

    fn chain_circuit<F: PrimeField>(c: &SparseCircuit<F>, n_steps: usize) -> ChainCircuit<F> {
        ChainCircuit::uniformize(c.n_wires, c.n_pub_out, c.n_pub_in, n_steps, &c.l, &c.r, &c.o)
            .unwrap()
    }

    /// Witness of one step: `[1, in·x, in, x]`.
    fn step_z(in_v: u64, x: u64) -> Vec<Fr> {
        vec![Fr::from(1u64), Fr::from(in_v * x), Fr::from(in_v), Fr::from(x)]
    }

    /// Chained witness list from `(initial_state, xs...)`.
    fn chained_steps(init: u64, xs: &[u64]) -> Vec<Vec<Fr>> {
        let mut cur = init;
        xs.iter()
            .map(|&x| {
                let z = step_z(cur, x);
                cur = cur * x;
                z
            })
            .collect()
    }

    /// BLS12-381 playground: honest 3-step window `2 → 6 → 30 → 210`.
    fn honest_chain() -> ChainCircuit<Fr> {
        chain_circuit(&step_circuit(), 3)
    }

    #[test]
    fn window_round_trip_honest() {
        let chain = honest_chain();
        let steps = chained_steps(2, &[3, 5, 7]);
        assert!(chain.is_io_chained(&steps));

        let proof = prove_window::<Bls12_381>(&chain, &steps, false);
        let out = verify_window(&chain, &proof, None);
        assert!(out.ok);
        assert_eq!(out.final_claim, Fr::zero());
        assert_eq!(out.window_io_in, vec![Fr::from(2u64)]);
        assert_eq!(out.window_io_out, vec![Fr::from(210u64)]);
        // 3 copies + 2 chain rows = 5 constraints → 8 padded → 3 rounds.
        assert_eq!(out.r_challenges.len(), 3);
    }

    #[test]
    fn window_single_step_round_trip() {
        let chain = chain_circuit(&step_circuit(), 1);
        let steps = chained_steps(2, &[3]);
        let proof = prove_window::<Bls12_381>(&chain, &steps, false);
        let out = verify_window(&chain, &proof, None);
        assert!(out.ok);
        assert_eq!(out.final_claim, Fr::zero());
        assert_eq!(out.r_challenges.len(), 0);
        assert_eq!(out.window_io_out, vec![Fr::from(6u64)]);
    }

    #[test]
    fn window_rejects_tampered_wire() {
        let chain = honest_chain();
        let mut steps = chained_steps(2, &[3, 5, 7]);
        steps[1][3] += Fr::from(5u64);

        let proof = prove_window::<Bls12_381>(&chain, &steps, false);
        let out = verify_window(&chain, &proof, None);
        assert!(!out.ok);
        assert_ne!(out.final_claim, Fr::zero());
    }

    /// The P9 gap-closure test: a step whose *own* constraints are satisfied
    /// but whose interface disagrees with the previous step (transport
    /// inconsistency) must be rejected — the explicit chain rows make the
    /// uniformized window's residual non-zero even though every per-step
    /// R1CS is locally valid.
    #[test]
    fn window_residual_catches_broken_chain() {
        let chain = honest_chain();
        let mut steps = chained_steps(2, &[3, 5, 7]);
        // Re-point step 2 at a different input and recompute its output so its
        // single constraint `in·x = out` still holds per-step.
        steps[2] = step_z(99, 5);
        assert!(!chain.is_io_chained(&steps));

        let proof = prove_window::<Bls12_381>(&chain, &steps, false);
        let out = verify_window(&chain, &proof, None);
        assert!(!out.ok);
        assert_ne!(out.final_claim, Fr::zero());
    }

    /// Canonical-lift boundary: when an explicit ring modulus `q` is given,
    /// every asserted window interface wire must be a canonical residue in
    /// `[0, q)`.  A window that is fully R1CS/chain-valid but whose output
    /// wraps past `q` must pass `q = None` yet fail the ring boundary test.
    #[test]
    fn window_canonical_lift_boundary() {
        let q = ModuleSisParams::ALL[0].q;

        // All-small honest chain: every wire is a canonical lift.
        let chain = honest_chain();
        let steps = chained_steps(2, &[3, 5, 7]);
        let proof = prove_window::<Bls12_381>(&chain, &steps, false);
        assert!(verify_window(&chain, &proof, None).ok);
        assert!(verify_window(&chain, &proof, Some(q)).ok);

        // Honest chain whose window output exceeds q (values stay < p, so the
        // field-side R1CS still holds exactly).
        let chain_big = chain_circuit(&step_circuit(), 3);
        let steps_big = vec![
            step_z(3, 5),      // out = 15
            step_z(15, q),     // out = 15·q  (internal, non-canonical is fine)
            step_z(15 * q, 2), // out = 30·q  → window_io_out NOT canonical
        ];
        assert!(chain_big.is_io_chained(&steps_big));
        let proof_big = prove_window::<Bls12_381>(&chain_big, &steps_big, false);
        let out_none = verify_window(&chain_big, &proof_big, None);
        assert!(out_none.ok, "field-side verification must pass");
        assert!(!verify_window(&chain_big, &proof_big, Some(q)).ok);
    }

    /// Cross-window chaining: the output of one window must equal the input
    /// of the next (used to connect windows at the fold level).
    #[test]
    fn window_cross_window_chain() {
        let w1 = chained_steps(2, &[3, 5, 7]);
        let chain = chain_circuit(&step_circuit(), 2);

        let steps_a = w1[0..2].to_vec();
        let p_a = prove_window::<Bls12_381>(&chain, &steps_a, false);
        let out_a = verify_window(&chain, &p_a, None);
        assert!(out_a.ok);
        assert_eq!(out_a.window_io_out, vec![Fr::from(30u64)]);

        let steps_b = vec![w1[2].clone(), step_z(210, 1)];
        let p_b = prove_window::<Bls12_381>(&chain, &steps_b, false);
        let out_b = verify_window(&chain, &p_b, None);
        assert!(out_b.ok);
        assert!(windows_chain_ok(&out_a, &out_b));

        // Broken chain across windows: next window starts at the *wrong* state.
        let chain1 = chain_circuit(&step_circuit(), 1);
        let steps_c = vec![step_z(999, 1)];
        let p_c = prove_window::<Bls12_381>(&chain1, &steps_c, false);
        let out_c = verify_window(&chain1, &p_c, None);
        assert!(out_c.ok);
        assert!(!windows_chain_ok(&out_a, &out_c));
    }

    /// Golden: a fixed window for the standard synthetic chain must produce
    /// an exactly deterministic proof digest, interface, and residual.
    #[test]
    fn window_golden_digest() {
        let chain = chain_circuit(&step_circuit(), 2);
        let steps = chained_steps(2, &[3, 7]);
        let proof = prove_window::<Bls12_381>(&chain, &steps, false);
        let out = verify_window(&chain, &proof, None);
        assert!(out.ok);
        assert_eq!(out.final_claim, Fr::zero());
        assert_eq!(out.window_io_in, vec![Fr::from(2u64)]);
        assert_eq!(out.window_io_out, vec![Fr::from(42u64)]);
        // 2 copies + 1 chain row = 3 constraints → 4 padded → 2 rounds.
        assert_eq!(out.r_challenges.len(), 2);
        assert_eq!(chain.wire_count(), 8);
        assert_eq!(proof.w_opening.len(), 8);
        assert_eq!(proof.e_opening.len(), 4);

        // Deterministic BLAKE2b-512 over claims + polynomials + interfaces.
        let digest = proof_hash(&proof);
        assert_eq!(hex::encode(&digest), GOLDEN_WINDOW_DIGEST);
        assert_eq!(hex::encode(&proof.w_commit_hash), GOLDEN_WINDOW_W_HASH);
        assert_eq!(hex::encode(&proof.e_commit_hash), GOLDEN_WINDOW_E_HASH);
    }

    const GOLDEN_WINDOW_DIGEST: &str =
        "2e5a244ba576caeec9a07182536a99e08d017a5facb00b11ce82da0b7a4ccab6205f0eb503567c96e8e2d63f02fad7a6865f27f65dddd0bc9182876e78c12a42";
    const GOLDEN_WINDOW_W_HASH: &str =
        "d87977d1293e3915b761ccef53bc5974dc71ccf6abb05621c6ac9ce15af8454aa4d5f55affaea3652bfb4fddcd795ed29810fd4a74a34f0c5f383fb82650d391";
    const GOLDEN_WINDOW_E_HASH: &str =
        "865939e120e6805438478841afb739ae4250cf372653078a065cdcfffca4caf798e6d462b65d658fc165782640eded70963449ae1500fb0f24981d7727e22c41";

    proptest! {
        /// Property: every honest chained window verifies to a zero residual,
        /// with or without the ring-boundary test, as long as all wires stay
        /// below the ring modulus.
        #[test]
        fn prop_honest_window_always_passes(
            init in 1u64..20,
            xs in prop::collection::vec(1u64..20, 2..6),
        ) {
            let steps = chained_steps(init, &xs);
            let chain = chain_circuit(&step_circuit(), steps.len());
            let proof = prove_window::<Bls12_381>(&chain, &steps, false);
            let out = verify_window(&chain, &proof, None);
            prop_assert!(out.ok);
            prop_assert_eq!(out.final_claim, Fr::zero());
            let q = ModuleSisParams::ALL[0].q;
            // The canonical-lift boundary test passes exactly when every
            // asserted window interface wire is a canonical residue mod q.
            let all_canonical = out
                .window_io_in
                .iter()
                .chain(out.window_io_out.iter())
                .all(|v| is_canonical_lift(v, q));
            prop_assert_eq!(
                verify_window(&chain, &proof, Some(q)).ok,
                all_canonical,
                "ring boundary acceptance must equal the canonical-lift predicate"
            );
        }

        /// Property: no tampering survives — distorted per-step constraints
        /// and transport-inconsistent (but locally valid) chains are all
        /// rejected with a non-zero residual.
        #[test]
        fn prop_tampered_window_never_passes(
            init in 1u64..20,
            xs in prop::collection::vec(1u64..20, 2..6),
        ) {
            let mut steps = chained_steps(init, &xs);
            let chain = chain_circuit(&step_circuit(), steps.len());
            let k = steps.len() / 2;
            // The correct chained state entering step `k`.
            let chained_in = {
                let mut cur = init;
                for &x in &xs[..k] {
                    cur *= x;
                }
                cur
            };
            if k % 2 == 0 {
                // Break the per-step R1CS of a middle step.
                steps[k][3] += Fr::from(7u64);
            } else {
                // Re-point the middle step at a *different* input and recompute
                // its output: locally valid, chain-inconsistent.
                steps[k] = step_z(chained_in + 1, xs[k]);
            }
            let proof = prove_window::<Bls12_381>(&chain, &steps, false);
            let out = verify_window(&chain, &proof, None);
            prop_assert!(!out.ok, "tampered window must not verify");
            prop_assert_ne!(out.final_claim, Fr::zero());
        }
    }
}