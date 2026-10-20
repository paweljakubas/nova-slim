# Formal Verification in `prover` (NovaSlim)

This document records the [Verus](https://github.com/verus-lang/verus)
verification layer: what is actually machine-checked today, what is only
*asserted* in a comment-shaped contract, and what is not covered at all.

## TL;DR — read this before trusting anything below

- **The verified surface is the integer model of the norm arithmetic.** The
  `verus_norm.rs` module proves properties of a `nat`-valued model of
  `norm::magnitude_bits`, `norm::fits_bits`, `norm::norm_ok`, and
  `norm::verify_range`. The `verus_smoke.rs` module adds a toolchain canary.
- **Verification is opt-in per crate and must be enabled.** Without
  `[package.metadata.verus] verify = true` in `prover/Cargo.toml`,
  `cargo-verus verify` only *compiles* the crate and silently skips the SMT
  checks. This is the exact failure mode that made the bls verification layer
  inert for its whole lifetime before it was caught. Keep the canary in
  `verus_smoke.rs` to detect it.
- **The production norm functions are not verified.** They are generic over
  `ark_ff::PrimeField` / `BigInteger`, which Verus has no model for, so even a
  bare loop over `&[F]` fails. The proofs cover a *model* of the arithmetic,
  not the ark-typed code.
- **The `verus_specs.rs` contracts are asserted, not proved.** They are
  `uninterp`/body-less specifications that document intent and are usable by
  other proofs; they are not evidence.
- **Nothing about the folding, sumcheck, commitment, or SIS code is
  verified.** There is no Verus model of the curve group, the field, the
  relaxed-R1CS relation, or the ring arithmetic.

## Why Verus?

The prover handles sensitive material (folded witness `Z`, error `E`) and
enforces a post-quantum "shortness" claim: soundness of the SIS/Hash
commitment label rests on an infinity-norm bound `‖v‖_∞ ≤ B` on `Z` and `E`.
Rust's type system does not establish that the certificate/verification logic
actually enforces that bound, nor the arithmetic relationships between
bit-lengths and bounds. Verus lets the integer core of that argument be
machine-checked in the same crate.

## Enabling verification (read this)

Verification only runs if the package opts in:

```toml
# prover/Cargo.toml
[package.metadata.verus]
verify = true
```

**Without this line, `cargo-verus verify` compiles the crate and exits `0`**
without checking anything. Because the failure is silent, treat a green run as
meaningful only after confirming it rejects a known-bad assertion — see the
canary note in `verus_smoke.rs`.

## Running verification

```bash
# from the repo root, with Verus + Z3 on PATH (see flake.nix)
cd prover
RUSTUP_TOOLCHAIN=1.98.1-x86_64-unknown-linux-gnu cargo-verus verify --features verus
```

Current result: **`15 verified, 0 errors`** for the crate's own modules (the
`vstd` library contributes a much larger, unrelated count). A clean run is
incremental and takes well under a minute once dependencies are built.

Normal builds are unaffected — every `verus!` block is behind
`#[cfg(feature = "verus")]` and is erased otherwise:

```bash
cd prover && cargo check && cargo test
```

### Toolchain pinning note

`vstd` / `verus_builtin` / `verus_builtin_macros` are pinned with `=` to the
versions bundled with the Verus release the toolchain ships
(`0.2026.09.20.aef82ed`). A newer `vstd` (e.g. `2026-10-18`) panics the
verifier with `unexpected verus diagnostic item ... rust_div`. Do not relax the
pins without moving the Verus release in `flake.nix` in lockstep.

## What is genuinely verified (`verus_norm.rs`)

All of these are over `nat`, i.e. an integer *model* of the corresponding
`norm.rs` function.

| Item | Statement |
|------|-----------|
| `is_bit_len` | spec: `b` is the least `b >= 1` with `m < 2^b` (model of `magnitude_bits`) |
| `coord_fits` | spec: `m` is representable in `bound_bits` bits (model of `fits_bits` for one coordinate) |
| `lemma_coord_fits_bound` | `coord_fits(m, b)` with `b >= 1` implies `m < 2^b` — the ground-truth norm enforcement `verify_range` relies on |
| `lemma_pow2_increases` | `a < b ==> 2^a < 2^b` (helper) |
| `lemma_inf_norm_monotone` | `norm_ok` is monotone in the bound: fits a tighter bound => fits any looser bound |
| `range_accepts` | spec: recursive acceptance predicate of the range certificate |
| `lemma_range_accepts_sound` | acceptance implies every recorded length is honest (`>=` true) and every true length is within the bound |

These are the parts of the norm argument that are genuinely arithmetic and can
be checked without a field/curve model. They are the leverage: the certificate
logic's *correctness shape* is now machine-checked, even though the
ark-typed loops that instantiate it are not.

## What is *not* verified

### The production norm functions

`signed_magnitude`, `measure_inf_norm`, `magnitude_bits::<F::BigInt>`,
`fits_bits`, `norm_ok`, `make_range`, `verify_range`, `make_jl`, `verify_jl`
operate on `ark_ff::PrimeField` / `BigInteger`. Verus reports the type as
unsupported:

```
error: `ark_ff::fields::models::fp::Fp` is not supported
       (note: you may be able to add a Verus specification to this type
       with the `external_type_specification` attribute)
```

Declaring `Fr` would require the `Ex*` + `View` pattern and a
`ZeroablePrimitive` impl on a foreign type, which is not possible. So the loops
and value arithmetic in these functions are only *asserted* in
`verus_specs.rs`.

### The asserted contracts (`verus_specs.rs`)

| Contract | Meaning | Useful? |
|----------|---------|---------|
| `spec_signed_magnitude` | magnitude is a canonical representative | asserted, name-only |
| `spec_measure_inf_norm` | the norm equals one of the input magnitudes | asserted, name-only |
| `spec_make_range_len` | a produced certificate has one length per coordinate | asserted |
| `spec_verify_range_accepts_implies_len_match` | acceptance implies lengths line up | asserted |

These document intent and are usable by other proofs, but they are not
evidence. None is vacuous, but none is checked.

### Everything else

- **Folding (`nifs.rs`, `fold.rs`)**: the relaxed-R1CS relation, cross-terms,
  and the NIFS completeness argument are described in prose and tested, but not
  verified. No Verus model of the group.
- **Sumcheck (`sumcheck.rs`)**: the degree-2 round arithmetic and the
  Fiat-Shamir transcript are not verified. A pure-integer model of the
  round/index arithmetic is a natural next step (see below).
- **Commitments (`commitment.rs`, `module_sis.rs`)**: Pedersen MSM and the
  Module-SIS ring `mat_vec_mul` are unverified. The ring arithmetic is small
  prime fields, which would need their own model.
- **Parsing / codec (`lib.rs::codec`)**: CBOR/serde/hex paths are unverified
  (`nom` and `serde` are external crates).

## Where verification can still go

The productive direction, exactly as in the bls repo, is extracting
**pure-integer** logic so Verus can check it, rather than annotating
ark-typed surface area:

- A `usize` model of the sumcheck round/index arithmetic (the number of
  evaluations per round, the `2^k` table sizes), mirroring the bls
  `term_loop_model` pattern.
- Parser cursor/stride bounds lifted out of `nom` into small `usize`
  functions (CBOR decode lengths, the MLE table indexing in `sumcheck`).
- The `usize`/`u32` casts around `bound_bits` and table lengths, which
  currently carry implicit range obligations.
- Any further loop or index arithmetic reachable from a checked caller.

## References

- [Verus repository](https://github.com/verus-lang/verus)
- [Verus guide](https://verus-lang.github.io/verus/guide/)
- [Amazon Science: Developing provably correct Rust code with Verus](https://www.amazon.science/blog/developing-provably-correct-rust-code-with-verus)
- [Vest](https://github.com/secure-foundations/vest) — Verus-verified binary format parser
- The sibling `bls` repo's `FormalVerification.md`, whose honesty format
  (TL;DR, verified-vs-asserted tables, "where verification can still go") this
  document follows.
