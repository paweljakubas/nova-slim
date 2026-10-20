# Native (blst) backend

An optional accelerator for the **BLS12-381 G1 multi-scalar multiplication** used
by the Pedersen / HashPC commitments.  It is off by default; enabling it swaps
one hot operation onto the vendored [blst](https://github.com/supranational/blst)
library through a C ABI, and *nothing else* changes.

## TL;DR

- **What it accelerates:** exactly one call — the G1 MSM `sum_i s_i · P_i`. That
  is the blst-mappable, size-sensitive work in the commitment path.
- **What it does not:** the ring-residue folds, Module-SIS arithmetic, sumcheck,
  and serialization have no blst analogue and stay in Rust.
- **Isolation:** the feature is purely additive. With `native` off, the crate
  builds and behaves exactly as before (the wrapper returns `None` and callers
  fall back to arkworks).
- **Correctness:** results are checked bit-for-bit against arkworks before any
  speedup is reported, in both the Rust tests and the benchmark harness.
- **Measured:** faster at **every** size tested, from the committed 15-base
  circuit up to 65 536 bases (≈1.3–1.95×). See [Results](#results).

## Why it exists (and why the size question mattered)

The `benchmark_nova` fold breakdown (B1) splits a fold step into
`load / commit(MSM) / fold-core / serialize`.  On the 254-step BLS12-381 VRF
circuit the split is:

| phase | ms/step |
|---|---|
| load (disk I/O) | 0.23 |
| commit (MSM) | 10.14 |
| fold-core | 12.27 |
| serialize | 0.10 |

Disk I/O and serialization are ~1.4% — the MSMs and field arithmetic dominate.
The *initial* hypothesis was that the 15-base MSMs are naive-scalar-mul bound,
so blst's Pippenger (a bucket method) would only pay off at large `n`.  The A/B
below **refutes** that for this codebase: arkworks' small-MSM path is itself
effectively a scalar-mul loop, and blst wins even at `n = 15`.  The guard is
nonetheless kept *size-aware* — the point is to only accelerate where it helps.

## Layout

```
prover/native/
  vendored/blst/            pinned upstream blst (Apache-2.0) checkout
  include/nova_backend.h    the stable C ABI (byte containers only)
  src/nova_backend.cpp      encoding glue; MSM is blst's Pippenger
  tests/test_nova_backend.cpp   ground-level C++ tests (18 checks)
  CMakeLists.txt            builds libblst.a, then libnova_backend.a
prover/build.rs             drives CMake, links nova_backend + blst + stdc++
prover/src/native_msm.rs    sole FFI surface (feature "native")
prover/src/bin/benchmark_msm.rs  A/B harness across sizes
```

## The ABI

Everything crossing the boundary is a fixed-size, ABI-stable byte container —
no C++ objects, no STL, no heap pointer owned by the Rust side.

| Rust | C | bytes | encoding |
|---|---|---|---|
| `Fr` | `nova_backend_fr_t` | 32 | canonical, **little-endian** |
| `Fq` | (inside `nova_backend_g1_t`) | 48 | canonical, **big-endian** |
| `G1Affine` | `nova_backend_g1_t` | 96 | `x (48 BE) ‖ y (48 BE)` |

Point at infinity is all-zero coordinate bytes (the C side skips it).  Scalars
that are zero, or points that are infinity, are skipped in the hot loop.

## Trust model

As in the sibling bls backend, there is **no per-point on-curve or
prime-subgroup check** in the MSM loop: a full final exponentiation per point
would dwarf the MSM once `n` grows.  Inputs come from the deterministic
in-process basis derivation (already valid G1 points), and the MSM *output* is
sanity-checked once (`blst_p1_affine_on_curve`) after the call.  This is a
performance/assurance trade documented here rather than hidden.

## Building

The native feature needs a C/C++ toolchain plus **CMake** and **`nasm`**
(Debian/Ubuntu: `build-essential cmake nasm`).  blst is vendored in-tree and
compiled by `build.rs` → CMake → blst's own `build.sh`; nothing is downloaded.

```sh
# default build: pure Rust, no native code linked
cargo build --release -p prover

# native build (BLS12-381 is required for the accelerator)
cargo build --release -p prover --features native,bls12-381
```

Wiring:

- `NovaCurve::native_msm(points, scalars) -> Option<G1Affine>` defaults to
  `None`.  `Bls12_381` overrides it under `native`.
- `pedersen_commit` calls `C::native_msm(...)` first and **falls back to
  arkworks** when it returns `None` (feature off) or on any native error.

## Correctness

Four independent layers:

1. **Rust parity tests** (`native_msm.rs`): `msm_matches_arkworks_small`,
   `msm_matches_arkworks_full_width` (64 bases, full-width scalars),
   `msm_handles_identity_and_zero`, `roundtrip_encoding_large_coordinates`.
2. **C++ unit tests** (`test_nova_backend.cpp`, run via CTest): known-truth
   built with blst directly — `1·G = G`, `2·G + 3·G = 5·G`, infinity/zero
   skipping, null-argument rejection.
3. **ABI-drift tests** (`native_msm.rs`): parse the committed
   `nova_backend.h` and fail if the version/width macros, function names, or
   status-code values diverge from the Rust bindings.
4. **Benchmark parity assertion** (`benchmark_msm.rs`): every native timing is
   preceded by an `assert_eq!` against arkworks, so a fast-but-wrong backend
   cannot report a "speedup".

## Results

`cargo run --release --bin benchmark_msm --features native,bls12-381`
(best-of-5; parity asserted before each row):

| n | arkworks (ms) | native (ms) | speedup |
|---|---|---|---|
| 15 | 4.41 | 2.26 | 1.95× |
| 100 | 20.07 | 15.51 | 1.29× |
| 1000 | 134.75 | 103.46 | 1.30× |
| 8000 | 1110.23 | 590.04 | 1.88× |
| 65536 | 5405.64 | 2930.20 | 1.84× |

CPU-only (blst Pippenger is single-threaded); run without `native` to print the
arkworks baseline alone.

## Where the Verus layer stands

The [formal-verification layer](FormalVerification.md) does **not** cover this
code: it has no Verus specs over the MSM or the FFI boundary.  The assurance
here is the parity testing above, not proof.

## Scope guard

This backend accelerates **one operation**.  It is deliberately not a port of
the prover: the folding, ring arithmetic, and compression remain pure Rust.  If
a future change needs more of the commitment path on blst, it should extend
`nova_backend.h` with a *new* named operation and its own parity test, rather
than growing the existing call.
