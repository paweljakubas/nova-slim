//! Rust wrapper over the optional native (vendored blst) BLS12-381 backend.
//!
//! The C ABI lives in `native/include/nova_backend.h` and is compiled into a
//! static library only when the `native` feature is enabled; this module is the
//! *only* Rust code that talks to it, and it is itself gated behind
//! `#[cfg(feature = "native")]`.
//!
//! Scope: the accelerator implements exactly one operation — a BLS12-381 G1
//! multi-scalar multiplication — because that is the blst-mappable,
//! size-sensitive hot spot in the commitment path.  Everything else (the ring
//! folds, Module-SIS arithmetic, sumcheck) has no blst analogue and stays in
//! Rust.  When the feature is off, `native_msm_g1` returns `None` and callers
//! fall back to arkworks, so results are unchanged.
//!
//! Byte encodings must match the header exactly:
//!   - Fr scalar : 32 bytes little-endian.
//!   - G1 affine : 96 bytes = x (48 BE) || y (48 BE).
//! Point-at-infinity is all-zero coordinate bytes.

use ark_bls12_381::{Fq, Fr, G1Affine};
use ark_ec::AffineRepr;
use ark_ff::{BigInteger, PrimeField};

pub const MODULE_VERSION: u32 = 1;
const FR_BYTES: usize = 32;
const FP_BYTES: usize = 48;
const G1_AFFINE_BYTES: usize = 96;

const STATUS_OK: i32 = 0;
const STATUS_INFINITY_OUTPUT: i32 = 3;

#[repr(C)]
#[derive(Clone, Copy)]
struct FrBytes {
    b: [u8; FR_BYTES],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct G1Bytes {
    b: [u8; G1_AFFINE_BYTES],
}

extern "C" {
    fn nova_backend_version() -> u32;
    fn nova_backend_flavor() -> *const core::ffi::c_char;
    fn nova_msm_g1(
        out: *mut G1Bytes,
        points: *const G1Bytes,
        scalars: *const FrBytes,
        npoints: usize,
    ) -> i32;
}

/// Version reported by the compiled native library.
pub fn backend_version() -> u32 {
    // SAFETY: no arguments, no aliasing; the symbol is linked when the feature
    // is enabled.
    unsafe { nova_backend_version() }
}

/// Short description of the compiled acceleration.
pub fn backend_flavor() -> String {
    // SAFETY: the library returns a pointer to a static, NUL-terminated string
    // with process lifetime.
    unsafe {
        let ptr = nova_backend_flavor();
        if ptr.is_null() {
            return String::from("<null>");
        }
        core::ffi::CStr::from_ptr(ptr)
            .to_string_lossy()
            .into_owned()
    }
}

fn fq_to_be_bytes(x: &Fq) -> [u8; FP_BYTES] {
    let le = x.into_bigint().to_bytes_le();
    let mut be = [0u8; FP_BYTES];
    for (i, byte) in le.iter().enumerate() {
        be[FP_BYTES - 1 - i] = *byte;
    }
    be
}

fn fq_zero_bytes(b: &[u8; FP_BYTES]) -> bool {
    b.iter().all(|&x| x == 0)
}

fn encode_g1(p: &G1Affine) -> G1Bytes {
    let mut out = G1Bytes {
        b: [0u8; G1_AFFINE_BYTES],
    };
    if let Some((x, y)) = p.xy() {
        out.b[..FP_BYTES].copy_from_slice(&fq_to_be_bytes(&x));
        out.b[FP_BYTES..].copy_from_slice(&fq_to_be_bytes(&y));
    }
    /* `AffineRepr::xy()` returns None for the identity; the all-zero encoding
       is exactly what the C side skips. */
    out
}

fn decode_g1(b: &G1Bytes) -> Option<G1Affine> {
    let xb: [u8; FP_BYTES] = b.b[..FP_BYTES].try_into().ok()?;
    let yb: [u8; FP_BYTES] = b.b[FP_BYTES..].try_into().ok()?;
    if fq_zero_bytes(&xb) && fq_zero_bytes(&yb) {
        return Some(G1Affine::identity());
    }
    let x = Fq::from_be_bytes_mod_order(&xb);
    let y = Fq::from_be_bytes_mod_order(&yb);
    Some(G1Affine::new_unchecked(x, y))
}

fn encode_fr(s: &Fr) -> FrBytes {
    let le = s.into_bigint().to_bytes_le();
    let mut out = FrBytes { b: [0u8; FR_BYTES] };
    let n = le.len().min(FR_BYTES);
    out.b[..n].copy_from_slice(&le[..n]);
    out
}

/// BLS12-381 G1 multi-scalar multiplication via the native backend.
///
/// Returns `Some(sum_i scalars[i] * points[i])` on success, or `None` if the
/// native call failed (so the caller may fall back to arkworks).  Encodings are
/// validated bit-for-bit against arkworks in the crate's `native` tests.
pub fn native_msm_g1(points: &[G1Affine], scalars: &[Fr]) -> Option<G1Affine> {
    debug_assert_eq!(points.len(), scalars.len(), "msm length mismatch");
    let n = points.len().min(scalars.len());
    if n == 0 {
        return Some(G1Affine::identity());
    }

    let pts: Vec<G1Bytes> = points[..n].iter().map(encode_g1).collect();
    let scs: Vec<FrBytes> = scalars[..n].iter().map(encode_fr).collect();

    let mut out = G1Bytes {
        b: [0u8; G1_AFFINE_BYTES],
    };
    // SAFETY: `pts`/`scs` are borrowed for the whole call and have length n;
    // `out` is a single, uniquely-owned stack slot. The C side does not retain
    // any pointer.
    let status = unsafe { nova_msm_g1(&mut out, pts.as_ptr(), scs.as_ptr(), n) };
    match status {
        STATUS_OK => decode_g1(&out),
        STATUS_INFINITY_OUTPUT => Some(G1Affine::identity()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::CurveGroup;
    use ark_ec::VariableBaseMSM;

    #[test]
    fn version_matches_header() {
        assert_eq!(backend_version(), MODULE_VERSION);
        assert!(!backend_flavor().is_empty());
    }

    #[test]
    fn msm_matches_arkworks_small() {
        let g = G1Affine::generator();
        let points = vec![g, g, g, g];
        let scalars = vec![
            Fr::from(2u64),
            Fr::from(3u64),
            Fr::from(0u64),
            Fr::from(11u64),
        ];
        let native = native_msm_g1(&points, &scalars).expect("native msm");
        let reference = G1Affine::from(g1_msm_reference(&points, &scalars));
        assert_eq!(native, reference);
    }

    // Reference value via arkworks' own MSM.
    fn g1_msm_reference(points: &[G1Affine], scalars: &[Fr]) -> ark_bls12_381::G1Projective {
        <ark_bls12_381::G1Projective as VariableBaseMSM>::msm(points, scalars).unwrap()
    }

    #[test]
    fn msm_handles_identity_and_zero() {
        let g = G1Affine::generator();
        let points = vec![g, G1Affine::identity(), g];
        let scalars = vec![Fr::from(5u64), Fr::from(9u64), Fr::from(0u64)];
        let native = native_msm_g1(&points, &scalars).expect("native msm");
        let reference = G1Affine::from(g1_msm_reference(&points, &scalars));
        assert_eq!(native, reference);
        assert_eq!(native_msm_g1(&[], &[]).unwrap(), G1Affine::identity());
    }

    #[test]
    fn msm_matches_arkworks_full_width() {
        // 64 pseudo-random bases and full-width scalars, to exercise the
        // 48-byte/32-byte encodings beyond tiny u64 values.
        let g = G1Affine::generator();
        let mut points = Vec::new();
        let mut scalars = Vec::new();
        let mut acc = Fr::from(0x9E3779B97F4A7C15u64);
        for i in 0..64u64 {
            acc = acc * Fr::from(6364136223846793005u64) + Fr::from(i + 1);
            scalars.push(acc);
            points.push((g * Fr::from(i * 2654435761u64 + 7)).into_affine());
        }
        let native = native_msm_g1(&points, &scalars).expect("native msm");
        let reference = G1Affine::from(g1_msm_reference(&points, &scalars));
        assert_eq!(native, reference);
    }

    #[test]
    fn roundtrip_encoding_large_coordinates() {
        // Exercise full-width coordinates (not just small u64 scalars).
        let p = (G1Affine::generator() * Fr::from(1234567890123456789u64)).into_affine();
        let bytes = encode_g1(&p);
        let back = decode_g1(&bytes).expect("decode");
        assert_eq!(p, back);
    }
}
