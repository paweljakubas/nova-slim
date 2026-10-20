/*
 * nova_backend.h — the C ABI of the nova-slim native backend library.
 *
 * This is the *only* surface Rust talks to.  Everything crossing the boundary
 * is a fixed-size, ABI-stable byte container; no C++ objects and no STL types
 * are ever exposed (vector-like layouts would not be FFI-safe).
 *
 * The one operation wired today is the BLS12-381 G1 multi-scalar
 * multiplication used by the Pedersen / HashPC commitments.  It is a *pure
 * accelerator*: the Rust wrapper falls back to arkworks whenever this library
 * is not compiled in, and the results are checked bit-for-bit against arkworks
 * in tests.
 *
 * Value encodings (all canonical, no Zcash "flag" bits):
 *   - scalar/Fr : 32 bytes, *little-endian* (blst's MSM scalar byte order,
 *                 byte[0] == least significant), canonical mod r.
 *   - Fp        : 48 bytes, *big-endian* (blst_fp_from_bendian format).
 *   - G1 affine : 96 bytes = x (48 BE) || y (48 BE).
 *   - G1 point at infinity : all coordinate bytes zero.
 *
 * TRUST MODEL / SECURITY NOTE:
 *   As in the sibling bls backend, no per-point on-curve or prime-subgroup
 *   validation is done in the hot loop (a final exponentiation per point would
 *   dwarf the MSM at large n).  Points here originate from the deterministic
 *   in-process basis derivation (already valid).  The MSM *output* is
 *   sanity-checked once (on-curve) after the call.
 */
#ifndef NOVA_BACKEND_H
#define NOVA_BACKEND_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NOVA_BACKEND_MODULE_VERSION   1
#define NOVA_BACKEND_FR_BYTES        32
#define NOVA_BACKEND_FP_BYTES        48
#define NOVA_BACKEND_G1_AFFINE_BYTES 96

typedef struct { uint8_t b[32]; } nova_backend_fr_t;
typedef struct { uint8_t b[96]; } nova_backend_g1_t;

typedef enum {
    NOVA_BACKEND_OK                    = 0,
    NOVA_BACKEND_INVALID_ARGUMENT      = 1,
    NOVA_BACKEND_POINT_NOT_ON_CURVE    = 2,
    NOVA_BACKEND_INFINITY_OUTPUT       = 3,
    NOVA_BACKEND_MSM_MISMATCH          = 4,
    NOVA_BACKEND_INTERNAL_ERROR        = 5,
} nova_backend_status;

/* Version of the native module and a short flavor string describing the
   compiled acceleration ("blst-pippenger; cpu"). */
uint32_t nova_backend_version(void);
const char *nova_backend_flavor(void);

/*
 * Multi-scalar multiplication over BLS12-381 G1:
 *   out = sum_i scalars[i] * points[i]
 *
 * `points` are affine G1 elements in the encoding above; all-zero-coordinate
 * points (infinity) and their paired scalars are skipped.  `scalars` are
 * 32-byte little-endian canonical Fr values.  If every pair is skipped,
 * NOVA_BACKEND_INFINITY_OUTPUT is returned and `out` is zeroed.
 */
nova_backend_status nova_msm_g1(nova_backend_g1_t *out,
                                const nova_backend_g1_t *points,
                                const nova_backend_fr_t *scalars,
                                size_t npoints);

#ifdef __cplusplus
}
#endif

#endif /* NOVA_BACKEND_H */
