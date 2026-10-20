#include <blst.h>
#include "nova_backend.h"

#include <cstdint>
#include <cstring>
#include <vector>

/*
 * nova_backend.cpp — the concrete native backend.
 *
 * Field/curve arithmetic (the Pippenger MSM) is delegated to the vendored
 * blst library (Apache-2.0, Supranational).  This translation unit only:
 *
 *   - defines the stable C ABI declared in nova_backend.h, and
 *   - converts between that byte encoding and blst's native types.
 */

namespace {
constexpr unsigned kScalarBits = 255; /* bit length of BLS12-381's Fr modulus */

/* blst's `blst_p1s_mult_pippenger` scratch must be 64-byte aligned; a plain
 * `std::vector<limb_t>` is only 8-byte aligned, which makes the asm paths take
 * the slow (or wrong) bucket path.  Keep an overallocated vector and hand the
 * caller a pointer rounded up to 64 bytes. */
class AlignedScratch {
  public:
    explicit AlignedScratch(size_t bytes)
        : storage_((bytes + sizeof(limb_t) - 1) / sizeof(limb_t) + 16) {
        uintptr_t base = reinterpret_cast<uintptr_t>(storage_.data());
        uintptr_t aligned = (base + 63) & ~uintptr_t(63);
        ptr_ = reinterpret_cast<limb_t *>(aligned);
    }
    limb_t *get() const { return ptr_; }

  private:
    std::vector<limb_t> storage_;
    limb_t *ptr_;
};

inline bool is_fp_zero(const uint8_t b[48]) {
    for (int i = 0; i < 48; i++) {
        if (b[i] != 0) return false;
    }
    return true;
}

/* NOTE: no per-point on-curve / subgroup validation here.  blst's
 * `blst_p1_affine_in_g1` is a full final exponentiation (~ms/point), which
 * would dwarf the MSM once n grows into the thousands.  Inputs come from the
 * deterministic in-process basis derivation (guaranteed valid); the final MSM
 * output is sanity-checked once after the call. */
inline bool decode_scalar(const nova_backend_fr_t *in, blst_scalar *out) {
    blst_scalar_from_lendian(out, in->b);
    return blst_scalar_fr_check(out);
}

inline bool is_scalar_zero(const blst_scalar *s) {
    for (int i = 0; i < 32; i++) {
        if (s->b[i] != 0) return false;
    }
    return true;
}

inline void encode_g1(const blst_p1_affine *in, nova_backend_g1_t *out) {
    blst_bendian_from_fp(out->b, &in->x);
    blst_bendian_from_fp(out->b + 48, &in->y);
}
} // namespace

extern "C" {

uint32_t nova_backend_version(void) {
    return NOVA_BACKEND_MODULE_VERSION;
}

const char *nova_backend_flavor(void) {
    return "blst-pippenger; cpu";
}

nova_backend_status nova_msm_g1(nova_backend_g1_t *out,
                                const nova_backend_g1_t *points,
                                const nova_backend_fr_t *scalars,
                                size_t npoints) {
    if (out == nullptr) {
        return NOVA_BACKEND_INVALID_ARGUMENT;
    }
    if (npoints == 0) {
        memset(out, 0, sizeof(*out));
        return NOVA_BACKEND_INFINITY_OUTPUT;
    }
    if (points == nullptr || scalars == nullptr) {
        return NOVA_BACKEND_INVALID_ARGUMENT;
    }

    std::vector<blst_p1_affine> pts;
    std::vector<blst_scalar> scs;
    pts.reserve(npoints);
    scs.reserve(npoints);

    for (size_t i = 0; i < npoints; i++) {
        if (is_fp_zero(points[i].b) && is_fp_zero(points[i].b + 48)) {
            continue; /* infinity base contributes nothing */
        }
        blst_scalar sc;
        if (!decode_scalar(&scalars[i], &sc)) {
            return NOVA_BACKEND_INVALID_ARGUMENT;
        }
        if (is_scalar_zero(&sc)) {
            continue; /* zero scalar contributes nothing */
        }
        blst_p1_affine pt;
        blst_fp_from_bendian(&pt.x, points[i].b);
        blst_fp_from_bendian(&pt.y, points[i].b + 48);
        pts.push_back(pt);
        scs.push_back(sc);
    }

    if (pts.empty()) {
        memset(out, 0, sizeof(*out));
        return NOVA_BACKEND_INFINITY_OUTPUT;
    }

    std::vector<const blst_p1_affine *> pp;
    std::vector<const byte *> sp;
    pp.reserve(pts.size());
    sp.reserve(scs.size());
    for (size_t i = 0; i < pts.size(); i++) {
        pp.push_back(&pts[i]);
        sp.push_back(reinterpret_cast<const byte *>(&scs[i]));
    }

    AlignedScratch scratch(blst_p1s_mult_pippenger_scratch_sizeof(pts.size()));

    blst_p1 agg;
    blst_p1s_mult_pippenger(&agg, pp.data(), pts.size(), sp.data(),
                            kScalarBits, scratch.get());

    if (blst_p1_is_inf(&agg)) {
        memset(out, 0, sizeof(*out));
        return NOVA_BACKEND_INFINITY_OUTPUT;
    }
    blst_p1_affine out_a;
    blst_p1_to_affine(&out_a, &agg);
    if (!blst_p1_affine_on_curve(&out_a)) {
        return NOVA_BACKEND_POINT_NOT_ON_CURVE;
    }
    encode_g1(&out_a, out);
    return NOVA_BACKEND_OK;
}

} // extern "C"
