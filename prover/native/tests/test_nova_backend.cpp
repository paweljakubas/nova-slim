/*
 * test_nova_backend.cpp — ground-level tests for the native backend.
 *
 * These run through the same C ABI the Rust crate uses.  Known-truth is built
 * with blst directly (generator constants, scalar multiplication), so the
 * tests validate the MSM and encoding round-trips without depending on the
 * Rust side.  Rust-side cross-validation against arkworks lives in the prover
 * crate (feature "native").
 */
#include <blst.h>
#include <nova_backend.h>

#include <cstdint>
#include <cstdio>
#include <cstring>

namespace {

int failures = 0;
int checks = 0;

#define CHECK(cond)                                                       \
    do {                                                                  \
        checks++;                                                         \
        if (!(cond)) {                                                    \
            failures++;                                                   \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__,  \
                         #cond);                                          \
        }                                                                 \
    } while (0)

void scalar_from_u64(nova_backend_fr_t *out, uint64_t v) {
    std::memset(out->b, 0, 32);
    for (int i = 0; i < 8; i++) {
        out->b[i] = static_cast<uint8_t>((v >> (8 * i)) & 0xff);
    }
}

void g1_generator(nova_backend_g1_t *out) {
    const blst_p1_affine *g = blst_p1_affine_generator();
    blst_bendian_from_fp(out->b, &g->x);
    blst_bendian_from_fp(out->b + 48, &g->y);
}

blst_p1_affine decode_g1(const nova_backend_g1_t *in) {
    blst_p1_affine out;
    blst_fp_from_bendian(&out.x, in->b);
    blst_fp_from_bendian(&out.y, in->b + 48);
    return out;
}

bool g1_eq(const nova_backend_g1_t *a, const nova_backend_g1_t *b) {
    blst_p1_affine da = decode_g1(a);
    blst_p1_affine db = decode_g1(b);
    return blst_p1_affine_is_equal(&da, &db);
}

void test_version_and_flavor() {
    CHECK(nova_backend_version() == NOVA_BACKEND_MODULE_VERSION);
    const char *flavor = nova_backend_flavor();
    CHECK(flavor != nullptr && std::strlen(flavor) > 0);
}

void test_msm_single() {
    /* 1 * G == G */
    nova_backend_g1_t g, out;
    nova_backend_fr_t one;
    g1_generator(&g);
    scalar_from_u64(&one, 1);
    CHECK(nova_msm_g1(&out, &g, &one, 1) == NOVA_BACKEND_OK);
    CHECK(g1_eq(&g, &out));
}

void test_msm_two() {
    /* 2*G + 3*G == 5*G */
    nova_backend_g1_t gs[2], out;
    nova_backend_fr_t ss[2];
    g1_generator(&gs[0]);
    g1_generator(&gs[1]);
    scalar_from_u64(&ss[0], 2);
    scalar_from_u64(&ss[1], 3);

    CHECK(nova_msm_g1(&out, gs, ss, 2) == NOVA_BACKEND_OK);

    /* reference 5*G via blst */
    blst_scalar five;
    nova_backend_fr_t five_bytes;
    scalar_from_u64(&five_bytes, 5);
    blst_scalar_from_lendian(&five, five_bytes.b);
    blst_p1 g_proj, ref;
    blst_p1_from_affine(&g_proj, blst_p1_affine_generator());
    blst_p1_mult(&ref, &g_proj, five.b, 255);
    blst_p1_affine ref_a;
    blst_p1_to_affine(&ref_a, &ref);
    nova_backend_g1_t ref_bytes;
    blst_bendian_from_fp(ref_bytes.b, &ref_a.x);
    blst_bendian_from_fp(ref_bytes.b + 48, &ref_a.y);

    CHECK(g1_eq(&out, &ref_bytes));
}

void test_msm_skips_infinity_and_zero() {
    /* points = [G, inf], scalars = [4, 7]  ==>  4*G */
    nova_backend_g1_t gs[2], out;
    nova_backend_fr_t ss[2];
    g1_generator(&gs[0]);
    std::memset(gs[1].b, 0, sizeof(gs[1].b)); /* infinity */
    scalar_from_u64(&ss[0], 4);
    scalar_from_u64(&ss[1], 7);

    CHECK(nova_msm_g1(&out, gs, ss, 2) == NOVA_BACKEND_OK);

    blst_scalar four;
    nova_backend_fr_t four_bytes;
    scalar_from_u64(&four_bytes, 4);
    blst_scalar_from_lendian(&four, four_bytes.b);
    blst_p1 g_proj, ref;
    blst_p1_from_affine(&g_proj, blst_p1_affine_generator());
    blst_p1_mult(&ref, &g_proj, four.b, 255);
    blst_p1_affine ref_a;
    blst_p1_to_affine(&ref_a, &ref);
    nova_backend_g1_t ref_bytes;
    blst_bendian_from_fp(ref_bytes.b, &ref_a.x);
    blst_bendian_from_fp(ref_bytes.b + 48, &ref_a.y);

    CHECK(g1_eq(&out, &ref_bytes));
}

void test_msm_all_skipped_is_infinity() {
    nova_backend_g1_t gs[1], out;
    nova_backend_fr_t ss[1];
    g1_generator(&gs[0]);
    scalar_from_u64(&ss[0], 0); /* zero scalar => skipped */
    CHECK(nova_msm_g1(&out, gs, ss, 1) == NOVA_BACKEND_INFINITY_OUTPUT);

    /* zero-length => infinity */
    CHECK(nova_msm_g1(&out, gs, ss, 0) == NOVA_BACKEND_INFINITY_OUTPUT);
}

void test_msm_rejects_null() {
    nova_backend_g1_t g, out;
    nova_backend_fr_t one;
    g1_generator(&g);
    scalar_from_u64(&one, 1);
    CHECK(nova_msm_g1(nullptr, &g, &one, 1) == NOVA_BACKEND_INVALID_ARGUMENT);
    CHECK(nova_msm_g1(&out, nullptr, &one, 1) == NOVA_BACKEND_INVALID_ARGUMENT);
    CHECK(nova_msm_g1(&out, &g, nullptr, 1) == NOVA_BACKEND_INVALID_ARGUMENT);
}

void test_byte_count_macros() {
    CHECK(NOVA_BACKEND_FR_BYTES == 32);
    CHECK(NOVA_BACKEND_FP_BYTES == 48);
    CHECK(NOVA_BACKEND_G1_AFFINE_BYTES == 96);
    CHECK(sizeof(nova_backend_fr_t) == NOVA_BACKEND_FR_BYTES);
    CHECK(sizeof(nova_backend_g1_t) == NOVA_BACKEND_G1_AFFINE_BYTES);
}

} // namespace

int main() {
    test_version_and_flavor();
    test_msm_single();
    test_msm_two();
    test_msm_skips_infinity_and_zero();
    test_msm_all_skipped_is_infinity();
    test_msm_rejects_null();
    test_byte_count_macros();

    std::printf("%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
