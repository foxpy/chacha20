#include <string.h>
#include <stddef.h>
#include <qc.h>
#include "../poly1305_impl.h"

static void serialization(qc_rnd* rnd) {
    uint8_t original[36];
    qc_rnd_buf(rnd, 36, original);
    uint288_t u288;
    poly1305_uint288_t_from_le_bytes(&u288, original);
    uint8_t copy[36];
    poly1305_uint288_t_to_le_bytes(copy, &u288);
    qc_assert(memcmp(original, copy, 36) == 0, "uint288_t (de)serialization is broken");
}

void iteration(uint8_t const a[36], uint8_t const b[36], uint8_t const expected[36],
               void (f)(uint288_t*, uint288_t const*), char const* f_name) {
    uint288_t u288_a, u288_b;
    poly1305_uint288_t_from_le_bytes(&u288_a, a);
    poly1305_uint288_t_from_le_bytes(&u288_b, b);
    f(&u288_a, &u288_b);
    uint8_t actual[36] = {0};
    poly1305_uint288_t_to_le_bytes(actual, &u288_a);
    qc_assert(memcmp(actual, expected, 36) == 0, "%s does not produce expected results", f_name);
}

#define ITER(a, b, expected, f) iteration(a, b, expected, f, #f)

void addition(void) {
    // clang-format off
    ITER(
            ((uint8_t const[36]){15, 0}),
            ((uint8_t const[36]){18, 0}),
            ((uint8_t const[36]){33, 0}),
            poly1305_uint288_t_add
    );
    ITER(
            ((uint8_t const[36]){27, 6,  0}),
            ((uint8_t const[36]){34, 18, 0}),
            ((uint8_t const[36]){61, 24, 0}),
            poly1305_uint288_t_add
    );
    ITER(
            ((uint8_t const[36]){225, 139, 100, 16, 234, 221, 76, 113, 251, 0, 0}),
            ((uint8_t const[36]){8,   251, 184, 16, 89,  79,  13, 181, 108, 0, 0}),
            ((uint8_t const[36]){233, 134, 29,  33, 67,  45,  90, 38,  104, 1, 0}),
            poly1305_uint288_t_add
    );
    ITER(
            ((uint8_t const[36]){68,  11,  52,  199, 236, 83,  84,  13,  34,  30,  175, 155, 128, 87,  37,  179, 115, 130, 184, 61,  228, 215, 136, 110, 152, 208, 41,  171, 165, 184, 96,  85,  57,  103, 197, 95}),
            ((uint8_t const[36]){206, 216, 228, 113, 119, 50,  223, 131, 159, 98,  208, 143, 14,  19,  106, 197, 240, 66,  100, 122, 135, 203, 142, 78,  170, 87,  3,   133, 234, 83,  57,  39,  228, 254, 175, 109}),
            ((uint8_t const[36]){18,  228, 24,  57,  100, 134, 51,  145, 193, 128, 127, 43,  143, 106, 143, 120, 100, 197, 28,  184, 107, 163, 23,  189, 66,  40,  45,  48,  144, 12,  154, 124, 29,  102, 117, 205}),
            poly1305_uint288_t_add
    );
    // clang-format on
}

void multiplication(void) {
    // clang-format off
    ITER(
            ((uint8_t const[36]){2, 0}),
            ((uint8_t const[36]){3, 0}),
            ((uint8_t const[36]){6, 0}),
            poly1305_uint288_t_mul
    );
    ITER(
            ((uint8_t const[36]){24,    1, 0, 0}),
            ((uint8_t const[36]){38,    6, 0, 0}),
            ((uint8_t const[36]){144, 185, 6, 0}),
            poly1305_uint288_t_mul
    );
    // clang-format on
}

#undef ITER

int main(void) {
    qc_rnd rnd;
    qc_err* err = qc_err_new();
    qc_assert(qc_rnd_init(&rnd, err) == QC_SUCCESS, "Random initialization failed: %s", qc_err_get(err));
    for (size_t i = 0; i < 10; ++i) {
        serialization(&rnd);
    }
    addition();
    multiplication();
    qc_err_free(err);
}
