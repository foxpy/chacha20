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

void addition_iteration(uint8_t const a[36], uint8_t const b[36], uint8_t const expected[36]) {
    uint288_t u288_a, u288_b;
    poly1305_uint288_t_from_le_bytes(&u288_a, a);
    poly1305_uint288_t_from_le_bytes(&u288_b, b);
    poly1305_uint288_t_add(&u288_a, &u288_b);
    uint8_t actual[36] = {0};
    poly1305_uint288_t_to_le_bytes(actual, &u288_a);
    qc_assert(memcmp(actual, expected, 36) == 0, "uint288_t addition does not produce expected results");
}

void addition(void) {
    // clang-format off
    addition_iteration(
        (uint8_t const[36]){15, 0},
        (uint8_t const[36]){18, 0},
        (uint8_t const[36]){33, 0}
    );
    addition_iteration(
            (uint8_t const[36]){27, 6,  0},
            (uint8_t const[36]){34, 18, 0},
            (uint8_t const[36]){61, 24, 0}
    );
    addition_iteration(
            (uint8_t const[36]){225, 139, 100, 16, 234, 221, 76, 113, 251, 0, 0},
            (uint8_t const[36]){8,   251, 184, 16, 89,  79,  13, 181, 108, 0, 0},
            (uint8_t const[36]){233, 134, 29,  33, 67,  45,  90, 38,  104, 1, 0}
    );
    // clang-format on
}

int main(void) {
    qc_rnd rnd;
    qc_err* err = qc_err_new();
    qc_assert(qc_rnd_init(&rnd, err) == QC_SUCCESS, "Random initialization failed: %s", qc_err_get(err));
    for (size_t i = 0; i < 10; ++i) {
        serialization(&rnd);
    }
    addition();
    qc_err_free(err);
}
