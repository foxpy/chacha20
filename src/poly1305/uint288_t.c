#include <stdint.h>
#include <stddef.h>
#include <qc/endian.h>
#include "poly1305_impl.h"

void poly1305_uint288_t_from_le_bytes(uint288_t* dst, uint8_t const src[36]) {
    for (size_t i = 0; i < 9; ++i) {
        dst->u[i] = qc_u32_from_le(&src[4*i]);
    }
}

void poly1305_uint288_t_to_le_bytes(uint8_t dst[36], uint288_t const* src) {
    for (size_t i = 0; i < 9; ++i) {
        qc_u32_to_le(&dst[4*i], src->u[i]);
    }
}
