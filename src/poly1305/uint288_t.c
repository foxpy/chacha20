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

void poly1305_uint288_t_add(uint288_t* a, uint288_t const* b) {
    uint32_t carry = 0;
    for (size_t i = 0; i < 9; ++i) {
        uint64_t accumulator = 0;
        accumulator += a->u[i];
        accumulator += b->u[i];
        accumulator += carry;
        carry = (uint32_t)(accumulator >> 32);
        accumulator &= UINT32_MAX;
        a->u[i] = (uint32_t) accumulator;
    }
}
