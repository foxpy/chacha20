#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <assert.h>
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

static void poly1305_impl_uint288_t_mul_scalar(uint288_t* a, uint32_t s) {
    uint32_t carry = 0;
    for (size_t i = 0; i < 9; ++i) {
        uint64_t accumulator = a->u[i];
        accumulator *= s;
        accumulator += carry;
        carry = (uint32_t)(accumulator >> 32);
        accumulator &= UINT32_MAX;
        a->u[i] = (uint32_t) accumulator;
    }
}

static void poly1305_impl_uint288_t_mul_shift_right(uint288_t* a, size_t n) {
    assert(n < 9);
    for (ptrdiff_t i = 9; i >= (ptrdiff_t) n; --i) {
        a->u[i] = a->u[i-n];
    }
    for (size_t i = 0; i < n; ++i) {
        a->u[i] = 0;
    }
}

void poly1305_uint288_t_mul(uint288_t* a, uint288_t const* b) {
    uint288_t m[9];
    for (size_t i = 0; i < 9; ++i) {
        memcpy(&m[i], a, sizeof(uint288_t));
        poly1305_impl_uint288_t_mul_scalar(&m[i], b->u[i]);
        poly1305_impl_uint288_t_mul_shift_right(&m[i], i);
    }
    memset(a, 0, sizeof(uint288_t));
    for (size_t i = 0; i < 9; ++i) {
        poly1305_uint288_t_add(a, &m[i]);
    }
}
