#pragma once
#include <stdint.h>

typedef struct {
    uint32_t u[9];
} uint288_t;

void poly1305_uint288_t_from_le_bytes(uint288_t* dst, uint8_t const src[36]);
void poly1305_uint288_t_to_le_bytes(uint8_t dst[36], uint288_t const* src);
