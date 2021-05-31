#pragma once
#include <stddef.h>
#include <poly1305.h>

typedef unsigned __int128 uint128_t;

#define MUL(out, x, y) out = ((uint128_t) (x) * (y))
#define ADD(out, in) out += in
#define ADDLO(out, in) out += in
#define SHR(in, shift) (unsigned long long) ((in) >> (shift))
#define LO(in) (unsigned long long) (in)

#define POLY1305_NOINLINE __attribute__((noinline))
#define poly1305_block_size 16

typedef struct poly1305_state_internal_t {
    unsigned long long r[3];
    unsigned long long h[3];
    unsigned long long pad[2];
    size_t leftover;
    unsigned char buffer[poly1305_block_size];
    unsigned char final;
} poly1305_state_internal_t;
