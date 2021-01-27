#pragma once
#include <qc.h>
#include <stddef.h>
#include <stdint.h>
#include "chacha20.h"

struct chacha20_state {
    uint32_t mat[16];
    size_t used;
    uint8_t buf[64];
};

qc_result chacha20_random_bytes(size_t len, uint8_t dst[static len], qc_err* err);
void chacha20_quarter_round(uint32_t* a, uint32_t* b, uint32_t* c, uint32_t* d);
void chacha20_next(chacha20_state* state);
void chacha20_process_bytes(chacha20_state* state, size_t len, uint8_t buf[static len]);
