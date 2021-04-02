#pragma once
#include <stdint.h>
#include <qc.h>

typedef struct poly1305_state poly1305_state;
poly1305_state* poly1305_new(uint8_t const key[static 32]);
void poly1305_free(poly1305_state* state);

qc_result poly1305_gen_key(uint8_t dst[static 32], qc_err* err);
