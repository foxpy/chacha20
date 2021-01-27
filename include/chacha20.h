#pragma once
#include <stddef.h>
#include <stdint.h>
#include <qc.h>

typedef struct chacha20_state chacha20_state;
chacha20_state* chacha20_new(uint8_t const key[static 32], uint8_t const nonce[static 12]);
void chacha20_encrypt_bytes(chacha20_state* state, size_t len, uint8_t buf[static len]);
void chacha20_decrypt_bytes(chacha20_state* state, size_t len, uint8_t buf[static len]);
void chacha20_free(chacha20_state* state);

qc_result chacha20_gen_key(uint8_t dst[static 32], qc_err* err);
qc_result chacha20_gen_nonce(uint8_t dst[static 12], qc_err* err);
