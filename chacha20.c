#include "cc20.h"

static void qround(uint32_t* a, uint32_t* b, uint32_t* c, uint32_t* d) {
    *a += *b;
    *d ^= *a;
    *d = qc_rotl32(*d, 16);
    *c += *d;
    *b ^= *c;
    *b = qc_rotl32(*b, 12);
    *a += *b;
    *d ^= *a;
    *d = qc_rotl32(*d, 8);
    *c += *d;
    *b ^= *c;
    *b = qc_rotl32(*b, 7);
}

void chacha20_init(struct chacha20_state *state, uint8_t key[static 32],
                   uint8_t nonce[static 12]) {
    state->state[0] = 0x61707865;
    state->state[1] = 0x3320646e;
    state->state[2] = 0x79622d32;
    state->state[3] = 0x6b206574;
    memcpy(&state->state[4], key, sizeof(uint8_t) * 32);
    state->state[12] = 0;
    memcpy(&state->state[13], nonce, sizeof(uint8_t) * 12);
}

void chacha20_next(struct chacha20_state *state, uint8_t buf[static 64]) {
    ++(state->state[12]);
    memcpy(state->copy, state->state, sizeof(uint32_t) * 16);
    uint32_t *s = state->copy;
    uint32_t *output = (uint32_t *)buf;
    for (size_t i = 0; i < 10; ++i) {
        qround(&s[0], &s[4], &s[8], &s[12]);
        qround(&s[1], &s[5], &s[9], &s[13]);
        qround(&s[2], &s[6], &s[10], &s[14]);
        qround(&s[3], &s[7], &s[11], &s[15]);
        qround(&s[0], &s[5], &s[10], &s[15]);
        qround(&s[1], &s[6], &s[11], &s[12]);
        qround(&s[2], &s[7], &s[8], &s[13]);
        qround(&s[3], &s[4], &s[9], &s[14]);
    }
    for (size_t i = 0; i < 16; ++i) {
        state->copy[i] += state->state[i];
    }
    for (size_t i = 0; i < 16; ++i) {
        output[i] ^= state->copy[i];
    }
}
