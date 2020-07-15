#include "cc20.h"

#define PLUS(a, b) ((a) + (b))
#define XOR(a, b) ((a) ^ (b))
#define ROTL32(a, n) (((a) << (n)) | ((a) >> (32 - (n))))

#define QROUND(a, b, c, d)                                                     \
    {                                                                          \
        (a) = PLUS((a), (b));                                                  \
        (d) = XOR((d), (a));                                                   \
        (d) = ROTL32((d), 16);                                                 \
        (c) = PLUS((c), (d));                                                  \
        (b) = XOR((b), (c));                                                   \
        (b) = ROTL32((b), 12);                                                 \
        (a) = PLUS((a), (b));                                                  \
        (d) = XOR((d), (a));                                                   \
        (d) = ROTL32((d), 8);                                                  \
        (c) = PLUS((c), (d));                                                  \
        (b) = XOR((b), (c));                                                   \
        (b) = ROTL32((b), 7);                                                  \
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
        QROUND(s[0], s[4], s[8], s[12]);
        QROUND(s[1], s[5], s[9], s[13]);
        QROUND(s[2], s[6], s[10], s[14]);
        QROUND(s[3], s[7], s[11], s[15]);
        QROUND(s[0], s[5], s[10], s[15]);
        QROUND(s[1], s[6], s[11], s[12]);
        QROUND(s[2], s[7], s[8], s[13]);
        QROUND(s[3], s[4], s[9], s[14]);
    }
    for (size_t i = 0; i < 16; ++i) {
        state->copy[i] += state->state[i];
    }
    for (size_t i = 0; i < 16; ++i) {
        output[i] ^= state->copy[i];
    }
}
