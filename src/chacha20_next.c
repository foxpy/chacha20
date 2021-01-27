#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "chacha20_impl.h"

void chacha20_next(chacha20_state* state) {
    ++(state->mat[12]);
    uint32_t s[16];
    memmove(s, state->mat, sizeof(state->mat));
    for (size_t i = 0; i < 10; ++i) {
        chacha20_quarter_round(&s[0], &s[4], &s[8], &s[12]);
        chacha20_quarter_round(&s[1], &s[5], &s[9], &s[13]);
        chacha20_quarter_round(&s[2], &s[6], &s[10], &s[14]);
        chacha20_quarter_round(&s[3], &s[7], &s[11], &s[15]);
        chacha20_quarter_round(&s[0], &s[5], &s[10], &s[15]);
        chacha20_quarter_round(&s[1], &s[6], &s[11], &s[12]);
        chacha20_quarter_round(&s[2], &s[7], &s[8], &s[13]);
        chacha20_quarter_round(&s[3], &s[4], &s[9], &s[14]);
    }
    for (size_t i = 0; i < 16; ++i) {
        s[i] += state->mat[i];
    }
    state->used = 0;
    memmove(state->buf, s, sizeof(state->buf));
}
