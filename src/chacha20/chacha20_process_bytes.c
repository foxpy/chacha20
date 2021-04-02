#include <stddef.h>
#include <stdint.h>
#include "chacha20_impl.h"

void chacha20_process_bytes(chacha20_state* state, size_t len, uint8_t buf[static len]) {
    for (size_t i = 0; i < len; ++i) {
        if (state->used == sizeof(state->buf)) {
            chacha20_next(state);
        }
        buf[i] ^= state->buf[state->used];
        ++(state->used);
    }
}
