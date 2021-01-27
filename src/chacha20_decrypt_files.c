#include <stddef.h>
#include <stdint.h>
#include "chacha20.h"
#include "chacha20_impl.h"

void chacha20_decrypt_bytes(chacha20_state* state, size_t len, uint8_t buf[static len]) {
    chacha20_process_bytes(state, len, buf);
}
