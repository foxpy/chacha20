#include "cc20.h"

int main() {
    struct chacha20_state state;
    uint32_t key[8] = {0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
                       0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c};
    uint32_t nonce[3] = {0x09000000, 0x4a000000, 0x00000000};
    uint8_t buf[64] = {0};
    chacha20_init(&state, (uint8_t *)key, (uint8_t *)nonce);
    chacha20_next(&state, buf);
    if (memcmp(state.copy,
               (uint32_t[16]){
                   0xe4e7f110,
                   0x15593bd1,
                   0x1fdd0f50,
                   0xc47120a3,
                   0xc7f4d1c7,
                   0x0368c033,
                   0x9aaa2204,
                   0x4e6cd4c3,
                   0x466482d2,
                   0x09aa9f07,
                   0x05d7c214,
                   0xa2028bd9,
                   0xd19c12b5,
                   0xb94e16de,
                   0xe883d0cb,
                   0x4e3c50a2,
               },
               sizeof(uint32_t) * 16) != 0) {
        qc_die("ChaCha20 test failed");
    };
}
