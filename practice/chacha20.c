#ifdef NDEBUG
#undef NDEBUG
#endif

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

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

uint32_t chacha20_init[16] = {
    [0] = 0x61707865, [1] = 0x3320646e, [2] = 0x79622d32, [3] = 0x6b206574,
    [12] = 0, // counter
};
uint32_t chacha20_copy[16];

void set_key(uint32_t const k[static 8]) {
    memcpy(&chacha20_init[4], k, 8 * sizeof(uint32_t));
}

void set_nonce(uint32_t const n[static 3]) {
    memcpy(&chacha20_init[13], n, 3 * sizeof(uint32_t));
}

void chacha20_round() {
    ++chacha20_init[12];
    memcpy(chacha20_copy, chacha20_init, sizeof(chacha20_init));
    uint32_t *s = chacha20_copy;
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
        chacha20_copy[i] += chacha20_init[i];
    }
}

// all constants are taken from https://tools.ietf.org/html/rfc8439
int main() {
    set_key((uint32_t[8]){
        0x03020100,
        0x07060504,
        0x0b0a0908,
        0x0f0e0d0c,
        0x13121110,
        0x17161514,
        0x1b1a1918,
        0x1f1e1d1c,
    });
    set_nonce((uint32_t[3]){0x09000000, 0x4a000000, 0x00000000});
    chacha20_round();
    assert(memcmp(chacha20_copy,
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
                  16 * sizeof(uint32_t)) == 0);
}
