#include <qc.h>
#include <stddef.h>
#include <string.h>
#include "chacha20.h"
#include "chacha20_impl.h"

chacha20_state* chacha20_new(uint8_t const key[static 32], uint8_t const nonce[static 12]) {
    chacha20_state* ret = qc_malloc(sizeof(chacha20_state));
    ret->mat[0] = 0x61707865;
    ret->mat[1] = 0x3320646e;
    ret->mat[2] = 0x79622d32;
    ret->mat[3] = 0x6b206574;
    for (size_t i = 0; i < 8; ++i) {
        ret->mat[4 + i] = qc_u32_from_le(&key[i * sizeof(uint32_t)]);
    }
    ret->mat[12] = 0;
    for (size_t i = 0; i < 3; ++i) {
        ret->mat[13 + i] = qc_u32_from_le(&nonce[i * sizeof(uint32_t)]);
    }
    ret->used = sizeof(ret->buf);
    memset(ret->buf, 0, sizeof(ret->buf));
    return ret;
}
