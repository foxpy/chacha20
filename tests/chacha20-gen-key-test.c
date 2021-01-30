#include <string.h>
#include <stdint.h>
#include <qc.h>
#include "chacha20.h"

int main(void) {
    qc_err* err = qc_err_new();
    uint8_t key[32] = {0};
    qc_result result = chacha20_gen_key(key, err);
    qc_assert(result == QC_SUCCESS, "Failed to generate ChaCha20 key: \"%s\"", qc_err_get(err));
    qc_err_free(err);
    qc_assert(memcmp(key, (uint8_t[32]){0}, 32) != 0, "chacha20_gen_key() did not actually write a key");
}
