#include <string.h>
#include <stdint.h>
#include <qc.h>
#include "chacha20.h"

int main(void) {
    qc_err* err = qc_err_new();
    uint8_t nonce[12] = {0};
    qc_result result = chacha20_gen_nonce(nonce, err);
    qc_assert(result == QC_SUCCESS, "Failed to generate ChaCha20 nonce: \"%s\"", qc_err_get(err));
    qc_err_free(err);
    qc_assert(memcmp(nonce, (uint8_t[12]){0}, 12) != 0, "chacha20_gen_nonce() did not actually write a nonce");
}
