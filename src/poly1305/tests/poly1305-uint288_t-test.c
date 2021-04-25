#include <string.h>
#include <stddef.h>
#include <qc.h>
#include "../poly1305_impl.h"

void serialization(qc_rnd* rnd) {
    uint8_t original[36] = {0};
    qc_rnd_buf(rnd, 36, original);
    uint288_t u288;
    poly1305_uint288_t_from_le_bytes(&u288, original);
    uint8_t copy[36] = {0};
    poly1305_uint288_t_to_le_bytes(copy, &u288);
    qc_assert(memcmp(original, copy, 36) == 0, "uint288_t (de)serialization is broken");
}

int main(void) {
    qc_rnd rnd;
    qc_err* err = qc_err_new();
    qc_assert(qc_rnd_init(&rnd, err) == QC_SUCCESS, "Random initialization failed: %s", qc_err_get(err));
    for (size_t i = 0; i < 10; ++i) serialization(&rnd);
    qc_err_free(err);
}
