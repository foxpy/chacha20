#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <qc.h>
#include "chacha20_impl.h"

qc_result chacha20_random_bytes(size_t len, uint8_t dst[static len], qc_err* err) {
    qc_rnd rnd;
    for (size_t i = 0; i < len; i += sizeof(uint64_t)) {
        if (qc_rnd_init(&rnd, err) == QC_FAILURE) {
            qc_err_append_front(err, "Failed to obtain entropy from operating system");
            return QC_FAILURE;
        } else {
            uint64_t buf = qc_rnd64(&rnd);
            memmove(&dst[i], &buf, qc_min(sizeof(uint64_t), len - sizeof(uint64_t) * i));
        }
    }
    return QC_SUCCESS;
}
