#include <stdint.h>
#include <qc.h>
#include "chacha20_impl.h"

void chacha20_quarter_round(uint32_t* a, uint32_t* b, uint32_t* c, uint32_t* d) {
    *a += *b;
    *d ^= *a;
    *d = qc_rotl32(*d, 16);
    *c += *d;
    *b ^= *c;
    *b = qc_rotl32(*b, 12);
    *a += *b;
    *d ^= *a;
    *d = qc_rotl32(*d, 8);
    *c += *d;
    *b ^= *c;
    *b = qc_rotl32(*b, 7);
}
