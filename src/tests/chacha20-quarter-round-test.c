#include <stdint.h>
#include "../chacha20_impl.h"

int main(void) {
    uint32_t a = 0x11111111, b = 0x01020304, c = 0x9b8d6f43, d = 0x01234567;
    chacha20_quarter_round(&a, &b, &c, &d);
    qc_assert(a == UINT32_C(0xea2a92f4) && b == UINT32_C(0xcb1cf8ce) &&
              c == UINT32_C(0x4581472e) && d == UINT32_C(0x5881c4bb),
              "chacha20_quarter_round() acts incorrectly");
}
