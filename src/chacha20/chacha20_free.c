#include <stdlib.h>
#include <string.h>
#include "chacha20.h"
#include "chacha20_impl.h"

void chacha20_free(chacha20_state* state) {
    memset(state, 0, sizeof(chacha20_state));
    free(state);
}
