#include "cc20.h"

__attribute__((noreturn)) void die(char const *msg) {
    fprintf(stderr, "%s", msg);
    exit(EXIT_FAILURE);
}
