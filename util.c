#include "cc20.h"

__attribute__((noreturn)) void die(char const *msg) {
    fprintf(stderr, "%s\n", msg);
    exit(EXIT_FAILURE);
}
