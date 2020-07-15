#include "cc20.h"

int parse_args(int argc, char *argv[static argc], struct config *cfg) {
    if (argc < 2) {
        cfg->err = "Error: No password specified";
        return -1;
    }
    cfg->decrypt = false;
    cfg->help = false;
    cfg->input = stdin;
    cfg->output = stdout;
    memcpy(&cfg->key, (uint8_t[32]){0}, sizeof(uint8_t) * 32);
    cfg->program_name = argv[0];
    cfg->err = NULL;
    return 0;
}

__attribute__((noreturn)) void print_help(struct config const *cfg,
                                          int status) {
    fprintf(stderr, "Usage: %s KEY\n", cfg->program_name);
    exit(status);
}
