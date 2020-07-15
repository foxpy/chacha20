#include "cc20.h"

int main(int argc, char *argv[static argc]) {
    struct config cfg;
    if (parse_args(argc, argv, &cfg) != 0) {
        fprintf(stderr, "%s\n", cfg.err);
    }
    if (cfg.help) {
        print_help(&cfg, EXIT_SUCCESS);
    }
    if (cfg.decrypt) {
        die("Decryption is not implemented");
    }
    return (main_loop(cfg.input, cfg.output) == 0) ? EXIT_SUCCESS
                                                   : EXIT_FAILURE;
}

int main_loop(FILE *input, FILE *output) {
    size_t nread;
    uint8_t buf[32];
    while ((nread = fread(buf, sizeof(uint8_t), 32, input)) > 0) {
        if (fwrite(buf, sizeof(uint8_t), nread, output) != nread) {
            return -1;
        }
    }
    return 0;
}
