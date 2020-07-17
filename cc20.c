#include "cc20.h"

int main(int argc, char *argv[static argc]) {
    struct config cfg;
    struct chacha20_state cc20;
    srand(clock() ^ time(NULL));
    uint8_t nonce[12];
    if (parse_args(argc, argv, &cfg) != 0) {
        if (cfg.help) {
            print_help(&cfg, EXIT_FAILURE);
        } else {
            fprintf(stderr, "%s\n", cfg.err);
        }
        return EXIT_FAILURE;
    }
    if (cfg.help) {
        print_help(&cfg, EXIT_SUCCESS);
    }
    if (cfg.decrypt) {
        if (fread(nonce, sizeof(uint8_t), 12, cfg.input) != 12) {
            die("Failed to read nonce");
        }
    } else {
        for (size_t i = 0; i < 12; ++i) {
            nonce[i] = rand();
        }
        if (fwrite(nonce, sizeof(uint8_t), 12, cfg.output) != 12) {
            die("Failed to write nonce");
        }
    }
    chacha20_init(&cc20, cfg.key, nonce);
    return (main_loop(cfg.input, cfg.output, &cc20) == 0) ? EXIT_SUCCESS
                                                          : EXIT_FAILURE;
}

int main_loop(FILE *input, FILE *output, struct chacha20_state *state) {
    size_t nread;
    uint8_t buf[64];
    while ((nread = fread(buf, sizeof(uint8_t), 64, input)) > 0) {
        chacha20_next(state, buf);
        if (fwrite(buf, sizeof(uint8_t), nread, output) != nread) {
            return -1;
        }
    }
    return 0;
}
