#include "cc20.h"

int main(int argc, char *argv[static argc]) {
    struct config cfg;
    if (parse_args(argc, argv, &cfg) != 0) {
        fprintf(stderr, "%s", cfg.err);
    }
    if (cfg.help) {
        print_help(&cfg, EXIT_SUCCESS);
    }
    if (cfg.decrypt) {
        die("Decryption is not implemented");
    }
}
