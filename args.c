#include "cc20.h"

static int parse_key(char const *str, struct config *cfg) {
    if (strlen(str) != 64) {
        cfg->err = "Key format is 32 bytes in hexadecimal notation";
        return -1;
    }
    for (size_t i = 0; i < 32; ++i) {
        unsigned u;
        sscanf(&str[2 * i], "%02x", &u);
        cfg->key[i] = (uint8_t)(u % UINT8_MAX);
    }
    return 0;
}

static int open_input_file(char const *str, struct config *cfg) {
    FILE *input;
    if ((input = fopen(str, "rb")) == NULL) {
        cfg->err = "Can't open input file";
        return -1;
    }
    cfg->input = input;
    return 0;
}

static int open_output_file(char const *str, struct config *cfg) {
    FILE *output;
    if ((output = fopen(str, "wb")) == NULL) {
        cfg->err = "Can't open output file";
        return -1;
    }
    cfg->output = output;
    return 0;
}

int parse_args(int argc, char *argv[static argc], struct config *cfg) {
    cfg->decrypt = false;
    cfg->help = false;
    cfg->input = stdin;
    cfg->output = stdout;
    memcpy(&cfg->key, (uint8_t[32]){0}, sizeof(uint8_t) * 32);
    cfg->program_name = argv[0];
    cfg->err = NULL;
    ++argv;
    --argc;

    int npos = 0;
    for (int i = 0; i < argc; ++i) {
        if (strcmp("--help", argv[i]) == 0) {
            cfg->help = true;
        } else if (strcmp("--decrypt", argv[i]) == 0) {
            cfg->decrypt = true;
        } else {
            ++npos;
            switch (npos) {
            case 1:
                if (parse_key(argv[i], cfg) != 0) {
                    return -1;
                }
                break;
            case 2:
                if (open_input_file(argv[i], cfg) != 0) {
                    return -1;
                }
                break;
            case 3:
                if (open_output_file(argv[i], cfg) != 0) {
                    return -1;
                }
                break;
            default:
                cfg->err = "Too much positional arguments!";
                return -1;
            }
        }
    }
    if (npos == 0) {
        cfg->err = "No key specified";
        return -1;
    }
    return 0;
}

__attribute__((noreturn)) void print_help(struct config const *cfg,
                                          int status) {
    fprintf(stderr, "Usage: %s [--help] [--decrypt] KEY [INPUT] [OUTPUT]\n",
            cfg->program_name);

    exit(status);
}
