#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <qc.h>
#include "chacha20.h"

typedef struct cfg {
    bool decrypt;
    FILE* input;
    FILE* output;
    uint8_t key[32];
} cfg;

static void free_config(cfg* c) {
    if (c->input != NULL && c->input != stdin) {
        fclose(c->input);
    }
    if (c->output != NULL && c->output != stdout) {
        fclose(c->output);
    }
    memset(c, 0, sizeof(cfg));
}

static qc_result open_file(char const* path, char const* mode, FILE* backup, FILE** dst, qc_err* err) {
    errno = 0;
    if (strcmp(path, "-") == 0) {
        *dst = backup;
    } else if ((*dst = fopen(path, mode)) == NULL) {
        qc_err_set(err, "Failed to open input file \"%s\": %s", path, strerror(errno));
        return QC_FAILURE;
    }
    return QC_SUCCESS;
}

static qc_result parse_key(uint8_t dst[32], char const* src, qc_err* err) {
    uint8_t* decoded;
    ptrdiff_t len = qc_hexstr_to_bytes(src, &decoded);
    if (len < 0) {
        qc_err_set(err, "Failed to parse \"%s\" as valid ChaCha20 key", src);
        return QC_FAILURE;
    } else if (len != 32) {
        qc_err_set(err, "ChaCha20 key should be %d bits long, but provided key is %td bits long", 256, len * 8);
        free(decoded);
        return QC_FAILURE;
    } else {
        memmove(dst, decoded, 32);
        free(decoded);
        return QC_SUCCESS;
    }
}

static qc_result parse_arguments(cfg* c, int argc, char* argv[], qc_err* err) {
    char const* input_file_str;
    char const* output_file_str;
    char const* key_str;
    qc_args* args = qc_args_new();
    qc_args_flag(args, 'd', "decrypt", &c->decrypt, "decrypt data");
    qc_args_string_default(args, "input", "-", &input_file_str, "input file, stdin if omitted");
    qc_args_string_default(args, "output", "-", &output_file_str, "output file, stdout if omitted");
    qc_args_string(args, "key", &key_str,
                   "256-bit little endian key in hexadecimal format "
                   "(example: 0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f)");
    memset(c, 0, sizeof(cfg));
    if (qc_args_parse(args, argc, argv, err) == QC_FAILURE || parse_key(c->key, key_str, err) == QC_FAILURE ||
        open_file(input_file_str, "rb", stdin, &c->input, err) == QC_FAILURE ||
        open_file(output_file_str, "wb", stdout, &c->output, err) == QC_FAILURE) {
        qc_args_free(args);
        free_config(c);
        return QC_FAILURE;
    } else {
        qc_args_free(args);
        return QC_SUCCESS;
    }
}

static qc_result main_loop(chacha20_state* cc20, FILE* dst, FILE* src, qc_err* err) {
    size_t nread;
    uint8_t buf[BUFSIZ];
    while ((nread = fread(buf, sizeof(uint8_t), BUFSIZ, src)) > 0) {
        chacha20_encrypt_bytes(cc20, nread, buf);
        errno = 0;
        if (fwrite(buf, sizeof(uint8_t), nread, dst) != nread) {
            qc_err_set(err, "Failed to write data: %s", strerror(errno));
            return QC_FAILURE;
        }
    }
    return QC_SUCCESS;
}

int main(int argc, char* argv[]) {
    qc_err* err = qc_err_new();
    cfg config;
    if (parse_arguments(&config, argc, argv, err) != QC_SUCCESS) {
        qc_err_fatal(err, "Failed to parse command line arguments");
    }
    qc_result result;
    uint8_t nonce[12];
    if (!config.decrypt) {
        if (chacha20_gen_nonce(nonce, err) == QC_FAILURE) {
            qc_err_fatal(err, "Failed to obtain nonce");
        }
        if (fwrite(nonce, sizeof(uint8_t), 12, config.output) != 12) {
            qc_err_fatal(err, "Failed to write nonce to output file");
        }
    } else {
        if (fread(nonce, sizeof(uint8_t), 12, config.input) != 12) {
            qc_err_fatal(err, "Failed to read nonce from file");
        }
    }
    chacha20_state* cc20 = chacha20_new(config.key, nonce);
    result = main_loop(cc20, config.output, config.input, err);
    chacha20_free(cc20);
    free_config(&config);
    if (result == QC_FAILURE) {
        qc_err_fatal(err, "Critical error during processing data");
    } else {
        qc_err_free(err);
        return EXIT_SUCCESS;
    }
}
