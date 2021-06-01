#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <qc.h>
#include <chacha20.h>
#include <poly1305.h>

typedef struct config {
    bool encrypt;
    FILE* input;
    FILE* output;
    uint8_t key[32];
} config;

static qc_result key_from_str(char const* src, uint8_t dst[static 32], qc_err* err) {
    uint8_t* bytes;
    ptrdiff_t len = qc_hexstr_to_bytes(src, &bytes);
    if (len == -1) {
        qc_err_set(err, "Failed to parse ChaCha20 key from invalid hexadecimal string: %s", src);
        return QC_FAILURE;
    } else if (len != 32) {
        free(bytes);
        qc_err_set(err, "Failed to parse ChaCha20 key: Invalid number of bytes in hexadecimal string: %td", len);
        return QC_FAILURE;
    } else {
        memmove(dst, bytes, 32);
        free(bytes);
        return QC_SUCCESS;
    }
}

static void print_help(void* help_data) {
    char const* program_name = help_data;
    FILE* e = stderr;
    fprintf(e, "Usage: %s [--mode=encrypt|decrypt] --key=KEY [INPUT [OUTPUT]]\n", program_name);
    fprintf(e, "Default mode is encrypt\n");
}

static qc_result open_file(char const* path, char const* mode, FILE** dst, qc_err* err) {
    errno = 0;
    FILE* f = fopen(path, mode);
    if (f == NULL) {
        qc_err_set(err, "Failed to open file: %s: %s", path, strerror(errno));
        return QC_FAILURE;
    } else {
        *dst = f;
        return QC_SUCCESS;
    }
}

static qc_result args_to_files(qc_args* args, char* argv[], config dst[static 1], qc_err* err) {
    int num_args = qc_args_positionals_count(args);
    if (num_args > 2) {
        qc_err_set(err, "Too much positional arguments: %d, expected two at most", num_args);
        return QC_FAILURE;
    } else {
        if (num_args == 2) {
            if (open_file(argv[qc_args_positionals_index(args)+0], "rb", &dst->input, err) == QC_FAILURE) {
                return QC_FAILURE;
            } else if (open_file(argv[qc_args_positionals_index(args)+1], "wb", &dst->output, err) == QC_FAILURE) {
                fclose(dst->input);
                return QC_FAILURE;
            } else {
                return QC_SUCCESS;
            }
        } else if (num_args == 1) {
            dst->output = stdout;
            return open_file(argv[qc_args_positionals_index(args)+0], "rb", &dst->input, err);
        } else {
            dst->input = stdin;
            dst->output = stdout;
            return QC_SUCCESS;
        }
    }
}

static qc_result mode_from_string(char const* str, bool *encrypt, qc_err* err) {
    if (strcmp(str, "encrypt") == 0) {
        *encrypt = true;
        return QC_SUCCESS;
    } else if (strcmp(str, "decrypt") == 0) {
        *encrypt = false;
        return QC_SUCCESS;
    } else {
        qc_err_set(err, "Invalid mode: %s", str);
        return QC_FAILURE;
    }
}

static qc_result args_to_config(int argc, char* argv[], config dst[static 1], qc_err* err) {
    char const* mode;
    char const* key;
    qc_args* args = qc_args_new();
    qc_result ret;
    qc_args_string_default(args, "mode", "encrypt", &mode, "encrypt|decrypt");
    qc_args_string(args, "key", &key, "ChaCha20 encryption key");
    qc_args_set_help(args, print_help, argv[0]);
    if (qc_args_parse(args, argc, argv, err) == QC_FAILURE) {
        qc_err_append_front(err, "Failed to parse CLI arguments");
        ret = QC_FAILURE;
    } else if (key_from_str(key, dst->key, err) == QC_FAILURE) {
        qc_err_append_front(err, "Failed to parse key from arguments");
        ret = QC_FAILURE;
    } else if (mode_from_string(mode, &dst->encrypt, err) == QC_FAILURE) {
        qc_err_append_front(err, "Failed to parse mode from arguments");
        ret = QC_FAILURE;
    } else if (args_to_files(args, argv, dst, err) == QC_FAILURE) {
        qc_err_append_front(err, "Failed to open requested files");
        ret = QC_FAILURE;
    } else {
        ret = QC_SUCCESS;
    }
    qc_args_free(args);
    return ret;
}

static void cleanup_config(config* cfg) {
    if (cfg->input != stdin) {
        fclose(cfg->input);
    }
    if (cfg->output != stdout) {
        fclose(cfg->output);
    }
}

static qc_result encryption_loop(FILE* from, FILE* to, uint8_t const key[static 32], qc_err* err) {
    uint8_t nonce[12];
    if (chacha20_gen_nonce(nonce, err) == QC_FAILURE) {
        return QC_FAILURE;
    }
    chacha20_state* cc20 = chacha20_new(key, nonce);
    uint8_t poly1305_key[64] = {0};
    chacha20_encrypt_bytes(cc20, 64, poly1305_key);
    poly1305_context pl1305[1];
    poly1305_init(pl1305, poly1305_key);
    uint8_t zeroes[16] = {0};
    fwrite(zeroes, 1, 16, to); // skip first 16 bytes for mac
    fwrite(nonce, 1, 12, to);
    size_t nread;
    uint8_t buf[16];
    while ((nread = fread(buf, 1, 16, from)) > 0) {
        chacha20_encrypt_bytes(cc20, 16, buf);
        poly1305_update(pl1305, buf, nread);
        fwrite(buf, 1, nread, to);
    }
    uint8_t mac[16];
    poly1305_finish(pl1305, mac);
    fseek(to, 0, SEEK_SET);
    fwrite(mac, 1, 16, to);
    fflush(to);
    chacha20_free(cc20);
    return QC_SUCCESS;
}

static qc_result decryption_loop(FILE* from, FILE* to, uint8_t const key[static 32], qc_err* err) {
    uint8_t expected_mac[16];
    uint8_t nonce[12];
    if (fread(expected_mac, 1, 16, from) != 16) {
        qc_err_set(err, "Failed to read mac from input file");
        return QC_FAILURE;
    } else if (fread(nonce, 1, 12, from) != 12) {
        qc_err_set(err, "Failed to read nonce from input file");
        return QC_FAILURE;
    } else {
        chacha20_state* cc20 = chacha20_new(key, nonce);
        uint8_t poly1305_key[64] = {0};
        poly1305_context pl1305[1];
        chacha20_encrypt_bytes(cc20, 64, poly1305_key);
        poly1305_init(pl1305, poly1305_key);
        size_t nread;
        uint8_t buf[16];
        while ((nread = fread(buf, 1, 16, from)) > 0) {
            poly1305_update(pl1305, buf, nread);
            chacha20_decrypt_bytes(cc20, nread, buf);
            fwrite(buf, 1, nread, to);
        }
        fflush(to);
        uint8_t actual_mac[16];
        poly1305_finish(pl1305, actual_mac);
        if (poly1305_verify(actual_mac, expected_mac) == 0) {
            qc_err_set(err, "decrypted BAD message");
            return QC_FAILURE;
        } else {
            return QC_SUCCESS;
        }
    }
}

int main(int argc, char* argv[]) {
    config cfg[1];
    qc_err* err = qc_err_new();
    if (args_to_config(argc, argv, cfg, err) == QC_FAILURE) {
        qc_err_fatal(err, "Failed to configure mode of operation");
    } else {
        if (cfg->encrypt) {
            if (encryption_loop(cfg->input, cfg->output, cfg->key, err) == QC_FAILURE) {
                qc_err_fatal(err, "Failed to encrypt data");
            }
        } else {
            if (decryption_loop(cfg->input, cfg->output, cfg->key, err) == QC_FAILURE) {
                qc_err_fatal(err, "Failed to decrypt data");
            }
        }
        cleanup_config(cfg);
    }
    qc_err_free(err);
}
