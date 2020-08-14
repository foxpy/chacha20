#pragma once
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <qc.h>

// args.c
struct config {
    bool decrypt;
    bool help;
    FILE *input;
    FILE *output;
    uint8_t key[32];
    char *err;
    char *program_name;
};
int parse_args(int argc, char *argv[static argc], struct config *cfg);
__attribute__((noreturn)) void print_help(struct config const *cfg, int status);

// chacha20.c
struct chacha20_state {
    uint32_t state[16];
    uint32_t copy[16];
};
void chacha20_init(struct chacha20_state *state, uint8_t key[static 32],
                   uint8_t nonce[static 12]);
void chacha20_next(struct chacha20_state *state, uint8_t buf[static 64]);

// main.c
int main_loop(FILE *input, FILE *output, struct chacha20_state *state);
