#pragma once
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// main.c
int main_loop(FILE *input, FILE *output);

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

// util.c
__attribute__((noreturn)) void die(char const *msg);
