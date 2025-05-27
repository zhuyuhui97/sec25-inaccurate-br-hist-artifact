#include <stdint.h>
#include <stdlib.h>
#include "args.h"
#include "arch_defines.h"
#include "tests.h"
static struct argp_option options[] =
{
    {"for-bh",    'f',    "NR_JMPS",     0,      "Number of for-loop conditional branches populating the BHB."},
    {"cond-bh",    'c',    "NR_JMPS",     0,      "Number of conditional branches populating the BHB."},
    {"ind-bh",    'i',    "NR_JMPS",     0,      "Number of indirect branches populating the BHB."},
    {"evset-size",    'e',    "NR_BYTES",     0,      "Size of BTB eviction set."},
    {"victim-base",    'v',    "HEX_ADDR",     0,      "Base address of victim snippet."},
    {"tramp-bits",    't',    "NR_BITS",     0,      "Specifies the number of bits to calculate the (BH&RET) trampoline size as 2^NR_BITS for indirect branches."},
	{ 0 }
};

struct args_t args;

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
    struct args_t *arguments = state->input;
    switch (key)
    {
        case 'f':
            arguments->nr_for_bh = strtoul(arg, NULL, 0);
            break;
        case 'c':
            arguments->nr_cond_bh = strtoul(arg, NULL, 0);
            break;
        case 'i':
            arguments->nr_ind_bh = strtoul(arg, NULL, 0);
            break;
        case 'e':
            arguments->nr_evset = strtoul(arg, NULL, 0);
            break;
        case 'v':
            arguments->victim_snippet_base = strtoul(arg, NULL, 0);
            break;
        case 't':
            arguments->tramp_bits = strtoul(arg, NULL, 0);
            if (arguments->tramp_bits < 12 || arguments->tramp_bits > 24)
            {
                argp_error(state, "Trampoline size must be between 12 and 24 bits.");
            }
            break;
        default:
            return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static struct argp argp = {options, parse_opt, NULL, NULL, argp_child_test};

void parse_args(int argc, char **argv)
{
    args.nr_for_bh = 0;
    args.nr_cond_bh = 0;
    args.nr_ind_bh = 0;
    args.nr_evset = 0;
    args.victim_snippet_base = 0;
    args.tramp_bits = 12; // 4096 bytes
    argp_parse(&argp, argc, argv, 0, 0, &args);
}