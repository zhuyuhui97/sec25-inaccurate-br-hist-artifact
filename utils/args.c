#include <stdint.h>
#include <stdlib.h>
#include "args.h"
#include "targets.h"
static struct argp_option options[] =
{
    {"cb",    'c',    "n.",     0,      NULL},
    {"ib",    'i',    "n.",     0,      NULL},
    {"ev",    'e',    "n.",     0,      NULL},
	{ 0 }
};

struct arguments
{
    unsigned long nr_cond_bh; /* number of conditional branches */
    unsigned long nr_ind_bh;  /* number of indirect branches */
    unsigned long nr_evset;      /* number of evictions */
} arguments;

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
    struct arguments *arguments = state->input;
    switch (key)
    {
        case 'c':
            arguments->nr_cond_bh = strtoul(arg, NULL, 0);
            break;
        case 'i':
            arguments->nr_ind_bh = strtoul(arg, NULL, 0);
            break;
        case 'e':
            arguments->nr_evset = strtoul(arg, NULL, 0);
            break;
        default:
            return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static struct argp argp = {options, parse_opt, NULL, NULL};

void parse_args(int argc, char **argv)
{
    arguments.nr_cond_bh = COND_FP_BITS;
    arguments.nr_ind_bh = BHB_LEN_IB;
    arguments.nr_evset = SZ_BTB_EVSET;
    argp_parse(&argp, argc, argv, 0, 0, &arguments);
}