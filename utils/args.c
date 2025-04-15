#include <stdint.h>
#include <stdlib.h>
#include "args.h"
#include "targets.h"
#include "tests.h"
static struct argp_option options[] =
{
    {"cb",    'c',    "n",     0,      "Number of conditional branches populating the BHB."},
    {"ib",    'i',    "n",     0,      "Number of indirect branches populating the BHB."},
    {"ev",    'e',    "n",     0,      "Size of BTB eviction set."},
	{ 0 }
};

struct args_t args;

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
    struct args_t *arguments = state->input;
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

static struct argp argp = {options, parse_opt, NULL, NULL, argp_child_test};

void parse_args(int argc, char **argv)
{
    args.nr_cond_bh = COND_FP_BITS;
    args.nr_ind_bh = BHB_LEN_IB;
    args.nr_evset = SZ_BTB_EVSET;
    argp_parse(&argp, argc, argv, 0, 0, &args);
}