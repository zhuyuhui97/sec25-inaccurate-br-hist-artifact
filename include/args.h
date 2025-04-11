#ifndef __ARGS_H__
#define __ARGS_H__
#include <argp.h>

struct args_t
{
    unsigned long nr_cond_bh; /* number of conditional branches */
    unsigned long nr_ind_bh;  /* number of indirect branches */
    unsigned long nr_evset;      /* number of evictions */
};

extern struct args_t args;

void parse_args(int argc, char **argv);
#endif