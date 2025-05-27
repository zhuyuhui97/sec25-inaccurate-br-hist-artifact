#ifndef __TESTS_H__
#define __TESTS_H__

#include "jit_utils.h"
#include "c_snippets.h"
#include "sc_utils.h"
#include "arch_defines.h"
#include "args.h"

bool next_run();
void init_test();
void free_test();
void print_test_info();

extern run_obj_t run;
extern struct argp_child argp_child_test[];

#endif