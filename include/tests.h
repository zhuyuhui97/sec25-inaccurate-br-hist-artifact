#ifndef __TESTS_H__
#define __TESTS_H__

#include "jit_utils.h"
#include "c_snippets.h"
#include "sc_utils.h"
#include "inline_asm.h"
#include "main.h"
#include "targets.h"
#include "args.h"

void init_test_bh_chains();
void free_test_bh_chains();
void walk_evset();
void init_evset();
void free_evset();

extern run_obj_t run;

#endif