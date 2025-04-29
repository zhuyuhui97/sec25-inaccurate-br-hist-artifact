#ifndef __MAIN_H__
#define __MAIN_H__

#include <linux/types.h>
#include "jit_utils.h"
#include "c_snippets.h"
#include "sc_utils.h"
#include "inline_asm.h"
#include "tests.h"
#include "args.h"

#define NR_TEST_ITER 64

extern trampoline_obj_t *tramp_ret;
extern trampoline_obj_t *tramp_br;

extern void *ib_ptr;

void goto_chain(branch_chain_t br_chain, uint64_t *bh_targets, void **ib_ptr_p, int nr_cond_bh, void *frbuf, void *secret_p, uint64_t ex_argc, char **ex_argv);


#endif