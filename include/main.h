#ifndef __MAIN_H__
#define __MAIN_H__

#include <linux/types.h>
#include "jit_utils.h"
#include "c_snippets.h"
#include "sc_utils.h"
#include "inline_asm.h"
#include "tests.h"

#define NR_TEST_ITER 64
#define LEN_BH_CHAIN 9
#define NR_TARGET_WARMUP_GROUPS 2

extern uint64_t offsets_bh_leak[];
extern uint64_t offsets_bh_safe[];

extern trampoline_obj_t *tramp_ret;
extern trampoline_obj_t *tramp_br;
extern uint64_t *targets_bh_leak;
extern uint64_t *targets_bh_safe;

extern void *ib_ptr;

extern uint8_t dummy_secret;
extern void *ib_ptr_empty;
extern branch_chain_t bh_chain_common;

void goto_chain(branch_chain_t br_chain, uint64_t *bh_targets, void **ib_ptr_p, int nr_cond_bh, void *frbuf, void *ptr_secret, uint64_t ex_argc, char **ex_argv);


#endif