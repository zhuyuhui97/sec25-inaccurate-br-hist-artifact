#ifndef __UTILS_H__
#define __UTILS_H__

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <string.h>
#include "arch_defines.h"
#include "asm_snippets.h"
#include "c_snippets.h"

#define NR_TEST_ITER 64
#define BASE_BTB_EVICT      VOIDPTR(0x6000000)
#define BASE_BHB_POPULATE   VOIDPTR(0x7000000)
#define BASE_RET_MEM        VOIDPTR(0xf00000)

enum ALLOC_METHOD
{
    ALLOC_MALLOC,
    ALLOC_MMAP
};

typedef struct
{
    uint64_t mem_size;
    uint64_t exec_size;
    void *mem_addr;
    void *call_entry;
    enum ALLOC_METHOD alloc_method;
} jit_mem_obj_t;

typedef struct
{
    uint64_t jump_size;
    uint64_t jump_interval;
    uint64_t offset;
    snippet_obj_t *jump_snippet;
    snippet_obj_t *padding_snippet;
    snippet_obj_t *tail_snippet;
    jit_mem_obj_t *jit_mem;
} trampoline_obj_t;

typedef struct {
    trampoline_obj_t **bh_tramp_p;
    void *ib_target;
    uint64_t **bh_args_p;
    uint64_t *nr_bh_for_p;
    uint64_t *nr_bh_cond_p;
    uint64_t *nr_bh_ind_p;
    void **ib_ptr_p;
    char **frbuf_p;
    char *secret_p;
    uint64_t ex_argc;
    char **ex_argv;
} bh_chain_params_t;

typedef void (cb_pre_test_t)(uint64_t idx_test, uint64_t idx_rept_test);
typedef void (cb_pre_train_t)(uint64_t idx_test, uint64_t idx_rept_test, uint64_t idx_rept_train);
typedef void (cb_in_train_t)(uint64_t idx_test, uint64_t idx_rept_test, uint64_t idx_rept_train, uint64_t idx_train);
typedef void (cb_pre_spec_t)(uint64_t idx_test, uint64_t idx_rept_test);
typedef void (cb_post_spec_t)(uint64_t idx_test, uint64_t idx_rept_test);

typedef struct {
    uint64_t nr_repeat;
    uint64_t nr_train_passes;
    uint64_t nr_train_chains;
    bh_chain_params_t** train_chains;
    bh_chain_params_t* spec_chain;
    uint64_t nr_dc_flush;
    void **dc_flush;
    cb_pre_test_t *pre_test;
    cb_pre_train_t *pre_train;
    cb_in_train_t *in_train;
    cb_pre_spec_t *pre_spec;
    cb_post_spec_t *post_spec;
    uint64_t nr_probes;
    char **probes_p;
    char *description;
} test_obj_t;

typedef struct {
    uint64_t nr_tests;
    void *bp_snippet;
    test_obj_t* tests[];
} run_obj_t;

extern trampoline_obj_t *tramp_ret;
extern trampoline_obj_t *tramp_br;
extern trampoline_obj_t *tramp_victim;
extern trampoline_obj_t *tramp_bcond;
extern uint8_t cacheline_mem[0x1000];
#define IBPTR ((void*)(&cacheline_mem[0x140]))

// In main.c
void goto_chain(branch_chain_t br_chain, uint64_t *bh_targets, void **ib_ptr_p, int nr_cond_bh, void *frbuf, void *secret_p, uint64_t ex_argc, char **ex_argv);

jit_mem_obj_t *reg_jit_mem(void* entry, void* addr, uint64_t mem_size,  uint64_t exec_size, enum ALLOC_METHOD method);
void free_jit_mem(jit_mem_obj_t *obj);
trampoline_obj_t* prep_trampoline(snippet_obj_t *jump, snippet_obj_t *padding, snippet_obj_t *tail, int jump_interval, int offset, register void *req_base_addr, uint64_t mem_size);
void free_trampoline(trampoline_obj_t *obj);

uint64_t *prep_jmp_targets(uint64_t *offsets, int len, trampoline_obj_t *trampoline);
trampoline_obj_t* prep_aligned_snippet(snippet_obj_t *jump, void *target, uint64_t nr_const_lsb);

/**
 * Populate the conditional BHB with a for-loop.
 * The history of conditional branches seems to be XOR'd to path history when updating or querying IB prediction.
 * Add an extra for-loop to keep it constant when CPU reaches BLR_pred.
*/
// void inline __attribute__((always_inline)) populate_cbhb(int n)
// {
//     NOP_PADDING(64);
//     for (register int j = 0; j < n; j++)
//     {
//         NOP_PADDING(64);
//     }
//     NOP_PADDING(64);
// }

#endif