#ifndef __UTILS_H__
#define __UTILS_H__

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <string.h>
#include "targets.h"
#include "asm_snippets.h"
#include "inline_asm.h"

#define BASE_BTB_EVICT      VOIDPTR(0x6000000)
#define BASE_BHB_POPULATE   VOIDPTR(0x7000000)
#define BASE_RET_MEM        VOIDPTR(0xf00000)

#define MACRO_TO_STR(x) #x
#define VOIDPTR(x) (void*)(x)
#define JMP_TO(x) ((void (*)())(x))()
#define MEM_ACCESS(p) *(volatile unsigned char *)p

enum ALLOC_METHOD
{
    ALLOC_MALLOC,
    ALLOC_MMAP
};

typedef struct
{
    uint64_t mem_size;
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
    jit_mem_obj_t *jit_mem;
} trampoline_obj_t;

enum test_type {
    TEST_SPEC_V2,
    TEST_SPEC_NO_BSE,
    TEST_SPEC_BSE,
    NR_TESTS,
};

typedef struct {
    branch_chain_t *bh_chain_p;
    void *ib_target;
    uint64_t **bh_targets_p;
    uint64_t nr_cond_bh;
    void **ib_ptr_p;
    char **frbuf_p;
    char *ptr_secret;
} bh_chain_params_t;

typedef struct {
    enum test_type test_spec;
    uint64_t nr_test_passes;
    uint64_t nr_train_passes;
    uint64_t nr_trains;
    bh_chain_params_t** trains;
    bh_chain_params_t* test;
    uint64_t nr_dc_flush;
    void **dc_flush_p;
    void (*before_train)(void);
    void (*before_test)(void);
} test_obj_t;

jit_mem_obj_t *reg_jit_mem(void* entry, void* addr, uint64_t size, enum ALLOC_METHOD method);
void free_jit_mem(jit_mem_obj_t *obj);
trampoline_obj_t* prep_trampoline(snippet_obj_t *jump, snippet_obj_t *padding, int jump_interval, int offset, register void *req_base_addr, int mem_size);
void free_trampoline(trampoline_obj_t *obj);

uint64_t *prep_jmp_targets(uint64_t *offsets, int len, trampoline_obj_t trampoline);

/**
 * Populate the conditional BHB with a for-loop.
 * The history of conditional branches seems to be XOR'd to path history when updating or querying IB prediction.
 * Add an extra for-loop to keep it constant when CPU reaches BLR_pred.
*/
void inline __attribute__((always_inline)) populate_cbhb(int n)
{
    NOP_PADDING(64);
    for (register int j = 0; j < n; j++)
    {
        NOP_PADDING(64);
    }
    NOP_PADDING(64);
}

#endif