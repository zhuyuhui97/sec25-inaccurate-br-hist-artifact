#ifndef __JIT_SNIPPETS_H__
#define __JIT_SNIPPETS_H__
#include <stdint.h>

typedef struct 
{
    void *entry;
    void *align;
    void *end;
} snippet_obj_t;

#define JIT_SNIPPET_LENGTH(x) (uint64_t)&__##x##_end - (uint64_t)&x
#define JIT_SNIPPET_ALIGN_OFFSET(x) (uint64_t)&__##x##_align - (uint64_t)&x
#define JIT_SNIPPET_OBJ(name, __entry, __align, __end) \
    static snippet_obj_t name##_obj = {         \
        .entry = __entry,                       \
        .align = __align,                       \
        .end = __end,                           \
    };

#define JIT_SNIPPET_SYMBOLS(rettype, x, ...)    \
    extern rettype  x(__VA_ARGS__);             \
    extern void  __##x##_end(void);             \
    typedef rettype (*x##_t)(__VA_ARGS__);      \
    JIT_SNIPPET_OBJ(x, (void*)&x, (void*)&x, (void*)&__##x##_end)
#define JIT_ALIGNED_SNIPPET_SYMBOLS(rettype, x, ...)    \
    extern rettype  x(__VA_ARGS__);             \
    extern void  __##x##_align(void);           \
    extern void  __##x##_end(void);             \
    typedef rettype (*x##_t)(__VA_ARGS__);      \
    JIT_SNIPPET_OBJ(x, (void*)&x, (void*)&__##x##_align, (void*)&__##x##_end)

JIT_ALIGNED_SNIPPET_SYMBOLS(void, jit_br_and_inc_idx, uint64_t *offsets, uint64_t idx);
JIT_ALIGNED_SNIPPET_SYMBOLS(void, jit_bcond_and_inc_idx, uint64_t *offsets, uint64_t idx);

JIT_ALIGNED_SNIPPET_SYMBOLS(void, asm_bhs_br, uint64_t *offsets, uint64_t idx, char** argv, void **ib_ptr_p, char *frbuf, void *secret_p);
JIT_ALIGNED_SNIPPET_SYMBOLS(void, jit_bhs_evict, uint64_t *offsets, uint64_t idx, char** argv, void **ib_ptr_p);
JIT_ALIGNED_SNIPPET_SYMBOLS(void, asm_br, uint64_t *offsets, uint64_t idx, char** argv, void **ib_ptr_p, char *frbuf, void *secret_p);
JIT_ALIGNED_SNIPPET_SYMBOLS(void, jit_bcond_mispred, uint64_t *offsets, uint64_t idx, char** argv, void **ib_ptr_p, char *frbuf, void *secret_p);

JIT_SNIPPET_SYMBOLS(void, jit_ret, void);
JIT_SNIPPET_SYMBOLS(void, jit_nop, void);

typedef void (*branch_chain_t)(uint64_t *offsets, uint64_t idx, char** argv, void **ib_ptr, char *frbuf, void *secret_p);

#endif