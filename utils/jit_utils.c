#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include "jit_utils.h"
#include "targets.h"

uint64_t os_page_size;
#define MASK_IN_PAGE_OFFSET (os_page_size-1)

jit_mem_obj_t *reg_jit_mem(void* entry, void* addr, uint64_t size, enum ALLOC_METHOD method)
{
    jit_mem_obj_t *obj = NULL;
    obj = malloc(sizeof(jit_mem_obj_t));
    *obj = (jit_mem_obj_t){
        .call_entry = entry,
        .mem_addr = addr,
        .mem_size = size,
        .alloc_method = method,
    };
    return obj;
}

void free_jit_mem(jit_mem_obj_t *obj)
{
    switch (obj->alloc_method)
    {
    case ALLOC_MALLOC:
        free(obj->mem_addr);
        break;
    case ALLOC_MMAP:
        munmap(obj->mem_addr, obj->mem_size);
        break;
    default:
        break;
    }
    free(obj);
}


trampoline_obj_t* prep_trampoline(snippet_obj_t *jump, snippet_obj_t *padding, int jump_interval, int offset, register void *req_base_addr, int mem_size)
{
    trampoline_obj_t *result = NULL;
    assert(jump != NULL);
    uint64_t jump_len = (uint64_t)jump->end - (uint64_t)jump->entry;
    if (jump_interval == 0) 
        jump_interval = jump_len;
    assert(jump_interval >= jump_len);

    void *trampoline = mmap(req_base_addr, mem_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);

    if (jump_interval > jump_len)
    {
        assert(padding != NULL);
        uint64_t padding_len = padding->end - padding->entry;
        for (int i = 0; i < mem_size; i += padding_len)
        {
            memcpy(trampoline + i, padding->entry, padding_len);
        }
    }
    int start_offset = offset % jump_interval;
    for (int i = start_offset; i < mem_size; i += jump_interval)
    {
        memcpy(trampoline + i, jump->entry, jump_len);
    }
    __clear_cache(trampoline, trampoline + mem_size);

    result = malloc(sizeof(trampoline_obj_t));
    *result = (trampoline_obj_t){
        .jump_size = jump_len,
        .jump_interval = jump_interval,
        .offset = start_offset,
        .jump_snippet = jump,
        .padding_snippet = padding,
        .jit_mem = reg_jit_mem(trampoline + offset, trampoline, mem_size, ALLOC_MMAP),
    };
    return result;
}

void free_trampoline(trampoline_obj_t *obj)
{
    free_jit_mem(obj->jit_mem);
    free(obj);
}

uint64_t *prep_jmp_targets(uint64_t *offsets, int len, trampoline_obj_t trampoline)
{
    uint64_t jump_interval = trampoline.jump_interval;
    uint64_t offset = trampoline.offset;
    uint64_t *result = malloc(len * sizeof(uint64_t));
    for (int i = 0; i < len; i++)
    {
        result[i] = (uint64_t)trampoline.jit_mem->mem_addr + jump_interval * (offsets[i] / jump_interval) + offset;
    }
    return result;
}