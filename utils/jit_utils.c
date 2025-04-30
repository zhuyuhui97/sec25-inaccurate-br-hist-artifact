#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include "jit_utils.h"
#include "targets.h"

__attribute__((aligned(0x1000)))
uint8_t cacheline_mem[0x1000] = {0};

trampoline_obj_t *tramp_ret;
trampoline_obj_t *tramp_br;
trampoline_obj_t *tramp_victim;

uint64_t os_page_size = 0;
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

trampoline_obj_t* prep_trampoline(snippet_obj_t *jump, snippet_obj_t *padding, int jump_interval, int offset, register void *req_base_addr, uint64_t mem_size)
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

trampoline_obj_t* prep_aligned_snippet(snippet_obj_t *src, void *anchor, uint64_t nr_const_lsb)
{
    if (os_page_size==0) os_page_size = getpagesize();
    trampoline_obj_t *result = NULL;
    void *mem;
    void *writeptr;
    uint64_t entry = (uint64_t) src->entry;
    uint64_t length = (uint64_t) src->end - entry;
    uint64_t align = (uint64_t) src->align;
    uint64_t align_offset = align - entry;

    uint64_t mask_flip = (1 << nr_const_lsb);
    uint64_t mask_lower = mask_flip - 1;
    uint64_t mask_higher = ~mask_lower ^ mask_flip;

    uint64_t addr_request = ((uint64_t)anchor - align_offset) ^ mask_flip;
    // if ((addr_request ^ (uint64_t)anchor)&(~(os_page_size-1))==0)
    //     addr_request += os_page_size;
    uint64_t offset_in_page = addr_request & MASK_IN_PAGE_OFFSET;
    uint64_t mem_size = (offset_in_page + length + os_page_size) & (~MASK_IN_PAGE_OFFSET);

    while (true)
    {
        mem = mmap((void*)addr_request, mem_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
        writeptr = mem + offset_in_page;
        uint64_t align_target = (uint64_t) writeptr + align_offset;
        // let's check:
        // lower bits should keep consistent
        // the higher 1 bit should be flipped
        bool lower_eq = (((uint64_t)anchor ^ align_target) & mask_lower) == 0;
        bool higher_lsb_flip = (((uint64_t)anchor ^ align_target) & mask_flip) != 0;
        if (lower_eq && higher_lsb_flip)
            break;
        // returned address does not match the conditions, try requesting next address
        addr_request += (1 << nr_const_lsb);
        munmap(mem, mem_size);
    }

    memcpy(writeptr, (void*)entry, length);
    __clear_cache(writeptr, writeptr + length + OPCODE_SIZE);

    result = malloc(sizeof(trampoline_obj_t));
    *result = (trampoline_obj_t){
        .jump_size = length,
        .jump_interval = 0,
        .offset = offset_in_page,
        .jump_snippet = src,
        .padding_snippet = 0,
        .jit_mem = reg_jit_mem(mem + offset_in_page, mem, mem_size, ALLOC_MMAP),
    };
    return result;
}

void free_trampoline(trampoline_obj_t *obj)
{
    free_jit_mem(obj->jit_mem);
    free(obj);
}

uint64_t *prep_jmp_targets(uint64_t *offsets, int len, trampoline_obj_t *trampoline)
{
    uint64_t jump_interval = trampoline->jump_interval;
    uint64_t offset = trampoline->offset;
    uint64_t *result = malloc(len * sizeof(uint64_t));
    for (int i = 0; i < len; i++)
    {
        result[i] = (uint64_t)trampoline->jit_mem->mem_addr + jump_interval * (offsets[i] / jump_interval) + offset;
    }
    return result;
}