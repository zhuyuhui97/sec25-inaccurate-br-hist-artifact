#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include "jit_utils.h"
#include "arch_defines.h"

__attribute__((aligned(0x1000)))
uint8_t cacheline_mem[0x1000] = {0};

trampoline_obj_t *tramp_ret;
trampoline_obj_t *tramp_br;
trampoline_obj_t *tramp_victim;
trampoline_obj_t *tramp_bcond;

uint64_t os_page_size = 0;
#define MASK_IN_PAGE_OFFSET (os_page_size-1)

jit_mem_obj_t *reg_jit_mem(void* entry, void* addr, uint64_t mem_size, uint64_t exec_size, enum ALLOC_METHOD method)
{
    jit_mem_obj_t *obj = NULL;
    obj = malloc(sizeof(jit_mem_obj_t));
    *obj = (jit_mem_obj_t){
        .call_entry = entry,
        .mem_addr = addr,
        .mem_size = mem_size,
        .exec_size = exec_size,
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

trampoline_obj_t* prep_trampoline(snippet_obj_t *jump, snippet_obj_t *padding, snippet_obj_t *tail, int jump_interval, int offset, register void *req_base_addr, uint64_t jump_size)
{
    assert(jump != NULL);
    if (os_page_size==0) os_page_size = getpagesize();
    bool has_padding = (padding != NULL);
    bool has_tail = (tail != NULL);
    uint64_t padding_size = (has_padding) ? padding->end - padding->entry : 0;
    uint64_t tail_size = (has_tail) ? tail->end - tail->entry : 0;
    uint64_t jump_len = (uint64_t)jump->end - (uint64_t)jump->entry;

    // We must fill the preamble (offset bytes) with padding snippet, complain if not provided.
    assert(offset == 0 || has_padding);
    // Calibrate the offset with the size of padding snippet
    offset = (offset == 0) ? 0 : (offset / padding_size) * padding_size;
    // Calibrate the JITed jump interval with the size of jump snippet
    if (jump_interval < jump_len) jump_interval = jump_len;
    // Round-down the jump memory size with the JITed jump interval
    jump_size = jump_size / jump_interval * jump_interval;

    // Calculate total memory size
    uint64_t exec_size = offset + jump_size + tail_size;
    // Round-up the total memory size with page size
    uint64_t mem_size = (jump_size % os_page_size == 0) ? exec_size : (exec_size + os_page_size) & ~(os_page_size - 1);
    // Get memory slice
    void *trampoline = mmap(req_base_addr, mem_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);

    if (offset != 0)
    {
        assert(has_padding);
        assert((offset % padding_size) == 0);
        for (int dst = 0; dst < offset; dst += padding_size)
            memcpy(trampoline + dst, padding->entry, padding_size);
    }
    
    if (jump_interval > jump_len)
    {
        assert(has_padding);
        assert((jump_interval - jump_len) % padding_size == 0);
        for (int dst = offset; dst <= exec_size - padding_size - tail_size; dst += padding_size)
            memcpy(trampoline + dst, padding->entry, padding_size);
    }

    int dst = offset;
    if (jump_size >= jump_interval)
    {
        for (; dst <= (exec_size - jump_interval - tail_size); dst += jump_interval)
            memcpy(trampoline + dst, jump->entry, jump_len);
    }

    if (has_tail)
    {
        memcpy(trampoline + dst, tail->entry, tail_size);
        dst += tail_size;
    }

    __clear_cache(trampoline, trampoline + exec_size);
    trampoline_obj_t *result = malloc(sizeof(trampoline_obj_t));
    *result = (trampoline_obj_t){
        .jump_size = jump_len,
        .jump_interval = jump_interval,
        .offset = offset,
        .jump_snippet = jump,
        .padding_snippet = padding,
        .tail_snippet = tail,
        .jit_mem = reg_jit_mem(trampoline + offset, trampoline, mem_size, jump_size, ALLOC_MMAP),
    };
    return result;
}

trampoline_obj_t* prep_aligned_snippet(snippet_obj_t *src, void *anchor, uint64_t nr_const_lsb)
{
    if (os_page_size==0) os_page_size = getpagesize();
    bool req_exact_addr = (nr_const_lsb == 0);
    bool align_le_page = ((1<<nr_const_lsb) <= os_page_size);

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

    uint64_t addr_request = ((uint64_t)anchor - align_offset);
    if (!req_exact_addr) addr_request ^= mask_flip;
    uint64_t page_request = addr_request & ~(os_page_size - 1);
    uint64_t offset_in_page = addr_request & MASK_IN_PAGE_OFFSET;
    uint64_t mem_size = (offset_in_page + length + os_page_size) & (~MASK_IN_PAGE_OFFSET);

    while (true)
    {
        mem = mmap((void*)page_request, mem_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
        writeptr = mem + offset_in_page;
        uint64_t align_target = (uint64_t) writeptr + align_offset;
        // let's check:
        // If requested consistent bits can be covered by page size, we can take any page.
        if (align_le_page) break;
        // Request exact address
        if (req_exact_addr)
        {
            assert((uint64_t)mem == page_request);
            break;
        }
        // lower bits should keep consistent
        bool lower_eq = (((uint64_t)anchor ^ align_target) & mask_lower) == 0;
        // the higher 1 bit should be flipped
        bool higher_lsb_flip = (((uint64_t)anchor ^ align_target) & mask_flip) != 0;
        if (lower_eq && higher_lsb_flip)
            break;
        // returned address does not match the conditions, try requesting next address
        page_request += (1 << nr_const_lsb);
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
        .jit_mem = reg_jit_mem(mem + offset_in_page, mem, mem_size, mem_size, ALLOC_MMAP),
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
    uint64_t jump_size = trampoline->jit_mem->exec_size;
    uint64_t *result = malloc(len * sizeof(uint64_t));
    for (int i = 0; i < len; i++)
    {
        offsets[i] = offsets[i] % jump_size;
        result[i] = (uint64_t)trampoline->jit_mem->call_entry + (offsets[i] / jump_interval) * jump_interval;
    }
    return result;
}