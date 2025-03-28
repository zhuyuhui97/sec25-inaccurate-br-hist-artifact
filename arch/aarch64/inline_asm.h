#ifndef __INLINE_ASM_H__
#define __INLINE_ASM_H__

#define FLUSH_DCACHE(p) asm volatile("dc civac, %0" ::"r"(p));
#define FLUSH_ICACHE(p) asm volatile("ic ivau, %0\n dc civac, %0" ::"r"(p))

#define __NOP(x, rsh) asm volatile(".rept " MACRO_TO_STR(x>>rsh) "\n nop\n .endr")
#define NOP(x) __NOP(x, 0)
#define NOP_PADDING(x) __NOP(x, OPCODE_ADDR_ALIGN) // TODO: Architecture-specific code, rewrite this when porting to x86 or other architectures!

// return an address for an IB that leaves a footprint of dst='0b??'
// #define RET_MEM_WRITE_IBHB(x) (mem_ret + (x << PATH_FP_DST_LSH))

#define OPS_BARRIER(x) \
            asm volatile("dsb sy");\
            asm volatile("isb");\
            NOP(x);
            
#endif