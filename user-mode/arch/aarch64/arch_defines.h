#ifndef __INLINE_ASM_H__
#define __INLINE_ASM_H__
#include "c_macros.h"

#define FLUSH_DCACHE(p) asm volatile("dc civac, %0" ::"r"(p));
#define FLUSH_ICACHE(p) asm volatile("ic ivau, %0\n dc civac, %0" ::"r"(p))

#define __NOP(x, rsh) asm volatile(".rept " MACRO_TO_STR(x>>rsh) "\n nop\n .endr")
#define NOP(x) __NOP(x, 0)
#define NOP_PADDING(x) __NOP(x, OPCODE_ADDR_ALIGN) // TODO: Architecture-specific code, rewrite this when porting to x86 or other architectures!

#define OPS_BARRIER(x) \
            asm volatile("dsb sy");\
            asm volatile("isb");\
            NOP(x);

#define OPCODE_ADDR_ALIGN           2
#define OPCODE_SIZE                 (1 << OPCODE_ADDR_ALIGN)
#define OPCODE_ADDR_MASK            (~(OPCODE_SIZE - 1))

#define OPCODE_SIZE_NOP             OPCODE_SIZE
#define OPCODE_SIZE_RET             OPCODE_SIZE
#define SIZE_CACHE_STRIDE           256
            
#endif