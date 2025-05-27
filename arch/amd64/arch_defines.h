#ifndef __INLINE_ASM_H__
#define __INLINE_ASM_H__
#include "c_macros.h"

#define FLUSH_DCACHE(p) asm volatile("clflush (%0)"::"r"(p));
#define FLUSH_ICACHE(p) asm volatile("clflush (%0)"::"r"(p));

#define NOP(x) asm volatile(".rept " MACRO_TO_STR(x) "\n nop\n .endr")
#define NOP_PADDING(x) NOP(x)

#define OPS_BARRIER(x)\
            asm volatile("mfence");\
            NOP(x);

#define OPCODE_SIZE_NOP             1
#define OPCODE_SIZE_RET             1
#define SIZE_CACHE_STRIDE           256
// SHOULD BE REMOVED
#define OPCODE_SIZE                 16

#endif