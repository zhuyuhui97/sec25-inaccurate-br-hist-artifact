#include "asm_macros.S"
#include "spec-bhs.h"

.macro ops_barrier n
    dsb sy
    isb
.rept \n
    nop
.endr
.endm

.altmacro
.macro padding_nop n
.rept \n
    nop
.endr
.endm

.altmacro
.macro GET_JMP_LAT_PRE_JMP
#if defined DBG_JMP_LATENCY
    mrs GLOBAL_REG_BR_LAT, pmccntr_el0
#endif
.endm

SNIPPET_DECLARE asm_bhs_br_measure_lat
    ops_barrier 0x10
    ldr x7, [x2]
    ldr x8, [x7]
    cmp x8, #0
SNIPPET_ALIGN asm_bhs_br_measure_lat
    b.gt #32
    padding_nop 32
    mov x0, x4
    mov x1, x5
#ifdef DBG_ARCH_BH
    ops_barrier 8
#endif
    GET_JMP_LAT_PRE_JMP
    ldr x7, [x3]
    br x7
SNIPPET_END asm_bhs_br_measure_lat

SNIPPET_DECLARE jit_bhs_evict_measure_lat
    ops_barrier 0x10
    ldr x7, [x2]
    ldr x8, [x7]
    cmp x8, #0
SNIPPET_ALIGN jit_bhs_evict_measure_lat
    b.gt #32
    padding_nop 64
    GET_JMP_LAT_PRE_JMP
    ret
SNIPPET_END jit_bhs_evict_measure_lat