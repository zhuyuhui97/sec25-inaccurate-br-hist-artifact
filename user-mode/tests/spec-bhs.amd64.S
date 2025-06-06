#include "asm_macros.S"
#include "spec-bhs.h"

.macro ops_barrier n
    mfence
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
    rdtsc
    mov %rdx, GLOBAL_REG_BR_LAT
    shl $32, GLOBAL_REG_BR_LAT
    or %rax, GLOBAL_REG_BR_LAT
#endif
.endm

SNIPPET_DECLARE asm_bhs_br_measure_lat
    ops_barrier 8
    mov (%rdx), %r10
    mov (%r10), %r11
    cmp $0, %r11
SNIPPET_ALIGN asm_bhs_br_measure_lat
    jg target1
    padding_nop 8
target1:
    mov %r8, %rdi
    mov %r9, %rsi
#ifdef DBG_ARCH_BH
    ops_barrier 8
#endif
    GET_JMP_LAT_PRE_JMP
    mov (%rcx), %r10
    jmp *%r10
SNIPPET_END asm_bhs_br_measure_lat

/**
 * Note:
 * - On zen4, eviction branches successfully trigger SLS only when jumping across 4k boundary.
 */
SNIPPET_DECLARE jit_bhs_evict_measure_lat
    ops_barrier 8
    mov (%rdx), %r10
    mov (%r10), %r11
    cmp $0, %r11
SNIPPET_ALIGN jit_bhs_evict_measure_lat
    jg target2
    padding_nop 8
    // padding_nop 0x2000 // for eviction on zen4
target2:
    padding_nop 0x40
    ret
SNIPPET_END jit_bhs_evict_measure_lat