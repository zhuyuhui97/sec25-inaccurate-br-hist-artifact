.altmacro

#include "asm_macros.S"

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

SNIPPET_DECLARE jit_ret
    ret
SNIPPET_END jit_ret

SNIPPET_DECLARE jit_nop
    nop
SNIPPET_END jit_nop

SNIPPET_DECLARE jit_br_and_inc_idx
    // load BR target from the offset array (uint64_t[])
    mov (%rdi,%rsi,8), %r10
    // increase iteration index
    inc %rsi
SNIPPET_ALIGN jit_br_and_inc_idx
    // let's jump!
    jmp *%r10
    nop
    padding_nop 4
SNIPPET_END jit_br_and_inc_idx

SNIPPET_DECLARE jit_bcond_and_inc_idx
    // load BCOND flag from the array (uint64_t[])
    mov (%rdi,%rsi,8), %r10
    // increase iteration index
    inc %rsi
    cmp $0, %r10
SNIPPET_ALIGN jit_bcond_and_inc_idx
    jnz .+8
    // padding_nop 0x13
    padding_nop 0xc
SNIPPET_END jit_bcond_and_inc_idx

SNIPPET_DECLARE asm_br
    mov %r8, %rdi
    mov %r9, %rsi
    ops_barrier 0x10
    mov (%rcx), %r10
SNIPPET_ALIGN asm_br
    jmp *%r10
SNIPPET_END asm_br

SNIPPET_DECLARE asm_bhs_br
    mfence
    padding_nop 8
    mov (%rdx), %r10
    mov (%r10), %r11
    cmp $0, %r11
SNIPPET_ALIGN asm_bhs_br
    jg asm_bhs_br_jg_target
    padding_nop 8
asm_bhs_br_jg_target:
    mov %r8, %rdi
    mov %r9, %rsi
    mov (%rcx), %r10
    jmp *%r10
SNIPPET_END asm_bhs_br

/**
 * Note:
 * - On zen4, eviction branches successfully trigger SLS only when jumping across 4k boundary.
 */
SNIPPET_DECLARE jit_bhs_evict
    mfence
    padding_nop 8
    mov (%rdx), %r10
    mov (%r10), %r11
    cmp $0, %r11
SNIPPET_ALIGN jit_bhs_evict
    jg jit_bhs_evict_target
    padding_nop 8
    // padding_nop 0x2000 // for eviction on zen4
jit_bhs_evict_target:
    padding_nop 0x40
    ret
SNIPPET_END jit_bhs_evict

SNIPPET_DECLARE jit_bcond_mispred
    mfence
    padding_nop 8
    mov (%rdx), %r10
    mov (%r10), %r11
    cmp $0, %r11
SNIPPET_ALIGN jit_bcond_mispred
    jg jit_bcond_mispred_target
    mov (%r9), %r9b
    movzb %r9b, %r9
    shl $0x8, %r9
    mov (%r8, %r9), %r10b
    padding_nop 0x40
jit_bcond_mispred_target:
    ret
SNIPPET_END jit_bcond_mispred