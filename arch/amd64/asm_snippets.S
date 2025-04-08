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
    // load BR target from the offset array (uint32_t[])
    mov (%rdi,%rsi,8), %r10
    // increase iteration index
    inc %rsi
SNIPPET_ALIGN jit_br_and_inc_idx
    // let's jump!
    jmp *%r10
    nop
    padding_nop 5
SNIPPET_END jit_br_and_inc_idx

SNIPPET_DECLARE asm_br
    mov %r8, %rdi
    mov %r9, %rsi
    ops_barrier 0x10
    mov (%r8), %r10
SNIPPET_ALIGN asm_br
    jmp *%r10
SNIPPET_END asm_br

SNIPPET_DECLARE asm_bhs_br
    mov (%rdx), %r10
    mov (%r10), %r11
    cmp $0, %r11
SNIPPET_ALIGN asm_bhs_br
    jg asm_bhs_br_jg_target
    padding_nop 32
asm_bhs_br_jg_target:
    mov %r8, %rdi
    mov %r9, %rsi
    mov (%rcx), %r10
    jmp *%r10
SNIPPET_END asm_bhs_br

SNIPPET_DECLARE jit_bhs_evict
    mov (%rcx), %r10
    mov (%rcx), %r10
    cmp $0, %r10
SNIPPET_ALIGN jit_bhs_evict
    jg jit_bhs_evict_target
jit_bhs_evict_target:
    padding_nop 64
    ret
SNIPPET_END jit_bhs_evict