.altmacro

#include "asm_macros.S"

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

SNIPPET_DECLARE jit_ret
    ret
SNIPPET_END jit_ret

SNIPPET_DECLARE jit_nop
    nop
SNIPPET_END jit_nop

SNIPPET_DECLARE jit_biasscope_sender
    mov x2, #1
    lsl x2, x2, x1
    ands x2, x0, x2
SNIPPET_ALIGN jit_biasscope_sender
    b.ne #12
    nop
    nop
SNIPPET_END jit_biasscope_sender

SNIPPET_DECLARE jit_br_and_inc_idx
    // load BR target from the offset array (uint32_t[])
    ldr x7, [x0, x1, lsl #3]
    // increase iteration index
    add x1, x1, #1
SNIPPET_ALIGN jit_br_and_inc_idx
    // let's jump!
    br x7
    nop
SNIPPET_END jit_br_and_inc_idx

SNIPPET_DECLARE jit_bcond_and_inc_idx
    // load BCOND flag from the array (uint64_t[])
    ldr x7, [x0, x1, lsl #3]
    // increase iteration index
    add x1, x1, #1
    cmp x7, #0
SNIPPET_ALIGN jit_bcond_and_inc_idx
    b.ne #4
    padding_nop 4
SNIPPET_END jit_bcond_and_inc_idx

SNIPPET_DECLARE asm_br
    mov x0, x4
    mov x1, x5
    ops_barrier 0x10
    ldr x7, [x3]
SNIPPET_ALIGN asm_br
    br x7
SNIPPET_END asm_br

SNIPPET_DECLARE asm_bhs_br
    ldr x7, [x2]
    ldr x8, [x7]
    cmp x8, #0
SNIPPET_ALIGN asm_bhs_br
    b.gt #32
    padding_nop 32
    mov x0, x4
    mov x1, x5
    ldr x7, [x3]
    br x7
SNIPPET_END asm_bhs_br

SNIPPET_DECLARE jit_bhs_evict
    ldr x7, [x2]
    ldr x8, [x7]
    cmp x8, #0
SNIPPET_ALIGN jit_bhs_evict
    b.gt #32
    padding_nop 64
    ret
SNIPPET_END jit_bhs_evict

SNIPPET_DECLARE jit_bcond_mispred
    ldr x7, [x2]
    ldr x8, [x7]
    cmp x8, #0
SNIPPET_ALIGN jit_bcond_mispred
    b.ne jit_bcond_mispred_target
    ldrb w5, [x5]
    lsl w5, w5, #8
    sxtw x5, w5
    add x5, x5, x4
    ldrb w5, [x5]
    padding_nop 32
jit_bcond_mispred_target:
    ret
SNIPPET_END jit_bcond_mispred