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

SNIPPET_DECLARE asm_br
    mov x0, x4
    mov x1, x5
    ops_barrier 0x10
    ldr x7, [x3]
    br x7
SNIPPET_END asm_br