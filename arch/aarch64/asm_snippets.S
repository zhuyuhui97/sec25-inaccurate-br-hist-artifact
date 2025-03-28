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

// x0 base of ret mem
// x1 base of offset mem
// x2 num of IB injection offsets
// x3 value to train dbhist
// x8 iteration index
SNIPPET_DECLARE jit_populate_phr
    // temporarily store return address
    mov x15, x30
    // expand the num of offset elements to actual size of offset array
    lsl x2, x2, #2
    // initialize iteration index
    mov x8, 0
__jit_populate_phr_for:
    // load IB offset from the offset array
    ldr x7, [x1, x8]
    // calc the actual IB dest from the base addr of ret mem
    add x7, x0, x7, uxtw
SNIPPET_ALIGN jit_populate_phr
    // let's go to the ret memory!
    blr x7
    // increase iteration index
    add x8, x8, #4
    // check if iteration index reaches the boundary of the offset array.
    cmp x8, x2
    nop
    nop
    // if not, start over the loop
    b.lt __jit_populate_phr_for
    // recover the actual return address
    mov x30, x15
    // go back home!
    ret
SNIPPET_END jit_populate_phr


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