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

.align 4
.global specbhs_victim_snippet
.global __specbhs_victim_align
.global __specbhs_victim_end
specbhs_victim_snippet:
    ldr x8, [x2]
    cmp x8, #0
__specbhs_victim_align:
    b.gt #32
    padding_nop 32
    mov x0, x4
    mov x1, x5
    ldr x7, [x3]
    br x7
__specbhs_victim_end:
