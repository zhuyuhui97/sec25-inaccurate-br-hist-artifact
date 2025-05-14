#ifndef __TARGETS_H__
#define __TARGETS_H__

#define OPCODE_ADDR_ALIGN           2
#define OPCODE_SIZE                 (1 << OPCODE_ADDR_ALIGN)
#define OPCODE_ADDR_MASK            (~(OPCODE_SIZE - 1))

#define OPCODE_SIZE_NOP             OPCODE_SIZE
#define OPCODE_SIZE_RET             OPCODE_SIZE
#define SIZE_CACHE_STRIDE           256

#if defined imx8 // Cortex-A72
#define COND_FP_BITS                (8)
#define SZ_BTB_EVSET                (2)
#define BHB_LEN_IB                  (4)

#elif defined orin // Cortex-A78, TBD
#define COND_FP_BITS                (512)
#define SZ_BTB_EVSET                (16)
#define CACHE_LINE_SIZE             (64)

#elif defined rpi5 // Cortex-A76, TBD
#define COND_FP_BITS                (512)
#define SZ_BTB_EVSET                (16)
#define BHB_LEN_IB                  (64)

#else
#error "Must specify a valid target"
#endif

#endif