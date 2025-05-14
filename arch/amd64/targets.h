#ifndef __TARGETS_H__
#define __TARGETS_H__

#define OPCODE_SIZE_NOP             1
#define OPCODE_SIZE_RET             1
#define SIZE_CACHE_STRIDE           256
// SHOULD BE REMOVED
#define OPCODE_SIZE                 16

#if defined zen4
#define SZ_BTB_EVSET                (2)
#define BHB_LEN_IB                  (32)
// SHOULD BE REMOVED
#define COND_FP_BITS                (512)
#else
#error "Must specify a valid architecture"
#endif


#endif