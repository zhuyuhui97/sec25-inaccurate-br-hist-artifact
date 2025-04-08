#ifndef __TARGETS_H__
#define __TARGETS_H__

#define BHB_SIZE_BITS               (BHB_LENGTH_PATH_FP_DST * PATH_FP_DST_BITS)
#define BHB_LENGTH_COND_FP          (BHB_SIZE_BITS)
#define PATH_FP_MASK(BITS, LSH)     (((1 << BITS) - 1) << LSH)
#define PATH_FP_SRC_MASK            PATH_FP_MASK(PATH_FP_SRC_BITS, PATH_FP_SRC_LSH)
#define PATH_FP_DST_MASK            PATH_FP_MASK(PATH_FP_DST_BITS, PATH_FP_DST_LSH)
#define BST_IDX_MASK                (((1 << BST_IDX_MSB) - 1) ^ ((1 << BST_IDX_LSB) - 1))

#if defined ARCH_aarch64

#define OPCODE_ADDR_ALIGN           2
#define OPCODE_SIZE                 (1 << OPCODE_ADDR_ALIGN)
#define OPCODE_ADDR_MASK            (~(OPCODE_SIZE - 1))

#define OPCODE_SIZE_NOP             OPCODE_SIZE
#define OPCODE_SIZE_RET             OPCODE_SIZE
#define SIZE_CACHE_STRIDE           256

#if defined imx8 // Cortex-A72

#define VA_BITS                     (40)
// #define BHB_SIZE_BITS               (8)
#define PATH_FP_SRC_ADDR            (false)
#define PATH_FP_SRC_LSH             (0)
#define PATH_FP_SRC_BITS            (0)
#define PATH_FP_DST_ADDR            (true)
#define PATH_FP_DST_LSH             (4)
#define PATH_FP_DST_BITS            (2)
#define BHB_LENGTH_PATH_FP_DST      (4)
#define COND_FP                     (true)
#define COND_FP_BITS                (8)
#define BST_IDX_MSB                 (14)
#define BST_IDX_LSB                 (4)
#define SZ_BTB_EVSET                (2)
#define IB_FAST_THRESHOLD_PMU_EL0   (12)
#define IB_FAST_THRESHOLD_POSIX     (35000)
#define CACHE_LINE_SIZE             (64)
#define BHB_LEN_IB                  (4)

#elif defined orin // Cortex-A78, TBD

#define VA_BITS                     (40)
// #define BHB_SIZE_BITS               (32)
#define PATH_FP_SRC_ADDR            (false)
#define PATH_FP_SRC_LSH             (0)
#define PATH_FP_SRC_BITS            (0)
#define PATH_FP_DST_ADDR            (true)
#define PATH_FP_DST_LSH             (2)
#define PATH_FP_DST_BITS            (8)
#define BHB_LENGTH_PATH_FP_DST      (64)
#define COND_FP                     (true)
#define COND_FP_BITS                (8)
#define BST_IDX_MSB               (24)
#define BST_IDX_LSB               (2)
#define BST_WAYS                  (8)
#define IB_FAST_THRESHOLD_PMU_EL0   (12)
#define IB_FAST_THRESHOLD_POSIX     (35000)
#define CACHE_LINE_SIZE             (64)

#elif defined rpi5 // Cortex-A76, TBD

#define VA_BITS                     (40)
// #define BHB_SIZE_BITS               (112)
#define PATH_FP_SRC_ADDR            (false)
#define PATH_FP_SRC_LSH             (2)
#define PATH_FP_SRC_BITS            (7)
#define BHB_LENGTH_PATH_FP_SRC      (0)
#define PATH_FP_DST_ADDR            (true)
#define PATH_FP_DST_LSH             (2)
// #define PATH_FP_DST_BITS            (7)
#define PATH_FP_DST_BITS            (7)
#define BHB_LENGTH_PATH_FP_DST      (16)
#define COND_FP                     (false)
#define COND_FP_BITS                (512)
#define BST_IDX_MSB                 (24)
#define BST_IDX_LSB                 (2)
#define SZ_BTB_EVSET                (16)
#define IB_FAST_THRESHOLD_PMU_EL0   (12)
#define IB_FAST_THRESHOLD_POSIX     (35000)
#define CACHE_LINE_SIZE             (64)
#define BHB_LEN_IB                  (64)

#else
#error "Must specify a valid target"
#endif

#elif defined ARCH_amd64

#define OPCODE_SIZE_NOP             1
#define OPCODE_SIZE_RET             1
#define SIZE_CACHE_STRIDE           256
// SHOULD BE REMOVED
#define OPCODE_SIZE                 16


#if defined zen4
#define SZ_BTB_EVSET                (4)
#define BHB_LEN_IB                  (32)
// SHOULD BE REMOVED
#define COND_FP_BITS                (512)
#endif

#else
#error "Must specify a valid architecture"
#endif




#endif