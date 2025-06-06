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

#ifndef __ARCH_H__
#define __ARCH_H__

#define BHB_SIZE_BITS               (BHB_LENGTH_PATH_FP_DST * PATH_FP_DST_BITS)
#define BHB_LENGTH_COND_FP          (BHB_SIZE_BITS)
#define PATH_FP_MASK(BITS, LSH)     (((1 << BITS) - 1) << LSH)
#define PATH_FP_SRC_MASK            PATH_FP_MASK(PATH_FP_SRC_BITS, PATH_FP_SRC_LSH)
#define PATH_FP_DST_MASK            PATH_FP_MASK(PATH_FP_DST_BITS, PATH_FP_DST_LSH)
#define BST_IDX_MASK                (((1 << BST_IDX_MSB) - 1) ^ ((1 << BST_IDX_LSB) - 1))

#if defined imx8 // Cortex-A72

#define ARCH_AARCH64
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
#define BST_WAYS                    (4)
#define IB_FAST_THRESHOLD_PMU_EL0   (12)
#define IB_FAST_THRESHOLD_POSIX     (35000)
#define CACHE_LINE_SIZE             (64)

#elif defined orin // Cortex-A78, TBD

#define ARCH_AARCH64
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

#define ARCH_AARCH64
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
#define COND_FP_BITS                (0)
#define BST_IDX_MSB                 (24)
#define BST_IDX_LSB                 (2)
#define BST_WAYS                    (8)
#define IB_FAST_THRESHOLD_PMU_EL0   (12)
#define IB_FAST_THRESHOLD_POSIX     (35000)
#define CACHE_LINE_SIZE             (64)

#else
#error "Must specify a target"
#endif

#if defined ARCH_AARCH64
#define OPCODE_ADDR_ALIGN           2
#define OPCODE_SIZE                 (1 << OPCODE_ADDR_ALIGN)
#define OPCODE_ADDR_MASK            (~(OPCODE_SIZE - 1))
#endif


#ifdef DBG_PMU_EL0
#define IB_FAST_THRESHOLD IB_FAST_THRESHOLD_PMU_EL0
#else
#define IB_FAST_THRESHOLD IB_FAST_THRESHOLD_POSIX
#endif

#endif