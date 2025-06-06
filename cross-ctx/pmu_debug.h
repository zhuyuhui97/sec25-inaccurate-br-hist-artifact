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

#ifndef _PMU_H_
#define _PMU_H_
#ifdef DBG_PMU_EL0
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
// https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/plain/include/linux/perf/arm_pmuv3.h?h=v6.6.8
#include "arm_pmuv3.h"

#define INT2STR(x) #x
#define PMEVTYPERm(x) "PMEVTYPER" INT2STR(x) "_EL0"
#define PMEVCNTRm(x) "PMEVCNTR" INT2STR(x) "_EL0"

uint64_t global_cntr_t_vfp_spec = 0;
uint64_t global_cntr_cycle = 0;
uint64_t global_cntr_cycle_train = 0;
uint64_t global_cntr_l1_refill = 0;
register uint64_t __cntr_l1_refill asm("x21");
register uint64_t __mark_ASE asm("x22");
register uint64_t __cntr_target1_spec asm("x23");
register uint64_t __cntr_target2_spec asm("x24");

extern uint8_t res_marks[];
extern uint64_t __timer;

// NOTE: Linux running in EL2 because of ARMv8.1 VHE              
#define __INIT_PMU(cntr, mask)                                  \
    register uint64_t xt;                                       \
    /* enable event */                                          \
    __asm__ volatile("MRS %0, " PMEVTYPERm(cntr) : "=r"(xt));   \
    xt &= ~0xFFFF;                                              \
    xt |= mask;                                                 \
    xt |= ARMV8_PMU_INCLUDE_EL2;                                \
    __asm__ volatile("MSR " PMEVTYPERm(cntr) ", %0" ::"r"(xt)); \
    /* reset counter */                                         \
    xt = 0;                                                     \
    __asm__ volatile("MSR " PMEVCNTRm(cntr) ", %0" ::"r"(xt));  \
    /* enable counter */                                        \
    __asm__ volatile("MRS %0, PMCNTENSET_EL0" : "=r"(xt));      \
    xt |= 1 << cntr;                                            \
    __asm__ volatile("MSR PMCNTENSET_EL0, %0" ::"r"(xt));

/**
 * Debug counter for probing if branch predictor mis-training succeeded
 */
#define CIDX_VFP_SPEC 5
void inline __attribute__ ((always_inline)) init_pmu_VFP_SPEC(){
    __INIT_PMU(CIDX_VFP_SPEC, ARMV8_IMPDEF_PERFCTR_VFP_SPEC)
}

uint64_t inline __attribute__ ((always_inline)) get_mark_VFP_SPEC()
{
    uint64_t xt;
    __asm__ volatile("MRS %0, " PMEVCNTRm(CIDX_VFP_SPEC) : "=r"(xt));
    return xt;
}

/**
 * Debug counter for out-of-border IB speculation
*/
#define CIDX_ASE_SPEC 3
void inline __attribute__ ((always_inline)) init_pmu_ASE_SPEC(){
    __INIT_PMU(CIDX_ASE_SPEC, ARMV8_IMPDEF_PERFCTR_ASE_SPEC)
}

uint64_t inline __attribute__ ((always_inline)) get_mark_ASE_SPEC()
{
    uint64_t xt;
    __asm__ volatile("MRS %0, " PMEVCNTRm(CIDX_ASE_SPEC) : "=r"(xt));
    // printf("%d\n", xt);
    return xt;
}

/**
 * Debug counter for L1 refill or miss
 */
#define CIDX_L1I_CACHE_REFILL 1
void inline __attribute__ ((always_inline)) init_pmu_L1I_CACHE_REFILL(){
    __INIT_PMU(CIDX_L1I_CACHE_REFILL, ARMV8_PMUV3_PERFCTR_L1I_CACHE_REFILL)
    // __INIT_PMU(CIDX_L1I_CACHE_REFILL, ARMV8_IMPDEF_PERFCTR_ASE_SPEC)
}

uint64_t inline __attribute__ ((always_inline)) get_mark_L1I_CACHE_REFILL()
{
    uint64_t xt;
    __asm__ volatile("MRS %0, " PMEVCNTRm(CIDX_L1I_CACHE_REFILL) : "=r"(xt));
    return xt;
}

/**
 * Debug counter for speculated instructions
 */
#define CIDX_INST_SPEC 2
void inline __attribute__ ((always_inline)) init_pmu_INST_SPEC(){
    __INIT_PMU(CIDX_INST_SPEC, ARMV8_PMUV3_PERFCTR_INST_SPEC)}

uint64_t inline __attribute__ ((always_inline)) get_mark_INST_SPEC()
{
    uint64_t xt;
    __asm__ volatile("MRS %0, " PMEVCNTRm(CIDX_INST_SPEC) : "=r"(xt));
    return xt;
}


/**
 * Debug counter for clock cycles
 */
void inline __attribute__ ((always_inline)) init_pmu_ccntr()
{
    register uint64_t xt;
    __asm__ volatile("MRS %0, PMCNTENSET_EL0" : "=r"(xt));
    xt |= 1 << 31;
    __asm__ volatile("MSR PMCNTENSET_EL0, %0" ::"r"(xt));
}

uint64_t inline __attribute__ ((always_inline)) get_pmu_ccntr()
{
    register uint64_t xt;
    asm volatile("mrs %0, pmccntr_el0" : "=r"(xt));
    return xt;
}

void inline __attribute__ ((always_inline)) init_pmu()
{
    init_pmu_ccntr();
    init_pmu_VFP_SPEC();
    init_pmu_L1I_CACHE_REFILL();
    init_pmu_INST_SPEC();
    init_pmu_ASE_SPEC();
}

void inline __always_inline DBG_PMU_EL0_evcntrs_reset()
{
    global_cntr_t_vfp_spec = 0;
    global_cntr_l1_refill = 0;
    global_cntr_cycle = 0;
}

// Get counter values before the branch prediction is fired.
void inline __always_inline DBG_PMU_EL0_evcntrs_pre_spec(int i_iter)
{
    __cntr_target1_spec = get_mark_VFP_SPEC();
    __cntr_target2_spec = get_mark_ASE_SPEC();
    __cntr_l1_refill = get_mark_L1I_CACHE_REFILL();
}

// Collect counter values after the speculation.
void inline __always_inline DBG_PMU_EL0_evcntrs_post_spec(int i_iter)
{
    res_marks[i_iter] = get_mark_VFP_SPEC() - __cntr_target1_spec;
    global_cntr_t_vfp_spec += res_marks[i_iter];
    global_cntr_l1_refill += get_mark_L1I_CACHE_REFILL() - __cntr_l1_refill;
    global_cntr_cycle += __timer;
}

#define DBG_PMU_EL0_ccntrs_pre_br() asm volatile("mrs %0, pmccntr_el0" : "=r"(__timer))
#define DBG_PMU_EL0_ccntrs_post_br() __timer = get_pmu_ccntr() - __timer;
#else // DBG_PMU_EL0
#define init_pmu()
#define DBG_PMU_EL0_evcntrs_reset()
#define DBG_PMU_EL0_evcntrs_pre_spec(i_iter)
#define DBG_PMU_EL0_evcntrs_post_spec(i_iter)
#define DBG_PMU_EL0_ccntrs_pre_br() NOP(1)
#define DBG_PMU_EL0_ccntrs_post_br() 
#endif // DBG_PMU_EL0
#endif