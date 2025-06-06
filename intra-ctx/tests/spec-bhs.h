#ifndef SPEC_BHS_H
#define SPEC_BHS_H

#ifdef DBG_JMP_LATENCY
#if defined ARCH_amd64
    #define GLOBAL_REG_BR_LAT           %r14
    #define GLOBAL_REG_BR_LAT_C         "r14"
    #define GET_JMP_LAT_POST_JMP() \
        register uint64_t cnt_new_lo asm("eax"), cnt_new_hi asm("edx"); \
        asm volatile("rdtsc\n" : "=a" (cnt_new_lo), "=d" (cnt_new_hi) ::); \
        global_reg_br_lat = ((cnt_new_hi<<32)|cnt_new_lo) - global_reg_br_lat; 
#elif defined ARCH_aarch64
    #define GLOBAL_REG_BR_LAT           x24
    #define GLOBAL_REG_BR_LAT_C         "x24"
    #define GET_JMP_LAT_POST_JMP() \
        register uint64_t cnt_new; \
        asm volatile("mrs %0, pmccntr_el0" : "=r"(cnt_new)); \
        global_reg_br_lat = cnt_new - global_reg_br_lat; 
#endif
#else
    #define GET_JMP_LAT_POST_JMP()
#endif

#endif