#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <asm/memory.h>


/* ---  BiasScope  --- */
#define BIASSCOPE_PROBE_N 8

typedef void (*biasscope_evict_bcond_t)(uint64_t, uint64_t);
extern void biasscope_evict_base(void);

static const uint64_t probe_offsets[BIASSCOPE_PROBE_N] = {0x2000, 0x2080, 0x21c0, 0x2180, 0x2200, 0x2280, 0x2340, 0x2380};
biasscope_evict_bcond_t evicts[8];

SYSCALL_DEFINE1(biasscope_send, uint64_t, payload)
{
    int i=0;
    for (; i<BIASSCOPE_PROBE_N; i++)
    {
        ((biasscope_evict_bcond_t)(&biasscope_evict_base + probe_offsets[i] - 0x0c))(payload, i);
    }
    return 0;
}

/* ---  Spectre-BSE  --- */
#define SIZE_CACHE_STRIDE 256

#define MACRO_TO_STR(x) #x
#define __NOP(x, rsh) asm volatile(".rept " MACRO_TO_STR(x>>rsh) "\n nop\n .endr")
#define NOP(x) __NOP(x, 0)
#define MEM_ACCESS(p) *(volatile unsigned char *)p

void specbse_victim_snippet(void* ret_mem, uint32_t* offset, void* target, void *probe_base, uint8_t *secret_ptr);
void specbhs_victim_snippet(uint64_t *r0, uint64_t r1, uint64_t* bx_prime_cond, void** ib_ptr_p, char *frbuf, void *secret_p);
void populate_bhb_tbz(uint64_t bits);
void ret_tramp(void);
void populate_bhb(uint64_t x);

__attribute__((aligned(128))) void *func_ptr;
__attribute__((aligned(128))) uint8_t* cache_probe_mem;

__attribute__((aligned(128))) uint64_t cond_aux;
__attribute__((aligned(128))) uint64_t bx_prime_cond;

//                                     |----------| <- not recorded by BHB if non-biased marks are evicted
uint32_t ib_fp_t_safe[6] = {0x30, 0x30, 0x20, 0x10, 0x30, 0x30};
uint32_t ib_fp_t_leak[6] = {0x00, 0x00, 0x30, 0x30, 0x30, 0x30};
uint32_t ib_fp_set_non_bias0[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
uint32_t ib_fp_set_non_bias1[6] = {0x30, 0x30, 0x30, 0x30, 0x30, 0x30};
uint8_t specbse_dummy_secret[8] = {128, 0, 0, 0, 0, 0, 0, 0};

enum specbse_victim_option
{
    BSE_V_OPT_SETUP,
    BSE_V_OPT_SAFE,
    BSE_V_OPT_LEAK
};

void target_leak(void *probe_base, uint8_t *secret_ptr)
{
    // write the cache side channel
    // MEM_ACCESS(&probe_base[(*secret_ptr) * SIZE_CACHE_STRIDE]);
    // leave a mark in PMU to indicate speculative execution of this gadget
    // less noisy than the cache side channel
    // DEBUG feature, not mandatory
    asm volatile("fmov s0, #1.3e+01");
    NOP(128);
}

void target_safe(void)
{
    NOP(128);
}

SYSCALL_DEFINE2(specbse_victim, enum specbse_victim_option, opt, uint8_t*, addr)
{
    switch (opt)
    {
        case BSE_V_OPT_SETUP:
            cache_probe_mem = addr;
            func_ptr = &ret_tramp;
            specbse_victim_snippet(&ret_tramp, ib_fp_set_non_bias0, &func_ptr, 0, 0);
            specbse_victim_snippet(&ret_tramp, ib_fp_set_non_bias1, &func_ptr, 0, 0);
            specbse_victim_snippet(&ret_tramp, ib_fp_set_non_bias0, &func_ptr, 0, 0);
            specbse_victim_snippet(&ret_tramp, ib_fp_set_non_bias1, &func_ptr, 0, 0);
            NOP(4);
            populate_bhb_tbz(0); NOP(4);
            populate_bhb_tbz(~0); NOP(4);
            populate_bhb_tbz(0); NOP(4);
            populate_bhb_tbz(~0); NOP(4);
            break;
        case BSE_V_OPT_SAFE:
            func_ptr = (void (*)(void))&target_safe;
            populate_bhb_tbz(0); NOP(4);
            specbse_victim_snippet(&ret_tramp, ib_fp_t_safe, &func_ptr, 0, 0);
            break;
        case BSE_V_OPT_LEAK:
            func_ptr = (void (*)(void))&target_leak;
            populate_bhb_tbz(0); NOP(4);
            specbse_victim_snippet(&ret_tramp, ib_fp_t_leak, &func_ptr, cache_probe_mem, addr); // TODO
            break;
    }
    return 0;
}

SYSCALL_DEFINE1(specbhs_victim, uint8_t, __bx_prime_cond)
{
    bx_prime_cond = __bx_prime_cond;
    func_ptr = (__bx_prime_cond > 0) ? (void *) &target_safe : (void*) &target_leak;
    asm volatile("dc civac, %0" ::"r"(&bx_prime_cond));

    populate_bhb(24);
    asm volatile("dsb ish");
    asm volatile("isb");
    specbhs_victim_snippet(0, 0, &bx_prime_cond, &func_ptr, 0, 0);
    return 0;
}

#define ARMV7_PMUSERENR_ENABLE (1 << 0)
#define ARMV7_PMCR_E (1 << 0) /* Enable all counters */
#define ARMV7_PMCR_P (1 << 1) /* Reset all counters */
#define ARMV7_PMCR_C (1 << 2) /* Cycle counter reset */
#define ARMV7_PMCR_D (1 << 3) /* Cycle counts every 64th cpu cycle */
#define ARMV7_PMCR_X (1 << 4) /* Export to ETM */

static void pmu_enable_base_armv8(void)
{
    uint64_t value = 1;
    uint64_t _tmp_value = 0;

    printk("Getting PMUSERENR:\n");
    __asm__ volatile("MRS %0, PMUSERENR_EL0" : "=r"(_tmp_value));
    printk("%d\n", _tmp_value);

    // configure the PMUSERENR register for user mode access - unfortunately I think this only works in kernel mode!
    // printf("Configuring PMUSERENR: probably won't work!\n");
    __asm__ volatile("MSR PMUSERENR_EL0, %0" ::"r"(value));


    // configure the PMCR register: E, P, C, X, but no clock divider.

    value |= ARMV7_PMCR_E; // Enable all counters
    value |= ARMV7_PMCR_P; // Reset all counters
    value |= ARMV7_PMCR_C; // Reset cycle counter to zero
    value |= ARMV7_PMCR_X; // Enable export of events

    __asm__ volatile("MSR PMCR_EL0, %0" ::"r"(value));

    // configure the Count Enable Set Register (PMCNTENSET) to enable the Cycle Count Register (PMCCNTR) and PMEVCNTR0 to 5
    // value = 0xff;
    __asm__ volatile("MRS %0, PMCNTENSET_EL0" :"=r"(value));
    value |= 1 << 31;
    // MCR coproc, opcode1, Rd, CRn, CRm [,opcode2]
    __asm__ volatile("MSR PMCNTENSET_EL0, %0" ::"r"(value));

    // configure the Overflow Status Register (PMOVSR) - same
    __asm__ volatile("MSR PMOVSSET_EL0, %0" ::"r"(value));
}

static void pmu_enable_ev(void)
{
    uint64_t xt;
    __asm__ volatile("MRS %0, PMCNTENSET_EL0" :"=r"(xt));
    printk(KERN_INFO "PMCNTENSET_EL0=%x", xt);
    xt |= 1 << 31;
    xt |= 15;
    __asm__ volatile("MSR PMCNTENSET_EL0, %0" ::"r"(xt));
    printk(KERN_INFO "PMCNTENSET_EL0:=%x", xt);
}

SYSCALL_DEFINE0(enable_pmu_el0)
{
    pmu_enable_base_armv8();
    pmu_enable_ev();
    return 0;
}
