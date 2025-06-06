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

#ifndef __EVICT_PROBES_H__
#define __EVICT_PROBES_H__
#include <stdint.h>
#include "jit_snippets.h"
#include "utils.h"

enum BPU_CACHE_ACTION
{
    BPU_CACHE_ACTION_EVICT,
    BPU_CACHE_ACTION_INSERT,
};

void do_bst_mgmt(int invoke_list_len, jit_bst_entry_blr_t *invoke_list, void *param_list[]);
void bst_record_create(int probe_idx);
void do_bpu_cache_evict(int probe_idx);
void prep_cache_mgmt_invoke_list(void *tramp_ret, jit_bst_entry_blr_t probe_gadgets[N_PROBES]);

#endif