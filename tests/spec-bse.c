#include "tests.h"

#define NR_BTB_EVICT_VICTIM 1
#define NR_BST_TRAIN 2

void init_btb_pc_targets();
void walk_evset();

trampoline_obj_t **tramp_btb_pc_evset;
uint64_t **targets_btb_pc_evset;
uint64_t *targets_btb_train;
uint64_t *targets_bhb_pc_warmup[NR_TARGET_WARMUP_GROUPS] = {(uint64_t *)&targets_bh_leak, (uint64_t *)&targets_bh_safe};

static uint64_t offsets_btb_train[NR_BST_TRAIN] = {0x10, 0x20};
static uint64_t offets_btb_victim[NR_BTB_EVICT_VICTIM] = {0x100};
static uint64_t btb_evset_base[SZ_BTB_EVSET] = {0x8000000, 0x9000000};

static bh_chain_params_t chain_leak = {
    .bh_chain_p = &bh_chain_common,
    .ib_target = &t_leak,
    .bh_targets_p = &targets_bh_leak,
    .nr_cond_bh = COND_FP_BITS,
    .ib_ptr_p = &ib_ptr,
    .frbuf_p = &frbuf,
    .ptr_secret = &dummy_secret
};

static bh_chain_params_t chain_safe = {
    .bh_chain_p = &bh_chain_common,
    .ib_target = &t_empty,
    .bh_targets_p = &targets_bh_safe,
    .nr_cond_bh = COND_FP_BITS,
    .ib_ptr_p = &ib_ptr,
    .frbuf_p = &frbuf,
    .ptr_secret = &dummy_secret
};

static bh_chain_params_t chain_mispred = {
    .bh_chain_p = &bh_chain_common,
    .ib_target = &t_empty,
    .bh_targets_p = &targets_bh_leak,
    .nr_cond_bh = COND_FP_BITS,
    .ib_ptr_p = &ib_ptr,
    .frbuf_p = &frbuf,
    .ptr_secret = &dummy_secret
};

static bh_chain_params_t *train_chains[2] = {&chain_leak, &chain_safe};

test_obj_t test_spec_v2 = {
    .test_spec = TEST_SPEC_V2,
    .nr_test_passes = NR_TEST_ITER,
    .nr_train_passes = 2,
    .nr_trains = 1,
    .trains = (bh_chain_params_t **)train_chains,
    .test = &chain_mispred,
    .nr_dc_flush = 0,
    .dc_flush_p = NULL,
    .before_train = &init_btb_pc_targets,
    .before_test = &t_empty
};

test_obj_t test_spec_bse_no_ev = {
    .test_spec = TEST_SPEC_NO_BSE,
    .nr_test_passes = NR_TEST_ITER,
    .nr_train_passes = 2,
    .nr_trains = 1,
    .trains = (bh_chain_params_t **)train_chains,
    .test = &chain_safe,
    .nr_dc_flush = 0,
    .dc_flush_p = NULL,
    .before_train = &init_btb_pc_targets,
    .before_test = &t_empty
};

test_obj_t test_spec_bse = {
    .test_spec = TEST_SPEC_BSE,
    .nr_test_passes = NR_TEST_ITER,
    .nr_train_passes = 2,
    .nr_trains = 1,
    .trains = (bh_chain_params_t **)train_chains,
    .test = &chain_safe,
    .nr_dc_flush = 0,
    .dc_flush_p = NULL,
    .before_train = &init_btb_pc_targets,
    .before_test = &walk_evset
};

void btb_pc_record(branch_chain_t *branches, int nr_branches, uint64_t *targets, int64_t nr_targets)
{
    for (int i = 0; i < nr_branches; i++)
        for (int j = 0; j < nr_targets; j++)
            (branches[i])(targets, j, NULL, NULL, NULL, NULL);
}

// Initialize BST entries so all involved branches update BHB
void init_btb_pc_targets()
{
    for (int i = 0; i < NR_TARGET_WARMUP_GROUPS; i++)
        btb_pc_record((branch_chain_t *)(*targets_bhb_pc_warmup[i]), LEN_BH_CHAIN - 1, targets_btb_train, NR_BST_TRAIN);
}

void walk_evset()
{
    for (int i = 0; i < SZ_BTB_EVSET; i++)
        btb_pc_record((branch_chain_t *)targets_btb_pc_evset[i], NR_BTB_EVICT_VICTIM, targets_btb_train, NR_BST_TRAIN);
}

void init_evset()
{
    targets_btb_train = prep_jmp_targets(offsets_btb_train, NR_BST_TRAIN, *tramp_ret);
    tramp_btb_pc_evset = malloc(SZ_BTB_EVSET * sizeof(trampoline_obj_t *));
    for (int i = 0; i < SZ_BTB_EVSET; i++)
        tramp_btb_pc_evset[i] = prep_trampoline(&jit_br_and_inc_idx_obj, NULL, 0, 0, (void *)btb_evset_base[i], 0x4000);
    targets_btb_pc_evset = malloc(SZ_BTB_EVSET * sizeof(uint64_t *));
    for (int i = 0; i < SZ_BTB_EVSET; i++)
        targets_btb_pc_evset[i] = prep_jmp_targets(offets_btb_victim, NR_BTB_EVICT_VICTIM, *tramp_btb_pc_evset[i]);

}

void free_evset()
{
    free(targets_btb_train);
    for (int i = 0; i < SZ_BTB_EVSET; i++) free(targets_btb_pc_evset[i]);
    free(targets_btb_pc_evset);
    for (int i = 0; i < SZ_BTB_EVSET; i++) free_trampoline(tramp_btb_pc_evset[i]);
    free(tramp_btb_pc_evset);
}