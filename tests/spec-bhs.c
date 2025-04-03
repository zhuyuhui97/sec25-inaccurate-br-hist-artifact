#include "tests.h"

void walk_btb_bh_evset();

trampoline_obj_t **tramp_btb_bh_evset;
uint64_t **targets_btb_bh_evset;

__attribute__((aligned(4096))) static uint64_t bhs_bcond_tt = 1;
__attribute__((aligned(4096))) static uint64_t bhs_bcond_nt = 0;

static uint64_t *argv_bhs_safe[1] = {&bhs_bcond_tt};
static uint64_t *argv_bhs_leak[1] = {&bhs_bcond_nt};
static void *bhs_dc_flush[2] = {&bhs_bcond_tt, &bhs_bcond_nt};

static bh_chain_params_t chain_bhs_safe = {
    .bh_chain_p = &bh_chain_common,
    .ib_target = &t_empty,
    .bh_targets_p = &targets_bh_safe,
    .nr_cond_bh = COND_FP_BITS,
    .ib_ptr_p = &ib_ptr,
    .frbuf_p = &frbuf,
    .secret_p = &dummy_secret,
    .ex_argc = 1,
    .ex_argv = (char **)&argv_bhs_safe
};

static bh_chain_params_t chain_bhs_leak = {
    .bh_chain_p = &bh_chain_common,
    .ib_target = &t_leak,
    .bh_targets_p = &targets_bh_safe,
    .nr_cond_bh = COND_FP_BITS,
    .ib_ptr_p = &ib_ptr,
    .frbuf_p = &frbuf,
    .secret_p = &dummy_secret,
    .ex_argc = 1,
    .ex_argv = (char **)&argv_bhs_leak
};

static bh_chain_params_t *train_chains_bhs[2] = {&chain_bhs_leak, &chain_bhs_safe};

test_obj_t test_spec_bhs = {
    .type = TEST_SPEC_BSE,
    .nr_repeat = NR_TEST_ITER,
    .nr_train_passes = 2,
    .nr_train_chains = 2,
    .train_chains = (bh_chain_params_t **)train_chains_bhs,
    .test_chain = &chain_bhs_safe,
    .nr_dc_flush = 2,
    .dc_flush_p = (void **)&bhs_dc_flush,
    .before_train = &t_empty,
    .before_test = &walk_btb_bh_evset
};

void walk_evset()
{
    for (int i = 0; i < SZ_BTB_EVSET; i++)
        goto_chain(bh_chain_common, targets_btb_bh_evset[i], &ib_ptr_empty, COND_FP_BITS, NULL, NULL, 0, NULL);
}

void init_evset()
{
    tramp_btb_bh_evset = malloc(SZ_BTB_EVSET * sizeof(trampoline_obj_t *));
    for (int i = 0; i < SZ_BTB_EVSET; i++)
        tramp_btb_bh_evset[i] = prep_aligned_snippet(&jit_bhs_evict_obj, &__asm_bhs_br_align, 16);
    targets_btb_bh_evset = malloc(SZ_BTB_EVSET * sizeof(uint64_t *));
    for (int i = 0; i < SZ_BTB_EVSET; i++)
    {
        targets_btb_bh_evset[i] = prep_jmp_targets(offsets_bh_safe, LEN_BH_CHAIN, *tramp_br);
        targets_btb_bh_evset[i][LEN_BH_CHAIN - 1] = (uint64_t)tramp_btb_bh_evset[i]->jit_mem->call_entry;
    }
}

void free_evset()
{
    for (int i = 0; i < SZ_BTB_EVSET; i++) free(targets_btb_bh_evset[i]);
    free(targets_btb_bh_evset);
    for (int i = 0; i < SZ_BTB_EVSET; i++) free_trampoline(tramp_btb_bh_evset[i]);
    free(tramp_btb_bh_evset);
}