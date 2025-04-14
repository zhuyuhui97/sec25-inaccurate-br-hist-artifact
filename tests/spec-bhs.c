#include "tests.h"

void walk_btb_bh_evset();

uint64_t *offsets_bh;
uint64_t *targets_bh;
trampoline_obj_t **tramp_btb_bh_evset;
uint64_t **targets_btb_bh_evset;

__attribute__((aligned(4096))) static uint64_t bhs_bcond_tt = 1;
__attribute__((aligned(4096))) static uint64_t bhs_bcond_nt = 0;

__attribute__((aligned(4096))) 
static uint64_t *argv_bhs_safe[1] = {&bhs_bcond_tt};
static uint64_t *argv_bhs_leak[1] = {&bhs_bcond_nt};
static void *bhs_dc_flush[2] = {&bhs_bcond_tt, &bhs_bcond_nt};

static bh_chain_params_t chain_bhs_safe = {
    .bh_tramp_p = &tramp_br,
    .ib_target = &t_empty,
    .bh_targets_p = &targets_bh,
    .nr_bh_cond_p = &args.nr_cond_bh,
    .nr_bh_ind_p = &args.nr_ind_bh,
    .ib_ptr_p = &ib_ptr,
    .frbuf_p = &frbuf,
    .secret_p = &dummy_secret,
    .ex_argc = 1,
    .ex_argv = (char **)&argv_bhs_safe
};

static bh_chain_params_t chain_bhs_leak = {
    .bh_tramp_p = &tramp_br,
    .ib_target = &t_leak,
    .bh_targets_p = &targets_bh,
    .nr_bh_cond_p = &args.nr_cond_bh,
    .nr_bh_ind_p = &args.nr_ind_bh,
    .ib_ptr_p = &ib_ptr,
    .frbuf_p = &frbuf,
    .secret_p = &dummy_secret,
    .ex_argc = 1,
    .ex_argv = (char **)&argv_bhs_leak
};

static bh_chain_params_t *train_chains_bhs[3] = {&chain_bhs_leak, &chain_bhs_safe, &chain_bhs_safe};

test_obj_t test_spec_bhs = {
    .nr_repeat = NR_TEST_ITER,
    .nr_train_passes = 32,
    .nr_train_chains = 2,
    .train_chains = (bh_chain_params_t **)train_chains_bhs,
    .test_chain = &chain_bhs_safe,
    .nr_dc_flush = 2,
    .dc_flush = (void **)&bhs_dc_flush,
    .before_train = &t_empty,
    .before_test = &walk_evset,
    .bp_snippet = &asm_bhs_br,
    .description = "Different BH with Spectre-BHS"
};

run_obj_t run = {
    .nr_tests = 1,
    .tests = {&test_spec_bhs}
};

void init_test_bh_chains()
{
    offsets_bh = malloc(BHB_LEN_IB * sizeof(uint64_t));
    for (int i = 0; i < BHB_LEN_IB; i++)
        offsets_bh[i] = ((i+1)<<5) & (0x1000-1);
    targets_bh = prep_jmp_targets(offsets_bh, BHB_LEN_IB, tramp_br);
    targets_bh[BHB_LEN_IB - 1] = (uint64_t)&asm_bhs_br;
}

void free_test_bh_chains()
{
    free(offsets_bh);
    free(targets_bh);
}


void walk_evset()
{
    OPS_BARRIER(0x10);
    for (int i = 0; i < args.nr_evset; i++)
        goto_chain(tramp_br->jit_mem->call_entry, targets_btb_bh_evset[i], &ib_ptr_empty, COND_FP_BITS, NULL, NULL, 0, NULL);
    OPS_BARRIER(0x10);
}

void init_evset()
{
    tramp_btb_bh_evset = malloc(args.nr_evset * sizeof(trampoline_obj_t *));
    for (int i = 0; i < args.nr_evset; i++)
        tramp_btb_bh_evset[i] = prep_aligned_snippet(&jit_bhs_evict_obj, &__asm_bhs_br_align, 16);
    targets_btb_bh_evset = malloc(args.nr_evset * sizeof(uint64_t *));
    for (int i = 0; i < args.nr_evset; i++)
    {
        targets_btb_bh_evset[i] = prep_jmp_targets(offsets_bh, BHB_LEN_IB, tramp_br);
        targets_btb_bh_evset[i][BHB_LEN_IB - 1] = (uint64_t)tramp_btb_bh_evset[i]->jit_mem->call_entry;
    }
}

void free_evset()
{
    for (int i = 0; i < args.nr_evset; i++) free(targets_btb_bh_evset[i]);
    free(targets_btb_bh_evset);
    for (int i = 0; i < args.nr_evset; i++) free_trampoline(tramp_btb_bh_evset[i]);
    free(tramp_btb_bh_evset);
}