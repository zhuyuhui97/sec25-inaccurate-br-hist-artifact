#include "tests.h"

struct argp_child argp_child_test[] = {0};

void mistrain();

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
    .ib_target = &t_alt,
    .bh_args_p = &targets_bh,
    .nr_bh_cond_p = &args.nr_cond_bh,
    .nr_bh_ind_p = &args.nr_ind_bh,
    .nr_bh_for_p = &args.nr_for_bh,
    .ib_ptr_p = IBPTR,
    .frbuf_p = &frbuf,
    .secret_p = DUMMY_SECRET_P,
    .ex_argc = 1,
    .ex_argv = (char **)&argv_bhs_safe
};

static bh_chain_params_t chain_bhs_leak = {
    .bh_tramp_p = &tramp_br,
    .ib_target = &t_empty,
    .bh_args_p = &targets_bh,
    .nr_bh_cond_p = &args.nr_cond_bh,
    .nr_bh_ind_p = &args.nr_ind_bh,
    .nr_bh_for_p = &args.nr_for_bh,
    .ib_ptr_p = IBPTR,
    .frbuf_p = &frbuf,
    .secret_p = DUMMY_SECRET_P,
    .ex_argc = 1,
    .ex_argv = (char **)&argv_bhs_leak
};

static bh_chain_params_t chain_bhs_test = {
    .bh_tramp_p = &tramp_br,
    .ib_target = &t_empty,
    .bh_args_p = &targets_bh,
    .nr_bh_cond_p = &args.nr_cond_bh,
    .nr_bh_ind_p = &args.nr_ind_bh,
    .nr_bh_for_p = &args.nr_for_bh,
    .ib_ptr_p = IBPTR,
    .frbuf_p = &frbuf,
    .secret_p = DUMMY_SECRET_P,
    .ex_argc = 1,
    .ex_argv = (char **)&argv_bhs_safe
};

test_obj_t test_spec_bhs = {
    .nr_repeat = NR_TEST_ITER,
    .nr_train_passes = 1,
    .nr_train_chains = 2,
    // .train_chains = (bh_chain_params_t *[]){&chain_bhs_leak, &chain_bhs_safe},
    .train_chains = (bh_chain_params_t *[]){&chain_bhs_safe, &chain_bhs_leak},
    .spec_chain = &chain_bhs_test,
    .nr_dc_flush = 2,
    .dc_flush = (void **)&bhs_dc_flush,
    .pre_train = &t_empty,
    .pre_spec = &mistrain,
    .nr_probes = 2,
    .probes_p = (char *[]){DUMMY_SECRET_P, DUMMY_SECRET_ALT_P},
    .description = "Different BH with Spectre-BHS"
};

run_obj_t run = {
    .nr_tests = 1,
    .bp_snippet = &asm_bhs_br_obj,
    .tests = {&test_spec_bhs}
};

uint64_t test_continue = true;
bool next_run()
{
    bool ret = test_continue;
    test_continue &= false;
    return ret;
}

void init_test_bh_chains()
{
    offsets_bh = malloc((args.nr_ind_bh + 1) * sizeof(uint64_t));
    for (int i = 0; i < (args.nr_ind_bh + 1); i++)
        offsets_bh[i] = ((i+1)<<5) & (0x1000-1);
    targets_bh = prep_jmp_targets(offsets_bh, (args.nr_ind_bh + 1), tramp_br);
    targets_bh[args.nr_ind_bh] = (uint64_t)tramp_victim->jit_mem->call_entry;
}

void free_test_bh_chains()
{
    free(offsets_bh);
    free(targets_bh);
}

void mistrain()
{
    OPS_BARRIER(0x10);
    void *ib_ptr_tmp = &t_leak;
    for (int i = 0; i < args.nr_evset; i++)
        goto_chain(tramp_br->jit_mem->call_entry, targets_btb_bh_evset[i], &ib_ptr_tmp, args.nr_for_bh, frbuf, DUMMY_SECRET_P, 1, (char**)argv_bhs_leak);
    OPS_BARRIER(0x10);
}

void init_test_evset()
{
    tramp_btb_bh_evset = malloc(args.nr_evset * sizeof(trampoline_obj_t *));
    for (int i = 0; i < args.nr_evset; i++)
        tramp_btb_bh_evset[i] = prep_aligned_snippet(&jit_bhs_evict_obj, (void *)args.victim_snippet_base, 24);
    targets_btb_bh_evset = malloc(args.nr_evset * sizeof(uint64_t *));
    for (int i = 0; i < args.nr_evset; i++)
    {
        targets_btb_bh_evset[i] = prep_jmp_targets(offsets_bh, (args.nr_ind_bh + 1), tramp_br);
        targets_btb_bh_evset[i][args.nr_ind_bh] = (uint64_t)tramp_btb_bh_evset[i]->jit_mem->call_entry;
    }
}

void free_test_evset()
{
    for (int i = 0; i < args.nr_evset; i++) free(targets_btb_bh_evset[i]);
    free(targets_btb_bh_evset);
    for (int i = 0; i < args.nr_evset; i++) free_trampoline(tramp_btb_bh_evset[i]);
    free(tramp_btb_bh_evset);
}

void init_test()
{
    init_test_bh_chains();
    init_test_evset();
}

void free_test()
{
    free_test_bh_chains();
    free_test_evset();
}