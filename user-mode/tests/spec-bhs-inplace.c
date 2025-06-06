#include "tests.h"

void mistrain();

uint64_t *bh_args;
trampoline_obj_t **tramp_btb_bh_evset;

__attribute__((aligned(4096))) static uint64_t bhs_bcond_tt = 1;
__attribute__((aligned(4096))) static uint64_t bhs_bcond_nt = 0;
__attribute__((aligned(4096))) static uint64_t bhs_exit_tt = 1;
__attribute__((aligned(4096))) static uint64_t bhs_exit_nt = 0;

__attribute__((aligned(4096))) 
static uint64_t *argv_bcond_tt[2] = {&bhs_bcond_tt, &bhs_exit_tt};
static uint64_t *argv_bcond_nt[2] = {&bhs_bcond_nt, &bhs_exit_tt};
static uint64_t *argv_bcond_mistrain[2] = {&bhs_bcond_nt, &bhs_exit_nt};
static void *bhs_dc_flush[4] = {&bhs_bcond_tt, &bhs_bcond_nt, &bhs_exit_tt, &bhs_exit_nt};


struct argp_child argp_child_test[] = 
{
    {0}
};

static bh_chain_params_t chain_bhs_safe = {
    .bh_tramp_p = &tramp_bcond,
    .ib_target = &t_alt,
    .bh_args_p = &bh_args,
    .nr_bh_cond_p = &args.nr_cond_bh,
    .nr_bh_ind_p = &args.nr_ind_bh,
    .nr_bh_for_p = &args.nr_for_bh,
    .ib_ptr_p = IBPTR,
    .frbuf_p = &frbuf,
    .secret_p = DUMMY_SECRET_P,
    .ex_argc = 1,
    .ex_argv = (char **)&argv_bcond_tt
    // .ex_argv = (char **)&argv_bcond_nt
};

static bh_chain_params_t chain_bhs_leak = {
    .bh_tramp_p = &tramp_bcond,
    .ib_target = &t_leak,
    .bh_args_p = &bh_args,
    .nr_bh_cond_p = &args.nr_cond_bh,
    .nr_bh_ind_p = &args.nr_ind_bh,
    .nr_bh_for_p = &args.nr_for_bh,
    .ib_ptr_p = IBPTR,
    .frbuf_p = &frbuf,
    .secret_p = DUMMY_SECRET_P,
    .ex_argc = 1,
    .ex_argv = (char **)&argv_bcond_nt
    // .ex_argv = (char **)&argv_bcond_tt
};

static bh_chain_params_t chain_bhs_test = {
    .bh_tramp_p = &tramp_bcond,
    .ib_target = &t_empty,
    .bh_args_p = &bh_args,
    .nr_bh_cond_p = &args.nr_cond_bh,
    .nr_bh_ind_p = &args.nr_ind_bh,
    .nr_bh_for_p = &args.nr_for_bh,
    .ib_ptr_p = IBPTR,
    .frbuf_p = &frbuf,
    .secret_p = DUMMY_SECRET_P,
    .ex_argc = 1,
    // .ex_argv = (char **)&argv_bcond_tt
    .ex_argv = (char **)&argv_bcond_mistrain
};

test_obj_t test_spec_bhs = {
    .nr_repeat = NR_TEST_ITER,
    .nr_train_passes = 4,
    .nr_train_chains = 2,
    .train_chains = (bh_chain_params_t *[]){&chain_bhs_leak, &chain_bhs_safe, &chain_bhs_safe},
    .spec_chain = &chain_bhs_test,
    .nr_dc_flush = 4,
    .dc_flush = (void **)&bhs_dc_flush,
    .pre_train = &t_empty,
    .pre_spec = &mistrain,
    .nr_probes = 2,
    .probes_p = (char *[]){DUMMY_SECRET_P, DUMMY_SECRET_ALT_P},
    .description = "Train with {leak,safe} and test with safe"
};

test_obj_t test_pht_mistrain = {
    .nr_repeat = NR_TEST_ITER,
    .nr_train_passes = 4,
    .nr_train_chains = 2,
    .train_chains = (bh_chain_params_t *[]){ &chain_bhs_safe, &chain_bhs_leak, &chain_bhs_safe},
    .spec_chain = &chain_bhs_test,
    .nr_dc_flush = 4,
    .dc_flush = (void **)&bhs_dc_flush,
    .pre_train = &t_empty,
    .pre_spec = &mistrain,
    .nr_probes = 2,
    .probes_p = (char *[]){DUMMY_SECRET_P, DUMMY_SECRET_ALT_P},
    .description = "Train with {safe,leak} and test with safe"
};

run_obj_t run = {
    .nr_tests = 2,
    .bp_snippet = &asm_bhs_br_obj,
    .tests = {&test_spec_bhs, &test_pht_mistrain},
};

void victim_snippet(uint64_t *offsets, uint64_t idx, char** argv, void **ib_ptr_p, void *frbuf, void *secret_p)
{
    OPS_BARRIER(0x10);
    if (*argv[0] == 0)
    {
        NOP(0x10);
    }
    if (*argv[1] == 0)
    {
        return;
        NOP(0x10);
    }
    
    void (*ib_ptr)(void *, void *) = *ib_ptr_p;
    ib_ptr(frbuf, secret_p);
}

uint64_t test_continue = true;
bool next_run()
{
    bool ret = test_continue;
    test_continue &= false;
    return ret;
}

void init_test_bh_chains()
{
    bh_args = malloc((args.nr_cond_bh + 1) * sizeof(uint64_t));
    for (int i = 0; i < (args.nr_cond_bh + 1); i++)
        bh_args[i] = i%2;
    bh_args[args.nr_cond_bh] = (uint64_t)(&victim_snippet);
}

void free_test_bh_chains()
{
    free(bh_args);
}

void mistrain()
{
    OPS_BARRIER(0x10);
    void *ib_ptr_empty = &t_alt;
    goto_chain(tramp_bcond->jit_mem->call_entry, bh_args, &ib_ptr_empty, args.nr_for_bh, frbuf, DUMMY_SECRET_P, 1, (char**)argv_bcond_tt);
    // goto_chain(tramp_bcond->jit_mem->call_entry, bh_args, &ib_ptr_empty, args.nr_for_bh, frbuf, DUMMY_SECRET_P, 1, (char**)argv_bcond_tt);
    for (int i = 0; i < args.nr_evset; i++)
    {
        goto_chain(tramp_bcond->jit_mem->call_entry, bh_args, NULL, args.nr_for_bh, frbuf, DUMMY_SECRET_P, 1, (char**)argv_bcond_mistrain);
    }
    OPS_BARRIER(0x10);
}

void init_test()
{
    init_test_bh_chains();
}

void free_test()
{
    free_test_bh_chains();
}