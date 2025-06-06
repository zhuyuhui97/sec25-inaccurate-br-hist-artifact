#include "tests.h"

void mistrain();

uint64_t *bh_args;
trampoline_obj_t **tramp_btb_bh_evset;
uint64_t **bh_args_mistrain;

__attribute__((aligned(4096))) static uint64_t bhs_bcond_tt = 1;
__attribute__((aligned(4096))) static uint64_t bhs_bcond_nt = 0;

__attribute__((aligned(4096))) 
static uint64_t *argv_bcond_tt[1] = {&bhs_bcond_tt};
static uint64_t *argv_bcond_nt[1] = {&bhs_bcond_nt};
static void *bhs_dc_flush[2] = {&bhs_bcond_tt, &bhs_bcond_nt};
uint64_t mistrain_align = 24;
uint64_t mistrain_passes = 1;
bool mistrain_taken = false;

struct argp_option options[] = 
{
    {"mistrain-align", 0x1000, "NR_BITS", 0, "Align of victim snippet addresses in bits"},
    {"mistrain-passes", 0x1001, "NR_PASSES", 0, "Number of mistraining passes"},
    {"mistrain-taken", 0x1002, 0, 0, "Mistrain with taken branches"},
    {0}
};

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
    struct args_t *arguments = state->input;
    switch (key)
    {
    case 0x1000:
        mistrain_align = strtoul(arg, NULL, 0);
        break;
    case 0x1001:
        mistrain_passes = strtoul(arg, NULL, 0);
        break;
    case 0x1002:
        mistrain_taken = true;
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

struct argp argp = {options, parse_opt, NULL, NULL};
struct argp_child argp_child_test[] = 
{
    {&argp, 0, "Test-specific parameters:"},
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
    .ex_argv = (char **)&argv_bcond_tt
};

test_obj_t test_pht_mistrain = {
    .nr_repeat = NR_TEST_ITER,
    .nr_train_passes = 2,
    .nr_train_chains = 4,
    .train_chains = (bh_chain_params_t *[]){ &chain_bhs_safe, &chain_bhs_leak, &chain_bhs_leak, &chain_bhs_leak},
    .spec_chain = &chain_bhs_test,
    .nr_dc_flush = 2,
    .dc_flush = (void **)&bhs_dc_flush,
    .pre_spec = &mistrain,
    .nr_probes = 1,
    .probes_p = (char *[]){DUMMY_SECRET_P},
    .description = "Train bcond to be NT and test whether we can mistrain the PHT record to TT"
};

test_obj_t test_pht_evict = {
    .nr_repeat = NR_TEST_ITER,
    .nr_train_passes = 2,
    .nr_train_chains = 4,
    .train_chains = (bh_chain_params_t *[]){ &chain_bhs_leak, &chain_bhs_safe, &chain_bhs_safe, &chain_bhs_safe},
    .spec_chain = &chain_bhs_test,
    .nr_dc_flush = 2,
    .dc_flush = (void **)&bhs_dc_flush,
    .pre_spec = &mistrain,
    .nr_probes = 1,
    .probes_p = (char *[]){DUMMY_SECRET_P},
    .description = "Train bcond to be TT and test whether we can evict the BTB record to make it NT"
};

run_obj_t run = {
    .nr_tests = 2,
    // .bp_snippet = &asm_bhs_br_obj,
    .bp_snippet = &jit_bcond_mispred_obj,
    .tests = {&test_pht_mistrain, &test_pht_evict},
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
    bh_args = malloc((args.nr_cond_bh + 1) * sizeof(uint64_t));
    for (int i = 0; i < (args.nr_cond_bh + 1); i++)
        // bh_args[i] = i%2;
        bh_args[i] = 1;
    bh_args[args.nr_cond_bh] = (uint64_t)tramp_victim->jit_mem->call_entry;
}

void free_test_bh_chains()
{
    free(bh_args);
}

void mistrain()
{
    OPS_BARRIER(0x10);
    void *ib_ptr_empty = &t_empty;
    for (int i = 0; i < args.nr_evset; i++)
    for (int j = 0; j < mistrain_passes; j++)
    {
        #if defined(zen4) || defined(rpi5)
        goto_chain(tramp_bcond->jit_mem->call_entry, bh_args_mistrain[i], &ib_ptr_empty, args.nr_for_bh, frbuf, DUMMY_SECRET_P, 1, (char**)argv_bcond_tt);
        goto_chain(tramp_bcond->jit_mem->call_entry, bh_args_mistrain[i], &ib_ptr_empty, args.nr_for_bh, frbuf, DUMMY_SECRET_P, 1, (char**)argv_bcond_nt);
        goto_chain(tramp_bcond->jit_mem->call_entry, bh_args_mistrain[i], &ib_ptr_empty, args.nr_for_bh, frbuf, DUMMY_SECRET_P, 1, (char**)argv_bcond_tt);
        goto_chain(tramp_bcond->jit_mem->call_entry, bh_args_mistrain[i], &ib_ptr_empty, args.nr_for_bh, frbuf, DUMMY_SECRET_P, 1, (char**)argv_bcond_nt);
        #endif
        if (mistrain_taken)
        {
            goto_chain(tramp_bcond->jit_mem->call_entry, bh_args_mistrain[i], &ib_ptr_empty, args.nr_for_bh, frbuf, DUMMY_SECRET_P, 1, (char**)argv_bcond_tt);
            goto_chain(tramp_bcond->jit_mem->call_entry, bh_args_mistrain[i], &ib_ptr_empty, args.nr_for_bh, frbuf, DUMMY_SECRET_P, 1, (char**)argv_bcond_tt);
            goto_chain(tramp_bcond->jit_mem->call_entry, bh_args_mistrain[i], &ib_ptr_empty, args.nr_for_bh, frbuf, DUMMY_SECRET_P, 1, (char**)argv_bcond_tt);
            goto_chain(tramp_bcond->jit_mem->call_entry, bh_args_mistrain[i], &ib_ptr_empty, args.nr_for_bh, frbuf, DUMMY_SECRET_P, 1, (char**)argv_bcond_tt);
        }
        else
        {
            goto_chain(tramp_bcond->jit_mem->call_entry, bh_args_mistrain[i], &ib_ptr_empty, args.nr_for_bh, frbuf, DUMMY_SECRET_P, 1, (char**)argv_bcond_nt);
            goto_chain(tramp_bcond->jit_mem->call_entry, bh_args_mistrain[i], &ib_ptr_empty, args.nr_for_bh, frbuf, DUMMY_SECRET_P, 1, (char**)argv_bcond_nt);
            goto_chain(tramp_bcond->jit_mem->call_entry, bh_args_mistrain[i], &ib_ptr_empty, args.nr_for_bh, frbuf, DUMMY_SECRET_P, 1, (char**)argv_bcond_nt);
            goto_chain(tramp_bcond->jit_mem->call_entry, bh_args_mistrain[i], &ib_ptr_empty, args.nr_for_bh, frbuf, DUMMY_SECRET_P, 1, (char**)argv_bcond_nt);
        }

        
    }
    OPS_BARRIER(0x10);
}

void init_test_evset()
{
    tramp_btb_bh_evset = malloc(args.nr_evset * sizeof(trampoline_obj_t *));
    printf("victim=%llx\n", tramp_victim->jit_mem->call_entry);
    for (int i = 0; i < args.nr_evset; i++)
    // int i = 0;
    {
        // tramp_btb_bh_evset[i] = prep_aligned_snippet(&jit_bhs_evict_obj, (void *)args.victim_snippet_base, mistrain_align+i);
        tramp_btb_bh_evset[i] = prep_aligned_snippet(&jit_bhs_evict_obj, (void *)args.victim_snippet_base, mistrain_align);
        // printf("%llx ", tramp_btb_bh_evset[i]->jit_mem->call_entry);
    }
    // printf("\n");
    bh_args_mistrain = malloc(args.nr_evset * sizeof(uint64_t *));
    for (int i = 0; i < args.nr_evset; i++)
    {
        bh_args_mistrain[i] = malloc((args.nr_cond_bh + 1) * sizeof(uint64_t));
        memcpy(bh_args_mistrain[i], bh_args, (args.nr_cond_bh) * sizeof(uint64_t));
        bh_args_mistrain[i][args.nr_cond_bh] = (uint64_t)tramp_btb_bh_evset[i]->jit_mem->call_entry;
    }
}

void free_test_evset()
{
    for (int i = 0; i < args.nr_evset; i++) free(bh_args_mistrain[i]);
    free(bh_args_mistrain);
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