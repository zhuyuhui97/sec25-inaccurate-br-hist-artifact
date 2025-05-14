#include "tests.h"

uint64_t *bh_args[2];
trampoline_obj_t **tramp_btb_bh_evset;
uint64_t **targets_btb_bh_evset;
trampoline_obj_t *tramp_bh_default;
bool bh_ind_first = false;

struct argp_option options[] = 
{
    {"ind-first", 0x1000, 0, 0, "Use indirect branch trampoline before the conditional branches to populate the BHB."},
    {0}
};

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
    struct args_t *arguments = state->input;
    switch (key)
    {
    case 0x1000:
        bh_ind_first = true;
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
    .bh_tramp_p = &tramp_bh_default,
    .ib_target = &t_alt,
    .bh_args_p = &bh_args[0],
    .nr_bh_for_p = &args.nr_for_bh,
    .nr_bh_cond_p = &args.nr_cond_bh,
    .nr_bh_ind_p = &args.nr_ind_bh,
    .ib_ptr_p = IBPTR,
    .frbuf_p = &frbuf,
    .secret_p = DUMMY_SECRET_P,
    .ex_argc = 0,
    .ex_argv = NULL
};

static bh_chain_params_t chain_bhs_leak = {
    .bh_tramp_p = &tramp_bh_default,
    .ib_target = &t_leak,
    .bh_args_p = &bh_args[1],
    .nr_bh_for_p = &args.nr_for_bh,
    .nr_bh_cond_p = &args.nr_cond_bh,
    .nr_bh_ind_p = &args.nr_ind_bh,
    .ib_ptr_p = IBPTR,
    .frbuf_p = &frbuf,
    .secret_p = DUMMY_SECRET_P,
    .ex_argc = 0,
    .ex_argv = NULL
};

static bh_chain_params_t chain_bhs_test = {
    .bh_tramp_p = &tramp_bh_default,
    .ib_target = &t_empty,
    .bh_args_p = &bh_args[0],
    .nr_bh_for_p = &args.nr_for_bh,
    .nr_bh_cond_p = &args.nr_cond_bh,
    .nr_bh_ind_p = &args.nr_ind_bh,
    .ib_ptr_p = IBPTR,
    .frbuf_p = &frbuf,
    .secret_p = DUMMY_SECRET_P,
    .ex_argc = 0,
    .ex_argv = NULL
};

test_obj_t test_spec_bhs = {
    .nr_repeat = NR_TEST_ITER,
    .nr_train_passes = 2,
    .nr_train_chains = 2,
    .train_chains = (bh_chain_params_t *[]){&chain_bhs_leak, &chain_bhs_safe},
    .test_chain = &chain_bhs_test,
    .nr_dc_flush = 0,
    .dc_flush = NULL,
    .before_train = &t_empty,
    .before_test = &t_empty,
    .nr_probes = 2,
    .probes_p = (char *[]){DUMMY_SECRET_P, DUMMY_SECRET_ALT_P},
    .description = "Train with {leak,safe} and test with safe"
};

test_obj_t test_pht_mistrain = {
    .nr_repeat = NR_TEST_ITER,
    .nr_train_passes = 2,
    .nr_train_chains = 2,
    .train_chains = (bh_chain_params_t *[]){ &chain_bhs_safe, &chain_bhs_leak},
    .test_chain = &chain_bhs_test,
    .nr_dc_flush = 0,
    .dc_flush = NULL,
    .before_train = &t_empty,
    .before_test = &t_empty,
    .nr_probes = 2,
    .probes_p = (char *[]){DUMMY_SECRET_P, DUMMY_SECRET_ALT_P},
    .description = "Train with {safe,leak} and test with safe"
};

run_obj_t run = {
    .nr_tests = 2,
    .bp_snippet = &asm_br_obj,
    .tests = {&test_spec_bhs, &test_pht_mistrain},
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
    if (args.nr_cond_bh == 0 && args.nr_ind_bh == 0)
    {
        tramp_bh_default = tramp_victim;
        return;
    }
    else if (args.nr_cond_bh == 0 && args.nr_ind_bh != 0)
    {
        tramp_bh_default = tramp_br;
    }
    else if (args.nr_cond_bh != 0 && args.nr_ind_bh == 0)
    {
        tramp_bh_default = tramp_bcond;
    }
    else
    {
        tramp_bh_default = bh_ind_first ? tramp_br : tramp_bcond;
    }

    uint64_t *bh_ind_offset_args[2] = {0};
    uint64_t *bh_ind_addr_args[2] = {0};
    uint64_t *bh_cond_args[2] = {0};

    uint64_t nr_cond_args = (args.nr_cond_bh == 0) ? 0 : (args.nr_cond_bh + 1);
    uint64_t nr_ind_args = (args.nr_ind_bh == 0) ? 0 : (args.nr_ind_bh + 1);
    uint64_t nr_bh_args = nr_cond_args + nr_ind_args;

    bh_args[0] = malloc(nr_bh_args * sizeof(uint64_t));
    bh_args[1] = malloc(nr_bh_args * sizeof(uint64_t));

    if (args.nr_cond_bh != 0)
    {

        bh_cond_args[0] = malloc(args.nr_cond_bh * sizeof(uint64_t));
        bh_cond_args[1] = malloc(args.nr_cond_bh * sizeof(uint64_t));

        for (int i = 0; i < args.nr_cond_bh; i++) bh_cond_args[0][i] = i % 2 - 1;
        for (int i = 0; i < args.nr_cond_bh; i++) bh_cond_args[0][i] = i % 2 ;
        // for (int i = 0; i < args.nr_cond_bh; i++) bh_cond_args[1][i] = i % 2;

        uint64_t args_start_offset = bh_ind_first ? nr_ind_args : 0;
        memcpy(&bh_args[0][args_start_offset], &bh_cond_args[0][0], args.nr_cond_bh * sizeof(uint64_t));
        memcpy(&bh_args[1][args_start_offset], &bh_cond_args[1][0], args.nr_cond_bh * sizeof(uint64_t));

        free(bh_cond_args[0]);
        free(bh_cond_args[1]);
    }

    if (args.nr_ind_bh != 0)
    {
        bh_ind_offset_args[0] = malloc(args.nr_ind_bh * sizeof(uint64_t));
        bh_ind_offset_args[1] = malloc(args.nr_ind_bh * sizeof(uint64_t));

        for (int i = 0; i < args.nr_ind_bh; i++)
            bh_ind_offset_args[0][i] = 0x00;
        bh_ind_addr_args[0] = prep_jmp_targets(bh_ind_offset_args[0], args.nr_ind_bh, tramp_br);
        for (int i = 0; i < args.nr_ind_bh; i++)
            bh_ind_offset_args[1][i] = 0x410;
        bh_ind_addr_args[1] = prep_jmp_targets(bh_ind_offset_args[1], args.nr_ind_bh, tramp_br);

        uint64_t args_start_offset = bh_ind_first ? 0 : nr_cond_args;
        memcpy(&bh_args[0][args_start_offset], &bh_ind_addr_args[0][0], args.nr_ind_bh * sizeof(uint64_t));
        memcpy(&bh_args[1][args_start_offset], &bh_ind_addr_args[1][0], args.nr_ind_bh * sizeof(uint64_t));

        free(bh_ind_offset_args[0]);
        free(bh_ind_offset_args[1]);
        free(bh_ind_addr_args[0]);
        free(bh_ind_addr_args[1]);
    }

    if (args.nr_cond_bh != 0 && args.nr_ind_bh != 0)
    {
        uint64_t args_offset = bh_ind_first ? args.nr_cond_bh : args.nr_cond_bh;
        trampoline_obj_t *tramp_bh_secondary = bh_ind_first ? tramp_bcond : tramp_br;
        bh_args[0][args_offset] = (uint64_t)tramp_bh_secondary->jit_mem->call_entry;
        bh_args[1][args_offset] = (uint64_t)tramp_bh_secondary->jit_mem->call_entry;
    }
    bh_args[0][nr_bh_args - 1] = (uint64_t)tramp_victim->jit_mem->call_entry;
    bh_args[1][nr_bh_args - 1] = (uint64_t)tramp_victim->jit_mem->call_entry;
}

void free_test_bh_chains()
{
    free(bh_args[0]);
    free(bh_args[1]);
}

void init_test()
{
    init_test_bh_chains();
}

void free_test()
{
    free_test_bh_chains();
}