#include "tests.h"

uint64_t *bh_args[2];
trampoline_obj_t *tramp_bh_a, *tramp_bh_b;
trampoline_obj_t *tramp_bcond_alt = NULL;

bool bh_ind_first = false;
bool test_bh_bcond_path = false;
bool bh_bcond_same_arg = false;
bool bh_br_same_arg = false;

struct argp_option options[] = 
{
    {"ind-first", 0x1000, 0, 0, "Use indirect branch trampoline before the conditional branches to populate the BHB."},
    {"bcond-path", 0x1001, 0, 0, "Populate the BHB with two bcond trampolines that have different offset values and same branching arguments."},
    {"bcond-same-arg", 0x1002, 0, 0, "Populate the BHB using bcond trampolines with same branching arguments. ALWAYS TRUE when \"--bcond-path\" is set."},
    {"br-same-arg", 0x1003, 0, 0, "Populate the BHB using br trampolines with same branching arguments."},
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
    case 0x1001:
        test_bh_bcond_path = true;
        bh_bcond_same_arg = true;
        break;
    case 0x1002:
        bh_bcond_same_arg = true;
        break;
    case 0x1003:
        bh_br_same_arg = true;
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
    .bh_tramp_p = &tramp_bh_a,
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
    .bh_tramp_p = &tramp_bh_b,
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
    .bh_tramp_p = &tramp_bh_a,
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

/**
 * BUG: A76 iBTB updates when trained with new results for at least 3 times?
 */
test_obj_t test_spec_bhs = {
    .nr_repeat = NR_TEST_ITER,
    .nr_train_passes = 4,
    .nr_train_chains = 4,
    .train_chains = (bh_chain_params_t *[]){&chain_bhs_leak, &chain_bhs_safe, &chain_bhs_safe, &chain_bhs_safe},
    .spec_chain = &chain_bhs_test,
    .nr_dc_flush = 0,
    .dc_flush = NULL,
    .nr_probes = 2,
    .probes_p = (char *[]){DUMMY_SECRET_P, DUMMY_SECRET_ALT_P},
    .description = "Train with {leak,safe} and test with safe"
};

test_obj_t test_pht_mistrain = {
    .nr_repeat = NR_TEST_ITER,
    .nr_train_passes = 4,
    .nr_train_chains = 4,
    .train_chains = (bh_chain_params_t *[]){&chain_bhs_safe, &chain_bhs_leak, &chain_bhs_leak, &chain_bhs_leak},
    .spec_chain = &chain_bhs_test,
    .nr_dc_flush = 0,
    .dc_flush = NULL,
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
    tramp_bcond_alt = tramp_bcond; // same as tramp_bcond by default
    if (test_bh_bcond_path)
    {
        tramp_bcond_alt = prep_trampoline(&jit_bcond_and_inc_idx_obj, &jit_nop_obj, &jit_br_and_inc_idx_obj, 0, 4, NULL, args.nr_cond_bh *(jit_bcond_and_inc_idx_obj.end - jit_bcond_and_inc_idx_obj.entry));
        // chain_bhs_leak.bh_tramp_p = &tramp_bcond_alt;
    }
    if (args.nr_cond_bh == 0 && args.nr_ind_bh == 0)
    {
        tramp_bh_a = tramp_victim;
        tramp_bh_b = tramp_victim;
        return;
    }
    else if (args.nr_cond_bh == 0 && args.nr_ind_bh != 0)
    {
        tramp_bh_a = tramp_br;
        tramp_bh_b = tramp_br;
    }
    else if (args.nr_cond_bh != 0 && args.nr_ind_bh == 0)
    {
        tramp_bh_a = tramp_bcond;
        tramp_bh_b = tramp_bcond_alt;
    }
    else
    {
        tramp_bh_a = bh_ind_first ? tramp_br : tramp_bcond;
        tramp_bh_b = bh_ind_first ? tramp_br : tramp_bcond_alt;
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

        for (int i = 0; i < args.nr_cond_bh; i++) bh_cond_args[0][i] = bh_bcond_same_arg ? (i % 2) : (i % 2 - 1);
        for (int i = 0; i < args.nr_cond_bh; i++) bh_cond_args[1][i] = i % 2;

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
            bh_ind_offset_args[0][i] = (i+1) << 6;
            // bh_ind_offset_args[0][i] = 0x20;

        if (bh_br_same_arg)
            memcpy(bh_ind_offset_args[1], bh_ind_offset_args[0], args.nr_ind_bh * sizeof(uint64_t));
        else
        {
            for (int i = 0; i < args.nr_ind_bh; i++)
                bh_ind_offset_args[1][i] = (i+2) << 6;
                // bh_ind_offset_args[1][i] = 0x410;
        }

        bh_ind_addr_args[0] = prep_jmp_targets(bh_ind_offset_args[0], args.nr_ind_bh, tramp_br);
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
        uint64_t args_offset = bh_ind_first ? args.nr_ind_bh : args.nr_cond_bh;
        // trampoline_obj_t *tramp_bh_secondary = bh_ind_first ? tramp_bcond : tramp_br;
        if (bh_ind_first)
        {
            bh_args[0][args_offset] = (uint64_t)tramp_bcond->jit_mem->call_entry;
            bh_args[1][args_offset] = (uint64_t)tramp_bcond_alt->jit_mem->call_entry;
        }
        else
        {
            bh_args[0][args_offset] = (uint64_t)tramp_br->jit_mem->call_entry;
            bh_args[1][args_offset] = (uint64_t)tramp_br->jit_mem->call_entry;
        }
    }
    bh_args[0][nr_bh_args - 1] = (uint64_t)tramp_victim->jit_mem->call_entry;
    bh_args[1][nr_bh_args - 1] = (uint64_t)tramp_victim->jit_mem->call_entry;
}

void free_test_bh_chains()
{
    free(bh_args[0]);
    free(bh_args[1]);
    if (test_bh_bcond_path)
        free_trampoline(tramp_bcond_alt);
}

void init_test()
{
    init_test_bh_chains();
}

void free_test()
{
    free_test_bh_chains();
}