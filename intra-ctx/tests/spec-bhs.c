#include "tests.h"
#include "spec-bhs.h"
#include "jit_utils.h"

#if defined DBG_JMP_LATENCY
#define IB_T_LEAK           &t_leak_latency
#define IB_T_ALT            &t_alt_latency
#define IB_T_EMPTY          &t_empty_latency
#define VICTIM_SNIPPET_OBJ  &asm_bhs_br_measure_lat_obj
#define EVICT_SNIPPET_OBJ   &jit_bhs_evict_measure_lat_obj
JIT_ALIGNED_SNIPPET_SYMBOLS(void, asm_bhs_br_measure_lat, uint64_t *offsets, uint64_t idx, char** argv, void **ib_ptr_p, char *frbuf, void *secret_p);
JIT_ALIGNED_SNIPPET_SYMBOLS(void, jit_bhs_evict_measure_lat, uint64_t *offsets, uint64_t idx, char** argv, void **ib_ptr_p);

register uint64_t global_reg_br_lat asm(GLOBAL_REG_BR_LAT_C);
uint64_t **res_jmp_lat;
uint64_t res_jmp_lat_cnt = 0;
uint64_t idx_test=0, idx_iter=0;

void t_leak_latency(register char *frbuf, register uint8_t *secret_ptr)
{
    GET_JMP_LAT_POST_JMP();
    MEM_ACCESS(SC_ENCODE_ADDR(frbuf, secret_ptr));
    NOP(32);
}

void t_alt_latency(register char *frbuf)
{
    GET_JMP_LAT_POST_JMP();
    MEM_ACCESS(SC_ENCODE_ADDR(frbuf, &dummy_secrets[1]));
}

void t_empty_latency()
{
    GET_JMP_LAT_POST_JMP();
    NOP(32);
}

void init_jmp_lat()
{
    res_jmp_lat = malloc(run.nr_tests * sizeof(uint64_t *));
    for (int i = 0; i < run.nr_tests; i++)
        res_jmp_lat[i] = malloc(run.tests[i]->nr_repeat * sizeof(uint64_t));
}

void get_jmp_lat(uint64_t idx_test, uint64_t rept_test)
{
    res_jmp_lat[idx_test][rept_test] = global_reg_br_lat;
}

void print_jmp_lat()
{
    for (int i = 0; i < run.nr_tests; i++)
    {
        printf("--- Test %d: %s\n", i, run.tests[i]->description);
        printf("Branch latency (average of %d tests): ", run.tests[i]->nr_repeat);
        uint64_t sum = 0;
        for (int j = 0; j < run.tests[i]->nr_repeat; j++)
        {
            sum += res_jmp_lat[i][j];
        }
        printf("%lu ", sum / run.tests[i]->nr_repeat);
        printf("\n");
    }
}

#else
#define IB_T_LEAK           &t_leak
#define IB_T_ALT            &t_alt
#define IB_T_EMPTY          &t_empty
#define VICTIM_SNIPPET_OBJ  &asm_bhs_br_obj
#define EVICT_SNIPPET_OBJ   &jit_bhs_evict_obj
#endif

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
    {"mistrain-align", 0x1000, "NR_BITS", 0, "Align of mistraining snippet addresses in bits"},
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

static bh_chain_params_t chain_bhs_train_tt = {
    .bh_tramp_p = &tramp_bcond,
    .ib_target = IB_T_ALT,
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

static bh_chain_params_t chain_bhs_train_nt = {
    .bh_tramp_p = &tramp_bcond,
    .ib_target = IB_T_LEAK,
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

static bh_chain_params_t chain_bhs_test_tt = {
    .bh_tramp_p = &tramp_bcond,
    .ib_target = IB_T_EMPTY,
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

static bh_chain_params_t chain_bhs_test_nt = {
    .bh_tramp_p = &tramp_bcond,
    .ib_target = IB_T_EMPTY,
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

test_obj_t train_tt_test_tt = {
    .nr_repeat = NR_TEST_ITER,
    .nr_train_passes = 4,
    .nr_train_chains = 4,
    .train_chains = (bh_chain_params_t *[]){&chain_bhs_train_nt, &chain_bhs_train_tt, &chain_bhs_train_tt, &chain_bhs_train_tt},
    .spec_chain = &chain_bhs_test_tt,
    .nr_dc_flush = 2,
    .dc_flush = (void **)&bhs_dc_flush,
    .pre_spec = &mistrain,
#ifdef DBG_JMP_LATENCY
    .post_spec = &get_jmp_lat,
#endif
    .nr_probes = 2,
    .probes_p = (char *[]){DUMMY_SECRET_P, DUMMY_SECRET_ALT_P},
    .description = "Train Bc_prime biased to TT and test with TT"
};

test_obj_t train_nt_test_tt = {
    .nr_repeat = NR_TEST_ITER,
    .nr_train_passes = 4,
    .nr_train_chains = 4,
    .train_chains = (bh_chain_params_t *[]){&chain_bhs_train_tt, &chain_bhs_train_nt, &chain_bhs_train_nt, &chain_bhs_train_nt},
    .spec_chain = &chain_bhs_test_tt,
    .nr_dc_flush = 2,
    .dc_flush = (void **)&bhs_dc_flush,
    .pre_spec = &mistrain,
#ifdef DBG_JMP_LATENCY
    .post_spec = &get_jmp_lat,
#endif
    .nr_probes = 2,
    .probes_p = (char *[]){DUMMY_SECRET_P, DUMMY_SECRET_ALT_P},
    .description = "Train Bc_prime biased to NT and test with TT"
};

test_obj_t train_nt_test_nt = {
    .nr_repeat = NR_TEST_ITER,
    .nr_train_passes = 4,
    .nr_train_chains = 4,
    .train_chains = (bh_chain_params_t *[]){&chain_bhs_train_tt, &chain_bhs_train_nt, &chain_bhs_train_nt, &chain_bhs_train_nt},
    .spec_chain = &chain_bhs_test_nt,
    .nr_dc_flush = 2,
    .dc_flush = (void **)&bhs_dc_flush,
    .pre_spec = &mistrain,
#ifdef DBG_JMP_LATENCY
    .post_spec = &get_jmp_lat,
#endif
    .nr_probes = 2,
    .probes_p = (char *[]){DUMMY_SECRET_P, DUMMY_SECRET_ALT_P},
    .description = "Train Bc_prime biased to NT and test with NT"
};

test_obj_t train_tt_test_nt = {
    .nr_repeat = NR_TEST_ITER,
    .nr_train_passes = 4,
    .nr_train_chains = 4,
    .train_chains = (bh_chain_params_t *[]){&chain_bhs_train_nt, &chain_bhs_train_tt, &chain_bhs_train_tt, &chain_bhs_train_tt},
    .spec_chain = &chain_bhs_test_nt,
    .nr_dc_flush = 2,
    .dc_flush = (void **)&bhs_dc_flush,
    .pre_spec = &mistrain,
#ifdef DBG_JMP_LATENCY
    .post_spec = &get_jmp_lat,
#endif
    .nr_probes = 2,
    .probes_p = (char *[]){DUMMY_SECRET_P, DUMMY_SECRET_ALT_P},
    .description = "Train Bc_prime biased to TT and test with NT"
};

run_obj_t run = {
    .nr_tests = 4,
    .bp_snippet = VICTIM_SNIPPET_OBJ,
    .tests = {&train_tt_test_tt, &train_nt_test_tt, &train_tt_test_nt, &train_nt_test_nt},
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
        bh_args[i] = i%2;
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
        #if !defined(DBG_NO_BH_PROMO)
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
    for (int i = 0; i < args.nr_evset; i++)
    {
        tramp_btb_bh_evset[i] = prep_aligned_snippet(EVICT_SNIPPET_OBJ, (void *)args.victim_snippet_base, mistrain_align);
    }
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
#ifdef DBG_JMP_LATENCY
    init_jmp_lat();
#endif
    init_test_bh_chains();
    init_test_evset();
}

void free_test()
{
#ifdef DBG_JMP_LATENCY
    print_jmp_lat();
    for (int i = 0; i < run.nr_tests; i++)
        free(res_jmp_lat[i]);
    free(res_jmp_lat);
#endif
    free_test_bh_chains();
    free_test_evset();
}