#include "tests.h"

#define LEN_DUMMY_BH_CHAIN 8
#define NR_BTB_EVICT_VICTIM 1
#define NR_BST_TRAIN 2
#define NR_TARGET_WARMUP_GROUPS 2
#define BH_OFFSET_DEFAULT 0x20

struct argp_child argp_child_test[] = {0};

void init_btb_pc_targets();
void walk_evset();

uint64_t *targets_bh_leak;
uint64_t *targets_bh_safe;

trampoline_obj_t **snippets_evset;
branch_chain_t *targets_btb_pc_evset;
uint64_t *targets_btb_train;
uint64_t *targets_bhb_pc_warmup[NR_TARGET_WARMUP_GROUPS] = {(uint64_t *)&targets_bh_leak, (uint64_t *)&targets_bh_safe};

static uint64_t offsets_btb_train[NR_BST_TRAIN] = {0x10, 0x20};
static uint64_t offsets_btb_victim[NR_BTB_EVICT_VICTIM] = {0x100};
uint64_t offsets_bh_leak_dummy[LEN_DUMMY_BH_CHAIN] = {0x00, 0x20, 0x40, 0x60, 0x80, 0xa0, 0xc0, 0x00};
uint64_t offsets_bh_safe_dummy[LEN_DUMMY_BH_CHAIN] = {0x20, 0x40, 0x60, 0x80, 0xa0, 0xc0, 0x100, 0xe0};

static bh_chain_params_t chain_leak = {
    .bh_tramp_p = &tramp_br,
    .ib_target = &t_leak,
    .bh_args_p = &targets_bh_leak,
    .nr_bh_cond_p = &args.nr_cond_bh,
    .nr_bh_ind_p = &args.nr_ind_bh,
    .nr_bh_for_p = &args.nr_for_bh,
    .ib_ptr_p = IBPTR,
    .frbuf_p = &frbuf,
    .secret_p = DUMMY_SECRET_P
};

static bh_chain_params_t chain_safe = {
    .bh_tramp_p = &tramp_br,
    .ib_target = &t_alt,
    .bh_args_p = &targets_bh_safe,
    .nr_bh_cond_p = &args.nr_cond_bh,
    .nr_bh_ind_p = &args.nr_ind_bh,
    .nr_bh_for_p = &args.nr_for_bh,
    .ib_ptr_p = IBPTR,
    .frbuf_p = &frbuf,
    .secret_p = DUMMY_SECRET_P
};

static bh_chain_params_t chain_mispred = {
    .bh_tramp_p = &tramp_br,
    .ib_target = &t_empty,
    .bh_args_p = &targets_bh_leak,
    .nr_bh_cond_p = &args.nr_cond_bh,
    .nr_bh_ind_p = &args.nr_ind_bh,
    .nr_bh_for_p = &args.nr_for_bh,
    .ib_ptr_p = IBPTR,
    .frbuf_p = &frbuf,
    .secret_p = DUMMY_SECRET_P
};

static bh_chain_params_t *train_chains[2] = {&chain_leak, &chain_safe};

test_obj_t test_spec_v2 = {
    .nr_repeat = NR_TEST_ITER,
    .nr_train_passes = 2,
    .nr_train_chains = 2,
    .train_chains = (bh_chain_params_t **)train_chains,
    .spec_chain = &chain_mispred,
    .nr_dc_flush = 0,
    .dc_flush = NULL,
    .pre_train = &init_btb_pc_targets,
    .nr_probes = 2,
    .probes_p = (char *[]){DUMMY_SECRET_P, DUMMY_SECRET_ALT_P},
    .description = "Spectre-v2"
};

test_obj_t test_spec_bse_no_ev = {
    .nr_repeat = NR_TEST_ITER,
    .nr_train_passes = 2,
    .nr_train_chains = 2,
    .train_chains = (bh_chain_params_t **)train_chains,
    .spec_chain = &chain_safe,
    .nr_dc_flush = 0,
    .dc_flush = NULL,
    .pre_train = &init_btb_pc_targets,
    .nr_probes = 2,
    .probes_p = (char *[]){DUMMY_SECRET_P, DUMMY_SECRET_ALT_P},
    .description = "Different BH"
};

test_obj_t test_spec_bse = {
    .nr_repeat = NR_TEST_ITER,
    .nr_train_passes = 2,
    .nr_train_chains = 2,
    .train_chains = (bh_chain_params_t **)train_chains,
    .spec_chain = &chain_safe,
    .nr_dc_flush = 0,
    .dc_flush = NULL,
    .pre_train = &init_btb_pc_targets,
    .pre_spec = &walk_evset,
    .nr_probes = 2,
    .probes_p = (char *[]){DUMMY_SECRET_P, DUMMY_SECRET_ALT_P},
    .description = "Different BH with Spectre-BSE"
};

run_obj_t run = {
    .nr_tests = 3,
    .bp_snippet = &asm_br_obj,
    .tests = {&test_spec_v2, &test_spec_bse_no_ev, &test_spec_bse}
};

uint64_t test_continue = true;
bool next_run()
{
    bool ret = test_continue;
    test_continue &= false;
    return ret;
}

void btb_pc_record(branch_chain_t *branches, int nr_branches, uint64_t *targets, int64_t nr_targets)
{
    for (int i = 0; i < nr_branches; i++)
        for (int j = 0; j < nr_targets; j++)
            (branches[i])(targets, j, NULL, NULL, NULL, NULL);
}

// Initialize BST entries so all involved branches update BHB
void init_btb_pc_targets()
{
    for (int i = 0; i < NR_TARGET_WARMUP_GROUPS; i++)
        btb_pc_record((branch_chain_t *)(*targets_bhb_pc_warmup[i]), args.nr_ind_bh, targets_btb_train, NR_BST_TRAIN);
}

uint64_t* init_targets(uint64_t *dummy, uint64_t len_dummy, uint64_t len_bh, trampoline_obj_t *tramp, void *last)
{
    uint64_t *offsets_tmp = malloc((len_bh + 1) * sizeof(uint64_t));
    int w_start = (len_bh >= len_dummy) ? len_bh - len_dummy : 0;
    int r_start = (len_bh >= len_dummy) ? 0 : len_dummy - len_bh;
    for (int i=0; i<w_start; i++)
        offsets_tmp[i] = BH_OFFSET_DEFAULT;
    for (int i=w_start; i < len_bh; i++)
        offsets_tmp[i] = dummy[i - w_start + r_start];
    uint64_t* targets = prep_jmp_targets(offsets_tmp, len_bh + 1, tramp);
    targets[len_bh] = (uint64_t)last;
    free(offsets_tmp);
    return targets;
}

void init_test_bh_chains()
{
    targets_bh_leak = init_targets(offsets_bh_leak_dummy, LEN_DUMMY_BH_CHAIN, args.nr_ind_bh, tramp_br, tramp_victim->jit_mem->call_entry);
    targets_bh_safe = init_targets(offsets_bh_safe_dummy, LEN_DUMMY_BH_CHAIN, args.nr_ind_bh, tramp_br, tramp_victim->jit_mem->call_entry);
}

void free_test_bh_chains()
{
    free(targets_bh_leak);
    free(targets_bh_safe);
}

void walk_evset()
{
    btb_pc_record(targets_btb_pc_evset, NR_BTB_EVICT_VICTIM * args.nr_evset, targets_btb_train, NR_BST_TRAIN);
}

void init_test_evset()
{
    targets_btb_train = prep_jmp_targets(offsets_btb_train, NR_BST_TRAIN, tramp_ret);
    snippets_evset = malloc(NR_BTB_EVICT_VICTIM * args.nr_evset * sizeof(trampoline_obj_t *));
    targets_btb_pc_evset = malloc(NR_BTB_EVICT_VICTIM * args.nr_evset * sizeof(branch_chain_t *));
    uint64_t *targets_btb_victim = prep_jmp_targets(offsets_btb_victim, NR_BTB_EVICT_VICTIM, tramp_br);
    int tramp_snippet_offset = tramp_br->jump_snippet->align - tramp_br->jump_snippet->entry;
    for (int i = 0; i < NR_BTB_EVICT_VICTIM; i++)
    {
        for (int j = 0; j < args.nr_evset; j++)
        {
            int idx = i * args.nr_evset + j;
            snippets_evset[idx] = prep_aligned_snippet(&jit_br_and_inc_idx_obj, (void *)targets_btb_victim[i] + tramp_snippet_offset, 24);
            targets_btb_pc_evset[idx] = snippets_evset[idx]->jit_mem->call_entry;
        }
    }
    free(targets_btb_victim);
}

void free_test_evset()
{
    for (int i = 0; i < NR_BTB_EVICT_VICTIM * args.nr_evset; i++)
        free_trampoline(snippets_evset[i]);
    free(snippets_evset);
    free(targets_btb_pc_evset);
    free(targets_btb_train);
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