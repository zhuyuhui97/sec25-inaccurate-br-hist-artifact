# Artifact code for paper "Exploiting Inaccurate Branch History in Side-Channel Attacks" - User-Mode Intra-Process PoCs

This artifact contains PoC codes demonstrating the vulnerable mechanism and attack flows described in the paper using intra-mode attack processes. Note they don't mount a practical attack, just demonstrating the exploited primitives and the corresponding microarchitectural behaviors.

## Project Structure

```
├── main.c              # Main entry point and test orchestration
├── tests/              # Test modules for specific attack scenarios
│   ├── pht-idx.c      # BTB/PHT mistraining and eviction (Sec. 3.3)
│   ├── spec-bse.c     # Spectre-BSE attack (Sec. 5.4)
│   ├── spec-bhs.c     # Spectre-BHS attack (Sec. 6.2)
│   └── chimera.c      # Chimera snippet based on C language (Sec. 7)
├── include/            # Header files and utility definitions
├── utils/              # JIT compilation and side-channel utilities
├── arch/               # Architecture-specific JIT snippets
└── build/              # Generated executables
```

## Building the Artifact

### Clean Build
***Always*** run `make clean` before building to ensure a fresh compilation:

```bash
make clean
```

### Build Commands

**For ARM64 (cross-compilation):**
```bash
make TEST=<test_name> ARCH=aarch64 CROSS_COMPILE=aarch64-linux-gnu-
```
You will need the `aarch64-linux-gnu-gcc` toolchain installed on your system. This can typically be done via your package manager (e.g., `apt install gcc-aarch64-linux-gnu` on Debian-based systems).

**For x86_64 (native compilation):**
```bash
make TEST=<test_name> ARCH=amd64
```

**Available test names:**
- `pht-idx`: BTB/PHT mistraining experiments (Sec. 3.3)
- `spec-bse`: Spectre-BSE attack demonstration (Sec. 5.4)
- `spec-bhs`: Spectre-BHS attack demonstration (Sec. 6.2)
- `chimera`: Spectre-BHS attack demonstration using Chimera gadget (Sec. 7)

The executable will be generated as `build/main`.

**Optional build flags:**
Some modules support additional flags for debugging or specific behaviors. You can pass these flags during the build process with appending `FLAGS="FLAG1 FLAG2 ..."` to the `make` command. For example:

```bash
make TEST=spec-bhs ARCH=aarch64 CROSS_COMPILE=aarch64-linux-gnu- FLAGS="DBG_ARCH_BH DBG_JMP_LATENCY"
```

## Usage

### Global Parameters

All tests share these command-line arguments:

| Parameter                | Description                                | Example        |
| ------------------------ | ------------------------------------------ | -------------- |
| `-f, --for-bh=N`         | Number of for-loop jumps to fill BHB       | `-f 8`         |
| `-c, --cond-bh=N`        | Number of conditional branches to fill BHB | `-c 100`       |
| `-i, --ind-bh=N`         | Number of indirect branches to fill BHB    | `-i 4`         |
| `-e, --evset-size=N`     | Number of mistraining branches             | `-e 32`        |
| `-v, --victim-base=ADDR` | Base address of victim code (hex)          | `-v 0xc000c30` |
| `-t, --tramp-bits=N`     | Trampoline size bits (12-24)               | `-t 16`        |

**Notes:**
1. A for-loop may not sufficient to populate the BHB completely on some microarchitectures, so besides `-f`, you may need `-c` or `-i` to fill the BHB.
2. The test modules may select populating the BHB with either indirect branches, conditional branches, or both of them depending on the implementation. This means the `-c` and `-i` arguments may not be used in some tests. We will specify the details in the corresponding test modules below.

### Running Tests

**General execution pattern:**
```bash
# Pin to specific CPU core for consistent results
taskset -c <core_id> ./build/main [global_args] [test_specific_args]
```

## Test Modules

### 1. **`pht-idx`** - BTB/PHT Mistraining (Section 3.3)

This module demonstrates BTB/PHT mistraining and eviction effects on the prediction of a conditional branch. 

In this module, the *victim* is a conditional branch jumping over a memory load. In its two sub-tests, it is either constantly taken or not taken. The user can employ a number of mistraining snippets (specified with `-e`) sharing the same BTB/PHT entry to influence the prediction of the victim branch.

This module uses *conditional branches* to fill the BHB, please use `-c` to specify the number BHB-filling branches.

**BHB population method:** Conditional branches (`-c` parameter).

**Debugging flags:**
This module requires several compiling flags to control the behavior of the mistraining snippets and branch history manipulation. You may use them in the `make` command to enable the corresponding features:

- `DBG_MISTRAIN_NO_BTB_PROMOTE`: This flag masks out the extra executions of the mistraining snippet using different branch histories before the execution of desired mistrainings. We found that, on some processors like Cortex-A76 and Zen4, enabling this is mandatory to make the mistraining branches able to influence the prediction of `Bx_prime`, which means that the branch prediction record is only promoted to the history-based mode when the branch is executed under different branch histories and different results. We enable this by default and you can disable it for debugging with `FLAGS=DBG_MISTRAIN_NO_BTB_PROMOTE`.
- `DBG_ZEN4_BTB_EVICT`: On Zen4, we observed that only *a conditional branch crossing a 4 KB boundary* can evict a BTB/PHT entry and successfully trigger Straight-Line Speculation. When testing Straight-Line Speculation (and BTB/PHT eviction) on Zen4, please enable this flag with `FLAGS=DBG_ZEN4_BTB_EVICT`. This is not needed on other microarchitectures.

**Additional parameters:**
- `--mistrain-pass=NR_PASSES`: Number of mistraining passes.
- `--mistrain-align=NR_BITS`: Alignment for mistraining. The mistraning snippets will be copied to addresses making the lower `NR_BITS` bits of the address identical to the victim.
- `--mistrain-taken`: Optional. If set, the mistraining branches will be taken. Otherwise, they will not be taken.

**Example usages:**

1. Mistraining a victim branch with single mistraining branch biased to not taken.

```bash
$ taskset -c 3 build/main -c100 -v0xc000c30 -e1 --mistrain-align=24 --mistrain-pass=1
```

2. Mistraining a victim branch with single mistraining branch biased to taken.

```bash
$ taskset -c 3 build/main -c100 -v0xc000c30 -e1 --mistrain-align=24 --mistrain-pass=1 --mistrain-taken
```

3. Triggering Straight-Line Speculation with multiple mistraining branches.

```bash
$ taskset -c 3 build/main -c100 -v0xc000c30 -e32 --mistrain-align=24 --mistrain-pass=1 --mistrain-taken
```

**Output:**

The output includes two sub-tests, while the program monitors the access latency for the FLUSH+RELOAD cache probe and prints its average value of each sub-test. A slow access indicates that the memory load is skipped due to the branch is taken, while a fast access indicates that the memory load is executed because the branch is not taken architecturally or speculatively.

Sample result on Cortex-A76 from *Example 1*:

```plaintext
slow access: 147
fast access: 56
threshold: 74

victim=c000c24
--- Test 0: Train bcond to be NT and test whether we can mistrain the PHT record to TT
Probe access latency (average of 64 tests): 55
--- Test 1: Train bcond to be TT and test whether we can evict the BTB record to make it NT
Probe access latency (average of 64 tests): 56
```

**Result Interpretation:**
- **Test 0** trains the conditional branch to be *not taken* (NT) in the PHT, but the architectural execution path makes it *taken*. 
  - With *not taken* mistraining (Example 1): Fast access (~56ns) indicates speculative execution as *not taken*
  - With *taken* mistraining (Example 2): Slow access (~147ns) indicates the branch direction is successfully reversed by mistraining

- **Test 1** trains the conditional branch to be *taken* (TT) in the PHT, but the architectural execution path makes it *not taken*.
  - With *not taken* mistraining (Example 1) or eviction with multiple branches (Example 3): Fast access (~56ns) indicates the branch direction is successfully reversed
  - With *taken* mistraining (Example 2): Slow access (~147ns) indicates speculative execution as *taken*


### 2. `spec-bse`: Spectre-BSE Attack (Section 5.4)

This module demonstrates the BST (Branch Status Table) eviction and its effect on the history-based branch prediction using a **Spectre-BSE** attack flow. This is tested only working on Cortex-A72, while ARM also reports it works on A73 and A75.

In this module, the *victim* `Bi_pred` is an indirect branch which jump target with two targets: `t_leak` is a typical Spectre gadget dereferencing a register pointer, and `t_alt` which loads a different and fixed offset on the FLUSH+RELOAD buffer. Then the test makes `Bi_pred` jump to the third empty target `t_empty` which does nothing, and monitors which cache probe producing a fast access latency.

**BHB population method:** For-loop and indirect branches (`-f` and `-i` parameters).

#### Example usage *(only available on Cortex-A72)*

We recommend the following parameters for running the demo on Cortex-A72:

```bash
taskset -c 5 build/main -i4 -f8 -e2 -v0xc000c30
```

This configuration initializes the BHB with 8 for-loop branches (`-f8`) and 4 indirect branches (`-i4`), and employs 2 eviction branches to manipulate the BHB value (`-e2`).

**Output:**
This module includes three sub-tests, including a standard Spectre-v2 with all `BH[n]` being initialized to non-biased, a similar one that tries to perform Spectre-v2 with different branch histories, and a mis-speculation caused by Spectre-BSE and consequent BHB confusion.
The output includes the average access latency of the memory address dereferenced by `t_leak` and `t_alt`, respectively.

```plaintext
slow access: 384
fast access: 216
threshold: 249

--- Test 0: Spectre-v2
Probe access latency (average of 64 tests): 224 392
--- Test 1: Different BH
Probe access latency (average of 64 tests): 384 201
--- Test 2: Different BH with Spectre-BSE
Probe access latency (average of 64 tests): 226 216
```

#### Result Interpretation

- **Test 0 and Test 1** expect `t_leak` and `t_alt` to be speculated, respectively. The two latency values reflect the speculative execution of these two targets. With correct settings, we should see a fast access (~216ns on Cortex-A72) corresponding to `t_leak` in Test 0 and `t_alt` in Test 1.
- **Test 2** demonstrates the effect of Spectre-BSE, where branch history confusion leads to a fast access for `t_leak`. This indicates that while the complete branch history should lead to speculating `t_alt`, the branch history confusion caused by BST eviction leads to mis-speculation of `t_leak` instead, resulting in a fast access for `t_leak` and a slow access for `t_alt`.

### 3. `spec-bhs`: Spectre-BHS Attack (Section 6.2)

This module demonstrates Branch History Speculative Update feature and its effect on the history-based branch prediction using a **Spectre-BHS** attack flow.

While the victim branch `Bi_pred` follows the same logic as in `spec-bse`, we use an additional branch `Bx_prime` to create different branch histories for different flows, and use mistraining snippets like mentioned in `pht-idx` to influence the prediction of `Bx_prime` and `Bi_pred`.

**BHB population method:** For-loop and indirect branches (`-f` and `-i` parameters).

#### Debugging flags
This module requires several compiling flags to control the behavior of the mistraining snippets and branch history manipulation. You may use them in the `make` command to enable the corresponding features:

- `DBG_ARCH_BH` and `DBG_JMP_LATENCY`: These two flags are used for experiments mentioned in Appendix C. They add a additional speculation barrier between `Bx_prime` and `Bi_pred`, then measure the branch latency of `Bi_pred`. The latter one also adds outputs of branch latency of `Bx_prime` in the output.
- `DBG_MISTRAIN_NO_BTB_PROMOTE`: This flag masks out the extra executions of the mistraining snippet using different branch histories before the execution of desired mistrainings. We found that, on some processors like Cortex-A76 and Zen4, enabling this is mandatory to make the mistraining branches able to influence the prediction of `Bx_prime`, which means that the branch prediction record is only promoted to the history-based mode when the branch is executed under different branch histories and different results. We enable this by default and you can disable it for debugging with `FLAGS=DBG_MISTRAIN_NO_BTB_PROMOTE`.
- `DBG_ZEN4_BTB_EVICT`: On Zen4, we observed that only *a conditional branch crossing a 4 KB boundary* can evict a BTB/PHT entry and successfully trigger Straight-Line Speculation. When testing Straight-Line Speculation (and BTB/PHT eviction) on Zen4, please enable this flag with `FLAGS=DBG_ZEN4_BTB_EVICT`. This is not needed on other microarchitectures.

#### Example usage 1: Spectre-BHS with mistraining branches

```bash
# (1) Cortex-A76, mistrain `Bx_prime` to be biased to not-taken
taskset -c 3 build/main -c100 -v0xc000c30 -e1 --mistrain-align=24 --mistrain-pass=1
# (2) Cortex-A76, mistrain `Bx_prime` to be biased to taken
taskset -c 3 build/main -c100 -v0xc000c30 -e1 --mistrain-align=24 --mistrain-pass=1 --mistrain-taken
# (3) Zen4, mistrain `Bx_prime` to be biased to not-taken
taskset -c 3 build/main -c1200 -v0xc000c30 -e4 --mistrain-align=24 --mistrain-pass=2
# (4) Zen4, mistrain `Bx_prime` to be biased to taken
taskset -c 3 build/main -c1200 -v0xc000c30 -e2 --mistrain-align=24 --mistrain-pass=2 --mistrain-taken
# (5) Gracemont/Redwood Cove/Crestmont, mistrain `Bx_prime` to be biased to not-taken
taskset -c 3 build/main -c300 -v0xc000c30 -e1 --mistrain-align=18 --mistrain-pass=4
# (6) Gracemont/Redwood Cove/Crestmont, mistrain `Bx_prime` to be biased to taken
taskset -c 3 build/main -c300 -v0xc000c30 -e1 --mistrain-align=18 --mistrain-pass=4 --mistrain-taken
```

This configuration initializes given number of conditional branches (`-c<value>`) and employs one or multiple eviction branches to manipulate the BHB value (`-e<value>`). The `--mistrain-align` parameter specifies the address alignment (in bits) for placing mis-training branches so they share lower address bits with the victim branch, creating conflicts in the branch prediction structures. The `--mistrain-pass` parameter specifies how many times the mis-training snippet is executed.

However, due to the different implementations of BPUs across different microarchitectures, the optimal parameters can vary significantly. You can also experiment with different values to find the optimal settings for your specific target.

**Output:**

The victim snippet in `spec-bse` allows two architectural execution paths:
- `Bx_prime` not taken, and `Bi_pred` jumps to `t_leak`;
- `Bx_prime` taken, and `Bi_pred` jumps to `t_alt`.

The output includes the average probe access latencies for the FLUSH+RELOAD cache probes, similar to `spec-bse`. Here we provide two samples from Cortex-A76. 

When executing *without `--mistrain-taken`*, `Bx_prime` is mistrained to be biased toward *not taken*. In Test 0 and Test 1, while `Bx_prime` is *architecturally taken but transiently not taken*, this leads `Bi_pred` to mis-speculate `t_leak`. Therefore, you may observe the first probe showing lower latency.

```plaintext
Memory access latency (average of 64 tests): 
slow access: 148
fast access: 56
threshold: 74

--- Test 0: Train Bc_prime biased to TT and test with TT
Probe access latency (average of 64 tests): 55 74
--- Test 1: Train Bc_prime biased to NT and test with TT
Probe access latency (average of 64 tests): 56 78
// Test 2 and Test 3 are omitted for brevity
```

Conversely, when executing *with `--mistrain-taken`*, `Bx_prime` is mistrained to be biased toward taken. *In Test 2 and Test 3*, while `Bx_prime` is *architecturally not taken but transiently taken*, this leads `Bi_pred` to mis-speculate `t_alt`. Therefore, you may observe the second probe showing lower latency.

```plaintext
Memory access latency (average of 64 tests): 
slow access: 147
fast access: 56
threshold: 74


// Test 0 and Test 1 are omitted for brevity
--- Test 2: Train Bc_prime biased to TT and test with NT
Probe access latency (average of 64 tests): 142 56
--- Test 3: Train Bc_prime biased to NT and test with NT
Probe access latency (average of 64 tests): 142 56
```

*When `DBG_JMP_LATENCY` is enabled, it also includes the branch latency of `Bi_pred`. This helps to distinguish branch stall (longer latency) or correct prediction(shorter latency) when no mistraining is detected.*


#### Example usage 2: Spectre-BHS with multiple mistraining branches causing BTB/PHT eviction of `Bx_prime`

```bash
# Cortex-A76
taskset -c 3 build/main -c100 -v0xc000c30 -e5 --mistrain-align=24 --mistrain-pass=1 --mistrain-taken
```

***Note for Zen4:** The compile switch `FLAGS=DBG_ZEN4_BTB_EVICT` is mandatory to demonstrate the BTB/PHT eviction behavior.*

**Output:**
The output is similar to the previous example. However, in Test 0 and 1 of this sample, `t_alt` should be speculated since Straight-Line Speculation is triggered **by** `Bx_prime`. Therefore, you may observe the **second** probe showing lower latency.

```plaintext
Memory access latency (average of 64 tests): 
slow access: 207
fast access: 88
threshold: 111

--- Test 0: Train Bc_prime biased to TT and test with TT
Probe access latency (average of 64 tests): 98 162
--- Test 1: Train Bc_prime biased to NT and test with TT
Probe access latency (average of 64 tests): 87 169
// Test 2 and Test 3 are omitted for brevity
```

#### Example usage 3: (Appendix C) BTB/PHT eviction on Zen4, with `DBG_JMP_LATENCY`, `DBG_ZEN4_BTB_EVICT`, and `DBG_ARCH_BH` enabled

As we described in Appendix C, BHB on Zen 4 omits never-taken conditional branches, thus evicting the BTB/PHT entry of `Bx_prime` and making it *unable* to be confused with *not taken*, but instead creates a unique *not recorded* state. Unlike the previously discussed Branch History Speculation behaviors, this has an architectural effect which is observable outside the speculation window.

When placing a speculation barrier between the BHB-initializing branches and the `Bi_pred`, we are not able to observe `t_leak` or `t_alt` being speculated, but the branch latency of `Bi_pred` is significantly shorter than in other tests (25ns vs. >500ns), indicating that the BPU has made a correct prediction to its architectural target `t_empty` due to a unique BHB value generated by the BTB/PHT eviction.

You may compile and run the code with the following commands:

```bash
make TEST=spec-bhs ARCH=amd64 FLAGS="DBG_JMP_LATENCY DBG_ZEN4_BTB_EVICT DBG_ARCH_BH"
# Tested on Zen4
taskset -c 3 build/main -c1200 -v0xc000c30 -e24 --mistrain-align=24 --mistrain-pass=2 --mistrain-taken
```

Test 3 both trains `Bx_prime` with *not taken* and then tests with *not taken*. As discussed above, the output reveals that both cache probes for `t_leak` and `t_alt` are slow, but the branch latency of `Bi_pred` is significantly shorter than in other tests, indicating a correct prediction to the architectural target `t_empty`.

This further indicates that the *not taken* `Bx_prime` is recorded under a different policy before and after the eviction, causing the BPU to select a different record based on different BHB values.

```plaintext
Memory access latency (average of 64 tests): 
slow access: 273
fast access: 29
threshold: 77

// ...
--- Test 3: Train Bc_prime biased to NT and test with NT
Probe access latency (average of 64 tests): 299 266
// ...
--- Test 2: Train Bc_prime biased to TT and test with NT
Branch latency (average of 64 tests): 901 
--- Test 3: Train Bc_prime biased to NT and test with NT
Branch latency (average of 64 tests): 25
```


### 4. **`chimera`** - Chimera snippet and the mistrain strategies (Section 7)

This module demonstrates how to induce a partial PC-based branch prediction using a Chimera snippet in C language.

**BHB population method:** Conditional branches (`-c` parameter).

**Sample setup:**

```bash
# Cortex-A76
taskset -c 3 build/main -c100 -v0xc0000150
# Zen4
taskset -c 3 build/main -c1200 -v0xc0000150
# Gracemont/Redwood Cove/Crestmont
taskset -c 3 build/main -c300 -v0xc0000150
```

**Output:**

The output is similar to the `pht-idx` module. When we successfully induce mis-speculation toward not-taken, we should observe a lower latency corresponding to speculative execution of the memory load instruction. The output on Cortex-A76 is as follows:

```plaintext
Memory access latency (average of 64 tests): 
slow access: 148
fast access: 55
threshold: 73

--- Test 0: Chimera
Probe access latency (average of 64 tests): 58
```