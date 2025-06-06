# Artifact code for paper "Exploiting Inaccurate Branch History in Side-Channel Attacks" - user-mode intra-process PoCs

This PoC contains code demonstrating the vulnerable mechanism and attack flows:

- **`spec-bhs-demo`**: **Spectre-BHS** attack in a user-space process.
- **`spec-bhs-demo-el1`**: **Spectre-BHS** attack targeting a victim branch in kernel space.

To compile a single demo, use the following command:

```bash
make $DEMO_NAME FLAGS="$FLAGS" TARGET="$TARGET"
```

Or, to compile all demos at once:

```bash
make all FLAGS="$FLAGS TARGET="$TARGET"
```

Additionally, to showcase the cross-privilege capabilities of the proposed attacks, auxiliary codes running in kernel space:

- **`el1/kmod`**: Kernel module that enables EL0 access to PMU counters for speculative execution monitoring.
- **`el1/syscall`**: Custom system call handlers that implement BST attack victims in the kernel space.

Please note that you will need to manually compile and deploy these kernel-space components.

## About `$FLAGS`

The `$FLAGS` is a user-defined variable that controls the compilation flags of this PoC code. It consists of multiple flags seperated by spaces:

```bash 
${flag0} ${flag1} #...
```

### Example Usage
Since our tests were run on an **Raspberry Pi 5** board with EL0 access to the PMU enabled, the following compile command was used:

```bash
make all FLAGS="DBG_PMU_EL0" TARGET="rpi5"
```

### Targets
This variable defines the target platform for the current compilation and determines which set of platform-specific parameters is selected from `target.h`. It must be included in the `$EXFLAGS` for successful compilation.

### Available Flags

#### 2. `DBG_PMU_EL0`
This flag enables monitoring of mis-speculation events using a VFP instruction and the `VFP_SPEC` counter in the PMU. When this flag is set, the code will use the PMU to track speculative execution.

**Note:** To use this flag, you **MUST** deploy and load the kernel module in `el1/kmod` before running any demos. This is because access to the PMU from EL0 is restricted by the operating system by default, and this kernel module unlocks that capability.

## Demo for Spectre-BHS

### Usage

Specify the address to be evicted in the command line parameter `-e <ADDR>` to this program on a selected CPU core, and .

```bash
taskset -c 4 spec-bhs-demo -e 0x3140 # or spec-bse-demo-el1 for a cross-privilege variant
```

### Overview

The code of `spec-bhs-demo` follows the attack flow described in the disclosure document.

Based on the overall flow of `spec-bhs-demo`, The **`spec-bhs-demo-el1`** version invokes a system call defined by `BHS_VICTIM_SYSCALL` to demonstrate a cross-privilege **Spectre-BHS** attack. This system call is handled by the kernel, with the handler defined in `el1/syscall/custom_syscall/`which is a kernel-mode implementation of the victim snippet.

The addresses of the victim branches are decided by the compiler and **NOT** tracked by the PoC code itself. User must get the addres of `Bc_victim` manually after compiling the demo or syscall handler, then tell the PoC on which address to perform the eviction.

**Important: `BHS_VICTIM_SYSCALL` should always be synchronized with the actual number used in the kernel, defined in `el1/syscall/custom_syscall.patch`!**

**The `DBG_PMU_EL0` flag is RECOMMENDED for `spec-bhs-demo` and MANDATORY for `spec-bhs-demo-el1`.**

### Expected results

Like the Spectre-BSE demo, this demo uses two primitives to measure the occurrence of mis-speculations of `t_vfp`: FLUSH+PROBE from cache side-channels, and the `VFP_SPEC` counter we discussed before. Upon successfully triggering mis-speculation, the probe will exhibit a shorter access latency, with the PMU counter increased.

All the information gathered from the `VFP_SPEC` counters and the FLUSH+PROBE primitive is printed as a summary at the end of the execution.

### Sample Output

The output will appear similar to the following:

```
Memory access latency (average of 128 tests): 
slow access: 187
fast access: 87

Probe access latency (average of 128 tests): 90
Mis-speculation succeeded (PMU VFP_SPEC marks): 128/128

```