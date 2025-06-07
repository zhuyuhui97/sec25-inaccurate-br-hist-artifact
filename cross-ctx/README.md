# Artifact code for paper "Exploiting Inaccurate Branch History in Side-Channel Attacks" - Cross-Context PoCs

This artifact contains PoC codes demonstrating the cross-context capabilities of primitives discussed in the paper using custom syscall handlers. The code is designed to run on ARMv8-A architecture.

## Project Structure

- **`kernel/`**: Custom syscall handlers containing a kernel-space **BiasScope** sender, **Spectre-BSE** and **Spectre-BHS** victims.
- **`scope-reader.c`, `scope-writer.c`**: User-space PoCs for **BiasScope** attack, which read and write the Branch Status Table (BST) to demonstrate the side channel.
- **`spec-bse-demo-el1.c`**: User-space PoC for cross-privilege **Spectre-BSE** attack.
- **`spec-bhs-demo-el1.c`**: User-space PoC for cross-privilege **Spectre-BHS** attack.

**Indicator of mis-speculation**: In `spec-bse-demo-el1` and `spec-bhs-demo-el1`, we use the `VFP_SPEC` PMU counter to detect mis-speculation events. This counter is incremented when the VFP unit is speculatively executed, which we use as an equivalent to the FLUSH+RELOAD side-channel. When the victim branch is mis-speculated toward the `t_vfp` target, the `VFP_SPEC` counter will be incremented.

## Building the artifact

To fully build the artifact, you need to compile both the user-space demos and the kernel-space components.

### Patching the Linux kernel to add custom syscall handlers

1. Download the Linux kernel source code for your target platform.
   - For Cortex-A76, we tested our PoC on *Raspberry Pi 5* with Linux kernel [`rpi-6.6.y`](https://github.com/raspberrypi/linux/tree/rpi-6.6.y) branch of the Raspberry Pi kernel repository. 
   - For Cortex-A72, we tested this on *i.MX8QuadMax MEK* with the kernel included in the Yocto project distributed by NXP, version [imx-5.15.71-2.2.2](https://github.com/nxp-imx/imx-manifest/blob/imx-linux-kirkstone/imx-5.15.71-2.2.2.xml). 
2. Copy the custom syscall handler files `custom_syscall/` to the kernel source code.
3. Patch `include/uapi/asm-generic/unistd.h` to add the syscall numbers for the custom syscall handlers.
   - For Raspberry Pi 5: use `rpi-6.6.y.diff`.
   - For i.MX8: use `lf-5.15.71-2.2.2.diff`.
4. Compile and install the kernel with the custom syscall handlers included.
   - For Raspberry Pi 5, you can follow the [Raspberry Pi kernel documentation](https://www.raspberrypi.com/documentation/computers/linux_kernel.html).
   - For i.MX8, you can follow the [community guidance](https://community.nxp.com/t5/i-MX-Processors-Knowledge-Base/i-MX-Yocto-Project-How-can-I-quickly-modify-the-kernel-and-test/ta-p/1129551). 

### Building the user-space demos

To compile a single demo, use the following command:

```bash
make $DEMO_NAME FLAGS="$FLAGS" TARGET="$TARGET"
```

You can use the following parameters in this command:

- **`DEMO_NAME`**: This specifies the demo you want to compile. The available values are `scope-reader`, `scope-writer`, `spec-bse-demo-el1`, or `spec-bhs-demo-el1`, as listed in the *Project Structure* section.
- **`TARGET`**: This variable defines the target platform for the current compilation and determines which set of platform-specific parameters is selected from `target.h`. `imx8` and `rpi5` are the currently supported targets.
- **`FLAGS`**: Some demos require additional compilation flags to enable specific features. We will discuss these flags for each demo in the following sections.

You will need the `aarch64-linux-gnu-gcc` toolchain installed on your system. This can typically be done via your package manager (e.g., `apt install gcc-aarch64-linux-gnu` on Debian-based systems).

## Demos

### BiasScope: encoding and decoding Branch Status Table (BST) side channel 

#### Overview

The `scope-reader` and `scope-writer` follow the BiasScope attack flow outlined in *Section 5.3 Attack Flow #1: BiasScope*. 

The `scope-reader` is a user-space program that reads the Branch Status Table (BST) side channel. We provide two implementations of the BiasScope sender: one implemented as a syscall handler in kernel space, and the other as a user-space program `scope-writer`.

The demo uses a pre-defined dummy secret value denoted as `DBG_PAYLOAD`. The sender simulates a victim process by executing a series of secret-dependent conditional branches. Each branch corresponds to one bit of the secret and performs branching based on whether the bit is set to 0 or 1. All the secret-dependent branches are placed at specific addresses for the reader to monitor.
  
In the `scope-reader`, the `BLR_probe[]` is implemented as an array of multiple probe branches so that it can simultaneously monitor all the victim branches. The secret is inferred and rebuilt based on the BST and BHB behavior.

Every time the `scope-reader` yields the CPU core and regains resources, it will perform the decoding process eight times to minimize noise from other software or hardware components. The decoding process involves Flow A and Flow B described in the paper. All eight decoding results for each retrieval are printed together in the console.

#### Build flags

`scope-reader.c` invokes the syscall to use the kernel-space writer to encode the BST side channel. On Cortex-A72, to test the intra-process capabilities with Spectre-v2 mitigations **disabled**, you need to compile the `scope-reader` with build option `FLAGS="DBG_RECV_FROM_USERSPACE"`.

#### Preparation

On Cortex-A72, the inter-process BiasScope attack is not effective with Spectre-v2 mitigations enabled, as the Branch Prediction Unit (BPU) is reset during context switches. To run this demo, you **MUST** disable the Spectre-v2 mitigation in the kernel. This can be done by modifying the kernel command line to include the following parameter:

```
mitigations=off
```

#### Usage

Run `scope-reader` and `scope-writer` simultaneously on the same CPU core:

```bash
taskset -c 5 scope-reader & taskset -c 5 scope-writer
```

#### Expected results

Upon successful construction of the BST side channel, the dummy secret should be successfully reconstructed by the `scope-reader` and displayed in the console output:

```
// ......

11010110
11010110
01011110
11010110
11010110
11011110
10010110
11010110

// ......
```

Note that the side channel may exhibit some noise due to interference from other hardware or software components. This interference is expected and unavoidable in a real-world environment.

### Spectre-BSE: influencing indirect branch prediction in kernel through BST eviction

#### Overview

The code of `spec-bse-demo-el1` follows the cross-privilege attack flow described in *Section 5.4 Attack Flow #2: Spectre-BSE*. As a user-space program, it evicts multiple BST records initialized by the syscall handler so that it can influence the indirect branch prediction in kernel space. The code is designed to run on Cortex-A72 cores.

#### Usage

Specify the address to be evicted in the command line parameter `-e <ADDR>` to this program on a selected CPU core. Here we provide a `bash` command to extract the address of the victim syscall handler from the kernel symbols:

```bash
EVICT=`sudo cat /proc/kallsyms | grep __specbse_victim_ | sort | sed -n '4,5 p' | awk '{printf "-e0x"$1" "}'`
taskset -c 5 ./spec-bse-demo-el1 ${EVICT}
```

#### Expected results

Upon successfully triggering mis-speculation, the `VFP_SPEC` PMU counter increases:

```plaintext
Eviction address 1 set to 0x84c35b0
Eviction address 2 set to 0x84c35c0
Snippet 0 prepared at 0x84cb5b0
Snippet 1 prepared at 0xffffa45eb5c0
WARNING: 
Cache probe is not implemented in this cross-privilege demo.
Please ignore this result since there will be no difference before Spectre-BSE and after.

--- without Spectre-BSE ---
Mis-speculation succeeded (PMU VFP_SPEC marks): 0/1024

--- WITH Spectre-BSE ---
Mis-speculation succeeded (PMU VFP_SPEC marks): 1024/1024
``` 

### Spectre-BHS: influencing indirect branch prediction in kernel through BTB/PHT eviction

#### Overview

The code of `spec-bhs-demo-el1` follows the cross-privilege attack flow described in *Section 6.2 Attack Flow #3a: Spectre-BHS*. As a user-space program, it evicts a BTB/PHT record generated by the syscall handler so that it can influence the indirect branch prediction in kernel space. The code is designed to run on Cortex-A76 cores.

#### Usage

Specify the address to be evicted in the command line parameter `-e <ADDR>` to this program on a selected CPU core. Here we provide a `bash` command to extract the address of the victim syscall handler from the kernel symbols:

```bash
ADDR=`sudo cat /proc/kallsyms | grep __specbhs_victim_align | awk '{print $1}'`
taskset -c 3 /tmp/spec-bhs-demo-el1 -e0x${ADDR}
```

#### Expected results

Upon successfully triggering mis-speculation, the `VFP_SPEC` PMU counter increases:

```plaintext
Eviction address set to 0x840923a8
Mis-speculation succeeded (PMU VFP_SPEC marks): 127/128
```