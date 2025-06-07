# Artifact code for paper "Exploiting Inaccurate Branch History in Side-Channel Attacks"

This artifact contains proof-of-concept (PoC) code demonstrating the vulnerabilities discovered in the paper. The project is organized into several submodules, each addressing different attack scenarios:

- **[intra-ctx](intra-ctx/README.md)**: Intra-process PoCs demonstrating the relevant microarchitectural behaviors and primitives to perturb and exploit their side effects. This module covers BHB/PHT mistraining (Section 3.3), Spectre-BSE (Section 5.4), Spectre-BHS (Section 6.2), and Chimera snippets (Section 7).

- **[cross-ctx](cross-ctx/README.md)**: Cross-context PoCs showcasing how these primitives can manipulate branch prediction in kernel mode or another process. This module covers BiasScope (Section 5.3), Spectre-BSE (Section 5.4), and Spectre-BHS (Section 6.2).

- **[chimera-ebpf](chimera-ebpf/README.md)**: End-to-end Chimera attack (Section 7) implemented as an eBPF program, demonstrating practical kernel memory leakage.
