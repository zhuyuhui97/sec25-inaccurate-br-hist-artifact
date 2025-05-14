#ifndef EBPF_POC_H
#define EBPF_POC_H

/**
 * uarch independent definitions
 */
// #define PR_BASE (0x1000)
// #define PR_STRIDE (4*SZ_CACHE_LINE)
#define PR_BASE (env_page_sz)
#define PR_STRIDE (env_page_sz)
#define PR_OFFSET(x) (PR_BASE + x * PR_STRIDE)
#define PR_OFFSET_0 PR_OFFSET(0)
#define PR_OFFSET_1 PR_OFFSET(1)
#define SZ_1K (1 << 10)
#define SZ_4K (4 * SZ_1K)
// #define SZ_EVICT_SET (SZ_CACHE_MAX * NR_EVICT_FACTOR)
#define SZ_EVICT_SET (SZ_4K * 256)
#define NR_SZ_EVICT_BATCH (256)
// assume we don't have any control of the physical base addresses of pages,
// so we do eviction using the offset-within-page on every page,
// each filtered socket handles NR_SZ_EVICT_BATCH addresses.
#define NR_EVICT_BATCHES ((SZ_EVICT_SET / SZ_4K) / NR_SZ_EVICT_BATCH)

#define EXIT_ERR_SETUP_EVICT -1
#define EXIT_ERR_SETUP_MIS_SPEC -2

#endif