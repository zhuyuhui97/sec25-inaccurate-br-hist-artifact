#define _POSIX_C_SOURCE 199309L // Bruh, to mute the warnings on clockid_t and CLOCK_REALTIME
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <stdint.h>
#include <time.h>
#include "jit_utils.h"

char *frbuf;
uint64_t frbuf_size;
uint64_t mem_fast = 0, mem_slow = 0;

char *init_frbuf(int slots, int stride)
{
    frbuf_size = slots * stride;
    frbuf = mmap(NULL, slots * stride, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    return frbuf;
}

void free_frbuf(void)
{
    munmap(frbuf, frbuf_size);
}

#define NANOSECONDS_PER_SECOND 1000000000L
uint64_t read_cycles()
{
    struct timespec tp;
    clockid_t clk_id = CLOCK_REALTIME;

    clock_gettime(clk_id, &tp);
    /*printf("tp.tv_sec : %ld\n", tp.tv_sec);
      printf("tp.tv_nsec: %ld\n", tp.tv_nsec); */
    return (uint64_t)((tp.tv_sec * NANOSECONDS_PER_SECOND) + tp.tv_nsec);
}

uint64_t mem_access_time(register volatile void *p)
{
    register uint64_t __cycles;
    __cycles = read_cycles();
    MEM_ACCESS(p);
    OPS_BARRIER(0);
    return (read_cycles() - __cycles);
}

void test_mem_latency(uint8_t *probe_ptr, uint64_t rounds)
{
    register uint64_t __cycles_slow = 0;
    register uint64_t __cycles_fast = 0;
    *probe_ptr = 0x41;

    read_cycles();

    for (int i = 0; i < rounds; i++)
    {
        OPS_BARRIER(64);
        FLUSH_DCACHE(probe_ptr);
        OPS_BARRIER(64);
        __cycles_slow += mem_access_time(probe_ptr);
    }

    OPS_BARRIER(64);

    for (int i = 0; i < rounds; i++)
    {
        OPS_BARRIER(64);
        MEM_ACCESS(probe_ptr);
        OPS_BARRIER(64);
        __cycles_fast += mem_access_time(probe_ptr);
    }

    OPS_BARRIER(64);

    mem_slow = __cycles_slow / rounds;
    mem_fast = __cycles_fast / rounds;
}