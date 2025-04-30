#ifndef SC_UTILS_H
#define SC_UTILS_H

#include <stdint.h>

#define SC_ENCODE_ADDR(frbuf, secret_ptr) (&frbuf[(*secret_ptr) * SIZE_CACHE_STRIDE])

extern char *frbuf;
extern uint64_t mem_slow, mem_fast;

void* init_frbuf(int slots, int stride);
void free_frbuf(void);
uint64_t read_cycles();
uint64_t mem_access_time(register volatile void *p);
void test_mem_latency(uint8_t *probe_ptr, uint64_t rounds);

#endif