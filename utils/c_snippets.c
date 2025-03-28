#include <stdint.h>
#include "c_snippets.h"
#include "targets.h"
#include "sc_utils.h"
#include "jit_utils.h"

void populate_bhb_bcond(int nr_iter)
{
    int i;
    for (i = 0; i < nr_iter; i++)
    {
        NOP(8);
    }
}

void t_leak(register char *frbuf, register uint8_t *secret_ptr)
{
    // MEM_ACCESS(&frbuf[(*secret_ptr) * SIZE_CACHE_STRIDE]);
    MEM_ACCESS(SC_ENCODE_ADDR(frbuf, secret_ptr));
    NOP(32);
}

void t_empty()
{
    NOP(32);
}