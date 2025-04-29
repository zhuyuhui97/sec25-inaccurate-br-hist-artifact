#include <stdint.h>
#include "c_snippets.h"
#include "sc_utils.h"
#include "jit_utils.h"

uint8_t dummy_secrets[NR_DUMMY_SECRETS] = {12, 13, 14, 15, 16, 17, 18, 19,
                                          20, 21, 22, 23, 24, 25, 26, 27};

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
    MEM_ACCESS(SC_ENCODE_ADDR(frbuf, secret_ptr));
    NOP(32);
}

void t_alt(register char *frbuf)
{
    MEM_ACCESS(SC_ENCODE_ADDR(frbuf, &dummy_secrets[1]));
}

void t_empty()
{
    NOP(32);
}