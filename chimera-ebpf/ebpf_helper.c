/*
 * From: https://github.com/vusec/bhi-spectre-bhb/tree/main
 * common/ebpf_helper.h
 * 
 * Original header comments:
 *
 * Thursday, September 9th 2021
 *
 * Enrico Barberis - e.barberis@vu.nl
 * Pietro Frigo - p.frigo@vu.nl
 * Marius Muench - m.muench@vu.nl
 * Herbert Bos - herbertb@cs.vu.nl
 * Cristiano Giuffrida - giuffrida@cs.vu.nl
 *
 * Vrije Universiteit Amsterdam - Amsterdam, The Netherlands
 */

#include "ebpf_helper.h"

const char *str =
"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

//helpers
int bpf_(int cmd, union bpf_attr *attrs) {
    return syscall(__NR_bpf, cmd, attrs, sizeof(*attrs));
}

int prog_load(struct bpf_insn *insns, size_t insns_count) {
    char verifier_log[100000];
    union bpf_attr create_prog_attrs = {
        .prog_type = BPF_PROG_TYPE_SOCKET_FILTER,
        .insn_cnt = insns_count,
        .insns = (uint64_t)insns,
        .license = (uint64_t)GPLv2,
        .log_level = 1,
        .log_size = sizeof(verifier_log),
        .log_buf = (uint64_t)verifier_log
    };
    int progfd = bpf_(BPF_PROG_LOAD, &create_prog_attrs);
    int errno_ = errno;
    errno = errno_;
    if (progfd == -1) {
        printf("==========================\n%s==========================\n", verifier_log);
        err(1, "prog load");
    }
    return progfd;
}

int create_filtered_socket_fd(int progfd) {
    int socks[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, socks))
        err(1, "socketpair");
    if (setsockopt(socks[0], SOL_SOCKET, SO_ATTACH_BPF, &progfd, sizeof(int)))
        err(1, "setsockopt");
    return socks[1];
}

void trigger_ebpf(int sockfd, int len) {
    if (sockfd == 0) err(1, "wrong socket");
    if (len > 256) err(1, "length too big");
    if (write(sockfd, str, len) != len)
        err(1, "write to proc socket failed");
}

int map_array_create(int value_size, int num_entries) {
    union bpf_attr create_map_attrs = {
        .map_type = BPF_MAP_TYPE_ARRAY,
        .key_size = 4,
        .value_size = value_size,
        .max_entries = num_entries,
        .map_flags = BPF_F_MMAPABLE
    };
    int mapfd = bpf_(BPF_MAP_CREATE, &create_map_attrs);
    if (mapfd == -1)
        err(1, "map create");
    return mapfd;
}

int map_jmptable_create(int num_entries) {
	union bpf_attr create_map_attrs = {
		.map_type = BPF_MAP_TYPE_PROG_ARRAY,
		.key_size = 4,
		.value_size = 4,
		.max_entries = num_entries
	};
	int mapfd = bpf_(BPF_MAP_CREATE, &create_map_attrs);
	if (mapfd == -1)
		err(1, "jmptable create");
	return mapfd;
}

void map_set(int mapfd, uint32_t key, uint64_t value) {
    union bpf_attr attr = {
        .map_fd = mapfd,
        .key    = (uint64_t)&key,
        .value  = (uint64_t)&value,
        .flags  = BPF_ANY,
    };

    int res = bpf_(BPF_MAP_UPDATE_ELEM, &attr);
    if (res)
        err(1, "map update elem");
}

void map_set_ptr(int mapfd, uint32_t key, void *ptr) {
	union bpf_attr attr = {
		.map_fd = mapfd,
		.key    = (uint64_t)&key,
		.value  = (uint64_t)ptr,
		.flags  = BPF_ANY,
	};

	int res = bpf_(BPF_MAP_UPDATE_ELEM, &attr);
	if (res)
		err(1, "map update ptr elem");
}

uint32_t map_get(int mapfd, uint32_t key) {
    uint32_t value = 0;
    union bpf_attr attr = {
        .map_fd = mapfd,
        .key    = (uint64_t)&key,
        .value  = (uint64_t)&value,
        .flags  = BPF_ANY,
    };
    int res = bpf_(BPF_MAP_LOOKUP_ELEM, &attr);
    if (res)
        err(1, "map lookup elem");
    return value;
}

