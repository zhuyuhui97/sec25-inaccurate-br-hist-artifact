CC := $(CROSS_COMPILE)gcc

DIR_ARCH_INCLUDE := arch/$(ARCH)/
DIR_INCLUDE := ../intra-ctx/include/ ../intra-ctx/$(DIR_ARCH_INCLUDE)

CFLAGS += -O0 -g -static $(addprefix -I,$(DIR_INCLUDE)) $(EXFLAGS) -DARCH_$(ARCH)

chimera-ebpf: chimera-ebpf.c ebpf_progs.c ebpf_helper.c ebpf_helper.h ebpf_progs.h ebpf_poc.h
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f chimera-ebpf