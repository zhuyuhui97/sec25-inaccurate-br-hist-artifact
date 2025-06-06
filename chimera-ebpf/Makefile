CC := $(CROSS_COMPILE)gcc

DIR_ARCH_INCLUDE := arch/$(ARCH)/
DIR_INCLUDE := ../user-mode/include/ ../user-mode/$(DIR_ARCH_INCLUDE)

EXFLAGS := -DARCH_$(ARCH)
# CFLAGS += -static -O0 -g -pie $(addprefix -I,$(DIR_INCLUDE)) $(EXFLAGS)
CFLAGS += -O0 -g -pie $(addprefix -I,$(DIR_INCLUDE)) $(EXFLAGS)

chimera-ebpf: chimera-ebpf.c ebpf_progs.c ebpf_helper.c ebpf_helper.h ebpf_progs.h ebpf_poc.h
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f chimera-ebpf