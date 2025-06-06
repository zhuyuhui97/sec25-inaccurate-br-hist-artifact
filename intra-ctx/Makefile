CC := $(CROSS_COMPILE)gcc

DIR_ARCH_INCLUDE := arch/$(ARCH)/
DIR_INCLUDE := include/ tests/ $(DIR_ARCH_INCLUDE)
DIR_BUILD := build/

EXFLAGS := -DARCH_$(ARCH) $(addprefix -D,$(FLAGS))
# CFLAGS += -static -O0 -g -pie $(addprefix -I,$(DIR_INCLUDE)) $(EXFLAGS)
CFLAGS += -O0 -g -pie $(addprefix -I,$(DIR_INCLUDE)) $(EXFLAGS)

ifneq (,$(wildcard tests/$(TEST).$(ARCH).S))
    TEST_SRC := tests/$(TEST).$(ARCH).S tests/$(TEST).c
else
    TEST_SRC := tests/$(TEST).c
endif

$(DIR_BUILD)main: main.c $(TEST_SRC) $(DIR_BUILD)asm_snippets.o $(DIR_BUILD)jit_utils.o $(DIR_BUILD)c_snippets.o $(DIR_BUILD)sc_utils.o utils/args.c
	$(CC) $(CFLAGS) -o $@ $^

$(DIR_BUILD)asm_snippets.o: $(DIR_ARCH_INCLUDE)asm_snippets.S include/asm_snippets.h include/asm_macros.S
	$(CC) $(CFLAGS) -c -o $@ $<

$(DIR_BUILD)sc_utils.o: utils/sc_utils.c include/sc_utils.h
	$(CC) $(CFLAGS) -c -o $@ $<

$(DIR_BUILD)jit_utils.o: utils/jit_utils.c include/jit_utils.h
	$(CC) $(CFLAGS) -c -o $@ $<

$(DIR_BUILD)c_snippets.o: utils/c_snippets.c include/c_snippets.h
	$(CC) $(CFLAGS) -c -o $@ $<

$(DIR_BUILD)chimera-ebpf: chimera-ebpf/chimera-ebpf.c chimera-ebpf/ebpf_progs.c chimera-ebpf/ebpf_helper.c chimera-ebpf/ebpf_helper.h chimera-ebpf/ebpf_progs.h chimera-ebpf/ebpf_poc.h $(DIR_BUILD)asm_snippets.o
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f build/*