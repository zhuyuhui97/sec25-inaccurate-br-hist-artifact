CC := $(CROSS_COMPILE)gcc

DIR_ARCH_INCLUDE := arch/$(ARCH)/
DIR_INCLUDE := include/ $(DIR_ARCH_INCLUDE)
DIR_BUILD := build/

EXFLAGS := -D$(TARGET) -DARCH_$(ARCH) $(addprefix -D,$(FLAGS))
# CFLAGS += -static -O0 -g -pie $(addprefix -I,$(DIR_INCLUDE)) $(EXFLAGS)
CFLAGS += -O0 -g -pie $(addprefix -I,$(DIR_INCLUDE)) $(EXFLAGS)

$(DIR_BUILD)main: main.c tests/$(TEST).c $(DIR_BUILD)asm_snippets.o $(DIR_BUILD)jit_utils.o $(DIR_BUILD)c_snippets.o $(DIR_BUILD)sc_utils.o utils/args.c
	$(CC) $(CFLAGS) -o $@ $^

$(DIR_BUILD)asm_snippets.o: $(DIR_ARCH_INCLUDE)asm_snippets.S include/asm_snippets.h include/asm_macros.S
	$(CC) $(CFLAGS) -c -o $@ $<

$(DIR_BUILD)sc_utils.o: utils/sc_utils.c include/sc_utils.h
	$(CC) $(CFLAGS) -c -o $@ $<

$(DIR_BUILD)jit_utils.o: utils/jit_utils.c include/jit_utils.h
	$(CC) $(CFLAGS) -c -o $@ $<

$(DIR_BUILD)c_snippets.o: utils/c_snippets.c include/c_snippets.h
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f build/*