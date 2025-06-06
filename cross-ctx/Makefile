CROSS_COMPILE := aarch64-linux-gnu-
CC := $(CROSS_COMPILE)gcc
EXFLAGS := -D$(TARGET) $(addprefix -D,$(FLAGS)) -DDBG_PMU_EL0
CFLAGS := -static -O0 -g -pie $(EXFLAGS)

programs-all	:= spec-bse-demo-el1 spec-bhs-demo-el1 scope-writer scope-reader
headers			:= $(wildcard *.h)

.PHONY: all
all: $(programs-all)

.PHONY: clean
clean: 
	$(RM) $(programs-all) $(objects-all)

scope-reader: $(headers) evict_probes.c jit_snippets.S utils.c
scope-writer: $(headers) evict_probes.c jit_snippets.S utils.c
spec-bse-demo-el1: $(headers) evict_probes.c jit_snippets.S utils.c
spec-bhs-demo-el1: $(headers) evict_probes.c jit_snippets.S utils.c
