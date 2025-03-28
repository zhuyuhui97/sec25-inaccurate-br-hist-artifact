# ARCH:=arm64
# CROSS_COMPILE := aarch64-linux-gnu-
# KDIR:=/home/makoto/dev.retis/imx-build-docker/build/tmp/work-shared/imx8qmmek/kernel-source
# ODIR:=/home/makoto/dev.retis/imx-build-docker/build/tmp/work-shared/imx8qmmek/kernel-build-artifacts/
# KINCLUDE:=$(KDIR)/arch/arm64/include

kmods += $(src_dir)/pmu-arm.ko

pmu-arm.ko: pmu-arm.c
	$(MAKE) -C $(KDIR) O=$(ODIR) M=$(PWD) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) CFLAGS=-O0 modules

.PHONY: clean-$(src_dir)/pmu-arm.ko
clean:
	$(MAKE) -C $(KDIR) O=$(ODIR) M=$(PWD) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) CFLAGS=-O0 clean
