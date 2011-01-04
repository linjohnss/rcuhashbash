ifneq ($(KERNELRELEASE),)
obj-m += rcuhashbash.o
obj-m += rcuhashbash-resize.o
else
# Build against the current kernel, or use the environment variable KERNELDIR.
KERNELDIR ?= /lib/modules/$(shell uname -r)/build
%:
	$(MAKE) -C $(KERNELDIR) M=$(CURDIR) $@
endif
