obj-m += goodix_milanl_transport.o
KDIR ?= /lib/modules/$(shell uname -r)/build
ifneq ($(shell grep -s '^CONFIG_CC_IS_CLANG=y$$' $(KDIR)/.config),)
LLVM ?= 1
endif
all:
	$(MAKE) -C $(KDIR) M=$(CURDIR) $(if $(LLVM),LLVM=$(LLVM)) modules
clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean
