ifneq ($(KERNELRELEASE),)

obj-m :=binfmt_elf_signature_verification.o

else

PWD=$(shell pwd)
# KDIR :=$(PWD)/../linux-kernel-elf-sig-verify
KDIR := /lib/modules/$(shell uname -r)/build

all:
	make -C $(KDIR) M=$(PWD) modules
clean:
	rm -f *.ko *.o *.mod.o *.mod.c *.symvers *.order
endif
