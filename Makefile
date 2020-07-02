ifneq ($(KERNELRELEASE),)

obj-m := binfmt_elf_signature_verification.o

else

# KDIR := ../
KDIR := /lib/modules/$(shell uname -r)/build

all:
	make -C $(KDIR) M=$(PWD) modules
clean:
	$(RM) *.ko
	$(RM) *.o
	$(RM) *.mod*
	$(RM) *.symvers
	$(RM) *.order
	$(RM) .*.mk
	$(RM) .*.cmd
	$(RM) -r .tmp_versions
endif
