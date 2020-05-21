ifneq ($(KERNELRELEASE),)

obj-m :=binfmt_elf_signature_verification.o

else

PWD=$(shell pwd)
KDIR :=$(PWD)/..

all:
	make -C $(KDIR) M=$(PWD) modules
clean:
	make -C $(KDIR) M=$(PWD) clean
endif
