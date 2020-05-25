# linux-kernel-elf-sig-verify-module
🐧 Stand-alone kernel module for signature verification of ELF.

Created by : zSnow.

2020 / 05 / 24 21:06

---

## Build the sig-verify kernel module

Firstly, modify the value of `KDIR` in `Makefile` to let `KDIR` point to the kernel source directory.

```
KDIR := /lib/modules/$(shell uname -r)/build
```

or

```
KDIR := ../linux-kernel-elf-sig-verify
```

It depends on which kernel you choose to compile & install this module.

Then, build the kernel module by `make` command:

```
$ make
make -C /home/snow/Desktop/linux-kernel-elf-sig-verify-module/../linux-kernel-elf-sig-verify M=/home/snow/Desktop/linux-kernel-elf-sig-verify-module modules
make[1]: Entering directory '/home/snow/Desktop/linux-kernel-elf-sig-verify'
  CC [M]  /home/snow/Desktop/linux-kernel-elf-sig-verify-module/binfmt_elf_signature_verification.o
  Building modules, stage 2.
  MODPOST 1 modules
  CC      /home/snow/Desktop/linux-kernel-elf-sig-verify-module/binfmt_elf_signature_verification.mod.o
  LD [M]  /home/snow/Desktop/linux-kernel-elf-sig-verify-module/binfmt_elf_signature_verification.ko
make[1]: Leaving directory '/home/snow/Desktop/linux-kernel-elf-sig-verify'
```

The `binfmt_elf_signature_verification.ko` is the kernel module. 

Finally, install the module with `insmod` command:

```
$ sudo insmod binfmt_elf_signature_verification.ko
```

You can remove the module with `rmmod` command:

```
# sudo rmmod binfmt_elf_signature_verification.ko
```

About the test, if it's installed successfully, you can not run an `ELF` file without signature. More information  you can see with `dmesg` command.

## License

Copyright © 2020, Jingtang Zhang, Hua Zong. ([MIT License](https://github.com/mrdrivingduck/linux-elf-binary-signer/blob/master/LICENSE))

----