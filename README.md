# linux-kernel-elf-sig-verify-module
🐧 Stand-alone kernel module for signature verification of ELF.

Created by : zSnow && Mr Dk.

2020 / 05 / 24 21:06

---

## Build the kernel module

By default, the value of `KDIR` in `Makefile` points to the kernel source code directory, on which the module to be loaded.

```
KDIR := /lib/modules/$(shell uname -r)/build
```

Also, you can build the module for a kernel on another kernel by overriding the `KDIR` variable.

```
KDIR := ../linux-kernel-elf-sig-verify
```

Then, build the kernel module by `make` command:

```bash
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

Install the module with `insmod` command:

```bash
$ sudo insmod binfmt_elf_signature_verification.ko
```

Remove the module with `rmmod` command:

```bash
$ sudo rmmod binfmt_elf_signature_verification
```

If the module is installed successfully, you cannot run an ELF file without signature any more. Through `dmesg` command you can see more information.

## License

Copyright © 2020, Jingtang Zhang, Hua Zong. ([MIT License](LICENSE))

----