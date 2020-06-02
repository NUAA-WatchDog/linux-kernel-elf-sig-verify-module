# linux-kernel-elf-sig-verify-module

🐧 Stand-alone kernel module for signature verification of ELF.

Created by : zSnow && Mr Dk.

2020 / 05 / 24 21:06

---

## Build the kernel module

By default, the value of `KDIR` in `Makefile` points to the source code directory of current running kernel, on which the kernel module will be installed.

```
KDIR := /lib/modules/$(shell uname -r)/build
```

Also, you can build the module for one kernel on another kernel by overriding the `KDIR` variable.

```
KDIR := ../linux-kernel-elf-sig-verify
```

Then, build the kernel module by `make` command:

```bash
$ make
make -C /lib/modules/5.3.0-53-generic/build M=/home/mrdrivingduck/Desktop/linux-kernel-elf-sig-verify/linux-kernel-elf-sig-verify-module modules
make[1]: Entering directory '/usr/src/linux-headers-5.3.0-53-generic'
  CC [M]  /home/mrdrivingduck/Desktop/linux-kernel-elf-sig-verify/linux-kernel-elf-sig-verify-module/binfmt_elf_signature_verification.o
  Building modules, stage 2.
  MODPOST 1 modules
  CC      /home/mrdrivingduck/Desktop/linux-kernel-elf-sig-verify/linux-kernel-elf-sig-verify-module/binfmt_elf_signature_verification.mod.o
  LD [M]  /home/mrdrivingduck/Desktop/linux-kernel-elf-sig-verify/linux-kernel-elf-sig-verify-module/binfmt_elf_signature_verification.ko
make[1]: Leaving directory '/usr/src/linux-headers-5.3.0-53-generic'
```

The `binfmt_elf_signature_verification.ko` is the kernel module. You can verify the basic information of this module:

```bash
$ modinfo binfmt_elf_signature_verification.ko 
filename:       /home/mrdrivingduck/Desktop/linux-kernel-elf-sig-verify/linux-kernel-elf-sig-verify-module/binfmt_elf_signature_verification.ko
alias:          fs-binfmt_elf_signature_verification
version:        1.0
description:    Binary handler for verifying signature in ELF section
author:         zonghuaxiansheng <zonghuaxiansheng@outlook.com>
author:         mrdrivingduck <mrdrivingduck@gmail.com>
license:        Dual MIT/GPL
srcversion:     24C778301DE1DD13C1BB3CF
depends:        
retpoline:      Y
name:           binfmt_elf_signature_verification
vermagic:       5.3.0-53-generic SMP mod_unload
```

Install the module via `insmod` command:

```bash
$ sudo insmod binfmt_elf_signature_verification.ko
```

Remove the module via `rmmod` command:

```bash
$ sudo rmmod binfmt_elf_signature_verification
```

If the module is installed successfully, you cannot run an ELF file without signature any more. Through `dmesg` command you can see more information.

## License

Copyright © 2020, Jingtang Zhang, Hua Zong. ([MIT License](LICENSE))

---

