# linux-kernel-elf-sig-verify-module

🐧 Kernel module for signature verification of ELF files.

Created by : zSnow && Mr Dk.

2020 / 05 / 24 21:06

---

## Build the kernel module

By default, the value of `KDIR` in `Makefile` points to the source code directory of **currently running kernel**, on which the kernel module will be installed.

```
KDIR := /lib/modules/$(shell uname -r)/build
```

Also, you can build the module for one kernel on another kernel by overriding the `KDIR` variable. Suppose your directory is a submodule of [linux-kernel-elf-sig-verify](https://github.com/mrdrivingduck/linux-kernel-elf-sig-verify) under its directory like `linux-kernel-elf-sig-verify/linux-kernel-elf-sig-verify-module`, then you can modify `KDIR` to:

```
KDIR := ../
```

Then, build the kernel module by `make` command:

```console
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

```console
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

```console
$ sudo insmod binfmt_elf_signature_verification.ko
```

Remove the module via `rmmod` command:

```console
$ sudo rmmod binfmt_elf_signature_verification
```

If the module is installed successfully, you cannot run an ELF file without signature any more. Through `dmesg` command you can see more information.

## Key for Verification

The `certs/kernel_key.pem` is the same as the key in [linux-elf-binary-signer](https://github.com/mrdrivingduck/linux-elf-binary-signer), and is only used for testing. To use the `binfmt_elf_signature_verification` module, you should compile the key into the kernel.

Or you can use the configuration file to get your own key pair by modifying `certs/x509.genkey`:

```
[ req ]
default_bits = 2048
distinguished_name = req_distinguished_name
prompt = no
string_mask = utf8only
x509_extensions = myexts

[ req_distinguished_name ]
O = WatchDog
CN = ELF verification
emailAddress = mrdrivingduck@gmail.com

[ myexts ]
basicConstraints=critical,CA:FALSE
keyUsage=digitalSignature
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
```

And generate the key with `openssl` tools:

```console
$ cd certs
$ openssl req -new -nodes -utf8 -sha256 -days 36500 -batch -x509 \
    -config x509.genkey -outform PEM
    -out kernel_key.pem -keyout kernel_key.pem
Generating a RSA private key
........+++++
........................................+++++
writing new private key to 'kernel_key.pem'
-----
$ cd ..
```

---

## License

Copyright © 2020, Jingtang Zhang, Hua Zong. ([MIT License](LICENSE))

---

