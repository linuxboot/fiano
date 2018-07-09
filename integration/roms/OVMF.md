# OVMF

EDK2 is open-source UEFI firmware, governed under a BSD license and can be
redistributed. OVMF is a EDK2 configuration which can run under QEMU.

In this folder, you will find:

- `OVMF.rom`: EDK2 firmware image
- `OVMF_target.txt`: Configuration used to build the OVMF image. To rebuild,
  copy this file to `conf/target.txt` in the EDK2 source tree.


## Build Notes

- OS: `Ubuntu 16.04.4 LTS xenial`
- Git tag: `vUDK2018`
- GCC version: `gcc (Ubuntu 5.4.0-6ubuntu1~16.04.10) 5.4.0 20160609`
- Build is not reproducible.
- Find instructions at: https://wiki.ubuntu.com/UEFI/EDK2


## Running in QEMU

    qemu-system-x86_64 -bios OVMF.rom -nographic -net none
