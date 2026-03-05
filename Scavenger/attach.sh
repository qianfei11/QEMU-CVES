#!/bin/bash
# GDB debug script for Scavenger (CVE-2020-25084, NVMe + virtio-gpu escape)
# Useful breakpoints:
#   b nvme_dma_read_prp    — entry to vulnerable DMA function
#   b qemu_sglist_destroy  — where uninitialized qsg is freed
set -e
cd rootfs && ./pack.sh
cd ..

LD_LIBRARY_PATH=/home/bea1e/miniconda3/lib \
gdb \
    -ex 'set confirm off' \
    -ex 'set pagination off' \
    -ex 'handle SIGUSR1 noprint nostop' \
    -ex 'handle SIGUSR2 noprint nostop' \
    -ex 'catch signal SIGSEGV' \
    -ex 'run' \
    --args ./qemu-system-x86_64 \
        -L ./pc-bios \
        -m 512 -smp 2 \
        -initrd ./rootfs.cpio -nographic \
        -kernel ./bzImage \
        -append "priority=low console=ttyS0 oops=panic panic=1 rdinit=/a.sh" \
        -drive format=raw,file=./nvme.img,if=none,id=D11 \
        -device nvme,drive=D11,serial=1234,cmb_size_mb=64 \
        -device virtio-gpu \
        -display none \
        -monitor /dev/null
