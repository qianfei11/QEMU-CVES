#!/bin/bash
# Launch Scavenger environment (interactive shell, run /exp manually)
# NVMe + virtio-gpu escape chain (CVE-2020-25084)
# Requires nvme.img (created by build.sh).
set -e
cd rootfs && ./pack.sh
cd ..

LD_LIBRARY_PATH=/home/bea1e/miniconda3/lib \
./qemu-system-x86_64 \
    -L ./pc-bios \
    -m 512 -smp 2 \
    -initrd ./rootfs.cpio -nographic \
    -kernel ./bzImage \
    -append "priority=low console=ttyS0 oops=panic panic=1" \
    -drive format=raw,file=./nvme.img,if=none,id=D11 \
    -device nvme,drive=D11,serial=1234,cmb_size_mb=64 \
    -device virtio-gpu \
    -display none \
    -monitor /dev/null
