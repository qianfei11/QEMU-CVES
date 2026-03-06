#!/bin/bash
# Launch Scavenger environment (interactive shell, run /exp manually)
# NVMe CMB uninitialized QEMUSGList UAF → full VM escape chain
# (Black Hat Asia 2021 — hustdebug/scavenger)
# Requires nvme.img (created by build.sh).
set -e
cd rootfs && ./pack.sh
cd ..

# Prepend conda base lib dir if conda is available (provides libtinfow.so.6 and others).
_CONDA_LIB="$(conda info --base 2>/dev/null)/lib"
[ -d "$_CONDA_LIB" ] && export LD_LIBRARY_PATH="$_CONDA_LIB${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
unset _CONDA_LIB

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
