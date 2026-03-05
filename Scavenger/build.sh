#!/bin/bash
# Build script for Scavenger (CVE-2020-25084 / Black Hat Asia 2021)
# Misuse of error-handling code in NVMe + virtio-gpu → QEMU/KVM escape
#
# Builds:
#   1. QEMU v5.0.0  → ./qemu-system-x86_64
#   2. Linux 5.4.40 → ./bzImage  (lightweight initramfs approach)
#
# Notes:
#   - The full exploit requires /dev/mem access + NVMe + virtio-gpu
#   - Configure with --extra-cflags="-pg" to match hardcoded offsets in exp.c
#   - Offsets (system, nvme_process_sq, cleanup) are build-specific and
#     must be re-derived via: nm qemu-system-x86_64 | grep <symbol>
#   - A NVMe backing image (nvme.img, 128 MB) is created during setup
set -e

JOBS=$(nproc)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
QEMU_TAG="v5.0.0"
BUILD_DIR="/tmp/qemu-scavenger"

build_qemu() {
    echo "=== Building QEMU ${QEMU_TAG} ==="

    if [ ! -d "$BUILD_DIR/src" ]; then
        git clone --branch "$QEMU_TAG" --depth 1 \
            https://mirrors.tuna.tsinghua.edu.cn/git/qemu.git \
            "$BUILD_DIR/src"
    fi

    mkdir -p "$BUILD_DIR/build"
    cd "$BUILD_DIR/build"

    if [ ! -f Makefile ]; then
        "$BUILD_DIR/src/configure" \
            --target-list=x86_64-softmmu \
            --enable-debug \
            --disable-werror \
            --extra-cflags="-pg"
    fi

    make -j"$JOBS" subdir-x86_64-softmmu
    cp x86_64-softmmu/qemu-system-x86_64 "$SCRIPT_DIR/qemu-system-x86_64"
    cp -r "$BUILD_DIR/src/pc-bios" "$SCRIPT_DIR/pc-bios"
    echo "[+] QEMU binary: $SCRIPT_DIR/qemu-system-x86_64"

    echo "[*] Deriving symbol offsets for exp.c..."
    NM=$(nm "$SCRIPT_DIR/qemu-system-x86_64" 2>/dev/null || nm "$BUILD_DIR/build/x86_64-softmmu/qemu-system-x86_64")
    SYSTEM_ADDR=$(echo "$NM" | awk '/\bsystem\b/ && /T/ {print $1; exit}')
    NVME_SQ_ADDR=$(echo "$NM" | awk '/nvme_process_sq/ && /T/ {print $1; exit}')
    echo "[*]   system           = 0x${SYSTEM_ADDR}"
    echo "[*]   nvme_process_sq  = 0x${NVME_SQ_ADDR}"
    echo "[!] Update offsets in rootfs/exp.c before building rootfs."
}

build_kernel() {
    echo "=== Building Linux 5.4.40 ==="
    KERNEL_VERSION="5.4.40"
    KERNEL_TARBALL="linux-${KERNEL_VERSION}.tar.xz"
    KERNEL_URL="https://cdn.kernel.org/pub/linux/kernel/v5.x/${KERNEL_TARBALL}"

    if [ ! -d "$SCRIPT_DIR/linux-${KERNEL_VERSION}" ]; then
        echo "[*] Downloading $KERNEL_TARBALL ..."
        wget -q --show-progress -O "$SCRIPT_DIR/$KERNEL_TARBALL" "$KERNEL_URL"
        tar -xf "$SCRIPT_DIR/$KERNEL_TARBALL" -C "$SCRIPT_DIR"
        rm -f "$SCRIPT_DIR/$KERNEL_TARBALL"
    fi

    cd "$SCRIPT_DIR/linux-${KERNEL_VERSION}"

    if [ ! -f .config ]; then
        make x86_64_defconfig
        scripts/config --enable  CONFIG_SERIAL_8250
        scripts/config --enable  CONFIG_SERIAL_8250_CONSOLE
        scripts/config --enable  CONFIG_BLK_DEV_INITRD
        scripts/config --disable CONFIG_UNWINDER_ORC
        scripts/config --enable  CONFIG_UNWINDER_FRAME_POINTER
        # /dev/mem access required for MMIO mapping
        scripts/config --enable  CONFIG_DEVMEM
        scripts/config --disable CONFIG_STRICT_DEVMEM
        # NVMe and virtio-gpu
        scripts/config --enable  CONFIG_BLK_DEV_NVME
        scripts/config --enable  CONFIG_DRM_VIRTIO_GPU
        make olddefconfig
    fi

    make -j"$JOBS" bzImage
    cp arch/x86/boot/bzImage "$SCRIPT_DIR/bzImage"
    echo "[+] Kernel image: $SCRIPT_DIR/bzImage"
}

setup_busybox() {
    local REF_BUSYBOX="$SCRIPT_DIR/../some-vuln-examples/pcnet-2.2.0/rootfs/bin/busybox"
    local DST="$SCRIPT_DIR/rootfs/bin/busybox"
    if [ ! -f "$DST" ] && [ -f "$REF_BUSYBOX" ]; then
        cp "$REF_BUSYBOX" "$DST"
        chmod +x "$DST"
        for cmd in sh ls cat echo mkdir mount umount halt mknod chown; do
            ln -sf busybox "$SCRIPT_DIR/rootfs/bin/$cmd" 2>/dev/null || true
        done
        echo "[+] busybox installed"
    fi
}

create_nvme_disk() {
    if [ ! -f "$SCRIPT_DIR/nvme.img" ]; then
        qemu-img create -f raw "$SCRIPT_DIR/nvme.img" 128M
        echo "[+] nvme.img created"
    fi
}

build_qemu
build_kernel
setup_busybox
create_nvme_disk

echo ""
echo "=== Build complete ==="
echo "  Run:  chmod +x launch.sh attach.sh rootfs/pack.sh rootfs/a.sh"
echo "        ./launch.sh"
echo "  Then inside the VM: /exp"
