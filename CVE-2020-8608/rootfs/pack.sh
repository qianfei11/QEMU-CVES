#!/bin/bash
set -e
gcc -static -O0 -o exp exp.c
find . | cpio -o --format=newc | gzip -9 > ../rootfs.cpio
echo "[+] rootfs.cpio created"
