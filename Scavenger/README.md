# Scavenger — Misuse of Error-Handling Code → QEMU/KVM Escape

**Black Hat Asia 2021** ([hustdebug/scavenger](https://github.com/hustdebug/scavenger))

## Summary

| Field      | Value |
|:-----------|:------|
| CVE        | N/A (no CVE assigned) |
| Affected   | QEMU ≤ 4.2.1 (Debian 1:4.2-3ubuntu6.7) |
| Component  | `hw/block/nvme.c`, `dma-helpers.c`, `virtio-gpu` |
| Type       | Uninitialized free (stack garbage freed by `qemu_sglist_destroy`) |
| Impact     | Full VM escape (host code execution) |

## Environment

```bash
chmod +x build.sh launch.sh attach.sh rootfs/pack.sh rootfs/a.sh
./build.sh        # builds QEMU v4.2.1 (with -pg) + Linux 5.4.40 + nvme.img
./launch.sh       # interactive VM — run /exp manually
./attach.sh       # GDB session (automated crash capture)
./exploit.sh      # one-click: checks binary, calls attach.sh
```

Kernel source is shared at `../linux-5.4.40`; built out-of-tree into `./linux-build/`
using `../default.config` (common options) plus `./kernel.config` (enables
`CONFIG_DEVMEM=y` / `CONFIG_STRICT_DEVMEM=n` / `CONFIG_IO_STRICT_DEVMEM=n`).
Dynamic libraries (including `libtinfow.so.6`) are obtained from the active conda
environment (`$(conda info --base)/lib`); `libslirp.so.0` is used from the system.
No libraries are bundled in this directory.

## Files

| File | Description |
|:-----|:------------|
| `build.sh` | Builds QEMU 4.2.1 (profiling build, `-pg`) + Linux 5.4.40 (shared source at `../linux-5.4.40`) + `nvme.img` |
| `launch.sh` | Boots the VM interactively; run `/exp` manually inside |
| `attach.sh` | GDB session — VM boots with `rdinit=/a.sh`, exploit runs automatically |
| `exploit.sh` | One-click: checks for `qemu-system-x86_64`, invokes `attach.sh` |
| `kernel.config` | Scenario-specific kernel config fragment (`CONFIG_DEVMEM=y`, `CONFIG_STRICT_DEVMEM=n`, `CONFIG_IO_STRICT_DEVMEM=n`); applied on top of `../default.config` |
| `nvme.img` | NVMe backing disk image (required for the NVMe CMB bug trigger) |
| `rootfs/exp.c` | Guest-side exploit source (NVMe CMB uninitialized-free crash PoC / exploit scaffold) |
| `rootfs/pack.sh` | Compiles `exp.c` and repacks `rootfs.cpio` |
| `rootfs/a.sh` | Minimal init: mounts `/proc`/`/sys`/`/dev`, runs `/exp`, halts |
| `rootfs/init` | Standard initramfs init script (interactive boot) |
| `pc-bios/` | QEMU BIOS ROM files (copied by `build.sh`) |
| `qemu-system-x86_64` | Vulnerable QEMU binary |
| `bzImage` | Guest kernel (compiled with `../default.config` + `./kernel.config`) |
| `rootfs.cpio` | Initramfs archive (repacked by `rootfs/pack.sh`) |
| `linux-build/` | Out-of-tree kernel build directory (gitignored, created by `build.sh`) |

## Distinction from CVE-2020-25084

**Scavenger is NOT CVE-2020-25084.** They are completely different vulnerabilities
from different QEMU components, despite both being tested against QEMU 4.x.

| Aspect | Scavenger (this directory) | CVE-2020-25084 |
|:-------|:--------------------------|:---------------|
| Component | `hw/block/nvme.c` — NVMe storage controller | `hw/usb/hcd-xhci.c` — xHCI USB controller |
| Bug class | Uninitialized stack `QEMUSGList` freed by `qemu_sglist_destroy` | Missing return-value check on `usb_packet_map()` → assertion failure |
| Root cause | `nvme_map_prp()` sets only `qsg->nsg=0` on CMB path; `dev`/`sg`/`as` left as stack garbage; `goto unmap` frees them via `object_unref` | `xhci_setup_packet()` ignores `usb_packet_map()` error; `iov.size` stays 0; `assert(0 + 18 ≤ 0)` fires |
| Outcome | **Full VM escape** (heap spray + physmap leak + timer callback overwrite → `system()` on host) | **SIGABRT** — QEMU process aborts → guest DoS only |
| CVE | **No CVE assigned** | CVE-2020-25084 |
| Presented | Black Hat Asia 2021 | — |

Scavenger is a **full host code execution** exploit demonstrated at Black Hat
Asia 2021.  CVE-2020-25084 is a **denial-of-service** — the QEMU process aborts
when a guest triggers an assertion in the xHCI USB subsystem.  These two issues
have nothing in common beyond targeting QEMU around version 4–5.



`nvme_dma_read_prp()` / `nvme_dma_write_prp()` declare a `QEMUSGList`
on the **stack** and pass its address to `nvme_map_prp()`.  On the CMB
(Controller Memory Buffer) code path, only `qsg->nsg = 0` is set —
`qsg->dev`, `qsg->sg`, `qsg->as` remain **stack garbage**.  When `prp2=0`,
the function jumps to `unmap:` which calls `qemu_sglist_destroy()` on the
uninitialised struct, and `object_unref(garbage_pointer)` → SIGSEGV.

```c
/* hw/block/nvme.c — nvme_map_prp() */
} else if (n->bar.cmbsz && prp1 >= n->ctrl_mem.addr &&
           prp1 < n->ctrl_mem.addr + int128_get64(n->ctrl_mem.size)) {
    qsg->nsg = 0;                    /* ← only this field set   */
    qemu_iovec_init(iov, num_prps);  /*   dev/sg/as = stack junk */
    qemu_iovec_add(iov, ...);
    if (len != trans_len) {
        if (!prp2) { goto unmap; }   /* ← prp2=0 → unmap        */
    }
} ...
unmap:
    qemu_sglist_destroy(qsg);        /* object_unref(garbage)    */
```

## Exploit Chain

```
1. Heap spray to clear tcache freelist
2. Alloc mapping table (physmap addr) → put in tcache head
3. Free mapping table
4. Alloc NvmeRequest → trigger NVMe CMB bug (prp1∈CMB, prp2=0)
   → chunk in guest userspace added to QEMU tcache (UAF primitive)
5. Re-alloc mapping table → overlaps with UAF chunk
   → leak physmap base address
6. Heap fengshui with create_sq + QEMUTimer placement
   → leak QEMU text base + heap address
7. Overwrite QEMUTimer.cb = slirp_smb_cleanup, .opaque = &cmd_str
   → timer fires → system(cmd_str) → host code execution
```

## QEMU Launch Flags

```
-drive format=raw,file=./nvme.img,if=none,id=D11
-device nvme,drive=D11,serial=1234,cmb_size_mb=64
-device virtio-gpu
-display none
```

## Trigger Conditions

1. `cmb_size_mb=64` must be set on the NVMe device (enables BAR2 CMB).
2. `prp1` must fall inside the CMB range: `bar2_phys + 0x500` (non-page-aligned).
3. `prp2 = 0` → `goto unmap` → `qemu_sglist_destroy` on uninit `qsg`.

## GDB Crash Output

```
Thread 1 "qemu-system-x86" hit Catchpoint 1 (signal SIGSEGV),
0x0000... in object_unref (obj=<.text pointer — stack garbage qsg->dev>)
    at qom/object.c:1127
#0  object_unref     (obj=...)           qom/object.c:1127
#1  qemu_sglist_destroy (qsg=0x7fff....) dma-helpers.c:66
#2  nvme_map_prp    (prp1=..., prp2=0)   hw/block/nvme.c:220
#3  nvme_dma_read_prp                    hw/block/nvme.c:257
#4  nvme_identify_ctrl                   hw/block/nvme.c:656
#5  nvme_identify                        hw/block/nvme.c:715
#6  nvme_admin_cmd                       hw/block/nvme.c:859
#7  nvme_process_sq                      hw/block/nvme.c:893
```

## References

- [Black Hat Asia 2021 — Scavenger: Misuse Error Handling Leading to QEMU/KVM Escape](https://blackhat.com/asia-21/briefings/schedule/#scavenger-misuse-error-handling-leading-to-qemukvm-escape-21971)
- [清道夫：误用"错误处理代码"导致的 QEMU/KVM 逃逸](https://mp.weixin.qq.com/s/1KYTZynabBqzNjoJhe1bWw)
- [hustdebug/scavenger exploit repo](https://github.com/hustdebug/scavenger)
