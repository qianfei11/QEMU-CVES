---
description: Guide QEMU CVE reproduction — build environment, trigger vulnerability, debug with GDB
allowed-tools: Bash(git *), Bash(ls *), Bash(cat *), Bash(chmod *), Bash(./build.sh*), Bash(./launch.sh*), Bash(./attach.sh*), Bash(gcc *), Bash(gdb *), Bash(make *), Bash(cp *), Bash(rm *)
---

You are assisting with QEMU/KVM vulnerability reproduction in the `QEMU-CVES` project.

## Project Layout

Each CVE subdirectory is self-contained:

```
CVE-XXXX-YYYY/
├── build.sh      # clones + builds vulnerable QEMU & Linux 5.4.40
├── launch.sh     # interactive VM session
├── attach.sh     # GDB session (rdinit=/a.sh auto-runs /exp, catches SIGSEGV)
├── README.md     # root-cause analysis, patch, references
└── rootfs/
    ├── exp.c     # guest-side exploit (static, musl or glibc)
    ├── init      # initramfs init script
    ├── a.sh      # non-interactive exploit runner
    └── pack.sh   # repack rootfs.cpio
```

## CVE → Directory Map

| CVE | Directory | QEMU ver | Component | Type |
|-----|-----------|----------|-----------|------|
| CVE-2015-3456 | `CVE-2015-3456 (VENOM)/` | 2.2.0-rc1 | `hw/block/fdc.c` | FIFO overflow |
| CVE-2016-4952 | `CVE-2016-4952/` | 2.6.2 | `hw/scsi/vmw_pvscsi.c` | Heap overflow |
| CVE-2019-6788 | `CVE-2019-6788/` | 3.1.0 | `slirp/tcp_subr.c` | Heap overflow |
| CVE-2019-14378 | `CVE-2019-14378/` | 4.0.0 | `slirp/ip_input.c` | Heap overflow |
| CVE-2020-8608 | `CVE-2020-8608/` | 4.2.1 | `slirp/tcp_subr.c` | Heap overflow |
| CVE-2020-14364 | `CVE-2020-14364/` | 4.2.1 | `hw/usb/core.c` | OOB write |
| CVE-2020-25084 | `Scavenger/` | 5.0.0 | `hw/block/nvme.c` | UAF |

## Standard Workflow

### Step 1 — Build

```bash
cd <CVE-dir>
chmod +x build.sh launch.sh attach.sh rootfs/pack.sh rootfs/a.sh
./build.sh
```

`build.sh` downloads the vulnerable QEMU tag into `/tmp/`, builds it with
`--enable-debug --disable-werror`, then copies `qemu-system-x86_64` and
`pc-bios/` here.  It also builds Linux 5.4.40 and creates any required disk
images (`nvme.img`, `usb.img`, `scratch.img`).

**QEMU 2.x quirks (CVE-2015-3456, CVE-2016-4952):**
- Needs Python 2: `--python=python2`
- Build only the x86_64 softmmu target to avoid `iasl` incompatibility:
  `make IASL= subdir-x86_64-softmmu`

**Scavenger quirk:** requires `--extra-cflags="-pg"` and prints `nm`-derived
symbol offsets after the build — update the three `#define` values in
`rootfs/exp.c` before compiling the exploit.

### Step 2 — Compile and pack the exploit

```bash
cd rootfs
gcc -o exp exp.c -static -O0 -g
./pack.sh     # rebuilds rootfs.cpio
```

Or let `a.sh` / `attach.sh` handle this automatically.

### Step 3a — Interactive VM

```bash
./launch.sh   # drops into a shell; run /exp to trigger the bug
```

### Step 3b — Automated crash under GDB

```bash
./attach.sh
```

`attach.sh` boots with `rdinit=/a.sh`, which compiles and runs `/exp`
automatically.  GDB is configured with:
- `catch signal SIGSEGV` — stops on crash
- `handle SIGUSR1/2 noprint nostop` — suppresses QEMU internal signals

### Step 4 — Inspect crash

Typical crash indicators:
- **VENOM**: `rax = 0x4242424242424242` in `aio_bh_poll` (QEMUBH.cb overwrite)
- **SLiRP**: crash inside `m_free` / `g_free` (mbuf overflow)
- **PVSCSI**: crash in `pvscsi_process_io` (SG list overflow)
- **USB EHCI (CVE-2020-14364)**: `rax = 0x4141414141414141` in `usb_bus_from_device`; crash in `ehci_work_bh` → `ehci_advance_async_state` → `ehci_state_execute` → `ehci_execute` → `usb_handle_packet` → `usb_packet_set_state` (heap neighbor of `data_buf` overwritten)
- **Scavenger**: arbitrary free in `qemu_sglist_destroy` (stack garbage freed)

## Environment Notes

- **LD_LIBRARY_PATH**: If QEMU segfaults on launch due to library mismatches,
  prepend `LD_LIBRARY_PATH=<path-to-libs>` when invoking `./qemu-system-x86_64`.
- **Reusing a binary**: If `build.sh` requires unavailable libs (e.g. `libspice-server-dev`),
  copy the `qemu-system-x86_64`, `pc-bios/`, and any `.so` files from another CVE directory
  that uses the same QEMU tag — the binary is identical.
- **rdinit=/a.sh**: When the kernel boots with `rdinit=/a.sh`, the `init` script
  is **never** executed.  `a.sh` must mount `/proc`, `/sys`, and `/dev` itself
  before running the exploit, otherwise sysfs lookups (e.g. PCI device scan) fail.
- **EHCI MMIO exploit pattern**:
  - Find EHCI by scanning `/sys/bus/pci/devices/*/class` for `0x0c0320` (USB EHCI).
  - Unbind kernel driver: write BDF to `/sys/bus/pci/drivers/ehci-pci/unbind`.
  - Map BAR0 via `/dev/mem`; read CAPLENGTH byte at offset 0 to get op-reg base.
  - EHCI async list must be circular and exactly one QH must have `H=1`.
  - QH with `qtd_next=T` (terminate bit set) is idle — EHCI skips it until armed.
  - After HC reset, `portsc[i] = PORTSC_PP` (0x1000); CCS=0 so port reset may fail.
    Power-cycle the port (clear PP → wait → set PP → wait) to restore device presence.
  - Two consecutive SETUP tokens are the key primitive for CVE-2020-14364:
    first establishes `setup_state=DATA`, second corrupts `setup_len` before stall.
- **Busybox**: shared from `../some-vuln-examples/pcnet-2.2.0/rootfs/bin/busybox`
- **SLiRP network CVEs**: guest uses `10.0.2.15/24`, gateway `10.0.2.2`
- **MMIO CVEs**: need `CONFIG_DEVMEM=y`, `CONFIG_STRICT_DEVMEM=n` in kernel

## Your Task

The user will describe what they need — building a CVE, debugging a crash,
writing or fixing `exp.c`, understanding the vulnerability, or extending the
exploit chain.  Read the relevant `README.md` and source files first, then
assist with the specific sub-task.  Do not modify `build.sh` or kernel config
without being asked.
