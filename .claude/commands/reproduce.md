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
- **SLiRP generic**: crash inside `m_free` / `g_free` (mbuf overflow)
- **CVE-2019-14378 (SLiRP ip_reass)**: QEMU **hangs** (not SIGSEGV) — I/O thread stuck in `dtom()` infinite loop; QEMU exits with code 143 (SIGTERM from external kill) rather than crashing. Guest VCPUs continue running (MTTCG) but network is dead. Confirmed by: QEMU doesn't exit after guest kernel panic; must be killed by `timeout` or manually.
- **PVSCSI**: crash in `pvscsi_process_io` (SG list overflow)
- **USB EHCI (CVE-2020-14364)**: `rax = 0x4141414141414141` in `usb_bus_from_device`; crash in `ehci_work_bh` → `ehci_advance_async_state` → `ehci_state_execute` → `ehci_execute` → `usb_handle_packet` → `usb_packet_set_state` (heap neighbor of `data_buf` overwritten)
- **Scavenger (CVE-2020-25084)**: SIGSEGV in `object_unref` called from `qemu_sglist_destroy`; `obj` points into QEMU `.text` (stack garbage used as `qsg->dev`). Full backtrace: `object_unref ← qemu_sglist_destroy ← nvme_map_prp ← nvme_dma_read_prp ← nvme_identify_ctrl ← nvme_process_sq`

## Environment Notes

- **LD_LIBRARY_PATH**: If QEMU segfaults on launch due to library mismatches,
  prepend `LD_LIBRARY_PATH=<path-to-libs>` when invoking `./qemu-system-x86_64`.
- **QEMU 4.0.0 library quirk**: links against `libtinfow.so.6` (wide-char ncurses);
  if the system only has `libtinfo.so.6`, create a symlink in a local `libs/` dir:
  `ln -s /usr/lib/x86_64-linux-gnu/libtinfo.so.6 libs/libtinfow.so.6` and
  add `export LD_LIBRARY_PATH=$(pwd)/libs:$LD_LIBRARY_PATH` in `launch.sh`/`attach.sh`.
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
- **NVMe CMB exploit pattern (Scavenger)**:
  - Find NVMe by scanning `/sys/bus/pci/devices/*/class` for `0x010802`.
  - Unbind kernel driver: write BDF to `/sys/bus/pci/drivers/nvme/unbind` (failure is OK — proceed anyway).
  - BAR2 (CMB, 64 MB) is at line index 2 (0-based) of sysfs `resource` file.
  - Map BAR0 via `/dev/mem`; allocate two 4096-byte locked pages for ASQ and ACQ.
  - NVMe init: disable (CC.EN=0, wait CSTS.RDY=0), set AQA/ASQ/ACQ, enable (CC=0x00460001), wait CSTS.RDY=1.
  - Trigger: submit Identify Controller SQE with `prp1 = bar2_phys + 0x500` (in CMB, non-page-aligned), `prp2 = 0`; ring SQ0 doorbell at BAR0 + 0x1000.
  - `--extra-cflags="-pg"` required for Scavenger build; `LD_LIBRARY_PATH=/home/bea1e/miniconda3/lib` needed at runtime.
- **Busybox**: shared from `../some-vuln-examples/pcnet-2.2.0/rootfs/bin/busybox`
- **SLiRP network CVEs**: guest uses `10.0.2.15/24`, gateway `10.0.2.2`
- **SLiRP ip_reass OOB exploit pattern (CVE-2019-14378)**:
  - Bug: in `ip_reass()` (`slirp/src/ip_input.c`), when a fragment mbuf has `M_EXT` set
    (allocated via `m_inc` for pkts > IF_MTU=1480 bytes), a stale `M_EXT` pointer is used to
    recompute `q` (the `ipasfrag` pointer), producing `q_new = m->m_ext + delta` where
    `delta = M1_chunk_size − offsetof(m_dat) = 1632 − 96 = 1536` (constant).
    If `m->m_ext` is 1524 bytes, this overshoots by 12 bytes into the next heap allocation.
  - Trigger: **FRAG1_DATA = 1488** (forces `m_inc`, so `m_ext` is allocated and `M_EXT` set);
    **FRAG2_DATA ≤ 36** (so `M_FREEROOM(m1) ≥ frag2_len`, `m_inc` NOT called in `m_cat`,
    `m_ext` stays at the original address; any larger frag2 triggers `g_realloc` and the new
    larger buffer contains `q_new` — no OOB).
  - MTU must be 9000 on the guest interface (`ifconfig eth0 mtu 9000`) to send 1508-byte
    IP packets (ETH + IP + 1488 B data) without EMSGSIZE from `sendto`.
  - Heap layout (consecutive `g_malloc` calls on a quiet heap):
    M1 (1612 B → chunk 1632) → A/m_ext (1524 B → chunk 1536) → FP/fp_mbuf (1612 B → chunk 1632)
    → M2 (1612 B). OOB write starts at A+1536 = FP; `fragtoip(q_new)` = FP+16; writes
    ip_dst (4 B) to FP+32 = `fp_mbuf→m_flags`.
  - With dst IP `10.0.2.2`: `m_flags` = 0x0202000a → `M_DOFREE` (bit 3) set, `M_USEDLIST`
    (bit 2) clear → `m_free` skips `remque`, calls `g_free(fp_mbuf)` while fp_mbuf remains on
    `m_usedlist`.
  - On glibc ≥ 2.32, SAFE_LINKING applies only to **tcache** (chunks ≤ 1032 B) and **fastbin**.
    Chunks ≥ 1040 B go to the **unsorted bin** with RAW fd/bk pointers (no XOR protection).
    fp_mbuf (chunk 1632 B) → unsorted bin → fp_mbuf+0 = libc arena address.
  - `dtom()` follows `m_usedlist` via `m→m_next`: reaches freed fp_mbuf, reads
    `m_next` = libc arena address, follows it → `arena→fd` = fp_mbuf → **infinite loop**.
    QEMU's I/O thread hangs; guest VCPUs (MTTCG) keep running; guest network is dead.
  - `M_FREEROOM(m)` macro is misleading: `= m_size − m_len` (counts the 36-byte gap BEFORE
    m_data as "free"), NOT the bytes available after `m_data + m_len`. Actual free space at
    end of data = `(m_ext + m_size) − (m_data + m_len)`; with FRAG1=1488 this equals 0.
- **MMIO CVEs**: need `CONFIG_DEVMEM=y`, `CONFIG_STRICT_DEVMEM=n` in kernel

## Your Task

The user will describe what they need — building a CVE, debugging a crash,
writing or fixing `exp.c`, understanding the vulnerability, or extending the
exploit chain.  Read the relevant `README.md` and source files first, then
assist with the specific sub-task.  Do not modify `build.sh` or kernel config
without being asked.
