---
description: Guide QEMU CVE reproduction — build environment, trigger vulnerability, debug with GDB
allowed-tools: Bash(git *), Bash(ls *), Bash(cat *), Bash(chmod *), Bash(./build.sh*), Bash(./exploit.sh*), Bash(./launch.sh*), Bash(./attach.sh*), Bash(gcc *), Bash(gdb *), Bash(make *), Bash(cp *), Bash(rm *)
---

You are assisting with QEMU/KVM vulnerability reproduction in the `QEMU-CVES` project.

## Project Layout

Each CVE subdirectory is self-contained:

```
CVE-XXXX-YYYY/
├── build.sh      # clones + builds vulnerable QEMU & Linux 5.4.40
├── exploit.sh    # one-click reproduction (build check → GDB crash demo)
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
| CVE-2020-25084 (xHCI) | `CVE-2020-25084/` | 4.2.1 | `hw/usb/hcd-xhci.c` + `hw/usb/core.c` | Assertion failure |
| CVE-2020-25084 (NVMe) | `Scavenger/` | 5.0.0 | `hw/block/nvme.c` | UAF |

## Standard Workflow

### Step 0 — One-click reproduction (recommended)

```bash
cd <CVE-dir>
./exploit.sh
```

`exploit.sh` checks for `qemu-system-x86_64`, runs `build.sh` automatically if
missing, then prints the expected crash indicator and calls `attach.sh`.
For CVE-2019-14378 (hang, not crash), a 90-second timeout is used.

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
- **CVE-2020-25084 xHCI**: SIGABRT in `usb_packet_copy` — `assert(p->actual_length + bytes <= iov->size)` fires with `iov->size=0`. Full backtrace: `usb_packet_copy ← do_parameter ← usb_process_one ← usb_handle_packet ← xhci_fire_ctl_transfer ← xhci_kick_epctx ← xhci_kick_ep ← xhci_doorbell_write`

## Environment Notes

- **LD_LIBRARY_PATH**: If QEMU segfaults on launch due to library mismatches,
  `attach.sh` scripts that need it auto-detect the conda base (`conda info --base`)
  and prepend its `lib/` directory to `LD_LIBRARY_PATH`.  You can also set
  `LD_LIBRARY_PATH` manually before running any script.
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
  - `--extra-cflags="-pg"` required for Scavenger build; `LD_LIBRARY_PATH=$(conda info --base)/lib` needed at runtime if system libs are mismatched (auto-detected by the updated `attach.sh`).
- **Busybox**: shared from `../some-vuln-examples/pcnet-2.2.0/rootfs/bin/busybox`
- **SLiRP network CVEs**: guest uses `10.0.2.15/24`, gateway `10.0.2.2`
- **SLiRP EMU subsystem (CVE-2020-8608)**: libslirp 4.1.0 has `tcp_emu()` but it is
  gated by `slirp->enable_emu`.  QEMU 4.2.1 calls `slirp_init()` (compat API) which
  zeroes `SlirpConfig` with `memset`, leaving `enable_emu = false`.  Without patching
  `slirp_init()` to set `cfg.enable_emu = true`, `tcp_tos()` never sets `so_emu` and
  `tcp_emu()` is never called — the bug is unreachable.  The reproduction patches this
  in `/tmp/libslirp-4.1.0/src/slirp.c` before `return slirp_new(...)`.
- **SLiRP EMU_IRC trigger**: `tcptos[]` in libslirp 4.1.0 matches on **destination**
  port 6667 only (`fport` field).  The guest must connect **to** port 6667.  Use
  `guestfwd=tcp:10.0.2.100:6667-cmd:cat` in QEMU's `-netdev` options; `cmd:cat`
  sets `SS_CTL` but `tcp_tos()` fires on the SYN before `SS_CTL` is set, so
  `so_emu = EMU_IRC` is correctly assigned and `tcp_emu()` IS called on data.
- **SLiRP mbuf layout (libslirp 4.1.0 / QEMU 4.2.1, MTU=1500, empirically measured)**:
  `m_size = 1544`; `H_OFFSET = m_data − m_dat = 84` after IP+TCP headers stripped;
  `M_ROOM = 1544 − 84 = 1460` bytes usable from `m_data`.  (Prior references citing
  `m_size=1536`, `H=96`, `M_ROOM=1440` are wrong for this build.)
- **SLiRP tcp_emu overflow math (CVE-2020-8608)**:
  With `DCC_OFFSET = 1175`: payload = 1459 bytes; `m_inc(m, 1460)` reallocates
  since `M_ROOM == 1460` (not `>` 1460); new `g_malloc(1544)` has 0 glibc padding;
  `snprintf` outputs 295 bytes (294 chars + null); available = 285 bytes;
  **10-byte heap overflow** into the next chunk's metadata.  With `DCC_OFFSET = 1155`
  (available = 305) there is NO overflow; minimum DCC_OFFSET for overflow is 1166.
- **GDB breakpoint for static symbols in shared libraries**:
  Source-level breakpoints (`b tcp_subr.c:792`) remain "pending" and never fire for
  static functions inside `.so` files.  Absolute addresses are ASLR-sensitive.
  **Working technique**: set `b slirp_input` (exported symbol); in its `commands` block,
  compute the inner breakpoint once via `b *((char *)&slirp_input + delta)` where
  `delta = target_offset − slirp_input_offset` (both from `readelf -s libslirp.so`).
  Use a `$flag == 0` guard to set the inner bp only once; the outer `slirp_input` bp
  continues firing but is cheap.  Current delta for post-`snprintf` return in the
  debug-patched libslirp: `0xad47`.
- **GDB formula for bptr_off after snprintf call**:
  At the breakpoint immediately after `snprintf` returns (before `m->m_len += snret`),
  `m->m_len` holds `bptr − m_data` (set one line earlier).  Therefore:
  `bptr_off = m->m_len` (NOT `m->m_len − snret`).
  Available bytes = `M_ROOM − bptr_off`; overflow = `snret + 1 − available`.
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
- **xHCI MMIO exploit pattern (CVE-2020-25084)**:
  - Find NEC xHCI by scanning `/sys/bus/pci/devices/*/class` for `0x0c0330`.
  - Map BAR0 via `/dev/mem`; read HCCPARAMS1 at offset 0x10 (CSZ bit = context size).
  - QEMU 4.x/5.x xHCI: context size is **hardcoded 32 bytes** regardless of CSZ.
    Input context layout: `[ICC@0][SlotCtx@32][EP0Ctx@64]`
  - xHCI init: HCRST, configure ERST/CRCR/DCBAAP, start (RS=1), then Enable Slot.
  - `HCSPARAMS1` field layout: bits[31:24]=numports, bits[7:0]=numslots (NOT numports).
  - **NEC xHCI sets `XHCI_FLAG_SS_FIRST`**: USB3 (SS) ports are at indices 0..3
    (RHPORT 1..4), USB2 (HS) ports are at indices 4..7 (RHPORT 5..8).
    `usb-storage` (default HS) connects to USB2 port → RHPORT=5.
  - PORTSC register for port i: `BAR0 + 0x40 + 0x400 + 0x10*i`.
  - Trigger: send Address Device with EP0 context pointing to an EP0 Transfer Ring.
    In the EP0 ring, create SETUP+DATA+STATUS control transfer.
    **Set DATA TRB direction = OUT (TRB_TR_DIR=0)** while the transfer is IN
    (GET_DESCRIPTOR → bmRequestType=0x80). The direction mismatch causes
    `xhci_xfer_create_sgl` to call `xhci_die` and destroy the SGL (nsg→0).
    `xhci_setup_packet` ignores the error; `usb_packet_map` with nsg=0 returns 0
    but iov.size=0. `usb_handle_packet` → `usb_packet_copy` → SIGABRT.
  - **Why unmapped PA does NOT trigger**: `address_space_map()` allocates a bounce
    buffer for non-RAM regions (`bounce.in_use` check), returning non-NULL so
    `usb_packet_map` succeeds with iov.size=wLength. The assert `18 ≤ wLength` passes.
  - `usb_packet_map` returns −1 only when `bounce.in_use` is already true (another
    concurrent DMA in progress) — not reliably triggerable from a single guest thread.
  - QEMU 4.2.1 and 5.0.0 are both affected; the QEMU 4.2.1 binary from CVE-2020-14364
    can be reused (`LD_LIBRARY_PATH=$(pwd)` for libtinfow.so.6).

## Your Task

The user will describe what they need — building a CVE, debugging a crash,
writing or fixing `exp.c`, understanding the vulnerability, or extending the
exploit chain.  Read the relevant `README.md` and source files first, then
assist with the specific sub-task.  Do not modify `build.sh` or kernel config
without being asked.
