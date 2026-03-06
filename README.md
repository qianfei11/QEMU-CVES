# QEMU-CVES — VM Escape Vulnerability Collection

A collection of QEMU/KVM vulnerability reproductions covering buffer overflows, use-after-free, and out-of-bounds write bugs that lead to VM escape (host code execution).

Each subdirectory contains a self-contained reproduction environment: build scripts, a minimal Linux guest (Linux 5.4.40 + busybox), and a skeleton exploit.

---

## CVE Index

| Directory | CVE | QEMU Version | Component | Type |
|:---|:---|:---|:---|:---|
| `CVE-2015-3456 (VENOM)/` | CVE-2015-3456 | 2.2.0-rc1 | `hw/block/fdc.c` | FIFO buffer overflow |
| `CVE-2016-4952/` | CVE-2016-4952 | 2.6.2 | `hw/scsi/vmw_pvscsi.c` | Heap buffer overflow |
| `CVE-2019-6788/` | CVE-2019-6788 | 3.1.0 | `slirp/tcp_subr.c` | Heap buffer overflow |
| `CVE-2019-14378/` | CVE-2019-14378 | 4.0.0 | `slirp/ip_input.c` | Heap buffer overflow |
| `CVE-2020-8608/` | CVE-2020-8608 | 4.2.1 | `slirp/tcp_subr.c` | Heap buffer overflow |
| `CVE-2020-14364/` | CVE-2020-14364 | 4.2.1 | `hw/usb/core.c` | Out-of-bounds write |
| `CVE-2020-25084/` | CVE-2020-25084 | 4.2.1 | `hw/usb/hcd-xhci.c` + `hw/usb/core.c` | Assertion failure (xHCI) |
| `Scavenger/` | CVE-2020-25084 | 5.0.0 | `hw/block/nvme.c` | Use-after-free (NVMe) |

---

## Vulnerability Summaries

### CVE-2015-3456 — VENOM (Floppy Disk Controller FIFO Overflow)

`fdctrl_handle_drive_specification_command()` in `hw/block/fdc.c` does not call
`fdctrl_reset_fifo()` when a DRIVE_SPECIFICATION_COMMAND byte has bit-7 clear and
`data_len <= 7`, leaving `data_pos` to advance past the 512-byte FIFO boundary on
subsequent writes.  Any adjacent heap data (e.g., a `QEMUBH.cb` function pointer)
can be overwritten.

Patched in QEMU 2.3.0 (commit `e6f4d0b`) by adding the missing `else` branch that
calls `fdctrl_reset_fifo()`.  **Confirmed working** — clean QEMU v2.2.0-rc1 crashes
with `SIGSEGV` at `aio_bh_poll` with `rax = 0x4242424242424242`.

---

### CVE-2016-4952 — PVSCSI Ring Heap Overflow

`pvscsi_ring_pop_req_descr()` in `hw/scsi/vmw_pvscsi.c` copies scatter-gather
entries from a guest-controlled request descriptor into a fixed-size host buffer
without validating the `numSGEs` field against `PVSCSI_MAX_SG_ENTRIES` (255).
A malicious guest can overflow the host SG buffer by supplying an oversized count.

Attack vector: MMIO (PCI BAR0) + DMA via the PVSCSI adapter.
Patched by clamping the loop bound with `MIN(descr->numSGEs, PVSCSI_MAX_SG_ENTRIES)`.

---

### CVE-2019-6788 — SLiRP FTP/IRC `tcp_emu()` Heap Overflow

`tcp_emu()` in `slirp/tcp_subr.c` handles FTP PORT and IRC DCC traffic by parsing
with `sscanf` then writing a rewritten string back into the same mbuf with `sprintf`,
without checking that the result fits within the mbuf boundary.  A guest can trigger
the overflow by connecting to SLiRP's FTP emulation (port 21) or IRC (port 6667)
and sending a crafted PORT or DCC command.

Related: CVE-2019-6778 (same family, SLiRP `tcp_emu` FTP PORT).

---

### CVE-2019-14378 — SLiRP `ip_reass()` Heap Overflow

`ip_reass()` in `slirp/ip_input.c` reassembles fragmented IP datagrams.  The
allocated mbuf may be smaller than the total reassembled size when certain fragment
offset combinations are presented, causing the subsequent `memcpy` of fragment data
to overflow the mbuf.

Attack vector: raw IP socket inside the VM sending crafted fragmented UDP datagrams
to the SLiRP gateway (10.0.2.2).
Patched by adding a `next > IP_MAXPACKET` check before `m_inc()`.

---

### CVE-2020-8608 — SLiRP IRC DCC `tcp_emu()` Heap Overflow

Closely related to CVE-2019-6788.  `tcp_emu()`'s IRC DCC SEND handler in
`slirp/tcp_subr.c` rewrites the DCC packet's embedded IP address to the SLiRP
external address.  When the rewritten address is longer than the original, the
`sprintf` call overflows the backing mbuf.

Attack vector: guest connects to 10.0.2.2:6667 and sends a DCC SEND with a
256-byte filename and a short internal IP that SLiRP expands to a longer external
address.

---

### CVE-2020-14364 — USB EHCI `do_token_setup()` Out-of-Bounds Write

`do_token_setup()` in `hw/usb/core.c` stores `setup_len` (derived from the
guest-controlled SETUP packet) into `s->setup_len` **before** checking whether it
exceeds `sizeof(s->data_buf)` (4096 bytes).  Subsequent DATA stage packets copy up
to `s->setup_len` bytes into `data_buf`, providing a controlled out-of-bounds write.

Call chain: `ehci_work_bh` → `ehci_advance_state` → `ehci_execute` →
`usb_handle_packet` → `do_token_setup`.  Requires `--enable-spice` at configure
time (enables the EHCI controller).
Patched by moving the `s->setup_len` assignment after the bounds check.

---

### CVE-2020-25084 (xHCI) — xhci_fire_ctl_transfer Assertion Failure

`xhci_fire_ctl_transfer()` in `hw/usb/hcd-xhci.c` sends a control transfer with
a DATA TRB whose direction field (TRB_TR_DIR) is set to OUT while the request is
an IN transfer (GET_DESCRIPTOR, bmRequestType=0x80).  The direction mismatch causes
`xhci_xfer_create_sgl()` to call `xhci_die()` and destroy the SGL (nsg→0).
`xhci_setup_packet()` ignores the error; `usb_packet_map()` returns 0 with
`iov.size=0`; `usb_handle_packet()` → `usb_packet_copy()` fires
`assert(p->actual_length + bytes <= iov->size)`.

Call chain: `xhci_doorbell_write` → `xhci_kick_ep` → `xhci_kick_epctx` →
`xhci_fire_ctl_transfer` → `usb_handle_packet` → `usb_packet_copy` → **SIGABRT**.
Affects QEMU 4.2.1 and 5.0.0; the QEMU 4.2.1 binary from `CVE-2020-14364/` can
be reused.

---

### Scavenger — CVE-2020-25084 (NVMe Stack UAF → VM Escape)

*(Black Hat Asia 2021)*

`nvme_dma_read_prp()` in `hw/block/nvme.c` declares a `QEMUSGList` on the
**stack** without zero-initialising it, then passes it to `nvme_map_prp()`.  On the
error path, `nvme_map_prp()` jumps to `unmap:` and calls `qemu_sglist_destroy()`
on the uninitialised stack struct, freeing stack garbage as heap pointers.

Full exploit chain (see `Scavenger/README.md`):
heap spray → virtio-gpu UAF primitive → chunk reclaim → physmap leak →
QEMU base derivation → timer hijack → `system()` on host.

---

## Common Workflow

Every CVE directory follows the same layout:

```
CVE-XXXX-YYYY/
├── build.sh          # downloads + builds QEMU & Linux kernel
├── exploit.sh        # one-click reproduction (build check + GDB crash)
├── launch.sh         # boots the VM interactively
├── attach.sh         # boots the VM under GDB, auto-catches SIGSEGV
├── .gitignore
├── README.md
└── rootfs/
    ├── exp.c         # exploit source (guest-side C)
    ├── init          # initramfs init script
    ├── a.sh          # non-interactive exploit runner (rdinit target)
    ├── pack.sh       # repacks rootfs.cpio from rootfs/
    ├── etc/          # passwd, group, hostname, …
    ├── root/         # welcome banner
    └── bin/          # busybox symlinks (built by build.sh)
```

### One-click reproduction

```bash
cd CVE-XXXX-YYYY/
./exploit.sh
```

`exploit.sh` checks whether `qemu-system-x86_64` is present (running `build.sh`
automatically if not), prints the expected crash indicator, then launches the
VM under GDB via `attach.sh`.  For CVE-2019-14378, which causes a hang rather
than a crash, a 90-second timeout is applied and exit code 124 confirms the bug.

### Build

```bash
cd CVE-XXXX-YYYY/
chmod +x build.sh launch.sh attach.sh rootfs/pack.sh rootfs/a.sh
./build.sh
```

`build.sh` clones the vulnerable QEMU tag into `/tmp/`, builds it, and copies
`qemu-system-x86_64` and `pc-bios/` into the CVE directory.  It also downloads
Linux 5.4.40, builds `bzImage`, and prepares any disk images the CVE needs.

### Interactive VM

```bash
./launch.sh      # opens a shell inside the VM; run /exp to trigger the bug
```

### Automated crash (non-interactive)

```bash
./attach.sh      # launches GDB; the VM boots with rdinit=/a.sh, which runs /exp
                 # automatically; GDB catches SIGSEGV
```

---

## Infrastructure Notes

- **Guest kernel**: Linux 5.4.40 with `x86_64_defconfig`,
  `CONFIG_UNWINDER_FRAME_POINTER=y`, `CONFIG_UNWINDER_ORC=n`.
  SLiRP-based CVEs also enable `CONFIG_E1000=y`.
  MMIO-based CVEs enable `CONFIG_STRICT_DEVMEM=n` / `CONFIG_DEVMEM=y`.
- **Busybox**: the pre-built busybox binary is shared from
  `some-vuln-examples/` and symlinked into each CVE's `rootfs/bin/`.
- **QEMU 2.x quirks**: requires Python 2 (`--python=python2`) and building
  with `make IASL= subdir-x86_64-softmmu` to avoid incompatibility with
  modern `iasl`.
- **Library path**: if your system glibc differs from the build environment,
  `attach.sh` auto-detects a conda installation (`conda info --base`) and
  prepends its `lib/` directory to `LD_LIBRARY_PATH`.  You can also set
  `LD_LIBRARY_PATH` manually before running any script.

---

## References

- [VENOM漏洞分析与利用 (terenceli)](https://terenceli.github.io/%E6%8A%80%E6%9C%AF/2015/06/26/venom)
- [Scavenger — Black Hat Asia 2021](https://blackhat.com/asia-21/briefings/schedule/#scavenger-misuse-error-handling-leading-to-qemukvm-escape-21971)
- [CVE-2019-6788 分析 (a1ex.online)](http://a1ex.online/2021/10/24/CVE-2019-6788-Qemu%E9%80%83%E9%80%B8%E6%BC%8F%E6%B4%9E%E5%A4%8D%E7%8E%B0%E4%B8%8E%E5%88%86%E6%9E%90/)
- [CVE-2019-14378 分析 (giantbranch)](https://www.giantbranch.cn/2019/10/09/QEMU%20%E8%99%9A%E6%8B%9F%E6%9C%BA%E9%80%83%E9%80%B8%E6%BC%8F%E6%B4%9E%EF%BC%88CVE-2019-14378%EF%BC%89%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90/)
- [CVE-2020-14364漏洞复现 (anquanke)](https://www.anquanke.com/post/id/227283)
- [NVD CVE list](https://nvd.nist.gov/)
