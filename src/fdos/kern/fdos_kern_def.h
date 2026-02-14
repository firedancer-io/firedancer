#ifndef HEADER_fd_src_fdos_kern_fdos_kern_def_h
#define HEADER_fd_src_fdos_kern_fdos_kern_def_h

/* Guest physical base addresses
   These are identity-mapped into the ring 0 virtual address space

   FIXME move these above the low 4 GiB (low 4 GiB needs to be reserved for user) */

#define FDOS_GPADDR_KERN_META   0x1000000UL /* page table, GDT, TSS, etc */
#define FDOS_GPADDR_KERN_CODE   0x2000000UL /* guest kern code */
#define FDOS_GPADDR_KERN_RODATA 0x3000000UL /* guest kern rodata */
#define FDOS_GPADDR_KERN_DATA   0x4000000UL /* guest kern data */
#define FDOS_GPADDR_KERN_STACK  0x5000000UL /* guest stack */
#define FDOS_GPADDR_USER_STACK  0x6000000UL /* user stack */

/* Global Descriptor Table */

#define FDOS_GDT_IDX_NULL      0UL
#define FDOS_GDT_IDX_KERN_CODE 1UL
#define FDOS_GDT_IDX_KERN_DATA 2UL
#define FDOS_GDT_IDX_USER_DATA 3UL
#define FDOS_GDT_IDX_USER_CODE 4UL
#define FDOS_GDT_IDX_TSS       5UL
#define FDOS_GDT_IDX_TSS_HIGH  6UL
#define FDOS_GDT_CNT           7UL

#endif /* HEADER_fd_src_fdos_kern_fdos_kern_def_h */
