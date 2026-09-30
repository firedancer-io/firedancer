#ifndef HEADER_fd_src_flamenco_vm_fd_vm_mem_h
#define HEADER_fd_src_flamenco_vm_fd_vm_mem_h

#include "../runtime/fd_runtime_const.h"

/* An fd_vm_mem_t holds pointers to specially allocated memory for sBPF
   program execution.  Unlike most of firedancer, the memory used must
   have a special layout but need not be contiguous.  This accelerates
   address translation in the VM/JIT.

   This struct has two goals: first, optimize address translation
   to a single operation: haddr = vaddr + base.  Second, be very lazy
   with copying and zeroing, we can save a lot of time in the
   setup/teardown phases of execution.  (CPIs to the token program are
   so common right now that the median number of memory operations in a
   VM invocation is just 28, and 75% of VM invocations do less than 100
   memory operations)

   To that end, we store one instance of the memory for each level of
   the CPI stack.  That way, when we return from a CPI call, we mostly
   just need to update the base address, without having to save/restore
   the stack, heap, etc.

   There are two forms of fd_vm_mem_t structs: those with a dense
   footprint and those with a sparse footprint.  Using a dense footprint
   is simpler, and more in line with most of the firedancer types, but
   wastes a substantial amount of memory.  Other than different
   allocation/release patterns, both types are totally compatible. */

struct fd_vm_mem {
  /* dirty: a bitset of FD_MAX_INSTRUCTION_STACK_DEPTH bits.  If bit i
     is set, then the memory associated with frame i may be dirty. */
  ulong  dirty;

  /* For i in [0, FD_MAX_INSTRUCTION_STACK_DEPTH), base_addr[ i ]
     establishes a frame of memory.  That means the following address
     ranges are mapped and essentially owned by this fd_vm_mem_t object:

     [0x0_0000_0000,  0x0_00A0_0000)  For SBPFv3   ro_data section     (FD_RUNTIME_ACC_SZ_MAX)
     TODO                             For the dirty bitmap
     [0x1_0000_0000,  0x1_00A0_0000)  For SBPFv0-2 ro_data section     (FD_RUNTIME_ACC_SZ_MAX)
     [0x2_0000_0000,  0x2_0008_0000)  For the stack                    (2*FD_VM_STACK_MAX)
     [0x3_0000_0000,  0x3_0004_0000)  For the heap                     (FD_VM_HEAP_MAX)
     [0x4_0000_0000,  0x4_0560_0000)  For the input region             (BPF_LOADER_SERIALIZATION_FOOTPRINT)

     The factor of 2 in FD_VM_STACK_MAX comes from the fact that the
     current version doesn't handle stack gaps, but still increases r10
     as if it did.

     In total, that's about 100 MiB per frame, but 16 GiB per frame if
     you allocate it densely (that said, if allocating densely, frames
     can overlap, so n frames takes 16 GiB + 86n MiB when n is in [1,
     47]).

     The VM code only requires that base_addr is 16 byte aligned, but
     it's much more sensible from a mmap/TLB perspective to make it 2
     MiB aligned. */
  ulong base_addr[ FD_MAX_INSTRUCTION_STACK_DEPTH ];
};

typedef struct fd_vm_mem fd_vm_mem_t;

#define FD_VM_MEM_ALLOC_CNT   5
#define FD_VM_MEM_LARGEST_IDX 4 /* The index of the largest alloc */
static const struct { ulong offset; ulong sz; int huge; } fd_vm_mem_allocs[ FD_VM_MEM_ALLOC_CNT ] = {
  { .offset=0x000000000UL, .sz = FD_ULONG_ALIGN_UP(FD_RUNTIME_ACC_SZ_MAX,              FD_SHMEM_HUGE_PAGE_SZ),   .huge=1 },
  { .offset=0x100000000UL, .sz = FD_ULONG_ALIGN_UP(FD_RUNTIME_ACC_SZ_MAX,              FD_SHMEM_HUGE_PAGE_SZ),   .huge=1 },
  { .offset=0x200000000UL, .sz = FD_ULONG_ALIGN_UP(2UL*FD_VM_STACK_MAX,                FD_SHMEM_NORMAL_PAGE_SZ), .huge=0 },
  { .offset=0x300000000UL, .sz = FD_ULONG_ALIGN_UP(FD_VM_HEAP_MAX,                     FD_SHMEM_NORMAL_PAGE_SZ), .huge=0 },
  { .offset=0x400000000UL, .sz = FD_ULONG_ALIGN_UP(BPF_LOADER_SERIALIZATION_FOOTPRINT, FD_SHMEM_HUGE_PAGE_SZ),   .huge=1 },
};

static inline ulong fd_vm_mem_align    ( void ) { return alignof(fd_vm_mem_t); }
static inline ulong fd_vm_mem_footprint( void ) { return sizeof (fd_vm_mem_t); }

static inline ulong fd_vm_mem_dense_backing_align( void ) { return 16UL; }
static inline ulong
fd_vm_mem_dense_backing_footprint( void ) {
  /* This depends on the fact that region 4 is the biggest */
  return fd_vm_mem_allocs[FD_VM_MEM_LARGEST_IDX].offset + fd_vm_mem_allocs[FD_VM_MEM_LARGEST_IDX].sz*FD_MAX_INSTRUCTION_STACK_DEPTH;
}


/* fd_vm_mem_new_{mmap,dense} initialize an fd_vm_mem_t AND join the
   caller to it.  m must have the footprint and alignment of an
   fd_vm_mem_t.

   fd_vm_mem_new_mmap acquires memory from the operating system using
   mmap with anonymous pages (huge/normal).  This initializes m using
   a sparse footprint.  The page_cnt functions indicate how many pages
   will be used.

   fd_vm_mem_new_dense uses `backing` as the backing memory, and takes
   ownership of the memory.  `backing` must have the footprint and
   alignment given by fd_vm_mem_dense_backing_{footprint,align}.  This
   initializes m using a dense footprint.

   Although it's possible to make sense of separate new/join calls for
   dense, it doesn't really make sense for the sparse form, so the new
   and join functions are combined.

   On success, returns m.  On failure, logs warning and returns NULL.
   (new_dense cannot fail) */
fd_vm_mem_t * fd_vm_mem_new_mmap ( void * m                 );
fd_vm_mem_t * fd_vm_mem_new_dense( void * m, void * backing );

/* fd_vm_mem_delete_{mmap,dense} perform the normal leave AND delete
   calls.  m must be a valid local join, coming created with the
   corresponding new function.  delete_mmap returns the memory to the
   operating system with munmap. delete_dense also returns the base of
   the backing memory via the non-optional out parameter `backing`. */
/*         */ void * fd_vm_mem_delete_mmap ( fd_vm_mem_t * m );
static inline void * fd_vm_mem_delete_dense( fd_vm_mem_t * m, void * * backing ) { *backing = (void *)m->base_addr[0]; return m; }

/* fd_vm_mem_{gigantic,huge,normal}_page_cnt return the number of pages
   of the respective type allocated by fd_vm_mem_mmap. */
static inline ulong fd_vm_mem_gigantic_page_cnt( void ) { return 0UL; }

static inline ulong
fd_vm_mem_huge_page_cnt( void ) {
  ulong cnt = 0UL;
  for( ulong i=0UL; i<FD_VM_MEM_ALLOC_CNT; i++ )
    if( fd_vm_mem_allocs[ i ].huge ) cnt += fd_vm_mem_allocs[ i ].sz/FD_SHMEM_HUGE_PAGE_SZ;
  cnt *= FD_MAX_INSTRUCTION_STACK_DEPTH;
  return cnt;
}

static inline ulong
fd_vm_mem_normal_page_cnt( void ) {
  ulong cnt = 0UL;
  for( ulong i=0UL; i<FD_VM_MEM_ALLOC_CNT; i++ )
    if( !fd_vm_mem_allocs[ i ].huge ) cnt += fd_vm_mem_allocs[ i ].sz/FD_SHMEM_NORMAL_PAGE_SZ;
  cnt *= FD_MAX_INSTRUCTION_STACK_DEPTH;
  return cnt;
}


/* fd_vm_mem_bpf_serial_region returns the address (haddr) of the base
   of the input region (region 4, also called the BPF serialization
   region) for execution at depth level.  m must be a valid local join
   (of any type).  level must be < FD_MAX_INSTRUCTION_STACK_DEPTH. */
static inline uchar * fd_vm_mem_bpf_serial_region( fd_vm_mem_t * m, ulong level ) { return (uchar *)(m->base_addr[level]+0x400000000UL); }


/* fd_vm_mem_acquire returns the base address (haddr) of the frame of
   memory for execution at depth level, and marks the frame as dirty.  m
   must be a valid local join (of any type), and level must be in [0,
   FD_MAX_INSTRUCTION_STACK_DEPTH).  If the frame at the specifed level
   is dirty, it calls FD_LOG_CRIT.  The base address of the frame is the
   haddr that vaddr 0 would translate to (assuming it is valid). */
static inline ulong
fd_vm_mem_acquire( fd_vm_mem_t * m,
                   ulong         level ) {
  if( FD_UNLIKELY( m->dirty & (1UL<<level) ) ) FD_LOG_CRIT(( "re-acquiring dirty level %lu", level ));
  m->dirty |= (1UL<<level);
  return m->base_addr[level];
}


/* fd_vm_mem_zero_one unconditionally zeros the frame of memory for
   execution at the specified level.
   fd_vm_mem_zero zeros all specified frames of memory that are marked
   as dirty.

   IMPORTANT: These functions only zero the stack and heap regions of
   the frame, because those are the only regions that are supposed to be
   zero-initialized.

   m must be a valid local join of any type.  level must be in [0,
   FD_MAX_INSTRUCTION_STACK_DEPTH), while levels_bitset may be any
   ulong.  Since frames that are not dirty are ignored, it's fine to
   pass ULONG_MAX as levels_bitset to indicate that all dirty frames
   should be cleared.  Both functions update m to mark that the cleared
   frames are no longer dirty. */
static inline void
fd_vm_mem_zero_one( fd_vm_mem_t * m,
                    ulong         level ) {
  /* FIXME: Use dirty set instead */
  memset( (void *)(m->base_addr[level] + fd_vm_mem_allocs[2].offset), '\0', fd_vm_mem_allocs[2].sz );
  memset( (void *)(m->base_addr[level] + fd_vm_mem_allocs[3].offset), '\0', fd_vm_mem_allocs[3].sz );
  m->dirty &= ~(1UL<<level);
}

static inline void
fd_vm_mem_zero( fd_vm_mem_t * m,
                ulong         levels_bitset ) {
  ulong to_clear = levels_bitset & m->dirty;
  while( to_clear ) {
    fd_vm_mem_zero_one( m, (ulong)fd_ulong_find_lsb( to_clear ) );
    to_clear = fd_ulong_pop_lsb( to_clear );
  }
  /* zero_one clears the bit in m */
}

#endif /* HEADER_fd_src_flamenco_vm_fd_vm_mem_h */
