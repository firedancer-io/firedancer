#ifndef HEADER_fd_src_util_wksp_fd_wksp_private_h
#define HEADER_fd_src_util_wksp_fd_wksp_private_h

#include "fd_wksp.h"

#if FD_HAS_HOSTED && FD_HAS_X86

/* FD_WKSP_MAGIC is an ideally unique number that specifies the precise
   memory layout of a fd_wksp. */

#define FD_WKSP_MAGIC (0xF17EDA2C3731C590UL) /* F17E=FIRE,DA2C/3R<>DANCER,31/C59<>WKSP,0<>0 --> FIRE DANCER WKSP VERSION 0 */

FD_STATIC_ASSERT( FD_WKSP_ALLOC_ALIGN_MIN==4096UL, update_fd_wksp_magic );

/* FD_WKSP_PRIVATE_HDR_SZ specifies the number of bytes in the fd_wksp_t
   header region. */

#define FD_WKSP_PRIVATE_HDR_SZ 128UL

/* fd_wksp_private_part_t indicates where a partition of the wksp data
   region starts and whether that partition is active (allocated) or
   inactive (partition).  fd_wksp_part_t is cheap and easy to read /
   write atomically. */

typedef ulong fd_wksp_private_part_t;

/* fd_wksp_private specifies the detailed layout of the internals of a
   fd_wksp_t */

FD_STATIC_ASSERT( (6UL*sizeof(ulong)+FD_SHMEM_NAME_MAX)<=FD_WKSP_PRIVATE_HDR_SZ, update_fd_wksp_private_layout );

struct __attribute__((aligned(FD_WKSP_ALLOC_ALIGN_MIN))) fd_wksp_private {
  ulong magic;    /* ==FD_WKSP_MAGIC */
  ulong owner;    /* ULONG_MAX if no process is operating on this workspace or pid of the process currently operating on this
                     workspace.  If pid is dead, the workspace is recoverable */
  ulong part_cnt; /* Number of partitions in the workspace.  0<part_cnt<=part_max.
                     partition i is completely described by ( part[i].active, part[i].lo, part[i+1].hi ) */
  ulong part_max; /* Maximum number of partitions of the workspace.  Positive.  In practice, this will typically be large
                     enough to accommodate a worst case partitioning of the workspace. */
  ulong gaddr_lo; /* (Convenience==part[0       ].off), data region covers bytes [gaddr_lo,gaddr_hi) relative to wksp */
  ulong gaddr_hi; /* (Convenience==part[part_cnt].off), " */

  char  name[ FD_SHMEM_NAME_MAX ]; /* (Convenience) backing fd_shmem region cstr name */

  uchar reserved[ FD_WKSP_PRIVATE_HDR_SZ - 6UL*sizeof(ulong) - FD_SHMEM_NAME_MAX ]; /* header padding */

  fd_wksp_private_part_t part[2]; /* Actually part_max+1 entries.  When the wksp is unlocked (does not have an owner), the
                                     partitions satisfies the following invariants:
                                     - Partition offsets are at least aligned to FD_WKSP_ALLOC_ALIGN_MIN
                                     - Partition offsets are strictly monotonically increasing (e.g. part[i+1].off > part[i].off)
                                       such that there are no empty partitions and partitions are indexed in address order).
                                     - There are no consecutive inactive partitions (e.g. !(!part[i].active && !part[i+1].active))
                                     - part[part_cnt].active==1 (i.e. "Partition part_cnt" is active to indicate there no memory
                                       available beyond the end of the workspace)
                                     When a thread is operating on the data structure, the structure might temporarily have one or
                                     more consecutive inactive partitions and one or more "holes" (partitions for which
                                     part[i].off>=part[j].off for j>i). */
  /* Remaining part_max-1 entries */
  /* Padding to FD_WKSP_ALLOC_ALIGN_MIN here */
  /* Data region here */
};

FD_PROTOTYPES_BEGIN

/* fd_wksp_private_part forms a fd_wksp_private_part_t from the tuple
   (active,gaddr) */

static inline fd_wksp_private_part_t
fd_wksp_private_part( int   active,   /* active assumed in [0,1] */
                      ulong gaddr ) { /* gaddr assumed aligned at least FD_WKSP_ALLOC_ALIGN_MIN */
  /* Since FD_WKSP_ALLOC_ALIGN_MIN is an integral power of 2 >= 2, we
     have room in bit 0 of gaddr to store the active bit. */
  return gaddr | (ulong)active;
}

static inline int   fd_wksp_private_part_active( fd_wksp_private_part_t part ) { return (int)(part & 1UL); }
static inline ulong fd_wksp_private_part_gaddr ( fd_wksp_private_part_t part ) { return part & ~1UL; }

/* fd_wksp_private_lock locks the wksp for use by the caller.  Will
   recover from from other processes that locked the workspace and died
   while holding the lock.  Assumes the caller does not already have the
   lock. */

void
fd_wksp_private_lock( fd_wksp_t * wksp );

/* fd_wksp_private_unlock unlocks the wksp for use by the caller.
   Assumes the caller has the lock. */

static inline void
fd_wksp_private_unlock( fd_wksp_t * wksp ) {
  FD_COMPILER_MFENCE();
  FD_VOLATILE( wksp->owner ) = ULONG_MAX;
  FD_COMPILER_MFENCE();
}

FD_PROTOTYPES_END

#endif

#endif /* HEADER_fd_src_util_wksp_fd_wksp_private_h */
