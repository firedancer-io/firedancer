#ifndef HEADER_fd_src_util_wksp_fd_wksp_private_h
#define HEADER_fd_src_util_wksp_fd_wksp_private_h

#include "fd_wksp.h"

/* FD_WKSP_MAGIC is an ideally unique number that specifies the precise
   memory layout of a fd_wksp. */

#define FD_WKSP_MAGIC (0xF17EDA2C3731C590UL) /* F17E=FIRE,DA2C/3R<>DANCER,31/C59<>WKSP,0<>0 --> FIRE DANCER WKSP VERSION 0 */

FD_STATIC_ASSERT( FD_WKSP_ALLOC_ALIGN_MIN==4096UL, update_fd_wksp_magic );

/* FD_WKSP_PRIVATE_HDR_SZ specifies the number of bytes in the fd_wksp_t
   header region. */

#define FD_WKSP_PRIVATE_HDR_SZ (128UL)

/* fd_wksp_private_part_t indicates where a partition of the wksp data
   region starts and whether that partition is active (allocated) or
   inactive (free).  fd_wksp_part_t is cheap and easy to read / write
   atomically. */

typedef ulong fd_wksp_private_part_t;

/* fd_wksp_private specifies the detailed layout of the internals of a
   fd_wksp_t */

FD_STATIC_ASSERT( (6UL*sizeof(ulong)+FD_SHMEM_NAME_MAX)<=FD_WKSP_PRIVATE_HDR_SZ, update_fd_wksp_private_layout );

struct __attribute__((aligned(FD_WKSP_ALLOC_ALIGN_MIN))) fd_wksp_private {
  ulong magic;    /* ==FD_WKSP_MAGIC */
  ulong owner;    /* ULONG_MAX if no process is operating on this workspace or pid of the process currently operating on this
                     workspace.  If pid is dead, the workspace is recoverable */
  ulong part_cnt; /* Number of partitions in the workspace.  0<part_cnt<=part_max.
                     partition i is completely described by ( part[i].active, part[i].lo, part[i+1].hi ).
                     Will be briefly 0 during a reset to aid in recoverability. */
  ulong part_max; /* Maximum number of partitions of the workspace.  Positive.  This will typically be large enough to accommodate
                     a worst case partitioning of the workspace. */
  ulong gaddr_lo; /* (Convenience==part[0       ].off), data region covers bytes [gaddr_lo,gaddr_hi) relative to wksp */
  ulong gaddr_hi; /* (Convenience==part[part_cnt].off), " */

  char  name[ FD_SHMEM_NAME_MAX ]; /* (Convenience) backing fd_shmem region cstr name */

  /* Padding to FD_WKSP_PRIVATE_HDR_SZ alignment */

  fd_wksp_private_part_t part[] __attribute__((aligned(FD_WKSP_PRIVATE_HDR_SZ)));

  /* part has part_max+1 entries.  When the wksp is unlocked (does not
     have an owner), the partitions satisfies the following invariants:
     - Partition offsets are at least aligned to FD_WKSP_ALLOC_ALIGN_MIN
     - Partition offsets are strictly monotonically increasing (e.g.
       part[i+1].gaddr > part[i].gaddr) such that there are no empty
       partitions and partitions are indexed in address order).
     - There are no consecutive inactive partitions (e.g.
       !(!part[i].tag && !part[i+1].tag))
     - part[part_cnt].tag==1 (i.e. "Partition part_cnt" is active to
       indicate there no memory available beyond the end of the
       workspace)
     When a thread is operating on the data structure, the structure
     might temporarily have one or more consecutive inactive partitions
     and one or more "holes" (partitions for which
     part[i].gaddr>=part[j].gaddr for j>i). */

  /* Padding to FD_WKSP_ALLOC_ALIGN_MIN here */

  /* Data region here */
};

/* A fd_alloc_wksp_tag_set_t holds a set of wksp tags */

#define SET_NAME fd_wksp_alloc_tag_set
#define SET_MAX  (FD_WKSP_ALLOC_TAG_MAX+1UL) /* Yes, +1 */
#include "../tmpl/fd_set.c"

FD_PROTOTYPES_BEGIN

/* fd_wksp_private_part forms a fd_wksp_private_part_t from the tuple
   (tag,gaddr).  Note that since
   FD_WKSP_ALLOC_TAG_MAX<FD_WKSP_ALLOC_ALIGN_MIN, we have room in the
   least significant bits to store the tag and since
   FD_WKSP_ALLOC_TAG_MAX is an integer power of two minus 1, we can use
   it as a bit mask. */

static inline fd_wksp_private_part_t
fd_wksp_private_part( ulong tag,      /* tag assumed in [0,FD_WKSP_ALLOC_TAG_MAX].  0 indicates inactive partition. */
                      ulong gaddr ) { /* gaddr assumed aligned at least FD_WKSP_ALLOC_ALIGN_MIN */
  return gaddr | tag;
}

static inline ulong fd_wksp_private_part_tag  ( fd_wksp_private_part_t part ) { return part &  FD_WKSP_ALLOC_TAG_MAX; }
static inline ulong fd_wksp_private_part_gaddr( fd_wksp_private_part_t part ) { return part & ~FD_WKSP_ALLOC_TAG_MAX; }

/* fd_wksp_alloc_tag_set_unpack inserts all tags in [tag_lo,tag_hi] in
   the tag array into the given tag set.  Assumes set is valid,
   tag_lo<=tag_hi<=FD_WKSP_ALLOC_TAG_MAX and tag / tag_cnt are valid.
   Returns the number of actual tags inserted into set. */

static inline ulong
fd_wksp_alloc_tag_set_unpack( fd_wksp_alloc_tag_set_t * set,
                              ulong                     tag_lo,
                              ulong                     tag_hi,
                              ulong const *             tag,        /* Indexed [0,tag_cnt) */
                              ulong                     tag_cnt ) {
  ulong cnt = 0UL;
  for( ulong tag_idx=0UL; tag_idx<tag_cnt; tag_idx++ ) {
    ulong t = tag[ tag_idx ];
    if( FD_LIKELY( (tag_lo<=t) & (t<=tag_hi) ) ) {
      fd_wksp_alloc_tag_set_insert( set, t );
      cnt++;
    }
  }
  return cnt;
}

/* fd_wksp_private_lock locks the wksp for use by the caller.  Will
   recover from other processes that locked the workspace and died while
   holding the lock.  Assumes the caller does not already have the lock. */

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

#endif /* HEADER_fd_src_util_wksp_fd_wksp_private_h */
