#ifndef HEADER_fd_src_util_wksp_fd_wksp_private_h
#define HEADER_fd_src_util_wksp_fd_wksp_private_h

#include "fd_wksp.h"

/* If FD_WKSP_LOCK_RECLAIM==0, do not try to recover the lock from
   dead processes.  This is useful, for example, if we know that the
   lock will not get acquired by another process, or that if another
   acquiring process dies that all potential users will get exited.  It
   prevents a syscall on various common workspace paths (eg, alloc). */

#ifndef FD_WKSP_LOCK_RECLAIM
#define FD_WKSP_LOCK_RECLAIM 0
#endif

/* FD_WKSP_PRIVATE_PINFO_IDX_NULL is the pinfo index value used to
   indicate NULL */

#define FD_WKSP_PRIVATE_PINFO_IDX_NULL ((ulong)UINT_MAX)

/* A fd_wksp_private_pinfo_t specifies details about a partition in a
   workspace and its relationship to other partitions in that workspace.

   FD_WKSP_PRIVATE_PINFO_ALIGN is an integer power of 2 and
   FD_WKSP_PRIVATE_PINFO_FOOTPRINT will be a multiple of align.

   If a partition is not idle:

   - [gaddr_lo,gaddr_hi) specify the range of offsets covered by this
     partition.

       wksp_gaddr_lo <= gaddr_lo < gaddr_hi <= wksp_gaddr_hi

     such that partitions always have at least 1 byte and are contained
     within the workspace's data region.

   - tag==0 indicates this partition is space in the workspace free
     for use and the partition is in the free treap, fast findable by
     its size.  Otherwise, this partition is allocated and the partition
     is in the used treap, fast O(1) findable by any in range gaddr.

   - prev_cidx, next_cidx give the index (in compressed form) of the
     previous / next partition if present or IDX_NULL if this is the
     workspace partition head / tail partition (in which case gaddr_lo /
     gaddr_hi will be wksp->gaddr_lo / wksp->gaddr_hi).  That is, for
     partition idx where idx is in [0,wksp->part_max):

       ulong prev_idx = fd_wksp_private_pinfo_idx( pinfo[ idx ].prev_cidx );
       if( fd_wksp_private_pinfo_idx_is_null( prev_idx ) ) {
         ... at this point:
         ...   idx == fd_wksp_private_pinfo_idx( wksp->part_head_cidx ) );
         ...   pinfo[ idx ].gaddr_lo == wksp->gaddr_lo );
       } else {
         ... at this point:
         ...   idx ==_fd_wksp_private_pinfo_idx( pinfo[ prev_idx ].next_cidx );
         ...   pinfo[ idx ].gaddr_lo == pinfo[ prev_idx ].gaddr_hi;
       }

     and:

       ulong next_idx = fd_wksp_private_pinfo_idx( pinfo[ idx ].next_cidx );
       if( fd_wksp_private_pinfo_idx_is_null( next_idx ) ) {
         ... at this point:
         ...   idx == fd_wksp_private_pinfo_idx( wksp->part_tail_cidx ) );
         ...   pinfo[ idx ].gaddr_hi == wksp->gaddr_hi );
       } else {
         ... at this point:
         ...   idx ==_fd_wksp_private_pinfo_idx( pinfo[ next_idx ].prev_cidx );
         ...   pinfo[ idx ].gaddr_hi == pinfo[ next_idx ].gaddr_lo;
       }

   - If partition idx is in the used treap, {left,right}_cidx specify
     the partition indices of the root of the left and right subtrees.

     The used treap obeys the binary search tree property that all
     partitions in the left/right subtree (if any) cover a range of
     offsets strictly lower/higher than range covered by idx.

     parent_cidx specifies idx's parent tree (if any).  If idx is the
     wksp used tree root, parent_cidx will specify IDX_NULL and
     wksp->part_used_cidx will specify idx.

     The used treap also obeys the heap property to make it well
     balanced on average.  Specifically, the idx's parent's heap
     priority will be at least idx's heap priority.

     in_same will be 0 and same_cidx will specify IDX_NULL as no used
     partitions can overlap.

   - If partition idx is in the free treap, if partition idx is not
     in a list of same sized partitions, in_same will be 0 and
     {left,right}_cidx specify the partition indices of the root of the
     left and right subtrees.

     The free treap obeys the binary search tree property that all
     partitions in the left/right subtree (if any) have partition sizes
     strictly lower/higher than partition idx's size.

     parent_cidx specifies idx's parent tree (if any).  If idx is the
     wksp free tree root, parent_cidx will specify IDX_NULL and
     wksp->part_free_cidx will specify idx.

     The free treap also obeys the heap property to make it well
     balanced on average.  Specifically, the idx's parent's heap
     priority will be at least idx's heap priority.

     If there are additional partitions of the same size to partition
     idx, same_cidx will refer to the next partition of the same size.

     If partition idx is in a list of same sized partitions, in_same
     will be 1 and parent_cidx / same_cidx will specify the prev / next
     index of additional partitions of the same size.  same_cidx will
     specify IDX_NULL if no more.

   - heap_prio is a random value used as described above.

   - stack_cidx and cycle_tag are for internal use */

/* TODO: Consider align 32/ footprint 96 without compressed indices if
   ever needing more than ~4B partitions. */

#define FD_WKSP_PRIVATE_PINFO_ALIGN     (64UL) /* At most FD_WKSP_ALIGN */
#define FD_WKSP_PRIVATE_PINFO_FOOTPRINT (64UL)

struct __attribute__((aligned(FD_WKSP_PRIVATE_PINFO_ALIGN))) fd_wksp_private_pinfo {
  ulong gaddr_lo;       /* If in idle stack, 0 */
  ulong gaddr_hi;       /* ",                0 */
  ulong tag;            /* ",                0 */
  uint  heap_prio : 31; /* 30 bit priority and 1 bit free to use for infinite priority bulk tree ops */
  uint  in_same   :  1; /* 1 if in a same list and 0 otherwise */
  uint  prev_cidx;      /* ",                fd_wksp_private_pinfo_cidx( FD_WKSP_INFO_IDX_NULL ) */
  uint  next_cidx;      /* ",                fd_wksp_private_pinfo_cidx( FD_WKSP_INFO_IDX_NULL ) */
  uint  left_cidx;      /* ",                fd_wksp_private_pinfo_cidx( FD_WKSP_INFO_IDX_NULL ) */
  uint  right_cidx;     /* ",                fd_wksp_private_pinfo_cidx( FD_WKSP_INFO_IDX_NULL ) */
  uint  parent_cidx;    /* ",                cidx of next idle or fd_wksp_private_pinfo_cidx( FD_WKSP_INFO_IDX_NULL ) if no more */
  uint  same_cidx;      /* ",                fd_wksp_private_pinfo_cidx( FD_WKSP_INFO_IDX_NULL ) */
  uint  stack_cidx;     /* internal use */
  ulong cycle_tag;      /* internal use */
};

typedef struct fd_wksp_private_pinfo fd_wksp_private_pinfo_t;

/* FD_WKSP_MAGIC is an ideally unique number that specifies the precise
   memory layout of a fd_wksp. */

#define FD_WKSP_MAGIC (0xF17EDA2C3731C591UL) /* F17E=FIRE,DA2C/3R<>DANCER,31/C59<>WKSP,0<>0 --> FIRE DANCER WKSP VERSION 1 */

/* fd_wksp_private specifies the detailed layout of the internals of a
   fd_wksp_t */

struct fd_wksp_private {

  /* This point is FD_WKSP_ALIGN aligned */

  /* This fields are static and mostly in the first cache line */

  ulong magic;                     /* ==FD_WKSP_MAGIC */
  ulong part_max;                  /* Max wksp partitions */
  ulong data_max;                  /* Data region */
  ulong gaddr_lo;                  /* ==fd_wksp_private_data_off( part_max ), data region covers offsets [gaddr_lo,gaddr_hi) */
  ulong gaddr_hi;                  /* ==gaddr_lo + data_max,                  offset gaddr_hi is to 1 byte footer */
  char  name[ FD_SHMEM_NAME_MAX ]; /* (Convenience) backing fd_shmem region cstr name */
  uint  seed;                      /* Heap priority random number seed, arbitrary */

  /* These fields are dynamic and in the adjacent cache line */

  uint  idle_top_cidx;             /* Stack of partition infos not in use, parent_idx is next pointer */
  uint  part_head_cidx;            /* Index for info about the leftmost partition */
  uint  part_tail_cidx;            /* Index for info about the rightmost partition */
  uint  part_used_cidx;            /* Treap of partitions that are currently used (tag!=0), searchable by gaddr */
  uint  part_free_cidx;            /* Treap of partitions that are currently free (tag==0), searchable by size */
  ulong cycle_tag;                 /* Used for cycle detection */
  ulong owner;                     /* thread group id of the owner or NULL otherwise */

  /* IMPORTANT!  The "single-source-of-truth" for what is currently
     used (and its tags) is the set of non-zero tagged partitions in the
     partition info array.  The idle stack, partition list, used treap
     and free treap are auxiliary data structuring that can be
     reconstructed at any time from this single source of truth.

     Conversely, if there accidental or deliberate data corruption of
     the wksp metadata resulting in a conflict between what is stored
     in the partition info array and the auxiliary data structures,
     the partition info array governs. */

  /* Padding to FD_WKSP_PRIVATE_PINFO_ALIGN here */

  /* part_max pinfo here */
  /* data_max byte data region here */
  /* 1 footer byte here */
  /* Padding to FD_WKSP_ALIGN here */
};

FD_PROTOTYPES_BEGIN

/* fd_wksp_private_pinfo_sz returns the size of a partition in bytes.
   Assumes pinfo points to the pinfo of a partition in a current local
   join.  Will be positive. */

FD_FN_PURE static inline ulong
fd_wksp_private_pinfo_sz( fd_wksp_private_pinfo_t const * pinfo ) {
  return pinfo->gaddr_hi - pinfo->gaddr_lo;
}

/* fd_wksp_private_{part,data}_off return the wksp offset of the
   pinfo array and the data region.  data_off assumes part_max is a
   value that will not overflow. */

FD_FN_CONST static inline ulong
fd_wksp_private_pinfo_off( void ) {
  return 128UL; /* fd_ulong_align_up( sizeof(fd_wksp_t), FD_WKSP_PRIVATE_PINFO_ALIGN ); */
}

FD_FN_CONST static inline ulong
fd_wksp_private_data_off( ulong part_max ) {
  return fd_wksp_private_pinfo_off() + part_max*sizeof(fd_wksp_private_pinfo_t);
}

/* fd_wksp_private_pinfo returns the location of wksp pinfo array in the
   caller's address space.  Assumes wksp is a current local join.
   fd_wksp_private_pinfo_const is a const-correct version. */

FD_FN_CONST static inline fd_wksp_private_pinfo_t *
fd_wksp_private_pinfo( fd_wksp_t * wksp ) {
  return (fd_wksp_private_pinfo_t *)(((ulong)wksp) + fd_wksp_private_pinfo_off());
}

FD_FN_CONST static inline fd_wksp_private_pinfo_t const *
fd_wksp_private_pinfo_const( fd_wksp_t const * wksp ) {
  return (fd_wksp_private_pinfo_t const *)(((ulong)wksp) + fd_wksp_private_pinfo_off());
}

/* fd_wksp_private_pinfo_{cidx,idx} compresses / uncompresses a pinfo index */

static inline uint  fd_wksp_private_pinfo_cidx( ulong idx  ) { return (uint) idx;  }
static inline ulong fd_wksp_private_pinfo_idx ( uint  cidx ) { return (ulong)cidx; }

/* fd_wksp_private_pinfo_idx_is_null returns 1 if idx is
   FD_WKSP_PRIVATE_PINFO_IDX_NULL and 0 otherwise */

static inline int fd_wksp_private_pinfo_idx_is_null( ulong idx ) { return idx==FD_WKSP_PRIVATE_PINFO_IDX_NULL; }

/* pinfo idle stack APIs **********************************************/

/* fd_wksp_private_idle_stack_is_empty returns 1 if there are no idle
   partitions and 0 otherwise.  Also returns 1 if corruption is
   detected.  Assumes wksp is a current local join. */

static inline int
fd_wksp_private_idle_stack_is_empty( fd_wksp_t * wksp ) {
  return fd_wksp_private_pinfo_idx( wksp->idle_top_cidx ) >= wksp->part_max;
}

/* fd_wksp_private_idle_stack_pop pops an idle partition off wksp's idle
   stack.  Assumes the caller knows idle stack is not empty.  The caller
   is promised that the popped partition has [gaddr_lo,gaddr_hi) = [0,0)
   tag 0, {prev, next, left, right, same, parent}_cidx specify IDX_NULL.
   Further, heap_prio should have been assigned a random value.
   stack_idx and cycle_tag are for internal use. */

static inline ulong                                                 /* Assumes in [0,part_max) */
fd_wksp_private_idle_stack_pop( fd_wksp_t *               wksp,     /* Assumes current local join */
                                fd_wksp_private_pinfo_t * pinfo ) { /* == fd_wksp_private_pinfo( wksp ) */
  ulong i = fd_wksp_private_pinfo_idx( wksp->idle_top_cidx );
# if FD_HAS_DEEPASAN
  fd_asan_unpoison( &pinfo[ i ], FD_WKSP_PRIVATE_PINFO_FOOTPRINT );
# endif
  wksp->idle_top_cidx = pinfo[ i ].parent_cidx;
  pinfo[ i ].parent_cidx = fd_wksp_private_pinfo_cidx( FD_WKSP_PRIVATE_PINFO_IDX_NULL );
  return i;
}

/* fd_wksp_private_idle_stack_push pushes partition i onto the idle
   stack.  Assumes the caller knows i is not currently in the idle
   stack, partitioning, used treap or free treap. */

static inline void
fd_wksp_private_idle_stack_push( ulong                     i,        /* Assumes in [0,part_max) */
                                 fd_wksp_t *               wksp,     /* Assumes current local join */
                                 fd_wksp_private_pinfo_t * pinfo ) { /* == fd_wksp_private_pinfo( wksp ) */
  pinfo[ i ].gaddr_lo    = 0UL;
  pinfo[ i ].gaddr_hi    = 0UL;
  pinfo[ i ].tag         = 0U;
  pinfo[ i ].in_same     = 0U;
  pinfo[ i ].prev_cidx   = fd_wksp_private_pinfo_cidx( FD_WKSP_PRIVATE_PINFO_IDX_NULL );
  pinfo[ i ].next_cidx   = fd_wksp_private_pinfo_cidx( FD_WKSP_PRIVATE_PINFO_IDX_NULL );
  pinfo[ i ].left_cidx   = fd_wksp_private_pinfo_cidx( FD_WKSP_PRIVATE_PINFO_IDX_NULL );
  pinfo[ i ].right_cidx  = fd_wksp_private_pinfo_cidx( FD_WKSP_PRIVATE_PINFO_IDX_NULL );
  pinfo[ i ].same_cidx   = fd_wksp_private_pinfo_cidx( FD_WKSP_PRIVATE_PINFO_IDX_NULL );
  pinfo[ i ].parent_cidx = wksp->idle_top_cidx;
  wksp->idle_top_cidx = fd_wksp_private_pinfo_cidx( i );

# if FD_HAS_DEEPASAN
  fd_asan_poison( &pinfo[ i ], FD_WKSP_PRIVATE_PINFO_FOOTPRINT );
# endif
}

/* pinfo used treap APIs **********************************************/

/* fd_wksp_private_used_treap_query queries wksp's used treap for the
   used partition that holds gaddr.  On success, returns the requested
   partition idx, in [0,part_max), and, on failure, returns IDX_NULL.
   Reasons for failure include gaddr is not in a used partition and
   internal treap corruption detected.  Might consume a wksp cycle tag
   and clobber partition cycle tags.  Reasonably fast O(lg N) where N is
   the number of used partitions. */

ulong
fd_wksp_private_used_treap_query( ulong                     gaddr,
                                  fd_wksp_t *               wksp,
                                  fd_wksp_private_pinfo_t * pinfo );

/* fd_wksp_private_used_treap_insert inserts partition n into wksp's
   used treap.  Assumes n is not in the idle stack, used treap or free
   treap.  Does not care if n is in the partitioning or not.  Reasonably
   fast O(lg N) where N is the number of used partitions.

   Partition n should have [gaddr_lo,gaddr_hi) and heap_prio initialized
   on entry (heap_prio should be a random value).  tag need not be
   initialized but it is assumed that the caller will set the tag to its
   final value on success to make the partition officially used.  This
   will initialize {in_same, left, right, same, parent}_cidx.  This will
   ignore {prev,next}_cidx.  This might consume a wksp cycle tag and
   clobber partition stack_cidx and cycle_tag fields.

   Returns FD_WKSP_SUCCESS (zero) on success and a FD_WKSP_ERR_*
   (negative) on failure (logs details for failure).  Reasons for
   failure include n is not in [0,part_max), n's range is not in wksp
   data region, n was detected as already inserted (this detection is
   not guaranteed), treap internal connectivity issues were detected
   (complete detection not guaranteed), and n overlaps with at least one
   element already inserted into the treap.

   On failure n and the treap itself were not modified (except possibly
   clobbering of stack_cidx and cycle_tag).  Note that failure reasons
   are either user error or memory corruption.  This cannot fail in
   normal operating circumstances. */

int
fd_wksp_private_used_treap_insert( ulong                     n,
                                   fd_wksp_t *               wksp,    /* Assumes current local join */
                                   fd_wksp_private_pinfo_t * pinfo ); /* == fd_wksp_private_pinfo( wksp ) */

/* fd_wksp_private_used_treap_remove removes partition d from wksp's
   used treap.  Assumes d in the used treap, not in the free treap, not
   in the idle stack.  Does not care if d is in the partitioning.
   Reasonably fast O(lg N) where N is the number of used partitions.
   This might consume a wksp cycle tag and clobber partition stack_cidx
   and cycle_tag fields.

   Returns FD_WKSP_SUCCESS (zero) on success and a FD_WKSP_ERR_*
   (negative) on failure (logs details for failure).  Reasons for
   failure include d is not in [0,part_max) and treap internal
   connectivity issues were detected (complete detection not
   guaranteed).

   Note that failure reasons are either user error or memory corruption.
   This cannot fail in normal operating circumstances. */

int
fd_wksp_private_used_treap_remove( ulong                     d,
                                   fd_wksp_t *               wksp,    /* Assumes current local join */
                                   fd_wksp_private_pinfo_t * pinfo ); /* == fd_wksp_private_pinfo( wksp ) */

/* pinfo free treap APIs **********************************************/

/* fd_wksp_private_free_treap_query queries wksp's free treap for the
   smallest partition of at least sz.  On success, returns the index of
   a partition in the free treap suitable for sz, in [0,part_max), and,
   on failure, returns IDX_NULL.  Reasons for failure include sz zero,
   sz is larger than any free partition, and internal treap corruption
   was detected.  Might consume a wksp cycle tag and clobber partition
   cycle tags.  Reasonably fast O(lg N) where N is the number of used
   partitions. */

ulong
fd_wksp_private_free_treap_query( ulong                     sz,
                                  fd_wksp_t *               wksp,    /* Assumes current local join */
                                  fd_wksp_private_pinfo_t * pinfo ); /* == fd_wksp_private_pinfo( wksp ) */

/* fd_wksp_private_free_treap_insert inserts partition n into wksp's
   free treap.  Assumes n is not in the idle stack, used treap or free
   treap.  Does not care if n is in the partitioning or not.  Reasonably
   fast O(lg N) where N is the number of partitions in the free treap.

   Partition n should have [gaddr_lo,gaddr_hi) and heap_prio initialized
   on entry (heap_prio should be a random value).  tag need not be
   initialized but it is assumed that the caller will zero the tag
   beforehand to make the partition officially free.  This will
   initialize {in_same, left, right, same, parent}_cidx.  This will
   ignore {prev,next}_cidx.  This might consume a wksp cycle tag and
   clobber the partition stack_cidx and cycle_tag fields.

   Returns FD_WKSP_SUCCESS (zero) on success and a FD_WKSP_ERR_*
   (negative) on failure (logs details for failure).  Reasons for
   failure include n is not in [0,part_max), n's range is not in wksp
   data region, n's tag is not zero, n was detected as already inserted
   (this detection is not guaranteed), treap internal connectivity
   issues were detected (complete detection not guaranteed).

   If n's size exactly matches the size of partition already in the
   treap, n will be pushed onto that partition's same stack rather than
   inserted into the treap.

   On failure n and the treap itself were not modified (except possibly
   clobbering of stack_cidx and cycle_tag).  Note that failures reasons
   are either user error or memory corruption.  This has no failures in
   normal operating circumstances. */

int
fd_wksp_private_free_treap_insert( ulong                     n,
                                   fd_wksp_t *               wksp,    /* Assumes current local join */
                                   fd_wksp_private_pinfo_t * pinfo ); /* == fd_wksp_private_pinfo( wksp ) */

/* fd_wksp_private_free_treap_same_is_empty returns 1 if the same list
   for d is empty and 0 if not.  Returns 1 if corruption in detected.
   Assumes d is in the free treap. */

static inline int
fd_wksp_private_free_treap_same_is_empty( ulong                     d,
                                          fd_wksp_t *               wksp,     /* Assumes current local join */
                                          fd_wksp_private_pinfo_t * pinfo ) { /* == fd_wksp_private_pinfo( wksp ) */
  ulong part_max = wksp->part_max;
  return fd_wksp_private_pinfo_idx( pinfo[ d ].same_cidx )>=part_max;
}

/* fd_wksp_private_free_treap_same_remove removes the first partition
   from d's same list.  Assumes the caller knows d's same list is not
   empty.  The caller is promised that returned partition has the same
   size as d. */

static inline ulong
fd_wksp_private_free_treap_same_remove( ulong                     d,
                                        fd_wksp_t *               wksp,     /* Assumes current local join */
                                        fd_wksp_private_pinfo_t * pinfo ) { /* == fd_wksp_private_pinfo( wksp ) */
  ulong part_max = wksp->part_max;
  ulong i = fd_wksp_private_pinfo_idx( pinfo[ d ].same_cidx );
  ulong j = fd_wksp_private_pinfo_idx( pinfo[ i ].same_cidx );
  /**/             pinfo[ d ].same_cidx = fd_wksp_private_pinfo_cidx( j );
  if( j<part_max ) pinfo[ j ].parent_cidx = fd_wksp_private_pinfo_cidx( d );
  pinfo[ i ].in_same     = 0U;
  pinfo[ i ].same_cidx   = fd_wksp_private_pinfo_cidx( FD_WKSP_PRIVATE_PINFO_IDX_NULL );
  pinfo[ i ].parent_cidx = fd_wksp_private_pinfo_cidx( FD_WKSP_PRIVATE_PINFO_IDX_NULL );
  return i;
}

/* fd_wksp_private_free_treap_remove removes partition d from wksp's
   free treap.  Assumes d in the free treap, not in the used treap, not
   in the idle stack.  Does not care if d is in the partitioning.
   Reasonably fast O(lg N) where N is the number of free partitions.
   This might consume a wksp cycle tag and clobber partition stack_cidx
   and cycle_tag fields.  There is an edge case where d's can be swapped
   with another same sized partition.

   Returns FD_WKSP_SUCCESS (zero) on success and a FD_WKSP_ERR_*
   (negative) on failure (logs details for failure).  Reasons for
   failure include d is not in [0,part_max) and treap internal
   connectivity issues were detected (complete detection not
   guaranteed).

   Note that failure reasons are either user error or memory corruption.
   This cannot fail in normal operating circumstances. */

int
fd_wksp_private_free_treap_remove( ulong                     d,
                                   fd_wksp_t *               wksp,    /* Assumes current local join */
                                   fd_wksp_private_pinfo_t * pinfo ); /* == fd_wksp_private_pinfo( wksp ) */

/* private admin APIs *************************************************/

/* fd_wksp_private_lock locks wksp.  Assumes wksp is a current local
   join.  If wksp is already locked, this will wait for the caller.  If
   this detects that the caller died while holding the lock, it will try
   to steal the lock from the dead caller and cleanup any incomplete
   operation the caller was doing.  Returns FD_WKSP_SUCCESS (0) if the
   lock was acquired or FD_WKSP_ERR_CORRUPT if the lock could not be
   obtained because memory corruption was detected while trying to
   recover from a dead caller that corrupted the wksp memory. */

int
fd_wksp_private_lock( fd_wksp_t * wksp );

/* fd_wksp_private_unlock unlocks a locked wksp.  Assumes wksp is a
   current local join and the caller has the lock */

static inline void
fd_wksp_private_unlock( fd_wksp_t * wksp ) {
  FD_COMPILER_MFENCE();
  FD_VOLATILE( wksp->owner ) = ULONG_MAX;
  FD_COMPILER_MFENCE();
}

/* private checkpt/restore APIs ***************************************/
/* FIXME: MOVE THIS TO PUBLIC HEADER? */

/* FD_WKSP_CHECKPT_{V1,V2}_{BINFO,UINFO}_MAX give the maximum byte size
   (including the terminating '\0') of a decompressed {v1,v2} checkpt
   {build,user} info cstr. */

#define FD_WKSP_CHECKPT_V1_BINFO_MAX (16384UL)
#define FD_WKSP_CHECKPT_V1_UINFO_MAX (16384UL)

#define FD_WKSP_CHECKPT_V2_BINFO_MAX (16384UL)
#define FD_WKSP_CHECKPT_V2_UINFO_MAX (16384UL)

/* A fd_wksp_checkpt_v2_hdr_t gives the byte layout of frame 0 of a wksp
   v2 checkpt.  This frame contains the style, compression algo used for
   the info, cgroup and appendix frames and fd_wksp_preview information
   uncompressed. */

struct fd_wksp_checkpt_v2_hdr {
  ulong magic;                     /* Must be first, ==FD_WKSP_MAGIC */
  int   style;                     /* Must be second, wksp checkpt style */
  int   frame_style_compressed;    /* frame style used for compressed frames */
  uint  reserved;                  /* header padding */
  char  name[ FD_SHMEM_NAME_MAX ]; /* cstr holding the original wksp name (note: FD_SHMEM_NAME_MAX==FD_LOG_NAME_MAX==40) */
  uint  seed;                      /* wksp seed when checkpointed (probably same used to construct) */
  ulong part_max;                  /* part_max used to construct the wksp */
  ulong data_max;                  /* data_max used to construct the wksp */
};

typedef struct fd_wksp_checkpt_v2_hdr fd_wksp_checkpt_v2_hdr_t;

/* A fd_wksp_checkpt_v2_info_t gives the byte layout of frame 1 of a
   wksp v2 checkpt.  frame 1 immediately follows frame 0 and this frame
   contains the info structure followed compactly by the corresponding
   cstr (including the terminating '\0') stored consecutively in the
   same order.  The size fields indicate the buffer layout.  This frame
   is compressed according hdr/ftr specification. */

struct fd_wksp_checkpt_v2_info {
  ulong mode;
  long  wallclock;
  ulong app_id;
  ulong thread_id;
  ulong host_id;
  ulong cpu_id;
  ulong group_id;
  ulong tid;
  ulong user_id;
  /* FIXME: CONSIDER MAKING THESE ALL UCHAR / USHORT / 4 BYTE RESERVED */
  ulong sz_app;    /* in [1,FD_LOG_NAME_MAX ~ 40B] */
  ulong sz_thread; /* " */
  ulong sz_host;   /* " */
  ulong sz_cpu;    /* " */
  ulong sz_group;  /* " */
  ulong sz_user;   /* " */
  ulong sz_path;   /* in [1,PATH_MAX ~ 4KiB] */
  ulong sz_binfo;  /* in [1,FD_WKSP_CHECKPT_V2_BINFO_MAX ~ 16KiB] */
  ulong sz_uinfo;  /* in [1,FD_WKSP_CHECKPT_V2_UINFO_MAX ~ 16KiB] */
};

typedef struct fd_wksp_checkpt_v2_info fd_wksp_checkpt_v2_info_t;

/* A v2 info frame is followed by zero or more volumes.  A volume
   consists of zero or more cgroup frames and an appendix frame.
   Volumes are followed by a frame with a footer command and then an
   uncompressed footer frame.

   A cgroup frame starts with a zero or more meta commands that describe
   the allocations it contains followed by a data command that indicates
   the cgroup data section follows.

   An appendix frame starts with an appendix command, giving the number
   of cgroup frames it covers and the offset to the previous appendix
   frame (0 if the first appendix frame).  This is followed by a ulong
   array with checkpt offsets to those cgroup frames followed a ulong
   array with the number of allocations in each cgroup frame.  An
   appendix covers all cgroup frames between it and the previous
   appendix frame (or info frame if the first appendix).

   The last volume is followed by a compressed frame with a sole volumes
   command.  The volumes command gives the offset of the appendix of the
   last volume (or 0 if there are no volumes).  (This allows the final
   frame to be uncompressed while all the volumes can be compressed.)

   An uncompressed footer frame follows indicating the v2 checkpt is
   done.  The command gives the total number of cgroup frames in the
   checkpt and the offset to the last volume's appendix (or 0 if no
   volumes).

   A fd_wksp_checkpt_v2_cmd_t supports writing an arbitrarily large
   checkpt single pass with only small upfront bounded allocation while
   supporting both streaming and parallel restore of those frames. */

union fd_wksp_checkpt_v2_cmd {
  struct { ulong tag; /* > 0 */ ulong gaddr_lo;                     ulong gaddr_hi;                    } meta;
  struct { ulong tag; /* ==0 */ ulong cgroup_cnt; /* ==ULONG_MAX */ ulong frame_off; /* ==ULONG_MAX */ } data;
  struct { ulong tag; /* ==0 */ ulong cgroup_cnt; /* < ULONG_MAX */ ulong frame_off; /* < ULONG_MAX */ } appendix;
  struct { ulong tag; /* ==0 */ ulong cgroup_cnt; /* ==ULONG_MAX */ ulong frame_off; /* < ULONG_MAX */ } volumes;
};

typedef union fd_wksp_checkpt_v2_cmd fd_wksp_checkpt_v2_cmd_t;

FD_FN_PURE static inline int
fd_wksp_checkpt_v2_cmd_is_meta( fd_wksp_checkpt_v2_cmd_t const * cmd ) {
  return cmd->meta.tag > 0UL;
}

FD_FN_PURE static inline int
fd_wksp_checkpt_v2_cmd_is_data( fd_wksp_checkpt_v2_cmd_t const * cmd ) {
  return (cmd->data.tag==0UL) & (cmd->data.cgroup_cnt==ULONG_MAX) & (cmd->data.frame_off==ULONG_MAX);
}

FD_FN_PURE static inline int
fd_wksp_checkpt_v2_cmd_is_appendix( fd_wksp_checkpt_v2_cmd_t const * cmd ) {
  return (cmd->appendix.tag==0UL) & (cmd->appendix.cgroup_cnt<ULONG_MAX) & (cmd->appendix.frame_off<ULONG_MAX);
}

FD_FN_PURE static inline int
fd_wksp_checkpt_v2_cmd_is_volumes( fd_wksp_checkpt_v2_cmd_t const * cmd ) {
  return (cmd->volumes.tag==0UL) & (cmd->volumes.cgroup_cnt==ULONG_MAX) & (cmd->volumes.frame_off<ULONG_MAX);
}

/* A fd_wksp_checkpt_v2_ftr_t gives the byte layout of the final frame
   of a wksp v2 checkpt.  This frame contains this footer uncompressed.
   This is wksp checkpt header backwards plus some additional
   information to allow users to seek from the end of the checkpt to the
   header (checkpt_sz), to the appendix frame (frame_off_appendix) and
   do any allocations upfront necessary to completely unpack the
   checkpt. */

struct fd_wksp_checkpt_v2_ftr {
  ulong alloc_cnt;                 /* total number of allocations in checkpt */
  ulong cgroup_cnt;                /* total number of cgroups     in checkpt */
  ulong volume_cnt;                /* total number of volumes     in checkpt */
  ulong frame_off;                 /* byte offset (relative to header initial byte) of the volumes command */
  ulong checkpt_sz;                /* checkpt byte size, from header initial byte to the footer final byte inclusive (note that
                                      this can be used to convert offsets relative to header initial byte to offsets relative to
                                      the end-of-file / the one past the final footer byte) */
  ulong data_max;                  /* should match header */
  ulong part_max;                  /* " */
  uint  seed;                      /* " */
  char  name[ FD_SHMEM_NAME_MAX ]; /* " */
  uint  reserved;                  /* " */
  int   frame_style_compressed;    /* " */
  int   style;                     /* " */
  ulong unmagic;                   /* ==~FD_WKSP_MAGIC */
};

typedef struct fd_wksp_checkpt_v2_ftr fd_wksp_checkpt_v2_ftr_t;

/* fd_wksp_private_{checkpt,restore,printf}_v1 provide the v1
   implementations of {checkpt,restore,printf}.  That is, checkpt_v1
   will only write a v1 style checkpt while the {restore,printt}_v1 can
   assume that the path exclusively contains a v1 style checkpt.  These
   can assume that the input arguments have been validated by their
   caller.  The printf implementation can further assume verbose is
   positive and the verbose 0 information has already been printed.  For
   checkpt/restore, if tpool is non-NULL, the operation will be
   parallelized over tpool threads [t0,t1).  Assumes the caller is
   thread t0 and threads (t0,t1) are available for thread dispatch. */

int
fd_wksp_private_checkpt_v1( fd_tpool_t * tpool,
                            ulong        t0,
                            ulong        t1,
                            fd_wksp_t *  wksp,
                            char const * path,
                            ulong        mode,
                            char const * uinfo );

int
fd_wksp_private_restore_v1( fd_tpool_t * tpool,
                            ulong        t0,
                            ulong        t1,
                            fd_wksp_t *  wksp,
                            char const * path,
                            uint         new_seed );

int
fd_wksp_private_printf_v1( int          fd,
                           char const * path,
                           int          verbose );

/* Similarly for v2.  Note that style==FD_WKSP_CHECKPT_STYLE_V3 in the
   fd_wksp_checkpt function becomes a FD_WKSP_CHECKPT_STYLE_V2 with a
   FD_CHECKPT_FRAME_STYLE_LZ4 cgroup frames in the checkpt itself. */

int
fd_wksp_private_checkpt_v2( fd_tpool_t * tpool,
                            ulong        t0,
                            ulong        t1,
                            fd_wksp_t *  wksp,
                            char const * path,
                            ulong        mode,
                            char const * uinfo,
                            int          frame_style_compresed );

int
fd_wksp_private_restore_v2( fd_tpool_t * tpool,
                            ulong        t0,
                            ulong        t1,
                            fd_wksp_t *  wksp,
                            char const * path,
                            uint         new_seed );

int
fd_wksp_private_printf_v2( int          fd,
                           char const * path,
                           int          verbose );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_util_wksp_fd_wksp_private_h */
