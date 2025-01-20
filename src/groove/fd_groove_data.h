#ifndef HEADER_fd_src_groove_fd_groove_data_h
#define HEADER_fd_src_groove_fd_groove_data_h

//#include "fd_groove_base.h" /* includes ../util/fd_util.h */
#include "fd_groove_meta.h"   /* includes fd_groove_base.h */
#include "fd_groove_volume.h" /* includes fd_groove_base.h */

/* A groove data object has a worst case footprint (e.g. 10MiB).  This
   footprint should be much larger than FD_GROOVE_DATA_BLOCK_FOOTPRINT
   and much smaller than FD_GROOVE_VOLUME_FOOTPRINT.  A groove data
   object can have a zero footprint.

   A groove data object has a worst case alignment of at most
   FD_GROOVE_DATA_BLOCK_ALIGN.

   A groove data object is stored contiguously in a compact range of
   groove data blocks.  Conversely, a groove data block can hold
   information about at most 1 groove data object.

   A groove data object is never split across multiple groove volume.

   A groove data object has a header describing the object at the
   beginning of their first data block.

   Groove data objects of similar size (i.e. in the same "sizeclass")
   are grouped together into superblocks.  Superblocks of a similar size
   are grouped together into larger superblocks.  And so on until the
   superblock is the size of an entire groove volume.

   Volume sized superblocks are acquired from the lockfree volume pool.

   The lockfree algorithms are viritually identically to fd_alloc but
   the superblock nesting has been optimized for HPC memory mapped I/O,
   bounded size objects and using the (lockfree) volume pool instead of
   the (locking) wksp as the allocator of last resort. */

/* fd_groove_data_szc_cfg[ szc ] specifies the configuration of
   sizeclass szc. */

struct fd_groove_data_szc_cfg {
  uint  block_footprint; /* FD_DATA_BLOCK_FOOTPRINT multiple, sb_footprint=FD_DATA_BLOCK_FOOTPRINT+block_cnt*block_footprint */
  uchar block_cnt;       /* ==number of blocks in this superblock, in [2,64] */
  uchar cgroup_mask;     /* Number of concurrency groups to use for this sizeclass (power-of-2) minus 1 */
  uchar parent_szc;      /* Parent size class, SZC_CNT indicates to use volume pool */
};

typedef struct fd_groove_data_szc_cfg fd_groove_data_szc_cfg_t;

#define FD_GROOVE_DATA_ALLOC_ALIGN_DEFAULT FD_GROOVE_DATA_HDR_ALIGN
#define FD_GROOVE_DATA_ALLOC_ALIGN_MAX     FD_GROOVE_DATA_BLOCK_ALIGN

#define FD_GROOVE_DATA_ALLOC_FOOTPRINT_MAX (10486272UL)
#define FD_GROOVE_DATA_SZC_CNT             (32UL)
#define FD_GROOVE_DATA_SZC_CGROUP_MAX      (64UL)

extern fd_groove_data_szc_cfg_t const fd_groove_data_szc_cfg[32];

/* A fd_groove_data_hdr encodes groove data object details:

     bits[ 0:16] 17 -> magic type
     bits[17:23]  7 -> sizeclass
     bits[24:29]  6 -> parent block index
     bits[30:39] 10 -> object align       (type BLOCK), unused          (type SUPERBLOCK)
     bits[40:63] 24 -> object sz          (type BLOCK), unsued          (type SUPERBLOCK)
     info        64 -> object tag         (type BLOCK), next superblock (type SUPERBLOCK)

   This layout assumes:

   - SZC_CNT <= 128 (such that a size class index fits in 7 bits)
   - superblocks have at most 64 blocks (such that a block index fits in
     6 bits)
   - groove data objects have sizes less than 16 MiB (such that sz fits
     in 24 bits)
   - groove data objects have alignments are at most 512 (such that
     align fits in 10 bits)

   Note: The next superblock is given as an offset relative to volume0.
   This could be up to machine address width (64 bits).  Since this
   offset is aligned 512, we could encode additional info there as the
   lower 9 bits are zero.

   Note: since alignments are powers of 2, we could use the log2 of the
   alignment to compact align further (it would be nice to store
   superblock offset in the header but this doesn't save enough space as
   the superblock offset needs ~30 bits ...  would have to lose details
   like object sz and align or use a bigger header).

   Note: Consider an alternate design where these headers are seperated
   out (e.g. a mirror header for each data block at the start of the
   volume similar to wksp or a separate mirror header region entirely).
   Advantages would be better isolation / protection of headers, more
   advanced analytics / repair / etc.  Disadvantages are ~5-6% storage
   overhead, more complexity for user to manage.  Performance
   implications are mixed (less implicit prefetching and more hopping
   around but may be faster if header storage region runs on separate
   optimized media ... e.g. headers in fast NVMe while data in slow
   spinning rust). */

#define FD_GROOVE_DATA_HDR_ALIGN     (16UL)
#define FD_GROOVE_DATA_HDR_FOOTPRINT (16UL)

#define FD_GROOVE_DATA_HDR_TYPE_BLOCK      (0x0fd67UL)
#define FD_GROOVE_DATA_HDR_TYPE_SUPERBLOCK (0x1fd67UL)

struct __attribute__((aligned(FD_GROOVE_DATA_HDR_ALIGN))) fd_groove_data_hdr {

  /* Top of a FD_GROOVE_DATA_BLOCK */

  ulong bits;
  ulong info;

  /* Lots of room for other hdr type dependent data here.  E.g.
     FD_GROOVE_DATA_HDR_TYPE_SUPERBLOCK has a ulong free_blocks here bit
     field (consider moving free blocks and next to different cache
     line?) */

};

typedef struct fd_groove_data_hdr fd_groove_data_hdr_t;

#define FD_GROOVE_DATA_ALIGN       (128UL)
#define FD_GROOVE_DATA_FOOTPRINT() sizeof(fd_groove_data_shmem_t)
#define FD_GROOVE_DATA_MAGIC       (0xfd67007eda7a36c0UL) /* fd groove data mgc version 0 */

struct __attribute__((aligned(FD_GROOVE_DATA_ALIGN))) fd_groove_data_shmem {

  /* This point is FD_GROOVE_DATA_ALIGN aligned */

  ulong magic; /* ==FD_GROOVE_DATA_MAGIC */

  /* Padding to FD_GROOVE_DATA_ALIGN alignment */

  ulong active_slot[ FD_GROOVE_DATA_SZC_CNT*FD_GROOVE_DATA_SZC_CGROUP_MAX ] __attribute__((aligned(FD_GROOVE_DATA_ALIGN)));

  /* Padding to FD_GROOVE_DATA_ALIGN alignment */

  /* Since superblocks offsets are all aligned 512, we use the least
     significant 9 bits of inactive_stack as an ABA tag.  We could also
     restrict the maximum size data to like 50B * 10MiB and move to most
     significant bits for a ~14 bit wide tag.  We could use 128-bit wide
     inactive_stack, falling back on a weakly locking implementation if
     the target doesn't have FD_HAS_INT128). */

  ulong inactive_stack[ FD_GROOVE_DATA_SZC_CNT ] __attribute__((aligned(FD_GROOVE_DATA_ALIGN)));

  /* Padding to FD_GROOVE_DATA_ALIGN==FD_GROOVE_VOLUME_POOL_ALIGN alignment */

  fd_groove_volume_pool_shmem_t volume_pool[1];

  /* Padding to FD_GROOVE_DATA_ALIGN alignment */

};

typedef struct fd_groove_data_shmem fd_groove_data_shmem_t;

struct fd_groove_data {
  fd_groove_volume_pool_t volume_pool[1]; /* volume_pool local join (shele is volume0, ele_max is 2^34) */
  ulong *                 active_slot;    /* active slot for sizeclass szc and concurrency group cgroup at
                                               active_slot + szc + SZC_CNT*cgroup in the local address */
  ulong *                 inactive_stack; /* inactive stack for sizeclass szc at inactive_stack + szc in local address space */
  ulong                   cgroup_hint;    /* cgroup_hint for this join */
};

typedef struct fd_groove_data fd_groove_data_t;

FD_PROTOTYPES_BEGIN

/* fd_groove_data_{align,footprint} returns the alignment and footprint
   needed for a memory region to hold a fd_groove_data's state.  align
   will be an integer power-of-two and footprint will be a multiple of
   align.

   fd_groove_data_new formats a memory region with the appropriate
   alignment and footprint into a fd_groove_data.  shmem points in the
   the caller's address space of the memory region to format.  Returns
   shmem on success (fd_groove_data has ownership of the memory region)
   and NULL on failure (no changes, logs details).  Caller is not joined
   on return.  The fd_groove_data will contain no volumes and have no
   data allocations.

   fd_groove_data_join joins a fd_groove_data.  ljoin points to a
   fd_groove_data_t compatible memory region in the caller's address
   space used to hold the local join's state, shdata points in the
   caller's address space to the memory region containing the
   fd_groove_data, volume0 points in the caller's address space reserved
   for mapping groove volumes, volume_max is the maximum number of
   volumes can be mapped in the caller's address space starting at
   volume0 (0 indicates to use as maximal default), and cgroup_hint is
   the concurrency group hint (see fd_alloc for details).  Returns a
   handle to the caller's local join on success (join has ownership of
   the ljoin region) and NULL on failure (no changes, logs details).

   fd_groove_data_leave leaves a fd_groove_data.  join points to a
   current local join.  Returns the memory used for the local join
   (caller has ownership on return and caller is no longer joined) on
   success and NULL on failure (no changes, logs details).  Use the join
   accessors before leaving to get shdata, volume0 and cgroup_hint used
   by the join if needed.

   fd_groove_data_delete unformats a memory region used as a
   fd_groove_data.  Assumes shdata points in the caller's address space
   to the memory region containing the fd_groove_data and that there are
   no current joins globally.  Returns shdata on success (caller has
   ownership of the memory region, any volumes in the groove and and any
   groove data objects in these volumes) and NULL on failure (no
   ownership changes, logs details). */

/* FIXME: SHOULD HAVE A WAY FOR A JOIN TO TELL THE CALLER WHICH VOLUMES
   NEED TO BE MAPPED INTO THE CALLER'S ADDRESS SPACE (E.G. A VERSIONED
   PMAP AND HAVE CALLS INDICATE TO APPLICATION TO REMAP) */

FD_FN_CONST static inline ulong fd_groove_data_align    ( void ) { return alignof( fd_groove_data_shmem_t ); }
FD_FN_CONST static inline ulong fd_groove_data_footprint( void ) { return sizeof ( fd_groove_data_shmem_t ); }

void *             fd_groove_data_new   ( void * shmem );
fd_groove_data_t * fd_groove_data_join  ( void * ljoin, void * shdata, void * volume0, ulong volume_max, ulong cgroup_hint );
void *             fd_groove_data_leave ( fd_groove_data_t * join );
void *             fd_groove_data_delete( void * shdata );

/* fd_groove_data_{shdata,volume0,volume_max,cgroup_hint} return
   {shdata,volume0,volume_max,cgroup_hint} used to join a
   fd_groove_data.  Assumes data is a current local join.
   fd_groove_data_{shdata,volume0}_const are const correct versions.
   shdata,volume0 are in the caller's address space. */

FD_FN_PURE static inline void const *
fd_groove_data_shdata_const( fd_groove_data_t const * data ) {
  return (void const *)((ulong)data->active_slot-FD_GROOVE_DATA_ALIGN);
}

FD_FN_PURE static inline void const *
fd_groove_data_volume0_const( fd_groove_data_t const * data ) {
  return fd_groove_volume_pool_shele_const( data->volume_pool );
}

FD_FN_PURE static inline ulong
fd_groove_data_volume_max( fd_groove_data_t const * data ) {
  return fd_groove_volume_pool_ele_max( data->volume_pool );
}

FD_FN_PURE static inline ulong
fd_groove_data_cgroup_hint( fd_groove_data_t const * data ) {
  return data->cgroup_hint;
}

FD_FN_PURE static inline void *
fd_groove_data_shdata( fd_groove_data_t * data ) {
  return (void *)((ulong)data->active_slot-FD_GROOVE_DATA_ALIGN);
}

FD_FN_PURE static inline void *
fd_groove_data_volume0( fd_groove_data_t * data ) {
  return fd_groove_volume_pool_shele( data->volume_pool );
}

/* fd_groove_data_hdr packs the given fields into a fd_groove_hdr_t. */

FD_FN_CONST static inline fd_groove_data_hdr_t
fd_groove_data_hdr( ulong type,    /* In [0,2^17), assumes FD_GROOVE_DATA_HDR_TYPE */
                    ulong szc,     /* In [0,2^7 ), assumes consistent with SZC_CNT */
                    ulong idx,     /* In [0,2^6 ), assumes consistent with cfg[szc].block_cnt */
                    ulong align,   /* In [0,2^10), assumes BLOCK ONLY power of 2 and consistent with cfg[szc].block_footprint */
                    ulong sz,      /* In [0,2^24), assumes BLOCK ONLY consistent with cfg[szc].block_footprint */
                    ulong info ) { /* arbitrary */
  fd_groove_data_hdr_t hdr;
  hdr.bits = type | (szc<<17) | (idx<<24) | (align<<30) | (sz<<40);
  hdr.info = info;
  return hdr;
}

/* fd_groove_data_hdr_* extract the given field from a fd_groove_hdr_t.  */

FD_FN_CONST static inline ulong /* <2^17 */ fd_groove_data_hdr_type ( fd_groove_data_hdr_t h ) { return  h.bits      & 131071UL; }
FD_FN_CONST static inline ulong /* <2^ 7 */ fd_groove_data_hdr_szc  ( fd_groove_data_hdr_t h ) { return (h.bits>>17) &    127UL; }
FD_FN_CONST static inline ulong /* <2^ 6 */ fd_groove_data_hdr_idx  ( fd_groove_data_hdr_t h ) { return (h.bits>>24) &     63UL; }
FD_FN_CONST static inline ulong /* <2^10 */ fd_groove_data_hdr_align( fd_groove_data_hdr_t h ) { return (h.bits>>30) &   1023UL; }
FD_FN_CONST static inline ulong /* <2^24 */ fd_groove_data_hdr_sz   ( fd_groove_data_hdr_t h ) { return  h.bits>>40            ; }
FD_FN_CONST static inline ulong /* <2^64 */ fd_groove_data_hdr_info ( fd_groove_data_hdr_t h ) { return  h.info                ; }

/* fd_groove_data_{alloc,superblock}_hdr returns the header
   for mem's {alloc,superblock}.  Assumes mem points to the byte in the
   first data block after the header in the caller's address space.  szc
   is the allocation's sizeclass and idx is the allocation's superblock
   idx.  fd_groove_data_{alloc,superblock}_hdr_const are const correct
   versions. */

FD_FN_CONST static inline fd_groove_data_hdr_t *
fd_groove_data_block_hdr( void * mem ) {
  return (fd_groove_data_hdr_t *)(((ulong)mem-16UL) & ~511UL);
}

FD_FN_PURE static inline fd_groove_data_hdr_t *
fd_groove_data_superblock_hdr( void * mem,
                               ulong  szc,
                               ulong  idx ) {
  return (fd_groove_data_hdr_t *)
    ((((ulong)mem-16UL) & ~511UL) - idx*(ulong)fd_groove_data_szc_cfg[ szc ].block_footprint - 512UL);
}

FD_FN_CONST static inline fd_groove_data_hdr_t const *
fd_groove_data_block_hdr_const( void const * mem ) {
  return (fd_groove_data_hdr_t const *)(((ulong)mem-16UL) & ~511UL);
}

FD_FN_PURE static inline fd_groove_data_hdr_t const *
fd_groove_data_superblock_hdr_const( void const * mem,
                                     ulong        szc,
                                     ulong        idx ) {
  return (fd_groove_data_hdr_t const *)
    ((((ulong)mem-16UL) & ~511UL) - idx*(ulong)fd_groove_data_szc_cfg[ szc ].block_footprint - 512UL);
}

/* fd_groove_data_szc returns the index of the tightest fitting
   sizeclass for footprint.  The caller promises there is at least one
   suitable sizeclass (i.e. footprint<=cfg[SZC_CNT-1].block_footprint).
   The return will be in [0,FD_GROOVE_DATA_SZC_CNT). */

static inline ulong
fd_groove_data_szc( ulong footprint ) {
  ulong l = 0UL;
  ulong h = FD_GROOVE_DATA_SZC_CNT - 1UL;

  /* Fixed count loop without early exit to make it easy for compiler to
     unroll and nominally eliminate all branches for fast, highly
     deterministic performance with no consumption of BTB resources.
     FIXME: check the compiler is doing the right thing here. */

  for( ulong r=0UL; r<5UL; r++ ) { /* Assumes SZC_CNT<=32 */

    /* At this point sizeclasses in [0,l) are known too small and
       sizeclasses [h,SZC_CNT) are known large enough.  Sizeclasses in
       [l,h) have not been tested.  The size of the range will be
       decreased to at least floor((h-l)/2) every iteration.  If this
       range is empty, m==l==h and c==1 as there m must be the tightest
       size class such that the l/h updates are no-ops. */

    ulong m = (l+h)>>1; /* No overflow for reasonable SZC_CNT */
    int   c = (((ulong)fd_groove_data_szc_cfg[ m ].block_footprint)>=footprint);
    l = fd_ulong_if( c, l, m+1UL ); /* cmov */
    h = fd_ulong_if( c, m, h     ); /* cmov */
  }

  return h;
}

/* fd_groove_data_active_displace lockfree atomically sets the active
   superblock for (szc,cgroup) to the superblock at offset
   superblock_off and returns the offset of the previously active
   superblock.  Offsets are relative to volume0.

   Assumes active_slot points in the caller's address space to the
   active superblock offset for (szc,cgroup).  If superblock_off is
   non-zero, further assumes the input superblock is for sizeclass szc,
   has at least one free block and is not in circulation (i.e. neither
   in any active slot nor on any inactive stack such that nobody can
   concurrently allocate from it).

   If this returns zero, there was no active superblock for (szc,cgroup)
   just before it was set to the input superblock.

   If this returns non-zero, the output superblock was the previously
   active superblock.  The output superblock will have at least one free
   block (and possibly growing over time to all blocks free due to
   concurrent frees) and will not be in circulation.

   If superblock_off is non-zero, the input superblock will be in
   circulation as the active superblock for (szc,cgroup) on return.

   If superblock_off is zero, there will be no active superblock for
   (szc,cgroup) on return.

   This is a compiler fence. */

static inline ulong
fd_groove_data_active_displace( ulong volatile *     _active_slot,
                                fd_groove_volume_t * volume0,
                                ulong                superblock_off ) {
  (void)volume0;
  FD_COMPILER_MFENCE();
# if FD_HAS_ATOMIC
  superblock_off = FD_ATOMIC_XCHG( _active_slot, superblock_off );
# else
  ulong old      = *_active_slot;
  *_active_slot  = superblock_off;
  superblock_off = old;
# endif
  FD_COMPILER_MFENCE();
  return superblock_off;
}

/* fd_groove_data_inactive_push does a lockfree atomic push of the
   superblock at superblock_off relative to volume0 onto the given
   inactive stack.  Assumes all inputs are valid, the inactive stack and
   superblock have the same sizeclass, the superblock is not in
   circulation, and superblock contains at least one free block.  On
   return, superblock will be the top of the inactive stack.  This
   is a compiler fence. */

static inline void
fd_groove_data_inactive_push( ulong volatile *     _inactive_stack,
                              fd_groove_volume_t * volume0,
                              ulong                superblock_off ) {
  FD_COMPILER_MFENCE();

  fd_groove_data_hdr_t * superblock = (fd_groove_data_hdr_t *)(((ulong)volume0) + superblock_off);

  for(;;) {
    ulong ver_off = *_inactive_stack;

    ulong      ver = ver_off &  (FD_GROOVE_DATA_BLOCK_FOOTPRINT-1UL);
    ulong next_off = ver_off & ~(FD_GROOVE_DATA_BLOCK_FOOTPRINT-1UL);

    superblock->info = next_off;

    ulong next_ver = (ver+1UL) &  (FD_GROOVE_DATA_BLOCK_FOOTPRINT-1UL);

#   if FD_HAS_ATOMIC
    ulong old = FD_ATOMIC_CAS( _inactive_stack, ver_off, next_ver | superblock_off );
#   else
    ulong old = *_inactive_stack;
    *_inactive_stack = fd_ulong_if( old==ver_off, next_ver | superblock_off, old );
#   endif

    if( FD_LIKELY( old==ver_off ) ) break;

    FD_SPIN_PAUSE();
  }

  FD_COMPILER_MFENCE();
}

/* fd_groove_data_inactive_pop does a lockfree atomic pop the given
   inactive stack.  Assumes all inputs are valid.  Returns the offset
   relative to volume0 of the superblock.  The superblock will be for
   the same sizeclass as the inactive stack, will not be in circulation
   and will have at least 1 block free.  If the stack was empty when
   observed, returns 0.  This is a compiler fence. */

static inline ulong
fd_groove_data_inactive_pop( ulong volatile *     _inactive_stack,
                             fd_groove_volume_t * volume0 ) {

  ulong off;

  FD_COMPILER_MFENCE();

  for(;; ) {
    ulong ver_off = *_inactive_stack;

    ulong ver = ver_off &  (FD_GROOVE_DATA_BLOCK_FOOTPRINT-1UL);
    /**/  off = ver_off & ~(FD_GROOVE_DATA_BLOCK_FOOTPRINT-1UL);

    if( FD_UNLIKELY( !off ) ) break;

    fd_groove_data_hdr_t * superblock = (fd_groove_data_hdr_t *)(((ulong)volume0) + off);

    ulong next_ver = (ver+1UL) & (FD_GROOVE_DATA_BLOCK_FOOTPRINT-1UL);
    ulong next_off = superblock->info;

#   if FD_HAS_ATOMIC
    ulong old = FD_ATOMIC_CAS( _inactive_stack, ver_off, next_ver | next_off );
#   else
    ulong old = *_inactive_stack;
    *_inactive_stack = fd_ulong_if( old==ver_off, next_ver | next_off, old );
#   endif

    if( FD_LIKELY( old==ver_off ) ) break;

    FD_SPIN_PAUSE();
  }

  FD_COMPILER_MFENCE();

  return off;
}

/* fd_groove_data_volume_{add,remove} are just thin wrappers around the
   volume pool APIs for data's volume_pool.  See the volume_pool API for
   details. */

static inline int
fd_groove_data_volume_add( fd_groove_data_t * data,
                           void *             volume,
                           ulong              footprint,
                           void const *       info,
                           ulong              info_sz ) {
  return fd_groove_volume_pool_add( data ? data->volume_pool : NULL, volume, footprint, info, info_sz );
}

static inline void *
fd_groove_data_volume_remove( fd_groove_data_t * data ) {
  return fd_groove_volume_pool_remove( data ? data->volume_pool : NULL );
}

/* fd_groove_data_alloc creates a groove data object in the groove data
   store with the given alignment, size and arbitrary user tag.  Align
   should be an integer power of 2 or 0 (0 indicates to use
   FD_GROOVE_DATA_ALLOC_ALIGN_DEFAULT).  Assumes data is current local
   join.  Because every allocation is independently tag, zero size
   allocations will produce a unique non-NULL returns.

   On success, returns a pointer in the caller's address to the created
   object (will be aligned align with room for sz bytes).  The lifetime
   of the _object_ is until it is freed or the data store is destroyed.
   The lifetime of the local _pointer_ is until the object is freed or
   the join is left.  If _opt_err is non-NULL, *_opt_err will be
   FD_GROOVE_SUCCESS (zero).

   On failure, returns NULL.  If _opt_err is non-NULL, *_opt_err will be
   an FD_GROOVE_ERR code (negative).  Reasons for failure include:
     INVAL (logged) - bad input args (NULL data, align not power of 2, align too large, sz too large)
     FULL  (silent) - groove too full for allocation right now */

void *
fd_groove_data_alloc( fd_groove_data_t * data,
                      ulong              align,
                      ulong              sz,
                      ulong              tag,
                      int *              _opt_err );

/* fd_groove_data_free frees a groove data object in the groove data
   store.  Assumes mem points to the first byte in the object in the
   caller's address space.  On return, obj is no longer a groove data
   obj.  Logs details if anything wonky happens under the hood.  Free
   NULL is a no-op. */

void
fd_groove_data_free( fd_groove_data_t * data,
                     void *             obj );

/* fd_groove_data_{align,sz,tag} return the values used when mem was
   allocated.  Assumes mem points in the caller's address space to a
   current allocation in the groove data. */

FD_FN_PURE static inline ulong
fd_groove_data_alloc_align( void const * mem ) {
  return fd_groove_data_hdr_align( *fd_groove_data_block_hdr_const( mem ) );
}

FD_FN_PURE static inline ulong
fd_groove_data_alloc_sz( void const * mem ) {
  return fd_groove_data_hdr_sz( *fd_groove_data_block_hdr_const( mem ) );
}

FD_FN_PURE static inline ulong
fd_groove_data_alloc_tag( void const * mem ) {
  return fd_groove_data_hdr_info( *fd_groove_data_block_hdr_const( mem ) );
}

/* fd_groove_data_{start,stop} return the actual range of addresses
   [start,stop) in the caller's address space actually reserved for the
   allocation mem.  [mem,mem+sz) will cover this region (and mem will be
   aligned appropriately).

   fd_groove_data_{start,stop}_const are const correct versions. */

FD_FN_CONST static inline void *
fd_groove_data_alloc_start( void * mem ) {
  return (void *)((ulong)fd_groove_data_block_hdr_const( mem ) + 16UL);
}

FD_FN_PURE static inline void *
fd_groove_data_alloc_stop( void * mem ) {
  fd_groove_data_hdr_t const * hdr = fd_groove_data_block_hdr_const( mem );
  return (void *)((ulong)hdr + (ulong)fd_groove_data_szc_cfg[ fd_groove_data_hdr_szc( *hdr ) ].block_footprint);
}

FD_FN_CONST static inline void const *
fd_groove_data_alloc_start_const( void const * mem ) {
  return (void const *)((ulong)fd_groove_data_block_hdr_const( mem ) + 16UL);
}

FD_FN_PURE static inline void const *
fd_groove_data_alloc_stop_const( void const * mem ) {
  fd_groove_data_hdr_t const * hdr = fd_groove_data_block_hdr_const( mem );
  return (void const *)((ulong)hdr + (ulong)fd_groove_data_szc_cfg[ fd_groove_data_hdr_szc( *hdr ) ].block_footprint);
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_groove_fd_groove_data_h */
