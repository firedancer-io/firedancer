#ifndef HEADER_fd_src_groove_fd_groove_data_h
#define HEADER_fd_src_groove_fd_groove_data_h

//#include "fd_groove_base.h" /* includes ../util/fd_util.h */
#include "fd_groove_meta.h"   /* includes fd_groove_base.h */
#include "fd_groove_volume.h" /* includes fd_groove_base.h */

/* A groove data object has a worst case footprint (e.g. 10MiB).  This
   footprint should be much larger than FD_GROOVE_BLOCK_FOOTPRINT and
   much smaller than FD_GROOVE_VOLUME_FOOTPRINT.  A groove data object
   can have a zero footprint.

   A groove data object has a worst case alignment of at most
   FD_GROOVE_BLOCK_ALIGN.

   A groove data object is stored contiguously in a compact range of
   groove data blocks.  Conversely, a groove data block can hold
   information about at most 1 groove data object.

   A groove data object is never split across multiple groove volumes.

   A groove data object has a header describing the object at the
   beginning of their first data block.

   Groove data objects of similar size (i.e. in the same "sizeclass")
   are grouped together into superblocks.  Superblocks of a similar size
   are grouped together into larger superblocks.  And so on until the
   superblock is the size of an entire groove volume.

   Volume sized superblocks are acquired from the lockfree volume pool.

   The lockfree algorithms are viritual identically to fd_alloc but the
   superblock nesting has been optimized for HPC memory mapped I/O,
   bounded size objects and using the (lockfree) volume pool instead of
   the (locking) wksp as the allocator of last resort. */

/* fd_groove_data_szc_cfg[ szc ] specifies the configuration of
   sizeclass szc. */

struct fd_groove_data_szc_cfg {
  uint  obj_footprint; /* FD_GROOVE_BLOCK_FOOTPRINT multiple,
                          superblock_footprint = FD_GROOVE_BLOCK_FOOTPRINT + obj_cnt*obj_footprint */
  uchar obj_cnt;       /* ==number of objects in the superblock for this sizeclass, in [2,64] */
  uchar cgroup_mask;   /* Number of concurrency groups to use for this sizeclass superblock (power-of-2) minus 1 */
  uchar parent_szc;    /* Parent size class, SZC_CNT indicates to use an entire volume data region */
};

typedef struct fd_groove_data_szc_cfg fd_groove_data_szc_cfg_t;

#define FD_GROOVE_DATA_ALLOC_ALIGN_DEFAULT FD_GROOVE_DATA_HDR_ALIGN
#define FD_GROOVE_DATA_ALLOC_ALIGN_MAX     FD_GROOVE_BLOCK_ALIGN

#define FD_GROOVE_DATA_ALLOC_FOOTPRINT_MAX (10486272UL)

#define FD_GROOVE_DATA_SZC_CNT        (32UL)
#define FD_GROOVE_DATA_SZC_CGROUP_MAX (64UL)

extern fd_groove_data_szc_cfg_t const fd_groove_data_szc_cfg[32];

/* A fd_groove_data_hdr encodes groove data object details:

     bits[ 0:15] 16 -> magic type
     bits[16:21]  6 -> object idx in parent (0 if parent is a volume)
     bits[22:28]  7 -> object sizeclass (type ALLOC), sizeclass of objects in superblock (type SUPERBLOCK)
     bits[29:38] 10 -> object align     (type ALLOC), DATA_HDR_ALIGN                     (type SUPERBLOCK)
     bits[39:63] 25 -> object sz        (type ALLOC), superblock sz (sat to 25-bits)     (type SUPERBLOCK)
     info        64 -> object tag       (type ALLOC), next superblock                    (type SUPERBLOCK)

   This layout assumes:

   - SZC_CNT <= 128 (such that a size class index fits in 7 bits)
   - superblocks have at most 64 objects (such that a object index fits
     in 6 bits)
   - groove data objects sizes are less than 32 MiB (such that sz fits
     in 25 bits)
   - groove data objects alignments are at most 512 (such that
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

   Note: Consider an alternate design where these headers are separated
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

#define FD_GROOVE_DATA_HDR_TYPE_ALLOC      (0xfd67UL)
#define FD_GROOVE_DATA_HDR_TYPE_SUPERBLOCK (0x0298UL)

struct __attribute__((aligned(FD_GROOVE_DATA_HDR_ALIGN))) fd_groove_data_hdr {

  /* Top of a FD_GROOVE_BLOCK */

  ulong bits;
  ulong info;

  /* Lots of room for other hdr type dependent data here.  E.g.
     FD_GROOVE_DATA_HDR_TYPE_SUPERBLOCK has a ulong free_objs bit field
     here (consider moving free_objs and next to different cache line?) */

};

typedef struct fd_groove_data_hdr fd_groove_data_hdr_t;

#define FD_GROOVE_DATA_ALIGN       (128UL)
#define FD_GROOVE_DATA_FOOTPRINT() sizeof(fd_groove_data_shmem_t)
#define FD_GROOVE_DATA_MAGIC       (0xfd67007eda7a36c0UL) /* fd groove data mgc version 0 */

struct __attribute__((aligned(FD_GROOVE_DATA_ALIGN))) fd_groove_data_shmem {

  /* This point is FD_GROOVE_DATA_ALIGN aligned */

  ulong magic; /* ==FD_GROOVE_DATA_MAGIC */

  /* Padding to FD_GROOVE_DATA_ALIGN alignment */

  /* active_slot indexed szc+SZC_CNT*cgroup */

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
  fd_groove_volume_pool_t volume_pool[1]; /* volume_pool local join (shele is volume0) */
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
   ownership of the memory region, any volumes in the groove and any
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
   fd_groove_data.  fd_groove_data_volume1 returns the end of the groove
   region such that [volume0,volume1) is the groove data region.
   Assumes data is a current local join.
   fd_groove_data_{shdata,volume0,volume1}_const are const correct
   versions.  shdata,volume0,volume1 are in the caller's address space. */

FD_FN_PURE static inline void const *
fd_groove_data_shdata_const( fd_groove_data_t const * data ) {
  return (void const *)((ulong)data->active_slot-FD_GROOVE_DATA_ALIGN);
}

FD_FN_PURE static inline void const *
fd_groove_data_volume0_const( fd_groove_data_t const * data ) {
  return fd_groove_volume_pool_shele_const( data->volume_pool );
}

FD_FN_PURE static inline void const *
fd_groove_data_volume1_const( fd_groove_data_t const * data ) {
  return (void const *)( (fd_groove_volume_t *)fd_groove_volume_pool_shele_const( data->volume_pool )
                       + fd_groove_volume_pool_ele_max( data->volume_pool ) );
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

FD_FN_PURE static inline void *
fd_groove_data_volume1( fd_groove_data_t * data ) {
  return (void *)( (fd_groove_volume_t *)fd_groove_volume_pool_shele( data->volume_pool ) +
                 + fd_groove_volume_pool_ele_max( data->volume_pool ) );
}

/* fd_groove_data_hdr packs the given fields into a fd_groove_hdr_t. */

FD_FN_CONST static inline fd_groove_data_hdr_t
fd_groove_data_hdr( ulong type,    /* assumed in [0,2^16) */
                    ulong idx,     /* assumed in [0,2^ 6) */
                    ulong szc,     /* assumed in [0,2^ 7) */
                    ulong align,   /* assumed in [0,2^10) */
                    ulong sz,      /* assumed in [0,2^25) */
                    ulong info ) { /* arbitrary */
  fd_groove_data_hdr_t hdr;
  hdr.bits = type | (idx<<16) | (szc<<22) | (align<<29) | (sz<<39);
  hdr.info = info;
  return hdr;
}

/* fd_groove_data_hdr_* extract the given field from a fd_groove_hdr_t.  */

FD_FN_CONST static inline ulong /* <2^16 */ fd_groove_data_hdr_type ( fd_groove_data_hdr_t h ) { return  h.bits      & 65535UL; }
FD_FN_CONST static inline ulong /* <2^ 6 */ fd_groove_data_hdr_idx  ( fd_groove_data_hdr_t h ) { return (h.bits>>16) &    63UL; }
FD_FN_CONST static inline ulong /* <2^ 7 */ fd_groove_data_hdr_szc  ( fd_groove_data_hdr_t h ) { return (h.bits>>22) &   127UL; }
FD_FN_CONST static inline ulong /* <2^10 */ fd_groove_data_hdr_align( fd_groove_data_hdr_t h ) { return (h.bits>>29) &  1023UL; }
FD_FN_CONST static inline ulong /* <2^25 */ fd_groove_data_hdr_sz   ( fd_groove_data_hdr_t h ) { return  h.bits>>39           ; }
FD_FN_CONST static inline ulong /* arb   */ fd_groove_data_hdr_info ( fd_groove_data_hdr_t h ) { return  h.info               ; }

/* fd_groove_data_{object,superblock}_hdr returns the header for a
   groove object / object superblock.  Assumes obj points to the first
   object byte in the caller's address space.  obj_szc is the object's
   sizeclass and parent_idx is the object's index in its parent
   superblock (and thus assumes the object is stored in a superblock).
   fd_groove_data_{alloc,superblock}_hdr_const are const correct
   versions. */

FD_FN_CONST static inline fd_groove_data_hdr_t *
fd_groove_data_object_hdr( void * obj ) {
  return (fd_groove_data_hdr_t *)fd_ulong_align_dn( (ulong)obj - FD_GROOVE_DATA_HDR_FOOTPRINT, FD_GROOVE_BLOCK_ALIGN );
}

FD_FN_PURE static inline fd_groove_data_hdr_t *
fd_groove_data_superblock_hdr( void * obj,
                               ulong  obj_szc,
                               ulong  parent_idx ) {
  return (fd_groove_data_hdr_t *)
    ( fd_ulong_align_dn( (ulong)obj - FD_GROOVE_DATA_HDR_FOOTPRINT, FD_GROOVE_BLOCK_ALIGN )
    - parent_idx*(ulong)fd_groove_data_szc_cfg[ obj_szc ].obj_footprint - FD_GROOVE_BLOCK_FOOTPRINT );
}

FD_FN_CONST static inline fd_groove_data_hdr_t const *
fd_groove_data_object_hdr_const( void const * obj ) {
  return (fd_groove_data_hdr_t const *)fd_ulong_align_dn( (ulong)obj - FD_GROOVE_DATA_HDR_FOOTPRINT, FD_GROOVE_BLOCK_ALIGN );
}

FD_FN_PURE static inline fd_groove_data_hdr_t const *
fd_groove_data_superblock_hdr_const( void const * obj,
                                     ulong        obj_szc,
                                     ulong        parent_idx ) {
  return (fd_groove_data_hdr_t const *)
    ( fd_ulong_align_dn( (ulong)obj - FD_GROOVE_DATA_HDR_FOOTPRINT, FD_GROOVE_BLOCK_ALIGN )
    - parent_idx*(ulong)fd_groove_data_szc_cfg[ obj_szc ].obj_footprint - FD_GROOVE_BLOCK_FOOTPRINT );
}

/* fd_groove_data_szc returns the index of the tightest fitting
   sizeclass for footprint.  The caller promises there is at least one
   suitable sizeclass (i.e. footprint<=cfg[SZC_CNT-1].obj_footprint).
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
    int   c = (((ulong)fd_groove_data_szc_cfg[ m ].obj_footprint)>=footprint);
    l = fd_ulong_if( c, l, m+1UL ); /* cmov */
    h = fd_ulong_if( c, m, h     ); /* cmov */
  }

  return h;
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
   should be an integer power of 2 of at most
   FD_GROOVE_DATA_ALLOC_ALIGN_MAX or 0 (0 indicates to use
   FD_GROOVE_DATA_ALLOC_ALIGN_DEFAULT).  Assumes data is current local
   join.  Because every allocation is independently tagged, a zero size
   allocation will produce a unique non-NULL return.

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
   store.  Assumes obj points to the first byte in the object in the
   caller's address space.  On return, obj is no longer a groove data
   obj.  On success, returns FD_GROOVE_SUCCESS (0) and a FD_GROOVE_ERR
   code (negative) on failure.  Reasons for failure include:

     INVAL - NULL data (logged), NULL obj (silent), all sorts of
       unexpected conditions that suggest buggy usage and/or data
       corruption (logged), groove data state was not changed.

     CORRUPT - all sorts of unexpected conditions that suggest buggy
       usage and/or data corruption (logged), groove data state might
       have been changed before the unexpected condition was detected. */

int
fd_groove_data_private_free( fd_groove_data_t * data,
                             void *             obj,
                             ulong              exp_type );

static inline int
fd_groove_data_free( fd_groove_data_t * data,
                     void *             obj ) {
  return fd_groove_data_private_free( data, obj, FD_GROOVE_DATA_HDR_TYPE_ALLOC );
}

/* fd_groove_data_{align,sz,tag} return the values used when obj was
   allocated.  Assumes obj points in the caller's address space to a
   current allocation in the groove data. */

FD_FN_PURE static inline ulong
fd_groove_data_alloc_align( void const * obj ) {
  return fd_groove_data_hdr_align( *fd_groove_data_object_hdr_const( obj ) );
}

FD_FN_PURE static inline ulong
fd_groove_data_alloc_sz( void const * obj ) {
  return fd_groove_data_hdr_sz( *fd_groove_data_object_hdr_const( obj ) );
}

FD_FN_PURE static inline ulong
fd_groove_data_alloc_tag( void const * obj ) {
  return fd_groove_data_hdr_info( *fd_groove_data_object_hdr_const( obj ) );
}

/* fd_groove_data_{start,stop} return the actual range of addresses
   [start,stop) in the caller's address space actually reserved for the
   allocation obj.  [obj,obj+sz) is completely covered by this region
   (and obj will be aligned appropriately).

   fd_groove_data_{start,stop}_const are const correct versions. */

FD_FN_CONST static inline void *
fd_groove_data_alloc_start( void * obj ) {
  return (void *)((ulong)fd_groove_data_object_hdr_const( obj ) + 16UL);
}

FD_FN_PURE static inline void *
fd_groove_data_alloc_stop( void * obj ) {
  fd_groove_data_hdr_t const * hdr = fd_groove_data_object_hdr_const( obj );
  return (void *)((ulong)hdr + (ulong)fd_groove_data_szc_cfg[ fd_groove_data_hdr_szc( *hdr ) ].obj_footprint);
}

FD_FN_CONST static inline void const *
fd_groove_data_alloc_start_const( void const * obj ) {
  return (void const *)((ulong)fd_groove_data_object_hdr_const( obj ) + 16UL);
}

FD_FN_PURE static inline void const *
fd_groove_data_alloc_stop_const( void const * obj ) {
  fd_groove_data_hdr_t const * hdr = fd_groove_data_object_hdr_const( obj );
  return (void const *)((ulong)hdr + (ulong)fd_groove_data_szc_cfg[ fd_groove_data_hdr_szc( *hdr ) ].obj_footprint);
}

/* fd_groove_data_verify returns FD_GROOVE_SUCCESS if join appears to be
   current local join to a valid groove data instance and
   FD_GROOVE_ERR_CORRUPT otherwise (logs details).  Assumes join is a
   current local join and the groove data is idle.  This only verifies
   the groove data's state.  Specifically, it verifies the join, the
   data volume pool, the active superblocks and the inactive superblocks
   look correct.  It is does verify the entire contains of all volumes.
   Use fd_groove_data_verify for that. */

int
fd_groove_data_verify( fd_groove_data_t const * data );

/* fd_groove_data_volume_verify returns FD_GROOVE_SUCCESS if the
   groove volume mapped into the caller's address at _volume is appears
   to be a valid groove volume and FD_GROOVE_ERR_CORRUPT otherwise (logs
   details).  Assumes join is a current local join and the groove data
   is idle.  It is fine to verify volumes in parallel (e.g. use hundreds
   of cores to verify petabytes of groove data). */

int
fd_groove_data_volume_verify( fd_groove_data_t   const * data,
                              fd_groove_volume_t const * _volume );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_groove_fd_groove_data_h */
