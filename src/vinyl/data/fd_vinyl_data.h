#ifndef HEADER_fd_src_vinyl_data_fd_vinyl_data_h
#define HEADER_fd_src_vinyl_data_fd_vinyl_data_h

/* fd_vinyl_data provides a data structure suitable for in-memory
   caching extremely of large amounts of variable sized pairs in memory.
   The memory layouts are such that cached pairs can be zero copy
   lockfree operated on by multiple threads in other address spaces and
   async direct I/O hardware concurrently.

   Pairs are cached in a shared memory region.  The allocator is thread
   safe: multiple threads may concurrently allocate and free objects
   using per-sizeclass spinlocks with a consistent lock ordering
   (lock[szc] < lock[parent_szc] < vol_lock) to prevent deadlock.

   Notes:

   - The shared memory region is divided into a fixed number of fixed
     sized volumes (similar to fd_groove).
   - Volumes flexibly store data objects.
   - Volumes not in use are stored on a free volume stack.
   - The size of a data object is determined by the object's size class.
   - A data object can either be an allocation (i.e. a cached pair val
     that fits in that object's sizeclass) or a superblock (a collection
     of smaller data objects from the same sizeclass).

   The algorithms that manage the allocations are virtually identical to
   fd_groove and fd_alloc.  But they have been simplified, customized
   and optimized for this use case (e.g. minimal need for address
   translation, simple spinlock concurrency, much more fine grained
   size classes for minimal data store overheads, etc).  This also does
   extensive (and compile time configurable)
   memory data integrity continuously to help catch memory corruption
   (either due to hardware failures, buggy usage or malicious usage).

   I/O alignment requirements quantize the data cache footprint of a
   val_sz pair to BLOCK_SZ+align_up(pair_sz(val_sz),BLOCK_SZ).  This
   unavoidable quantization dominates allocation footprint efficiency
   for the smallest values (e.g. a val_sz 1 pair will occupy 2 blocks
   for the I/O alignment requirements and metadata).  This is negligible
   for large pairs (e.g. ~0.0024% for a VAL_MAX ~ 10 MiB val).

   Rounding an allocation to the smallest compatible size class adds no
   additional overhead for smallest sizes (every possible quantization
   of a val_sz less then ~4-8 KiB has a dedicated sizeclass).  For
   object sizes << VAL_MAX, the worst case overhead is better than ~2%.
   For the object sizes ~ VAL_MAX, if the volume size is ~O(1) VAL_MAX,
   volume divisibility starts to impact this overhead.  It still less
   than ~20% for the current config (and such sizes should be rare in
   the practical usage).  This effect can eliminated by using volume
   sizes much larger than VAL_MAX (at the expense of creating a deeper
   sizeclass nesting).

   The packing of objects into nested superblocks also incurs a small
   amount of additional overhead. The smallest footprint object (2
   blocks or 256B) will be in a leaf superblock with 64 objects.  The
   leaf superblock overhead (128B) amortized over these 64 objects is
   thus 2 bytes per object.  This leaf superblock will be nested in a
   larger superblock with 2 leaf superblocks.  With 128B additional
   overhead amortized over 128 objects, this yields 1 more byte overhead
   per object.  And so forth.  For this sizeclass, the overall
   superblock overhead converges to <~4 bytes per object absolute or
   <~1.5% relative.  This is a rough relative upper bound for all
   sizeclasses.  Specifically, for leaf superblocks with less than 64
   objects, there is more absolute superblock overhead per object but
   the object itself is large enough to compensate.  And for objects in
   large superblocks, the objects more than large enough to compensate.

   The allocator will also implicitly adaptively preallocate space for
   frequently used sizeclasses to speed up allocations.  For
   asymptotically large data caches relative to the worst case object
   sizes, the amount of preallocation is very small.

   TL;DR Allocator footprint overhead is the unavoidable BLOCK_SZ
   quantization plus a couple percent typically. */

#include "../io/fd_vinyl_io.h"

/* fd_vinyl_data_szc **************************************************/

struct __attribute__((aligned(8))) fd_vinyl_data_szc_cfg {
  uint   val_max;    /* max pair val byte size that can be stored in an object in this size class.
                        The object is aligned in memory with FD_VINYL_BSTREAM_BLOCK_SZ alignment and with a footprint of:
                          FD_VINYL_BSTREAM_BLOCK_SZ + sizeof(fd_vinyl_bstream_phdr_t) + val_max + FD_VINYL_BSTREAM_FTR_SZ
                        The footprint is a FD_VINYL_BSTREAM_BLOCK_SZ multiple. */
  ushort obj_cnt;    /* ==num objects in the containing superblock, in [2,64] */
  ushort parent_szc; /* size class of the superblock that contains objects of this size class,
                        FD_VINYL_DATA_SZC_CNT indicates superblocks for objects of this size class fill an entire volume,
                        (the superblock footprint is FD_VINYL_BSTREAM_BLOCK_SZ + obj_cnt*obj_footprint) */
};

typedef struct fd_vinyl_data_szc_cfg fd_vinyl_data_szc_cfg_t;

FD_PROTOTYPES_BEGIN

/* fd_vinyl_data_szc_cfg describes the sizeclasses used by the data
   cache.  Indexed [0,FD_VINYL_DATA_SZC_CNT). */

#define FD_VINYL_DATA_SZC_CNT (327UL)

extern fd_vinyl_data_szc_cfg_t const fd_vinyl_data_szc_cfg[ FD_VINYL_DATA_SZC_CNT ];

/* fd_vinyl_data_szc_obj_footprint returns the in-memory footprint for
   an object with the given size class.

   fd_vinyl_data_szc_val_max returns the largest pair val that can be
   cached in an object with the given size class.  Assumes szc is in
   [O,FD_VINYL_DATA_SZC_CNT).  Return will be in
   [0,cfg(SZC_CNT-1).val_max].

   fd_vinyl_data_szc returns the tightest fitting size class that can
   cache a pair val with a maximum size of val_max.  Assumes val_max is
   in [0,szc.cfg(SZC_CNT-1.val_max].  Return will be in
   [0,FD_VINYL_DATA_SZC_CNT).  The returned size class is typically able
   to hold a val_max ~1-2% larger than the given val_max.

   Note that the size classes are configured such that, given val_sz in
   [0,FD_VINYL_VAL_MAX]:

     fd_vinyl_data_szc_val_max( fd_vinyl_data_szc( val_sz ) ) <= FD_VINYL_VAL_MAX.

   where equality is achieved when val_sz==FD_VINYL_VAL_MAX.

   FIXME: should these be FD_FN_CONST (szc_cfg is const)? */

FD_FN_PURE static inline ulong
fd_vinyl_data_szc_obj_footprint( ulong szc ) {
  return FD_VINYL_BSTREAM_BLOCK_SZ +
    sizeof(fd_vinyl_bstream_phdr_t) + (ulong)fd_vinyl_data_szc_cfg[ szc ].val_max + FD_VINYL_BSTREAM_FTR_SZ;
}

FD_FN_PURE static inline ulong
fd_vinyl_data_szc_val_max( ulong szc ) {
  return (ulong)fd_vinyl_data_szc_cfg[ szc ].val_max;
}

FD_FN_PURE static inline ulong
fd_vinyl_data_szc( ulong val_max ) {

  ulong l = 0UL;
  ulong h = FD_VINYL_DATA_SZC_CNT-1UL;

  for( ulong rem=9UL; rem; rem-- ) { /* Update if FD_VINYL_DATA_SZC_CNT changed */

    /* At this point, szc in [0,l) aren't suitable, szc in [h,CNT) are
       suitable and szc in [l,h) are untested.  See fd_alloc for more
       detail on using fixed count loop. */

    ulong m = (l+h) >> 1;
    int   c = (((ulong)fd_vinyl_data_szc_cfg[ m ].val_max) >= val_max);
    l = fd_ulong_if( c, l, m+1UL );
    h = fd_ulong_if( c, m, h     );

  }

  return l;
}

FD_PROTOTYPES_END

/* fd_vinyl_data_obj **************************************************/

#define FD_VINYL_DATA_OBJ_TYPE_FREEVOL    (0xf7eef7eef7eef7eeUL) /* free, object is a  free volume */
#define FD_VINYL_DATA_OBJ_TYPE_ALLOC      (0xa11ca11ca11ca11cUL) /* allc, object is an allocation */
#define FD_VINYL_DATA_OBJ_TYPE_SUPERBLOCK (0x59e759e759e759e7UL) /* sper, object is a  superblock */

#define FD_VINYL_DATA_OBJ_GUARD_SZ (FD_VINYL_BSTREAM_BLOCK_SZ - sizeof(fd_vinyl_io_rd_t) - 8UL*sizeof(ulong))

struct fd_vinyl_data_obj;
typedef struct fd_vinyl_data_obj fd_vinyl_data_obj_t;

struct __attribute__((aligned(FD_VINYL_BSTREAM_BLOCK_SZ))) fd_vinyl_data_obj {

  /* type gives the object type.  A FD_VINYL_DATA_OBJ_TYPE_*.

     For type SUPERBLOCK objects, child_szc gives the size class of the
     objects contained in this superblock.  In
     [0,FD_VINYL_DATA_SZC_CNT).  Ignored for other types of objects.

     For type SUPERBLOCK and type ALLOC objects, szc gives the size
     class of the object.  In [0,FD_VINYL_DATA_SZC_CNT].  Values less
     then SZC_CNT indicate an object contained in a superblock.  Equal
     to SZC_CNT indicates an object that fills an entire volume.  For
     other types of objects, ignored.

     For objects contained in a parent superblock, idx gives the index
     of the object in its parent, in [0,szc.obj_cnt).  For objects that
     fill an entire volume, idx gives the data volume index, in
     [0,vol_cnt).

     For type SUPERBLOCK objects, free_blocks gives a bit field
     identifying which blocks are free.  Ignored for other types of
     objects.

     For inactive type SUPERBLOCK objects, next_off gives the byte
     offset from laddr0 of the next inactive superblock and 0UL if no
     more inactive superblocks.  next_off is ignored in other
     circumstances (but see note about pending I/O ops).  Note that this
     implies laddr0 must less than the local address of vol (such that
     data gaddr==0 never points to an object).  Note also that, if
     laddr0 is 0, next_off will be just a pointer in the local address
     space.

     Note that I/O acceleration may require memory alignment and I/O
     device alignment to match.  So we need to put all the object
     allocator data its own block.  This can leave a lot of extra space.
     We put this space up front in the block to that it can act as a
     guard region for whatever preceeds it (applications could even use
     this guard region to stash extra info but this is not recommended
     because of false sharing conflicts in might induce between
     different threads using adjacent in memory objects).  Likewise,
     because we have all this space from block quantization, we don't
     try to be hyperefficient with the packing (like we do for, say,
     fd_alloc). */

# if 0 /* Note: with BLOCK_SZ==128, GUARD_SZ=0 so there's no guard field due to language limitations */
  uchar guard[ FD_VINYL_DATA_OBJ_GUARD_SZ ];
# endif

  /* rd on its own cache line */

  fd_vinyl_io_rd_t rd[1]; /* rd: ctx is element idx */

  /* allocator metadata on its own cache line */

  ulong   unused[1];   /* unused space */
  schar * rd_err;      /* rd: client req_err       (or dummy location if no client req_err) */
  short   rd_active;   /* rd: is a read in progess on this obj */
  ushort  _unused;     /* unused space */
  ushort  szc;         /* data: allocation size class */
  ushort  child_szc;   /* data: (superblock) contains allocations of this sizeclass */
  ulong   line_idx;    /* vinyl line_idx that is responsible for this object, in [0,line_cnt), ignored if not type alloc */
  ulong   type;        /* data: allocation type (alloc or superblock) */
  ulong   idx;         /* data: (alloc or superblock) index of this allocation in its parent superblock, (vol) vol idx */
  ulong   free_blocks; /* data: (superblock) bit field free allocations */
  ulong   next_off;    /* data: (inactive superblock) pointer to next inactive superblock or 0 last */

  /* This point is FD_VINYL_BSTREAM_BLOCK_SZ aligned */

  /* Space for sizeof(fd_vinyl_bstream_phdr_t) + fd_vinyl_data_szc_cfg[szc].val_max + FD_VINYL_BSTREAM_FTR_SZ

     Note that is is a FD_VINYL_BSTREAM_BLOCK_SZ multiple so that the
     entire region starting from phdr can submitted zero copy for
     streaming to hardware async direct I/O friendly. */

  /* This point is FD_VINYL_BSTREAM_BLOCK_SZ aligned */

  /* There is an implied FD_VINYL_DATA_OBJ_GUARD_SZ region here as per
     note above.  It is not considered part of _this_ data_obj_t though. */

};

FD_PROTOTYPES_BEGIN

/* fd_vinyl_data_obj_* returns a pointer to the eponymous field in
   the given data object.  Assumes obj is valid.  Returns value for
   fd_vinyl_data_obj_phdr will be FD_VINYL_BSTREAM_BLOCK_SZ aligned.
   fd_vinyl_data_* mirror the above but they take the value region as
   input. */

FD_FN_CONST static inline fd_vinyl_bstream_phdr_t *
fd_vinyl_data_obj_phdr( fd_vinyl_data_obj_t const * obj ) {
  return (fd_vinyl_bstream_phdr_t *)((ulong)obj + sizeof(fd_vinyl_data_obj_t));
}

FD_FN_CONST static inline fd_vinyl_key_t *
fd_vinyl_data_obj_key( fd_vinyl_data_obj_t const * obj ) {
  return (fd_vinyl_key_t *)((ulong)obj + sizeof(fd_vinyl_data_obj_t) + sizeof(ulong));
}

FD_FN_CONST static inline fd_vinyl_info_t *
fd_vinyl_data_obj_info( fd_vinyl_data_obj_t const * obj ) {
  return (fd_vinyl_info_t *)((ulong)obj + sizeof(fd_vinyl_data_obj_t) + sizeof(ulong) + sizeof(fd_vinyl_key_t));
}

FD_FN_CONST static inline void *
fd_vinyl_data_obj_val( fd_vinyl_data_obj_t const * obj ) {
  return (void *)((ulong)obj + sizeof(fd_vinyl_data_obj_t) + sizeof(fd_vinyl_bstream_phdr_t));
}

FD_FN_PURE static inline ulong
fd_vinyl_data_obj_val_sz( fd_vinyl_data_obj_t const * obj ) {
  return (ulong)fd_vinyl_data_obj_info( obj )->val_sz;
}

FD_FN_PURE static inline ulong
fd_vinyl_data_obj_val_max( fd_vinyl_data_obj_t const * obj ) {
  return fd_vinyl_data_szc_val_max( (ulong)obj->szc );
}

FD_FN_CONST static inline fd_vinyl_data_obj_t *
fd_vinyl_data_obj( void const * val ) {
  return (fd_vinyl_data_obj_t *)((ulong)val - sizeof(fd_vinyl_bstream_phdr_t) - sizeof(fd_vinyl_data_obj_t));
}

FD_FN_CONST static inline fd_vinyl_bstream_phdr_t *
fd_vinyl_data_phdr( void const * val ) {
  return (fd_vinyl_bstream_phdr_t *)((ulong)val - sizeof(fd_vinyl_bstream_phdr_t));
}

FD_FN_CONST static inline fd_vinyl_key_t *
fd_vinyl_data_key( void const * val ) {
  return (fd_vinyl_key_t *)((ulong)val - sizeof(fd_vinyl_info_t) - sizeof(fd_vinyl_key_t));
}

FD_FN_CONST static inline fd_vinyl_info_t *
fd_vinyl_data_info( void const * val ) {
  return (fd_vinyl_info_t *)((ulong)val - sizeof(fd_vinyl_info_t));
}

FD_FN_PURE static inline ulong
fd_vinyl_data_val_sz( void const * val ) {
  return (ulong)fd_vinyl_data_info( val )->val_sz;
}

FD_FN_PURE static inline ulong
fd_vinyl_data_val_max( void const * val ) {
  return fd_vinyl_data_szc_val_max( (ulong)fd_vinyl_data_obj( val )->szc );
}

FD_PROTOTYPES_END

/* fd_vinyl_data_vol **************************************************/

#define FD_VINYL_DATA_VOL_FOOTPRINT (34078592UL) /* autogenerated */

struct fd_vinyl_data_vol {
  fd_vinyl_data_obj_t obj[1];
  uchar               data[ FD_VINYL_DATA_VOL_FOOTPRINT - sizeof(fd_vinyl_data_obj_t) ];
};

typedef struct fd_vinyl_data_vol fd_vinyl_data_vol_t;

/* fd_vinyl_data ******************************************************/

#define FD_VINYL_DATA_ALIGN     (128UL)
#define FD_VINYL_DATA_FOOTPRINT sizeof(fd_vinyl_data_t)

struct __attribute((aligned(FD_VINYL_DATA_ALIGN))) fd_vinyl_data {
  void *                shmem;           /* Raw shared memory region */
  ulong                 shmem_sz;        /* Raw shared memory region size */
  void *                laddr0;          /* Location where gaddr 0 points in the local address space
                                            (FD_VINYL_BSTREAM_BLOCK_SZ aligned) */
  fd_vinyl_data_vol_t * vol;             /* Vols, indexed [0,vol_cnt), in raw shared memory region */
  ulong                 vol_cnt;         /* Num vols, in [0,FD_VINYL_DATA_VOL_MAX) */
  int                   vol_lock;        /* Spinlock protecting vol_idx_free */
  ulong                 vol_idx_free;    /* Idx of first free volume if in [0,vol_cnt), no free volumes o.w. */
  struct {
    int                   lock;          /* Spinlock protecting this size class */
    fd_vinyl_data_obj_t * active;        /* active superblock for this size class */
    fd_vinyl_data_obj_t * inactive_top;  /* top of the inactive superblock stack for this size class */
  } superblock[ FD_VINYL_DATA_SZC_CNT ];
};

typedef struct fd_vinyl_data fd_vinyl_data_t;

FD_PROTOTYPES_BEGIN

/* fd_vinyl_data_{align,footprint} return the alignment and footprint
   needed for a local memory region to hold the state of a data cache.
   align will be a power of 2 and footprint will be a multiple of align.
   Matches FD_VINYL_DATA_{ALIGN,FOOTPRINT}. */

FD_FN_CONST ulong fd_vinyl_data_align    ( void );
FD_FN_CONST ulong fd_vinyl_data_footprint( void );

/* fd_vinyl_data_init formats a suitable local memory region lmem and an
   arbitrary shared memory region shmem with byte size shmem_sz as a
   vinyl data cache.  laddr0 gives the location in the caller's local
   address space that corresponds to data object global address 0.  It
   should be FD_VINYL_BSTREAM_BLOCK_SZ aligned and before shmem.  E.g.
   laddr0==NULL could be used when the data objects aren't shared with
   threads in different processes while laddr0==wksp could be used for
   data objects that are shared and backed by a wksp.

   IMPORTANT SAFETY TIP!  This does _not_ do the initial formatting of
   the shmem region into free data volumes (e.g. the caller can use the
   data shmem region as a scratch during thread parallel resume and then
   format it appropriately).  The caller is responsible for calling
   fd_vinyl_data_reset before using data as an object store.

   Returns a handle to the data cache on success (data cache owns the
   memory regions) and NULL on failure (bad lmem, bad shmem, too small
   size ... logs details, no ownership changes). */

fd_vinyl_data_t *
fd_vinyl_data_init( void * lmem,
                    void * shmem,
                    ulong  shmem_sz,
                    void * laddr0 );

/* fd_vinyl_data_fini stops using lmem and shmem as a data cache.
   Returns lmem on success and NULL on failure (logs details). */

void *
fd_vinyl_data_fini( fd_vinyl_data_t * data );

/* fd_vinyl_data_{laddr0,shmem,shmem_sz} return the address translation
   and shared memory region used by the data cache. */

FD_FN_PURE static inline void * fd_vinyl_data_laddr0  ( fd_vinyl_data_t const * data ) { return (void *)data->laddr0; }
FD_FN_PURE static inline void * fd_vinyl_data_shmem   ( fd_vinyl_data_t const * data ) { return (void *)data->shmem;  }
FD_FN_PURE static inline ulong  fd_vinyl_data_shmem_sz( fd_vinyl_data_t const * data ) { return data->shmem_sz;       }

/* fd_vinyl_data_is_valid_obj returns 1 if laddr appears to point to
   a valid data object and 0 if not.  vol points to data volume 0 in the
   local address space and vol_cnt is the number of data volumes. */

FD_FN_PURE static inline int
fd_vinyl_data_is_valid_obj( void const *                laddr,
                            fd_vinyl_data_vol_t const * vol,
                            ulong                       vol_cnt ) {

  ulong vol_idx = ((ulong)laddr - (ulong)vol) / FD_VINYL_DATA_VOL_FOOTPRINT;

  if( FD_UNLIKELY( !( ((ulong)vol<=(ulong)laddr)                                     &
                      (vol_idx<vol_cnt)                                              &
                      fd_ulong_is_aligned( (ulong)laddr, FD_VINYL_BSTREAM_BLOCK_SZ ) ) ) ) return 0;

  /* At this point, laddr seems to be properly aligned and in volume
     vol_idx.  We are safe to read the type and sizeclass. */

  fd_vinyl_data_obj_t const * obj = (fd_vinyl_data_obj_t const *)laddr;
  ulong                       szc = (ulong)obj->szc;

  if( FD_UNLIKELY( !((obj->type==FD_VINYL_DATA_OBJ_TYPE_ALLOC) & (szc<FD_VINYL_DATA_SZC_CNT)) ) ) return 0;

  /* At this point, laddr seems to contain an allocation of sizeclass
     szc.  Make sure the object idx seems to be valid and the object is
     contained entirely within volume vol_idx. */

  ulong end = (ulong)laddr + fd_vinyl_data_szc_obj_footprint( szc );

  if( FD_UNLIKELY( !((obj->idx<(ulong)fd_vinyl_data_szc_cfg[ szc ].obj_cnt) & (end<=(ulong)&vol[vol_idx+1UL])) ) ) return 0;

  return 1;
}

/* fd_vinyl_data_alloc acquires an object of sizeclass szc from the data
   cache.  Returns a pointer to the object on success and NULL if there
   is no space available in the data.  Thread safe.  Will FD_LOG_CRIT
   if anything wonky is detected (bad, memory corruption, etc). */

fd_vinyl_data_obj_t *
fd_vinyl_data_alloc( fd_vinyl_data_t * data,
                     ulong             szc );

/* fd_vinyl_data_free releases obj to the data cache.  This cannot fail
   from the caller's perspective.  Thread safe.  Will FD_LOG_CRIT if
   anything wonky is detected (bad args, memory corruption, etc). */

void
fd_vinyl_data_free( fd_vinyl_data_t *     data,
                    fd_vinyl_data_obj_t * obj );

/* fd_vinyl_data_reset uses the caller and tpool threads (t0,t1) to free
   all objects from the data cache.  Not thread safe with concurrent
   alloc/free; caller must ensure exclusive access.  level zero/non-zero
   indicates to do
   soft/hard reset.  In a hard reset, the shmem region is zero'd before
   formatting it into a set of free data volumes.  This cannot fail from
   the caller's perspective.  Assumes tpool threads (t0,t1) are
   available for dispatch.  Retains no interest in tpool and tpool
   threads (t0,t1) will be available for dispatch on return. */

void
fd_vinyl_data_reset( fd_tpool_t * tpool, ulong t0, ulong t1, int level,
                     fd_vinyl_data_t * data );

/* fd_vinyl_data_verify returns FD_VINYL_SUCCESS (0) if the given data
   appears to be a valid vinyl data and FD_VINYL_ERR_CORRUPT (negative)
   otherwise (logs details).  Not thread safe with concurrent
   alloc/free; caller must ensure exclusive access.  This only verifies
   the vinyl data's state
   and superblock heirarchy are intact.  It does not test any of the
   allocations for correctness (but could given access to the bstream,
   line and/or meta). */

FD_FN_PURE int
fd_vinyl_data_verify( fd_vinyl_data_t const * data );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_vinyl_data_fd_vinyl_data_h */
