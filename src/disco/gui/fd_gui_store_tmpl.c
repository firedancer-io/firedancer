/* Generate prototypes, inlines and implementations for a keyed store
   with variable-sized elements backed by a file-backed write-back LRU
   cache.  Any append that can fit in the store must always succeed.
   Entries are evicted in FIFO order to make room for new inserts.

   Includes an asynchronous batch pre-eviction API which moves the cost
   of cache eviction off the critical path reducing the amortized cost
   of disk I/O.

   The store occupies two distinct regions.  The in-memory allocation
   (1) holds an index and a cache; the file-backed allocation (2) lives
   in an independent caller-provided file region.

   1) In-Memory Allocation

   The index is a map of up to ele_max records, each tracking a value
   that lives either in the in-mem cache (fd_circq) or on disk.  Both
   the cache and disk allocation are fixed-size ring buffers. The cache
   uses an LRU eviction policy while the file buffer evicts in FIFO
   order.

   +===================================================================+
   |  index                                                            |
   |    record0: val0_ptr (value0 lives in in-mem circq)               |
   |    record1: val1_off (value1 lives on-disk)                       |
   |    ...                                                            |
   +===================================================================+
   |  cache (fd_circq)                                                 |
   |    +-------+-----+------+-----+-----+-------+-----+------+-----+  |
   |    | meta0 | pad | val0 | pad | ... | metaN | pad | valN | pad |  |
   |    +-------+-----+------+-----+-----+-------+-----+------+-----+  |
   +===================================================================+

   2) On-Disk Allocation

   +===================================================================+
   |  superblock                                                       |
   |    magic | version | head | tail | cnt | gen | checksum | (pad)   |
   +===================================================================+
   |  ring buffer                                                      |
   |    +-------+------+-----+-----+-------+-----+------+              |
   |    | metaN | valN | pad | ... | meta1 | val1 | pad |              |
   |    +-------+------+-----+-----+-------+-----+------+              |
   |                         ^     ^                                   |
   |              ftail (next)     fhead (oldest)                      |
   |                                                                   |
   |  record [meta | val | pad]                                        |
   |    +-------+----+-----+-------+-----+                             |
   |    | align | sz | key | value | pad |                             |
   |    +-------+----+-----+-------+-----+                             |
   +===================================================================+

   Typical usage:

    struct myrec_key {
      ulong slot;
      ulong block_id;
    };
    typedef struct myrec_key myrec_key_t;

    #define GUI_STORE_NAME             myrec_store
    #define GUI_STORE_KEY_T            myrec_key_t
    #define GUI_STORE_KEY_HASH(k,seed) fd_ulong_hash( (k)->slot ^ fd_ulong_rotate_left( (k)->block_id, 32 ) ^ (seed) )
    #define GUI_STORE_KEY_EQ(k0,k1)    ( ((k0)->slot==(k1)->slot) & ((k0)->block_id==(k1)->block_id) )
    #include "fd_gui_store_tmpl.c"

  declares the following header-only library in the current translation
  unit (myrec_store_* prefix from GUI_STORE_NAME):

    // A myrec_store_t is a quasi-opaque handle for a local join.  Its
    // contents should not be used directly.

    typedef struct myrec_store_private myrec_store_t;

    // align/footprint - Return the alignment/footprint required for a
    // memory region to be used as a myrec_store that can hold up to
    // ele_max records with a cache_sz byte cache.  cache_sz must be
    // larger than the largest storeable key+value (including extra
    // space for alignment padding and a seq).  For good performance, a
    // cache_sz several times larger then the average element footrpint
    // is recommended.  footprint does not include the caller-provided
    // on-disk allocation.
    //
    // new - Format a memory region pointed to by shmem into a
    // myrec_store.  Assumes shmem points to a region with the required
    // alignment and footprint.  seed is the hash seed passed into
    // GUI_STORE_KEY_HASH.  file_len==0 makes the store cache-only.
    // Otherwise it occupies [file_base_off,file_base_off+file_len) of
    // the file passed to join.  Caller is not joined on return.
    // Returns shmem.
    //
    // join - Join a myrec_store.  Assumes shstore points at a region
    // formatted as a myrec_store.  fd is the descriptor of the backing
    // file for a file-backed store, or -1 for a mem-only store (must
    // match new).  The caller retains ownership of fd, but must keep it
    // open for the lifetime of the myrec_store.  Returns a handle of
    // the caller's join.
    //
    // leave - Leave a join.  Returns a pointer to the underlying memory
    // region. Does not close caller-owned fd passed into join.
    //
    // delete - Unformat a memory region used as a myrec_store.  Returns a
    // pointer to the unformatted memory region.

    ulong           myrec_store_align    ( void );
    ulong           myrec_store_footprint( ulong ele_max, ulong cache_sz, ulong file_len );
    void *          myrec_store_new      ( void * shmem, ulong ele_max, ulong cache_sz, ulong seed,
                                           ulong file_base_off, ulong file_len );
    myrec_store_t * myrec_store_join     ( void * shstore, int fd );
    void *          myrec_store_leave    ( myrec_store_t * join );
    void *          myrec_store_delete   ( void * shstore );

    // append - Insert a new key into the store, reserving footprint
    // bytes (with alignment align) for its value.  Returns a writable
    // pointer for the caller to fill in the value, or NULL on failure.
    // Failure can happen if the key is already in the store, the value
    // is individually larger than cache_sz, or align is not a power of
    // two.

    void * myrec_store_append( myrec_store_t *     join,
                               myrec_key_t const * key,
                               ulong               align,
                               ulong               footprint );

    // get - Query the store for key.  Return a pointer to the value
    // bytes, or NULL if key is not in the store.  If opt_out_sz is
    // non-NULL, the value size is written to *opt_out_sz on success.
    // get_ro returns a read-only pointer; get_mut returns a writable
    // pointer, in which case the caller is free to modify the value
    // bytes in place.  Assumes join is a current join.

    void const * myrec_store_get_ro ( myrec_store_t *       join,
                                      myrec_key_t const *   key,
                                      ulong *               opt_out_sz );
    void *       myrec_store_get_mut( myrec_store_t *       join,
                                      myrec_key_t const *   key,
                                      ulong *               opt_out_sz );

    // Pre-eviction.  Drains internal data structures that are at or
    // above their LOAD_FACTOR high watermark down to their low
    // watermark (LOAD_FACTOR - EVICT_PCT), evicting the oldest entries.
    //
    // This may be called periodically so that the synchronous critical
    // path evicts rarely.  Safe to call any time; a no-op when
    // everything is below its high watermark. Assumes join is a current
    // join.
    //
    // Note: draining the cache writes dirty entries into the disk ring,
    // so a single pre_evict may leave the disk ring above its high
    // watermark; call again if a strict bound is required.

    void myrec_store_pre_evict( myrec_store_t * join );

    // verify - Check that all store invariants hold.  Returns 0 if the
    // store is internally consistent, and -1 otherwise (after an
    // FD_LOG_WARNING describing the first failing invariant).  This is
    // a read-only consistency check (it does not mutate store state,
    // beyond transiently using the circq iteration cursor as scratch)
    // intended to be called periodically while the store is quiescent,
    // i.e. between top-level public API calls.  Assumes join is a
    // current join.

    int myrec_store_verify( myrec_store_t * join );

  Do this as often as desired in a compilation unit to get different
  stores. */

#ifndef GUI_STORE_NAME
#error "need to define GUI_STORE_NAME"
#endif

#ifndef GUI_STORE_KEY_T
#error "need to define GUI_STORE_KEY_T"
#endif

#ifndef GUI_STORE_KEY_HASH
#error "need to define GUI_STORE_KEY_HASH"
#endif

#ifndef GUI_STORE_KEY_EQ
#error "need to define GUI_STORE_KEY_EQ"
#endif

#define GUI_STORE_(n) FD_EXPAND_THEN_CONCAT3(GUI_STORE_NAME,_,n)

#ifndef GUI_STORE_IMPL_STYLE
#define GUI_STORE_IMPL_STYLE 0
#endif

#if GUI_STORE_IMPL_STYLE==0
#define GUI_STORE_STATIC static FD_FN_UNUSED
#else
#define GUI_STORE_STATIC
#endif

/* GUI_STORE_TIER_{MEM/FILE} name the storage tier holding a given
   value.  MEM values live in the embedded fd_circq and are referenced
   by pointer. FILE values live in the on-disk buffer and are referenced
   by byte offset. */

#define GUI_STORE_TIER_MEM  (0U)
#define GUI_STORE_TIER_FILE (1U)

#define GUI_STORE_MAGIC        (0x4753545200000001UL) /* "GSTR" + version */
#define GUI_STORE_VERSION      (1UL)
#define GUI_STORE_SUPERBLOCK_SZ (64UL)

/* Eviction watermarks. TODO derive these better. */

#ifndef GUI_STORE_IDX_LOAD_FACTOR
#define GUI_STORE_IDX_LOAD_FACTOR (50UL)
#endif
#ifndef GUI_STORE_IDX_EVICT_PCT
#define GUI_STORE_IDX_EVICT_PCT (20UL)
#endif

#ifndef GUI_STORE_CACHE_LOAD_FACTOR
#define GUI_STORE_CACHE_LOAD_FACTOR (90UL)
#endif
#ifndef GUI_STORE_CACHE_EVICT_PCT
#define GUI_STORE_CACHE_EVICT_PCT (20UL)
#endif

#ifndef GUI_STORE_DISK_LOAD_FACTOR
#define GUI_STORE_DISK_LOAD_FACTOR (95UL)
#endif
#ifndef GUI_STORE_DISK_EVICT_PCT
#define GUI_STORE_DISK_EVICT_PCT (5UL)
#endif

#include "../../util/log/fd_log.h"          /* failure logs            */
#include "../../util/bits/fd_bits.h"        /* fd_ulong_*, FD_LAYOUT_* */
#include "../../util/circq/fd_circq.h"      /* cache                   */
#include "../../util/io/fd_io.h"            /* fd_io_strerror          */

/* The translation unit that instantiates this template must define
   _GNU_SOURCE (or another macro implying _DEFAULT_SOURCE), since
   pwritev(2) support is required. */
#include <errno.h>                          /* errno                   */
#include <unistd.h>                         /* pread/pwrite/fdatasync  */
#include <sys/uio.h>                        /* pwritev / struct iovec  */
#include <limits.h>                         /* IOV_MAX                 */

#define GUI_STORE_MAX_WRITEBACK_IOV (3UL*FD_CIRCQ_EVICT_BATCH_MAX)
FD_STATIC_ASSERT( GUI_STORE_MAX_WRITEBACK_IOV<=IOV_MAX, gui_store_writeback_iov_fits );

/* On-disk record header. */
struct __attribute__((aligned(8UL))) GUI_STORE_(rechdr) {
  ulong           align;  /* value align                                 */
  ulong           sz;     /* value size in bytes (excludes this header)  */
  GUI_STORE_KEY_T key;    /* full key */
};
typedef struct GUI_STORE_(rechdr) GUI_STORE_(rechdr_t);

/* The per-message cache header.  key lets the evict callback recover
   the map element; seq is a sequence number incremented on every push. */
struct __attribute__((packed,aligned(8UL))) GUI_STORE_(msghdr) {
  GUI_STORE_KEY_T key;
  ulong           seq;
};
typedef struct GUI_STORE_(msghdr) GUI_STORE_(msghdr_t);

struct __attribute__((packed,aligned(8UL))) GUI_STORE_(ele) {
  GUI_STORE_KEY_T key;          /* full composite key, inline (MAP_KEY) */
  uchar *         mem;          /* direct pointer to the value bytes (past the msg header) in the circq; valid iff tier==MEM. */
  ulong           off;          /* on-disk record offset (data-region relative); valid iff has_disk. */
  ulong           sz;           /* value size in bytes (excludes msg header) */
  ulong           seq;          /* seq of the authoritative cache message; valid iff tier==MEM */
  ushort          align;        /* caller's value align; recovers val_off=align_up(hdr_sz,align) at warm/write-back  */
  uint            free     : 1; /* 1 => this ele is unused in the map */
  uint            tier     : 1; /* GUI_STORE_TIER_{MEM,FILE} */
  uint            dirty    : 1; /* 1 => map copy differs from disk */
  uint            has_disk : 1; /* 1 => a disk copy exists at off */
};
typedef struct GUI_STORE_(ele) GUI_STORE_(ele_t);

#define MAP_NAME             GUI_STORE_(map)
#define MAP_ELE_T            GUI_STORE_(ele_t)
#define MAP_KEY_T            GUI_STORE_KEY_T
#define MAP_KEY              key
#define MAP_KEY_HASH(k,seed) GUI_STORE_KEY_HASH( (k), (seed) )
#define MAP_KEY_EQ(k0,k1)    GUI_STORE_KEY_EQ( (k0), (k1) )
#define MAP_ELE_IS_FREE(ele) ( (ele)->free )
#define MAP_ELE_FREE(ctx,ele) do { (void)(ctx); (ele)->free = 1U; } while(0)

/* The default MAP_ELE_MOVE shallow copies and zeroes the moved-from
   key. We need to overwrite it to correctly manage free bit lifetime. */
#define MAP_ELE_MOVE(ctx,dst,src) do { \
    (void)(ctx);                       \
    GUI_STORE_(ele_t) * _src = (src);  \
    *(dst) = *_src;                    \
    _src->free = 1U;                   \
  } while(0)
#include "../../util/tmpl/fd_map_slot.c"

struct GUI_STORE_(private) {
  GUI_STORE_(map_t) map[1];        /* map local join state (lmem)              */
  ulong             seed;          /* hash seed                                */
  ulong             ele_max;       /* map element capacity (power of two)      */
  fd_circq_t *      circq;         /* join to cache fd_circq (caller addr sp.) */
  ulong             cache_sz;      /* embedded circq capacity in bytes         */

  ulong             live_cnt;      /* live index map entries (MEM + FILE); used to drive index pre-eviction watermarks    */

  int               fd;            /* backing file descriptor, -1 if mem-only  */
  ulong             file_base_off; /* file region base byte offset             */
  ulong             file_len;      /* file region length in bytes; 0 => mem    */

  ulong             fhead;         /* file data-region offset of oldest record */
  ulong             ftail;         /* file data-region offset of next write    */
  ulong             fcnt;          /* file record count                        */
  ulong             fbytes;        /* file bytes used                          */
  ulong             fdata_end;     /* upper-segment end; ==data_sz unless a tail gap from a wrap exists. TODO persist in the superblock. */
  ulong             gen;           /* superblock generation                    */

  ulong             msg_seq;       /* monotonic cache-message liveness counter;
                                      next push assigns this value then bumps   */

  int               drop_cache_evictions; /* 1 => The cache evict callback removes (map_remove) evicted entries instead of demoting them to disk.
                                             0 => The cache evict callback copies evicted entries to disk.  */

  /* Write-back coalescing state used by private_evict_cb. */
  GUI_STORE_(rechdr_t) wb_hdr[ FD_CIRCQ_EVICT_BATCH_MAX ];    /* staged record headers */
  struct iovec         wb_iov[ GUI_STORE_MAX_WRITEBACK_IOV ]; /* header + value + pad per record */
  ulong                wb_run_lo;                             /* staged run start (data-region offset) */
  ulong                wb_run_hi;                             /* staged run end   (data-region offset) */
};

typedef struct GUI_STORE_(private) GUI_STORE_(t);

FD_PROTOTYPES_BEGIN

GUI_STORE_STATIC ulong           GUI_STORE_(align)    ( void );
GUI_STORE_STATIC ulong           GUI_STORE_(footprint)( ulong ele_max, ulong cache_sz, ulong file_len );
GUI_STORE_STATIC void *          GUI_STORE_(new)      ( void * shmem, ulong ele_max, ulong cache_sz, ulong seed, ulong file_base_off, ulong file_len );
GUI_STORE_STATIC GUI_STORE_(t) * GUI_STORE_(join)     ( void * shstore, int fd );
GUI_STORE_STATIC void *          GUI_STORE_(leave)    ( GUI_STORE_(t) * join );
GUI_STORE_STATIC void *          GUI_STORE_(delete)   ( void * shstore );

GUI_STORE_STATIC void * GUI_STORE_(append)( GUI_STORE_(t) *         join,
                                            GUI_STORE_KEY_T const * key,
                                            ulong                   align,
                                            ulong                   footprint );

GUI_STORE_STATIC void const * GUI_STORE_(get_ro)( GUI_STORE_(t) *         join,
                                                  GUI_STORE_KEY_T const * key,
                                                  ulong *                 opt_out_sz );

GUI_STORE_STATIC void * GUI_STORE_(get_mut)( GUI_STORE_(t) *         join,
                                             GUI_STORE_KEY_T const * key,
                                             ulong *                 opt_out_sz );

GUI_STORE_STATIC void GUI_STORE_(pre_evict)( GUI_STORE_(t) * join );

GUI_STORE_STATIC int GUI_STORE_(verify)( GUI_STORE_(t) * join );

static void GUI_STORE_(private_evict_cb)( void * ctx, fd_circq_evict_entry_t const * batch, ulong cnt );

static void GUI_STORE_(index_evict_oldest)( GUI_STORE_(t) * store );

static int
GUI_STORE_(pread_all)( int    fd,
                       void * buf,
                       ulong  sz,
                       ulong  off ) {
  uchar * p   = (uchar *)buf;
  ulong   rem = sz;
  while( rem ) {
    long n = pread( fd, p, rem, (long)off );
    if( FD_UNLIKELY( n<0L ) ) {
      if( FD_UNLIKELY( errno==EINTR ) ) continue;
      FD_LOG_WARNING(( "pread failed (%i-%s)", errno, fd_io_strerror( errno ) ));
      return errno;
    }
    if( FD_UNLIKELY( !n ) ) {
      FD_LOG_WARNING(( "pread hit EOF short by %lu bytes", rem ));
      return EIO;
    }
    p   += (ulong)n;
    off += (ulong)n;
    rem -= (ulong)n;
  }
  return 0;
}

static int
GUI_STORE_(pwrite_all)( int          fd,
                        void const * buf,
                        ulong        sz,
                        ulong        off ) {
  uchar const * p   = (uchar const *)buf;
  ulong         rem = sz;
  while( rem ) {
    long n = pwrite( fd, p, rem, (long)off );
    if( FD_UNLIKELY( n<0L ) ) {
      if( FD_UNLIKELY( errno==EINTR ) ) continue;
      FD_LOG_WARNING(( "pwrite failed (%i-%s)", errno, fd_io_strerror( errno ) ));
      return errno;
    }
    if( FD_UNLIKELY( !n ) ) {
      FD_LOG_WARNING(( "pwrite returned 0" ));
      return EIO;
    }
    p   += (ulong)n;
    off += (ulong)n;
    rem -= (ulong)n;
  }
  return 0;
}

/* GUI_STORE_(iov_advance) consumes n bytes from the gathered buffer
   described by iov[*pi..iovcnt), advancing *pi past any iovec fully
   covered by n and trimming iov_base/iov_len of the first partially
   covered iovec.  On return *pi indexes the first not-yet-consumed
   iovec (== iovcnt iff n covered the whole remaining buffer). */
static inline void
GUI_STORE_(iov_advance)( struct iovec * iov,
                         int            iovcnt,
                         int *          pi,
                         ulong          n ) {
  int i = *pi;
  while( n && i<iovcnt ) {
    if( n>=iov[ i ].iov_len ) {
      n -= iov[ i ].iov_len;
      i++;
    } else {
      iov[ i ].iov_base = (uchar *)iov[ i ].iov_base + n;
      iov[ i ].iov_len -= n;
      n = 0UL;
    }
  }
  *pi = i;
}

/* GUI_STORE_(pwritev_all) writes the gathered contents of iov[0..iovcnt)
   to fd starting at byte offset off, handling partial writes (advancing
   into and within the iovec array) and retrying on EINTR.  iov is
   mutated in place. Returns 0 on success or an errno on failure. */
static int
GUI_STORE_(pwritev_all)( int            fd,
                         struct iovec * iov,
                         int            iovcnt,
                         ulong          off ) {
  int i = 0;  /* index of first not-fully-written iovec */
  while( i<iovcnt ) {
    /* Skip empty iovecs. */
    while( i<iovcnt && !iov[ i ].iov_len ) i++;
    if( i>=iovcnt ) break;
    int cnt = iovcnt - i;
    if( FD_UNLIKELY( cnt>IOV_MAX ) ) cnt = IOV_MAX;
    long n = pwritev( fd, iov+i, cnt, (long)off );
    if( FD_UNLIKELY( n<0L ) ) {
      if( FD_UNLIKELY( errno==EINTR ) ) continue;
      FD_LOG_WARNING(( "pwritev failed (%i-%s)", errno, fd_io_strerror( errno ) ));
      return errno;
    }
    if( FD_UNLIKELY( !n ) ) {
      FD_LOG_WARNING(( "pwritev returned 0" ));
      return EIO;
    }
    off += (ulong)n;
    GUI_STORE_(iov_advance)( iov, iovcnt, &i, (ulong)n );
  }
  return 0;
}

static int
GUI_STORE_(file_superblock_write)( GUI_STORE_(t) * store,
                                   ulong           gen ) {
  ulong sb[ GUI_STORE_SUPERBLOCK_SZ / sizeof(ulong) ];
  memset( sb, 0, sizeof(sb) );
  sb[ 0 ] = GUI_STORE_MAGIC;
  sb[ 1 ] = GUI_STORE_VERSION;
  sb[ 2 ] = store->fhead;
  sb[ 3 ] = store->ftail;
  sb[ 4 ] = store->fcnt;
  sb[ 5 ] = gen;
  sb[ 6 ] = sb[ 0 ] ^ sb[ 1 ] ^ sb[ 2 ] ^ sb[ 3 ] ^ sb[ 4 ] ^ sb[ 5 ]; /* checksum */
  return GUI_STORE_(pwrite_all)( store->fd, sb, sizeof(sb), store->file_base_off );
}

/* Lifecycle ********************************************************/

GUI_STORE_STATIC ulong
GUI_STORE_(align)( void ) {
  ulong a = 1UL;
  a = fd_ulong_max( a, alignof(GUI_STORE_(t)) );
  a = fd_ulong_max( a, GUI_STORE_(map_align)() );
  a = fd_ulong_max( a, fd_circq_align() );
  return a;
}

/* GUI_STORE_(file_len_min) is the smallest legal file region: the
   superblock plus room for one maximally-sized record (a header plus a
   value as large as the circq can hold). */
static inline ulong
GUI_STORE_(file_len_min)( ulong cache_sz ) {
  return GUI_STORE_SUPERBLOCK_SZ + sizeof(GUI_STORE_(rechdr_t)) + fd_ulong_align_up( cache_sz, 8UL );
}

GUI_STORE_STATIC ulong
GUI_STORE_(footprint)( ulong ele_max,
                       ulong cache_sz,
                       ulong file_len ) {
  ele_max = fd_ulong_pow2_up( fd_ulong_max( ele_max, 1UL ) );
  ulong map_fp = GUI_STORE_(map_footprint)( ele_max );
  if( FD_UNLIKELY( !map_fp ) ) return 0UL;

  if( file_len && FD_UNLIKELY( file_len<GUI_STORE_(file_len_min)( cache_sz ) ) ) {
    FD_LOG_WARNING(( "file_len %lu too small (need >= %lu)", file_len, GUI_STORE_(file_len_min)( cache_sz ) ));
    return 0UL;
  }

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(GUI_STORE_(t)),    sizeof(GUI_STORE_(t))          );
  l = FD_LAYOUT_APPEND( l, GUI_STORE_(map_align)(),   map_fp                         );
  l = FD_LAYOUT_APPEND( l, fd_circq_align(),          fd_circq_footprint( cache_sz ) );
  return FD_LAYOUT_FINI( l, GUI_STORE_(align)() );
}

GUI_STORE_STATIC void *
GUI_STORE_(new)( void * shmem,
                 ulong  ele_max,
                 ulong  cache_sz,
                 ulong  seed,
                 ulong  file_base_off,
                 ulong  file_len ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, GUI_STORE_(align)() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  ele_max = fd_ulong_pow2_up( fd_ulong_max( ele_max, 1UL ) );
  ulong map_fp = GUI_STORE_(map_footprint)( ele_max );
  if( FD_UNLIKELY( !map_fp ) ) {
    FD_LOG_WARNING(( "bad ele_max" ));
    return NULL;
  }

  if( file_len && FD_UNLIKELY( file_len<GUI_STORE_(file_len_min)( cache_sz ) ) ) {
    FD_LOG_WARNING(( "file_len %lu too small (need >= %lu)", file_len, GUI_STORE_(file_len_min)( cache_sz ) ));
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  GUI_STORE_(t) *     store = FD_SCRATCH_ALLOC_APPEND( l, alignof(GUI_STORE_(t)),  sizeof(GUI_STORE_(t))          );
  void *              ele0  = FD_SCRATCH_ALLOC_APPEND( l, GUI_STORE_(map_align)(), map_fp                         );
  void *              cq    = FD_SCRATCH_ALLOC_APPEND( l, fd_circq_align(),        fd_circq_footprint( cache_sz ) );
  FD_SCRATCH_ALLOC_FINI( l, GUI_STORE_(align)() );

  GUI_STORE_(ele_t) * eles = GUI_STORE_(map_new)( ele0, ele_max, 0 );
  if( FD_UNLIKELY( !eles ) ) {
    FD_LOG_WARNING(( "map new failed" ));
    return NULL;
  }
  for( ulong i=0UL; i<ele_max; i++ ) eles[ i ].free = 1U; /* Set free bit */

  if( FD_UNLIKELY( !fd_circq_new( cq, cache_sz ) ) ) {
    FD_LOG_WARNING(( "circq new failed" ));
    return NULL;
  }

  store->circq         = NULL;
  store->seed          = seed;
  store->ele_max       = ele_max;
  store->cache_sz      = cache_sz;

  store->fd            = -1;
  store->file_base_off = file_len ? file_base_off : 0UL;
  store->file_len      = file_len;

  store->fhead         = 0UL;
  store->ftail         = 0UL;
  store->fcnt          = 0UL;
  store->fbytes        = 0UL;
  store->fdata_end     = file_len ? file_len - GUI_STORE_SUPERBLOCK_SZ : 0UL;
  store->gen           = 0UL;
  store->msg_seq       = 0UL;
  store->live_cnt       = 0UL;

  store->drop_cache_evictions = 0;

  return shmem;
}

GUI_STORE_STATIC GUI_STORE_(t) *
GUI_STORE_(join)( void * shstore,
                  int    fd ) {
  if( FD_UNLIKELY( !shstore ) ) {
    FD_LOG_WARNING(( "NULL shstore" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shstore, GUI_STORE_(align)() ) ) ) {
    FD_LOG_WARNING(( "misaligned shstore" ));
    return NULL;
  }

  GUI_STORE_(t) * store = (GUI_STORE_(t) *)shstore;

  if( FD_UNLIKELY( store->file_len && fd<0 ) ) {
    FD_LOG_ERR(( FD_EXPAND_THEN_STRINGIFY( GUI_STORE_(new) ) " used file_len!=0; "
                 FD_EXPAND_THEN_STRINGIFY( GUI_STORE_(join) ) " requires a valid fd" ));
  }
  if( FD_UNLIKELY( !store->file_len && fd>=0 ) ) {
    FD_LOG_ERR(( FD_EXPAND_THEN_STRINGIFY( GUI_STORE_(new) ) " used file_len=0; "
                 FD_EXPAND_THEN_STRINGIFY( GUI_STORE_(join) ) " requires fd<0" ));
  }

  FD_SCRATCH_ALLOC_INIT( l, shstore );
  /**/                       FD_SCRATCH_ALLOC_APPEND( l, alignof(GUI_STORE_(t)),  sizeof(GUI_STORE_(t))                       );
  void *              ele0 = FD_SCRATCH_ALLOC_APPEND( l, GUI_STORE_(map_align)(), GUI_STORE_(map_footprint)( store->ele_max ) );
  void *              cq   = FD_SCRATCH_ALLOC_APPEND( l, fd_circq_align(),        fd_circq_footprint( store->cache_sz )       );
  FD_SCRATCH_ALLOC_FINI( l, GUI_STORE_(align)() );

  if( FD_UNLIKELY( !GUI_STORE_(map_join)( store->map, ele0, store->ele_max, GUI_STORE_(map_probe_max_est)( store->ele_max ), store->seed ) ) ) {
    FD_LOG_WARNING(( "map join failed" ));
    return NULL;
  }

  store->circq = fd_circq_join( cq );
  if( FD_UNLIKELY( !store->circq ) ) {
    FD_LOG_WARNING(( "circq join failed" ));
    GUI_STORE_(map_leave)( store->map );
    return NULL;
  }

  fd_circq_set_batch_evict_cb( store->circq, GUI_STORE_(private_evict_cb), store );

  if( FD_UNLIKELY( fd<0 ) ) {
    store->fd = -1;
    return store;
  }

  /* TODO: joining persisted file on restart */
  store->fd = fd;
  if( FD_UNLIKELY( GUI_STORE_(file_superblock_write)( store, store->gen ) ) ) {
    FD_LOG_WARNING(( "superblock write failed" ));
    fd_circq_set_batch_evict_cb( store->circq, NULL, NULL );
    fd_circq_leave( store->circq );
    store->circq = NULL;
    GUI_STORE_(map_leave)( store->map );
    return NULL;
  }

  return store;
}

GUI_STORE_STATIC void *
GUI_STORE_(leave)( GUI_STORE_(t) * join ) {
  if( FD_UNLIKELY( !join ) ) {
    FD_LOG_WARNING(( "NULL join" ));
    return NULL;
  }

  fd_circq_leave( join->circq );
  join->circq = NULL;
  join->fd    = -1; /* caller owns the fd; do not close it */
  GUI_STORE_(map_leave)( join->map );

  return (void *)join;
}

GUI_STORE_STATIC void *
GUI_STORE_(delete)( void * shstore ) {
  if( FD_UNLIKELY( !shstore ) ) {
    FD_LOG_WARNING(( "NULL shstore" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shstore, GUI_STORE_(align)() ) ) ) {
    FD_LOG_WARNING(( "misaligned shstore" ));
    return NULL;
  }

  return shstore;
}

/* append / get ******************************************************/

GUI_STORE_STATIC void *
GUI_STORE_(append)( GUI_STORE_(t) *         join,
                    GUI_STORE_KEY_T const * key,
                    ulong                   align,
                    ulong                   footprint ) {
  if( FD_UNLIKELY( !fd_ulong_is_pow2( align ) ) ) {
    FD_LOG_WARNING(( "align is not a power of two" ));
    return NULL;
  }

  /* A key that already exists is not supported by the API */
  if( FD_UNLIKELY( GUI_STORE_(map_query)( join->map, key ) ) ) return NULL;

  ulong hdr_sz    = sizeof(GUI_STORE_(msghdr_t));
  ulong val_off   = fd_ulong_align_up( hdr_sz, align ); /* header + pad, base-relative */
  ulong msg_fp    = val_off + footprint;
  ulong msg_align = fd_ulong_max( alignof(GUI_STORE_(msghdr_t)), align );

  /* Push the value into the cache first, which may fire the eviction
     callback synchronously updating the index.  Because we hold no map
     element pointer here, the relocation is harmless. */
  uchar * base = fd_circq_push_back( join->circq, msg_align, msg_fp );
  if( FD_UNLIKELY( !base ) ) {
    FD_LOG_WARNING(( "value too large for circq (msg footprint %lu)", msg_fp ));
    return NULL;
  }

  /* Stamp a valid header immediately: the message now exists in the
     cache regardless of whether the index insert succeeds.  If the
     insert fails this slot becomes an orphan, but with a real header
     its seq matches no live element, so the eviction callback and
     verify correctly treat it as stale. */
  ulong seq = join->msg_seq++;
  GUI_STORE_(msghdr_t) mhdr;
  fd_memcpy( &mhdr.key, key, sizeof(GUI_STORE_KEY_T) );
  mhdr.seq = seq;
  fd_memcpy( base, &mhdr, hdr_sz );

  GUI_STORE_(ele_t) * ele = GUI_STORE_(map_insert)( join->map, key );
  if( FD_UNLIKELY( !ele ) ) {
    /* Slow eviction path: the map has no free probe slot for this key. */
    GUI_STORE_(index_evict_oldest)( join );
    ele = GUI_STORE_(map_insert)( join->map, key );
  }
  if( FD_UNLIKELY( !ele ) ) {
    FD_LOG_WARNING(( "index too full to seat key (msg footprint %lu)", msg_fp ));
    return NULL;
  }

  join->live_cnt++;

  uchar * val = base + val_off;

  ele->mem      = val;
  ele->sz       = footprint;
  ele->off      = 0UL;
  ele->seq      = seq;
  ele->align    = (ushort)align;
  ele->free     = 0U;
  ele->tier     = GUI_STORE_TIER_MEM;
  ele->dirty    = 1U; /* A fresh insert is dirty */
  ele->has_disk = 0U;

  return (void *)val;
}

/* GUI_STORE_(warm) brings a FILE element's value back into the cache and
   sets dirty=0.  Returns a pointer to the value bytes in the cache.
   *out_ele is set to the re-resolved index element. */

static uchar *
GUI_STORE_(warm)( GUI_STORE_(t) *         join,
                  GUI_STORE_KEY_T const * key,
                  GUI_STORE_(ele_t) *     ele,
                  GUI_STORE_(ele_t) **    out_ele ) {
  ulong hdr_sz    = sizeof(GUI_STORE_(msghdr_t));
  ulong align     = (ulong)ele->align;
  ulong sz        = ele->sz;
  ulong off       = ele->off;
  ulong val_off   = fd_ulong_align_up( hdr_sz, align );
  ulong msg_fp    = val_off + sz;
  ulong msg_align = fd_ulong_max( alignof(GUI_STORE_(msghdr_t)), align );

  if( FD_UNLIKELY( !ele->has_disk ) ) FD_LOG_ERR(( "warm of FILE element with no disk copy" ));

  uchar * base = fd_circq_push_back( join->circq, msg_align, msg_fp );
  if( FD_UNLIKELY( !base ) ) FD_LOG_ERR(( "warm push_back failed: value larger than circq" ));

  /* Write the msg header.  The disk record at off is left intact: a
     later dirty write-back goes back into the same spot on disk. */
  ulong seq = join->msg_seq++;
  GUI_STORE_(msghdr_t) mhdr;
  fd_memcpy( &mhdr.key, key, sizeof(GUI_STORE_KEY_T) );
  mhdr.seq = seq;
  fd_memcpy( base, &mhdr, hdr_sz );
  uchar * val = base + val_off;

  ulong rec_off = join->file_base_off + GUI_STORE_SUPERBLOCK_SZ + off + sizeof(GUI_STORE_(rechdr_t));
  if( FD_UNLIKELY( GUI_STORE_(pread_all)( join->fd, val, sz, rec_off ) ) ) {
    FD_LOG_ERR(( "warm pread failed" ));
  }

  /* Evicting dirty entries to disk can wrap the disk ring and drop the
     oldest disk record -- possibly this very key's -- so it may no
     longer be in the index.  Treat that as not-found. */
  GUI_STORE_(ele_t) * s = GUI_STORE_(map_update)( join->map, key );
  if( FD_UNLIKELY( !s ) ) { *out_ele = NULL; return NULL; }

  s->mem   = val;
  s->seq   = seq;
  s->tier  = GUI_STORE_TIER_MEM;
  s->dirty = 0U; /* warm-in is clean */
  /* off / has_disk preserved */

  *out_ele = s;
  return val;
}

GUI_STORE_STATIC void const *
GUI_STORE_(get_ro)( GUI_STORE_(t) *         join,
                    GUI_STORE_KEY_T const * key,
                    ulong *                 opt_out_sz ) {
  GUI_STORE_(ele_t) * ele = GUI_STORE_(map_update)( join->map, key );
  if( FD_UNLIKELY( !ele ) ) return NULL;

  if( opt_out_sz ) *opt_out_sz = ele->sz;

  if( FD_LIKELY( ele->tier==GUI_STORE_TIER_MEM ) ) return (void const *)ele->mem;

  if( FD_UNLIKELY( !join->file_len ) ) FD_LOG_ERR(( "Encountered FILE element in a mem-only store" ));

  GUI_STORE_(ele_t) * warmed = NULL;
  return (void const *)GUI_STORE_(warm)( join, key, ele, &warmed );
}

GUI_STORE_STATIC void *
GUI_STORE_(get_mut)( GUI_STORE_(t) *         join,
                     GUI_STORE_KEY_T const * key,
                     ulong *                 opt_out_sz ) {
  /* map_update returns a mutable element so we can set the dirty bit. */
  GUI_STORE_(ele_t) * ele = GUI_STORE_(map_update)( join->map, key );
  if( FD_UNLIKELY( !ele ) ) return NULL;

  if( FD_LIKELY( opt_out_sz ) ) *opt_out_sz = ele->sz;

  if( FD_LIKELY( ele->tier==GUI_STORE_TIER_MEM ) ) {
    ele->dirty = 1U;
    return (void *)ele->mem;
  }

  if( FD_UNLIKELY( !join->file_len ) ) FD_LOG_ERR(( "FILE element in a mem-only store" ));

  GUI_STORE_(ele_t) * warmed = NULL;
  uchar * val = GUI_STORE_(warm)( join, key, ele, &warmed );
  if( FD_UNLIKELY( !warmed ) ) return NULL; /* self-evicted during warm */
  warmed->dirty = 1U;
  return (void *)val;
}

FD_PROTOTYPES_END

/* The on-disk ring is a FIFO of variable-size records living in the
   data region [0,data_sz).  Its state is fully described by:

     fcnt      number of live records (0 => empty, the unambiguous
               empty/full discriminator),
     fbytes    sum of live record footprints (never counts the gap),
     fhead     offset of the oldest record,
     ftail     offset where the next record will be written,
     fdata_end one past the last byte the upper run uses; equals data_sz
               unless a wrap left a tail gap [fdata_end,data_sz).

   Records are written contiguously and never straddle data_sz.  The live
   bytes therefore occupy, in physical order, either one run [fhead,ftail)
   (when fhead<ftail, or the lone full case) or two runs
   [fhead,fdata_end) and [0,ftail) (when the ring wraps).  All occupancy
   decisions are driven by fcnt/fbytes, not by comparing fhead to ftail
   (which is ambiguous when they are equal). */

/* GUI_STORE_(disk_record_fp) reads the record header at data-region
   offset off and returns its 8-byte-aligned total footprint. */
static ulong
GUI_STORE_(disk_record_fp)( GUI_STORE_(t) * store,
                            ulong           off,
                            GUI_STORE_(rechdr_t) * out_hdr ) {
  ulong hdr_off = store->file_base_off + GUI_STORE_SUPERBLOCK_SZ + off;
  if( FD_UNLIKELY( GUI_STORE_(pread_all)( store->fd, out_hdr, sizeof(*out_hdr), hdr_off ) ) ) {
    FD_LOG_ERR(( "disk record header read failed" ));
  }
  return fd_ulong_align_up( sizeof(GUI_STORE_(rechdr_t)) + out_hdr->sz, 8UL );
}

/* GUI_STORE_(disk_drop_oldest_record) drops the single oldest live
   on-disk record (the one at fhead): it reads the victim header, removes
   the victim's index element, advances fhead past it (wrapping at
   fdata_end), and decrements fcnt/fbytes.  When the ring becomes empty
   it is reset (fhead=ftail=0, fdata_end=data_sz).  Assumes fcnt>0.

   A disk eviction evicts the key from EVERYWHERE: the element is removed
   even if the value is currently warmed into the cache.  It is left in
   the cache as a stale orphan and no-op'd by the seq check in
   private_evict_cb when it is later popped. */
static void
GUI_STORE_(disk_drop_oldest_record)( GUI_STORE_(t) * store ) {
  ulong data_sz = store->file_len - GUI_STORE_SUPERBLOCK_SZ;
  ulong vhead   = store->fhead;

  GUI_STORE_(rechdr_t) vhdr;
  ulong vfp = GUI_STORE_(disk_record_fp)( store, vhead, &vhdr );

  GUI_STORE_(ele_t) * vele = GUI_STORE_(map_update)( store->map, &vhdr.key );
  if( FD_LIKELY( vele && vele->has_disk && vele->off==vhead ) ) {
    GUI_STORE_(map_remove)( store->map, vele );
    store->live_cnt--;
  }

  store->fcnt--;
  store->fbytes -= vfp;

  if( FD_UNLIKELY( !store->fcnt ) ) { /* ring empty; reset to canonical buffer */
    store->fhead     = 0UL;
    store->ftail     = 0UL;
    store->fdata_end = data_sz;
    return;
  }

  /* Advance past end of the file.  Reclaim any padding added to the end
     during a wrap. */
  ulong vnext = vhead + vfp;
  if( FD_UNLIKELY( vnext>=store->fdata_end ) ) {
    vnext            = 0UL;
    store->fdata_end = data_sz;
  }
  store->fhead = vnext;
}

/* GUI_STORE_RESERVE_FAIL is the sentinel offset returned by
   GUI_STORE_(disk_ring_reserve) when the reservation cannot proceed.
   ULONG_MAX is never a valid data-region offset. */
#define GUI_STORE_RESERVE_FAIL (ULONG_MAX)

/* GUI_STORE_(disk_ring_reserve) reserves enough space on disk for
   appending one record [align|sz|key|value] at the tail -- wrapping and
   dropping older live records as needed -- without issuing any disk I/O.
   On success it fills *out_hdr with the record header, sets *opt_footprint
   (if given) to the record's total footprint, and returns the data-region
   offset at which the record's bytes belong.

   The reservation fails (returns GUI_STORE_RESERVE_FAIL, mutating no
   state) when making room would require dropping (or reading the header
   of) a record that is still only staged in the caller's pending
   write-back run -- i.e. an offset in [wb_run_lo,wb_run_hi) whose bytes
   are not on disk yet.  The caller must flush its run (clearing the
   pending span) and reserve again.  This only happens when the cache is
   small enough that a single batch wraps onto its own not-yet-written
   records.

   Evicting can relocate map elements, so a caller holding an element
   pointer must re-resolve it after this returns. */
static ulong
GUI_STORE_(disk_ring_reserve)( GUI_STORE_(t) *         store,
                               GUI_STORE_KEY_T const * key,
                               ulong                   align,
                               ulong                   sz,
                               GUI_STORE_(rechdr_t) *  out_hdr,
                               ulong *                 opt_footprint ) {
  ulong data_sz = store->file_len - GUI_STORE_SUPERBLOCK_SZ;
  ulong rec_fp  = fd_ulong_align_up( sizeof(GUI_STORE_(rechdr_t)) + sz, 8UL );

  /* Choose the slot.  A record never straddles data_sz, so if it does
     not fit in the contiguous run [ftail,data_sz) the tail wraps to 0
     and [ftail,data_sz) becomes an abandoned gap.  rec_off is the
     chosen start; gap_lo marks the start of the abandoned tail
     (==data_sz when not wrapping, so the gap is empty). */
  int   wrap    = ( store->fcnt && store->ftail + rec_fp > data_sz );
  ulong rec_off = wrap ? 0UL : store->ftail;
  ulong rec_end = rec_off + rec_fp;
  ulong gap_lo  = wrap ? store->ftail : data_sz;

  /* Drop the oldest records until neither the new slot [rec_off,rec_end)
     nor the abandoned tail [gap_lo,data_sz) contains any live record.
     Records are scanned oldest-first from fhead and compared as concrete
     byte ranges (unambiguous).  Terminates because each drop frees bytes
     and the slot fits in data_sz (guaranteed by file_len_min). */
  while( store->fcnt ) {
    ulong voff = store->fhead;

    if( FD_UNLIKELY( store->wb_run_hi>store->wb_run_lo && voff>=store->wb_run_lo && voff<store->wb_run_hi ) ) {
      return GUI_STORE_RESERVE_FAIL;
    }

    GUI_STORE_(rechdr_t) vhdr;
    ulong vfp = GUI_STORE_(disk_record_fp)( store, voff, &vhdr );
    int   hits_slot = ( rec_off<voff+vfp && voff<rec_end );
    int   hits_gap  = ( gap_lo <voff+vfp && voff<data_sz );
    if( FD_LIKELY( !hits_slot && !hits_gap ) ) break;
    GUI_STORE_(disk_drop_oldest_record)( store );
  }

  /* If this reservation wraps, freeze the upper run end at the abandoned
     tail (creating the gap) before moving the tail to 0. */
  if( FD_UNLIKELY( wrap ) ) store->fdata_end = store->ftail;

  memset( out_hdr, 0, sizeof(*out_hdr) );
  out_hdr->align = align;
  out_hdr->sz    = sz;
  fd_memcpy( &out_hdr->key, key, sizeof(GUI_STORE_KEY_T) );

  ulong new_tail = rec_off + rec_fp;
  if( FD_UNLIKELY( !store->fcnt ) ) store->fhead = rec_off; /* first record */
  store->fcnt++;
  store->fbytes += rec_fp;

  /* A record that fills exactly to data_sz leaves no gap and the next
     write wraps to 0; normalize ftail so it is always a valid offset. */
  int exact_fill = ( new_tail==data_sz );
  store->ftail = exact_fill ? 0UL : new_tail;

  /* No gap exists while the live region is one contiguous run that
     reaches the buffer end -- i.e. it does not wrap, or it wraps only
     because the last record filled exactly to data_sz. Reclaim any
     stale gap here. */
  if( new_tail>store->fhead || exact_fill ) store->fdata_end = data_sz;

  if( opt_footprint ) *opt_footprint = rec_fp;
  return rec_off;
}

/* GUI_STORE_(disk_ring_writeback_inplace) writes a record with an
   already-existing disk reservation back to disk.

   Values are not resizable, so the slot footprint is unchanged; only the
   value bytes are rewritten (the header at off is already correct). */
static void
GUI_STORE_(disk_ring_writeback_inplace)( GUI_STORE_(t) * store,
                                         ulong           off,
                                         ulong           sz,
                                         uchar const *   val ) {
  ulong val_off = store->file_base_off + GUI_STORE_SUPERBLOCK_SZ + off + sizeof(GUI_STORE_(rechdr_t));
  if( FD_UNLIKELY( GUI_STORE_(pwrite_all)( store->fd, val, sz, val_off ) ) ) {
    FD_LOG_ERR(( "in-place write-back value pwrite failed" ));
  }
}

/* Eviction callback.  Invoked immediately before a contiguous run of
   messages is dropped from the front of the circq (from inside
   fd_circq_push_back).

   drop_cache_evictions=0
     Dirty values are written back to disk before the value is evicted.
     Note that disk may itself wrap and drop older live records, which
     then trigger further cache evictions, so this function is
     reentrant-safe. Clean entries already have a byte-identical copy on
     disk, so nothing is written back.

   drop_cache_evictions=1
     Value and index element are removed without being written to disk.
     This mode is an optimization used when we're deliberately dropping
     an entry from the index. We don't want to write an evicted copy to
     disk only to have to clean it up right after.

   If the store is not file-backed evictions are dropped. This callback
   must not push to or otherwise mutate the circq.  It may pwrite/pread
   and map_update/map_remove. */
static void
GUI_STORE_(private_evict_cb)( void *                         ctx,
                              fd_circq_evict_entry_t const * batch,
                              ulong                          cnt ) {
  GUI_STORE_(t) * store = (GUI_STORE_(t) *)ctx;

  /* Consecutive fresh appends form one contiguous span.  We flush all
     the collected headers and values with a single gathered pwritev.
     The run is broken (flushed) whenever a reservation reports it is no
     longer contiguous (i.e. ring wrap).

     A batch holds at most FD_CIRCQ_EVICT_BATCH_MAX entries, so at most
     that many records (up to 3 iovecs each) are ever staged at once.  The
     staging arrays live in the context (store->wb_*) to keep this
     eviction-path stack frame small regardless of the batch size. */

  GUI_STORE_(rechdr_t) * run_hdr    = store->wb_hdr; /* stable header storage */
  struct iovec *         run_iov    = store->wb_iov; /* header + value + pad per record */
  int                    run_iovcnt = 0;
  ulong                  run_base   = 0UL; /* file byte offset of first staged record */
  ulong                  run_end    = 0UL; /* file byte offset just past the staged run */
  ulong                  run_recs   = 0UL; /* staged record (header) count */

  store->wb_run_lo = store->wb_run_hi = 0UL; /* nothing staged yet */

  /* Zero source for trailing record padding */
  static uchar const GUI_STORE_(zero_pad)[ 8 ] = { 0 };

# define FLUSH_RUN() do { \
  if( run_iovcnt ) { \
    if( FD_UNLIKELY( GUI_STORE_(pwritev_all)( store->fd, run_iov, run_iovcnt, run_base ) ) ) { \
      FD_LOG_ERR(( "write-back pwritev failed" )); \
    } \
    run_iovcnt = 0; \
    run_recs   = 0UL; \
  } \
  store->wb_run_lo = store->wb_run_hi = 0UL; /* staged bytes are now on disk */ \
  } while(0)

  for( ulong i=0UL; i<cnt; i++ ) {
    GUI_STORE_(msghdr_t) mhdr;
    fd_memcpy( &mhdr, batch[ i ].payload, sizeof(mhdr) );

    GUI_STORE_(ele_t) * ele = GUI_STORE_(map_update)( store->map, &mhdr.key );
    if( FD_UNLIKELY( !ele ) ) continue; /* orphan (e.g. failed append) */

    /* Skip stale entries (records with an old seq). */
    if( FD_UNLIKELY( ele->tier!=GUI_STORE_TIER_MEM || ele->seq!=mhdr.seq ) ) continue;

    /* Drop without writeback */
    if( !store->file_len || store->drop_cache_evictions ) {
      FLUSH_RUN();
      GUI_STORE_(map_remove)( store->map, ele );
      store->live_cnt--;
      continue;
    }

    if( FD_LIKELY( ele->dirty ) ) {
      /* Snapshot the fields we need before any disk_ring_reserve below:
         reserve can evict and relocate map elements, invalidating ele. */
      ulong align   = (ulong)ele->align;
      ulong sz      = ele->sz;
      ulong val_off = fd_ulong_align_up( sizeof(GUI_STORE_(msghdr_t)), align );
      uchar const * val = batch[ i ].payload + val_off;

      if( FD_UNLIKELY( ele->has_disk ) ) {
        /* Dirty writeback to disk */
        FLUSH_RUN();
        GUI_STORE_(disk_ring_writeback_inplace)( store, ele->off, sz, val );
        ele->tier  = GUI_STORE_TIER_FILE;
        ele->dirty = 0U;
        /* off / has_disk preserved */
      } else {
        /* Append to disk. */
        GUI_STORE_(rechdr_t) hdr;
        ulong rec_fp;
        ulong rec_off = GUI_STORE_(disk_ring_reserve)( store, &mhdr.key, align, sz, &hdr, &rec_fp );
        if( FD_UNLIKELY( rec_off==GUI_STORE_RESERVE_FAIL ) ) {
          FLUSH_RUN(); /* free the pending span, then the reserve succeeds */
          rec_off = GUI_STORE_(disk_ring_reserve)( store, &mhdr.key, align, sz, &hdr, &rec_fp );
        }
        ulong base_off = store->file_base_off + GUI_STORE_SUPERBLOCK_SZ + rec_off;
        ulong pad      = rec_fp - sizeof(GUI_STORE_(rechdr_t)) - sz;

        /* Coalesce into the current run only if this record's bytes
           start exactly where the last record ends */
        if( FD_UNLIKELY( run_iovcnt && base_off!=run_end ) ) FLUSH_RUN();
        if( FD_UNLIKELY( !run_iovcnt ) ) { run_base = base_off; store->wb_run_lo = rec_off; }
        run_end          = base_off + rec_fp;
        store->wb_run_hi = rec_off + rec_fp;

        run_hdr[ run_recs ] = hdr;
        run_iov[ run_iovcnt ].iov_base = &run_hdr[ run_recs ];
        run_iov[ run_iovcnt ].iov_len  = sizeof(GUI_STORE_(rechdr_t));
        run_iovcnt++;
        run_iov[ run_iovcnt ].iov_base = (void *)val;
        run_iov[ run_iovcnt ].iov_len  = sz;
        run_iovcnt++;
        if( pad ) {
          run_iov[ run_iovcnt ].iov_base = (void *)GUI_STORE_(zero_pad);
          run_iov[ run_iovcnt ].iov_len  = pad;
          run_iovcnt++;
        }
        run_recs++;

        /* The reserve may have dropped (and thus map_removed) other
           elements, relocating map elements.  Re-resolve this element
           before updating it. */
        GUI_STORE_(ele_t) * s = GUI_STORE_(map_update)( store->map, &mhdr.key );
        if( FD_UNLIKELY( !s ) ) FD_LOG_ERR(( "evicted dirty element vanished during write-back" ));

        s->off      = rec_off;
        s->tier     = GUI_STORE_TIER_FILE;
        s->dirty    = 0U;
        s->has_disk = 1U;
      }
    } else {
      /* A byte-identical disk copy already exists. Demote to FILE
         pointing at that existing record. */
      if( FD_UNLIKELY( !ele->has_disk ) ) {
        FD_LOG_ERR(( "clean mem eviction with no disk copy" ));
      }
      ele->tier = GUI_STORE_TIER_FILE;
      /* dirty already 0; off / has_disk preserved. */
    }
  }

  FLUSH_RUN();
# undef FLUSH_RUN
}

/* GUI_STORE_(cache_pop_oldest) pops up to n oldest cache (fd_circq)
   messages from the front.  Returns the number of messages actually
   popped (!=n if the cache had <n message to begin with). */
static ulong
GUI_STORE_(cache_pop_oldest)( GUI_STORE_(t) * store,
                              ulong           n ) {
  if( FD_UNLIKELY( !n ) ) return 0UL;

  fd_circq_reset_cursor( store->circq );

  ulong m        = 0UL;
  ulong last_seq = 0UL;
  int   has_any  = 0;
  for( ulong i=0UL; i<n; i++ ) {
    ulong msg_sz = 0UL;
    if( FD_UNLIKELY( !fd_circq_cursor_advance( store->circq, &msg_sz ) ) ) break;
    last_seq = fd_circq_cursor( store->circq ) - 1UL; /* this msg's seq */
    has_any  = 1;
    m++;
  }
  if( FD_LIKELY( has_any ) ) fd_circq_pop_until( store->circq, last_seq );

  return m;
}

/* GUI_STORE_(index_evict_oldest) frees a single map element by dropping
   the oldest live entry.  Prefers dropping the oldest disk record; if
   there are none it drops the oldest cache entry. */
static void
GUI_STORE_(index_evict_oldest)( GUI_STORE_(t) * store ) {
  ulong before = store->live_cnt;

  /* Drain the disk FIFO oldest-first until a live slot is freed. */
  while( store->fcnt ) {
    GUI_STORE_(disk_drop_oldest_record)( store );
    if( FD_LIKELY( store->live_cnt<before ) ) return;
  }

  /* No disk records -- fall back to popping the oldest cache entries
     one at a time, stopping the instant a slot is reclaimed. */
  int saved = store->drop_cache_evictions;
  store->drop_cache_evictions = 1;
  while( store->live_cnt==before ) {
    if( FD_UNLIKELY( !GUI_STORE_(cache_pop_oldest)( store, 1UL ) ) ) break; /* cache empty */
  }
  store->drop_cache_evictions = saved;
}

/* GUI_STORE_(pre_evict) is the public batched pre-eviction entry point.
   It drains each data structure that is at or above its high watermark
   (LOAD_FACTOR) down to its low watermark (LOAD_FACTOR-EVICT_PCT),
   evicting the OLDEST entries.  Data structures are processed bottom-up
   (disk -> cache -> index). A no-op when every resource is below its
   high watermark. */
GUI_STORE_STATIC void
GUI_STORE_(pre_evict)( GUI_STORE_(t) * store ) {
  if( FD_LIKELY( store->file_len ) ) {
    ulong data_sz = store->file_len - GUI_STORE_SUPERBLOCK_SZ;
    ulong hi      = (data_sz*GUI_STORE_DISK_LOAD_FACTOR)/100UL;
    ulong drain   = (data_sz*GUI_STORE_DISK_EVICT_PCT  )/100UL;
    ulong lo      = hi>drain ? hi-drain : 0UL;
    if( FD_UNLIKELY( store->fbytes>=hi ) ) {
      while( store->fbytes>lo && store->fcnt ) {
        GUI_STORE_(disk_drop_oldest_record)( store );
      }
    }
  }

  {
    ulong size  = store->cache_sz;
    ulong hi    = (size*GUI_STORE_CACHE_LOAD_FACTOR)/100UL;
    ulong drain = (size*GUI_STORE_CACHE_EVICT_PCT  )/100UL;
    ulong lo    = hi>drain ? hi-drain : 0UL;
    if( FD_UNLIKELY( fd_circq_bytes_used( store->circq )>=hi ) ) {
      while( fd_circq_bytes_used( store->circq )>lo ) {
        if( FD_UNLIKELY( !GUI_STORE_(cache_pop_oldest)( store, FD_CIRCQ_EVICT_BATCH_MAX ) ) ) break;
      }
    }
  }

  {
    ulong ele_max = store->ele_max;
    ulong hi      = (ele_max*GUI_STORE_IDX_LOAD_FACTOR)/100UL;
    ulong drain   = (ele_max*GUI_STORE_IDX_EVICT_PCT  )/100UL;
    ulong lo      = hi>drain ? hi-drain : 0UL;
    if( FD_UNLIKELY( store->live_cnt>=hi ) ) {
      while( store->live_cnt>lo && store->fcnt ) {
        GUI_STORE_(disk_drop_oldest_record)( store );
      }
      if( FD_LIKELY( store->live_cnt>lo ) ) {
        int saved = store->drop_cache_evictions;
        store->drop_cache_evictions = 1;
        while( store->live_cnt>lo ) {
          ulong want = store->live_cnt - lo;
          if( FD_UNLIKELY( !GUI_STORE_(cache_pop_oldest)( store, want ) ) ) break; /* cache empty */
        }
        store->drop_cache_evictions = saved;
      }
    }
  }
}

/* GUI_STORE_(verify) checks every store invariant and returns 0 if all
   of them hold, or -1 (after logging the first failing invariant) if any
   does not.  It is a read-only consistency check meant to be called while
   the store is quiescent (between top-level public API calls).  It does
   not mutate store state; it does walk the circq iteration cursor (which
   is scratch shared with the eviction drains) and resets it on return. */
GUI_STORE_STATIC int
GUI_STORE_(verify)( GUI_STORE_(t) * store ) {

# define VERIFY_TEST(c) do { if( FD_UNLIKELY( !(c) ) ) { FD_LOG_WARNING(( "FAIL: %s", #c )); return -1; } } while(0)

  VERIFY_TEST( store );

  /* Static layout invariants */

  VERIFY_TEST( (GUI_STORE_SUPERBLOCK_SZ % 8UL)==0UL                  );
  VERIFY_TEST( GUI_STORE_SUPERBLOCK_SZ >= 7UL*sizeof(ulong)          );
  VERIFY_TEST( (sizeof(GUI_STORE_(rechdr_t)) % 8UL)==0UL             );

  /* Map structural integrity (unique keys -> unique slots, bounded
     probe length).  Do this first so subsequent map_query lookups are
     trustworthy. */

  VERIFY_TEST( !GUI_STORE_(map_verify)( store->map ) );

  GUI_STORE_(ele_t) const * eles    = GUI_STORE_(map_ele0)( store->map );
  ulong                     ele_max = GUI_STORE_(map_ele_max)( store->map );

  /* Struct scalars */

  VERIFY_TEST( fd_ulong_is_pow2( store->ele_max )                );
  VERIFY_TEST( ele_max==store->ele_max                           );
  VERIFY_TEST( store->cache_sz > 0UL                             );
  VERIFY_TEST( (store->file_len==0UL)==(store->fd<0)             );
  VERIFY_TEST( store->file_len!=0UL || store->file_base_off==0UL );
  VERIFY_TEST( store->fcnt!=0UL || store->fbytes==0UL            );
  if( store->file_len ) VERIFY_TEST( store->file_len >= GUI_STORE_(file_len_min)( store->cache_sz ) );

  ulong data_sz = store->file_len ? store->file_len - GUI_STORE_SUPERBLOCK_SZ : 0UL;

  /* Map / element scan.  Count the live elements (and, of those, the
     ones that are MEM-tier) so the cache walk and live_cnt can be
     cross-checked below. */

  ulong live     = 0UL; /* # live (free==0) elements                      */
  ulong mem_live = 0UL; /* # live elements whose value lives in the cache */

  for( ulong i=0UL; i<ele_max; i++ ) {
    GUI_STORE_(ele_t) const * e = &eles[ i ];
    if( e->free ) continue;
    live++;

    VERIFY_TEST( e->tier==GUI_STORE_TIER_MEM || e->tier==GUI_STORE_TIER_FILE );
    VERIFY_TEST( e->align!=0 && fd_ulong_is_pow2( (ulong)e->align ) );

    /* The whole message (header + alignment pad + value) must fit in
       the cache, since any FILE element can be warmed back in. */
    VERIFY_TEST( fd_ulong_align_up( sizeof(GUI_STORE_(msghdr_t)), (ulong)e->align ) + e->sz <= store->cache_sz );

    if( e->tier==GUI_STORE_TIER_MEM ) {
      VERIFY_TEST( e->mem!=NULL          );
      VERIFY_TEST( e->seq < store->msg_seq );
      mem_live++;
    } else { /* GUI_STORE_TIER_FILE */
      VERIFY_TEST( e->has_disk==1U       );
      VERIFY_TEST( store->file_len!=0UL  );
      VERIFY_TEST( e->off < data_sz      );
      VERIFY_TEST( (e->off % 8UL)==0UL   );
    }

    /* a FILE element is never dirty (its disk copy is authoritative) */
    VERIFY_TEST( !( e->tier==GUI_STORE_TIER_FILE && e->dirty ) );

    /* a MEM that is clean must have an disk allocation */
    VERIFY_TEST( !( e->tier==GUI_STORE_TIER_MEM && !e->dirty && !e->has_disk ) );

    /* The element must be the one the map resolves its own key to. */
    VERIFY_TEST( GUI_STORE_(map_query)( store->map, &e->key )==&eles[ i ] );

    /* In a mem-only store nothing can ever be on disk. */
    if( !store->file_len ) {
      VERIFY_TEST( e->tier==GUI_STORE_TIER_MEM );
      VERIFY_TEST( e->has_disk==0U             );
    }
  }

  VERIFY_TEST( store->live_cnt==live          );
  VERIFY_TEST( store->live_cnt<=store->ele_max );

  if( !store->file_len ) {
    VERIFY_TEST( store->fcnt==0UL   );
    VERIFY_TEST( store->fbytes==0UL );
    VERIFY_TEST( store->fhead==0UL  );
    VERIFY_TEST( store->ftail==0UL  );
  }

  /* Cache walk.  Every cache message carries a copy of the msg header.
     A message is not stale iff its key resolves to a live cache
     element whose seq matches and whose mem pointer points at this
     message's value bytes. */

  VERIFY_TEST( fd_circq_bytes_used( store->circq )<=store->cache_sz );

  ulong auth = 0UL; /* # authoritative messages */

  fd_circq_reset_cursor( store->circq );
  for(;;) {
    ulong         msg_sz  = 0UL;
    uchar const * payload = fd_circq_cursor_advance( store->circq, &msg_sz );
    if( !payload ) break;
    (void)msg_sz;

    GUI_STORE_(msghdr_t) mhdr;
    fd_memcpy( &mhdr, payload, sizeof(mhdr) );

    if( FD_UNLIKELY( !(mhdr.seq < store->msg_seq) ) ) {
      FD_LOG_WARNING(( "FAIL: cache message seq %lu >= msg_seq %lu", mhdr.seq, store->msg_seq ));
      fd_circq_reset_cursor( store->circq );
      return -1;
    }

    GUI_STORE_(ele_t) const * e = GUI_STORE_(map_query)( store->map, &mhdr.key );
    if( !e ) continue; /* orphan of an evicted key */

    int authoritative = ( e->tier==GUI_STORE_TIER_MEM ) &&
                        ( e->seq==mhdr.seq            ) &&
                        ( e->mem==payload + fd_ulong_align_up( sizeof(GUI_STORE_(msghdr_t)), (ulong)e->align ) );
    if( authoritative ) auth++;
  }
  fd_circq_reset_cursor( store->circq );

  VERIFY_TEST( auth==mem_live );

  if( store->file_len ) {

    VERIFY_TEST( store->fhead < data_sz );
    VERIFY_TEST( store->ftail < data_sz );
    VERIFY_TEST( store->fbytes <= data_sz );

    /* The upper segment ends at fdata_end; bytes in [fdata_end,data_sz)
       are an abandoned tail gap left by a wrap. */
    VERIFY_TEST( store->fdata_end<=data_sz );
    VERIFY_TEST( store->fdata_end>=store->ftail );

    /* Validate on-disk footprint/align fields, walking head->tail and
       wrapping at fdata_end (not data_sz) so the walk skips the gap. */
    ulong off = store->fhead;
    ulong sum = 0UL;
    for( ulong r=0UL; r<store->fcnt; r++ ) {
      GUI_STORE_(rechdr_t) hdr;
      ulong hdr_off = store->file_base_off + GUI_STORE_SUPERBLOCK_SZ + off;
      if( FD_UNLIKELY( GUI_STORE_(pread_all)( store->fd, &hdr, sizeof(hdr), hdr_off ) ) ) {
        FD_LOG_WARNING(( "FAIL: disk ring header read at off %lu", off ));
        return -1;
      }

      ulong rec_fp = fd_ulong_align_up( sizeof(GUI_STORE_(rechdr_t)) + hdr.sz, 8UL );
      VERIFY_TEST( (rec_fp % 8UL)==0UL                       );
      VERIFY_TEST( rec_fp >= sizeof(GUI_STORE_(rechdr_t))    );

      sum += rec_fp;
      off += rec_fp;
      if( FD_UNLIKELY( off>=store->fdata_end ) ) off = 0UL;
    }
    VERIFY_TEST( sum==store->fbytes );
    VERIFY_TEST( off==store->ftail  );

    /* On-disk offsets/flags match cache */
    for( ulong i=0UL; i<ele_max; i++ ) {
      GUI_STORE_(ele_t) const * e = &eles[ i ];
      if( e->free || !e->has_disk ) continue;

      for( ulong j=i+1UL; j<ele_max; j++ ) {
        GUI_STORE_(ele_t) const * o = &eles[ j ];
        if( o->free || !o->has_disk ) continue;
        VERIFY_TEST( o->off!=e->off );
      }

      GUI_STORE_(rechdr_t) hdr;
      ulong hdr_off = store->file_base_off + GUI_STORE_SUPERBLOCK_SZ + e->off;
      if( FD_UNLIKELY( GUI_STORE_(pread_all)( store->fd, &hdr, sizeof(hdr), hdr_off ) ) ) {
        FD_LOG_WARNING(( "FAIL: disk record header read at off %lu", e->off ));
        return -1;
      }
      VERIFY_TEST( GUI_STORE_KEY_EQ( &hdr.key, &e->key ) );
      VERIFY_TEST( hdr.sz==e->sz                         );
      VERIFY_TEST( hdr.align==(ulong)e->align            );
    }

    /* Superblock.  Validate the self-describing fields and the checksum. */
    ulong sb[ GUI_STORE_SUPERBLOCK_SZ / sizeof(ulong) ];
    if( FD_UNLIKELY( GUI_STORE_(pread_all)( store->fd, sb, sizeof(sb), store->file_base_off ) ) ) {
      FD_LOG_WARNING(( "FAIL: superblock read" ));
      return -1;
    }
    VERIFY_TEST( sb[ 0 ]==GUI_STORE_MAGIC   );
    VERIFY_TEST( sb[ 1 ]==GUI_STORE_VERSION );
    VERIFY_TEST( sb[ 6 ]==( sb[ 0 ] ^ sb[ 1 ] ^ sb[ 2 ] ^ sb[ 3 ] ^ sb[ 4 ] ^ sb[ 5 ] ) );
  }

# undef VERIFY_TEST

  return 0;
}

#undef GUI_STORE_NAME
#undef GUI_STORE_KEY_T
#undef GUI_STORE_KEY_HASH
#undef GUI_STORE_KEY_EQ
#undef GUI_STORE_IMPL_STYLE
#undef GUI_STORE_STATIC
#undef GUI_STORE_TIER_MEM
#undef GUI_STORE_TIER_FILE
#undef GUI_STORE_MAGIC
#undef GUI_STORE_VERSION
#undef GUI_STORE_SUPERBLOCK_SZ
#undef GUI_STORE_RESERVE_FAIL
#undef GUI_STORE_IDX_LOAD_FACTOR
#undef GUI_STORE_IDX_EVICT_PCT
#undef GUI_STORE_CACHE_LOAD_FACTOR
#undef GUI_STORE_CACHE_EVICT_PCT
#undef GUI_STORE_DISK_LOAD_FACTOR
#undef GUI_STORE_DISK_EVICT_PCT
#undef GUI_STORE_MAX_WRITEBACK_IOV
#undef GUI_STORE_
