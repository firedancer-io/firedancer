#include "fd_gui_store.h"

#include <errno.h>      /* errno                        */
#include <unistd.h>     /* close, ftruncate             */
#include <fcntl.h>      /* open, O_RDWR/O_CREAT/O_TRUNC */
#include <sys/mman.h>   /* mmap, munmap, PROT_*, MAP_*  */

#define FD_GUI_STORE_MAGIC (0xf17e6d0c0117db04UL)

#define FD_GUI_STORE_PAGE_SZ (4096UL)

/* FD_GUI_STORE_TS_IDX_DEPTH is the depth of the time-series index array.

   Must be greater than FD_GUI_HIST_TS_SKEW_NS, so a live record's
   window-index bucket can never be aliased/wrapped off. */
#define FD_GUI_STORE_TS_IDX_DEPTH (30UL*24UL*60UL*60UL) /* 30 days of 1s windows */

struct fd_gui_store_ts_idx_ent {
  ulong window;     /* bucket window (==ULONG_MAX if empty) */
  ulong first_cur;  /* lowest cursor tagged with this window */
  ulong last_cur;   /* highest cursor tagged with this window */
};
typedef struct fd_gui_store_ts_idx_ent fd_gui_store_ts_idx_ent_t;

struct fd_gui_store_ring {
  ulong stride;          /* align_up( hdr + val_sz, val_align ) */
  ulong region_capacity; /* whole slots per region (REGION_SZ/stride) */
  ulong key_off;         /* KV key offset within val (0 for TS) */
  ulong key_sz;          /* KV key width (0 for TS) */
  ulong val_sz;          /* stored record size */
  ulong val_align;       /* slot/record alignment */
  ulong ts_off;          /* TS timestamp offset within val (0 for KV) */
  ulong granularity;     /* TS window granularity (0 for KV) */
  int   kind;            /* FD_GUI_STORE_KIND_* */
  ulong head_cur;        /* next cursor to write */
  ulong evict_cur;       /* logical low-watermark */
  ulong tail_cur;        /* oldest physically-present slot */
};
typedef struct fd_gui_store_ring fd_gui_store_ring_t;

#define FD_GUI_STORE_SUPER_MAGIC (0xf17e6d0c0117db05UL) /* fd_gui_store regions, versioned */

struct fd_gui_store_super {
  ulong            magic;
  ulong            size_bytes;  /* configured ceiling (max file size) */
  ulong            data_off;    /* byte offset of region 0 within the file */
  ulong            region_sz;   /* bytes per region */
  ulong            region_cnt;  /* total regions in the pool */
  ulong            ring_cnt;
  fd_gui_store_ring_t ring[ FD_GUI_STORE_MAX_RINGS ];
};
typedef struct fd_gui_store_super fd_gui_store_super_t;

struct fd_gui_store_kv_idx_node {
  ulong key;       /* MAP_KEY: ring->key_hash of the record's key */
  ulong cur;       /* generation cursor of the ring slot */
  ulong next;      /* MAP_NEXT (chain link) */
  ulong prev;      /* MAP_PREV (random-access removal of a specific node) */
  ulong pool_next; /* POOL_NEXT (free list) */
};
typedef struct fd_gui_store_kv_idx_node fd_gui_store_kv_idx_node_t;

#define MAP_NAME              fd_gui_store_kv_idx
#define MAP_KEY               key
#define MAP_KEY_T             ulong
#define MAP_ELE_T             fd_gui_store_kv_idx_node_t
#define MAP_NEXT              next
#define MAP_PREV              prev
#define MAP_KEY_EQ(k0,k1)     ( *(k0)==*(k1) )
#define MAP_KEY_HASH(k,s)     fd_ulong_hash( *(k) ^ (s) )
#define MAP_MULTI             1
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1
#include "../../util/tmpl/fd_map_chain.c"

#define POOL_NAME fd_gui_store_kv_pool
#define POOL_T    fd_gui_store_kv_idx_node_t
#define POOL_NEXT pool_next
#include "../../util/tmpl/fd_pool.c"

#define STACK_NAME fd_gui_store_freelist
#define STACK_T    ulong
#include "../../util/tmpl/fd_stack.c"

struct fd_gui_store_ring_rt {
  ulong reg_base;  /* logical ordinal of oldest owned region */
  ulong reg_cnt;   /* number of regions owned */
};
typedef struct fd_gui_store_ring_rt fd_gui_store_ring_rt_t;

struct fd_gui_store_private {
  ulong                        magic;        /* ==FD_GUI_STORE_MAGIC after fd_gui_store_new */
  ulong                        size;         /* configured size ceiling in bytes */
  ulong                        ring_cnt;
  int                          fd;           /* backing-file fd, or -1 */
  void *                       mapped;       /* mmap base (the file) */
  ulong                        mapped_sz;    /* size of `mapped` in bytes */
  ulong                        file_sz;      /* current ftruncate'd file length */
  fd_gui_store_super_t *       super;        /* == mapped (page 0) */
  fd_gui_store_kv_idx_t *      kv_idx[ FD_GUI_STORE_MAX_RINGS ]; /* per-KV-ring index (RAM); NULL for TS rings */
  fd_gui_store_kv_idx_node_t * kv_pool;      /* shared KV index node pool (RAM) */
  ulong ( * kv_key_hash[ FD_GUI_STORE_MAX_RINGS ] )( void const * key );              /* RAM: per-KV-ring key hash */
  int   ( * kv_key_cmp [ FD_GUI_STORE_MAX_RINGS ] )( void const * a, void const * b ); /* RAM: per-KV-ring key compare */
  fd_gui_store_ts_idx_ent_t *  ts_idx;       /* TS window index (RAM): ring_cnt rows of DEPTH entries */
  ulong *                      freelist;     /* region free list (RAM) */
  fd_gui_store_ring_rt_t *     ring_rt;      /* per-ring region ownership (RAM): ring_cnt rows */
  ulong *                      region_ids;   /* per-ring region-id rings (RAM): ring_cnt rows of region_cnt ulongs */
  ulong                        region_cnt;   /* total regions in the pool (== super->region_cnt; ring divisor) */
  fd_gui_store_metrics_t       metrics[ 1 ]; /* cumulative per-ring metrics */
};

/* fd_gui_store_ts_idx_row returns `ring_idx` ring's window-index
   circular array. */
static inline fd_gui_store_ts_idx_ent_t *
fd_gui_store_ts_idx_row( fd_gui_store_t * db, ulong ring_idx ) {
  return db->ts_idx + ring_idx*FD_GUI_STORE_TS_IDX_DEPTH;
}

/* fd_gui_store_region_ring returns `ring_idx` ring's region_id. */
static inline ulong *
fd_gui_store_region_ring( fd_gui_store_t * db, ulong ring_idx ) {
  return db->region_ids + ring_idx*db->region_cnt;
}

FD_FN_CONST ulong
fd_gui_store_align( void ) {
  return 128UL;
}

/* fd_gui_store_ring_stride returns the align-padded slot stride.
   Neither kind has a store-added header. */
static inline ulong
fd_gui_store_ring_stride( int   kind,
                          ulong val_sz,
                          ulong val_align ) {
  (void)kind;
  return fd_ulong_align_up( val_sz, fd_ulong_max( val_align, 1UL ) );
}

FD_FN_CONST ulong
fd_gui_store_min_overhead_bytes( void ) {
  /* Superblock page plus one region. */
  return fd_ulong_align_up( sizeof(fd_gui_store_super_t), FD_GUI_STORE_PAGE_SZ ) + FD_GUI_STORE_REGION_SZ;
}

static ulong
fd_gui_store_file_footprint( ulong                       size_bytes,
                             ulong                       ring_cnt,
                             fd_gui_store_desc_t const * descs,
                             ulong *                     region_sz_out,
                             ulong *                     data_off_out ) {
  if( FD_UNLIKELY( !ring_cnt || ring_cnt>FD_GUI_STORE_MAX_RINGS || !descs ) ) return 0UL;

  ulong data_off  = fd_ulong_align_up( sizeof(fd_gui_store_super_t), FD_GUI_STORE_PAGE_SZ );
  ulong region_sz = FD_GUI_STORE_REGION_SZ;
  if( FD_UNLIKELY( size_bytes<data_off+region_sz ) ) return 0UL; /* ceiling too small for one region */
  ulong avail = size_bytes - data_off;

  /* Every ring must fit at least one slot in a region. */
  for( ulong i=0UL; i<ring_cnt; i++ ) {
    ulong stride = fd_gui_store_ring_stride( descs[ i ].kind, descs[ i ].val_sz, descs[ i ].val_align );
    if( FD_UNLIKELY( !stride || stride>region_sz ) ) return 0UL; /* record does not fit a region */
  }

  ulong region_cnt = avail / region_sz;
  if( FD_UNLIKELY( !region_cnt ) ) return 0UL;

  if( region_sz_out ) *region_sz_out = region_sz;
  if( data_off_out  ) *data_off_out  = data_off;
  return region_cnt;
}

static inline ulong
fd_gui_store_kv_idx_max( fd_gui_store_desc_t const * desc ) {
  if( desc->kind!=FD_GUI_STORE_KIND_KV ) return 0UL;
  return fd_ulong_max( desc->max_records, 1UL );
}

FD_FN_CONST ulong
fd_gui_store_footprint( ulong                       size_bytes,
                        ulong                       ring_cnt,
                        fd_gui_store_desc_t const * descs ) {
  if( FD_UNLIKELY( ring_cnt>FD_GUI_STORE_MAX_RINGS ) ) return 0UL;

  ulong region_cnt = fd_gui_store_file_footprint( size_bytes, ring_cnt, descs, NULL, NULL );
  if( FD_UNLIKELY( !region_cnt ) ) return 0UL;

  ulong pool_max = 0UL;
  for( ulong i=0UL; i<ring_cnt; i++ ) pool_max += fd_gui_store_kv_idx_max( &descs[ i ] );
  pool_max = fd_ulong_max( pool_max, 1UL );

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, fd_gui_store_align(),               sizeof(fd_gui_store_t) );
  for( ulong i=0UL; i<ring_cnt; i++ ) {
    if( descs[ i ].kind!=FD_GUI_STORE_KIND_KV ) continue;
    ulong chain_cnt = fd_gui_store_kv_idx_chain_cnt_est( fd_gui_store_kv_idx_max( &descs[ i ] ) );
    l = FD_LAYOUT_APPEND( l, fd_gui_store_kv_idx_align(),     fd_gui_store_kv_idx_footprint( chain_cnt ) );
  }
  l = FD_LAYOUT_APPEND( l, fd_gui_store_kv_pool_align(),      fd_gui_store_kv_pool_footprint( pool_max ) );
  l = FD_LAYOUT_APPEND( l, alignof(fd_gui_store_ts_idx_ent_t), fd_ulong_max( ring_cnt, 1UL )*FD_GUI_STORE_TS_IDX_DEPTH*sizeof(fd_gui_store_ts_idx_ent_t) );
  l = FD_LAYOUT_APPEND( l, fd_gui_store_freelist_align(),      fd_gui_store_freelist_footprint( region_cnt ) );
  l = FD_LAYOUT_APPEND( l, alignof(fd_gui_store_ring_rt_t),    fd_ulong_max( ring_cnt, 1UL )*sizeof(fd_gui_store_ring_rt_t) );
  l = FD_LAYOUT_APPEND( l, alignof(ulong),                 fd_ulong_max( ring_cnt, 1UL )*region_cnt*sizeof(ulong) );
  return FD_LAYOUT_FINI( l, fd_gui_store_align() );
}

void *
fd_gui_store_new( void *                      mem,
                  char const *                path,
                  ulong                       size_bytes,
                  ulong                       ring_cnt,
                  fd_gui_store_desc_t const * descs ) {

  if( FD_UNLIKELY( !mem ) )                 { FD_LOG_WARNING(( "fd_gui_store_new: null mem" )); return NULL; }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_gui_store_align() ) ) ) { FD_LOG_WARNING(( "fd_gui_store_new: misaligned mem" )); return NULL; }
  if( FD_UNLIKELY( !path || !path[ 0 ] ) ) { FD_LOG_WARNING(( "fd_gui_store_new: null path" )); return NULL; }
  if( FD_UNLIKELY( !size_bytes ) )          { FD_LOG_WARNING(( "fd_gui_store_new: zero size" )); return NULL; }
  if( FD_UNLIKELY( !ring_cnt || ring_cnt>FD_GUI_STORE_MAX_RINGS ) ) { FD_LOG_WARNING(( "fd_gui_store_new: bad ring_cnt %lu", ring_cnt )); return NULL; }
  if( FD_UNLIKELY( !descs ) )               { FD_LOG_WARNING(( "fd_gui_store_new: null descs" )); return NULL; }

  for( ulong i=0UL; i<ring_cnt; i++ ) {
    if( FD_UNLIKELY( !descs[ i ].name ) ) { FD_LOG_WARNING(( "fd_gui_store_new: null descs[%lu].name", i )); return NULL; }
    if( FD_UNLIKELY( descs[ i ].kind!=FD_GUI_STORE_KIND_KV && descs[ i ].kind!=FD_GUI_STORE_KIND_TS ) ) {
      FD_LOG_WARNING(( "fd_gui_store_new: bad descs[%lu].kind %d", i, descs[ i ].kind )); return NULL;
    }
    if( FD_UNLIKELY( !descs[ i ].val_sz ) ) {
      FD_LOG_WARNING(( "fd_gui_store_new: descs[%lu] has zero val_sz", i )); return NULL;
    }
    if( FD_UNLIKELY( descs[ i ].kind==FD_GUI_STORE_KIND_KV && !descs[ i ].key_sz ) ) {
      FD_LOG_WARNING(( "fd_gui_store_new: KV descs[%lu] has zero key_sz", i )); return NULL;
    }
    if( FD_UNLIKELY( descs[ i ].kind==FD_GUI_STORE_KIND_KV && ( !descs[ i ].key_hash || !descs[ i ].key_cmp ) ) ) {
      FD_LOG_WARNING(( "fd_gui_store_new: KV descs[%lu] missing key_hash/key_cmp", i )); return NULL;
    }
    if( FD_UNLIKELY( descs[ i ].kind==FD_GUI_STORE_KIND_KV && descs[ i ].key_off+descs[ i ].key_sz>descs[ i ].val_sz ) ) {
      FD_LOG_WARNING(( "fd_gui_store_new: KV descs[%lu] key (off %lu sz %lu) exceeds val_sz %lu", i, descs[ i ].key_off, descs[ i ].key_sz, descs[ i ].val_sz )); return NULL;
    }
  }

  ulong region_sz, data_off;
  ulong region_cnt = fd_gui_store_file_footprint( size_bytes, ring_cnt, descs, &region_sz, &data_off );
  if( FD_UNLIKELY( !region_cnt ) ) {
    FD_LOG_WARNING(( "fd_gui_store_new: store size %lu too small for %lu rings", size_bytes, ring_cnt ));
    return NULL;
  }

  /* Shared KV node pool sized to the sum of per-ring max_records. */
  ulong pool_max = 0UL;
  for( ulong i=0UL; i<ring_cnt; i++ ) pool_max += fd_gui_store_kv_idx_max( &descs[ i ] );
  pool_max = fd_ulong_max( pool_max, 1UL );

  fd_memset( mem, 0, sizeof(fd_gui_store_t) );
  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_gui_store_t * db          = FD_SCRATCH_ALLOC_APPEND( l, fd_gui_store_align(),          sizeof(fd_gui_store_t) );
  void * kv_idx_mem[ FD_GUI_STORE_MAX_RINGS ];
  ulong  kv_idx_chains[ FD_GUI_STORE_MAX_RINGS ];
  for( ulong i=0UL; i<ring_cnt; i++ ) {
    if( descs[ i ].kind!=FD_GUI_STORE_KIND_KV ) { kv_idx_mem[ i ] = NULL; kv_idx_chains[ i ] = 0UL; continue; }
    kv_idx_chains[ i ] = fd_gui_store_kv_idx_chain_cnt_est( fd_gui_store_kv_idx_max( &descs[ i ] ) );
    kv_idx_mem[ i ]    = FD_SCRATCH_ALLOC_APPEND( l, fd_gui_store_kv_idx_align(), fd_gui_store_kv_idx_footprint( kv_idx_chains[ i ] ) );
  }
  void *        kv_pool_mem= FD_SCRATCH_ALLOC_APPEND( l, fd_gui_store_kv_pool_align(), fd_gui_store_kv_pool_footprint( pool_max ) );
  fd_gui_store_ts_idx_ent_t * ts_idx_mem = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_gui_store_ts_idx_ent_t), ring_cnt*FD_GUI_STORE_TS_IDX_DEPTH*sizeof(fd_gui_store_ts_idx_ent_t) );
  void *        freelist_mem= FD_SCRATCH_ALLOC_APPEND( l, fd_gui_store_freelist_align(), fd_gui_store_freelist_footprint( region_cnt ) );
  fd_gui_store_ring_rt_t * ring_rt_mem = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_gui_store_ring_rt_t), ring_cnt*sizeof(fd_gui_store_ring_rt_t) );
  ulong *       region_ids_mem = FD_SCRATCH_ALLOC_APPEND( l, alignof(ulong), ring_cnt*region_cnt*sizeof(ulong) );
  FD_SCRATCH_ALLOC_FINI( l, fd_gui_store_align() );

  db->fd         = -1;
  db->mapped     = NULL;
  db->ring_cnt   = ring_cnt;
  db->size       = size_bytes;
  db->ts_idx     = ts_idx_mem;
  db->ring_rt    = ring_rt_mem;
  db->region_ids = region_ids_mem;
  db->region_cnt = region_cnt;
  for( ulong i=0UL; i<ring_cnt*FD_GUI_STORE_TS_IDX_DEPTH; i++ ) ts_idx_mem[ i ].window = ULONG_MAX;
  for( ulong i=0UL; i<ring_cnt; i++ ) { ring_rt_mem[ i ].reg_base = 0UL; ring_rt_mem[ i ].reg_cnt = 0UL; }

  /* Shared node pool + one ulong-keyed index per KV ring. */
  if( FD_UNLIKELY( !fd_gui_store_kv_pool_new( kv_pool_mem, pool_max ) ) ) { FD_LOG_WARNING(( "fd_gui_store_new: ent_pool_new failed" )); return NULL; }
  db->kv_pool = fd_gui_store_kv_pool_join( kv_pool_mem );
  if( FD_UNLIKELY( !db->kv_pool ) ) { FD_LOG_WARNING(( "fd_gui_store_new: kv_pool join failed" )); return NULL; }
  for( ulong i=0UL; i<FD_GUI_STORE_MAX_RINGS; i++ ) db->kv_idx[ i ] = NULL;
  for( ulong i=0UL; i<ring_cnt; i++ ) {
    if( !kv_idx_mem[ i ] ) continue;
    if( FD_UNLIKELY( !fd_gui_store_kv_idx_new( kv_idx_mem[ i ], kv_idx_chains[ i ], (ulong)i ) ) ) { FD_LOG_WARNING(( "fd_gui_store_new: ent_idx_new[%lu] failed", i )); return NULL; }
    db->kv_idx[ i ] = fd_gui_store_kv_idx_join( kv_idx_mem[ i ] );
    if( FD_UNLIKELY( !db->kv_idx[ i ] ) ) { FD_LOG_WARNING(( "fd_gui_store_new: kv_idx join[%lu] failed", i )); return NULL; }
  }

  if( FD_UNLIKELY( !fd_gui_store_freelist_new( freelist_mem, region_cnt ) ) ) { FD_LOG_WARNING(( "fd_gui_store_new: freelist_new failed" )); return NULL; }
  db->freelist = fd_gui_store_freelist_join( freelist_mem );
  if( FD_UNLIKELY( !db->freelist ) ) { FD_LOG_WARNING(( "fd_gui_store_new: freelist join failed" )); return NULL; }
  for( ulong i=region_cnt; i-->0UL; ) fd_gui_store_freelist_push( db->freelist, i );

  /* Wipe + (re)create the backing file. */
  ulong map_sz = data_off + region_cnt*region_sz;
  int fd = open( path, O_RDWR | O_CREAT | O_TRUNC, (mode_t)0600 );
  if( FD_UNLIKELY( fd<0 ) ) { FD_LOG_WARNING(( "fd_gui_store_new: open(%s) failed (%d-%s)", path, errno, fd_io_strerror( errno ) )); return NULL; }
  if( FD_UNLIKELY( ftruncate( fd, (off_t)data_off ) ) ) {
    FD_LOG_WARNING(( "fd_gui_store_new: ftruncate(%s, %lu) failed (%d-%s)", path, data_off, errno, fd_io_strerror( errno ) ));
    close( fd ); return NULL;
  }
  void * mapped = mmap( NULL, map_sz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0 );
  if( FD_UNLIKELY( mapped==MAP_FAILED ) ) {
    FD_LOG_WARNING(( "fd_gui_store_new: mmap(%s, %lu) failed (%d-%s)", path, map_sz, errno, fd_io_strerror( errno ) ));
    close( fd ); return NULL;
  }

  db->fd        = fd;
  db->mapped    = mapped;
  db->mapped_sz = map_sz;
  db->file_sz   = data_off;
  db->super     = (fd_gui_store_super_t *)mapped;

  fd_gui_store_super_t * super = db->super;
  fd_memset( super, 0, sizeof(fd_gui_store_super_t) );
  super->size_bytes = size_bytes;
  super->data_off   = data_off;
  super->region_sz  = region_sz;
  super->region_cnt = region_cnt;
  super->ring_cnt   = ring_cnt;

  for( ulong i=0UL; i<ring_cnt; i++ ) {
    fd_gui_store_ring_t * p = &super->ring[ i ];
    p->stride          = fd_gui_store_ring_stride( descs[ i ].kind, descs[ i ].val_sz, descs[ i ].val_align );
    p->region_capacity = region_sz / p->stride; /* >=1 by layout */
    p->key_off         = descs[ i ].key_off;
    p->key_sz          = descs[ i ].key_sz;
    p->val_sz          = descs[ i ].val_sz;
    p->val_align       = descs[ i ].val_align;
    p->ts_off          = descs[ i ].ts_off;
    p->granularity     = descs[ i ].granularity;
    p->kind            = descs[ i ].kind;
    p->head_cur        = 0UL;
    p->evict_cur       = 0UL;
    p->tail_cur        = 0UL;
    db->kv_key_hash[ i ] = descs[ i ].key_hash; /* NULL for TS rings */
    db->kv_key_cmp [ i ] = descs[ i ].key_cmp;  /* NULL for TS rings */
  }

  FD_COMPILER_MFENCE();
  super->magic = FD_GUI_STORE_SUPER_MAGIC;
  db->magic    = FD_GUI_STORE_MAGIC;
  FD_COMPILER_MFENCE();

  memset( db->metrics, 0, sizeof(fd_gui_store_metrics_t) );

  FD_LOG_INFO(( "fd_gui_store: opened %s (ceiling %lu MiB, %lu regions x %lu MiB, %lu rings)",
                path, size_bytes>>20, region_cnt, region_sz>>20, ring_cnt ));
  return mem;
}

fd_gui_store_t *
fd_gui_store_join( void * mem ) {
  if( FD_UNLIKELY( !mem ) ) return NULL;
  fd_gui_store_t * db = (fd_gui_store_t *)mem;
  if( FD_UNLIKELY( db->magic!=FD_GUI_STORE_MAGIC ) ) { FD_LOG_WARNING(( "fd_gui_store_join: bad magic" )); return NULL; }
  return db;
}

void *
fd_gui_store_leave( fd_gui_store_t * db ) {
  return (void *)db;
}

void *
fd_gui_store_delete( void * mem ) {
  if( FD_UNLIKELY( !mem ) ) return NULL;
  fd_gui_store_t * db = (fd_gui_store_t *)mem;
  if( db->mapped ) munmap( db->mapped, db->mapped_sz );
  if( db->fd>=0  ) close( db->fd );
  db->mapped = NULL;
  db->fd     = -1;
  db->super  = NULL;
  db->magic  = 0UL;
  return mem;
}

ulong
fd_gui_store_cnt( fd_gui_store_t const * db ) {
  return db->ring_cnt;
}

static inline ulong
fd_gui_store_committed_bytes( fd_gui_store_t const * db ) {
  ulong used = db->super->data_off;
  for( ulong i=0UL; i<db->ring_cnt; i++ ) used += db->ring_rt[ i ].reg_cnt * db->super->region_sz;
  return used;
}

ulong
fd_gui_store_used_bytes( fd_gui_store_t * db ) {
  if( FD_UNLIKELY( !db->super ) ) return 0UL;
  return fd_gui_store_committed_bytes( db );
}

ulong
fd_gui_store_live_bytes( fd_gui_store_t * db ) {
  if( FD_UNLIKELY( !db->super ) ) return 0UL;
  ulong live = 0UL;
  for( ulong i=0UL; i<db->ring_cnt; i++ ) {
    fd_gui_store_ring_t const * p = &db->super->ring[ i ];
    live += ( p->head_cur - p->evict_cur ) * p->stride;
  }
  return live;
}

fd_gui_store_metrics_t const *
fd_gui_store_metrics( fd_gui_store_t const * db ) {
  return db->metrics;
}

void
fd_gui_store_ring_stats( fd_gui_store_t * db,
                         ulong            ring_idx,
                         ulong *          used_bytes,
                         ulong *          cap_bytes,
                         ulong *          free_bytes,
                         ulong *          used_slots,
                         ulong *          cap_slots,
                         ulong *          free_slots ) {
  if( FD_LIKELY( db->super && ring_idx<db->ring_cnt ) ) {
    fd_gui_store_ring_t const *    p  = &db->super->ring[ ring_idx ];
    fd_gui_store_ring_rt_t const * rt = &db->ring_rt[ ring_idx ];

    *used_slots = p->head_cur - p->tail_cur;
    *cap_slots  = rt->reg_cnt * p->region_capacity;
    *free_slots = fd_gui_store_freelist_cnt( db->freelist ) * p->region_capacity;
    *used_bytes = *used_slots * p->stride;
    *cap_bytes  = rt->reg_cnt * db->super->region_sz;
    *free_bytes = fd_gui_store_freelist_cnt( db->freelist ) * db->super->region_sz;
  }
}

ulong
fd_gui_store_size( fd_gui_store_t const * db ) {
  return db->size;
}

ulong
fd_gui_store_free_region_cnt( fd_gui_store_t const * db ) {
  if( FD_UNLIKELY( !db->super ) ) return 0UL;
  return fd_gui_store_freelist_cnt( db->freelist );
}

int
fd_gui_store_fd( fd_gui_store_t const * db ) {
  if( FD_UNLIKELY( !db ) ) return -1;
  return db->fd;
}

static inline ulong
fd_gui_store_ring_head_limit( fd_gui_store_t const *      db,
                              ulong                       ring_idx,
                              fd_gui_store_ring_t const * p ) {
  fd_gui_store_ring_rt_t const * rt = &db->ring_rt[ ring_idx ];
  return ( rt->reg_base + rt->reg_cnt )*p->region_capacity;
}

static int
fd_gui_store_region_grow( fd_gui_store_t * db, ulong ring_idx ) {
  fd_gui_store_ring_rt_t * rt          = &db->ring_rt[ ring_idx ];
  ulong *               region_ring = fd_gui_store_region_ring( db, ring_idx );
  if( FD_UNLIKELY( fd_gui_store_freelist_empty( db->freelist ) ) )        return 0;

  ulong region_id = fd_gui_store_freelist_pop( db->freelist );
  ulong ordinal   = rt->reg_base + rt->reg_cnt;
  region_ring[ ordinal % db->region_cnt ] = region_id;
  rt->reg_cnt++;

  ulong region_end = db->super->data_off + ( region_id + 1UL )*db->super->region_sz;
  if( region_end>db->file_sz ) {
    if( FD_UNLIKELY( ftruncate( db->fd, (off_t)region_end ) ) ) {
      /* roll back the claim */
      rt->reg_cnt--;
      fd_gui_store_freelist_push( db->freelist, region_id );
      FD_LOG_WARNING(( "fd_gui_store: ftruncate grow to %lu failed (%d-%s)", region_end, errno, fd_io_strerror( errno ) ));
      return 0;
    }
    db->file_sz = region_end;
  }
  db->metrics->region_grows[ ring_idx ]++;
  return 1;
}

static void
fd_gui_store_region_reclaim( fd_gui_store_t * db, ulong ring_idx,
                             fd_gui_store_ring_t * p ) {
  fd_gui_store_ring_rt_t * rt          = &db->ring_rt[ ring_idx ];
  ulong *               region_ring = fd_gui_store_region_ring( db, ring_idx );
  ulong                 cap         = p->region_capacity;
  while( rt->reg_cnt && p->tail_cur >= ( rt->reg_base + 1UL )*cap ) {
    ulong region_id = region_ring[ rt->reg_base % db->region_cnt ];
    fd_gui_store_freelist_push( db->freelist, region_id );
    rt->reg_base++;
    rt->reg_cnt--;
    db->metrics->region_reclaims[ ring_idx ]++;
  }
}

static inline void *
fd_gui_store_slot( fd_gui_store_t *            db,
                   ulong                       ring_idx,
                   fd_gui_store_ring_t const * p,
                   ulong                       cur ) {
  ulong cap       = p->region_capacity;
  ulong ordinal   = cur / cap;
  ulong region_id = fd_gui_store_region_ring( db, ring_idx )[ ordinal % db->region_cnt ];
  ulong off       = db->super->data_off + region_id*db->super->region_sz + ( cur % cap )*p->stride;
  return (uchar *)db->mapped + off;
}

static inline ulong
fd_gui_store_ts_window( fd_gui_store_ring_t const * p,
                        void const *                val ) {
  long  ts   = *(long const *)( (uchar const *)val + p->ts_off );
  ulong gran = fd_ulong_max( p->granularity, 1UL );
  return (ulong)fd_long_max( ts, 0L ) / gran;
}

static inline uchar const *
fd_gui_store_kv_slot_key( fd_gui_store_t *            db,
                          ulong                       ring_idx,
                          fd_gui_store_ring_t const * p,
                          ulong                       cur ) {
  return (uchar const *)fd_gui_store_slot( db, ring_idx, p, cur ) + p->key_off;
}

static fd_gui_store_kv_idx_node_t *
fd_gui_store_kv_find_node( fd_gui_store_t *            db,
                           fd_gui_store_ring_t const * p,
                           ulong                       ring_idx,
                           void const *                key ) {
  ulong ik = db->kv_key_hash[ ring_idx ]( key );
  fd_gui_store_kv_idx_node_t * node = fd_gui_store_kv_idx_ele_query( db->kv_idx[ ring_idx ], &ik, NULL, db->kv_pool );
  while( node ) {
    fd_gui_store_kv_idx_node_t * next = (fd_gui_store_kv_idx_node_t *)fd_gui_store_kv_idx_ele_next_const( node, NULL, db->kv_pool );
    if( FD_UNLIKELY( node->cur<p->evict_cur ) ) {
      /* stale: the slot was evicted; lazily drop the dead index node */
      fd_gui_store_kv_idx_ele_remove_fast( db->kv_idx[ ring_idx ], node, db->kv_pool );
      fd_gui_store_kv_pool_ele_release( db->kv_pool, node );
    } else {
      uchar const * slot_key = fd_gui_store_kv_slot_key( db, ring_idx, p, node->cur );
      if( FD_LIKELY( 0==db->kv_key_cmp[ ring_idx ]( slot_key, key ) ) ) return node;
    }
    node = next;
  }
  return NULL;
}

int
fd_gui_store_kv_get_or_create( fd_gui_store_t * db,
                               ulong            ring_idx,
                               void const *     key,
                               void **          val_out ) {
  if( FD_UNLIKELY( ring_idx>=db->ring_cnt ) ) { FD_LOG_WARNING(( "fd_gui_store_kv_get_or_create: bad ring_idx %lu", ring_idx )); return FD_GUI_STORE_ERR; }
  fd_gui_store_ring_t * p = &db->super->ring[ ring_idx ];
  if( FD_UNLIKELY( p->kind!=FD_GUI_STORE_KIND_KV ) ) { FD_LOG_WARNING(( "fd_gui_store_kv_get_or_create: ring_idx %lu is not a KV ring", ring_idx )); return FD_GUI_STORE_ERR; }

  /* Existing key: hand back the live value region for in-place population. */
  fd_gui_store_kv_idx_node_t * node = fd_gui_store_kv_find_node( db, p, ring_idx, key );
  if( FD_LIKELY( node ) ) {
    uchar * slot = fd_gui_store_slot( db, ring_idx, p, node->cur );
    if( val_out ) *val_out = slot;
    return FD_GUI_STORE_SUCCESS;
  }

  if( FD_UNLIKELY( p->head_cur >= fd_gui_store_ring_head_limit( db, ring_idx, p ) ) ) {
    if( FD_UNLIKELY( !fd_gui_store_region_grow( db, ring_idx ) ) ) { db->metrics->map_full[ ring_idx ]++; return FD_GUI_STORE_MAP_FULL; }
  }
  if( FD_UNLIKELY( !fd_gui_store_kv_pool_free( db->kv_pool ) ) )  { db->metrics->map_full[ ring_idx ]++; return FD_GUI_STORE_MAP_FULL; }

  ulong   cur  = p->head_cur;
  uchar * slot = fd_gui_store_slot( db, ring_idx, p, cur );
  /* Seed the key inside the value so the stored record always carries a
     consistent key; the caller fills the remaining value bytes. */
  fd_memcpy( slot + p->key_off, key, p->key_sz );

  fd_gui_store_kv_idx_node_t * n = fd_gui_store_kv_pool_ele_acquire( db->kv_pool );
  n->key = db->kv_key_hash[ ring_idx ]( key );
  n->cur = cur;
  fd_gui_store_kv_idx_ele_insert( db->kv_idx[ ring_idx ], n, db->kv_pool );

  p->head_cur = cur + 1UL;
  if( val_out ) *val_out = slot;
  return FD_GUI_STORE_SUCCESS;
}

void *
fd_gui_store_kv_get( fd_gui_store_t * db,
                     ulong            ring_idx,
                     void const *     key ) {
  if( FD_UNLIKELY( ring_idx>=db->ring_cnt ) ) { FD_LOG_WARNING(( "fd_gui_store_kv_get: bad ring_idx %lu", ring_idx )); return NULL; }
  fd_gui_store_ring_t * p = &db->super->ring[ ring_idx ];
  if( FD_UNLIKELY( p->kind!=FD_GUI_STORE_KIND_KV ) ) { FD_LOG_WARNING(( "fd_gui_store_kv_get: ring_idx %lu is not a KV ring", ring_idx )); return NULL; }

  fd_gui_store_kv_idx_node_t * node = fd_gui_store_kv_find_node( db, p, ring_idx, key );
  db->metrics->kv_lookups[ ring_idx ]++;
  if( FD_UNLIKELY( !node ) ) return NULL;
  return (uchar *)fd_gui_store_slot( db, ring_idx, p, node->cur );
}

static uchar const *
fd_gui_store_kv_lowest_gt( fd_gui_store_t *         db,
                           ulong                    ring_idx,
                           fd_gui_store_ring_t const * p,
                           void const *             key,
                           uchar const *            gt ) {
  int  ( * key_cmp )( void const *, void const * ) = db->kv_key_cmp[ ring_idx ];
  uchar const * best     = NULL;
  uchar const * best_key = NULL;

  if( FD_LIKELY( key ) ) {
    /* Fast path: walk the query key's index bucket (records sharing its
       hashed leading field), tracking the lowest full key still > gt that
       matches `key`. */
    ulong ik = db->kv_key_hash[ ring_idx ]( key );
    fd_gui_store_kv_idx_node_t * node = fd_gui_store_kv_idx_ele_query( db->kv_idx[ ring_idx ], &ik, NULL, db->kv_pool );
    while( node ) {
      fd_gui_store_kv_idx_node_t * next = (fd_gui_store_kv_idx_node_t *)fd_gui_store_kv_idx_ele_next_const( node, NULL, db->kv_pool );
      if( FD_UNLIKELY( node->cur<p->evict_cur ) ) {
        fd_gui_store_kv_idx_ele_remove_fast( db->kv_idx[ ring_idx ], node, db->kv_pool );
        fd_gui_store_kv_pool_ele_release( db->kv_pool, node );
      } else {
        uchar const * val = (uchar const *)fd_gui_store_slot( db, ring_idx, p, node->cur );
        uchar const * k   = val + p->key_off;
        if( FD_LIKELY( 0==key_cmp( k, key ) ) ) {
          if( ( !gt   || key_cmp( k, gt       )>0 ) &&
              ( !best || key_cmp( k, best_key )<0 ) ) { best = val; best_key = k; }
        }
      }
      node = next;
    }
  } else {
    /* Slow path: no query key.  Only epoch-based eviction uses this. */
    for( ulong cur=p->evict_cur; cur<p->head_cur; cur++ ) {
      uchar const * val = (uchar const *)fd_gui_store_slot( db, ring_idx, p, cur );
      uchar const * k   = val + p->key_off;
      if( ( !gt   || key_cmp( k, gt       )>0 ) &&
          ( !best || key_cmp( k, best_key )<0 ) ) { best = val; best_key = k; }
    }
  }
  return best;
}

void *
fd_gui_store_kv_get_any( fd_gui_store_t * db,
                         ulong            ring_idx,
                         void const *     key ) {
  if( FD_UNLIKELY( ring_idx>=db->ring_cnt ) ) { FD_LOG_WARNING(( "fd_gui_store_kv_get_any: bad ring_idx %lu", ring_idx )); return NULL; }
  fd_gui_store_ring_t * p = &db->super->ring[ ring_idx ];
  if( FD_UNLIKELY( p->kind!=FD_GUI_STORE_KIND_KV ) ) { FD_LOG_WARNING(( "fd_gui_store_kv_get_any: ring_idx %lu is not a KV ring", ring_idx )); return NULL; }

  db->metrics->kv_lookups[ ring_idx ]++;
  return (void *)fd_gui_store_kv_lowest_gt( db, ring_idx, p, key, NULL );
}

fd_gui_store_kv_iter_t *
fd_gui_store_kv_iter_begin( fd_gui_store_t *          db,
                            fd_gui_store_kv_iter_t * iter,
                            ulong                    ring_idx,
                            void const *             key ) {
  memset( iter, 0, sizeof(fd_gui_store_kv_iter_t) );
  iter->_db = db;

  if( FD_UNLIKELY( ring_idx>=db->ring_cnt ) ) { FD_LOG_WARNING(( "fd_gui_store_kv_iter_begin: bad ring_idx %lu", ring_idx )); return iter; }
  fd_gui_store_ring_t * p = &db->super->ring[ ring_idx ];
  if( FD_UNLIKELY( p->kind!=FD_GUI_STORE_KIND_KV ) ) { FD_LOG_WARNING(( "fd_gui_store_kv_iter_begin: ring_idx %lu is not a KV ring", ring_idx )); return iter; }
  if( FD_UNLIKELY( !key || p->key_sz>sizeof(iter->_key) ) ) { FD_LOG_WARNING(( "fd_gui_store_kv_iter_begin: null key or key_sz %lu too large", p->key_sz )); return iter; }

  iter->_ring_idx = ring_idx;
  fd_memcpy( iter->_key, key, p->key_sz );

  db->metrics->kv_lookups[ ring_idx ]++;
  uchar const * best = fd_gui_store_kv_lowest_gt( db, ring_idx, p, iter->_key, NULL );
  if( FD_UNLIKELY( !best ) ) return iter; /* empty: _valid stays 0 */

  fd_memcpy( iter->_prev_key, best + p->key_off, p->key_sz );
  iter->_have_prev = 1;
  iter->_valid     = 1;
  iter->rec        = best;
  iter->key        = best + p->key_off;
  iter->key_sz     = p->key_sz;
  iter->val_sz     = p->val_sz;
  return iter;
}

int
fd_gui_store_kv_iter_next( fd_gui_store_kv_iter_t * iter ) {
  if( FD_UNLIKELY( !iter->_valid ) ) return 0;
  fd_gui_store_t *      db = (fd_gui_store_t *)iter->_db;
  fd_gui_store_ring_t * p  = &db->super->ring[ iter->_ring_idx ];

  uchar const * best = fd_gui_store_kv_lowest_gt( db, iter->_ring_idx, p,
                                                iter->_key,
                                                iter->_have_prev ? iter->_prev_key : NULL );
  if( FD_UNLIKELY( !best ) ) {
    iter->_valid = 0;
    iter->rec    = NULL;
    iter->key    = NULL;
    return 0;
  }

  fd_memcpy( iter->_prev_key, best + p->key_off, p->key_sz );
  iter->rec = best;
  iter->key = best + p->key_off;
  return 1;
}

int
fd_gui_store_kv_evict( fd_gui_store_t * db,
                       ulong            ring_idx,
                       void const *     hi_key,
                       ulong *          budget,
                       int *            drained ) {
  *drained = 1;
  if( FD_UNLIKELY( ring_idx>=db->ring_cnt ) ) { FD_LOG_WARNING(( "fd_gui_store_kv_evict: bad ring_idx %lu", ring_idx )); return FD_GUI_STORE_ERR; }
  fd_gui_store_ring_t * p = &db->super->ring[ ring_idx ];
  if( FD_UNLIKELY( p->kind!=FD_GUI_STORE_KIND_KV ) ) { FD_LOG_WARNING(( "fd_gui_store_kv_evict: ring_idx %lu is not a KV ring", ring_idx )); return FD_GUI_STORE_ERR; }

  ulong evict_cur0 = p->evict_cur;

  while( p->evict_cur<p->head_cur ) {
    uchar const * slot = (uchar const *)fd_gui_store_slot( db, ring_idx, p, p->evict_cur );
    uchar const * k    = slot + p->key_off;

    /* Reached the boundary key. Inserts are not ordered, so we may miss
       some entires after this within the eviction range. They will get
       caught in a subsequent eviction. Replay slots are inserted in
       roughly sorted order so this is acceptable. */
    if( db->kv_key_cmp[ ring_idx ]( k, hi_key )>=0 ) break;
    if( !*budget ) { *drained = 0; break; }

    /* Free the index node backing this record */
    fd_gui_store_kv_idx_node_t * node = fd_gui_store_kv_find_node( db, p, ring_idx, k );
    if( FD_LIKELY( node ) ) {
      fd_gui_store_kv_idx_ele_remove_fast( db->kv_idx[ ring_idx ], node, db->kv_pool );
      fd_gui_store_kv_pool_ele_release( db->kv_pool, node );
    }

    p->evict_cur++;
    (*budget)--;
    db->metrics->evict_records[ ring_idx ]++;
  }

  if( p->evict_cur!=evict_cur0 ) db->metrics->evicts[ ring_idx ]++;

  p->tail_cur = p->evict_cur; /* clean prefix: reclaim chases the watermark */
  fd_gui_store_region_reclaim( db, ring_idx, p );
  return FD_GUI_STORE_SUCCESS;
}

int
fd_gui_store_ts_append( fd_gui_store_t * db,
                        ulong            ring_idx,
                        void const *     val ) {
  if( FD_UNLIKELY( ring_idx>=db->ring_cnt ) ) { FD_LOG_WARNING(( "fd_gui_store_ts_append: bad ring_idx %lu", ring_idx )); return FD_GUI_STORE_ERR; }
  fd_gui_store_ring_t * p = &db->super->ring[ ring_idx ];
  if( FD_UNLIKELY( p->kind!=FD_GUI_STORE_KIND_TS ) ) { FD_LOG_WARNING(( "fd_gui_store_ts_append: ring_idx %lu is not a TS ring", ring_idx )); return FD_GUI_STORE_ERR; }

  if( FD_UNLIKELY( p->head_cur >= fd_gui_store_ring_head_limit( db, ring_idx, p ) ) ) {
    if( FD_UNLIKELY( !fd_gui_store_region_grow( db, ring_idx ) ) ) { db->metrics->map_full[ ring_idx ]++; return FD_GUI_STORE_MAP_FULL; }
  }

  /* Window is derived from the timestamp embedded in the value; the
     value is stored verbatim with no store-added header. */
  ulong   window = fd_gui_store_ts_window( p, val );
  ulong   cur    = p->head_cur;
  uchar * slot   = fd_gui_store_slot( db, ring_idx, p, cur );
  fd_memcpy( slot, val, p->val_sz );
  p->head_cur = cur + 1UL;
  db->metrics->ts_appends[ ring_idx ]++;

  fd_gui_store_ts_idx_ent_t * e = &fd_gui_store_ts_idx_row( db, ring_idx )[ window % FD_GUI_STORE_TS_IDX_DEPTH ];
  if( e->window==window ) {
    e->last_cur = cur; /* same window: extend the extent */
  } else {
    e->window    = window; /* fresh / overwritten window */
    e->first_cur = cur;
    e->last_cur  = cur;
  }
  return FD_GUI_STORE_SUCCESS;
}

int
fd_gui_store_ts_oldest_window( fd_gui_store_t * db,
                               ulong            ring_idx,
                               ulong *          out_window ) {
  if( FD_UNLIKELY( ring_idx>=db->ring_cnt ) ) return 0;
  fd_gui_store_ring_t const * p = &db->super->ring[ ring_idx ];
  if( FD_UNLIKELY( p->kind!=FD_GUI_STORE_KIND_TS ) ) return 0;
  if( FD_UNLIKELY( p->evict_cur>=p->head_cur ) )     return 0; /* empty */
  uchar const * slot = (uchar const *)fd_gui_store_slot( db, ring_idx, p, p->evict_cur );
  *out_window = fd_gui_store_ts_window( p, slot );
  return 1;
}

static void
fd_gui_store_ts_scan_bound( fd_gui_store_t * db,
                            ulong            ring_idx,
                            ulong            window_lo,
                            ulong            window_hi,
                            ulong *          lo_cur,
                            ulong *          hi_cur ) {
  fd_gui_store_ring_t const *       p   = &db->super->ring[ ring_idx ];
  fd_gui_store_ts_idx_ent_t const * row = fd_gui_store_ts_idx_row( db, ring_idx );
  ulong lo = ULONG_MAX; /* min first_cur */
  ulong hi = 0UL;       /* max last_cur+1 */
  int   any = 0;

  if( FD_LIKELY( window_hi-window_lo<FD_GUI_STORE_TS_IDX_DEPTH ) ) {
    for( ulong bucket=window_lo; bucket<=window_hi; bucket++ ) {
      fd_gui_store_ts_idx_ent_t const * e = &row[ bucket % FD_GUI_STORE_TS_IDX_DEPTH ];
      if( e->window!=bucket )        continue; /* empty slot, or aliased by another bucket */
      if( e->last_cur<p->evict_cur ) continue; /* fully evicted bucket */
      any = 1;
      lo  = fd_ulong_min( lo, e->first_cur );
      hi  = fd_ulong_max( hi, e->last_cur + 1UL );
    }
    if( !any ) { *lo_cur = p->head_cur; *hi_cur = p->head_cur; return; } /* empty */
    *lo_cur = fd_ulong_max( lo, p->evict_cur );
    *hi_cur = fd_ulong_min( hi, p->head_cur );
  } else {
    *lo_cur = p->evict_cur;
    *hi_cur = p->head_cur;
  }
}

static void
fd_gui_store_ts_scan_advance( fd_gui_store_ts_iter_t * iter ) {
  fd_gui_store_t *      db       = (fd_gui_store_t *)iter->_db;
  ulong              ring_idx = iter->_rec_sz - 1UL;
  fd_gui_store_ring_t * p        = &db->super->ring[ ring_idx ];

  ulong cur = (ulong)iter->_cur;
  for( ; cur<iter->_cur_hi; cur++ ) {
    uchar const * slot   = (uchar const *)fd_gui_store_slot( db, ring_idx, p, cur );
    ulong         window = fd_gui_store_ts_window( p, slot );
    if( FD_UNLIKELY( cur<p->evict_cur ) )    continue;        /* stale */
    if( window>iter->_window_hi )            continue;        /* out of range high */
    if( window<iter->_window_lo )            continue;        /* out of range low  */
    if( iter->_filter && !iter->_filter( slot, iter->_filter_ctx ) ) continue;
    iter->_valid = 1;
    iter->window = window;
    iter->rec    = (void *)slot;
    iter->_cur   = (void *)( cur + 1UL ); /* resume past this record */
    db->metrics->ts_read_records[ ring_idx ]++;
    return;
  }
  iter->_valid = 0;
  iter->rec    = NULL;
  iter->_cur   = (void *)cur;
}

fd_gui_store_ts_iter_t *
fd_gui_store_ts_scan_begin( fd_gui_store_t *          db,
                            fd_gui_store_ts_iter_t *  iter,
                            ulong                     ring_idx,
                            ulong                     window_lo,
                            ulong                     window_hi,
                            fd_gui_store_ts_filter_fn filter,
                            void *                    filter_ctx ) {
  memset( iter, 0, sizeof(fd_gui_store_ts_iter_t) );
  iter->_window_hi  = window_hi;
  iter->_filter     = filter;
  iter->_filter_ctx = filter_ctx;

  if( FD_UNLIKELY( ring_idx>=db->ring_cnt ) ) { FD_LOG_WARNING(( "fd_gui_store_ts_scan_begin: bad ring_idx %lu", ring_idx )); return iter; }
  fd_gui_store_ring_t * p = &db->super->ring[ ring_idx ];
  if( FD_UNLIKELY( p->kind!=FD_GUI_STORE_KIND_TS ) ) { FD_LOG_WARNING(( "fd_gui_store_ts_scan_begin: ring_idx %lu is not a TS ring", ring_idx )); return iter; }

  iter->_db         = (void *)db;
  iter->_rec_sz     = ring_idx + 1UL; /* ring_idx, biased so 0 means uninitialised */
  iter->_window_lo  = window_lo;
  db->metrics->ts_reads[ ring_idx ]++;
  ulong lo_cur, hi_cur;
  fd_gui_store_ts_scan_bound( db, ring_idx, window_lo, window_hi, &lo_cur, &hi_cur );
  iter->_cur        = (void *)lo_cur;
  iter->_cur_hi     = hi_cur;
  fd_gui_store_ts_scan_advance( iter );
  return iter;
}

int
fd_gui_store_ts_scan_next( fd_gui_store_ts_iter_t * iter ) {
  if( FD_UNLIKELY( !iter->_valid ) ) return 0;
  fd_gui_store_ts_scan_advance( iter );
  return iter->_valid;
}

void
fd_gui_store_ts_scan_end( fd_gui_store_ts_iter_t * iter ) {
  iter->_valid = 0;
  iter->rec    = NULL;
  iter->_db    = NULL;
}

int
fd_gui_store_ts_evict( fd_gui_store_t * db,
                       ulong            ring_idx,
                       ulong            hi_window,
                       ulong *          budget,
                       int *            drained ) {
  *drained = 1;
  if( FD_UNLIKELY( ring_idx>=db->ring_cnt ) ) { FD_LOG_WARNING(( "fd_gui_store_ts_evict: bad ring_idx %lu", ring_idx )); return FD_GUI_STORE_ERR; }
  fd_gui_store_ring_t * p = &db->super->ring[ ring_idx ];
  if( FD_UNLIKELY( p->kind!=FD_GUI_STORE_KIND_TS ) ) { FD_LOG_WARNING(( "fd_gui_store_ts_evict: ring_idx %lu is not a TS ring", ring_idx )); return FD_GUI_STORE_ERR; }

  ulong evict_cur0 = p->evict_cur;

  while( p->evict_cur<p->head_cur ) {
    uchar const * slot   = (uchar const *)fd_gui_store_slot( db, ring_idx, p, p->evict_cur );
    ulong         window = fd_gui_store_ts_window( p, slot );

    /* reached the watermark window. We may miss some entries in-window
       above this, they will get reclaimed in a subsequent eviction. */
    if( window>=hi_window ) break;
    if( !*budget ) { *drained = 0; break; }
    p->evict_cur++;
    (*budget)--;
    db->metrics->evict_records[ ring_idx ]++;
  }

  if( p->evict_cur!=evict_cur0 ) db->metrics->evicts[ ring_idx ]++;

  p->tail_cur = p->evict_cur;
  fd_gui_store_region_reclaim( db, ring_idx, p );
  return FD_GUI_STORE_SUCCESS;
}
