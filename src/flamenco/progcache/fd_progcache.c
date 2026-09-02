#include "fd_progcache.h"
#include "fd_progcache_clock.h"

#define MAP_NAME              fd_prog_recm
#define MAP_ELE_T             fd_progcache_rec_t
#define MAP_KEY_T             fd_progcache_rec_key_t
#define MAP_KEY               pair
#define MAP_KEY_EQ(k0,k1)     fd_progcache_rec_key_eq((k0),(k1))
#define MAP_KEY_HASH(k0,seed) fd_progcache_rec_key_hash( &(k0)->prog, (seed) )
#define MAP_IDX_T             uint
#define MAP_NEXT              map_next
#define MAP_MAGIC             (0xf173da2ce77ecdb8UL)
#define MAP_IMPL_STYLE        2
#include "../../util/tmpl/fd_map_chain_para.c"

#define POOL_NAME       fd_prog_txnp
#define POOL_T          fd_progcache_txn_t
#define POOL_IDX_T      uint
#define POOL_NEXT       map_next
#define POOL_IMPL_STYLE 2
#include "../../util/tmpl/fd_pool.c"

#define  MAP_NAME              fd_prog_txnm
#define  MAP_ELE_T             fd_progcache_txn_t
#define  MAP_KEY               xid
#define  MAP_IDX_T             uint
#define  MAP_NEXT              map_next
#define  MAP_MAGIC             (0xf173da2ce77ecdb9UL)
#define  MAP_IMPL_STYLE        2
#include "../../util/tmpl/fd_map_chain.c"

/* Metadata one record costs: the record and its map chain. */

#define FD_PROGCACHE_REC_META_SZ ( sizeof(fd_progcache_rec_t)                 + \
                                   sizeof(fd_prog_recm_shmem_private_chain_t) )

/* fd_progcache_slot_cost returns the amount of memory a single slot consumes. */
FD_FN_CONST static inline ulong
fd_progcache_slot_cost( ulong c ) {
  return fd_progcache_cache_slot_sz[ c ] + FD_PROGCACHE_REC_META_SZ;
}

/* fd_progcache_arena_sz returns the amount of memory an entire arena
   (with slot_cnt[c] for each class c) consumes. */
static ulong
fd_progcache_arena_sz( ulong const * slot_cnt ) {
  ulong sz = 0UL;
  for( ulong c=0UL; c<FD_PROGCACHE_CACHE_CLASS_CNT; c++ ) {
    sz += slot_cnt[ c ]*fd_progcache_cache_slot_sz[ c ];
  }
  return sz;
}

/* fd_progcache_layout_footprint returns the exact shmem footprint of a cache
   holding txn_max transactions, rec_max records and arena_sz bytes of value arena.
   fd_progcache_new lays out these same regions in this same order. */
static ulong
fd_progcache_layout_footprint( ulong txn_max,
                               ulong rec_max,
                               ulong arena_sz ) {
  ulong l = FD_LAYOUT_INIT;

  l = FD_LAYOUT_APPEND( l, alignof(fd_progcache_shmem_t), sizeof(fd_progcache_shmem_t) );

  ulong txn_chain_cnt = fd_prog_txnm_chain_cnt_est( txn_max );
  l = FD_LAYOUT_APPEND( l, fd_prog_txnm_align(), fd_prog_txnm_footprint( txn_chain_cnt ) );
  l = FD_LAYOUT_APPEND( l, fd_prog_txnp_align(), fd_prog_txnp_footprint( txn_max ) );

  ulong rec_chain_cnt = fd_prog_recm_chain_cnt_est( rec_max );
  l = FD_LAYOUT_APPEND( l, fd_prog_recm_align(), fd_prog_recm_footprint( rec_chain_cnt ) );
  l = FD_LAYOUT_APPEND( l, alignof(fd_progcache_rec_t), sizeof(fd_progcache_rec_t)*rec_max );
  l = FD_LAYOUT_APPEND( l, fd_progcache_val_align(), arena_sz );

  return FD_LAYOUT_FINI( l, fd_progcache_shmem_align() );
}

/* fd_progcache_setup_slots provisions progcache_sz across the classes.  Returns rec_max (== sum(slot_cnt)),
   or 0 if the budget cannot cover class_min for every class. */

ulong
fd_progcache_setup_slots( ulong   txn_max,
                          ulong   progcache_sz,
                          ulong * slot_cnt ) {
  /* Share of the surplus per data class, from the mainnet size distribution.
     Class 0 is not distributed by share: it takes the remainder, so its entry
     below is nominal and it also absorbs every other class's rounding slack. */
  static const uint pct[ FD_PROGCACHE_CACHE_DATA_CLASS_CNT ] = {
     4U,   /* class 0: 128 KiB */
    29U,   /* class 1: 512 KiB */
    25U,   /* class 2:   1 MiB */
    18U,   /* class 3:   2 MiB */
    14U,   /* class 4:   4 MiB */
    10U,   /* class 5:  ~10 MiB */
  };

  ulong min_sz = fd_progcache_shmem_min_sz( txn_max );
  if( FD_UNLIKELY( progcache_sz<min_sz ) ) return 0UL;

  /* Seed every class with its guaranteed minimum, which is what min_sz paid for. */
  for( ulong c=0UL; c<FD_PROGCACHE_CACHE_CLASS_CNT; c++ ) {
    slot_cnt[ c ] = fd_progcache_cache_class_min( c );
  }

  /* Distribute the surplus by percentage, rounding down. */
  ulong surplus  = progcache_sz - min_sz;
  ulong leftover = surplus;
  for( ulong c=1UL; c<FD_PROGCACHE_CACHE_DATA_CLASS_CNT; c++ ) {
    ulong want = ((surplus/100UL)*(ulong)pct[ c ]) / fd_progcache_slot_cost( c );
    slot_cnt[ c ] += want;
    leftover      -= want*fd_progcache_slot_cost( c );
  }
  slot_cnt[ 0 ] += leftover / fd_progcache_slot_cost( 0 );

  ulong rec_max = 0UL;
  for( ulong c=0UL; c<FD_PROGCACHE_CACHE_CLASS_CNT; c++ ) rec_max += slot_cnt[ c ];
  return rec_max;
}

FD_FN_CONST ulong
fd_progcache_shmem_align( void ) {
  return fd_ulong_max( fd_ulong_max( fd_ulong_max( fd_ulong_max( fd_ulong_max( fd_ulong_max(
      alignof(fd_progcache_shmem_t),
      fd_prog_txnm_align() ),
      fd_prog_txnp_align() ),
      alignof(fd_progcache_txn_t) ),
      fd_prog_recm_align() ),
      alignof(fd_progcache_rec_t) ),
      fd_progcache_val_align() );
}

/* Fork depth cannot exceed txn_max, so bounding txn_max by the lineage array's
   depth is what keeps fd_progcache_load_fork from overrunning it. */

ulong
fd_progcache_shmem_min_sz( ulong txn_max ) {
  if( FD_UNLIKELY( !txn_max || txn_max>FD_PROGCACHE_DEPTH_MAX ) ) return 0UL;

  ulong min_sz = fd_progcache_layout_footprint( txn_max, 0UL, 0UL ) + fd_progcache_val_align();
  for( ulong c=0UL; c<FD_PROGCACHE_CACHE_CLASS_CNT; c++ ) {
    min_sz += fd_progcache_cache_class_min( c )*fd_progcache_slot_cost( c );
  }

  /* round at 1MiB */
  return ( (min_sz>>20UL)+1UL )<<20UL;
}

ulong
fd_progcache_shmem_footprint( ulong txn_max,
                              ulong progcache_sz ) {
  if( FD_UNLIKELY( !txn_max || txn_max>FD_PROGCACHE_DEPTH_MAX ) ) return 0UL;

  /* explicitly validate that progcache_sz is enough */
  ulong slot_cnt[ FD_PROGCACHE_CACHE_CLASS_CNT ];
  if( FD_UNLIKELY( !fd_progcache_setup_slots( txn_max, progcache_sz, slot_cnt ) ) ) return 0UL;

  return progcache_sz;
}

fd_progcache_shmem_t *
fd_progcache_shmem_new( void * shmem,
                        ulong  wksp_tag,
                        ulong  seed,
                        ulong  txn_max,
                        ulong  progcache_sz ) {
  fd_progcache_shmem_t * pc   = shmem;
  fd_wksp_t *            wksp = fd_wksp_containing( shmem );

  if( FD_UNLIKELY( !pc ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)pc, fd_progcache_shmem_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !wksp_tag ) ) {
    FD_LOG_WARNING(( "bad wksp_tag" ));
    return NULL;
  }

  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_WARNING(( "shmem must be part of a workspace" ));
    return NULL;
  }

  if( FD_UNLIKELY( !txn_max || txn_max>FD_PROGCACHE_DEPTH_MAX ) ) {
    FD_LOG_WARNING(( "invalid txn_max" ));
    return NULL;
  }

  ulong slot_cnt[ FD_PROGCACHE_CACHE_CLASS_CNT ];
  ulong rec_max = fd_progcache_setup_slots( txn_max, progcache_sz, slot_cnt );
  if( FD_UNLIKELY( !rec_max || rec_max>UINT_MAX ) ) {
    FD_LOG_WARNING(( "invalid progcache_sz (%lu B)", progcache_sz ));
    return NULL;
  }
  ulong arena_sz = fd_progcache_arena_sz( slot_cnt );

  FD_SCRATCH_ALLOC_INIT( l, pc+1 );

  ulong txn_chain_cnt = fd_prog_txnm_chain_cnt_est( txn_max );
  void * txn_map  = FD_SCRATCH_ALLOC_APPEND( l, fd_prog_txnm_align(), fd_prog_txnm_footprint( txn_chain_cnt ) );
  void * txn_pool = FD_SCRATCH_ALLOC_APPEND( l, fd_prog_txnp_align(), fd_prog_txnp_footprint( txn_max ) );

  ulong rec_chain_cnt = fd_prog_recm_chain_cnt_est( rec_max );
  void *               rec_map = FD_SCRATCH_ALLOC_APPEND( l, fd_prog_recm_align(), fd_prog_recm_footprint( rec_chain_cnt ) );
  fd_progcache_rec_t * rec_ele = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_progcache_rec_t), sizeof(fd_progcache_rec_t)*rec_max );
  uchar *              arena   = FD_SCRATCH_ALLOC_APPEND( l, fd_progcache_val_align(), arena_sz );

  ulong layout_sz = fd_progcache_layout_footprint( txn_max, rec_max, arena_sz );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, fd_progcache_shmem_align() ) == (ulong)pc + layout_sz );
  FD_TEST( layout_sz<=progcache_sz );

  fd_memset( pc,         0, offsetof(fd_progcache_shmem_t, spill) ); /* spill fields set below */
  fd_memset( &pc->cache, 0, sizeof(pc->cache)                     );
  fd_memset( rec_ele,    0, rec_max*sizeof(fd_progcache_rec_t)    );

  pc->wksp_tag = wksp_tag;
  pc->seed     = seed;

  /* Fork graph */

  pc->txn.map_gaddr = fd_wksp_gaddr_fast( wksp, fd_prog_txnm_new( txn_map, txn_chain_cnt, seed ) );
  void * txn_pool2 = fd_prog_txnp_new( txn_pool, txn_max );
  pc->txn.pool_gaddr = fd_wksp_gaddr_fast( wksp, txn_pool2 );
  fd_progcache_txn_t * txn_ele = fd_prog_txnp_join( txn_pool2 );
  pc->txn.ele_gaddr = fd_wksp_gaddr_fast( wksp, txn_ele );
  pc->txn.max = txn_max;
  pc->txn.child_head_idx = UINT_MAX;
  pc->txn.child_tail_idx = UINT_MAX;
  pc->txn.root = fd_progcache_fork_id_initial();
  pc->txn.seq  = fd_progcache_fork_id_initial();
  fd_rwlock_new( &pc->txn.rwlock );
  for( ulong i=0UL; i<txn_max; i++ ) {
    fd_rwlock_new( &txn_ele[ i ].lock );
  }
  fd_prog_txnp_leave( txn_ele );

  /* Record map + array.  Records double as value slots: free records are
     kept write-locked (a stale speculative reader can never lock one) on
     their class's free list. */

  pc->rec.map_gaddr   = fd_wksp_gaddr_fast( wksp, fd_prog_recm_new( rec_map, rec_chain_cnt, seed ) );
  pc->rec.ele_gaddr   = fd_wksp_gaddr_fast( wksp, rec_ele );
  pc->rec.max         = (uint)rec_max;
  for( ulong i=0UL; i<rec_max; i++ ) rec_ele[ i ].lock.value = FD_RWLOCK_WRITE_LOCK;

  fd_rwlock_new( &pc->spill.lock );
  pc->spill.rec_used  = 0U;
  pc->spill.spad_used = 0U;

  /* Size-class cache: partition the record array and the value arena by class. */
  ulong rec_base    = 0UL;
  ulong arena_gaddr = arena_sz ? fd_wksp_gaddr_fast( wksp, arena ) : 0UL;

  ulong arena_off = 0UL;
  for( ulong c=0UL; c<FD_PROGCACHE_CACHE_CLASS_CNT; c++ ) {
    ulong n       = slot_cnt[ c ];
    ulong slot_sz = fd_progcache_cache_slot_sz[ c ];
    pc->cache.class_max     [ c ] = n;
    pc->cache.rec_base  [ c ] = rec_base;
    pc->cache.clock_hand[ c ].val = 0UL; /* ticket, not an index */

    /* Every record starts free.  Construction is single threaded, so chain them
       directly: the top is the highest index and each links to the one below, so
       a class hands out descending indices.  An empty class parks UINT_MAX. */
    pc->cache.free_cnt[ c ].val     = n;
    pc->cache.free_top[ c ].ver_top = n ? (ulong)(uint)( rec_base+n-1UL ) : (ulong)UINT_MAX;
    for( ulong s=0UL; s<n; s++ )
      rec_ele[ rec_base+s ].free_next = (uint)( s ? ( rec_base+s-1UL ) : (ulong)UINT_MAX );

    if( n ) {
      pc->cache.arena_gaddr[ c ] = arena_gaddr + arena_off;
      arena_off += n*slot_sz;
    }

    rec_base += n;
  }

  FD_COMPILER_MFENCE();
  FD_VOLATILE( pc->magic ) = FD_PROGCACHE_SHMEM_MAGIC;
  FD_COMPILER_MFENCE();

  return (void *)pc;

}

fd_progcache_join_t *
fd_progcache_shmem_join( fd_progcache_join_t *  ljoin,
                         fd_progcache_shmem_t * shmem ) {

  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_progcache_shmem_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }
  fd_wksp_t * wksp = fd_wksp_containing( shmem );
  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_WARNING(( "shmem must be part of a workspace" ));
    return NULL;
  }
  if( FD_UNLIKELY( shmem->magic!=FD_PROGCACHE_SHMEM_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  if( FD_UNLIKELY( !ljoin ) ) {
    FD_LOG_WARNING(( "NULL join" ));
    return NULL;
  }

  memset( ljoin, 0, sizeof(fd_progcache_join_t) );

  ljoin->shmem     = shmem;
  ljoin->data_base = wksp; /* all value/bookkeeping gaddrs are wksp-relative */

  ljoin->txn.map = fd_prog_txnm_join( fd_wksp_laddr( wksp, shmem->txn.map_gaddr ) );
  if( FD_UNLIKELY( !ljoin->txn.map ) ) {
    FD_LOG_WARNING(( "fd_prog_txnm_join failed" ));
    return NULL;
  }
  ljoin->txn.pool = fd_prog_txnp_join( fd_wksp_laddr( wksp, shmem->txn.pool_gaddr ) );
  if( FD_UNLIKELY( !ljoin->txn.pool ) ) {
    FD_LOG_WARNING(( "fd_prog_txnp_join failed" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_prog_recm_join( ljoin->rec.map, fd_wksp_laddr( wksp, shmem->rec.map_gaddr ), fd_wksp_laddr( wksp, shmem->rec.ele_gaddr ), shmem->rec.max ) ) ) {
    FD_LOG_WARNING(( "fd_prog_recm_join failed" ));
    return NULL;
  }
  ljoin->rec.ele = fd_wksp_laddr( wksp, shmem->rec.ele_gaddr );
  ljoin->rec.max = shmem->rec.max;

  return ljoin;
}

void *
fd_progcache_shmem_leave( fd_progcache_join_t *   ljoin,
                          fd_progcache_shmem_t ** opt_shmem ) {

  if( FD_UNLIKELY( !ljoin ) ) {
    FD_LOG_WARNING(( "NULL join" ));
    if( opt_shmem ) *opt_shmem = NULL;
    return NULL;
  }

  void * shmem = ljoin->shmem;

  memset( ljoin, 0, sizeof(fd_progcache_join_t) );

  if( opt_shmem ) *opt_shmem = shmem;
  return shmem;
}

void *
fd_progcache_shmem_delete( fd_progcache_shmem_t * shmem ) {

  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_progcache_shmem_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  fd_wksp_t * wksp = fd_wksp_containing( shmem );
  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_WARNING(( "shmem must be part of a workspace" ));
    return NULL;
  }

  if( FD_UNLIKELY( shmem->magic!=FD_PROGCACHE_SHMEM_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  FD_TEST( !shmem->txn.rwlock.value );
  fd_progcache_txn_t * txn0 = fd_wksp_laddr_fast( wksp, shmem->txn.ele_gaddr );
  for( ulong i=0UL; i<shmem->txn.max; i++ ) FD_TEST( !txn0[ i ].lock.value );
  FD_TEST( !shmem->spill.lock.value );

  FD_COMPILER_MFENCE();
  FD_VOLATILE( shmem->magic ) = 0UL;
  FD_COMPILER_MFENCE();

  return shmem;
}

void *
fd_progcache_shmem_delete_fast( fd_progcache_shmem_t * shmem ) {

  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_progcache_shmem_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_wksp_containing( shmem ) ) ) {
    FD_LOG_WARNING(( "shmem must be part of a workspace" ));
    return NULL;
  }

  if( FD_UNLIKELY( shmem->magic!=FD_PROGCACHE_SHMEM_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  FD_COMPILER_MFENCE();
  FD_VOLATILE( shmem->magic ) = 0UL;
  FD_COMPILER_MFENCE();

  fd_wksp_free_laddr( shmem );

  return shmem;
}
