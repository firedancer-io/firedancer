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

/* FD_PROGCACHE_ARENA_EPS is loose space reserved for the alignment of the
   per-class arena allocations (7 wksp allocations x worst-case padding). */

#define FD_PROGCACHE_ARENA_EPS (64UL<<10)

/* fd_progcache_meta_footprint returns the exact shmem footprint for a
   record capacity of rec_max (each class free stack is sized at rec_max,
   so the layout depends only on (txn_max, rec_max)). */

static ulong
fd_progcache_meta_footprint( ulong txn_max,
                             ulong rec_max ) {
  ulong l = FD_LAYOUT_INIT;

  l = FD_LAYOUT_APPEND( l, alignof(fd_progcache_shmem_t), sizeof(fd_progcache_shmem_t) );

  ulong txn_chain_cnt = fd_prog_txnm_chain_cnt_est( txn_max );
  l = FD_LAYOUT_APPEND( l, fd_prog_txnm_align(), fd_prog_txnm_footprint( txn_chain_cnt ) );
  l = FD_LAYOUT_APPEND( l, fd_prog_txnp_align(), fd_prog_txnp_footprint( txn_max ) );

  ulong rec_chain_cnt = fd_prog_recm_chain_cnt_est( rec_max );
  l = FD_LAYOUT_APPEND( l, fd_prog_recm_align(), fd_prog_recm_footprint( rec_chain_cnt ) );
  l = FD_LAYOUT_APPEND( l, alignof(fd_progcache_rec_t), sizeof(fd_progcache_rec_t)*rec_max );
  l = FD_LAYOUT_APPEND( l, fd_progcache_state_align(), fd_progcache_state_footprint( rec_max ) );

  for( ulong c=0UL; c<FD_PROGCACHE_CLASS_CNT; c++ )
    l = FD_LAYOUT_APPEND( l, fd_prog_freestack_align(), fd_prog_freestack_footprint( rec_max ) );

  return FD_LAYOUT_FINI( l, fd_progcache_shmem_align() );
}

/* fd_progcache_setup_slots derives the exact allocation for a shared
   memory budget of shared_sz bytes (metadata + value arenas):

     1. provision the whole budget to bound the record count, and round
        the bound up to a power of two -> rec_max (the pow2 headroom
        absorbs any class-mix shift between the two passes);
     2. metadata cost is then exact: meta_footprint( txn_max, rec_max );
     3. provision the remaining bytes -> the actual per-class counts.

   If successful, each class is guaranteed 1+ slots and
   sum(slot_cnt) <= rec_max.  Returns rec_max, or 0 on error. */

static ulong
fd_progcache_setup_slots( ulong   txn_max,
                          ulong   shared_sz,
                          ulong * slot_cnt ) {
  if( FD_UNLIKELY( !fd_progcache_class_cnt( shared_sz, slot_cnt ) ) ) return 0UL;
  ulong bound = 0UL;
  for( ulong c=0UL; c<FD_PROGCACHE_CLASS_CNT; c++ ) bound += slot_cnt[ c ];
  ulong rec_max = fd_ulong_pow2_up( bound );

  ulong meta = fd_progcache_meta_footprint( txn_max, rec_max );
  if( FD_UNLIKELY( shared_sz < meta+FD_PROGCACHE_ARENA_EPS ) ) return 0UL;
  ulong budget = shared_sz - meta - FD_PROGCACHE_ARENA_EPS;

  if( FD_UNLIKELY( !fd_progcache_class_cnt( budget, slot_cnt ) ) ) return 0UL;
  ulong tot = 0UL;
  for( ulong c=0UL; c<FD_PROGCACHE_CLASS_CNT; c++ ) tot += slot_cnt[ c ];
  if( FD_UNLIKELY( tot>rec_max ) ) return 0UL; /* unreachable: pow2 headroom */
  return rec_max;
}

/* Typical allocation size progcache reports to the workspace partition
   estimator.  Only the estimate below uses it. */

#define FD_PROGCACHE_WKSP_SZ_TYPICAL (1UL<<18) /* 256 KiB */

FD_FN_CONST ulong
fd_progcache_wksp_part_max( ulong wksp_sz ) {
  return fd_wksp_part_max_est( wksp_sz, FD_PROGCACHE_WKSP_SZ_TYPICAL );
}

FD_FN_CONST ulong
fd_progcache_shared_sz( ulong wksp_sz ) {
  ulong part_max = fd_progcache_wksp_part_max( wksp_sz );
  if( FD_UNLIKELY( !part_max ) ) return 0UL;
  return fd_wksp_data_max_est( wksp_sz, part_max );
}

FD_FN_CONST ulong
fd_progcache_wksp_sz( ulong shared_sz ) {
  /* Workspace overhead grows with the workspace size, so invert by
     growing until the data region covers shared_sz.  Using the forward
     function keeps the two directions consistent by construction; the
     shortfall shrinks by more than an order of magnitude per step. */
  ulong wksp_sz = shared_sz;
  for( int i=0; i<8; i++ ) {
    ulong got = fd_progcache_shared_sz( wksp_sz );
    if( FD_LIKELY( got>=shared_sz ) ) break;
    wksp_sz += shared_sz-got;
  }
  return fd_ulong_align_up( wksp_sz, 1UL<<20 );
}

ulong
fd_progcache_min_wksp_sz( ulong txn_max ) {
  /* Smallest budget: the guaranteed class minimums plus the exact metadata
     for the (pow2-rounded) record count. */
  ulong min_value = 0UL;
  ulong min_recs  = 0UL;
  for( ulong c=0UL; c<FD_PROGCACHE_CLASS_CNT; c++ ) {
    min_value += fd_progcache_class_min( c )*fd_progcache_slot_sz[ c ];
    min_recs  += fd_progcache_class_min( c );
  }
  ulong rec_max = fd_ulong_pow2_up( min_recs );
  ulong shared  = min_value + fd_progcache_meta_footprint( txn_max, rec_max ) + FD_PROGCACHE_ARENA_EPS;

  return fd_progcache_wksp_sz( shared );
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
      fd_progcache_state_align() );
}

ulong
fd_progcache_shmem_footprint( ulong txn_max,
                              ulong shared_sz ) {
  if( FD_UNLIKELY( !txn_max || txn_max>UINT_MAX ) ) return 0UL;

  ulong slot_cnt[ FD_PROGCACHE_CLASS_CNT ];
  ulong rec_max = fd_progcache_setup_slots( txn_max, shared_sz, slot_cnt );
  if( FD_UNLIKELY( !rec_max ) ) return 0UL;

  return fd_progcache_meta_footprint( txn_max, rec_max );
}

fd_progcache_shmem_t *
fd_progcache_shmem_new( void * shmem,
                        ulong  wksp_tag,
                        ulong  seed,
                        ulong  txn_max,
                        ulong  shared_sz ) {
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

  if( FD_UNLIKELY( !txn_max || txn_max>UINT_MAX ) ) {
    FD_LOG_WARNING(( "invalid txn_max" ));
    return NULL;
  }

  /* FD_PROGCACHE_SPAD_MAX is exactly DEPTH*SLOT_TOP_SZ, so the spill spad
     covers a full CPI stack only while align_up never pads: every value
     footprint is a multiple of val_align, and so must the slot size be. */
  FD_TEST( fd_ulong_is_aligned( FD_PROGCACHE_SLOT_TOP_SZ, fd_progcache_val_align() ) );

  ulong slot_cnt[ FD_PROGCACHE_CLASS_CNT ];
  ulong rec_max = fd_progcache_setup_slots( txn_max, shared_sz, slot_cnt );
  if( FD_UNLIKELY( !rec_max || rec_max>UINT_MAX ) ) {
    FD_LOG_WARNING(( "invalid shared_sz (%lu B)", shared_sz ));
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT( l, pc+1 );

  ulong txn_chain_cnt = fd_prog_txnm_chain_cnt_est( txn_max );
  void * txn_map  = FD_SCRATCH_ALLOC_APPEND( l, fd_prog_txnm_align(), fd_prog_txnm_footprint( txn_chain_cnt ) );
  void * txn_pool = FD_SCRATCH_ALLOC_APPEND( l, fd_prog_txnp_align(), fd_prog_txnp_footprint( txn_max ) );

  ulong rec_chain_cnt = fd_prog_recm_chain_cnt_est( rec_max );
  void *               rec_map = FD_SCRATCH_ALLOC_APPEND( l, fd_prog_recm_align(), fd_prog_recm_footprint( rec_chain_cnt ) );
  fd_progcache_rec_t * rec_ele = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_progcache_rec_t), sizeof(fd_progcache_rec_t)*rec_max );
  uchar *              state   = FD_SCRATCH_ALLOC_APPEND( l, fd_progcache_state_align(), fd_progcache_state_footprint( rec_max ) );

  void * fs_mem[ FD_PROGCACHE_CLASS_CNT ];
  for( ulong c=0UL; c<FD_PROGCACHE_CLASS_CNT; c++ )
    fs_mem[ c ] = FD_SCRATCH_ALLOC_APPEND( l, fd_prog_freestack_align(), fd_prog_freestack_footprint( rec_max ) );

  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, fd_progcache_shmem_align() ) == (ulong)pc + fd_progcache_shmem_footprint( txn_max, shared_sz ) );

  fd_memset( pc,         0, offsetof(fd_progcache_shmem_t, spill) ); /* spill doesn't need to be zeroed */
  fd_memset( &pc->cache, 0, sizeof(pc->cache)                     );
  fd_memset( rec_ele,    0, rec_max*sizeof(fd_progcache_rec_t)    );
  fd_memset( state,      0, fd_progcache_state_footprint( rec_max )    );

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
  for( ulong i=0UL; i<txn_max; i++ ) {
    fd_rwlock_new( &txn_ele[ i ].lock );
  }
  fd_prog_txnp_leave( txn_ele );

  /* Record map + array */

  pc->rec.map_gaddr   = fd_wksp_gaddr_fast( wksp, fd_prog_recm_new( rec_map, rec_chain_cnt, seed ) );
  pc->rec.ele_gaddr   = fd_wksp_gaddr_fast( wksp, rec_ele );
  pc->rec.state_gaddr = fd_wksp_gaddr_fast( wksp, state );
  pc->rec.max         = (uint)rec_max;
  fd_rwlock_new( &pc->rec.reclaim_lock );
  pc->rec.reclaim_head = UINT_MAX; /* shared deferred-reclaim list starts empty */
  for( ulong i=0UL; i<rec_max; i++ ) rec_ele[ i ].lock.value = FD_RWLOCK_WRITE_LOCK;

  fd_rwlock_new( &pc->txn.rwlock );

  fd_rwlock_new( &pc->spill.lock );
  pc->spill.rec_used  = 0U;
  pc->spill.spad_used = 0U;

  /* Size-class cache: partition the record array by class and carve each
     class's value arena directly from the workspace (the nx class has
     none). */
  ulong rec_base = 0UL;
  for( ulong c=0UL; c<FD_PROGCACHE_CLASS_CNT; c++ ) {
    ulong n       = slot_cnt[ c ];
    ulong slot_sz = fd_progcache_slot_sz[ c ];
    fd_rwlock_new( &pc->cache.lock[ c ] );
    pc->cache.nslot     [ c ] = n;
    pc->cache.rec_base  [ c ] = rec_base;
    pc->cache.clock_hand[ c ] = rec_base;

    uint * freestack = fd_prog_freestack_join( fd_prog_freestack_new( fs_mem[ c ], rec_max ) );
    pc->cache.free_gaddr[ c ] = fd_wksp_gaddr_fast( wksp, fs_mem[ c ] );
    pc->cache.free_cnt  [ c ] = n;
    for( ulong s=0UL; s<n; s++ ) fd_prog_freestack_push( freestack, (uint)( rec_base+s ) ); /* all records free */

    if( slot_sz && n ) {
      void * arena = fd_wksp_alloc_laddr( wksp, fd_progcache_val_align(), n*slot_sz, wksp_tag );
      if( FD_UNLIKELY( !arena ) ) {
        FD_LOG_WARNING(( "progcache cache arena alloc failed (class %lu, %lu B); heap too small?", c, n*slot_sz ));
        goto fail;
      }
      pc->cache.arena_gaddr[ c ] = fd_wksp_gaddr_fast( wksp, arena );
    }

    rec_base += n;
  }

  FD_COMPILER_MFENCE();
  FD_VOLATILE( pc->magic ) = FD_PROGCACHE_SHMEM_MAGIC;
  FD_COMPILER_MFENCE();

  return (void *)pc;

fail:
  /* Roll back the per-class arenas allocated before the failure (each is a
     distinct wksp block; unset gaddrs are 0).  Clear each gaddr after
     freeing so a retried construction in the same shmem stays safe. */
  for( ulong c=0UL; c<FD_PROGCACHE_CLASS_CNT; c++ ) {
    if( pc->cache.arena_gaddr[ c ] ) fd_wksp_free_laddr( fd_wksp_laddr_fast( wksp, pc->cache.arena_gaddr[ c ] ) );
    pc->cache.arena_gaddr[ c ] = 0UL;
  }
  return NULL;
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

  ljoin->txn.pool = fd_prog_txnp_join( fd_wksp_laddr( wksp, shmem->txn.pool_gaddr ) );
  if( FD_UNLIKELY( !ljoin->txn.pool ) ) {
    FD_LOG_WARNING(( "fd_prog_txnp_join failed" ));
    return NULL;
  }
  ljoin->txn.map = fd_prog_txnm_join( fd_wksp_laddr( wksp, shmem->txn.map_gaddr ) );
  if( FD_UNLIKELY( !ljoin->txn.map ) ) {
    FD_LOG_WARNING(( "fd_prog_txnm_join failed" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_prog_recm_join( ljoin->rec.map, fd_wksp_laddr( wksp, shmem->rec.map_gaddr ), fd_wksp_laddr( wksp, shmem->rec.ele_gaddr ), shmem->rec.max ) ) ) {
    FD_LOG_WARNING(( "fd_prog_recm_join failed" ));
    return NULL;
  }
  ljoin->rec.ele   = fd_wksp_laddr( wksp, shmem->rec.ele_gaddr );
  ljoin->rec.max   = shmem->rec.max;
  ljoin->rec.state = fd_wksp_laddr( wksp, shmem->rec.state_gaddr );

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
  FD_TEST( !shmem->spill.lock.value );
  FD_TEST( shmem->rec.reclaim_head==UINT_MAX );
  fd_progcache_txn_t * txn0 = fd_wksp_laddr_fast( wksp, shmem->txn.ele_gaddr );
  for( ulong i=0UL; i<shmem->txn.max; i++ ) FD_TEST( !txn0[ i ].lock.value );

  /* Free the size-class value arenas (one wksp allocation each; none for
     nx). */
  for( ulong c=0UL; c<FD_PROGCACHE_CLASS_CNT; c++ ) {
    if( shmem->cache.arena_gaddr[ c ] ) fd_wksp_free_laddr( fd_wksp_laddr_fast( wksp, shmem->cache.arena_gaddr[ c ] ) );
  }

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

  if( FD_UNLIKELY( shmem->magic!=FD_PROGCACHE_SHMEM_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  fd_wksp_t * wksp = fd_wksp_containing( shmem );
  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_WARNING(( "shmem must be part of a workspace" ));
    return NULL;
  }

  FD_COMPILER_MFENCE();
  FD_VOLATILE( shmem->magic ) = 0UL;
  FD_COMPILER_MFENCE();

  ulong const tags[1] = { shmem->wksp_tag };
  fd_wksp_tag_free( wksp, tags, 1UL );

  return shmem;
}
