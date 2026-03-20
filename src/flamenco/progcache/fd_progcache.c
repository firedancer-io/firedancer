#include "fd_progcache.h"
#include "fd_progcache_clock.h"

#define POOL_NAME       fd_prog_recp
#define POOL_ELE_T      fd_progcache_rec_t
#define POOL_IDX_T      uint
#define POOL_NEXT       map_next
#define POOL_IMPL_STYLE 2
#include "../../util/tmpl/fd_pool_para.c"

#define MAP_NAME              fd_prog_recm
#define MAP_ELE_T             fd_progcache_rec_t
#define MAP_KEY_T             fd_funk_xid_key_pair_t
#define MAP_KEY               pair
#define MAP_KEY_EQ(k0,k1)     fd_funk_xid_key_pair_eq((k0),(k1))
#define MAP_KEY_HASH(k0,seed) fd_funk_xid_key_pair_hash((k0),(seed))
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
#define  MAP_KEY_T             fd_xid_t
#define  MAP_KEY               xid
#define  MAP_KEY_EQ(k0,k1)     fd_funk_txn_xid_eq((k0),(k1))
#define  MAP_KEY_HASH(k0,seed) fd_funk_txn_xid_hash((k0),(seed))
#define  MAP_IDX_T             uint
#define  MAP_NEXT              map_next
#define  MAP_MAGIC             (0xf173da2ce77ecdb9UL)
#define  MAP_IMPL_STYLE        2
#include "../../util/tmpl/fd_map_chain.c"

FD_FN_CONST ulong
fd_progcache_shmem_align( void ) {
  return fd_ulong_max( fd_ulong_max( fd_ulong_max( fd_ulong_max( fd_ulong_max( fd_ulong_max( fd_ulong_max( fd_ulong_max(
      alignof(fd_progcache_shmem_t),
      fd_prog_txnm_align() ),
      fd_prog_txnp_align() ),
      alignof(fd_progcache_txn_t) ),
      fd_prog_recm_align() ),
      fd_prog_recp_align() ),
      alignof(fd_progcache_rec_t) ),
      fd_alloc_align() ),
      fd_prog_cbits_align() );
}

FD_FN_CONST ulong
fd_progcache_shmem_footprint( ulong txn_max,
                              ulong rec_max ) {
  if( FD_UNLIKELY( txn_max>UINT_MAX ) ) return 0UL;
  if( FD_UNLIKELY( rec_max>UINT_MAX ) ) return 0UL;

  ulong l = FD_LAYOUT_INIT;

  l = FD_LAYOUT_APPEND( l, alignof(fd_progcache_shmem_t), sizeof(fd_progcache_shmem_t) );

  ulong txn_chain_cnt = fd_prog_txnm_chain_cnt_est( txn_max );
  l = FD_LAYOUT_APPEND( l, fd_prog_txnm_align(), fd_prog_txnm_footprint( txn_chain_cnt ) );
  l = FD_LAYOUT_APPEND( l, fd_prog_txnp_align(), fd_prog_txnp_footprint( txn_max ) );

  ulong rec_chain_cnt = fd_prog_recm_chain_cnt_est( rec_max );
  l = FD_LAYOUT_APPEND( l, fd_prog_recm_align(), fd_prog_recm_footprint( rec_chain_cnt ) );
  l = FD_LAYOUT_APPEND( l, fd_prog_recp_align(), fd_prog_recp_footprint() );
  l = FD_LAYOUT_APPEND( l, alignof(fd_progcache_rec_t), sizeof(fd_progcache_rec_t) * rec_max );

  l = FD_LAYOUT_APPEND( l, fd_alloc_align(), fd_alloc_footprint() );

  l = FD_LAYOUT_APPEND( l, fd_prog_cbits_align(), fd_prog_cbits_footprint( rec_max ) );

  return FD_LAYOUT_FINI( l, fd_progcache_shmem_align() );
}

fd_progcache_shmem_t *
fd_progcache_shmem_new( void * shmem,
                        ulong  wksp_tag,
                        ulong  seed,
                        ulong  txn_max,
                        ulong  rec_max ) {
  fd_progcache_shmem_t * pc   = shmem;
  fd_wksp_t *            wksp = fd_wksp_containing( pc );

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

  if( FD_UNLIKELY( !rec_max || rec_max>UINT_MAX ) ) {
    FD_LOG_WARNING(( "invalid rec_max" ));
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT( l, pc+1 );

  ulong txn_chain_cnt = fd_prog_txnm_chain_cnt_est( txn_max );
  void * txn_map = FD_SCRATCH_ALLOC_APPEND( l, fd_prog_txnm_align(), fd_prog_txnm_footprint( txn_chain_cnt ) );
  void * txn_pool = FD_SCRATCH_ALLOC_APPEND( l, fd_prog_txnp_align(), fd_prog_txnp_footprint( txn_max ) );

  ulong rec_chain_cnt = fd_prog_recm_chain_cnt_est( rec_max );
  void * rec_map = FD_SCRATCH_ALLOC_APPEND( l, fd_prog_recm_align(), fd_prog_recm_footprint( rec_chain_cnt ) );
  void * rec_pool = FD_SCRATCH_ALLOC_APPEND( l, fd_prog_recp_align(), fd_prog_recp_footprint() );
  fd_progcache_rec_t * rec_ele = (fd_progcache_rec_t *)FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_progcache_rec_t), sizeof(fd_progcache_rec_t) * rec_max );

  void * alloc = FD_SCRATCH_ALLOC_APPEND( l, fd_alloc_align(), fd_alloc_footprint() );

  atomic_ulong * cbits = FD_SCRATCH_ALLOC_APPEND( l, fd_prog_cbits_align(), fd_prog_cbits_footprint( rec_max ) );

  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, fd_progcache_shmem_align() ) == (ulong)pc + fd_progcache_shmem_footprint( txn_max, rec_max ) );

  fd_memset( pc, 0, offsetof(fd_progcache_shmem_t, spill) );

  pc->wksp_tag = wksp_tag;
  pc->seed     = seed;

  pc->txn.map_gaddr = fd_wksp_gaddr_fast( wksp, fd_prog_txnm_new( txn_map, txn_chain_cnt, seed ) );
  void * txn_pool2 = fd_prog_txnp_new( txn_pool, txn_max );
  pc->txn.pool_gaddr = fd_wksp_gaddr_fast( wksp, txn_pool2 );
  fd_progcache_txn_t * txn_ele = fd_prog_txnp_join( txn_pool2 );
  pc->txn.ele_gaddr = fd_wksp_gaddr_fast( wksp, txn_ele );
  pc->txn.max = txn_max;
  pc->txn.child_head_idx = UINT_MAX;
  pc->txn.child_tail_idx = UINT_MAX;
  fd_funk_txn_xid_set_root( pc->txn.last_publish );
  for( ulong i=0UL; i<txn_max; i++ ) {
    fd_rwlock_new( &txn_ele[ i ].lock );
  }
  fd_prog_txnp_leave( txn_ele );

  pc->rec.map_gaddr = fd_wksp_gaddr_fast( wksp, fd_prog_recm_new( rec_map, rec_chain_cnt, seed ) );
  void * rec_pool2 = fd_prog_recp_new( rec_pool );
  pc->rec.pool_gaddr = fd_wksp_gaddr_fast( wksp, rec_pool2 );
  fd_prog_recp_t rec_join[1];
  fd_prog_recp_join( rec_join, rec_pool2, rec_ele, rec_max );
  fd_prog_recp_reset( rec_join, 0UL );
  pc->rec.ele_gaddr = fd_wksp_gaddr_fast( wksp, rec_ele );
  pc->rec.max = (uint)rec_max;
  for( ulong i=0UL; i<rec_max; i++ ) {
    fd_rwlock_new( &rec_ele[ i ].lock );
  }
  fd_prog_recp_leave( rec_join );

  fd_rwlock_new( &pc->txn.rwlock );

  fd_rwlock_new( &pc->spill.lock );
  pc->spill.rec_used  = 0U;
  pc->spill.spad_used = 0U;

  pc->alloc_gaddr = fd_wksp_gaddr_fast( wksp, fd_alloc_join( fd_alloc_new( alloc, wksp_tag ), 0UL ) );

  pc->clock.cbits_gaddr = fd_wksp_gaddr_fast( wksp, cbits );
  pc->clock.head        = 0UL;
  fd_rwlock_new( &pc->clock.lock );
  fd_prog_clock_init( cbits, rec_max );

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

  ljoin->shmem = shmem;
  if( FD_UNLIKELY( fd_progcache_use_malloc ) ) {
    ljoin->data_base = NULL;
  } else {
    ljoin->data_base = wksp;
  }

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
  if( FD_UNLIKELY( !fd_prog_recp_join( ljoin->rec.pool, fd_wksp_laddr( wksp, shmem->rec.pool_gaddr ), fd_wksp_laddr( wksp, shmem->rec.ele_gaddr ), shmem->rec.max ) ) ) {
    FD_LOG_WARNING(( "fd_prog_recp_join failed" ));
    return NULL;
  }
  ljoin->rec.reclaim_head = UINT_MAX;

  if( FD_UNLIKELY( !( ljoin->alloc = fd_alloc_join( fd_wksp_laddr( wksp, shmem->alloc_gaddr ), fd_tile_idx() ) ) ) ) {
    FD_LOG_WARNING(( "fd_alloc_join failed" ));
    return NULL;
  }

  ljoin->clock.bits = fd_wksp_laddr( wksp, shmem->clock.cbits_gaddr );

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
  void * data_base = fd_progcache_use_malloc ? NULL : wksp;

  if( FD_UNLIKELY( shmem->magic!=FD_PROGCACHE_SHMEM_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  FD_TEST( !shmem->txn.rwlock.value );
  FD_TEST( !shmem->spill.lock.value );
  FD_TEST( !shmem->clock.lock.value );
  fd_progcache_txn_t * txn0 = fd_wksp_laddr_fast( wksp, shmem->txn.ele_gaddr );
  fd_progcache_rec_t * rec0 = fd_wksp_laddr_fast( wksp, shmem->rec.ele_gaddr );
  for( ulong i=0UL; i<shmem->txn.max; i++ ) FD_TEST( !txn0[ i ].lock.value );
  for( ulong i=0UL; i<shmem->rec.max; i++ ) FD_TEST( !rec0[ i ].lock.value );

  /* Free all fd_alloc allocations made, individually
     (FIXME consider walking the element pool instead of the map?) */

  fd_alloc_t * alloc = fd_alloc_join( fd_wksp_laddr_fast( wksp, shmem->alloc_gaddr ), fd_tile_idx() );

  void * shmap = fd_wksp_laddr_fast( wksp, shmem->rec.map_gaddr );
  void * shele = fd_wksp_laddr_fast( wksp, shmem->rec.ele_gaddr );
  fd_prog_recm_t rec_map[1];
  if( FD_UNLIKELY( !fd_prog_recm_join( rec_map, shmap, shele, 0UL ) ) ) {
    FD_LOG_ERR(( "failed to join rec_map (corrupt funk?)" ));
    return NULL;
  }
  ulong chain_cnt = fd_prog_recm_chain_cnt( rec_map );
  for( ulong chain_idx=0UL; chain_idx<chain_cnt; chain_idx++ ) {
    for(
        fd_prog_recm_iter_t iter = fd_prog_recm_iter( rec_map, chain_idx );
        !fd_prog_recm_iter_done( iter );
        iter = fd_prog_recm_iter_next( iter )
    ) {
      fd_progcache_rec_t * rec = fd_prog_recm_iter_ele( iter );
      if( rec->data_gaddr ) {
        fd_progcache_val_free1( rec, fd_wksp_laddr_fast( data_base, rec->data_gaddr ), alloc );
      }
      rec->data_gaddr = 0UL;
      rec->data_max   = 0U;
    }
  }

  fd_prog_recm_leave( rec_map );

  FD_COMPILER_MFENCE();
  FD_VOLATILE( shmem->magic ) = 0UL;
  FD_COMPILER_MFENCE();

  /* Free the fd_alloc instance */

  fd_wksp_free_laddr( fd_alloc_delete( fd_alloc_leave( alloc ) ) );

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
