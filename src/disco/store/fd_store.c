#include "fd_store.h"

static inline fd_store_map_t *
map_laddr( fd_store_t * store ) {
  return fd_wksp_laddr_fast( fd_store_wksp( store ), store->map_gaddr );
}

static inline fd_store_pool_t
pool_ljoin( fd_store_t const * store ) {
  return (fd_store_pool_t){
      .pool    = fd_wksp_laddr_fast( fd_store_wksp( store ), store->pool_mem_gaddr ),
      .ele     = fd_wksp_laddr_fast( fd_store_wksp( store ), store->pool_ele_gaddr ),
      .ele_max = store->fec_max };
}

static inline fd_store_fec_t *
pool_laddr( fd_store_t * store ) {
  fd_store_pool_t pool = pool_ljoin( store );
  return pool.ele;
}

void *
fd_store_new( void * shmem,
              ulong  part_cnt,
              ulong  fec_max,
              ulong  fec_data_max ) {

  if( FD_UNLIKELY( part_cnt==0UL ) ) {
    FD_LOG_WARNING(( "part_cnt must be non-zero" ));
    return NULL;
  }

  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_store_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  ulong footprint = fd_store_footprint( fec_max, fec_data_max );

  fd_wksp_t * wksp = fd_wksp_containing( shmem );
  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_WARNING(( "shmem must be part of a workspace" ));
    return NULL;
  }

  /* The seed is derived from the number of chains in the map.  The
     number of chains is estimated from fec_max (via chain_cnt_est) and
     is always a power of two.  The size of each partition is chain_cnt
     / part_cnt.  We use the per partition slot count as the seed so
     that the modified hash function can hash the key into the correct
     partition. */

  ulong chain_cnt     = fd_store_map_chain_cnt_est( fec_max );
  ulong part_slot_cnt = chain_cnt / part_cnt;
  ulong seed          = part_slot_cnt;

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_store_t * store    = FD_SCRATCH_ALLOC_APPEND( l, fd_store_align(),        sizeof(fd_store_t)                   );
  void *       map      = FD_SCRATCH_ALLOC_APPEND( l, fd_store_map_align(),    fd_store_map_footprint( chain_cnt ) );
  void *       shpool   = FD_SCRATCH_ALLOC_APPEND( l, fd_store_pool_align(),   fd_store_pool_footprint()            );
  void *       shele    = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_store_fec_t), sizeof(fd_store_fec_t)*fec_max       );
  uchar *      data     = FD_SCRATCH_ALLOC_APPEND( l, FD_STORE_ALIGN,          fec_data_max*fec_max                 );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, fd_store_align() )==(ulong)shmem + footprint );

  fd_memset( store, 0, sizeof(fd_store_t) );
  store->part_cnt       = part_cnt;
  store->fec_max        = fec_max;
  store->fec_data_max   = fec_data_max;
  store->store_gaddr    = fd_wksp_gaddr_fast( wksp, store );
  store->map_gaddr      = fd_wksp_gaddr_fast( wksp, fd_store_map_join( fd_store_map_new( map, chain_cnt, seed ) ) );
  store->pool_mem_gaddr = fd_wksp_gaddr_fast( wksp, shpool   );
  store->pool_ele_gaddr = fd_wksp_gaddr_fast( wksp, shele    );
  store->data_gaddr     = fd_wksp_gaddr_fast( wksp, data );

  if( FD_UNLIKELY( !fd_store_pool_new( shpool ) ) ) {
    FD_LOG_WARNING(( "fd_store_pool_new failed" ));
    return NULL;
  }
  fd_store_pool_t pool_ljoin;
  fd_store_pool_reset( fd_store_pool_join( &pool_ljoin, shpool, shele, fec_max ) );

  /* Set each element's data_gaddr to point to its slice of the
     contiguous data buffer region. */

  fd_store_fec_t * fec0 = (fd_store_fec_t *)shele;
  for( ulong i=0UL; i<fec_max; i++ ) {
    fec0[ i ].data_gaddr = fd_wksp_gaddr_fast( wksp, data + i*fec_data_max );
  }

  FD_COMPILER_MFENCE();
  FD_VOLATILE( store->magic ) = FD_STORE_MAGIC;
  FD_COMPILER_MFENCE();

  return shmem;
}

fd_store_t *
fd_store_join( void * shstore ) {

  if( FD_UNLIKELY( !shstore ) ) {
    FD_LOG_WARNING(( "NULL store" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned((ulong)shstore, fd_store_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned store" ));
    return NULL;
  }

  fd_wksp_t * wksp = fd_wksp_containing( shstore );
  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_WARNING(( "store must be part of a workspace" ));
    return NULL;
  }

  fd_store_t * store = (fd_store_t *)shstore;
  if( FD_UNLIKELY( store->magic!=FD_STORE_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return store;
}

void *
fd_store_leave( fd_store_t const * store ) {

  if( FD_UNLIKELY( !store ) ) {
    FD_LOG_WARNING(( "NULL store" ));
    return NULL;
  }

  return (void *)store;
}

void *
fd_store_delete( void * shstore ) {

  if( FD_UNLIKELY( !shstore ) ) {
    FD_LOG_WARNING(( "NULL store" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned((ulong)shstore, fd_store_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned store" ));
    return NULL;
  }

  fd_store_t * store = (fd_store_t *)shstore;
  if( FD_UNLIKELY( store->magic!=FD_STORE_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  FD_COMPILER_MFENCE();
  FD_VOLATILE( store->magic ) = 0UL;
  FD_COMPILER_MFENCE();

  return shstore;
}

fd_store_fec_t *
fd_store_query( fd_store_t       * store,
                fd_hash_t  const * merkle_root ) {

  fd_store_pool_t pool = pool_ljoin( store );
  ulong           null = fd_store_pool_idx_null();
  for( uint part_idx = 0; part_idx < store->part_cnt; part_idx++ ) {
    fd_store_key_t   key = { *merkle_root, part_idx };
    ulong            idx = fd_store_map_idx_query_const( map_laddr( store ), &key, null, pool_laddr( store ) );
    fd_store_fec_t * fec = fd_store_pool_ele( &pool, idx );
    if( FD_LIKELY( fec ) ) return fec;
  }
  return NULL;
}

fd_store_fec_t *
fd_store_insert( fd_store_t * store,
                 ulong        part_idx,
                 fd_hash_t  * merkle_root ) {

  fd_store_pool_t pool = pool_ljoin( store );
  ulong           null = fd_store_pool_idx_null();

  for( ulong part_idx = 0; part_idx < store->part_cnt; part_idx++ ) {
    fd_store_key_t key = { *merkle_root, part_idx };
    ulong          idx = null;

    FD_STORE_SLOCK_BEGIN( store ) {
      idx = fd_store_map_idx_query_const( map_laddr( store ), &key, null, pool_laddr( store ) );
    } FD_STORE_SLOCK_END;

    fd_store_fec_t * fec = fd_store_pool_ele( &pool, idx );
    if( FD_UNLIKELY( fec ) ) return fec;
  }

  fd_store_fec_t * fec = fd_store_pool_acquire( &pool );
  if( FD_UNLIKELY( !fec ) ) FD_LOG_CRIT(( "fd_store_pool_acquire failed" ));
  fec->key.merkle_root = *merkle_root;
  fec->key.part_idx    = part_idx;
  fec->cmr             = (fd_hash_t){ 0 };
  fec->next            = null;
  fec->data_sz         = 0UL;

  FD_STORE_SLOCK_BEGIN( store ) {
    fd_store_map_ele_insert( map_laddr( store ), fec, pool_laddr( store ) );
  } FD_STORE_SLOCK_END;

  return fec;
}

void
fd_store_remove( fd_store_t      * store,
                 fd_hash_t const * merkle_root ) {

  fd_store_pool_t pool = pool_ljoin( store );
  for( uint part_idx = 0; part_idx < store->part_cnt; part_idx++ ) {
    fd_store_key_t   key = { *merkle_root, part_idx };
    fd_store_fec_t * fec = NULL;

    FD_STORE_XLOCK_BEGIN( store ) {
      fec = fd_store_map_ele_remove( map_laddr( store ), &key, NULL, pool_laddr( store ) );
    } FD_STORE_XLOCK_END;
    if( FD_UNLIKELY( !fec ) ) continue;

    fd_store_pool_release( &pool, fec );
    return;
  }

  FD_BASE58_ENCODE_32_BYTES( merkle_root->uc, _merkle_root );
  FD_LOG_WARNING(( "key not found %s", _merkle_root ));
}

int
fd_store_verify( fd_store_t * store ) {

  fd_store_map_t * map  = map_laddr( store );
  fd_store_fec_t * fec0 = pool_laddr( store );

  ulong part_sz = map->chain_cnt / store->part_cnt;
  if( part_sz != map->seed ) {
    FD_LOG_WARNING(( "part_sz (%lu) != map->seed (%lu)", part_sz, map->seed ));
    return -1;
  }

  /* Iterate the map and check slots are partitioned correctly. */

  for( fd_store_map_iter_t iter = fd_store_map_iter_init(       map, fec0 );
                                 !fd_store_map_iter_done( iter, map, fec0 );
                           iter = fd_store_map_iter_next( iter, map, fec0 ) ) {
    fd_store_fec_t const * fec = fd_store_map_iter_ele_const( iter, map, fec0 );
    if( FD_UNLIKELY( !fec ) ) {
      FD_LOG_WARNING(( "NULL ele" ));
      return -1;
    }
    ulong chain_idx = fd_store_map_private_chain_idx( &fec->key, map->seed, map->chain_cnt );
    ulong k         = fec->key.part_idx;
    ulong n         = part_sz;
    if( FD_UNLIKELY( chain_idx < k * n || chain_idx >= (k + 1) * n ) ) { /* chain_idx in [k*n, (k+1)*n) */
      FD_LOG_WARNING(( "chain_idx %lu not in range [%lu, %lu)", chain_idx, k * n, (k + 1) * n ) );
      return -1;
    }
  }
  fd_store_pool_t pool = pool_ljoin( store );
  if( FD_UNLIKELY( fd_store_pool_verify( &pool )==-1 ) ) return -1;
  return fd_store_map_verify( map, store->fec_max, fec0 );
}
