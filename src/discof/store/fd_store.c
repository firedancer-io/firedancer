#include "fd_store.h"
#include "../../flamenco/fd_flamenco_base.h"

void *
fd_store_new( void * shmem, ulong fec_max, ulong seed ) {

  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_store_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  ulong footprint = fd_store_footprint( fec_max );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "bad fec_max (%lu)", fec_max ));
    return NULL;
  }

  fd_wksp_t * wksp = fd_wksp_containing( shmem );
  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_WARNING(( "shmem must be part of a workspace" ));
    return NULL;
  }

  fd_memset( shmem, 0, footprint );

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_store_t * store = FD_SCRATCH_ALLOC_APPEND( l, fd_store_align(),      sizeof( fd_store_t )               );
  void *       pool  = FD_SCRATCH_ALLOC_APPEND( l, fd_store_pool_align(), fd_store_pool_footprint( fec_max ) );
  void *       map   = FD_SCRATCH_ALLOC_APPEND( l, fd_store_map_align(),  fd_store_map_footprint ( fec_max ) );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, fd_store_align() ) == (ulong)shmem + footprint );

  store->seed        = seed;
  store->root        = ULONG_MAX;
  store->store_gaddr = fd_wksp_gaddr_fast( wksp, store                                                         );
  store->pool_gaddr  = fd_wksp_gaddr_fast( wksp, fd_store_pool_join( fd_store_pool_new( pool, fec_max      ) ) );
  store->map_gaddr   = fd_wksp_gaddr_fast( wksp, fd_store_map_join ( fd_store_map_new ( map, fec_max, seed ) ) );

  FD_COMPILER_MFENCE();
  FD_VOLATILE( store->magic ) = FD_STORE_MAGIC;
  FD_COMPILER_MFENCE();

  return shmem;
}

fd_store_t *
fd_store_join( void * shstore ) {
  fd_store_t * store = (fd_store_t *)shstore;

  if( FD_UNLIKELY( !store ) ) {
    FD_LOG_WARNING(( "NULL store" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned((ulong)store, fd_store_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned store" ));
    return NULL;
  }

  fd_wksp_t * wksp = fd_wksp_containing( store );
  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_WARNING(( "store must be part of a workspace" ));
    return NULL;
  }

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
fd_store_delete( void * store ) {

  if( FD_UNLIKELY( !store ) ) {
    FD_LOG_WARNING(( "NULL store" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned((ulong)store, fd_store_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned store" ));
    return NULL;
  }

  return store;
}

fd_store_fec_t *
fd_store_insert( fd_store_t * store,
                 fd_hash_t  * merkle_root,
                 uchar      * data,
                 ulong        data_sz ) {

# if FD_STORE_USE_HANDHOLDING /* FIXME eviction? max bound guaranteed for worst-case? */
  if( FD_UNLIKELY( !fd_store_pool_free( fd_store_pool( store ) ) ) ) { FD_LOG_WARNING(( "store full"                                                              )); return NULL; }
  if( FD_UNLIKELY( data_sz > FD_STORE_DATA_MAX                   ) ) { FD_LOG_WARNING(( "data_sz %lu > FD_STORE_DATA_MAX", data_sz                                )); return NULL; }
  if( FD_UNLIKELY( fd_store_query_const( store, merkle_root )    ) ) { FD_LOG_WARNING(( "merkle root %s already in store", FD_BASE58_ENC_32_ALLOCA( merkle_root ) )); return NULL; }
# endif

  fd_store_fec_t * pool = fd_store_pool( store );
  ulong            null = fd_store_pool_idx_null( pool );
  fd_store_fec_t * fec  = fd_store_pool_ele_acquire( pool );
  fec->key              = *merkle_root;
  fec->next             = null;
  fec->parent           = null;
  fec->child            = null;
  fec->sibling          = null;
  fec->data_sz          = data_sz;
  memcpy( fec->data, data, data_sz );
  fd_store_map_ele_insert( fd_store_map( store ), fec, fd_store_pool( store ) );
  if( FD_UNLIKELY( store->root == null ) ) store->root = fd_store_pool_idx( pool, fec );
  return fec;
}

fd_store_fec_t *
fd_store_link( fd_store_t * store, fd_hash_t * merkle_root, fd_hash_t * chained_merkle_root ) {

# if FD_STORE_USE_HANDHOLDING
  if( FD_UNLIKELY( !fd_store_query_const( store, merkle_root         ) ) ) { FD_LOG_WARNING(( "missing merkle root %s",         FD_BASE58_ENC_32_ALLOCA( merkle_root         ) ) ); return NULL; }
  if( FD_UNLIKELY( !fd_store_query_const( store, chained_merkle_root ) ) ) { FD_LOG_WARNING(( "missing chained merkle root %s", FD_BASE58_ENC_32_ALLOCA( chained_merkle_root ) ) ); return NULL; }
# endif

  fd_store_map_t * map    = fd_store_map( store );
  fd_store_fec_t * pool   = fd_store_pool( store );
  ulong            null   = fd_store_pool_idx_null( pool );
  fd_store_fec_t * parent = fd_store_map_ele_query( map, chained_merkle_root, NULL, pool );
  fd_store_fec_t * child  = fd_store_map_ele_query( map, merkle_root, NULL, pool );

  child->parent = fd_store_pool_idx( pool, parent );
  if( FD_LIKELY( parent->child == null ) ) {
    parent->child = fd_store_pool_idx( pool, child ); /* set as left-child. */
  } else {
    fd_store_fec_t * curr = fd_store_pool_ele( pool, parent->child );
    while( curr->sibling != null ) curr = fd_store_pool_ele( pool, curr->sibling );
    curr->sibling = fd_store_pool_idx( pool, child ); /* set as right-sibling. */
  }
  return child;
}

fd_store_fec_t *
fd_store_publish( fd_store_t  * store,
                  fd_hash_t   * merkle_root ) {

  fd_store_map_t * map  = fd_store_map( store );
  fd_store_fec_t * pool = fd_store_pool( store );
  ulong            null = fd_store_pool_idx_null( pool );
  fd_store_fec_t * oldr = fd_store_root( store );
  fd_store_fec_t * newr = fd_store_map_ele_query( map, merkle_root, NULL, pool );

# if FD_STORE_USE_HANDHOLDING
  if( FD_UNLIKELY( !newr ) ) { FD_LOG_WARNING(( "merkle root %s not found", FD_BASE58_ENC_32_ALLOCA( merkle_root ) )); return NULL; }
# endif

  /* First, remove the previous root, and push it as the first element
     of the BFS queue. */

  fd_store_fec_t * head = fd_store_map_ele_remove( map, &oldr->key, NULL, pool );
  head->next            = null; /* clear map next */
  fd_store_fec_t * tail = head; /* tail of BFS queue */

  /* Second, BFS down the tree, pruning all of root's ancestors and also
     any descendants of those ancestors. */

  while( FD_LIKELY( head ) ) {
    fd_store_fec_t * child = fd_store_pool_ele( pool, head->child );          /* left-child */
    while( FD_LIKELY( child ) ) {                                             /* iterate over children */
      if( FD_LIKELY( child != newr ) ) {                                      /* stop at new root */
        tail->next = fd_store_map_idx_remove( map, &child->key, null, pool ); /* remove node from map to reuse `.next` */
        tail       = fd_store_pool_ele( pool, tail->next );                   /* push onto BFS queue (so descendants can be pruned) */
        tail->next = null;                                                    /* clear map next */
      }
      child = fd_store_pool_ele( pool, child->sibling ); /* right-sibling */
    }
    fd_store_fec_t * next = fd_store_pool_ele( pool, head->next ); /* pophead */
    fd_store_pool_ele_release( pool, head );                       /* release */
    head = next;                                                   /* advance */
  }
  newr->parent = null;                            /* unlink old root */
  store->root  = fd_store_pool_idx( pool, newr ); /* replace with new root */
  return newr;
}
