#include "fd_store.h"
#include "../../flamenco/fd_flamenco_base.h"

static const fd_hash_t hash_null = { 0 };

#define null fd_store_pool_idx_null()

#define BLOCKING 1

void *
fd_store_new( void * shmem, ulong fec_max, ulong part_cnt ) {

  if( FD_UNLIKELY( part_cnt == 0UL ) ) {
    FD_LOG_ERR(( "partition count must be greater than 0, should match the number of writers/shred tiles" ));
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
  fec_max = fd_ulong_pow2_up( fec_max ); /* required by map_chain */

  /* This seed value is very important. We have fec_max chains in the
     map, which means the size of each partition of buckets should be
     fec_max / part_cnt. When inserting into the map, we use the
     partition_slot_cnt as the seed, so that the modified hash function
     can use the seed/partition_slot_cnt to hash the key into the
     correct partition. */
  ulong part_slot_cnt = fec_max / part_cnt;
  ulong seed          = part_slot_cnt;

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_store_t * store  = FD_SCRATCH_ALLOC_APPEND( l, fd_store_align(),        sizeof( fd_store_t )               );
  void *       map    = FD_SCRATCH_ALLOC_APPEND( l, fd_store_map_align(),    fd_store_map_footprint ( fec_max ) );
  void *       shpool = FD_SCRATCH_ALLOC_APPEND( l, fd_store_pool_align(),   fd_store_pool_footprint()          );
  void *       shele  = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_store_fec_t), sizeof(fd_store_fec_t)*fec_max     );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, fd_store_align() ) == (ulong)shmem + footprint );

  store->store_gaddr    = fd_wksp_gaddr_fast( wksp, store  );
  store->pool_mem_gaddr = fd_wksp_gaddr_fast( wksp, shpool );
  store->pool_ele_gaddr = fd_wksp_gaddr_fast( wksp, shele  );
  store->map_gaddr      = fd_wksp_gaddr_fast( wksp, fd_store_map_join( fd_store_map_new ( map, fec_max, seed ) ) );

  store->part_cnt = part_cnt;
  store->fec_max  = fec_max;
  store->root     = null;

  fd_store_pool_t pool = fd_store_pool( store );
  fd_store_pool_reset( &pool, 0 );

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
                 ulong        part_idx,
                 fd_hash_t  * merkle_root ) {
# if FD_STORE_USE_HANDHOLDING
  if( FD_UNLIKELY( fd_store_query_const( store, merkle_root ) ) ) { FD_LOG_WARNING(( "merkle root %s already in store", FD_BASE58_ENC_32_ALLOCA( merkle_root ) )); return NULL; }
# endif
  int err;

  fd_store_pool_t  pool = fd_store_pool( store );
  fd_store_fec_t * fec  = fd_store_pool_acquire( &pool, NULL, BLOCKING, &err );

  if( FD_UNLIKELY( err == FD_POOL_ERR_EMPTY   ) ) { FD_LOG_WARNING(( "store full %s",    fd_store_pool_strerror( err ) )); return NULL; } /* FIXME: eviction? max bound guaranteed for worst-case? */
  if( FD_UNLIKELY( err == FD_POOL_ERR_CORRUPT ) ) { FD_LOG_ERR    (( "store corrupt %s", fd_store_pool_strerror( err ) )); return NULL; }
  FD_TEST( fec );

  fec->key.mr           = *merkle_root;
  fec->key.part         = part_idx;
  fec->cmr              = hash_null;
  fec->next             = null;
  fec->parent           = null;
  fec->child            = null;
  fec->sibling          = null;
  fec->data_sz          = 0UL;
  if( FD_UNLIKELY( store->root == null ) ) store->root = fd_store_pool_idx( &pool, fec );
  fd_store_map_ele_insert( fd_store_map( store ), fec, fd_store_fec0( store ) );

  return fec;
}

fd_store_fec_t *
fd_store_link( fd_store_t * store, fd_hash_t * merkle_root, fd_hash_t * chained_merkle_root ) {
# if FD_STORE_USE_HANDHOLDING
  if( FD_UNLIKELY( !fd_store_query_const( store, merkle_root         ) ) ) { FD_LOG_WARNING(( "missing merkle root %s",         FD_BASE58_ENC_32_ALLOCA( merkle_root         ) ) ); return NULL; }
  if( FD_UNLIKELY( !fd_store_query_const( store, chained_merkle_root ) ) ) { FD_LOG_WARNING(( "missing chained merkle root %s", FD_BASE58_ENC_32_ALLOCA( chained_merkle_root ) ) ); return NULL; }
# endif

  fd_store_pool_t   pool   = fd_store_pool( store );
  fd_store_fec_t  * parent = fd_store_query( store, chained_merkle_root );
  fd_store_fec_t  * child  = fd_store_query( store, merkle_root );

  child->parent = fd_store_pool_idx( &pool, parent );
  if( FD_LIKELY( parent->child == null ) ) {
    parent->child = fd_store_pool_idx( &pool, child ); /* set as left-child. */
  } else {
    fd_store_fec_t * curr = fd_store_pool_ele( &pool, parent->child );
    while( curr->sibling != null ) curr = fd_store_pool_ele( &pool, curr->sibling );
    curr->sibling = fd_store_pool_idx( &pool, child ); /* set as right-sibling. */
  }
  return child;
}

fd_store_fec_t *
fd_store_publish( fd_store_t  * store,
                  fd_hash_t   * merkle_root ) {

  fd_store_map_t  * map  = fd_store_map ( store );
  fd_store_pool_t   pool = fd_store_pool( store );
  fd_store_fec_t  * fec0 = fd_store_fec0( store );
  fd_store_fec_t  * oldr = fd_store_root( store );
  fd_store_fec_t  * newr = fd_store_query( store, merkle_root );

# if FD_STORE_USE_HANDHOLDING
  if( FD_UNLIKELY( !newr ) ) { FD_LOG_WARNING(( "merkle root %s not found", FD_BASE58_ENC_32_ALLOCA( merkle_root ) )); return NULL; }
# endif

  /* First, remove the previous root, and push it as the first element
     of the BFS queue. */

  fd_store_fec_t * head = fd_store_map_ele_remove( map, &oldr->key, NULL, fec0 );
  head->next            = null; /* clear map next */
  fd_store_fec_t * tail = head; /* tail of BFS queue */

  /* Second, BFS down the tree, pruning all of root's ancestors and also
     any descendants of those ancestors. */

  while( FD_LIKELY( head ) ) {
    fd_store_fec_t * child = fd_store_pool_ele( &pool, head->child );          /* left-child */
    while( FD_LIKELY( child ) ) {                                             /* iterate over children */
      if( FD_LIKELY( child != newr ) ) {                                      /* stop at new root */
        tail->next = fd_store_map_idx_remove( map, &child->key, null, fec0 ); /* remove node from map to reuse `.next` */
        tail       = fd_store_pool_ele( &pool, tail->next );                   /* push onto BFS queue (so descendants can be pruned) */
        tail->next = null;                                                    /* clear map next */
      }
      child = fd_store_pool_ele( &pool, child->sibling );                      /* right-sibling */
    }
    fd_store_fec_t * next = fd_store_pool_ele( &pool, head->next ); /* pophead */
    fd_store_pool_release( &pool, head, BLOCKING );                 /* release */
    head = next;                                                    /* advance */
  }
  newr->parent = null;                             /* unlink old root */
  store->root  = fd_store_pool_idx( &pool, newr ); /* replace with new root */
  return newr;
}

fd_store_t *
fd_store_clear( fd_store_t * store ) {
  fd_store_map_t * map  = fd_store_map( store );
  fd_store_pool_t  pool = fd_store_pool( store );
  fd_store_fec_t * fec0 = fd_store_fec0( store );

  fd_store_fec_t * head = fd_store_root( store );
  fd_store_fec_t * tail = head;
  for( fd_store_map_iter_t iter = fd_store_map_iter_init( map, fec0 );
       !fd_store_map_iter_done( iter, map, fec0 );
       iter = fd_store_map_iter_next( iter, map, fec0 ) ) {
    ulong idx = fd_store_map_iter_idx( iter, map, fec0 );
    if( FD_UNLIKELY( idx == fd_store_pool_idx( &pool, head ) ) ) continue;
    tail->sibling = idx;
    tail          = fd_store_pool_ele( &pool, tail->sibling );
  }
  tail->sibling = null;
  for( ulong idx = fd_store_pool_idx( &pool, head );
       FD_LIKELY( idx != null );
       idx = fd_store_pool_ele( &pool, idx )->sibling ) {
    fd_store_fec_t * fec = fd_store_pool_ele( &pool, idx );
    fd_store_map_idx_remove( map, &fec->key, null, fec0 );
    fd_store_pool_release( &pool, fec, 1 );
  }
  store->root = null;
  return store;
}

int
fd_store_verify( fd_store_t * store ) {
  fd_store_map_t * map  = fd_store_map( store );
  fd_store_fec_t * fec0 = fd_store_fec0( store );

  ulong part_sz = store->fec_max / store->part_cnt;
  if( part_sz != map->seed ) {
    FD_LOG_WARNING(( "part_sz (%lu) != map->seed (%lu)", part_sz, map->seed ));
    return -1;
  }

  /* iter the map, check that the partitions are correct */

  ulong ele_cnt = 0;
  for( fd_store_map_iter_t iter = fd_store_map_iter_init( map, fec0 ); !fd_store_map_iter_done( iter, map, fec0 ); iter = fd_store_map_iter_next( iter, map, fec0 ) ) {
    fd_store_fec_t const * fec = fd_store_map_iter_ele_const( iter, map, fec0 );
    if( FD_UNLIKELY( !fec ) ) {
      FD_LOG_WARNING(( "NULL ele" ));
      return -1;
    }
    ulong chain_idx = fd_store_map_private_chain_idx( &fec->key, map->seed, map->chain_cnt );
    /* the chain_idx should be in the range of the partition */
    if( FD_UNLIKELY( chain_idx < part_sz * fec->key.part || chain_idx >= part_sz * (fec->key.part + 1) ) ) {
      FD_LOG_WARNING(( "chain_idx %lu not in range %lu-%lu", chain_idx, part_sz * fec->key.part, part_sz * (fec->key.part + 1) ) );
      return -1;
    }
    ele_cnt++;
  }
  fd_store_map_verify( map, ele_cnt, fec0 );
  return 0;
}

#include <stdio.h>

static void
print( fd_store_t const * store, fd_store_fec_t const * fec, int space, const char * prefix ) {
  fd_store_pool_t pool = fd_store_pool_const( store );

  if( fec == NULL ) return;

  if( space > 0 ) printf( "\n" );
  for( int i = 0; i < space; i++ ) printf( " " );
  printf( "%s%s", prefix, FD_BASE58_ENC_32_ALLOCA( &fec->key ) );

  fd_store_fec_t const * curr = fd_store_pool_ele_const( &pool, fec->child );
  char new_prefix[1024]; /* FIXME size this correctly */
  while( curr ) {
    if( fd_store_pool_ele_const( &pool, curr->sibling ) ) {
      sprintf( new_prefix, "├── " ); /* branch indicating more siblings follow */
      print( store, curr, space + 4, new_prefix );
    } else {
      sprintf( new_prefix, "└── " ); /* end branch */
      print( store, curr, space + 4, new_prefix );
    }
    curr = fd_store_pool_ele_const( &pool, curr->sibling );
  }
}

void
fd_store_print( fd_store_t const * store ) {
  FD_LOG_NOTICE( ( "\n\n[Store]" ) );
  print( store, fd_store_root_const( store ), 0, "" );
  printf( "\n\n" );
}
