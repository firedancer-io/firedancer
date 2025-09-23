#include "fd_forest.h"

static void ver_inc( ulong ** ver ) {
  fd_fseq_update( *ver, fd_fseq_query( *ver ) + 1 );
}

#define VER_INC ulong * ver __attribute__((cleanup(ver_inc))) = fd_forest_ver( forest ); ver_inc( &ver )

void *
fd_forest_new( void * shmem, ulong ele_max, ulong seed ) {
  FD_TEST( fd_ulong_is_pow2( ele_max ) );

  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_forest_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  ulong footprint = fd_forest_footprint( ele_max );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "bad ele_max (%lu)", ele_max ));
    return NULL;
  }

  fd_wksp_t * wksp = fd_wksp_containing( shmem );
  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_WARNING(( "shmem must be part of a workspace" ));
    return NULL;
  }

  fd_memset( shmem, 0, footprint );
  fd_forest_t * forest;

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  forest          = FD_SCRATCH_ALLOC_APPEND( l, fd_forest_align(),          sizeof(fd_forest_t)                                    );
  void * ver      = FD_SCRATCH_ALLOC_APPEND( l, fd_fseq_align(),            fd_fseq_footprint()                                    );
  void * pool     = FD_SCRATCH_ALLOC_APPEND( l, fd_forest_pool_align(),     fd_forest_pool_footprint    ( ele_max                ) );
  void * ancestry = FD_SCRATCH_ALLOC_APPEND( l, fd_forest_ancestry_align(), fd_forest_ancestry_footprint( ele_max                ) );
  void * frontier = FD_SCRATCH_ALLOC_APPEND( l, fd_forest_frontier_align(), fd_forest_frontier_footprint( ele_max                ) );
  void * subtrees = FD_SCRATCH_ALLOC_APPEND( l, fd_forest_subtrees_align(), fd_forest_subtrees_footprint( FD_FOREST_FORK_CNT_EST ) );
  void * orphaned = FD_SCRATCH_ALLOC_APPEND( l, fd_forest_orphaned_align(), fd_forest_orphaned_footprint( ele_max                ) );
  void * consumed = FD_SCRATCH_ALLOC_APPEND( l, fd_forest_consumed_align(), fd_forest_consumed_footprint( FD_FOREST_FORK_CNT_EST ) );
  void * conspool = FD_SCRATCH_ALLOC_APPEND( l, fd_forest_conspool_align(), fd_forest_conspool_footprint( ele_max                ) );
  void * deque    = FD_SCRATCH_ALLOC_APPEND( l, fd_forest_deque_align(),    fd_forest_deque_footprint   ( ele_max                ) );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, fd_forest_align() ) == (ulong)shmem + footprint );

  forest->root           = ULONG_MAX;
  forest->subtree_cnt    = 0;
  forest->wksp_gaddr     = fd_wksp_gaddr_fast( wksp, forest );
  forest->ver_gaddr      = fd_wksp_gaddr_fast( wksp, fd_fseq_join           ( fd_fseq_new           ( ver,      FD_FOREST_VER_UNINIT         ) ) );
  forest->pool_gaddr     = fd_wksp_gaddr_fast( wksp, fd_forest_pool_join    ( fd_forest_pool_new    ( pool,     ele_max                      ) ) );
  forest->ancestry_gaddr = fd_wksp_gaddr_fast( wksp, fd_forest_ancestry_join( fd_forest_ancestry_new( ancestry, ele_max, seed                ) ) );
  forest->frontier_gaddr = fd_wksp_gaddr_fast( wksp, fd_forest_frontier_join( fd_forest_frontier_new( frontier, ele_max, seed                ) ) );
  forest->subtrees_gaddr = fd_wksp_gaddr_fast( wksp, fd_forest_subtrees_join( fd_forest_subtrees_new( subtrees, FD_FOREST_FORK_CNT_EST, seed ) ) );
  forest->orphaned_gaddr = fd_wksp_gaddr_fast( wksp, fd_forest_orphaned_join( fd_forest_orphaned_new( orphaned, ele_max, seed                ) ) );
  forest->consumed_gaddr = fd_wksp_gaddr_fast( wksp, fd_forest_consumed_join( fd_forest_consumed_new( consumed, FD_FOREST_FORK_CNT_EST, seed ) ) );
  forest->conspool_gaddr = fd_wksp_gaddr_fast( wksp, fd_forest_conspool_join( fd_forest_conspool_new( conspool, ele_max                      ) ) );
  forest->deque_gaddr    = fd_wksp_gaddr_fast( wksp, fd_forest_deque_join   ( fd_forest_deque_new   ( deque,    ele_max                      ) ) );

  FD_COMPILER_MFENCE();
  FD_VOLATILE( forest->magic ) = FD_FOREST_MAGIC;
  FD_COMPILER_MFENCE();

  return shmem;
}

fd_forest_t *
fd_forest_join( void * shforest ) {
  fd_forest_t * forest = (fd_forest_t *)shforest;

  if( FD_UNLIKELY( !forest ) ) {
    FD_LOG_WARNING(( "NULL forest" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned((ulong)forest, fd_forest_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned forest" ));
    return NULL;
  }

  fd_wksp_t * wksp = fd_wksp_containing( forest );
  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_WARNING(( "forest must be part of a workspace" ));
    return NULL;
  }

  return forest;
}

void *
fd_forest_leave( fd_forest_t const * forest ) {

  if( FD_UNLIKELY( !forest ) ) {
    FD_LOG_WARNING(( "NULL forest" ));
    return NULL;
  }

  return (void *)forest;
}

void *
fd_forest_delete( void * forest ) {

  if( FD_UNLIKELY( !forest ) ) {
    FD_LOG_WARNING(( "NULL forest" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned((ulong)forest, fd_forest_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned forest" ));
    return NULL;
  }

  // TODO: zero out mem?

  return forest;
}


static void
consumed_map_insert( fd_forest_t * forest, ulong slot, ulong pool_idx ) {
  fd_forest_consumed_t * consumed = fd_forest_consumed( forest );
  fd_forest_cns_t      * pool     = fd_forest_conspool( forest );
  fd_forest_cns_t      * ele      = fd_forest_conspool_ele_acquire( pool );
  ele->slot            = slot;
  ele->forest_pool_idx = pool_idx;
  fd_forest_consumed_ele_insert( consumed, ele, pool );
}

fd_forest_t *
fd_forest_init( fd_forest_t * forest, ulong root_slot ) {
  FD_TEST( forest );
  FD_TEST( fd_fseq_query( fd_forest_ver( forest ) ) == FD_FOREST_VER_UNINIT );

  VER_INC;

  fd_forest_blk_t *      pool     = fd_forest_pool( forest );
  ulong                  null     = fd_forest_pool_idx_null( pool );
  fd_forest_frontier_t * frontier = fd_forest_frontier( forest );

  /* Initialize the root node from a pool element. */

  fd_forest_blk_t * root_ele = fd_forest_pool_ele_acquire( pool );
  root_ele->slot             = root_slot;
  root_ele->parent           = null;
  root_ele->child            = null;
  root_ele->sibling          = null;
  root_ele->buffered_idx     = 0;
  root_ele->complete_idx     = 0;

  fd_forest_blk_idxs_full( root_ele->fecs );
  fd_forest_blk_idxs_full( root_ele->cmpl );

  forest->root = fd_forest_pool_idx( pool, root_ele );
  fd_forest_frontier_ele_insert( frontier, root_ele, pool ); /* cannot fail */
  consumed_map_insert( forest, root_ele->slot, fd_forest_pool_idx( pool, root_ele ) );

  /* Sanity checks. */

  FD_TEST( root_ele );
  FD_TEST( root_ele == fd_forest_frontier_ele_query( frontier, &root_slot, NULL, pool ));
  FD_TEST( root_ele->slot == root_slot );

  return forest;
}

static ulong *
fd_forest_deque( fd_forest_t * forest ) {
  return fd_wksp_laddr_fast( fd_forest_wksp( forest ), forest->deque_gaddr );
}

fd_forest_t *
fd_forest_fini( fd_forest_t * forest ) {
  fd_fseq_update( fd_forest_ver( forest ), FD_FOREST_VER_INVAL );

  fd_forest_blk_t *      pool      = fd_forest_pool( forest );
  ulong                  null      = fd_forest_pool_idx_null( pool );
  fd_forest_ancestry_t * ancestry  = fd_forest_ancestry( forest );
  fd_forest_frontier_t * frontier  = fd_forest_frontier( forest );
  fd_forest_subtrees_t * subtrees  = fd_forest_subtrees( forest );
  fd_forest_orphaned_t * orphaned  = fd_forest_orphaned( forest );
  if( FD_UNLIKELY( !fd_forest_pool_used( pool ) ) ) return forest;

  ulong * q = fd_forest_deque( forest );
  fd_forest_deque_remove_all( q );
  for( fd_forest_ancestry_iter_t iter = fd_forest_ancestry_iter_init( ancestry, pool );
       !fd_forest_ancestry_iter_done( iter, ancestry, pool );
       iter = fd_forest_ancestry_iter_next( iter, ancestry, pool ) ) {
    fd_forest_deque_push_tail( q, fd_forest_ancestry_iter_idx( iter, ancestry, pool ) );
  }
  while( !fd_forest_deque_empty( q ) ) {
    ulong idx = fd_forest_deque_pop_head( q );
    FD_TEST( fd_forest_ancestry_ele_remove( ancestry, &fd_forest_pool_ele( pool, idx )->slot, NULL, pool ) );
    fd_forest_pool_idx_release( pool, idx );
  }
  for( fd_forest_frontier_iter_t iter = fd_forest_frontier_iter_init( frontier, pool );
       !fd_forest_frontier_iter_done( iter, frontier, pool );
       iter = fd_forest_frontier_iter_next( iter, frontier, pool ) ) {
    fd_forest_deque_push_tail( q, fd_forest_frontier_iter_idx( iter, frontier, pool ) );
  }
  while( !fd_forest_deque_empty( q ) ) {
    ulong idx = fd_forest_deque_pop_head( q );
    FD_TEST( fd_forest_frontier_ele_remove( frontier, &fd_forest_pool_ele( pool, idx )->slot, NULL, pool ) );
    fd_forest_pool_idx_release( pool, idx );
  }
  for( fd_forest_subtrees_iter_t iter = fd_forest_subtrees_iter_init( subtrees, pool );
       !fd_forest_subtrees_iter_done( iter, subtrees, pool );
       iter = fd_forest_subtrees_iter_next( iter, subtrees, pool ) ) {
    fd_forest_deque_push_tail( q, fd_forest_subtrees_iter_idx( iter, subtrees, pool ) );
  }
  while( !fd_forest_deque_empty( q ) ) {
    ulong idx = fd_forest_deque_pop_head( q );
    FD_TEST( fd_forest_subtrees_ele_remove( subtrees, &fd_forest_pool_ele( pool, idx )->slot, NULL, pool ) );
    fd_forest_pool_idx_release( pool, idx );
  }
  for( fd_forest_orphaned_iter_t iter = fd_forest_orphaned_iter_init( orphaned, pool );
       !fd_forest_orphaned_iter_done( iter, orphaned, pool );
       iter = fd_forest_orphaned_iter_next( iter, orphaned, pool ) ) {
    fd_forest_deque_push_tail( q, fd_forest_orphaned_iter_idx( iter, orphaned, pool ) );
  }
  while( !fd_forest_deque_empty( q ) ) {
    ulong idx = fd_forest_deque_pop_head( q );
    FD_TEST( fd_forest_orphaned_ele_remove( orphaned, &fd_forest_pool_ele( pool, idx )->slot, NULL, pool ) );
    fd_forest_pool_idx_release( pool, idx );
  }
  forest->root = null;
# if FD_FOREST_USE_HANDHOLDING
  FD_TEST( !fd_forest_pool_used( pool ) );
# endif

  fd_fseq_update( fd_forest_ver( forest ), FD_FOREST_VER_UNINIT );
  return forest;
}

int
fd_forest_verify( fd_forest_t const * forest ) {
  if( FD_UNLIKELY( !forest ) ) {
    FD_LOG_WARNING(( "NULL forest" ));
    return -1;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)forest, fd_forest_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned forest" ));
    return -1;
  }

  fd_wksp_t * wksp = fd_wksp_containing( forest );
  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_WARNING(( "forest must be part of a workspace" ));
    return -1;
  }

  if( FD_UNLIKELY( forest->magic!=FD_FOREST_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return -1;
  }

  if( FD_UNLIKELY( fd_fseq_query( fd_forest_ver_const( forest ) ) == ULONG_MAX ) ) {
    FD_LOG_WARNING(( "forest uninitialized or invalid" ));
    return -1;
  }

  fd_forest_blk_t const * pool = fd_forest_pool_const( forest );

  fd_forest_frontier_t const * frontier = fd_forest_frontier_const( forest );
  fd_forest_orphaned_t const * orphaned = fd_forest_orphaned_const( forest );
  fd_forest_ancestry_t const * ancestry = fd_forest_ancestry_const( forest );
  fd_forest_subtrees_t const * subtrees = fd_forest_subtrees_const( forest );

  if( fd_forest_ancestry_verify( ancestry, fd_forest_pool_max( pool ), pool ) == -1 ) return -1;
  if( fd_forest_frontier_verify( frontier, fd_forest_pool_max( pool ), pool ) == -1 ) return -1;
  if( fd_forest_subtrees_verify( subtrees, fd_forest_pool_max( pool ), pool ) == -1 ) return -1;
  if( fd_forest_orphaned_verify( orphaned, fd_forest_pool_max( pool ), pool ) == -1 ) return -1;

  /* Invariant: elements can only appear in one of the four maps. */
  for( fd_forest_frontier_iter_t iter = fd_forest_frontier_iter_init( frontier, pool ); !fd_forest_frontier_iter_done( iter, frontier, pool ); iter = fd_forest_frontier_iter_next( iter, frontier, pool ) ) {
    fd_forest_blk_t const * ele = fd_forest_frontier_iter_ele_const( iter, frontier, pool );
    if( fd_forest_ancestry_ele_query_const( ancestry, &ele->slot, NULL, pool ) ) return -1;
    if( fd_forest_orphaned_ele_query_const( orphaned, &ele->slot, NULL, pool ) ) return -1;
    if( fd_forest_subtrees_ele_query_const( subtrees, &ele->slot, NULL, pool ) ) return -1;
  }

  for( fd_forest_orphaned_iter_t iter = fd_forest_orphaned_iter_init( orphaned, pool ); !fd_forest_orphaned_iter_done( iter, orphaned, pool ); iter = fd_forest_orphaned_iter_next( iter, orphaned, pool ) ) {
    fd_forest_blk_t const * ele = fd_forest_orphaned_iter_ele_const( iter, orphaned, pool );
    if( fd_forest_ancestry_ele_query_const( ancestry, &ele->slot, NULL, pool ) ) return -1;
    if( fd_forest_frontier_ele_query_const( frontier, &ele->slot, NULL, pool ) ) return -1;
    if( fd_forest_subtrees_ele_query_const( subtrees, &ele->slot, NULL, pool ) ) return -1;
  }

  for( fd_forest_subtrees_iter_t iter = fd_forest_subtrees_iter_init( subtrees, pool ); !fd_forest_subtrees_iter_done( iter, subtrees, pool ); iter = fd_forest_subtrees_iter_next( iter, subtrees, pool ) ) {
    fd_forest_blk_t const * ele = fd_forest_subtrees_iter_ele_const( iter, subtrees, pool );
    if( fd_forest_ancestry_ele_query_const( ancestry, &ele->slot, NULL, pool ) ) return -1;
    if( fd_forest_frontier_ele_query_const( frontier, &ele->slot, NULL, pool ) ) return -1;
    if( fd_forest_orphaned_ele_query_const( orphaned, &ele->slot, NULL, pool ) ) return -1;
  }

  fd_forest_consumed_t const * consumed = fd_forest_consumed_const( forest );
  fd_forest_cns_t const *      conspool = fd_forest_conspool_const( forest );

  /* from every frontier walk back and verify that there is an ancestor in the consumed map */
  for( fd_forest_frontier_iter_t iter = fd_forest_frontier_iter_init( frontier, pool ); !fd_forest_frontier_iter_done( iter, frontier, pool ); iter = fd_forest_frontier_iter_next( iter, frontier, pool ) ) {
    fd_forest_blk_t const * ele = fd_forest_frontier_iter_ele_const( iter, frontier, pool );
    int found = 0;
    while( FD_LIKELY( ele ) ) {
      if( fd_forest_consumed_ele_query_const( consumed, &ele->slot, NULL, conspool ) ) {
        found = 1;
        break;
      }
      ele = fd_forest_pool_ele_const( pool, ele->parent );
    }
    if( FD_UNLIKELY( !found ) ) return -1;
  }

  /* Consumed map elements must be in the frontier or ancestry map. */

  for( fd_forest_consumed_iter_t iter = fd_forest_consumed_iter_init( consumed, conspool ); !fd_forest_consumed_iter_done( iter, consumed, conspool ); iter = fd_forest_consumed_iter_next( iter, consumed, conspool ) ) {
    fd_forest_cns_t const * ele = fd_forest_consumed_iter_ele_const( iter, consumed, conspool );
    if( !fd_forest_ancestry_ele_query_const( ancestry, &ele->slot, NULL, pool ) && !fd_forest_frontier_ele_query_const( frontier, &ele->slot, NULL, pool ) ) {
      return -1;
    }
  }

  return 0;
}

/* remove removes and returns a connected ele from ancestry or frontier
   maps.  does not remove orphaned ele.  does not unlink ele. */

static fd_forest_blk_t *
ancestry_frontier_remove( fd_forest_t * forest, ulong slot ) {
  fd_forest_blk_t * pool = fd_forest_pool( forest );
  fd_forest_blk_t * ele  = NULL;
  ele =                  fd_forest_ancestry_ele_remove( fd_forest_ancestry( forest ), &slot, NULL, pool );
  ele = fd_ptr_if( !ele, fd_forest_frontier_ele_remove( fd_forest_frontier( forest ), &slot, NULL, pool ), ele );
  return ele;
}

static fd_forest_blk_t *
subtrees_orphaned_remove( fd_forest_t * forest, ulong slot ) {
  fd_forest_blk_t * pool = fd_forest_pool( forest );
  fd_forest_blk_t * ele = NULL;
  ele = fd_forest_orphaned_ele_remove( fd_forest_orphaned( forest ), &slot, NULL, pool );
  if( ele ) return ele;
  ele = fd_forest_subtrees_ele_remove( fd_forest_subtrees( forest ), &slot, NULL, pool );
  if( ele ) forest->subtree_cnt--;
  return ele;
}

/* link ele to the tree via its sibling. */

static void
link_sibling( fd_forest_t * forest, fd_forest_blk_t * sibling, fd_forest_blk_t * ele ) {
  fd_forest_blk_t * pool = fd_forest_pool( forest );
  ulong             null = fd_forest_pool_idx_null( pool );
  while( FD_UNLIKELY( sibling->sibling != null )) sibling = fd_forest_pool_ele( pool, sibling->sibling );
  sibling->sibling = fd_forest_pool_idx( pool, ele );
}

/* link child to the tree via its parent. */

static void
link( fd_forest_t * forest, fd_forest_blk_t * parent, fd_forest_blk_t * child ) {
  fd_forest_blk_t * pool = fd_forest_pool( forest );
  ulong             null = fd_forest_pool_idx_null( pool );
  if( FD_LIKELY( parent->child == null ) ) parent->child = fd_forest_pool_idx( pool, child ); /* left-child */
  else link_sibling( forest, fd_forest_pool_ele( pool, parent->child ), child );          /* right-sibling */
  child->parent = fd_forest_pool_idx( pool, parent );
}

/* advance_consumed_frontier attempts to advance the consumed frontier beginning from slot
   using BFS.  head is the first element of a linked list representing
   the BFS queue.  A slot can be advanced if all shreds for the block
   are received ie. consumed_idx = complete_idx. */

static void
advance_consumed_frontier( fd_forest_t * forest, ulong slot, ulong parent_slot ) {
  fd_forest_blk_t *      pool     = fd_forest_pool( forest );
  fd_forest_cns_t *      conspool = fd_forest_conspool( forest );
  fd_forest_consumed_t * consumed = fd_forest_consumed( forest );
  ulong                * queue    = fd_forest_deque( forest );

  fd_forest_cns_t * ele;
  ele = fd_forest_consumed_ele_query( consumed, &slot, NULL, conspool );
  ele = fd_ptr_if( !ele, fd_forest_consumed_ele_query( consumed, &parent_slot, NULL, conspool ), ele );
  if( FD_UNLIKELY( !ele ) ) return;

# if FD_FOREST_USE_HANDHOLDING
  FD_TEST( fd_forest_deque_cnt( queue ) == 0 );
# endif

  /* BFS elements as pool idxs.
     Invariant: whatever is in the queue, must be in the consumed map. */
  fd_forest_deque_push_tail( queue, ele->forest_pool_idx );
  while( FD_LIKELY( fd_forest_deque_cnt( queue ) ) ) {
    fd_forest_blk_t * head  = fd_forest_pool_ele( pool, fd_forest_deque_pop_head( queue ) );
    fd_forest_blk_t * child = fd_forest_pool_ele( pool, head->child );
    if( FD_LIKELY( child &&
                   head->complete_idx != UINT_MAX &&
                   head->complete_idx == head->buffered_idx &&                                                     /* we've received all the shreds for the slot */
                   0==memcmp( head->cmpl, head->fecs, sizeof(fd_forest_blk_idxs_t) * fd_forest_blk_idxs_word_cnt ) /* AND all the FECs for the slot have been completed */) ) {
      fd_forest_cns_t * cons = fd_forest_consumed_ele_remove( consumed, &head->slot, NULL, conspool );
      fd_forest_conspool_ele_release( conspool, cons );
      while( FD_LIKELY( child ) ) { /* add children to consumed frontier */
        consumed_map_insert( forest, child->slot, fd_forest_pool_idx( pool, child ) );

        fd_forest_deque_push_tail( queue, fd_forest_pool_idx( pool, child ) );
        child = fd_forest_pool_ele( pool, child->sibling );
      }
    }
  }
}

static fd_forest_blk_t *
query( fd_forest_t * forest, ulong slot ) {
  fd_forest_blk_t *      pool      = fd_forest_pool( forest );
  fd_forest_ancestry_t * ancestry  = fd_forest_ancestry( forest );
  fd_forest_frontier_t * frontier  = fd_forest_frontier( forest );
  fd_forest_subtrees_t * subtrees  = fd_forest_subtrees( forest );
  fd_forest_orphaned_t * orphaned  = fd_forest_orphaned( forest );

  fd_forest_blk_t * ele = NULL;
  ele =                  fd_forest_ancestry_ele_query( ancestry, &slot, NULL, pool );
  ele = fd_ptr_if( !ele, fd_forest_frontier_ele_query( frontier, &slot, NULL, pool ), ele );
  ele = fd_ptr_if( !ele, fd_forest_subtrees_ele_query( subtrees, &slot, NULL, pool ), ele );
  ele = fd_ptr_if( !ele, fd_forest_orphaned_ele_query( orphaned, &slot, NULL, pool ), ele );
  return ele;
}

static fd_forest_blk_t *
acquire( fd_forest_t * forest, ulong slot, ulong parent_slot ) {
  fd_forest_blk_t * pool = fd_forest_pool( forest );
  if( FD_UNLIKELY( !fd_forest_pool_free( pool ) ) ) {
    FD_LOG_ERR(( "Firedancer ran out of memory when repairing new blocks. If this happened during catchup, your "
                 "snapshot is likely too old and there are too many blocks to repair. You can fix this by using a more "
                 "recent snapshot (if loading a pre-downloaded snapshot) or rebooting (if downloading the snapshot "
                 "live). If this happened while running live (after catchup), Firedancer got disconnected from the "
                 "cluster and stopped being able to receive shreds. Try rebooting." ));
  }
  fd_forest_blk_t * blk  = fd_forest_pool_ele_acquire( pool );
  ulong             null = fd_forest_pool_idx_null( pool );

  blk->slot        = slot;
  blk->parent_slot = parent_slot;
  blk->next        = null;
  blk->parent      = null;
  blk->child       = null;
  blk->sibling     = null;

  blk->consumed_idx = UINT_MAX;
  blk->buffered_idx = UINT_MAX;
  blk->complete_idx = UINT_MAX;

  fd_forest_blk_idxs_null( blk->fecs ); /* expensive */
  fd_forest_blk_idxs_null( blk->idxs ); /* expensive */
  fd_forest_blk_idxs_null( blk->cmpl ); /* expensive */

  /* Metrics tracking */

  fd_forest_blk_idxs_null( blk->code ); /* expensive */
  blk->first_shred_ts = 0;
  blk->first_req_ts   = 0;
  blk->turbine_cnt    = 0;
  blk->repair_cnt     = 0;
  blk->recovered_cnt  = 0;

  return blk;
}

fd_forest_blk_t *
fd_forest_query( fd_forest_t * forest, ulong slot ) {
  return query( forest, slot );
}

fd_forest_blk_t *
fd_forest_blk_insert( fd_forest_t * forest, ulong slot, ulong parent_slot ) {
# if FD_FOREST_USE_HANDHOLDING
  if( FD_UNLIKELY( slot <= fd_forest_root_slot( forest ) ) ) {
    FD_LOG_WARNING(( "fd_forest: fd_forest_blk_insert: slot %lu is <= root slot %lu", slot, fd_forest_root_slot( forest ) ));
    __asm__("int $3");
  }
  FD_TEST( slot > fd_forest_root_slot( forest ) ); /* caller error - inval */
# endif
  fd_forest_blk_t * ele = query( forest, slot );
  if( FD_LIKELY( ele ) ) { return ele; }

  fd_forest_ancestry_t * ancestry = fd_forest_ancestry( forest );
  fd_forest_frontier_t * frontier = fd_forest_frontier( forest );
  fd_forest_subtrees_t * subtrees = fd_forest_subtrees( forest );
  fd_forest_orphaned_t * orphaned = fd_forest_orphaned( forest );
  fd_forest_consumed_t * consumed = fd_forest_consumed( forest );
  fd_forest_cns_t *      conspool = fd_forest_conspool( forest );
  fd_forest_blk_t *      pool     = fd_forest_pool ( forest );
  ulong *                bfs      = fd_forest_deque( forest );

  fd_forest_blk_t * parent = NULL;

  ele = acquire( forest, slot, parent_slot );

  if(        FD_LIKELY  ( parent = fd_forest_ancestry_ele_query ( ancestry, &parent_slot, NULL, pool ) ) ) { /* parent is in ancestry, ele makes new frontier */
    fd_forest_frontier_ele_insert( frontier, ele, pool );
  } else if( FD_UNLIKELY( parent = fd_forest_frontier_ele_remove( frontier, &parent_slot, NULL, pool ) ) ) { /* parent is in frontier, ele makes new frontier */
    fd_forest_ancestry_ele_insert( ancestry, parent, pool );
    fd_forest_frontier_ele_insert( frontier, ele,    pool );
  } else if( FD_UNLIKELY( parent = fd_forest_orphaned_ele_query ( orphaned, &parent_slot, NULL, pool ) ) ) { /* parent is in orphaned, ele makes new orphaned */
    fd_forest_orphaned_ele_insert( orphaned, ele, pool );
  } else if( FD_UNLIKELY( parent = fd_forest_subtrees_ele_query ( subtrees, &parent_slot, NULL, pool ) ) ) { /* parent is in subtrees, ele makes new orphaned */
    fd_forest_orphaned_ele_insert( orphaned, ele, pool );
  } else {                                                                                                   /* parent is not in any map, ele makes new subtree */
    fd_forest_subtrees_ele_insert( subtrees, ele, pool );
    forest->subtree_cnt++;
  }

  if( FD_LIKELY( parent ) ) link( forest, parent, ele );

  /* Iterate subtrees and connect ones where the parent slot matches up
     to the new ele.*/

  for( fd_forest_subtrees_iter_t iter = fd_forest_subtrees_iter_init( subtrees, pool );
       !fd_forest_subtrees_iter_done( iter, subtrees, pool );
       iter = fd_forest_subtrees_iter_next( iter, subtrees, pool ) ) {
    fd_forest_blk_t * orphan = fd_forest_subtrees_iter_ele( iter, subtrees, pool );
    fd_forest_deque_push_tail( bfs, fd_forest_pool_idx( pool, orphan ) );
  }
  while( FD_LIKELY( fd_forest_deque_cnt( bfs ) ) ) {
    fd_forest_blk_t * orphan = fd_forest_pool_ele( pool, fd_forest_deque_pop_head( bfs ) );
    if( FD_UNLIKELY( orphan->parent_slot == ele->slot ) ) {
      link( forest, ele, orphan );
      fd_forest_subtrees_ele_remove( subtrees, &orphan->slot, NULL, pool );
      fd_forest_orphaned_ele_insert( orphaned, orphan,              pool );
      forest->subtree_cnt--;
    }
  }

  /* At this point we are in the state where:

    ele      < in frontier/subtrees/orphaned >
     |
    children < all in orphaned >

    if ele is in frontier, we need to extend the frontier from this child.
    if ele is in orphaned/subtrees, we are done. don't do anything, */

  if( FD_LIKELY( fd_forest_frontier_ele_query( frontier, &ele->slot, NULL, pool ) ) ) fd_forest_deque_push_tail( bfs, fd_forest_pool_idx( pool, ele ) );
  while( FD_LIKELY( !fd_forest_deque_empty( bfs ) ) ) {
    fd_forest_blk_t * parent = fd_forest_pool_ele( pool, fd_forest_deque_pop_head( bfs ) );
    fd_forest_blk_t * child  = fd_forest_pool_ele( pool, parent->child );
    if( FD_LIKELY( child ) ) {
      fd_forest_frontier_ele_remove( frontier, &parent->slot, NULL, pool );
      fd_forest_ancestry_ele_insert( ancestry, parent,              pool );
    }
    while( FD_LIKELY( child ) ) {
      fd_forest_orphaned_ele_remove( orphaned, &child->slot, NULL, pool );
      fd_forest_frontier_ele_insert( frontier, child,              pool );
      fd_forest_deque_push_tail( bfs, fd_forest_pool_idx( pool, child ) );
      child = fd_forest_pool_ele( pool, child->sibling );
    }
  }

  FD_TEST( fd_forest_deque_empty( bfs ) );
  if( FD_LIKELY( fd_forest_ancestry_ele_query( ancestry, &ele->slot, NULL, pool ) ||
                 fd_forest_frontier_ele_query( frontier, &ele->slot, NULL, pool ) ) ) {
    /* There is a chance that we connected this ele to the main tree.
       If this ele doesn't have a parent in the consumed map, add it
       to the consumed map. */
    fd_forest_blk_t * ancestor = ele;
    while( FD_UNLIKELY( ancestor && !fd_forest_consumed_ele_query( consumed, &ancestor->slot, NULL, conspool ) ) ) {
      ancestor = fd_forest_pool_ele( pool, ancestor->parent );
    }
    if( FD_UNLIKELY( !ancestor ) ) {
      FD_LOG_NOTICE(( "fd_forest: ensure_consumed_reachable: ele %lu is not reachable from consumed frontier, adding myself", ele->slot ));
      consumed_map_insert( forest, ele->slot, fd_forest_pool_idx( pool, ele ) );
    }
  }
  return ele;
}

fd_forest_blk_t *
fd_forest_data_shred_insert( fd_forest_t * forest, ulong slot, ulong parent_slot FD_PARAM_UNUSED, uint shred_idx, uint fec_set_idx, int slot_complete, int src ) {
  VER_INC;
  fd_forest_blk_t * ele = query( forest, slot );
# if FD_FOREST_USE_HANDHOLDING
  if( FD_UNLIKELY( !ele ) ) FD_LOG_ERR(( "fd_forest: fd_forest_data_shred_insert: ele %lu is not in the forest. data_shred_insert should be preceded by blk_insert", slot ));
# endif
  fd_forest_blk_idxs_insert_if( ele->fecs, fec_set_idx > 0, fec_set_idx - 1 );
  fd_forest_blk_idxs_insert_if( ele->fecs, slot_complete,   shred_idx       );
  ele->complete_idx = fd_uint_if( slot_complete, shred_idx, ele->complete_idx );

  if( !fd_forest_blk_idxs_test( ele->idxs, shred_idx ) ) { /* newly seen shred */
    ele->turbine_cnt   += (src==SHRED_SRC_TURBINE);
    ele->repair_cnt    += (src==SHRED_SRC_REPAIR);
    ele->recovered_cnt += (src==SHRED_SRC_RECOVERED);
  }
  if( FD_UNLIKELY( ele->first_shred_ts == 0 ) ) ele->first_shred_ts = fd_tickcount();

  fd_forest_blk_idxs_insert( ele->idxs, shred_idx );
  while( fd_forest_blk_idxs_test( ele->idxs, ele->buffered_idx + 1U ) ) ele->buffered_idx++;
  advance_consumed_frontier( forest, slot, parent_slot );
  return ele;
}

fd_forest_blk_t *
fd_forest_fec_insert( fd_forest_t * forest, ulong slot, ulong parent_slot, uint last_shred_idx, uint fec_set_idx, int slot_complete ) {
  VER_INC;

  fd_forest_blk_t * ele = query( forest, slot );
# if FD_FOREST_USE_HANDHOLDING
  if( FD_UNLIKELY( !ele ) ) FD_LOG_ERR(( "fd_forest_fec_insert: ele %lu is not in the forest. fec_insert should be preceded by blk_insert", slot ));
# endif
  /* It's important that we set the cmpl idx here. If this happens to be
     the last fec_complete we needed to finish the slot, then we rely on
     the advance_consumed_frontier call in the below data_shred_insert
     to move forward the consumed frontier.  */
  fd_forest_blk_idxs_insert( ele->cmpl, last_shred_idx );
  for( uint idx = fec_set_idx; idx <= last_shred_idx; idx++ ) {
    ele = fd_forest_data_shred_insert( forest, slot, parent_slot, idx, fec_set_idx, slot_complete & (idx == last_shred_idx), SHRED_SRC_RECOVERED );
  }
  return ele;
}

fd_forest_blk_t *
fd_forest_code_shred_insert( fd_forest_t * forest, ulong slot, uint shred_idx ) {
  fd_forest_blk_t * ele  = query( forest, slot );
  if( FD_UNLIKELY( !ele ) ) {
    return NULL;
  }
  if( FD_UNLIKELY( ele->first_shred_ts == 0 ) ) ele->first_shred_ts = fd_tickcount();

  if( FD_UNLIKELY( shred_idx >= fd_forest_blk_idxs_max( ele->code ) ) ) {
    FD_LOG_INFO(( "fd_forest: fd_forest_code_shred_insert: shred_idx %u is greater than max, not tracking.", shred_idx ));
    ele->turbine_cnt += 1;
    return ele;
  }

  if( FD_LIKELY( !fd_forest_blk_idxs_test( ele->code, shred_idx ) ) ) { /* newly seen shred */
    ele->turbine_cnt += 1;
    fd_forest_blk_idxs_insert( ele->code, shred_idx );
  }
  return ele;
}

void
fd_forest_fec_clear( fd_forest_t * forest, ulong slot, uint fec_set_idx, uint max_shred_idx ) {
  VER_INC;

  if( FD_UNLIKELY( slot <= fd_forest_root_slot( forest ) ) ) {
    FD_LOG_NOTICE(( "fd_forest: fd_forest_fec_clear: slot %lu is <= root slot %lu, ignoring", slot, fd_forest_root_slot( forest ) ));
    return;
  }
  fd_forest_blk_t * ele = query( forest, slot );
  if( FD_UNLIKELY( !ele ) ) return;
  for( uint i=fec_set_idx; i<=fec_set_idx+max_shred_idx; i++ ) {
    fd_forest_blk_idxs_remove( ele->idxs, i );
  }
  if( FD_UNLIKELY( fec_set_idx == 0 ) ) ele->buffered_idx = UINT_MAX;
  else                                  ele->buffered_idx = fd_uint_if( ele->buffered_idx != UINT_MAX, fd_uint_min( ele->buffered_idx, fec_set_idx - 1 ), UINT_MAX );
}

fd_forest_blk_t const *
fd_forest_publish( fd_forest_t * forest, ulong new_root_slot ) {
  FD_LOG_DEBUG(( "[%s] slot %lu", __func__, new_root_slot ));

  VER_INC;

  fd_forest_ancestry_t * ancestry = fd_forest_ancestry( forest );
  fd_forest_orphaned_t * orphaned = fd_forest_orphaned( forest );
  fd_forest_frontier_t * frontier = fd_forest_frontier( forest );
  fd_forest_subtrees_t * subtrees = fd_forest_subtrees( forest );
  fd_forest_consumed_t * consumed = fd_forest_consumed( forest );
  fd_forest_cns_t *      conspool = fd_forest_conspool( forest );
  fd_forest_blk_t *      pool     = fd_forest_pool( forest );
  ulong                  null     = fd_forest_pool_idx_null( pool );
  ulong *                queue    = fd_forest_deque( forest );

  fd_forest_blk_t * old_root_ele = fd_forest_pool_ele( pool, forest->root );
  fd_forest_blk_t * new_root_ele = query( forest, new_root_slot );

# if FD_FOREST_USE_HANDHOLDING
  if( FD_LIKELY( new_root_ele ) ) {
    FD_TEST( new_root_ele->slot > old_root_ele->slot ); /* caller error - inval */
  }
# endif

  /* Edge case where if we haven't been getting repairs, and we have a
     gap between the root and orphans. we publish forward to a slot that
     we don't have. This only case this should be happening is when we
     load a second incremental and that incremental slot lives in the
     gap. In that case this isn't a bug, but we should be treating this
     new root like the snapshot slot / init root. Should be happening
     very rarely given a well-functioning repair.  */

  if( FD_UNLIKELY( !new_root_ele ) ) {
    new_root_ele = fd_forest_blk_insert( forest, new_root_slot, 0 );
    new_root_ele->complete_idx = 0;
    new_root_ele->buffered_idx = 0;
    fd_forest_blk_idxs_full( new_root_ele->cmpl );
    fd_forest_blk_idxs_full( new_root_ele->fecs );
    advance_consumed_frontier( forest, new_root_slot, 0 ); /* advances consumed frontier if possible */
  }

  /* First, remove the previous root, and add it to a FIFO prune queue.
     head points to the queue head (initialized with old_root_ele). */
# if FD_FOREST_USE_HANDHOLDING
  FD_TEST( fd_forest_deque_cnt( queue ) == 0 );
# endif
  fd_forest_blk_t * head = ancestry_frontier_remove( forest, old_root_ele->slot );
  if( FD_LIKELY( head ) ) fd_forest_deque_push_tail( queue, fd_forest_pool_idx( pool, head ) );

  /* Second, BFS down the tree, inserting each ele into the prune queue
     except for the new root.  Loop invariant: head always descends from
     old_root_ele and never descends from new_root_ele. */

  while( FD_LIKELY( fd_forest_deque_cnt( queue ) ) ) {
    head = fd_forest_pool_ele( pool, fd_forest_deque_pop_head( queue ) );
    fd_forest_blk_t * child = fd_forest_pool_ele( pool, head->child );
    while( FD_LIKELY( child ) ) {
      if( FD_LIKELY( child != new_root_ele ) ) { /* do not prune new root or descendants */
        child = ancestry_frontier_remove( forest, child->slot );
        fd_forest_deque_push_tail( queue, fd_forest_pool_idx( pool, child ) );
      }
      child = fd_forest_pool_ele( pool, child->sibling );
    }

    fd_forest_cns_t * cns = NULL;
    if( FD_UNLIKELY( cns = fd_forest_consumed_ele_remove( consumed, &head->slot, NULL, conspool ) ) ) {
      fd_forest_conspool_ele_release( conspool, cns );
    }
    fd_forest_pool_ele_release( pool, head );
  }

  new_root_ele->parent = null; /* unlink new root from parent */
  forest->root         = fd_forest_pool_idx( pool, new_root_ele );

  int new_root_is_orphan = fd_forest_subtrees_ele_query( subtrees, &new_root_ele->slot, NULL, pool ) ||
                           fd_forest_orphaned_ele_query( orphaned, &new_root_ele->slot, NULL, pool );
  if( FD_UNLIKELY( new_root_is_orphan ) ) {

    /* Extend the frontier from the new root */

    FD_TEST( fd_forest_deque_empty( queue ) );
    fd_forest_deque_push_tail( queue, fd_forest_pool_idx( pool, new_root_ele ) );
    while( FD_LIKELY( fd_forest_deque_cnt( queue ) ) ) {
      head = fd_forest_pool_ele( pool, fd_forest_deque_pop_head( queue ) );
      subtrees_orphaned_remove( forest, head->slot );

      fd_forest_blk_t * child = fd_forest_pool_ele( pool, head->child );
      if( FD_LIKELY( child ) ) fd_forest_ancestry_ele_insert( ancestry, head, pool );
      else                     fd_forest_frontier_ele_insert( frontier, head, pool );
      while( child ) {
        fd_forest_deque_push_tail( queue, fd_forest_pool_idx( pool, child ) );
        child = fd_forest_pool_ele( pool, child->sibling );
      }
    }
  }

  /* If there is nothing on the consumed, we have hit an edge case
     during catching up where all of our repair frontiers were < the new root.
     In that case we need to continue repairing from the new root, so
     add it to the consumed map. */

  if( FD_UNLIKELY( fd_forest_consumed_iter_done( fd_forest_consumed_iter_init( consumed, conspool ), consumed, conspool ) ) ) {
    consumed_map_insert( forest, new_root_ele->slot, fd_forest_pool_idx( pool, new_root_ele ) );
    new_root_ele->complete_idx = 0;
    new_root_ele->buffered_idx = 0;
    fd_forest_blk_idxs_full( new_root_ele->cmpl );
    fd_forest_blk_idxs_full( new_root_ele->fecs );
    advance_consumed_frontier( forest, new_root_ele->slot, 0 );
  }

  /* Lastly, cleanup orphans if there orphan heads < new_root_slot.
     First, add any relevant orphans to the prune queue. */

  for( fd_forest_subtrees_iter_t iter = fd_forest_subtrees_iter_init( subtrees, pool );
       !fd_forest_subtrees_iter_done( iter, subtrees, pool );
       iter = fd_forest_subtrees_iter_next( iter, subtrees, pool ) ) {
    fd_forest_blk_t * ele = fd_forest_subtrees_iter_ele( iter, subtrees, pool );
    if( FD_UNLIKELY( ele->slot < new_root_slot ) ) {
      fd_forest_deque_push_tail( queue, fd_forest_pool_idx( pool, ele ) );
    }
  }

  /* Now BFS and clean up children of these orphan heads */
  while( FD_UNLIKELY( fd_forest_deque_cnt( queue ) ) ) {
    head = fd_forest_pool_ele( pool, fd_forest_deque_pop_head( queue ) );
    fd_forest_blk_t * child = fd_forest_pool_ele( pool, head->child );
    while( FD_LIKELY( child ) ) {
      if( FD_LIKELY( child != new_root_ele ) ) {
        fd_forest_deque_push_tail( queue, fd_forest_pool_idx( pool, child ) );
      }
      child = fd_forest_pool_ele( pool, child->sibling );
    }
    ulong remove = fd_forest_orphaned_idx_remove( orphaned, &head->slot, null, pool ); /* remove myself */
    remove = fd_ulong_if( remove == null, fd_forest_subtrees_idx_remove( subtrees, &head->slot, null, pool ), remove );
    fd_forest_pool_ele_release( pool, head ); /* free head */
  }
  return new_root_ele;
}

fd_forest_t *
fd_forest_clear( fd_forest_t * forest ) {
  return forest;
}

fd_forest_iter_t
fd_forest_iter_init( fd_forest_t * forest ) {
  /* Find first element. Anything on the frontier. */
  fd_forest_blk_t      const * pool     = fd_forest_pool_const( forest );
  fd_forest_cns_t      const * conspool = fd_forest_conspool_const( forest );
  fd_forest_consumed_t const * consumed = fd_forest_consumed_const( forest );


  fd_forest_consumed_iter_t consumed_iter = fd_forest_consumed_iter_init( consumed, conspool );
  fd_forest_iter_t          repair_iter   = { fd_forest_pool_idx_null( pool ),
                                              UINT_MAX,
                                              fd_fseq_query( fd_forest_ver_const( forest ) ),
                                              consumed_iter };
  /* Nothing on frontier */

  if( FD_UNLIKELY( fd_forest_consumed_iter_done( consumed_iter, consumed, conspool ) ) ) return repair_iter;

  /* Populate initial iter shred index */

  fd_forest_cns_t const * ele_ = fd_forest_consumed_iter_ele_const( consumed_iter, consumed, conspool );
  fd_forest_blk_t const * ele  = fd_forest_pool_ele_const( pool, ele_->forest_pool_idx );

  while( ele->complete_idx != UINT_MAX && ele->buffered_idx == ele->complete_idx ) {
    /* This fork frontier is actually complete, so we can skip it. Also
       handles edge case where we are calling iter_init right after a
       forest_init */
    consumed_iter = fd_forest_consumed_iter_next( consumed_iter, consumed, conspool );
    if( FD_UNLIKELY( fd_forest_consumed_iter_done( consumed_iter, consumed, conspool ) ) ) {
      repair_iter.ele_idx   = fd_forest_pool_idx_null( pool );
      repair_iter.shred_idx = UINT_MAX; /* no more elements */
      return repair_iter;
    }
    ele_ = fd_forest_consumed_iter_ele_const( consumed_iter, consumed, conspool );
    ele  = fd_forest_pool_ele_const( pool, ele_->forest_pool_idx );
  }

  repair_iter.ele_idx   = ele_->forest_pool_idx;
  repair_iter.shred_idx = ele->complete_idx == UINT_MAX ? UINT_MAX : ele->buffered_idx + 1;

  return repair_iter;
}

fd_forest_iter_t
fd_forest_iter_next( fd_forest_iter_t iter, fd_forest_t const * forest ) {
  fd_forest_consumed_t const * consumed = fd_forest_consumed_const( forest );
  fd_forest_cns_t      const * conspool = fd_forest_conspool_const( forest );

  fd_forest_blk_t const      * pool     = fd_forest_pool_const( forest );
  fd_forest_blk_t const      * ele      = fd_forest_pool_ele_const( pool, iter.ele_idx );

  if( iter.frontier_ver != fd_fseq_query( fd_forest_ver_const( forest ) ) ) {
    /* If the frontier has changed since we started this traversal, we
       need to reset the iterator. */
    iter.ele_idx   = fd_forest_pool_idx_null( pool ) ;
    iter.shred_idx = UINT_MAX; /* no more elements */
    return iter;
  }

  uint next_shred_idx = iter.shred_idx;
  for(;;) {
    next_shred_idx++;

    /* Case 1: No more shreds in this slot to request, move to the
       next one. Wraparound the shred_idx.

       Case 2: original iter.shred_idx == UINT_MAX (implies prev req
       was a highest_window_idx request). Also requires moving to next
       slot and wrapping the shred_idx. */

    if( FD_UNLIKELY( next_shred_idx >= ele->complete_idx || iter.shred_idx == UINT_MAX ) ) {
      iter.ele_idx = ele->child;
      ele          = fd_forest_pool_ele_const( pool, iter.ele_idx );
      if( FD_UNLIKELY( iter.ele_idx == fd_forest_pool_idx_null( pool ) ) ) {
        iter.shred_idx = UINT_MAX; /* no more elements */

        /* rare and unlikely to happen during a regular run, but if the
           frontier pool hasn't changed at all since we started this
           traversal, we can cleanly select the next node in the
           frontier using the stored frontier iterator. If the frontier
           has changed though, we should just return done and let the
           caller reset the iterator. */

        if( FD_UNLIKELY( iter.frontier_ver == fd_fseq_query( fd_forest_ver_const( forest ) ) ) ) {
          iter.head = fd_forest_consumed_iter_next( iter.head, consumed, conspool );
          if( FD_UNLIKELY( !fd_forest_consumed_iter_done( iter.head, consumed, conspool ) ) ) {
            iter.ele_idx   = fd_forest_consumed_iter_ele_const( iter.head, consumed, conspool )->forest_pool_idx;
            ele            = fd_forest_pool_ele_const( pool, iter.ele_idx );
            iter.shred_idx = ele->complete_idx == UINT_MAX ? UINT_MAX : ele->buffered_idx + 1;
          }
        }
        return iter;
      }
      next_shred_idx = ele->buffered_idx + 1;
    }

    /* Common case - valid shred to request. Note you can't know the
       ele->complete_idx until you have actually received the slot
       complete shred, thus the we can do lt instead of leq  */

    if( ele->complete_idx != UINT_MAX &&
        next_shred_idx < ele->complete_idx &&
        !fd_forest_blk_idxs_test( ele->idxs, next_shred_idx ) ) {
      iter.shred_idx = next_shred_idx;
      break;
    }

    /* Current slot actually needs a highest_window_idx request */

    if( FD_UNLIKELY( ele->complete_idx == UINT_MAX ) ) {
      iter.shred_idx = UINT_MAX;
      break;
    }
  }
  return iter;
}

int
fd_forest_iter_done( fd_forest_iter_t iter, fd_forest_t const * forest ) {
  fd_forest_blk_t const * pool = fd_forest_pool_const( forest );
  return iter.ele_idx == fd_forest_pool_idx_null( pool ); /* no more elements */
}

#include <stdio.h>

static void
preorder( fd_forest_t const * forest, fd_forest_blk_t const * ele ) {
  fd_forest_blk_t const * pool  = fd_forest_pool_const( forest );
  fd_forest_blk_t const * child = fd_forest_pool_ele_const( pool, ele->child );
  printf( "%lu ", ele->slot );
  while( FD_LIKELY( child ) ) {
    preorder( forest, child );
    child = fd_forest_pool_ele_const( pool, child->sibling );
  }
}

void
fd_forest_preorder_print( fd_forest_t const * forest ) {
  FD_LOG_NOTICE( ( "\n\n[Preorder]" ) );
  preorder( forest, fd_forest_pool_ele_const( fd_forest_pool_const( forest ), forest->root ) );
  printf( "\n\n" );
}

/* TODO use bit tricks / change */
static int
num_digits( ulong slot ) {
  /* using log10 */
  int digits = 0;
  while( slot ) {
    digits++;
    slot /= 10;
  }
  return digits;
}

static void
ancestry_print2( fd_forest_t const * forest,
                 fd_forest_blk_t const    * ele,
                 fd_forest_blk_t const    * prev,
                 ulong        last_printed,
                 int          depth,
                 const char * prefix ) {

  if( FD_UNLIKELY( ele == NULL ) ) return;

  fd_forest_blk_t const * pool = fd_forest_pool_const( forest );
  int digits = num_digits( ele->slot );

  /* If there is a prefix, this means we are on a fork,  and we need to
     indent to the correct depth. We do depth - 1 for more satisfying
     spacing. */
  if( FD_UNLIKELY( strcmp( prefix, "" ) ) ) {
    for( int i = 0; i < depth - 1; i++ ) printf( " " );
    if( depth > 0 ) printf( "%s", prefix );
  }

  if ( FD_UNLIKELY( !prev ) ) { // New interval
    printf("[%lu" , ele->slot );
    last_printed = ele->slot;
    depth       += 1 + digits;
  }

  fd_forest_blk_t const * curr = fd_forest_pool_ele_const( pool, ele->child );

  /* Cases in which we close the interval:
     1. the slots are no longer consecutive. no eliding, close bracket
     2. current ele has multiple children, want to print forks.
     Maintain last_printed on this fork so that we don't print [a, a]
     intervals. */

  fd_forest_blk_t const * new_prev = ele;

  if( prev && prev->slot != ele->slot - 1 ) { // non-consecutive, do not elide
    if( last_printed == prev->slot ){
      printf( "] ── [%lu", ele->slot );
      depth += digits + 6;
    } else {
      printf( ", %lu] ── [%lu", prev->slot, ele->slot );
      depth += digits + num_digits(prev->slot ) + 8;
    }
    last_printed = ele->slot;
  } else if( curr && curr->sibling != ULONG_MAX ) { // has multiple children, do not elide
    if( last_printed == ele->slot ){
      printf( "] ── " );
      depth += 5;
    } else {
      printf( ", %lu] ── ", ele->slot );
      depth += digits + 2;
    }
    last_printed = ele->slot;
    new_prev = NULL;
  }

  if( !curr ){ // no children, close bracket, end fork
    if( last_printed == ele->slot ){
      printf( "]\n" );
    } else {
      printf( ", %lu]\n", ele->slot );
    }
    return;
  }

  char new_prefix[512]; /* FIXME size this correctly */
  new_prefix[0] = '\0'; /* first fork stays on the same line, no prefix */
  while( curr ) {
    if( fd_forest_pool_ele_const( pool, curr->sibling ) ) {
      ancestry_print2( forest, curr, new_prev, last_printed, depth, new_prefix );
    } else {
      ancestry_print2( forest, curr, new_prev, last_printed, depth, new_prefix );
    }
    curr = fd_forest_pool_ele_const( pool, curr->sibling );

    /* Set up prefix for following iterations */
    if( curr && curr->sibling != ULONG_MAX ) {
      sprintf( new_prefix, "├── " ); /* any following forks start on new lines */
    } else {
      sprintf( new_prefix, "└── " ); /* any following forks start on new lines */
    }
  }

}

static void
ancestry_print3( fd_forest_t const * forest, fd_forest_blk_t const * ele, int space, const char * prefix, fd_forest_blk_t const * prev, int elide ) {
  fd_forest_blk_t const * pool = fd_forest_pool_const( forest );

  if( ele == NULL ) return;

  /* print the slot itself. either we might need to start a new interval, or it may get elided */
  fd_forest_blk_t const * child = fd_forest_pool_ele_const( pool, ele->child );

  if( !elide ) {
    if( space > 0 ) printf( "\n" );
    for( int i = 0; i < space; i++ ) printf( " " );
    printf( "%s", prefix );
    printf( "%lu", ele->slot );
  }

  if( !child && !elide ) { /* double check these cases arent the same...*/
    printf( "]" );
    return;
  } /* no children, close bracket */

  if( !child && elide ) {
    printf( ", %lu]", ele->slot );
    return;
  }

  prev = ele;
  char new_prefix[1024]; /* FIXME size this correctly */
  int one_child = child && child->sibling == ULONG_MAX;
  if( one_child &&
      child->slot != ele->slot + 1 ) { // if I have ONE CHILD and one child is non-consecutive

    if( elide ) {
      /* current slot wasn't printed, but now that we are branching,
         we will want to print the current slot and close the bracket */
      printf( ", %lu]", ele->slot );
      space += fd_int_max( num_digits( ele->slot ) + 2, 0 );
    } else {
      printf( "]");
    }

    sprintf( new_prefix, "└── [" ); /* end branch */
    ancestry_print3( forest, child, space + 5, new_prefix, prev, 0 );
  } else if ( one_child && child->slot == ele->slot + 1 ) {
    ancestry_print3( forest, child, space, prefix, prev, 1);
  } else { /* multiple children */
    if( elide ) {
      /* current slot wasn't printed, but now that we are branching,
         we will want to print the current slot and close the bracket */
      printf( ", %lu]", ele->slot );
      space += fd_int_max( num_digits( ele->slot ) + 2, 0 );
    } else {
      printf( "]");
    }

    while( child ) {
      if( fd_forest_pool_ele_const( pool, child->sibling ) ) {
        sprintf( new_prefix, "├── [" ); /* branch indicating more siblings follow */
        ancestry_print3( forest, child, space + 5, new_prefix, prev, 0 );
      } else {
        sprintf( new_prefix, "└── [" ); /* end branch */
        ancestry_print3( forest, child, space + 5, new_prefix, prev, 0 );
      }
      child = fd_forest_pool_ele_const( pool, child->sibling );
    }
  }
}

void
fd_forest_ancestry_print( fd_forest_t const * forest ) {
  printf(("\n\n[Ancestry]\n" ) );
  ancestry_print3( forest, fd_forest_pool_ele_const( fd_forest_pool_const( forest ), forest->root ), 0, "[", NULL, 0 );
  fflush(stdout); /* Ensure ancestry printf output is flushed */
}

void
fd_forest_frontier_print( fd_forest_t const * forest ) {
  printf( "\n\n[Repairing Next]\n" );
  fd_forest_consumed_t const * consumed = fd_forest_consumed_const( forest );
  fd_forest_cns_t const *      conspool = fd_forest_conspool_const( forest );
  fd_forest_blk_t const *      pool     = fd_forest_pool_const( forest );
  for( fd_forest_consumed_iter_t iter = fd_forest_consumed_iter_init( consumed, conspool );
       !fd_forest_consumed_iter_done( iter, consumed, conspool );
       iter = fd_forest_consumed_iter_next( iter, consumed, conspool ) ) {
    fd_forest_cns_t const * ele = fd_forest_consumed_iter_ele_const( iter, consumed, conspool );
    fd_forest_blk_t const * ele_ = fd_forest_pool_ele_const( pool, ele->forest_pool_idx );
    printf("%lu (%u/%u)\n", ele_->slot, ele_->buffered_idx + 1, ele_->complete_idx + 1 );
   //ancestry_print( forest, fd_forest_pool_ele_const( fd_forest_pool_const( forest ), fd_forest_pool_idx( pool, ele ) ), 0, "" );
  }
  fflush(stdout);
}

void
fd_forest_orphaned_print( fd_forest_t const * forest ) {
  printf( "\n[Orphaned]\n" );
  fd_forest_subtrees_t const * subtrees = fd_forest_subtrees_const( forest );
  fd_forest_blk_t const * pool = fd_forest_pool_const( forest );
  for( fd_forest_subtrees_iter_t iter = fd_forest_subtrees_iter_init( subtrees, pool );
       !fd_forest_subtrees_iter_done( iter, subtrees, pool );
       iter = fd_forest_subtrees_iter_next( iter, subtrees, pool ) ) {
    fd_forest_blk_t const * ele = fd_forest_subtrees_iter_ele_const( iter, subtrees, pool );
    ancestry_print2( forest, fd_forest_pool_ele_const( fd_forest_pool_const( forest ), fd_forest_pool_idx( pool, ele ) ), NULL, 0, 0, "" );
  }
  fflush(stdout);
}

void
fd_forest_print( fd_forest_t const * forest ) {
  if( FD_UNLIKELY( forest->root == ULONG_MAX ) ) return;
  FD_LOG_NOTICE(("\n\n[Forest]" ) );
  fd_forest_ancestry_print( forest );
  fd_forest_frontier_print( forest );
  fd_forest_orphaned_print( forest );
  printf("\n");
  fflush(stdout);
}

#undef FD_FOREST_PRINT
