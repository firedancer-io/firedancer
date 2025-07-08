#include "fd_forest.h"

static void ver_inc( ulong ** ver ) {
  fd_fseq_update( *ver, fd_fseq_query( *ver ) + 1 );
}

#define VER_INC ulong * ver __attribute__((cleanup(ver_inc))) = fd_forest_ver( forest ); ver_inc( &ver )

void *
fd_forest_new( void * shmem, ulong ele_max, ulong seed ) {
  ulong fec_max = ele_max * 32;
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
  forest          = FD_SCRATCH_ALLOC_APPEND( l, fd_forest_align(),          sizeof(fd_forest_t)                     );
  void * ver      = FD_SCRATCH_ALLOC_APPEND( l, fd_fseq_align(),            fd_fseq_footprint()                     );
  void * pool     = FD_SCRATCH_ALLOC_APPEND( l, fd_forest_pool_align(),     fd_forest_pool_footprint    ( fec_max ) );
  void * ancestry = FD_SCRATCH_ALLOC_APPEND( l, fd_forest_ancestry_align(), fd_forest_ancestry_footprint( fec_max ) );
  void * frontier = FD_SCRATCH_ALLOC_APPEND( l, fd_forest_frontier_align(), fd_forest_frontier_footprint( fec_max ) );
  void * orphaned = FD_SCRATCH_ALLOC_APPEND( l, fd_forest_orphaned_align(), fd_forest_orphaned_footprint( fec_max ) );
  void * deque    = FD_SCRATCH_ALLOC_APPEND( l, fd_forest_deque_align(),    fd_forest_deque_footprint   ( fec_max ) );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, fd_forest_align() ) == (ulong)shmem + footprint );

  forest->root           = ULONG_MAX;
  forest->wksp_gaddr     = fd_wksp_gaddr_fast( wksp, forest );
  forest->ver_gaddr      = fd_wksp_gaddr_fast( wksp, fd_fseq_join           ( fd_fseq_new           ( ver,      FD_FOREST_VER_UNINIT ) ) );
  forest->pool_gaddr     = fd_wksp_gaddr_fast( wksp, fd_forest_pool_join    ( fd_forest_pool_new    ( pool,     fec_max              ) ) );
  forest->ancestry_gaddr = fd_wksp_gaddr_fast( wksp, fd_forest_ancestry_join( fd_forest_ancestry_new( ancestry, fec_max, seed        ) ) );
  forest->frontier_gaddr = fd_wksp_gaddr_fast( wksp, fd_forest_frontier_join( fd_forest_frontier_new( frontier, fec_max, seed        ) ) );
  forest->orphaned_gaddr = fd_wksp_gaddr_fast( wksp, fd_forest_orphaned_join( fd_forest_orphaned_new( orphaned, fec_max, seed        ) ) );
  forest->deque_gaddr    = fd_wksp_gaddr_fast( wksp, fd_forest_deque_join   ( fd_forest_deque_new   ( deque,    fec_max              ) ) );

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

fd_forest_t *
fd_forest_init( fd_forest_t * forest, ulong root_slot ) {
  FD_LOG_INFO(( "fd_forest_init( forest, %lu);", root_slot ));
  FD_TEST( forest );
  FD_TEST( fd_fseq_query( fd_forest_ver( forest ) ) == FD_FOREST_VER_UNINIT );

  VER_INC;

  fd_forest_ele_t *      pool     = fd_forest_pool( forest );
  ulong                  null     = fd_forest_pool_idx_null( pool );
  fd_forest_frontier_t * frontier = fd_forest_frontier( forest );

  /* Initialize the root node from a pool element. */

  fd_forest_ele_t * root_ele = fd_forest_pool_ele_acquire( pool );
  root_ele->key              = root_slot << 32 | UINT_MAX;
  root_ele->slot             = root_slot;
  root_ele->fec_set_idx      = UINT_MAX;
  root_ele->parent           = null;
  root_ele->child            = null;
  root_ele->sibling          = null;
  root_ele->buffered_idx     = FD_REEDSOL_DATA_SHREDS_MAX - 1;
  root_ele->data_cnt         = FD_REEDSOL_DATA_SHREDS_MAX;
  root_ele->completed        = 1;
  fd_fec_shred_idxs_null( root_ele->idxs );

  forest->root = fd_forest_pool_idx( pool, root_ele );
  fd_forest_frontier_ele_insert( frontier, root_ele, pool ); /* cannot fail */

  /* Sanity checks. */

  FD_TEST( root_ele );
  FD_TEST( root_ele == fd_forest_frontier_ele_query( frontier, &root_ele->key, NULL, pool ));
  FD_TEST( root_ele->slot == root_slot );

  return forest;
}

void *
fd_forest_fini( fd_forest_t * forest ) {
  fd_fseq_update( fd_forest_ver( forest ), FD_FOREST_VER_UNINIT );
  return (void *)forest;
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

  fd_forest_ele_t const * pool = fd_forest_pool_const( forest );
  if( fd_forest_ancestry_verify( fd_forest_ancestry_const( forest ), fd_forest_pool_max( pool ), pool ) == -1 ) return -1;
  if( fd_forest_frontier_verify( fd_forest_frontier_const( forest ), fd_forest_pool_max( pool ), pool ) == -1 ) return -1;

  return 0;
}

FD_FN_PURE static inline ulong *
fd_forest_deque( fd_forest_t * forest ) {
  return fd_wksp_laddr_fast( fd_forest_wksp( forest ), forest->deque_gaddr );
}

/* remove removes and returns a connected ele from ancestry or frontier
   maps.  does not remove orphaned ele.  does not unlink ele. */

static fd_forest_ele_t *
ancestry_frontier_remove( fd_forest_t * forest, /*fd_hash_t * merkle, */ ulong slot, uint fec_set_idx ) {
  ulong key = slot << 32 | fec_set_idx;
  fd_forest_ele_t * pool = fd_forest_pool( forest );
  fd_forest_ele_t * ele  = NULL;
  ele =                  fd_forest_ancestry_ele_remove( fd_forest_ancestry( forest ), &key, NULL, pool );
  ele = fd_ptr_if( !ele, fd_forest_frontier_ele_remove( fd_forest_frontier( forest ), &key, NULL, pool ), ele );
  return ele;
}

/* link ele to the tree via its sibling. */

static void
link_sibling( fd_forest_t * forest, fd_forest_ele_t * sibling, fd_forest_ele_t * ele ) {
  fd_forest_ele_t * pool = fd_forest_pool( forest );
  ulong             null = fd_forest_pool_idx_null( pool );
  while( FD_UNLIKELY( sibling->sibling != null )) sibling = fd_forest_pool_ele( pool, sibling->sibling );
  sibling->sibling = fd_forest_pool_idx( pool, ele );
}

/* link child to the tree via its parent. */

static void
link( fd_forest_t * forest, fd_forest_ele_t * parent, fd_forest_ele_t * child ) {
  fd_forest_ele_t * pool = fd_forest_pool( forest );
  ulong             null = fd_forest_pool_idx_null( pool );
  if( FD_LIKELY( parent->child == null ) ) parent->child = fd_forest_pool_idx( pool, child ); /* left-child */
  else link_sibling( forest, fd_forest_pool_ele( pool, parent->child ), child );          /* right-sibling */
  child->parent = fd_forest_pool_idx( pool, parent );
}

/* advance_frontier attempts to advance the frontier beginning from slot
   using BFS.  head is the first element of a linked list representing
   the BFS queue.  A slot can be advanced if all shreds for the block
   are received ie. consumed_idx = complete_idx. */

static void
advance_frontier( fd_forest_t * forest, ulong slot, uint fec_set_idx ) {
  fd_forest_ele_t *      pool     = fd_forest_pool( forest );
  fd_forest_ancestry_t * ancestry = fd_forest_ancestry( forest );
  fd_forest_frontier_t * frontier = fd_forest_frontier( forest );
  ulong                * queue    = fd_forest_deque( forest );

  ulong key = slot << 32 | fec_set_idx;
  fd_forest_ele_t * ele;
  ele = fd_forest_frontier_ele_query( fd_forest_frontier( forest ), &key, NULL, pool );
  if( FD_UNLIKELY( !ele ) ) {
    ele = fd_forest_ancestry_ele_query( fd_forest_ancestry( forest ), &key, NULL, pool );
    if( FD_UNLIKELY( !ele ) ) return;
    /* current ele is in ancestry, but its parent is on frontier*/
    ulong parent_key = fd_forest_pool_ele( pool, ele->parent )->key;
    ele = fd_forest_frontier_ele_query( fd_forest_frontier( forest ), &parent_key, NULL, pool );
  }
  if( FD_UNLIKELY( !ele ) ) return;

# if FD_FOREST_USE_HANDHOLDING
  FD_TEST( fd_forest_deque_cnt( queue ) == 0 );
# endif

  /* BFS elements as pool idxs */
  fd_forest_deque_push_tail( queue, fd_forest_pool_idx( pool, ele ) );
  while( FD_LIKELY( fd_forest_deque_cnt( queue ) ) ) {
    fd_forest_ele_t * head  = fd_forest_pool_ele( pool, fd_forest_deque_pop_head( queue ) );
    fd_forest_ele_t * child = fd_forest_pool_ele( pool, head->child );
    if( FD_LIKELY( child && head->data_cnt != UINT_MAX && head->buffered_idx == head->data_cnt - 1 ) ) {
      fd_forest_frontier_ele_remove( frontier, &head->key, NULL, pool );
      fd_forest_ancestry_ele_insert( ancestry, head, pool );
      while( FD_LIKELY( child ) ) { /* append children to frontier */
        fd_forest_ancestry_ele_remove( ancestry, &child->key, NULL, pool );
        fd_forest_frontier_ele_insert( frontier, child, pool );

        fd_forest_deque_push_tail( queue, fd_forest_pool_idx( pool, child ) );
        child = fd_forest_pool_ele( pool, child->sibling );
      }
    }
  }
}


static fd_forest_ele_t *
query( fd_forest_t * forest, ulong slot, uint fec_set_idx ) {
  ulong key = slot << 32 | fec_set_idx;
  fd_forest_ele_t *      pool      = fd_forest_pool( forest );
  fd_forest_ancestry_t * ancestry  = fd_forest_ancestry( forest );
  fd_forest_frontier_t * frontier  = fd_forest_frontier( forest );
  fd_forest_orphaned_t * orphaned  = fd_forest_orphaned( forest );

  fd_forest_ele_t * ele;
  ele =                  fd_forest_ancestry_ele_query( ancestry, &key, NULL, pool );
  ele = fd_ptr_if( !ele, fd_forest_frontier_ele_query( frontier, &key, NULL, pool ), ele );
  ele = fd_ptr_if( !ele, fd_forest_orphaned_ele_query( orphaned, &key, NULL, pool ), ele );
  return ele;
}

static fd_forest_ele_t *
remove_fec( fd_forest_t * forest, ulong slot, uint fec_set_idx ) {
  ulong key = slot << 32 | fec_set_idx;
  fd_forest_ele_t *      pool      = fd_forest_pool( forest );
  fd_forest_ancestry_t * ancestry  = fd_forest_ancestry( forest );
  fd_forest_frontier_t * frontier  = fd_forest_frontier( forest );
  fd_forest_orphaned_t * orphaned  = fd_forest_orphaned( forest );

  fd_forest_ele_t * ele;
  ele =                  fd_forest_ancestry_ele_remove( ancestry, &key, NULL, pool );
  ele = fd_ptr_if( !ele, fd_forest_frontier_ele_remove( frontier, &key, NULL, pool ), ele );
  ele = fd_ptr_if( !ele, fd_forest_orphaned_ele_remove( orphaned, &key, NULL, pool ), ele );
  return ele;
}

static fd_forest_ele_t *
acquire( fd_forest_t * forest, ulong slot, uint fec_set_idx ) {
  fd_forest_ele_t * pool = fd_forest_pool( forest );
  fd_forest_ele_t * ele  = fd_forest_pool_ele_acquire( pool );
  ulong             null = fd_forest_pool_idx_null( pool );

  ele->key     = slot << 32 | fec_set_idx;
  ele->slot    = slot;
  ele->fec_set_idx = fec_set_idx;
  ele->next    = null;
  ele->parent  = null;
  ele->child   = null;
  ele->sibling = null;

  ele->buffered_idx = fd_uint_if( fec_set_idx == UINT_MAX, FD_REEDSOL_DATA_SHREDS_MAX - 1, UINT_MAX );
  ele->data_cnt     = fd_uint_if( fec_set_idx == UINT_MAX, FD_REEDSOL_DATA_SHREDS_MAX, UINT_MAX );
  ele->completed    = fd_uchar_if( fec_set_idx == UINT_MAX, 1, 0 );
  /* for sentinel ele we've buffered everything already */
  fd_fec_shred_idxs_null( ele->idxs ); /* FIXME expensive */

  return ele;
}

/* Inserts a new ele for the fec_set, and inserts all the parents up until UINT_MAX of the parent_slot.
  Returns the head of all the inserted eles, so usually will be the sentinel of the parent. But
  if that sentinel already exists....??? */
static fd_forest_ele_t *
insert( fd_forest_t * forest, ulong slot, uint fec_set_idx, ushort parent_off ) {
  fd_forest_ele_t * pool = fd_forest_pool( forest );

# if FD_FOREST_USE_HANDHOLDING
  //FD_TEST( parent_off <= slot );                   /* caller err - inval */
  FD_TEST( fd_forest_pool_free( pool ) );          /* impl err - oom */
  FD_TEST( slot > fd_forest_root_slot( forest ) ); /* caller error - inval */
# endif

  ulong parent_slot = slot - parent_off;

  fd_forest_ele_t * ele   = acquire( forest, slot, fec_set_idx );
  fd_forest_ele_t * parent;
  fd_forest_orphaned_ele_insert( fd_forest_orphaned( forest ), ele, pool );
  /* Atp we have:
         ancestry
    (slot, fec_set_idx)
  */

  if( FD_LIKELY( fec_set_idx ) ) {
    /* Not the first FEC set in the slot, so we can't link it to anything yet. */
    return ele;
  }

  parent = query( forest, parent_slot, UINT_MAX );
  if( FD_LIKELY( parent ) ) {
    /* sentinel exists, can link to it, i.e. parent slot last fec arrived before this slot. not an orphan head, but we do need to worry about frontier */
    fd_forest_orphaned_ele_remove( fd_forest_orphaned( forest ), &ele->key, NULL, pool );
    fd_forest_ancestry_ele_insert( fd_forest_ancestry( forest ), ele, pool );
    link( forest, parent, ele ); /* cannot fail */

    /* Edge case where we are creating a fork off of a node that is behind the frontier.
       We need to add this node to the frontier. FIXME: can we make this loop more efficient, hopping fecs? */

    fd_forest_ele_t * ancestor = ele;
    while( ancestor /* ancestor exists */
           && !fd_forest_frontier_ele_query( fd_forest_frontier( forest ), &ancestor->key, NULL, pool ) /* ancestor is not on frontier */
           && !fd_forest_orphaned_ele_query( fd_forest_orphaned( forest ), &ancestor->key, NULL, pool ) /* ancestor is not an orphan */ ) {
      ancestor = fd_forest_pool_ele( pool, ancestor->parent );
    }
    if( FD_UNLIKELY( !ancestor ) ) {
      /* Did not find ancestor on frontier OR orphan, which means it must be behind the frontier barrier. */
      fd_forest_ancestry_ele_remove( fd_forest_ancestry( forest ), &ele->key, NULL, pool );
      fd_forest_frontier_ele_insert( fd_forest_frontier( forest ), ele, pool );
    }
  }
  return ele;
}

fd_forest_ele_t const *
fd_forest_query_const( fd_forest_t const * forest, ulong slot, uint fec_set_idx ) {
  ulong key = slot << 32 | fec_set_idx;
  fd_forest_ele_t const *      pool     = fd_forest_pool_const( forest );
  fd_forest_ancestry_t const * ancestry = fd_forest_ancestry_const( forest );
  fd_forest_frontier_t const * frontier = fd_forest_frontier_const( forest );
  fd_forest_orphaned_t const * orphaned = fd_forest_orphaned_const( forest );

  fd_forest_ele_t const * ele;
  ele =                  fd_forest_ancestry_ele_query_const( ancestry, &key, NULL, pool );
  ele = fd_ptr_if( !ele, fd_forest_frontier_ele_query_const( frontier, &key, NULL, pool ), ele );
  ele = fd_ptr_if( !ele, fd_forest_orphaned_ele_query_const( orphaned, &key, NULL, pool ), ele );
  return ele;

}

fd_forest_ele_t *
fd_forest_query( fd_forest_t * forest, ulong slot, uint fec_set_idx ) {
  return query( forest, slot, fec_set_idx );
}


fd_forest_ele_t *
fd_forest_data_shred_insert( fd_forest_t * forest, ulong slot, ushort parent_off, uint shred_idx, uint fec_set_idx, int data_complete, int slot_complete ) {

  FD_LOG_INFO(( "fd_forest_data_shred_insert( forest, %lu, %u, %u, %u, %d, %d);", slot, parent_off, shred_idx, fec_set_idx, data_complete, slot_complete ));
# if FD_FOREST_USE_HANDHOLDING
  FD_TEST( slot > fd_forest_root_slot( forest ) ); /* caller error - inval */
# endif

  VER_INC;

  ulong parent_slot = slot - parent_off;

  fd_forest_ele_t * pool = fd_forest_pool( forest );
  fd_forest_ele_t * ele  = query( forest, slot, fec_set_idx );
  if( FD_UNLIKELY( !ele ) ) ele = insert( forest, slot, fec_set_idx, parent_off ); /* cannot fail */

  /* atp if new ele, its probably in orphan map (unless fec_set_idx == 0, then its in ancestry) */

  if( FD_UNLIKELY( data_complete || slot_complete ) ) ele->data_cnt = shred_idx - fec_set_idx + 1;
  if( FD_UNLIKELY( query( forest, slot, shred_idx + 1 ) ) ) ele->data_cnt = shred_idx - fec_set_idx + 1;

  if ( FD_UNLIKELY( slot_complete && ele->child == fd_forest_pool_idx_null( pool ) )) {
    /* link it to the forward sentinel */
    fd_forest_ele_t * sentinel = query( forest, slot, UINT_MAX );
    sentinel = fd_ptr_if( !sentinel, acquire( forest, slot, UINT_MAX ), sentinel );
    remove_fec( forest, slot, UINT_MAX );
    fd_forest_ancestry_ele_insert( fd_forest_ancestry( forest ), sentinel, pool );
    link( forest, ele, sentinel );
  } else if( FD_UNLIKELY( ele->data_cnt != UINT_MAX && ele->child == fd_forest_pool_idx_null( pool ) ) ) {
    /* link it to the forward FEC */
    fd_forest_ele_t * next = query( forest, slot, fec_set_idx + ele->data_cnt );
    next = fd_ptr_if( !next, acquire( forest, slot, fec_set_idx + ele->data_cnt ), next );
    remove_fec( forest, slot, fec_set_idx + ele->data_cnt );
    fd_forest_ancestry_ele_insert( fd_forest_ancestry( forest ), next, pool );
    link( forest, ele, next );
  }

  if( FD_UNLIKELY( ele->parent == fd_forest_pool_idx_null( pool ) && ele->fec_set_idx == 0 ) ) {

    /* `ele` is an orphan tree root so it does not have a parent. Now,
       having received a shred for ele, we know ele's parent
       slot. Here we check whether ele's parent is already in the tree.
       If it is, then the orphan tree rooted at ele can be linked to the
       tree containing ele's parent (which may be another orphan tree or
       the canonical tree). */

    fd_forest_ele_t * parent = query( forest, parent_slot, UINT_MAX ); /* sentinel for parent, may not exist */
    if( FD_UNLIKELY( !parent ) ) {
      parent = acquire( forest, parent_slot, UINT_MAX );
      fd_forest_orphaned_ele_insert( fd_forest_orphaned( forest ), parent, pool ); /* update orphan root */
    }
    fd_forest_orphaned_ele_remove( fd_forest_orphaned( forest ), &ele->key, NULL, pool );
    fd_forest_ancestry_ele_insert( fd_forest_ancestry( forest ), ele, pool );
    link( forest, parent, ele );
  }

  fd_fec_shred_idxs_insert( ele->idxs, shred_idx - fec_set_idx );
  while( fd_fec_shred_idxs_test( ele->idxs, ele->buffered_idx + 1U ) ) ele->buffered_idx++;
  advance_frontier( forest, slot, fec_set_idx );
  return ele;
}

fd_forest_ele_t const *
fd_forest_publish( fd_forest_t * forest, ulong new_root_slot ) {
  FD_LOG_DEBUG(( "[%s] slot %lu", __func__, new_root_slot ));

  VER_INC;

  fd_forest_ancestry_t * ancestry = fd_forest_ancestry( forest );
  fd_forest_frontier_t * frontier = fd_forest_frontier( forest );
  fd_forest_orphaned_t * orphaned = fd_forest_orphaned( forest );
  fd_forest_ele_t *      pool     = fd_forest_pool( forest );
  ulong                  null     = fd_forest_pool_idx_null( pool );
  ulong *                queue    = fd_forest_deque( forest );

  fd_forest_ele_t * old_root_ele = fd_forest_pool_ele( pool, forest->root );
  fd_forest_ele_t * new_root_ele = query( forest, new_root_slot, 0 );

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
    new_root_ele = acquire( forest, new_root_slot, UINT_MAX );
    fd_forest_frontier_ele_insert( frontier, new_root_ele, pool );
  }

  /* First, remove the previous root, and add it to a FIFO prune queue.
     head points to the queue head (initialized with old_root_ele). */
# if FD_FOREST_USE_HANDHOLDING
  FD_TEST( fd_forest_deque_cnt( queue ) == 0 );
# endif
  fd_forest_ele_t * head = ancestry_frontier_remove( forest, old_root_ele->slot, old_root_ele->fec_set_idx );
  if( FD_LIKELY( head ) ) fd_forest_deque_push_tail( queue, fd_forest_pool_idx( pool, head ) );

  /* Second, BFS down the tree, inserting each ele into the prune queue
     except for the new root.  Loop invariant: head always descends from
     old_root_ele and never descends from new_root_ele. */

  while( FD_LIKELY( fd_forest_deque_cnt( queue ) ) ) {
    head = fd_forest_pool_ele( pool, fd_forest_deque_pop_head( queue ) );
    fd_forest_ele_t * child = fd_forest_pool_ele( pool, head->child );
    while( FD_LIKELY( child ) ) {
      if( FD_LIKELY( child != new_root_ele ) ) { /* do not prune new root or descendants */
        ulong idx = fd_forest_ancestry_idx_remove( ancestry, &child->key, null, pool );
        idx       = fd_ulong_if( idx != null, idx, fd_forest_frontier_idx_remove( frontier, &child->slot, null, pool ) );
        fd_forest_deque_push_tail( queue, idx );
      }
      child = fd_forest_pool_ele( pool, child->sibling );
    }
    fd_forest_pool_ele_release( pool, head );
  }

  /* If there is nothing on the frontier, we have hit an edge case
     during catching up where all of our frontiers were < the new root.
     In that case we need to continue repairing from the new root, so
     add it to the frontier. */

  if( FD_UNLIKELY( fd_forest_frontier_iter_done( fd_forest_frontier_iter_init( frontier, pool ), frontier, pool ) ) ) {
    __asm__("int $3");
    FD_LOG_ERR( ("not implemented") );
    fd_forest_ele_t * remove = fd_forest_ancestry_ele_remove( ancestry, &new_root_ele->slot, NULL, pool );
    if( FD_UNLIKELY( !remove ) ) {
      /* Very rare case where during second incremental load we could publish to an orphaned slot */
      remove = fd_forest_orphaned_ele_remove( orphaned, &new_root_ele->slot, NULL, pool );
    }
    FD_TEST( remove == new_root_ele );
    fd_forest_frontier_ele_insert( frontier, new_root_ele, pool );
    new_root_ele->data_cnt = FD_REEDSOL_DATA_SHREDS_MAX;
    new_root_ele->buffered_idx = FD_REEDSOL_DATA_SHREDS_MAX - 1;
    advance_frontier( forest, new_root_ele->slot, 0 );
  }

  new_root_ele->parent = null; /* unlink new root from parent */
  forest->root         = fd_forest_pool_idx( pool, new_root_ele );

  /* Lastly, cleanup orphans if there orphan heads < new_root_slot.
     First, add any relevant orphans to the prune queue. */

  for( fd_forest_orphaned_iter_t iter = fd_forest_orphaned_iter_init( orphaned, pool );
       !fd_forest_orphaned_iter_done( iter, orphaned, pool );
       iter = fd_forest_orphaned_iter_next( iter, orphaned, pool ) ) {
    fd_forest_ele_t * ele = fd_forest_orphaned_iter_ele( iter, orphaned, pool );
    if( FD_UNLIKELY( ele->slot < new_root_slot ) ) {
      fd_forest_deque_push_tail( queue, fd_forest_pool_idx( pool, ele ) );
    }
  }

  /* Now BFS and clean up children of these orphan heads */
  while( FD_UNLIKELY( fd_forest_deque_cnt( queue ) ) ) {
    head = fd_forest_pool_ele( pool, fd_forest_deque_pop_head( queue ) );
    fd_forest_ele_t * child = fd_forest_pool_ele( pool, head->child );
    while( FD_LIKELY( child ) ) {
      if( FD_LIKELY( child != new_root_ele ) ) {
        fd_forest_deque_push_tail( queue, fd_forest_pool_idx( pool, child ) );
      }
      child = fd_forest_pool_ele( pool, child->sibling );
    }
    ulong remove = fd_forest_orphaned_idx_remove( orphaned, &head->key, null, pool ); /* remove myself */
    remove = fd_ulong_if( remove == null, fd_forest_ancestry_idx_remove( ancestry, &head->key, null, pool ), remove );
    fd_forest_pool_ele_release( pool, head ); /* free head */
  }
  return new_root_ele;
}

static inline uint FD_FN_PURE
complete_idx( fd_forest_t const * forest, fd_forest_ele_t const * ele ) {
  fd_forest_ele_t const * pool = fd_forest_pool_const( forest );
  fd_forest_ele_t const * last = fd_forest_query_const( forest, ele->slot, UINT_MAX );
  if( FD_UNLIKELY( last ) ) { last = fd_forest_pool_ele_const( pool, last->parent ); }
  return last && last->data_cnt != UINT_MAX ? last->fec_set_idx + last->data_cnt - 1 : UINT_MAX;
}

fd_forest_iter_t
fd_forest_iter_init( fd_forest_t * forest ) {
  /* Find first element. Anything on the frontier. */
  fd_forest_ele_t      const * pool     = fd_forest_pool_const( forest );
  fd_forest_frontier_t const * frontier = fd_forest_frontier_const( forest );

  fd_forest_frontier_iter_t frontier_iter = fd_forest_frontier_iter_init( frontier, pool );
  fd_forest_iter_t          repair_iter   = { fd_forest_pool_idx_null( pool ),
                                              UINT_MAX,
                                              fd_fseq_query( fd_forest_ver_const( forest ) ),
                                              frontier_iter };
  /* Nothing on frontier */

  if( FD_UNLIKELY( fd_forest_frontier_iter_done( frontier_iter, frontier, pool ) ) ) return repair_iter;

  /* Populate initial iter shred index */

  fd_forest_ele_t const * ele = fd_forest_frontier_iter_ele_const( frontier_iter, frontier, pool );
  while( ele->data_cnt != UINT_MAX && ele->buffered_idx == ele->data_cnt - 1 ) {
    /* This fork frontier is actually complete, so we can skip it. Also
       handles edge case where we are calling iter_init right after a
       forest_init */
    frontier_iter = fd_forest_frontier_iter_next( frontier_iter, frontier, pool );
    if( FD_UNLIKELY( fd_forest_frontier_iter_done( frontier_iter, frontier, pool ) ) ) {
      repair_iter.ele_idx   = fd_forest_pool_idx_null( pool );
      repair_iter.shred_idx = UINT_MAX; /* no more elements */
      return repair_iter;
    }
    ele = fd_forest_frontier_iter_ele_const( frontier_iter, frontier, pool );
  }

  repair_iter.ele_idx   = frontier_iter.ele_idx;
  repair_iter.shred_idx = complete_idx( forest, ele ) != UINT_MAX ? ele->fec_set_idx + ele->buffered_idx + 1 : UINT_MAX;
 /* FIX ME iterator by fec not slot*/
  return repair_iter;
}

fd_forest_iter_t
fd_forest_iter_next( fd_forest_iter_t iter, fd_forest_t const * forest ) {
  fd_forest_frontier_t const * frontier = fd_forest_frontier_const( forest );
  fd_forest_ele_t const      * pool     = fd_forest_pool_const( forest );
  fd_forest_ele_t const      * ele      = fd_forest_pool_ele_const( pool, iter.ele_idx );

  if( iter.frontier_ver != fd_fseq_query( fd_forest_ver_const( forest ) ) ) {
    /* If the frontier has changed since we started this traversal, we
       need to reset the iterator. */
    iter.ele_idx   = fd_forest_pool_idx_null( pool ) ;
    iter.shred_idx = UINT_MAX; /* no more elements */
    return iter;
  }

  uint next_shred_idx = iter.shred_idx; /* Universal shred index across entire slot */
  for(;;) {
    next_shred_idx++;

    /* Case 1: No more shreds in this slot to request, move to the
       next one. Wraparound the shred_idx.

       Case 2: original iter.shred_idx == UINT_MAX (implies prev req
       was a highest_window_idx request). Also requires moving to next
       slot and wrapping the shred_idx. */

    if( FD_UNLIKELY( next_shred_idx >= complete_idx( forest, ele ) || iter.shred_idx == UINT_MAX ) ) {
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
          iter.head = fd_forest_frontier_iter_next( iter.head, frontier, pool );
          if( FD_UNLIKELY( !fd_forest_frontier_iter_done( iter.head, frontier, pool ) ) ) {
            iter.ele_idx = iter.head.ele_idx;
            ele          = fd_forest_pool_ele_const( pool, iter.head.ele_idx );
            iter.shred_idx = complete_idx( forest, ele ) != UINT_MAX ? ele->fec_set_idx + ele->buffered_idx + 1 : UINT_MAX;
          }
        }
        return iter;
      }
      next_shred_idx = ele->fec_set_idx + ele->buffered_idx + 1;
    }

    /* Common case - valid shred to request. Note you can't know the
       ele->complete_idx until you have actually recieved the slot
       complete shred, thus the we can do lt instead of leq  */
    uint cmpl_idx = complete_idx( forest, ele );
    if( cmpl_idx != UINT_MAX &&
        next_shred_idx < cmpl_idx &&
        !fd_fec_shred_idxs_test( ele->idxs, next_shred_idx ) ) {
      iter.shred_idx = next_shred_idx;
      break;
    }

    /* Current slot actually needs a highest_window_idx request */

    if( FD_UNLIKELY( cmpl_idx == UINT_MAX ) ) {
      iter.shred_idx = UINT_MAX;
      break;
    }
  }
  return iter;
}

int
fd_forest_iter_done( fd_forest_iter_t iter, fd_forest_t const * forest ) {
  fd_forest_ele_t const * pool = fd_forest_pool_const( forest );
  return iter.ele_idx == fd_forest_pool_idx_null( pool ); /* no more elements */
}

#include <stdio.h>

static void
preorder( fd_forest_t const * forest, fd_forest_ele_t const * ele ) {
  fd_forest_ele_t const * pool  = fd_forest_pool_const( forest );
  fd_forest_ele_t const * child = fd_forest_pool_ele_const( pool, ele->child );
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
simple_bfs_print( fd_forest_t const * forest, fd_forest_ele_t const * ele ) {
  fd_forest_ele_t const * pool = fd_forest_pool_const( forest );
  fd_forest_ele_t const * child = fd_forest_pool_ele_const( pool, ele->child );
  if( ele->fec_set_idx == UINT_MAX ) {
    printf( "(%lu, END) ", ele->slot );
  } else {
    printf( "(%lu, %u) ", ele->slot, ele->fec_set_idx );
  }
  while( FD_LIKELY( child ) ) {
    simple_bfs_print( forest, child );
    child = fd_forest_pool_ele_const( pool, child->sibling );
  }
}

static void
ancestry_print( fd_forest_t const * forest, fd_forest_ele_t const * ele, int space, const char * prefix, fd_forest_ele_t const * prev, int elide ) {
  fd_forest_ele_t const * pool = fd_forest_pool_const( forest );

  if( ele == NULL ) return;

  /* print the slot itself. either we might need to start a new interval, or it may get elided */
  fd_forest_ele_t const * child = fd_forest_pool_ele_const( pool, ele->child );

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
      child->slot > ele->slot + 1 ) { // if I have ONE CHILD and one child is non-consecutive

    if( elide ) {
      /* current slot wasn't printed, but now that we are branching,
         we will want to print the current slot and close the bracket */
      printf( ", %lu]", ele->slot );
      space += fd_int_max( num_digits( ele->slot ) + 2, 0 );
    } else {
      printf( "]");
    }

    sprintf( new_prefix, "└── [" ); /* end branch */
    ancestry_print( forest, child, space + 5, new_prefix, prev, 0 );
  } else if ( one_child && child->slot <= ele->slot + 1 ) {
    ancestry_print( forest, child, space, prefix, prev, 1);
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
        ancestry_print( forest, child, space + 5, new_prefix, prev, 0 );
      } else {
        sprintf( new_prefix, "└── [" ); /* end branch */
        ancestry_print( forest, child, space + 5, new_prefix, prev, 0 );
      }
      child = fd_forest_pool_ele_const( pool, child->sibling );
    }
  }
}

void
fd_forest_ancestry_print( fd_forest_t const * forest ) {
  FD_LOG_NOTICE(("\n\n[Ancestry]\n\n" ) );

  ancestry_print( forest, fd_forest_pool_ele_const( fd_forest_pool_const( forest ), forest->root ), 0, "[", NULL, 0 );
}

void
fd_forest_frontier_print( fd_forest_t const * forest ) {
  printf( "\n\n[Frontier]\n" );
  fd_forest_ele_t const *      pool     = fd_forest_pool_const( forest );
  fd_forest_frontier_t const * frontier = fd_forest_frontier_const( forest );
  for( fd_forest_frontier_iter_t iter = fd_forest_frontier_iter_init( frontier, pool );
       !fd_forest_frontier_iter_done( iter, frontier, pool );
       iter = fd_forest_frontier_iter_next( iter, frontier, pool ) ) {
    fd_forest_ele_t const * ele = fd_forest_frontier_iter_ele_const( iter, frontier, pool );
    uint data_cnt = fd_uint_if( ele->data_cnt == UINT_MAX, 0, ele->data_cnt );
    if( ele->data_cnt == UINT_MAX ) {
      printf("%lu (%u/?)\n", ele->slot, ele->fec_set_idx + ele->buffered_idx + 1 );
    } else {
      printf("%lu (%u/%u)\n", ele->slot, ele->fec_set_idx + ele->buffered_idx + 1, ele->fec_set_idx + data_cnt - 1 );
    }
  }
}

void
fd_forest_orphaned_print( fd_forest_t const * forest ) {
  printf( "\n\n[Orphaned]\n" );
  fd_forest_orphaned_t const * orphaned = fd_forest_orphaned_const( forest );
  fd_forest_ele_t const * pool = fd_forest_pool_const( forest );
  for( fd_forest_orphaned_iter_t iter = fd_forest_orphaned_iter_init( orphaned, pool );
       !fd_forest_orphaned_iter_done( iter, orphaned, pool );
       iter = fd_forest_orphaned_iter_next( iter, orphaned, pool ) ) {
    fd_forest_ele_t const * ele = fd_forest_orphaned_iter_ele_const( iter, orphaned, pool );
    //ancestry_print( forest, fd_forest_pool_ele_const( fd_forest_pool_const( forest ), fd_forest_pool_idx( pool, ele ) ), 0, "[", NULL, 0 );
    simple_bfs_print( forest, ele );
    printf( "\n\n" );
  }
}

void
fd_forest_print( fd_forest_t const * forest ) {
  if( FD_UNLIKELY( forest->root == ULONG_MAX ) ) return;
  fd_forest_ancestry_print( forest );
  fd_forest_frontier_print( forest );
  fd_forest_orphaned_print( forest );
  FD_LOG_NOTICE(( "DONE PRINTING"));
  printf("\n\n");
}
