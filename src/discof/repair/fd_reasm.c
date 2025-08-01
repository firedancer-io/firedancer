#include "fd_reasm.h"
#include "fd_reasm_private.h"

FD_FN_CONST ulong
fd_reasm_align( void ) {
  return alignof(fd_reasm_t);
}

ulong
fd_reasm_footprint( ulong fec_max ) {
  return FD_LAYOUT_FINI(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_INIT,
      alignof(fd_reasm_t), sizeof(fd_reasm_t)            ),
      pool_align(),        pool_footprint    ( fec_max ) ),
      ancestry_align(),    ancestry_footprint( fec_max ) ),
      frontier_align(),    frontier_footprint( fec_max ) ),
      orphaned_align(),    orphaned_footprint( fec_max ) ),
      subtrees_align(),    subtrees_footprint( fec_max ) ),
      bfs_align(),         bfs_footprint     ( fec_max ) ),
      out_align(),         out_footprint     ( fec_max ) ),
    fd_reasm_align() );
}

void *
fd_reasm_new( void * shmem, ulong fec_max, ulong seed ) {

  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_reasm_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  ulong footprint = fd_reasm_footprint( fec_max );
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

  fd_reasm_t * reasm;
  FD_SCRATCH_ALLOC_INIT( l, shmem );
  reasm           = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_reasm_t), sizeof(fd_reasm_t)            );
  void * pool     = FD_SCRATCH_ALLOC_APPEND( l, pool_align(),        pool_footprint    ( fec_max ) );
  void * ancestry = FD_SCRATCH_ALLOC_APPEND( l, ancestry_align(),    ancestry_footprint( fec_max ) );
  void * frontier = FD_SCRATCH_ALLOC_APPEND( l, frontier_align(),    frontier_footprint( fec_max ) );
  void * orphaned = FD_SCRATCH_ALLOC_APPEND( l, orphaned_align(),    orphaned_footprint( fec_max ) );
  void * subtrees = FD_SCRATCH_ALLOC_APPEND( l, subtrees_align(),    subtrees_footprint( fec_max ) );
  void * bfs      = FD_SCRATCH_ALLOC_APPEND( l, bfs_align(),         bfs_footprint     ( fec_max ) );
  void * out      = FD_SCRATCH_ALLOC_APPEND( l, out_align(),         out_footprint     ( fec_max ) );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, fd_reasm_align() ) == (ulong)shmem + footprint );

  reasm->root     = pool_idx_null( pool );
  reasm->pool     = pool_new     ( pool,     fec_max       );
  reasm->ancestry = ancestry_new ( ancestry, fec_max, seed );
  reasm->frontier = frontier_new ( frontier, fec_max, seed );
  reasm->orphaned = orphaned_new ( orphaned, fec_max, seed );
  reasm->subtrees = subtrees_new ( subtrees, fec_max, seed );
  reasm->bfs      = bfs_new      ( bfs,      fec_max       );
  reasm->out      = out_new      ( out,      fec_max       );

  return shmem;
}

fd_reasm_t *
fd_reasm_join( void * shreasm ) {
  fd_reasm_t * reasm = (fd_reasm_t *)shreasm;

  if( FD_UNLIKELY( !reasm ) ) {
    FD_LOG_WARNING(( "NULL reasm" ));
    return NULL;
  }

  reasm->pool     = pool_join    ( reasm->pool     );
  reasm->ancestry = ancestry_join( reasm->ancestry );
  reasm->frontier = frontier_join( reasm->frontier );
  reasm->orphaned = orphaned_join( reasm->orphaned );
  reasm->subtrees = subtrees_join( reasm->subtrees );
  reasm->bfs      = bfs_join     ( reasm->bfs      );
  reasm->out      = out_join     ( reasm->out      );

  return reasm;
}

void *
fd_reasm_leave( fd_reasm_t * reasm ) {

  if( FD_UNLIKELY( !reasm ) ) {
    FD_LOG_WARNING(( "NULL reasm" ));
    return NULL;
  }

  return (void *)reasm;
}

void *
fd_reasm_delete( void * shreasm ) {
  fd_reasm_t * reasm = (fd_reasm_t *)shreasm;

  if( FD_UNLIKELY( !reasm ) ) {
    FD_LOG_WARNING(( "NULL reasm" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned((ulong)reasm, fd_reasm_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned reasm" ));
    return NULL;
  }

  return reasm;
}

fd_reasm_t *
fd_reasm_init( fd_reasm_t * reasm, fd_hash_t const * merkle_root, ulong slot ) {
# if FD_REASM_USE_HANDHOLDING
  FD_TEST( pool_free( reasm->pool )==pool_max( reasm->pool ) );
  FD_TEST( reasm->root==pool_idx_null( reasm->pool )         );
# endif

  fd_reasm_fec_t * pool = reasm->pool;
  ulong            null = pool_idx_null( pool );

  fd_reasm_fec_t * fec = pool_ele_acquire( pool );
  fec->key             = *merkle_root;
  fec->cmr             = *merkle_root; /* chains to itself */
  fec->next            = null;
  fec->parent          = null;
  fec->child           = null;
  fec->sibling         = null;
  fec->slot            = slot;
  fec->parent_off      = 0;
  fec->fec_set_idx     = 0;
  fec->data_cnt        = 0;
  fec->data_complete   = 0;
  fec->slot_complete   = 0;

  /* Set this dummy FEC as the root and add it to the frontier. */

  reasm->root  = pool_idx( pool, fec );
  reasm->slot0 = slot;
  frontier_ele_insert( reasm->frontier, fec, pool );

  return reasm;
}

fd_reasm_fec_t *
fd_reasm_next( fd_reasm_t * reasm ) {
  if( FD_UNLIKELY( out_empty( reasm->out ) ) ) return NULL;
  return pool_ele( reasm->pool, out_pop_head( reasm->out ) );
}

fd_reasm_fec_t *
fd_reasm_root( fd_reasm_t * reasm ) {
  return pool_ele( reasm->pool, reasm->root );
}

ulong
fd_reasm_slot0( fd_reasm_t * reasm ) {
  return reasm->slot0;
}

fd_reasm_fec_t *
fd_reasm_query( fd_reasm_t * reasm,
                fd_hash_t const * merkle_root ) {
  fd_reasm_fec_t * fec = NULL;
  fec =                  ancestry_ele_query( reasm->ancestry, merkle_root, NULL, reasm->pool );
  fec = fd_ptr_if( !fec, frontier_ele_query( reasm->frontier, merkle_root, NULL, reasm->pool ), fec );
  fec = fd_ptr_if( !fec, orphaned_ele_query( reasm->orphaned, merkle_root, NULL, reasm->pool ), fec );
  fec = fd_ptr_if( !fec, subtrees_ele_query( reasm->subtrees, merkle_root, NULL, reasm->pool ), fec );
  return fec;
}

static void
link( fd_reasm_t     * reasm,
      fd_reasm_fec_t * parent,
      fd_reasm_fec_t * child ) {
  child->parent = pool_idx( reasm->pool, parent );
  if( FD_LIKELY( parent->child == pool_idx_null( reasm->pool ) ) ) {
    parent->child = pool_idx( reasm->pool, child ); /* set as left-child. */
  } else {
    fd_reasm_fec_t * curr = pool_ele( reasm->pool, parent->child );
    while( curr->sibling != pool_idx_null( reasm->pool ) ) curr = pool_ele( reasm->pool, curr->sibling );
    curr->sibling = pool_idx( reasm->pool, child ); /* set as right-sibling. */
  }
}

fd_reasm_fec_t *
fd_reasm_insert( fd_reasm_t *      reasm,
                 fd_hash_t const * merkle_root,
                 fd_hash_t const * chained_merkle_root,
                 ulong             slot,
                 uint              fec_set_idx,
                 ushort            parent_off,
                 ushort            data_cnt,
                 int               data_complete,
                 int               slot_complete ) {
  // FD_LOG_NOTICE(( "inserting %s %lu %u %u %d %d", FD_BASE58_ENC_32_ALLOCA( merkle_root ), slot, fec_set_idx, data_cnt, data_complete, slot_complete ));

# if FD_REASM_USE_HANDHOLDING
  FD_TEST( pool_free( reasm->pool ) );
  FD_TEST( !fd_reasm_query( reasm, merkle_root ) );
# endif

  fd_reasm_fec_t * pool = reasm->pool;
  ulong            null = pool_idx_null( pool );

  ancestry_t * ancestry = reasm->ancestry;
  frontier_t * frontier = reasm->frontier;
  orphaned_t * orphaned = reasm->orphaned;
  subtrees_t * subtrees = reasm->subtrees;

  ulong * bfs = reasm->bfs;
  ulong * out = reasm->out;

  fd_reasm_fec_t * fec = pool_ele_acquire( pool );
  fec->key             = *merkle_root;
  fec->cmr             = *chained_merkle_root;
  fec->next            = null;
  fec->parent          = null;
  fec->child           = null;
  fec->sibling         = null;
  fec->slot            = slot;
  fec->parent_off      = parent_off;
  fec->fec_set_idx     = fec_set_idx;
  fec->data_cnt        = data_cnt;
  fec->data_complete   = data_complete;
  fec->slot_complete   = slot_complete;

  /* First, we search for the parent of this new FEC and link if found.
     The new FEC set may result in a new leaf or a new orphan tree root
     so we need to check that. */

  int              is_leaf = 0;
  int              is_root = 0;
  fd_reasm_fec_t * parent    = NULL;
  if(        FD_LIKELY( parent = ancestry_ele_query ( ancestry, &fec->cmr, NULL, pool ) ) ) { /* parent is connected non-leaf */
    frontier_ele_insert( frontier, fec, pool );
    out_push_tail( out, pool_idx( pool, fec ) );
    is_leaf = 1;
  } else if( FD_LIKELY( parent = frontier_ele_remove( frontier, &fec->cmr, NULL, pool ) ) ) { /* parent is connected leaf    */
    ancestry_ele_insert( ancestry, parent, pool );
    frontier_ele_insert( frontier, fec,    pool );
    out_push_tail( out, pool_idx( pool, fec ) );
    is_leaf = 1;
  } else if( FD_LIKELY( parent = orphaned_ele_query ( orphaned, &fec->cmr, NULL, pool ) ) ) { /* parent is orphaned non-root */
    orphaned_ele_insert( orphaned, fec, pool );
  } else if( FD_LIKELY( parent = subtrees_ele_query ( subtrees, &fec->cmr, NULL, pool ) ) ) { /* parent is orphaned root     */
    orphaned_ele_insert( orphaned, fec, pool );
  } else {                                                                                    /* parent not found            */
    subtrees_ele_insert( subtrees, fec, pool );
    is_root = 1;
  }

  if( FD_LIKELY( parent ) ) link( reasm, parent, fec );

  /* Second, we search for children of this new FEC and link them to it.
     By definition any children must be orphaned (a child cannot be part
     of a connected tree before its parent).  Therefore, we only search
     through the orphaned subtrees.  As part of this operation, we also
     coalesce connected orphans into the same tree.  This way we only
     need to search the orphan tree roots (vs. all orphaned nodes). */

  FD_TEST( bfs_empty( bfs ) ); bfs_remove_all( bfs );
  for( subtrees_iter_t iter = subtrees_iter_init(       subtrees, pool );
                             !subtrees_iter_done( iter, subtrees, pool );
                       iter = subtrees_iter_next( iter, subtrees, pool ) ) {
    bfs_push_tail( bfs, subtrees_iter_idx( iter, subtrees, pool ) );
  }
  while( FD_LIKELY( !bfs_empty( bfs ) ) ) {
    fd_reasm_fec_t * orphan_root = pool_ele( reasm->pool, bfs_pop_head( bfs ) );
    if( FD_LIKELY( orphan_root && 0==memcmp( orphan_root->cmr.uc, fec->key.uc, sizeof(fd_hash_t) ) ) ) { /* this orphan_root is a direct child of fec */
      link( reasm, fec, orphan_root );
      if( FD_UNLIKELY( is_root ) ) { /* this is an orphan tree */
        subtrees_ele_remove( subtrees, &orphan_root->key, NULL, pool );
        orphaned_ele_insert( orphaned, orphan_root,             pool );
      }
    }
  }

  /* Third, we advance the frontier beginning from this FEC, if it was
     connected.  By definition if this FEC was connected then its parent
     is connected, so by induction this new FEC extends the frontier.
     However, even though we have already inserted this new FEC into the
     frontier it is not necessarily a leaf, as it may have connected to
     orphaned children.  So we BFS the from the new FEC outward until we
     reach the leaves. */

  if( FD_LIKELY( is_leaf ) ) bfs_push_tail( bfs, pool_idx( pool, fec ) );
  while( FD_LIKELY( !bfs_empty( bfs ) ) ) {
    fd_reasm_fec_t * parent  = pool_ele( pool, bfs_pop_head( bfs ) );
    fd_reasm_fec_t * child = pool_ele( pool, parent->child );
    if( FD_LIKELY( child ) ) {
      frontier_ele_remove( frontier, &parent->key, NULL, pool );
      ancestry_ele_insert( ancestry, parent,             pool );
    }
    while( FD_LIKELY( child ) ) {
      subtrees_ele_remove( subtrees, &child->key, NULL, pool );
      orphaned_ele_remove( orphaned, &child->key, NULL, pool );
      frontier_ele_insert( frontier, child,             pool );
      bfs_push_tail( bfs, pool_idx( pool, child ) );
      out_push_tail( out, pool_idx( pool, child ) );
      child = pool_ele( pool, child->sibling );
    }
  }
  return fec;
}

static fd_reasm_fec_t *
maps_remove( fd_reasm_t * reasm,
             fd_hash_t const * merkle_root ) {
  fd_reasm_fec_t * fec = frontier_ele_remove( reasm->frontier, merkle_root, NULL, reasm->pool );
  fec = fd_ptr_if( !fec, ancestry_ele_remove( reasm->ancestry, merkle_root, NULL, reasm->pool ), fec );
  fec = fd_ptr_if( !fec, orphaned_ele_remove( reasm->orphaned, merkle_root, NULL, reasm->pool ), fec );
  fec = fd_ptr_if( !fec, subtrees_ele_remove( reasm->subtrees, merkle_root, NULL, reasm->pool ), fec );
  return fec;
}

fd_reasm_fec_t *
fd_reasm_publish( fd_reasm_t * reasm, fd_hash_t const * merkle_root ) {
# if FD_REASM_USE_HANDHOLDING
  if( FD_UNLIKELY( !pool_ele( reasm->pool, reasm->root ) ) ) { FD_LOG_WARNING(( "missing root"                                                     )); return NULL; }
  if( FD_UNLIKELY( !pool_ele( reasm->pool, reasm->root ) ) ) { FD_LOG_WARNING(( "merkle root %s not found", FD_BASE58_ENC_32_ALLOCA( merkle_root ) )); return NULL; }
# endif

  fd_reasm_fec_t *  pool = reasm->pool;
  ulong             null = pool_idx_null( pool );
  fd_reasm_fec_t  * oldr = pool_ele( pool, reasm->root );
  fd_reasm_fec_t  * newr = pool_ele( pool, reasm->root );

  /* First, remove the previous root, and push it as the first element
     of the BFS queue. */

  fd_reasm_fec_t * head = maps_remove( reasm, &oldr->key ); /* initialize BFS queue */
  head->next            = null;                             /* clear map next */
  fd_reasm_fec_t * tail = head;                             /* tail of BFS queue */

  /* Second, BFS down the tree, pruning all of root's ancestors and also
     any descendants of those ancestors. */

  while( FD_LIKELY( head ) ) {
    fd_reasm_fec_t * child = pool_ele( pool, head->child );               /* left-child */
    while( FD_LIKELY( child ) ) {                                         /* iterate over children */
      if( FD_LIKELY( child != newr ) ) {                                  /* stop at new root */
        tail->next = pool_idx( pool, maps_remove( reasm, &child->key ) ); /* remove node from map to reuse `.next` */
        tail       = pool_ele( pool, tail->next );                        /* push onto BFS queue (so descendants can be pruned) */
        tail->next = null;                                                /* clear map next */
      }
      child = pool_ele( pool, child->sibling );                           /* right-sibling */
    }
    fd_reasm_fec_t * next = pool_ele( pool, head->next ); /* pophead */
    pool_ele_release( pool, head );                       /* release */
    head = next;                                          /* advance */
  }
  newr->parent = null;                   /* unlink old root */
  reasm->root  = pool_idx( pool, newr ); /* replace with new root */
  return newr;
}
