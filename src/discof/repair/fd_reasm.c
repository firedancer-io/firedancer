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
      q_align(),           q_footprint       ( fec_max ) ),
      q_align(),           q_footprint       ( fec_max ) ),
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
  void * bfs      = FD_SCRATCH_ALLOC_APPEND( l, q_align(),           q_footprint       ( fec_max ) );
  void * out      = FD_SCRATCH_ALLOC_APPEND( l, q_align(),           q_footprint       ( fec_max ) );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, fd_reasm_align() ) == (ulong)shmem + footprint );

  reasm->root     = pool_idx_null( pool );
  reasm->slot0    = ULONG_MAX;
  reasm->pool     = pool_new    ( pool,     fec_max       );
  reasm->ancestry = ancestry_new( ancestry, fec_max, seed );
  reasm->frontier = frontier_new( frontier, fec_max, seed );
  reasm->orphaned = orphaned_new( orphaned, fec_max, seed );
  reasm->subtrees = subtrees_new( subtrees, fec_max, seed );
  reasm->bfs      = q_new       ( bfs,      fec_max       );
  reasm->out      = q_new       ( out,      fec_max       );

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
  reasm->bfs      = q_join       ( reasm->bfs      );
  reasm->out      = q_join       ( reasm->out      );

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

void *
fd_reasm_fini( fd_reasm_t * reasm ) {
  return (void *)reasm;
}

FD_FN_PURE fd_reasm_fec_t *
fd_reasm_query( fd_reasm_t * reasm, fd_hash_t const * merkle_root ) {
  fd_reasm_fec_t * fec = NULL;
  fec =                  ancestry_ele_query( reasm->ancestry, merkle_root, NULL, reasm->pool );
  fec = fd_ptr_if( !fec, frontier_ele_query( reasm->frontier, merkle_root, NULL, reasm->pool ), fec );
  fec = fd_ptr_if( !fec, orphaned_ele_query( reasm->orphaned, merkle_root, NULL, reasm->pool ), fec );
  fec = fd_ptr_if( !fec, subtrees_ele_query( reasm->subtrees, merkle_root, NULL, reasm->pool ), fec );
  return fec;
}

// static fd_reasm_fec_t *
// remove( fd_reasm_t * reasm, fd_hash_t const * merkle_root ) {
//   fd_reasm_fec_t * fec = frontier_ele_remove( reasm->frontier, merkle_root, NULL, reasm->pool );
//   fec = fd_ptr_if( !fec, ancestry_ele_remove( reasm->ancestry, merkle_root, NULL, reasm->pool ), fec );
//   fec = fd_ptr_if( !fec, orphaned_ele_remove( reasm->orphaned, merkle_root, NULL, reasm->pool ), fec );
//   return fec;
// }

static void link( fd_reasm_t * reasm, fd_reasm_fec_t * parent, fd_reasm_fec_t * child ) {
  FD_LOG_NOTICE(( "parent (%lu, %u) child (%lu, %u)", parent->slot, parent->fec_set_idx, child->slot, child->fec_set_idx ));
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
  // FD_LOG_NOTICE(( "inserting %lu %u %u %d %d", slot, fec_set_idx, data_cnt, data_complete, slot_complete ));

  fd_reasm_fec_t * pool = reasm->pool;
  ulong            null = pool_idx_null( pool );

  ancestry_t * ancestry = reasm->ancestry;
  frontier_t * frontier = reasm->frontier;
  orphaned_t * orphaned = reasm->orphaned;
  subtrees_t * subtrees = reasm->subtrees;

  ulong * bfs = reasm->bfs;
  ulong * out = reasm->out;

# if FD_REASM_USE_HANDHOLDING
  FD_TEST( pool_free( pool ) );
  FD_TEST( !fd_reasm_query( reasm, merkle_root ) );
# endif

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

  /* When inserting into an empty tree, set this element as the root and
     add it to the frontier. */

  if( FD_UNLIKELY( reasm->root == null ) ) {
    reasm->root = pool_idx( pool, fec );
    frontier_ele_insert( frontier, fec, pool );
    return fec;
  }

  /* First, we search for the parent of this new FEC and link if found.
     The new FEC set may result in a new leaf or a new orphan tree root
     so we need to check that. */

  int              is_leaf = 0;
  int              is_root = 0;
  fd_reasm_fec_t * parent    = NULL;
  if(        FD_LIKELY( parent = ancestry_ele_query ( ancestry, &fec->cmr, NULL, pool ) ) ) { /* parent is connected non-leaf */
    frontier_ele_insert( frontier, fec,    pool );
    q_push_tail( out, pool_idx( pool, fec ) );
    is_leaf = 1;
  } else if( FD_LIKELY( parent = frontier_ele_remove( frontier, &fec->cmr, NULL, pool ) ) ) { /* parent is connected leaf    */
    ancestry_ele_insert( ancestry, parent, pool );
    frontier_ele_insert( frontier, fec,    pool );
    q_push_tail( out, pool_idx( pool, fec ) );
    is_leaf = 1;
  } else if( FD_LIKELY( parent = orphaned_ele_query ( orphaned, &fec->cmr, NULL, pool ) ) ) { /* parent is orphaned non-root */
    orphaned_ele_insert( orphaned, fec,    pool );
  } else if( FD_LIKELY( parent = subtrees_ele_query ( subtrees, &fec->cmr, NULL, pool ) ) ) { /* parent is orphaned root     */
    orphaned_ele_insert( orphaned, fec,    pool );
  } else {                                                                                    /* parent not found            */
    subtrees_ele_insert( subtrees, fec,    pool );
    is_root = 1;
  }

  if( FD_LIKELY( parent ) ) link( reasm, parent, fec );

  /* Second, we search for children of this new FEC and link them to it.
     By definition any children must be orphaned (a child cannot be part
     of a connected tree before its parent).  Therefore, we only search
     through the orphaned subtrees.  As part of this operation, we also
     coalesce connected orphans into the same tree.  This way we only
     need to search the orphan tree roots (vs. all orphaned nodes). */

  FD_TEST( q_empty(bfs) ); q_remove_all( bfs );
  for( subtrees_iter_t iter = subtrees_iter_init(       subtrees, pool );
                             !subtrees_iter_done( iter, subtrees, pool );
                       iter = subtrees_iter_next( iter, subtrees, pool ) ) {
    q_push_tail( bfs, subtrees_iter_idx( iter, subtrees, pool ) );
  }
  while( FD_LIKELY( !q_empty( bfs ) ) ) {
    fd_reasm_fec_t * orphan_root = pool_ele( reasm->pool, q_pop_head( bfs ) );
    if( FD_LIKELY( 0==memcmp( orphan_root->cmr.uc, fec->key.uc, sizeof(fd_hash_t) ) ) ) { /* this orphan_root is a direct child of fec */
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

  if( FD_LIKELY( is_leaf ) ) q_push_tail( bfs, pool_idx( pool, fec ) );
  while( FD_LIKELY( !q_empty( bfs ) ) ) {
    fd_reasm_fec_t * parent  = pool_ele( pool, q_pop_head( bfs ) );
    fd_reasm_fec_t * child = pool_ele( pool, parent->child );
    if( FD_LIKELY( child ) ) {
      frontier_ele_remove( frontier, &parent->key, NULL, pool );
      ancestry_ele_insert( ancestry, parent,             pool );
    }
    while( FD_LIKELY( child ) ) {
      subtrees_ele_remove( subtrees, &child->key, NULL, pool );
      orphaned_ele_remove( orphaned, &child->key, NULL, pool );
      frontier_ele_insert( frontier, child,             pool );
      q_push_tail( bfs, pool_idx( pool, child ) );
      q_push_tail( out, pool_idx( pool, child ) );
      child = pool_ele( pool, child->sibling );
    }
  }
  return fec;
}

fd_reasm_fec_t *
fd_reasm_out( fd_reasm_t * reasm ) {
  if( FD_UNLIKELY( q_empty( reasm->out ) ) ) return NULL;
  return pool_ele( reasm->pool, q_pop_head( reasm->out ) );
}

// void
// fd_reasm_publish( fd_reasm_t * reasm, ulong new_root_slot ) {
//   fd_reasm_fec_t * old_root = pool_ele( reasm->pool, reasm->root );
//   fd_reasm_fec_t * new_root = fd_reasm_query( reasm, new_root_slot, 0 );

//   FD_TEST( old_root );
//   if( FD_UNLIKELY( !new_root ) ) {
//     /* It is possible to not have a fec element for the new root during
//     second incremental snapshot load */

//     new_root = pool_ele_acquire( reasm->pool );
//     new_root->key           = new_root_slot << 32; /* fec_set_idx 0, similar to reasm_init */
//     new_root->slot          = new_root_slot;
//     new_root->fec_set_idx   = 0;
//     new_root->data_cnt      = 0;
//     new_root->data_complete = 1;
//     new_root->slot_complete = 1;
//     new_root->parent_off    = 0;
//     memset( new_root->chained_merkle_root, 0, FD_SHRED_MERKLE_ROOT_SZ );

//     parent_t * p = parents_insert( reasm->parents, new_root_slot << 32 | UINT_MAX );
//     p->parent_key       = new_root_slot << 32;

//     frontier_ele_insert( reasm->frontier, new_root, reasm->pool );
//   }

//   /* Prune children of the old root */

//   queue_push_tail( reasm->queue, old_root->key );

//   while( FD_LIKELY( !queue_empty( reasm->queue ) ) ) {
//     ulong key = queue_pop_head( reasm->queue );
//     fd_reasm_fec_t * ele = fd_reasm_query( reasm, key >> 32, (uint)key );
//     if( FD_UNLIKELY( !ele ) ) continue;

//     if( FD_UNLIKELY( ele->slot_complete ) ) {
//       children_t * fec_children = children_query( reasm->children, ele->slot, NULL );
//       if( FD_UNLIKELY( fec_children ) ) {
//         for( ulong off = fd_slot_child_offs_const_iter_init( fec_children->child_offs );
//             !fd_slot_child_offs_const_iter_done( off );
//             off = fd_slot_child_offs_const_iter_next( fec_children->child_offs, off ) ) {
//           ulong child_slot = ele->slot + off;

//           if( FD_UNLIKELY( child_slot == new_root_slot ) ) continue;

//           queue_push_tail( reasm->queue, child_slot << 32 | 0 );
//         }
//       }
//     } else {
//       ulong child_key = (ele->slot << 32) | (ele->key + ele->data_cnt);
//       queue_push_tail( reasm->queue, child_key );
//     }

//     /* Remove ele from the reasm. */

//     fd_reasm_fec_t * remove = fd_reasm_remove( reasm, ele->key );
//     FD_TEST( remove == ele );
//   }

//   /* Update the root_fec */

//   reasm->root = pool_idx( reasm->pool, new_root );
// }
