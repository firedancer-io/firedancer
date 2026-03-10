#include "fd_reasm.h"
#include "fd_reasm_private.h"
#include "../../ballet/shred/fd_shred.h"

#define LOGGING 0

FD_FN_CONST ulong
fd_reasm_align( void ) {
  return alignof(fd_reasm_t);
}

FD_FN_CONST ulong
fd_reasm_footprint( ulong fec_max ) {
  ulong max_fec_per_slot = FD_SHRED_BLK_MAX / 32;                             /* untrue until fix-32. TODO probably replace with macro after fix-32 is active */
  ulong max_slots        = fd_ulong_max(fec_max / max_fec_per_slot, 1UL);     /* add capacity for a block id per slot */
  int lgf_max = fd_ulong_find_msb( fd_ulong_pow2_up( fec_max + max_slots ) ); /* capacity for fec_max fecs + (fec_max / 1024) more block ids */
  return FD_LAYOUT_FINI(
    FD_LAYOUT_APPEND(
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
      xid_align(),         xid_footprint     ( lgf_max ) ),
    fd_reasm_align() );
}

void *
fd_reasm_new( void * shmem,
              ulong  fec_max,
              ulong  seed ) {

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

  ulong max_fec_per_slot = FD_SHRED_BLK_MAX / 32;                             /* untrue until fix-32. TODO probably replace with macro after fix-32 is active */
  ulong max_slots        = fd_ulong_max(fec_max / max_fec_per_slot, 1UL);     /* add capacity for a block id per slot */
  int   lgf_max = fd_ulong_find_msb( fd_ulong_pow2_up( fec_max + max_slots ) ); /* capacity for fec_max fecs + (fec_max / 1024) more block ids */

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
  void * xid      = FD_SCRATCH_ALLOC_APPEND( l, xid_align(),         xid_footprint     ( lgf_max ) );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, fd_reasm_align() ) == (ulong)shmem + footprint );

  reasm->slot0      = ULONG_MAX;
  reasm->root       = pool_idx_null( pool );
  reasm->pool_gaddr = fd_wksp_gaddr_fast( wksp, pool_join( pool_new( pool, fec_max ) ) );
  reasm->ancestry   = ancestry_new( ancestry, fec_max, seed );
  reasm->frontier   = frontier_new( frontier, fec_max, seed );
  reasm->orphaned   = orphaned_new( orphaned, fec_max, seed );
  reasm->subtrees   = subtrees_new( subtrees, fec_max, seed );
  /*               */ dlist_new   ( reasm->_subtrlf         );
  reasm->bfs        = bfs_new     ( bfs,      fec_max       );
  reasm->out        = out_new     ( out,      fec_max       );
  reasm->xid        = xid_new     ( xid,      lgf_max, seed );

  return shmem;
}

fd_reasm_t *
fd_reasm_join( void * shreasm ) {
  fd_reasm_t * reasm = (fd_reasm_t *)shreasm;

  if( FD_UNLIKELY( !reasm ) ) {
    FD_LOG_WARNING(( "NULL reasm" ));
    return NULL;
  }
  /* pool join handled in fd_reasm_new */
  reasm->ancestry = ancestry_join( reasm->ancestry );
  reasm->frontier = frontier_join( reasm->frontier );
  reasm->orphaned = orphaned_join( reasm->orphaned );
  reasm->subtrees = subtrees_join( reasm->subtrees );
  reasm->subtreel = dlist_join   ( reasm->_subtrlf );
  reasm->bfs      = bfs_join     ( reasm->bfs      );
  reasm->out      = out_join     ( reasm->out      );
  reasm->xid      = xid_join     ( reasm->xid      );

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

fd_reasm_fec_t       * fd_reasm_root         ( fd_reasm_t       * reasm                                 ) { return pool_ele      ( reasm_pool      ( reasm ), reasm->root      ); }
fd_reasm_fec_t const * fd_reasm_root_const   ( fd_reasm_t const * reasm                                 ) { return pool_ele_const( reasm_pool_const( reasm ), reasm->root      ); }
fd_reasm_fec_t       * fd_reasm_parent       ( fd_reasm_t       * reasm, fd_reasm_fec_t       * child   ) { return pool_ele      ( reasm_pool      ( reasm ), child->parent    ); }
fd_reasm_fec_t const * fd_reasm_parent_const ( fd_reasm_t const * reasm, fd_reasm_fec_t const * child   ) { return pool_ele_const( reasm_pool_const( reasm ), child->parent    ); }
fd_reasm_fec_t       * fd_reasm_child        ( fd_reasm_t       * reasm, fd_reasm_fec_t       * parent  ) { return pool_ele      ( reasm_pool      ( reasm ), parent->child    ); }
fd_reasm_fec_t const * fd_reasm_child_const  ( fd_reasm_t const * reasm, fd_reasm_fec_t const * parent  ) { return pool_ele_const( reasm_pool_const( reasm ), parent->child    ); }
fd_reasm_fec_t       * fd_reasm_sibling      ( fd_reasm_t       * reasm, fd_reasm_fec_t       * sibling ) { return pool_ele      ( reasm_pool      ( reasm ), sibling->sibling ); }
fd_reasm_fec_t const * fd_reasm_sibling_const( fd_reasm_t const * reasm, fd_reasm_fec_t const * sibling ) { return pool_ele_const( reasm_pool_const( reasm ), sibling->sibling ); }

ulong
fd_reasm_slot0( fd_reasm_t * reasm ) {
  return reasm->slot0;
}

ulong
fd_reasm_free( fd_reasm_t * reasm ) {
  return pool_free( reasm_pool( reasm ) );
}

fd_reasm_fec_t *
fd_reasm_peek( fd_reasm_t * reasm ) {
  for( out_iter_t iter = out_iter_init( reasm->out       );
                        !out_iter_done( reasm->out, iter );
                  iter = out_iter_next( reasm->out, iter ) ) {
    fd_hash_t * mr = out_iter_ele( reasm->out, iter );
    fd_reasm_fec_t * fec = fd_reasm_query( reasm, mr );
    if( FD_LIKELY( fec && !fec->popped && ( !fec->eqvoc || fec->confirmed ) ) ) return fec;
  }
  return NULL;
}

fd_reasm_fec_t *
fd_reasm_pop( fd_reasm_t * reasm ) {
  while( FD_LIKELY( !out_empty( reasm->out ) ) ) {
    fd_hash_t mr = out_pop_head( reasm->out );
    fd_reasm_fec_t * fec = fd_reasm_query( reasm, &mr );
    if( FD_LIKELY( fec && !fec->popped && ( !fec->eqvoc || fec->confirmed ) ) ) {
      fec->popped = 1;
      return fec;
    }
  }
  return NULL;
}

fd_reasm_fec_t *
fd_reasm_query( fd_reasm_t       * reasm,
                fd_hash_t  const * merkle_root ) {
  fd_reasm_fec_t * pool = reasm_pool( reasm );
  fd_reasm_fec_t * fec = NULL;
  fec =                  ancestry_ele_query( reasm->ancestry, merkle_root, NULL, pool );
  fec = fd_ptr_if( !fec, frontier_ele_query( reasm->frontier, merkle_root, NULL, pool ), fec );
  fec = fd_ptr_if( !fec, orphaned_ele_query( reasm->orphaned, merkle_root, NULL, pool ), fec );
  fec = fd_ptr_if( !fec, subtrees_ele_query( reasm->subtrees, merkle_root, NULL, pool ), fec );
  return fec;
}

void
fd_reasm_confirm( fd_reasm_t      * reasm,
                  fd_hash_t const * block_id ) {
  fd_reasm_fec_t * pool = reasm_pool( reasm );
  fd_reasm_fec_t * fec = ancestry_ele_query( reasm->ancestry, block_id, NULL, pool );
  fec = fd_ptr_if( !fec, frontier_ele_query( reasm->frontier, block_id, NULL, pool ), fec );

  /* TODO there is a potential optimization where we don't actually need
     to confirm every FEC and instead just confirm at the slot-level.
     Given roughly ~1k shreds per slot at 32 shreds per FEC, this would
     save ~32 loop iterations.  Punting given the additional complexity
     of bookkeeping and logic this would require. */

  while( FD_LIKELY( fec && !fec->confirmed ) ) {
    fec->confirmed = 1;

    xid_t * xid = xid_query( reasm->xid, (fec->slot << 32) | fec->fec_set_idx, NULL );
    xid->idx    = pool_idx( pool, fec );
    if( FD_UNLIKELY( fec->slot_complete ) ) {
      xid_t * bid = xid_query( reasm->xid, ( fec->slot << 32 ) | UINT_MAX, NULL );
      bid->idx    = pool_idx( pool, fec );
    }

    if( FD_LIKELY( !fec->popped ) ) out_push_head( reasm->out, fec->key );
    fec = fd_reasm_parent( reasm, fec );
  }
}

/* This is a gross case reasm needs to handle because Agave currently
    does not validate chained merkle roots across slots ie. if a leader
    sends a bad chained merkle root on a slot boundary, the cluster
    might converge on the leader's block anyways.  So we overwrite the
    chained merkle root based on the slot and parent_off metadata.
    There are two cases: 1. we receive the parent before the child.  In
    this case we just overwrite the child's CMR.  2. we receive the
    child before the parent.  In this case every time we receive a new
    FEC set we need to check the orphan roots for whether we can link
    the orphan to the new FEC via slot metadata, since the chained
    merkle root metadata on that orphan root might be wrong. */

static void
overwrite_invalid_cmr( fd_reasm_t     * reasm,
                       fd_reasm_fec_t * child ) {
  fd_reasm_fec_t * pool = reasm_pool( reasm );
  if( FD_UNLIKELY( child->fec_set_idx==0 && !fd_reasm_query( reasm, &child->cmr ) ) ) {
    xid_t * parent_bid = xid_query( reasm->xid, (child->slot - child->parent_off) << 32 | UINT_MAX, NULL );
    if( FD_LIKELY( parent_bid ) ) {
      fd_reasm_fec_t * parent = pool_ele( pool, parent_bid->idx );
      if( FD_LIKELY( parent ) ) {
        FD_BASE58_ENCODE_32_BYTES( child->cmr.key,  cmr_b58        );
        FD_BASE58_ENCODE_32_BYTES( parent->key.key, parent_key_b58 );
        FD_LOG_INFO(( "overwriting invalid cmr for FEC slot: %lu fec_set_idx: %u from %s (CMR) to %s (parent's block id)", child->slot, child->fec_set_idx, cmr_b58, parent_key_b58 ));
        child->cmr = parent->key; /* use the parent's merkle root */
      }
    }
  }
}

/* Mark the entire subtree beginning from root as equivocating.  This is
   linear in the number of descendants in the subtree, but amortizes
   because we can short-circuit the BFS at nodes that are already marked
   equivocating, so each node is visited at most once. */

static void
eqvoc( fd_reasm_t     * reasm,
       fd_reasm_fec_t * root ) {
  fd_reasm_fec_t * pool = reasm_pool( reasm );
  ulong *          bfs  = reasm->bfs;
  bfs_push_tail( bfs, pool_idx( pool, root ) );
  while( FD_LIKELY( !bfs_empty( bfs ) ) ) {
    fd_reasm_fec_t * descendant = pool_ele( pool, bfs_pop_head( bfs ) );
    if( FD_LIKELY( descendant->eqvoc ) ) continue;
    descendant->eqvoc      = 1;
    fd_reasm_fec_t * child = fd_reasm_child( reasm, descendant );
    while( FD_LIKELY( child ) ) {
      bfs_push_tail( bfs, pool_idx( pool, child ) );
      child = fd_reasm_sibling( reasm, child );
    }
  }
}

static void
link( fd_reasm_t     * reasm,
      fd_reasm_fec_t * parent,
      fd_reasm_fec_t * child ) {
  fd_reasm_fec_t * pool = reasm_pool( reasm );
  child->parent = pool_idx( pool, parent );
  if( FD_LIKELY( parent->child == pool_idx_null( pool ) ) ) {
    parent->child = pool_idx( pool, child ); /* set as left-child. */
  } else {
    fd_reasm_fec_t * sibling = pool_ele( pool, parent->child );
    while( FD_LIKELY( sibling->sibling != pool_idx_null( pool ) ) ) sibling = pool_ele( pool, sibling->sibling );
    sibling->sibling = pool_idx( pool, child ); /* set as right-sibling. */
  }
}

/* Assumes caller is de-duplicating FEC sets of the same merkle root. */
static xid_t *
xid_update( fd_reasm_t * reasm, ulong slot, uint fec_set_idx, ulong pool_idx ) {
  xid_t * xid = xid_query( reasm->xid, (slot << 32) | fec_set_idx, NULL );
  if( FD_UNLIKELY( xid ) ) {
    xid->cnt++;
  } else {
    xid = xid_insert( reasm->xid, (slot << 32) | fec_set_idx );
    if( FD_UNLIKELY( !xid ) ) FD_LOG_CRIT(( "xid map full, slot=%lu fec_set_idx=%u", slot, fec_set_idx )); // TODO remove after reasm eviction is implemented
    xid->idx = pool_idx;
    xid->cnt = 1;
  }
  return xid;
}

static fd_reasm_fec_t *
clear_slot_metadata( fd_reasm_t     * reasm,
                     fd_reasm_fec_t * fec ) {
  /* remove from bid and xid */
  if( FD_UNLIKELY( fec->slot_complete ) ) {
    xid_t * bid = xid_query( reasm->xid, (fec->slot << 32)|UINT_MAX, NULL );
    bid->cnt--;
    if( FD_LIKELY( !bid->cnt ) ) xid_remove( reasm->xid, bid );
  }
  xid_t * xid = xid_query( reasm->xid, ( fec->slot << 32 ) | fec->fec_set_idx, NULL );
  xid->cnt--;
  if( FD_LIKELY( !xid->cnt ) ) xid_remove( reasm->xid, xid );

  return fec;
}

void
fd_reasm_pool_release( fd_reasm_t *     reasm,
                       fd_reasm_fec_t * ele   ){
  pool_ele_release( reasm_pool( reasm ), ele );
}

fd_reasm_fec_t *
fd_reasm_remove( fd_reasm_t     * reasm,
                 fd_reasm_fec_t * head,
                 fd_store_t     * opt_store ) {
  /* see fd_forest.c clear_leaf */

  fd_reasm_fec_t *    pool     = reasm_pool( reasm );
  orphaned_t *        orphaned = reasm->orphaned;
  frontier_t *        frontier = reasm->frontier;
  ancestry_t *        ancestry = reasm->ancestry;
  subtrees_t *        subtrees = reasm->subtrees;
  dlist_t    *        subtreel = reasm->subtreel;

  FD_TEST( head && head->child == ULONG_MAX ); /* must be a leaf node */
  fd_reasm_fec_t * leaf = head;

  if( FD_UNLIKELY( frontier_ele_query( frontier, &leaf->key, NULL, pool ) ) ) {
  /* If the leaf is in the frontier, we could be removing something that
     has been executed.  Move the head pointer up to where we begin
     evicting.

     We search up the tree until the theoretical boundary of a bank.
     This is usually when we jump to a parent slot, but if an
     equivocation occured, this could also be the middle of the slot.

     0 ── 32 ──  64 ──  96          (confirmed)
            └──  64' ── 96' ── 128' (eqvoc)

      Note we only have execute a slot twice (have 2 bank idxs for it)
      if the slot equivocated, we replayed the wrong version, and then
      replayed the confirmed version afterwards.

      The state after executing the wrong version first is:

            0  ────  32 ────  64 ────  96 ──── 128
      (bank_idx=1) (bank_idx=1) .... (all bank_idx=1)

      After receiving and executing the confirmed version, the state looks like

      0 (b=2) ── 32 (b=2) ──  64  (b=2) ──  96  (b=2)               (confirmed)
                         └──  64' (b=1) ──  96' (b=1) ── 128' (b=1) (eqvoc)

      Here we want to evict only until fec 64'. Or let's say we are
      getting around to executing the confirmed version, but we haven't
      executed it yet.

      0 (b=1) ── 32 (b=1) ──  64  (b=ULONG_MAX) ── 96  (b=ULONG_MAX)           (confirmed, but not executed yet)
                         └──  64' (b=1)         ── 96' (b=1) ── 128'(b=1)      (eqvoc)

      Now we know we should evict until the max(parent has > 1 child, or fec set idx == 0) */

    while( FD_LIKELY( head ) ) {
      fd_reasm_fec_t * parent = fd_reasm_parent( reasm, head );
      if( FD_UNLIKELY( head->fec_set_idx==0  ) )                   break;
      if( FD_UNLIKELY( head->sibling != pool_idx_null( pool ) ) )  break; /* if the parent has more than 1 child, we know for sure the parent is a slot boundary or eqvoc point, so we can stop here. */
      if( FD_UNLIKELY( parent->slot_complete ) )                   break; /* specifically catches case where slot complete is in middle of slot. */
      head = parent;
    }
  }

  FD_LOG_INFO(( "evicting reasm slot %lu, fec idx %u, down to %u bank_idx %lu", head->slot, head->fec_set_idx, leaf->fec_set_idx, head->bank_idx ));

  fd_reasm_fec_t * parent = fd_reasm_parent( reasm, head );
  if( FD_LIKELY( parent ) ) {
   /* Clean up the parent pointing to this head, and remove block from the maps
      remove the block from the parent's child list */

    fd_reasm_fec_t * child = pool_ele( pool, parent->child );
    if( FD_LIKELY( 0==memcmp( &child->key, &head->key, sizeof(fd_hash_t) ) ) ) { /* evicted is left-child (or only child) */
      parent->child = child->sibling;
    } else {
      /* evicted is a right-sibling */
      fd_reasm_fec_t * sibling = pool_ele( pool, child->sibling );
      fd_reasm_fec_t * prev    = child;
      while( FD_LIKELY( sibling && memcmp( &sibling->key, &head->key, sizeof(fd_hash_t) ) ) ) {
        prev = sibling;
        sibling = pool_ele( pool, sibling->sibling );
      }
      prev->sibling = sibling->sibling;
    }

    /* remove the chain itself from the maps */

    fd_reasm_fec_t * removed_orphan = NULL;
    if( FD_LIKELY  ( removed_orphan = orphaned_ele_remove( orphaned, &head->key, NULL, pool ) ) ) {
      clear_slot_metadata( reasm, head );
      if( FD_LIKELY( opt_store ) ) fd_store_remove( opt_store, &head->key );
      return head;
    }

    /* remove from ancestry and frontier */
    fd_reasm_fec_t * curr = head;
    while( FD_LIKELY( curr ) ) {
      fd_reasm_fec_t * removed = ancestry_ele_remove( ancestry, &curr->key, NULL, pool );
      if( !removed )   removed = frontier_ele_remove( frontier, &curr->key, NULL, pool );

      curr = fd_reasm_child( reasm, curr );
      clear_slot_metadata( reasm, removed );
      if( FD_LIKELY( opt_store ) ) fd_store_remove( opt_store, &removed->key );
    }

    /* We removed from the main tree, so we might need to insert parent into the frontier.
        Only need to add parent to the frontier if it doesn't have any other children. */

    if( parent->child == pool_idx_null( pool ) ) {
      parent = ancestry_ele_remove( ancestry, &parent->key, NULL, pool );
      FD_TEST( parent );
      frontier_ele_insert( frontier, parent, pool );
    }
    return head;
  }

  /* No parent, remove from subtrees and subtree list */
  subtrees_ele_remove( subtrees, &head->key, NULL, pool );
  dlist_ele_remove   ( subtreel,  head,            pool );
  clear_slot_metadata( reasm, head );
  if( FD_LIKELY( opt_store ) ) fd_store_remove( opt_store, &head->key );
  return head;
}

fd_reasm_fec_t *
latest_confirmed_fec( fd_reasm_t * reasm,
                      ulong        subtree_root ) {
  ulong *          bfs  = reasm->bfs;
  fd_reasm_fec_t * pool = reasm_pool( reasm );
  bfs_push_tail( bfs, subtree_root );
  fd_reasm_fec_t * latest_confirmed = NULL;
  while( FD_LIKELY( !bfs_empty( bfs ) ) ) {
    fd_reasm_fec_t * ele = pool_ele( pool, bfs_pop_head( bfs ) );
    if( FD_LIKELY( ele->confirmed ) ) {
      if( FD_LIKELY( latest_confirmed == NULL ||
                     latest_confirmed->slot < ele->slot ||
                     (latest_confirmed->slot == ele->slot && latest_confirmed->fec_set_idx < ele->fec_set_idx)) )
        latest_confirmed = ele;
    }
    fd_reasm_fec_t * child = fd_reasm_child( reasm, ele );
    while( FD_LIKELY( child ) ) {
      bfs_push_tail( bfs, pool_idx( pool, child ) );
      child = pool_ele( pool, child->sibling );
    }
  }
  return latest_confirmed;
}

static fd_reasm_fec_t *
gca( fd_reasm_t     * reasm,
     fd_reasm_fec_t * a,
     fd_reasm_fec_t * b ) {
  fd_reasm_fec_t * parent1 = a;
  fd_reasm_fec_t * parent2 = b;
  while( FD_LIKELY( parent1 && parent2 ) ) {
    if( FD_LIKELY( parent1 == parent2 ) ) return parent1;
    if( parent1->slot > parent2->slot ||
      ( parent1->slot == parent2->slot && parent1->fec_set_idx > parent2->fec_set_idx ) ) parent1 = fd_reasm_parent( reasm, parent1 );
    else                                                                                  parent2 = fd_reasm_parent( reasm, parent2 );
  }
  return NULL;
}

#define UPDATE_BEST_CANDIDATE( best_confrmd, best_unconfrmd, ele, filter )                                                    \
  if( FD_UNLIKELY( filter ) ) continue;                                                                                       \
  do {                                                                                                                        \
    if( FD_UNLIKELY( ele->confirmed ) ) {                                                                                     \
      if( FD_LIKELY( !best_confrmd ) ) best_confrmd = ele;                                                                    \
      else                             best_confrmd = fd_ptr_if( best_confrmd->slot < ele->slot, ele, best_confrmd );         \
    } else {                                                                                                                  \
      if( FD_LIKELY( !best_unconfrmd ) ) best_unconfrmd = ele;                                                                \
      else                               best_unconfrmd = fd_ptr_if( best_unconfrmd->slot < ele->slot, ele, best_unconfrmd ); \
    }                                                                                                                         \
  } while(0)

/* Caller guarantees new_root and parent_root are non-NULL */
static fd_reasm_fec_t *
evict( fd_reasm_t      * reasm,
       fd_store_t      * opt_store,
       fd_hash_t const * new_root FD_PARAM_UNUSED,
       fd_hash_t const * parent_root ) {
  fd_reasm_fec_t * pool     = reasm_pool( reasm );
  frontier_t *     frontier = reasm->frontier;
  orphaned_t *     orphaned = reasm->orphaned;
  subtrees_t *     subtrees = reasm->subtrees;
  dlist_t *        subtreel = reasm->subtreel;

  /* Generally, best policy for eviction is to evict in the order of:
    1. Highest unconfirmed orphan leaf                   - furthest from root
    2. Highest incomplete, unconfirmed leaf in ancestry  - furthest from tip of execution
    3. Highest confirmed orphan leaf                     - evictable, since unrelated to banks, but less ideal */

  fd_reasm_fec_t * unconfrmd_orphan = NULL; /* 1st best candidate for eviction is the highest unconfirmed orphan. */
  fd_reasm_fec_t * confirmed_orphan = NULL; /* 3rd best candidate for eviction is the highest confirmed orphan.   */
  for( dlist_iter_t iter = dlist_iter_fwd_init( subtreel, pool );
                          !dlist_iter_done    ( iter, subtreel, pool );
                    iter = dlist_iter_fwd_next( iter, subtreel, pool ) ) {
    fd_reasm_fec_t * ele = dlist_iter_ele( iter, subtreel, pool );
    UPDATE_BEST_CANDIDATE( confirmed_orphan, unconfrmd_orphan, ele, ele->child != ULONG_MAX || memcmp( &ele->key, parent_root, sizeof(fd_hash_t) ) == 0 );
  }
  for( orphaned_iter_t iter = orphaned_iter_init( orphaned, pool );
                              !orphaned_iter_done( iter, orphaned, pool );
                        iter = orphaned_iter_next( iter, orphaned, pool ) ) {
    fd_reasm_fec_t *    ele = orphaned_iter_ele( iter, orphaned, pool );
    UPDATE_BEST_CANDIDATE( confirmed_orphan, unconfrmd_orphan, ele, ele->child != ULONG_MAX || memcmp( &ele->key, parent_root, sizeof(fd_hash_t) ) == 0 );
  }

  if( FD_UNLIKELY( unconfrmd_orphan )) {
    return fd_reasm_remove( reasm, unconfrmd_orphan, opt_store );
  }

  fd_reasm_fec_t * unconfrmd_leaf = NULL; /* 2nd best candidate for eviction is the highest unconfirmed, incomplete slot. */
  for( frontier_iter_t iter = frontier_iter_init( frontier, pool );
                              !frontier_iter_done( iter, frontier, pool );
                        iter = frontier_iter_next( iter, frontier, pool ) ) {
    fd_reasm_fec_t * ele = frontier_iter_ele( iter, frontier, pool );
    if( iter.ele_idx == reasm->root
        || 0==memcmp( &ele->key, parent_root, sizeof(fd_hash_t) )
        || ele->confirmed
        || ele->slot_complete
        || ele->is_leader ) continue; /* not a candidate */
    unconfrmd_leaf = fd_ptr_if( !unconfrmd_leaf || ele->slot > unconfrmd_leaf->slot, ele, unconfrmd_leaf );
  }

  if( FD_UNLIKELY( unconfrmd_leaf )) {
    return fd_reasm_remove( reasm, unconfrmd_leaf, opt_store );
  }

  /* Already did traversal to find best confirmed orphan candidate,
     which is the third choice */

  if( FD_UNLIKELY( confirmed_orphan )) {
    fd_reasm_fec_t * parent = fd_reasm_query( reasm, parent_root );
    if( !parent ) {
      return fd_reasm_remove( reasm, confirmed_orphan, opt_store );
    }
  /* for any subtree:
      0 ── 1 ── 2 ── 3 (confirmed) ── 4(confirmed) ── 5 ── 6 ──> add 7 here is valid.
                                      └──> add 7 here is valid.
                        └──> add 7 here is invalid. */
    ulong subtree_root = reasm->root;
    if( subtrees_ele_query( subtrees, parent_root, NULL, pool )  ||
        orphaned_ele_query( orphaned, parent_root, NULL, pool ) ) {
      /* if adding to an orphan, find the root of the orphan subtree. */
      fd_reasm_fec_t * root = parent;
      while( FD_LIKELY( root->parent != ULONG_MAX ) ) {
        root = pool_ele( pool, root->parent );
      }
      subtree_root = pool_idx( pool, root );
    }

    fd_reasm_fec_t * latest_confirmed_leaf = latest_confirmed_fec( reasm, subtree_root );
    if( !latest_confirmed_leaf || latest_confirmed_leaf == gca( reasm, latest_confirmed_leaf, parent )) {
      return fd_reasm_remove( reasm, confirmed_orphan, opt_store );
    }
    /* is a useless new fork. */
    return NULL;
  }
  return NULL; /* nothing else could be evicted */
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
                 int               slot_complete,
                 int               is_leader,
                 fd_store_t      * opt_store,
                 fd_reasm_fec_t ** evicted ) {

# if LOGGING
  FD_BASE58_ENCODE_32_BYTES( merkle_root->key,         merkle_root_b58         );
  FD_BASE58_ENCODE_32_BYTES( chained_merkle_root->key, chained_merkle_root_b58 );
  FD_LOG_NOTICE(( "inserting (%lu %u) %s %s. %u %d %d", slot, fec_set_idx, merkle_root_b58, chained_merkle_root_b58, data_cnt, data_complete, slot_complete ));
# endif

  fd_reasm_fec_t * pool = reasm_pool( reasm );
# if FD_REASM_USE_HANDHOLDING
  FD_TEST( !fd_reasm_query( reasm, merkle_root ) );
# endif

  ulong        null     = pool_idx_null( pool );
  ancestry_t * ancestry = reasm->ancestry;
  frontier_t * frontier = reasm->frontier;
  orphaned_t * orphaned = reasm->orphaned;
  subtrees_t * subtrees = reasm->subtrees;
  dlist_t *    dlist    = reasm->subtreel;

  ulong     * bfs = reasm->bfs;
  fd_hash_t * out = reasm->out;

  *evicted = NULL;

  if( FD_UNLIKELY( pool_free( pool )==1UL ) ) {
    FD_TEST( reasm->root!=pool_idx_null( pool ) );
    /* The eviction removes evicted elements from the maps, but leaves
       the elements in the pool for caller to release.  Thus, in order
       for the following insert/acquire to succeed, we have to start
       evicting when we have 1 remaining free element in the pool.  This
       element is the one that will be acquired below.  reasm is
       dependent on the caller to then release the evicted elements back
       to the pool before the next insert/acquire. */
    *evicted = evict( reasm, opt_store, merkle_root, chained_merkle_root );
    if( FD_UNLIKELY( *evicted == NULL ) )  {
      FD_LOG_INFO(("reasm failed to evict a fec set when inserting slot %lu fec set %u", slot, fec_set_idx));

      /* in this case we want to signal to the replay tile that we
         failed to insert the FEC set.  This is effectively is the same
         logic as if we had this FEC set, and then it got evicted, and
         then the caller now needs to process the evicted FEC set.  So
         here we acquire the final pool element for it and return it
         to the caller as the evicted FEC set. */

      fd_reasm_fec_t * fec = pool_ele_acquire( pool );
      fec->key             = *merkle_root;
      fec->cmr             = *chained_merkle_root;
      fec->parent          = null;
      fec->child           = null;
      fec->slot            = slot;
      fec->parent_off      = parent_off;
      fec->fec_set_idx     = fec_set_idx;
      fec->bank_idx        = null;

      *evicted = fec;
      return NULL;
    }
  }

  FD_TEST( pool_free( pool ) );
  fd_reasm_fec_t * fec = pool_ele_acquire( pool );
  fec->key             = *merkle_root;
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
  fec->is_leader       = is_leader;
  fec->eqvoc           = 0;
  fec->confirmed       = 0;
  fec->popped          = 0;
  fec->bank_dead       = 0;
  fec->bank_idx        = null;
  fec->parent_bank_idx = null;
  fec->bank_seq        = null;
  fec->parent_bank_seq = null;

  if( FD_UNLIKELY( !chained_merkle_root ) ) { /* initialize the reasm with the root */
    FD_TEST( reasm->root==pool_idx_null( pool ) );
    fec->confirmed      = 1;
    fec->popped         = 1;
    /*                 */ xid_update( reasm, slot, UINT_MAX,    pool_idx( pool, fec ) );
    /*                 */ xid_update( reasm, slot, fec_set_idx, pool_idx( pool, fec ) );
    reasm->root         = pool_idx( pool, fec );
    reasm->slot0        = slot;
    frontier_ele_insert( reasm->frontier, fec, pool );
    return fec;
  }

  fec->cmr = *chained_merkle_root;
  FD_TEST( memcmp( &fec->cmr, chained_merkle_root, sizeof(fd_hash_t) ) == 0 );

  if( FD_UNLIKELY( slot_complete ) ) {
    xid_t * bid = xid_query( reasm->xid, (slot << 32) | UINT_MAX, NULL );
    if( FD_UNLIKELY( bid ) ) {
      fd_reasm_fec_t * orig_fec = pool_ele( pool, bid->idx );
      FD_BASE58_ENCODE_32_BYTES( orig_fec->key.key, prev_block_id_b58 );
      FD_BASE58_ENCODE_32_BYTES( fec->key.key,      curr_block_id_b58 );
      FD_LOG_WARNING(( "equivocating block_id for FEC slot: %lu fec_set_idx: %u prev: %s curr: %s", fec->slot, fec->fec_set_idx, prev_block_id_b58, curr_block_id_b58 )); /* it's possible there's equivocation... */
    }
    xid_update( reasm, slot, UINT_MAX, pool_idx( pool, fec ) );
  }
  overwrite_invalid_cmr( reasm, fec ); /* handle receiving parent before child */

  /* First, we search for the parent of this new FEC and link if found.
     The new FEC set may result in a new leaf or a new orphan tree root
     so we need to check that. */

  fd_reasm_fec_t * parent = NULL;
  if(        FD_LIKELY ( parent = ancestry_ele_query ( ancestry, &fec->cmr, NULL, pool ) ) ) { /* parent is connected non-leaf */
    frontier_ele_insert( frontier, fec,    pool );
    out_push_tail      ( out,      fec->key     );
  } else if( FD_LIKELY ( parent = frontier_ele_remove( frontier, &fec->cmr, NULL, pool ) ) ) { /* parent is connected leaf     */
    ancestry_ele_insert( ancestry, parent, pool );
    frontier_ele_insert( frontier, fec,    pool );
    out_push_tail      ( out,      fec->key     );
  } else if( FD_LIKELY ( parent = orphaned_ele_query ( orphaned, &fec->cmr, NULL, pool ) ) ) { /* parent is orphaned non-root */
    orphaned_ele_insert( orphaned, fec,    pool );
  } else if( FD_LIKELY ( parent = subtrees_ele_query ( subtrees, &fec->cmr, NULL, pool ) ) ) { /* parent is orphaned root     */
    orphaned_ele_insert( orphaned, fec,    pool );
  } else {                                                                                     /* parent not found            */
    subtrees_ele_insert( subtrees, fec,    pool );
    dlist_ele_push_tail( dlist,    fec,    pool );
  }

  if( FD_LIKELY( parent ) ) link( reasm, parent, fec );

  /* Second, we search for children of this new FEC and link them to it.
     By definition any children must be orphaned (a child cannot be part
     of a connected tree before its parent).  Therefore, we only search
     through the orphaned subtrees.  As part of this operation, we also
     coalesce connected orphans into the same tree.  This way we only
     need to search the orphan tree roots (vs. all orphaned nodes). */

  ulong min_descendant = ULONG_MAX; /* needed for eqvoc checks below */
  FD_TEST( bfs_empty( bfs ) );
  for( dlist_iter_t iter = dlist_iter_fwd_init(       dlist, pool );
                          !dlist_iter_done    ( iter, dlist, pool );
                    iter = dlist_iter_fwd_next( iter, dlist, pool ) ) {
    bfs_push_tail( bfs, dlist_iter_idx( iter, dlist, pool ) );
  }
  while( FD_LIKELY( !bfs_empty( bfs ) ) ) { /* link orphan subtrees to the new FEC */
    fd_reasm_fec_t * orphan_root = pool_ele( pool, bfs_pop_head( bfs ) );
    FD_TEST( orphan_root ); // `overwrite_invalid_cmr` relies on orphan_root being non-null
    overwrite_invalid_cmr( reasm, orphan_root ); /* case 2: received child before parent */
    if( FD_LIKELY( 0==memcmp( orphan_root->cmr.uc, fec->key.uc, sizeof(fd_hash_t) ) ) ) { /* this orphan_root is a direct child of fec */
      link( reasm, fec, orphan_root );
      subtrees_ele_remove( subtrees, &orphan_root->key, NULL, pool );
      dlist_ele_remove   ( dlist,     orphan_root,            pool );
      orphaned_ele_insert( orphaned,  orphan_root,            pool );
      min_descendant = fd_ulong_min( min_descendant, orphan_root->slot );
    }
  }

  /* Third, we advance the frontier outward beginning from fec as we may
     have connected orphaned descendants to fec in the above step.  This
     does a BFS outward from fec until it reaches leaves, moving fec and
     its non-leaf descendants into ancestry and leaves into frontier.

     parent (ancestry)     orphan root  (subtrees)
       |                        |
      fec   (frontier)     orphan child (orphaned)

     parent
       |
      fec         <- frontier is here
       |
     orphan root
       |
     orphan child <- advance to here */

  if( FD_LIKELY( frontier_ele_query( frontier, &fec->key, NULL, pool ) ) ) bfs_push_tail( bfs, pool_idx( pool, fec ) );
  while( FD_LIKELY( !bfs_empty( bfs ) ) ) {
    fd_reasm_fec_t * parent = pool_ele( pool, bfs_pop_head( bfs ) );
    fd_reasm_fec_t * child  = pool_ele( pool, parent->child );
    if( FD_LIKELY( child ) ) {
      frontier_ele_remove( frontier, &parent->key, NULL, pool );
      ancestry_ele_insert( ancestry, parent,             pool );
    }
    while( FD_LIKELY( child ) ) {
      FD_TEST( orphaned_ele_remove( orphaned, &child->key, NULL, pool ) );
      frontier_ele_insert( frontier, child, pool );
      bfs_push_tail( bfs, pool_idx( pool, child ) );
      out_push_tail( out, child->key              );
      child = pool_ele( pool, child->sibling );
    }
  }

  /* Fourth, check and handle equivocation.  There are three cases.

     1. we've already seen this FEC's xid (slot, fec_set_idx)
     2. this FEC's parent equivocates. */

  xid_t * xid = xid_query( reasm->xid, (slot<<32) | fec_set_idx, NULL );
  if( FD_UNLIKELY( xid ) ) {
    eqvoc( reasm, fec );
    eqvoc( reasm, pool_ele( pool, xid->idx ) ); /* first appearance of this xid */
  }
  xid_update( reasm, slot, fec_set_idx, pool_idx( pool, fec ) );
  if( FD_UNLIKELY( parent && parent->eqvoc && !parent->confirmed ) ) eqvoc( reasm, fec );

  /* 3. this FEC's parent is a slot_complete, but this FEC is part of
        the same slot.  Or this fec is a slot_complete, but it's child
        is part of the same slot. i.e.

             A - B - C (slot cmpl) - D - E - F (slot cmpl)

        We do not want to deliver this entire slot if possible. The
        block has TWO slot complete flags. This is not honest behavior.

         Two ways this can happen:
          scenario 1: A - B - C (slot cmpl) - D - E - F (slot cmpl)

          scenario 2: A - B - C (slot cmpl)
                           \
                            D - E - F (slot cmpl)   [true equivocation case]

        Scenario 2 is handled first-class in reasm, and we will only
        replay this slot if one version gets confirmed (or we did not
        see evidence of the other version until after we replayed the
        first).

        In scenario 1, it is impossible for the cluster to converge on
        ABC(slot cmpl)DEF(slot cmpl), but depending on the order in
        which each node receives the FEC sets, the cluster could either
        confirm ABC(slot cmpl), or mark the slot dead.  In general, if
        the majority of nodes received and replayed the shorter version
        before seeing the second half, the slot could still end up
        getting confirmed. Whereas if the majority of nodes saw shreds
        from DEF before finishing replay and voting on ABC, the slot
        would likely be marked dead.

        Firedancer handles this case by marking the slot eqvoc upon
        detecting a slot complete in the middle of a slot.  reasm will
        mark the earliest FEC possible in the slot as eqvoc, but may not
        be able to detect fec 0 because the FEC may be orphaned, or fec
        0 may not exist yet.  Thus, it is possible for Firedancer to
        replay ABC(slot cmpl), but it is impossible for reasm to deliver
        fecs D, E, or F. The node would then vote for ABC(slot cmpl).

        If the node sees D before replaying A, B, or C, then it would be
        able to mark ABCD as eqvoc, and prevent the corresponding FECs
        from being delivered. In this case, the Firedancer node would
        have an incompletely executed bank that eventually gets pruned
        away.

        Agave's handling differs because they key by slot, but our
        handling is compatible with the protocol. */

  if( FD_UNLIKELY( (parent && parent->slot_complete && parent->slot == slot) ||
                   (fec->slot_complete && min_descendant == slot) ) ) {
    /* walk up to the earliest fec in slot */
    fd_reasm_fec_t * curr = fec;
    while( FD_LIKELY( curr->parent != pool_idx_null( pool ) && pool_ele( pool, curr->parent )->slot == slot ) ) {
      curr = pool_ele( pool, curr->parent );
    }
    eqvoc( reasm, curr );
  }

  /* Finally, return the newly inserted FEC. */
  return fec;
}

fd_reasm_fec_t *
fd_reasm_publish( fd_reasm_t      * reasm,
                  fd_hash_t const * merkle_root,
                  fd_store_t      * opt_store ) {

# if FD_REASM_USE_HANDHOLDING
  if( FD_UNLIKELY( !pool_ele( reasm_pool( reasm ), reasm->root ) ) ) { FD_LOG_WARNING(( "missing root" )); return NULL; }
  if( FD_UNLIKELY( !fd_reasm_query( reasm, merkle_root ) ) ) {
    FD_BASE58_ENCODE_32_BYTES( merkle_root->key, merkle_root_b58 );
    FD_LOG_WARNING(( "merkle root %s not found", merkle_root_b58 ));
    return NULL;
  }
# endif

  fd_reasm_fec_t *  pool = reasm_pool( reasm );
  ulong             null = pool_idx_null( pool );
  fd_reasm_fec_t  * oldr = pool_ele( pool, reasm->root );
  fd_reasm_fec_t  * newr = fd_reasm_query( reasm, merkle_root );
  ulong *           bfs  = reasm->bfs;

  bfs_push_tail( bfs, pool_idx( pool, oldr ) );

  /* First, BFS down the tree, pruning all of root's ancestors and also
     any descendants of those ancestors. */

  /* Also, prune any subtrees who's root is less than the new root. */

  dlist_t * subtreel = reasm->subtreel;
  for( dlist_iter_t iter = dlist_iter_fwd_init( subtreel, pool );
                          !dlist_iter_done    ( iter, subtreel, pool );
                    iter = dlist_iter_fwd_next( iter, subtreel, pool ) ) {
    fd_reasm_fec_t * ele = dlist_iter_ele( iter, subtreel, pool );
    if( ele->slot < newr->slot ) {
      bfs_push_tail( bfs, pool_idx( pool, ele ) );
    }
  }

  while( FD_LIKELY( !bfs_empty( bfs ) ) ) {
    fd_reasm_fec_t * head  = pool_ele( pool, bfs_pop_head( bfs ) );

    fd_reasm_fec_t *          fec = ancestry_ele_remove( reasm->ancestry, &head->key, NULL, pool );
    if( FD_UNLIKELY( !fec ) ) fec = frontier_ele_remove( reasm->frontier, &head->key, NULL, pool );
    if( FD_UNLIKELY( !fec ) ) fec = orphaned_ele_remove( reasm->orphaned, &head->key, NULL, pool );
    if( FD_UNLIKELY( !fec ) ) {
      fec = subtrees_ele_remove( reasm->subtrees, &head->key, NULL, pool );
      dlist_ele_remove( reasm->subtreel, head, pool );
    }

    fd_reasm_fec_t * child = pool_ele( pool, head->child );
    while( FD_LIKELY( child ) ) {                                                       /* iterate over children */
      if( FD_LIKELY( child != newr ) ) {                                                /* stop at new root */
        bfs_push_tail( bfs, pool_idx( pool, child ) );
      }
      child = pool_ele( pool, child->sibling );                                         /* right-sibling */
    }
    clear_slot_metadata( reasm, head );
    if( FD_LIKELY( opt_store ) ) fd_store_remove( opt_store, &head->key );
    pool_ele_release( pool, head );
  }

  /* Third, remove any elements from the out queue that were pruned from
     the tree in the above. */

  ulong cnt = out_cnt( reasm->out );
  for( ulong i = 0UL; i < cnt; i++ ) {
    fd_hash_t mr = out_pop_head( reasm->out );
    if( FD_LIKELY( fd_reasm_query( reasm, &mr ) ) ) out_push_tail( reasm->out, mr );
  }

  newr->parent = null;                   /* unlink old root */
  reasm->root  = pool_idx( pool, newr ); /* replace with new root */
  return newr;
}

#include <stdio.h>

FD_FN_UNUSED static void
print( fd_reasm_t const * reasm, fd_reasm_fec_t const * fec, int space, const char * prefix ) {
  fd_reasm_fec_t const * pool = reasm_pool_const( reasm );

  if( fec == NULL ) return;

  if( space > 0 ) printf( "\n" );
  for( int i = 0; i < space; i++ ) printf( " " );
  FD_BASE58_ENCODE_32_BYTES( fec->key.key, key_b58 );
  printf( "%s%s", prefix, key_b58 );

  fd_reasm_fec_t const * curr = pool_ele_const( pool, fec->child );
  char new_prefix[1024]; /* FIXME size this correctly */
  while( curr ) {
    if( pool_ele_const( pool, curr->sibling ) ) {
      sprintf( new_prefix, "├── " ); /* branch indicating more siblings follow */
      print( reasm, curr, space + 4, new_prefix );
    } else {
      sprintf( new_prefix, "└── " ); /* end branch */
      print( reasm, curr, space + 4, new_prefix );
    }
    curr = pool_ele_const( pool, curr->sibling );
  }
}

static void
ancestry_print( fd_reasm_t const * reasm, fd_reasm_fec_t const * fec, int space, const char * prefix, fd_reasm_fec_t const * prev, ulong recurse_depth ) {
  fd_reasm_fec_t const * pool = reasm_pool_const( reasm );
  if( fec == NULL ) return;
  recurse_depth++;
  if( recurse_depth == 2048 ) {
    FD_BASE58_ENCODE_32_BYTES( fec->key.key, key_b58 );
    FD_LOG_NOTICE(("Cutting off ancestry print at depth %lu, slot %lu. Continue printing with this root key %s.", recurse_depth, fec->slot, key_b58 ));
    return;
  }
  fd_reasm_fec_t const * child = fd_reasm_child_const( reasm, fec );

  if( !prev ||  /* root OR */
      ( fec->slot_complete || (!prev->eqvoc && fec->eqvoc) || fec->child == pool_idx_null( pool ) || child->sibling != pool_idx_null( pool ) )) {
    if( space > 0 ) printf( "\n" );
    for( int i = 0; i < space; i++ ) printf( " " );
    printf( "%s", prefix );

    FD_BASE58_ENCODE_32_BYTES( fec->key.key, key_b58 );
    key_b58[5] = '\0'; /* only print first 5 characters of key_b58 */
    printf( "%lu(%u) %s", fec->slot, fec->fec_set_idx, key_b58 );
    if( fec->eqvoc )     printf( " [eqvoc]" );
    if( fec->is_leader ) printf( " [leader]" );
    space += 5;
    fflush(stdout);
  }

  char new_prefix[1024]; /* FIXME size this correctly */

  while( child ) {
    if( pool_ele_const( pool, child->sibling ) ) {
      sprintf( new_prefix, "├── " ); /* branch indicating more siblings follow */
      ancestry_print( reasm, child, space, new_prefix, fec, recurse_depth );
    } else {
      sprintf( new_prefix, "└── " ); /* end branch */
      ancestry_print( reasm, child, space, new_prefix, fec, recurse_depth );
    }
    child = pool_ele_const( pool, child->sibling );
  }
}

void
fd_reasm_print( fd_reasm_t const * reasm ) {
  FD_LOG_NOTICE( ( "\n\n[Reasm - showing only leaves, slot completes, and branches]" ) );
  fd_reasm_fec_t const * pool = reasm_pool_const( reasm );
  printf( "ele cnt: %lu\n", pool_used( pool ) );

  if( FD_LIKELY( reasm->root != pool_idx_null( pool ) ) ) {
    printf( "\n\n[Connected Fecs]\n" );
    ancestry_print( reasm, fd_reasm_root_const( reasm ), 0, "", NULL, 0 );
  }

  printf( "\n\n[Unconnected Fecs]\n" );
  dlist_t const * subtreel = reasm->_subtrlf;
  for( dlist_iter_t iter = dlist_iter_fwd_init( subtreel,       pool );
                          !dlist_iter_done    ( iter, subtreel, pool );
                    iter = dlist_iter_fwd_next( iter, subtreel, pool ) ) {
    fd_reasm_fec_t const * fec = pool_ele_const( pool, iter );
    ancestry_print( reasm, fec, 0, "", NULL, 0 );
  }

  printf( "\n\n" );
  fflush(stdout);
}
