#include "fd_repair.h"
#include "../../ballet/bmtree/fd_bmtree.h"
#include "../../ballet/sha256/fd_sha256.h"
#include "../../flamenco/alpenglow/fd_block_marker_serde.h"
#include "../../disco/events/generated/fd_event_gen.h"

static void
blk_treap_insert( fd_repair_t *     self,
                  fd_repair_blk_t * blk ) {
  fd_repair_slot_meta_t const * meta = fd_repair_slot_meta( self, blk->slot );
  ulong                         idx  = fd_repair_blk_pool_idx( self->blk_pool, blk );
  if( FD_UNLIKELY( blk->in_blk_treap ) ) return;
  if( FD_UNLIKELY( meta->final!=idx && meta->notar!=idx && meta->eager==idx && !blk->eager ) ) return;
  fd_repair_treap_ele_insert( meta->final==idx ? self->final_treap : meta->notar==idx ? self->notar_treap : self->eager_treap, blk, self->blk_pool );
  blk->in_blk_treap = 1;
}

static void
blk_treap_remove( fd_repair_t *     self,
                  fd_repair_blk_t * blk ) {
  if( FD_LIKELY( !blk->in_blk_treap  ) ) return;
  fd_repair_slot_meta_t const * meta = fd_repair_slot_meta( self, blk->slot );
  ulong                         idx  = fd_repair_blk_pool_idx( self->blk_pool, blk );
  fd_repair_treap_ele_remove( meta->final==idx ? self->final_treap : meta->notar==idx ? self->notar_treap : self->eager_treap, blk, self->blk_pool );
  blk->in_blk_treap = 0;
}


/* blk_insert creates a blk of slot named dmr (null for an eager blk)
   with nothing received yet.  An eager blk is the slot's eager blk. */

static fd_repair_blk_t *
blk_insert( fd_repair_t *     self,
            ulong             slot,
            fd_mr32_t const * dmr ) {
  FD_TEST( fd_repair_blk_pool_free( self->blk_pool ) );
  fd_repair_slot_meta_t *       meta = fd_repair_slot_meta( self, slot );
  fd_repair_blk_t *             blk  = fd_repair_blk_pool_ele_acquire( self->blk_pool );
  blk->slot             = slot;
  blk->dmr              = *dmr;
  blk->parent           = fd_repair_blk_pool_idx_null( self->blk_pool );
  blk->child            = fd_repair_blk_pool_idx_null( self->blk_pool );
  blk->sibling          = fd_repair_blk_pool_idx_null( self->blk_pool );
  blk->cmpl_fec_cnt     = 0U;
  blk->rcvd_fec_cnt     = 0U;
  blk->buff_fec_cnt     = 0U;
  blk->cons_fec_cnt     = 0U;
  blk->wait_fec_cnt     = 0U;
  blk->parent_slot      = ULONG_MAX;
  blk->parent_blk_mr    = hash_null;
  blk->init_fec_cnt     = 0U;
  blk->init_parent_slot = ULONG_MAX;

  blk->in_blk_treap  = 0;
  blk->eager         = (!memcmp( dmr, &hash_null, sizeof(fd_mr32_t)) && !meta->invalidated && meta->final==fd_repair_blk_pool_idx_null( self->blk_pool ) && !meta->leader );
  blk->meta_req      = 0;
  blk->highest_req   = 0;
  blk->orphan_req    = 0;
  memset( &blk->telemetry, 0, sizeof(blk->telemetry) );
  blk->telemetry.last_cmpl_fec_idx = UINT_MAX;
  blk->rcvd_fec_ts   = 0L;
  for( ulong k=0UL; k<self->fec_blk_max; k++ ) blk->fecs[ k ] = fd_repair_fec_pool_idx_null( self->fec_pool );
  fd_repair_blk_map_ele_insert( self->blk_map, blk, self->blk_pool );
  if     ( !memcmp( dmr, &hash_null, sizeof(fd_mr32_t) ) )               meta->eager = fd_repair_blk_pool_idx( self->blk_pool, blk );
  else if( meta->notar==fd_repair_blk_pool_idx_null( self->blk_pool ) ) meta->notar = fd_repair_blk_pool_idx( self->blk_pool, blk );
  blk_treap_insert( self, blk );
  return blk;
}

/* compute_dmr computes the double merkle root of a complete eager blk:
   the merkle tree over its FEC set roots, then a parent info leaf. */

static void
compute_dmr( fd_repair_t *     self,
             fd_repair_blk_t * blk ) {
  uint fec_set_cnt = blk->cmpl_fec_cnt;

  uchar tree_mem[ FD_BMTREE_COMMIT_FOOTPRINT( 0UL ) ] __attribute__((aligned(FD_BMTREE_COMMIT_ALIGN)));
  fd_bmtree_commit_t * tree = fd_bmtree_commit_init( tree_mem, FD_SHRED_MERKLE_NODE_SZ, FD_BMTREE_LONG_PREFIX_SZ, 0UL );
  for( uint k=0U; k<fec_set_cnt; k++ ) {
    fd_bmtree_node_t leaf[1];
    memcpy( leaf->hash, fd_repair_fec_pool_ele( self->fec_pool, blk->fecs[ k ] )->mr32.uc, sizeof(fd_mr32_t) );
    fd_bmtree_commit_append( tree, leaf, 1UL );
  }

  fd_bmtree_node_t parent_info[1];
  fd_sha256_t      sha[1];
  fd_sha256_init  ( sha );
  fd_sha256_append( sha, &blk->parent_slot,      sizeof(ulong)     );
  fd_sha256_append( sha, blk->parent_blk_mr.uc,  sizeof(fd_mr32_t) );
  fd_sha256_append( sha, &fec_set_cnt,           sizeof(uint)      );
  fd_sha256_fini  ( sha, parent_info->hash );
  fd_bmtree_commit_append( tree, parent_info, 1UL );

  memcpy( blk->dmr.uc, fd_bmtree_commit_fini( tree ), sizeof(fd_mr32_t) );
}

/* consume pushes buffered FECs onto the reasm queue.  The first push
   after a reconsume first pushes blk's consumed FECs and its ancestors'
   onto the head, so its chain goes out again from the root. */

static void
consume( fd_repair_t *     self,
         fd_repair_blk_t * blk ) {
  fd_repair_slot_meta_t const * meta = fd_repair_slot_meta( self, blk->slot );
  if( FD_UNLIKELY( meta->invalidated && !memcmp( &blk->dmr, &hash_null, sizeof(fd_mr32_t) ) ) ) return;
  if( FD_UNLIKELY( blk->parent==fd_repair_blk_pool_idx_null( self->blk_pool ) ) ) return; /* orphaned, even if partly consumed */
  if( FD_UNLIKELY( blk->cons_fec_cnt<=blk->init_fec_cnt ) ) {
    fd_repair_blk_t const * parent = fd_repair_blk_pool_ele_const( self->blk_pool, blk->parent );
    if( FD_LIKELY( parent!=self->root_blk && ( !parent->cmpl_fec_cnt || parent->cons_fec_cnt!=parent->cmpl_fec_cnt ) ) ) return;
  }
  ulong             idx   = fd_repair_blk_pool_idx( self->blk_pool, blk );
  fd_repair_blk_t * eager = fd_repair_blk_pool_ele( self->blk_pool, meta->eager );
  if( FD_UNLIKELY(  eager && meta->eager!=idx && !meta->invalidated && !memcmp( &eager->dmr, &hash_null, sizeof(fd_mr32_t) ) ) ) {
    int dup = eager->parent==blk->parent;
    for( uint k=blk->cons_fec_cnt; dup && k<blk->buff_fec_cnt; k++ ) dup = eager->fecs[ k ]==blk->fecs[ k ];
    if( FD_LIKELY( dup ) ) {
      blk = eager;
      idx = meta->eager;
    }
  }
  if( FD_UNLIKELY( self->reconsume && blk->cons_fec_cnt<blk->buff_fec_cnt ) ) {
    self->reconsume = 0;
    for( fd_repair_blk_t * anc = blk; anc && anc!=self->root_blk; anc = fd_repair_blk_pool_ele( self->blk_pool, anc->parent ) ) {
      for( uint k=anc->cons_fec_cnt; k>anc->init_fec_cnt; k-- ) fd_repair_deque_push_head( self->reasm_deque, (fd_repair_deque_t){ .blk_idx = (uint)fd_repair_blk_pool_idx( self->blk_pool, anc ), .fec_idx = k-1U } );
    }
  }
  if( FD_UNLIKELY( meta->leader && meta->eager==idx ) ) { /* our leader blk goes first, in FEC order */
    for( uint k=blk->buff_fec_cnt; k>blk->cons_fec_cnt; k-- ) fd_repair_deque_push_head( self->reasm_deque, (fd_repair_deque_t){ .blk_idx = (uint)idx, .fec_idx = k-1U } );
    blk->cons_fec_cnt = blk->buff_fec_cnt;
    return;
  }
  for( ; blk->cons_fec_cnt<blk->buff_fec_cnt; blk->cons_fec_cnt++ ) fd_repair_deque_push_tail( self->reasm_deque, (fd_repair_deque_t){ .blk_idx = (uint)idx, .fec_idx = blk->cons_fec_cnt } );
}

/* cascade performs a stackless (ie. O(1) space) preorder traversal. */

static void
cascade( fd_repair_t *     self,
         fd_repair_blk_t * root ) {
  fd_repair_blk_t * pool = self->blk_pool;
  ulong             null = fd_repair_blk_pool_idx_null( pool );
  ulong             tidx = fd_repair_blk_pool_idx( pool, root );
  ulong             idx  = root->child;
  while( FD_LIKELY( idx!=null ) ) {
    fd_repair_blk_t * blk = fd_repair_blk_pool_ele( pool, idx );
    consume( self, blk );
    if( FD_LIKELY( blk->cmpl_fec_cnt && blk->cons_fec_cnt==blk->cmpl_fec_cnt && blk->child!=null ) ) { idx = blk->child; continue; }
    while( FD_LIKELY( idx!=tidx && fd_repair_blk_pool_ele( pool, idx )->sibling==null ) ) idx = fd_repair_blk_pool_ele( pool, idx )->parent;
    if( FD_UNLIKELY( idx==tidx ) ) break;
    idx = fd_repair_blk_pool_ele( pool, idx )->sibling;
  }
}

/* promote gives blk the slot_meta role (notar or final), moving it to
   that role's treap if it was in one.  A blk with a role is not
   repaired by position. */

static void
promote( fd_repair_t *     self,
         fd_repair_blk_t * blk,
         ulong *           role ) {
  if( FD_LIKELY( *role==fd_repair_blk_pool_idx( self->blk_pool, blk ) ) ) return;
  int in_blk_treap = blk->in_blk_treap;
  blk_treap_remove( self, blk );
  *role      = fd_repair_blk_pool_idx( self->blk_pool, blk );
  blk->eager = 0;
  if( FD_LIKELY( in_blk_treap ) ) blk_treap_insert( self, blk );
}

/* connect_ancestors links a notar or final blk to its ancestors via
   parent dmr, creating the ones not held, up to the root or a blk whose
   parent is not known.

   For every blk B that is notar or final and whose header is known, the
   blk B names must be held, B must be linked under it, and if B is
   final so must it be. Then apply the same rule to that parent.

   If the parent was just created, the blk must be re-added to the
   treap. It's the responsibility of the blk's presence in the treap for
   the tile to make orphan requests; NOT the parent, which only gets a
   META request.

   This should be called anytime a blk becomes notar or final and its
   header is known, or vice versa.

   Only the highest blk linked here (else blk itself) can have become
   consumable: the blks above were linked before and their FEC sets are
   untouched, the blks below are reached by its cascade.  */

static void
connect_ancestors(  fd_repair_t *     self,
                    fd_repair_blk_t * blk ) {
  fd_repair_blk_t * pool = self->blk_pool;
  ulong             null = fd_repair_blk_pool_idx_null( pool );
  fd_repair_blk_t * top  = blk;
  for(;;) {
    if( FD_UNLIKELY( blk->parent_slot==ULONG_MAX || blk->parent_slot<self->root ) ) break;
    if( FD_UNLIKELY( blk->parent_slot!=self->root && !memcmp( &blk->parent_blk_mr, &hash_null, sizeof(fd_mr32_t) ) ) ) break;
    fd_repair_slot_meta_t * meta   = fd_repair_slot_meta( self, blk->slot );
    fd_repair_slot_meta_t * pmeta  = fd_repair_slot_meta( self, blk->parent_slot );
    int                     final  = meta->final==fd_repair_blk_pool_idx( pool, blk );
    fd_repair_blk_t *       parent = fd_repair_blk_map_ele_query( self->blk_map, &blk->parent_slot, NULL, pool );
    while( parent && memcmp( &parent->dmr, &blk->parent_blk_mr, sizeof(fd_mr32_t) ) ) parent = (fd_repair_blk_t *)fd_repair_blk_map_ele_next_const( parent, NULL, pool );
    if( FD_UNLIKELY( !parent && blk->parent_slot==self->root ) ) break; /* names a root other than ours */
    int held = !!parent;
    if( FD_UNLIKELY( !parent ) ) parent = fd_repair_blk_notarized( self, blk->parent_slot, &blk->parent_blk_mr );
    if( FD_UNLIKELY( !parent ) ) break; /* the parent slot is settled otherwise */
    if( FD_UNLIKELY( !held   ) ) { /* link_children linked blk under the new parent */
      blk_treap_insert( self, blk ); /* its tile asks ORPHAN for eager ancestry, which may merge with the named parents */
      top = blk;
    }
    if( FD_UNLIKELY( blk->parent==null ) ) {
      if( FD_LIKELY( blk!=self->root_blk /* && blk->parent==null */ && memcmp( &blk->parent_blk_mr, &hash_null, sizeof(fd_mr32_t) ) ) ) {
        fd_repair_orphan_map_ele_remove_fast( self->orphan_map, blk, pool );
      }
      blk->parent   = fd_repair_blk_pool_idx( pool, parent );
      blk->sibling  = parent->child;
      parent->child = fd_repair_blk_pool_idx( pool, blk );
      top           = blk;
    }
    if( FD_UNLIKELY( final && pmeta->final==null ) ) promote( self, parent, &pmeta->final );
    blk = parent;
  }
  consume( self, top );
  if( FD_UNLIKELY( top->cmpl_fec_cnt && top->cons_fec_cnt==top->cmpl_fec_cnt ) ) cascade( self, top );
}

/* link_parent links an unlinked blk whose header is known under the
   held blk it names, if any.  Returns the parent linked under. */

static fd_repair_blk_t *
link_parent( fd_repair_t *     self,
             fd_repair_blk_t * blk ) {
  fd_repair_blk_t * pool = self->blk_pool;
  if( FD_UNLIKELY( blk->parent_slot==ULONG_MAX ) ) return NULL;
  if( FD_UNLIKELY( blk->parent_slot!=self->root && !memcmp( &blk->parent_blk_mr, &hash_null, sizeof(fd_mr32_t) ) ) ) return NULL;

  fd_repair_blk_t * parent = fd_repair_blk_map_ele_query( self->blk_map, &blk->parent_slot, NULL, pool );
  while( parent && memcmp( &parent->dmr, &blk->parent_blk_mr, sizeof(fd_mr32_t) ) ) parent = (fd_repair_blk_t *)fd_repair_blk_map_ele_next_const( parent, NULL, pool );
  if( FD_LIKELY( !parent ) ) return NULL;

  if( FD_LIKELY( blk!=self->root_blk && blk->parent==fd_repair_blk_pool_idx_null( pool ) && memcmp( &blk->parent_blk_mr, &hash_null, sizeof(fd_mr32_t) ) ) ) {
    fd_repair_orphan_map_ele_remove_fast( self->orphan_map, blk, pool );
  }

  blk->parent   = fd_repair_blk_pool_idx( pool, parent );
  blk->sibling  = parent->child;
  parent->child = fd_repair_blk_pool_idx( pool, blk );
  return parent;
}

/* handle_update_parent applies the UpdateParent at the head of FEC set
   fec_idx to each blk of slot holding it, once both halves of the
   marker test are known: FEC set fec_idx-1 ends in DATA_COMPLETE and
   the first data shred of FEC set fec_idx parsed as an UpdateParent.
   Called when either half becomes known, again is a no-op.

   The eager blk leaves the header's parent: it is unlinked from it, or
   out of orphan_map under it, and is linked under the new parent if
   held, else waits in orphan_map under it.  Its shreds keep the
   header's parent offset, so they are checked against init_parent_slot.
   An UpdateParent that breaks a rule invalidates the slot, as agave
   marks it dead.

   A notar blk's parent came from ParentAndFecSetCount, which its dmr
   commits to, so it only learns init_fec_cnt.  Its UpdateParent must
   name that parent. */

static void
handle_update_parent( fd_repair_t * self,
                      ulong         slot,
                      uint          fec_idx,
                      long          ts ) {
  if( FD_UNLIKELY( !fec_idx || fec_idx>=self->fec_blk_max ) ) return;
  fd_repair_slot_meta_t * meta  = fd_repair_slot_meta( self, slot );
  fd_repair_blk_t *       pool  = self->blk_pool;
  ulong                   null  = fd_repair_blk_pool_idx_null( pool );
  fd_repair_blk_t * next;
  for( fd_repair_blk_t * blk = fd_repair_blk_map_ele_query( self->blk_map, &slot, NULL, pool ); blk; blk = next ) {
    next = (fd_repair_blk_t *)fd_repair_blk_map_ele_next_const( blk, NULL, pool );

    if( FD_LIKELY( blk->fecs[ fec_idx-1U ]==fd_repair_fec_pool_idx_null( self->fec_pool ) || blk->fecs[ fec_idx ]==fd_repair_fec_pool_idx_null( self->fec_pool ) ) ) continue;
    fd_repair_fec_t const * prev_fec = fd_repair_fec_pool_ele_const( self->fec_pool, blk->fecs[ fec_idx-1U ] );
    fd_repair_fec_t const * next_fec = fd_repair_fec_pool_ele_const( self->fec_pool, blk->fecs[ fec_idx    ] );

    if( FD_LIKELY( !prev_fec->data_complete || next_fec->update_parent.new_parent_slot==ULONG_MAX ) ) continue;
    if( FD_UNLIKELY( blk->init_fec_cnt==fec_idx ) ) continue;

    fd_update_parent_t const * update = &next_fec->update_parent;
    int                        eager  = meta->eager==fd_repair_blk_pool_idx( pool, blk );
    if( FD_UNLIKELY( eager && meta->invalidated ) ) continue;

    int bad = !fd_is_start_of_window( slot )                                            /* not in the first slot of its leader window */
              || blk->init_fec_cnt                                                      /* a second UpdateParent */
              || update->new_parent_slot<self->root                                    /* a parent below the root */
              || update->new_parent_slot>=slot                                          /* a parent newer than the header's */
              || ( eager && update->new_parent_slot>blk->init_parent_slot )             /* a parent newer than the header's */
              || !memcmp( &update->new_parent_block_id, &hash_null, sizeof(fd_mr32_t) ) /* a null parent block id */
              || ( eager && update->new_parent_slot==blk->parent_slot && !memcmp( &update->new_parent_block_id, &blk->parent_blk_mr, sizeof(fd_mr32_t) ) ); /* updating to the same thing */

    /* TODO: mark notarize blks invalid? */
    if( FD_UNLIKELY( bad && !eager ) ) { FD_LOG_WARNING(( "notarized blk at slot %lu has an invalid UpdateParent at fec set idx %u, ignoring it", slot, fec_idx*FD_FEC_SHRED_CNT )); continue; }
    if( FD_UNLIKELY( bad &&  eager ) ) { fd_repair_slot_invalidated( self, slot, FD_EVENT_BLOCK_RECEIVED_CANCELLED_REASON_INVALID_UPDATE_PARENT, ts ); continue; }

    if( FD_UNLIKELY( !eager ) ) {
      if( FD_UNLIKELY( blk->parent_slot!=ULONG_MAX && ( blk->parent_slot!=update->new_parent_slot || memcmp( &blk->parent_blk_mr, &update->new_parent_block_id, sizeof(fd_mr32_t) ) ) ) ) {
        FD_LOG_WARNING(( "notarized blk at slot %lu has an UpdateParent naming slot %lu, not its proven parent slot %lu, ignoring it", slot, update->new_parent_slot, blk->parent_slot ));
        continue;
      }
      blk->init_fec_cnt = fec_idx;
      blk->cons_fec_cnt = fd_uint_max( blk->cons_fec_cnt, fec_idx ); /* stream starts at the UpdateParent, prefix is skipped */
      continue;
    }

    if( FD_LIKELY( blk->parent!=null ) ) {
      ulong   idx  = fd_repair_blk_pool_idx( pool, blk );
      ulong * link = &fd_repair_blk_pool_ele( pool, blk->parent )->child;
      while( *link!=idx ) link = &fd_repair_blk_pool_ele( pool, *link )->sibling;
      *link        = blk->sibling;
      blk->parent  = null;
      blk->sibling = null;
    } else if( FD_LIKELY( blk!=self->root_blk && memcmp( &blk->parent_blk_mr, &hash_null, sizeof(fd_mr32_t) ) ) ) {
      fd_repair_orphan_map_ele_remove_fast( self->orphan_map, blk, pool );
    }

    blk->parent_slot   = update->new_parent_slot;
    blk->parent_blk_mr = update->new_parent_block_id;
    blk->init_fec_cnt  = fec_idx;
    blk->cons_fec_cnt  = fd_uint_max( blk->cons_fec_cnt, fec_idx ); /* stream starts at the UpdateParent, prefix is skipped */
    blk->orphan_req    = 0; /* an ORPHAN req for the header's parent is moot */

    fd_repair_orphan_map_ele_insert( self->orphan_map, blk, pool ); /* under the new key, link_parent takes it out if the new parent is held */
    if( FD_UNLIKELY( link_parent( self, blk ) ) ) continue;
    fd_repair_slot_meta_t * pmeta = fd_repair_slot_meta( self, blk->parent_slot );
    if( FD_UNLIKELY( pmeta->eager==null && pmeta->final==null && !pmeta->skipped && !pmeta->invalidated ) ) blk_insert( self, blk->parent_slot, &hash_null ); /* seed the new parent slot's eager blk */
    blk_treap_insert( self, blk ); /* its tile asks ORPHAN for the new parent */
  }
}

/* link_children links the orphans naming parent's (slot, dmr) under
   it: their headers named it before it was held, a notar blk just
   created or an eager blk that just completed.
   A final child makes the parent final, as connect_ancestors would. */

static void
link_children( fd_repair_t *     self,
               fd_repair_blk_t * parent ) {
  fd_repair_blk_t *       pool  = self->blk_pool;
  ulong                   null  = fd_repair_blk_pool_idx_null( pool );
  fd_repair_slot_meta_t * pmeta = fd_repair_slot_meta( self, parent->slot );
  fd_repair_blk_t *       next;
  for( fd_repair_blk_t * blk = fd_repair_orphan_map_ele_query( self->orphan_map, &parent->dmr, NULL, pool );
                         blk;
                         blk = next ) {
    next = (fd_repair_blk_t *)fd_repair_orphan_map_ele_next_const( blk, NULL, pool );
    if( FD_UNLIKELY( blk->parent_slot!=parent->slot ) ) continue;
    fd_repair_orphan_map_ele_remove_fast( self->orphan_map, blk, pool );
    blk->parent   = fd_repair_blk_pool_idx( pool, parent );
    blk->sibling  = parent->child;
    parent->child = fd_repair_blk_pool_idx( pool, blk );
    if( FD_UNLIKELY( fd_repair_slot_meta( self, blk->slot )->final==fd_repair_blk_pool_idx( pool, blk ) && pmeta->final==null ) ) promote( self, parent, &pmeta->final );
  }
}

static void
unlink( fd_repair_t *     self,
        fd_repair_blk_t * blk ) {
  fd_repair_blk_t * pool = self->blk_pool;
  ulong             null = fd_repair_blk_pool_idx_null( pool );
  ulong             idx  = fd_repair_blk_pool_idx( pool, blk );
  if( FD_LIKELY( blk->parent!=null ) ) {
    ulong * link = &fd_repair_blk_pool_ele( pool, blk->parent )->child;
    while( *link!=idx ) link = &fd_repair_blk_pool_ele( pool, *link )->sibling;
    *link = blk->sibling;
  }
  ulong next;
  for( ulong c=blk->child; c!=null; c=next ) {
    fd_repair_blk_t * child = fd_repair_blk_pool_ele( pool, c );
    next            = child->sibling;
    child->parent   = null;
    child->sibling  = null;
    if( FD_LIKELY(  child!=self->root_blk /* && child->parent==null */ && memcmp( &child->parent_blk_mr, &hash_null, sizeof(fd_mr32_t) ) ) ) {
      fd_repair_orphan_map_ele_insert( self->orphan_map, child, pool ); /* waits for blk's dmr again, should it be held again */
    }
  }
}

static void
prune( fd_repair_t *     self,
       fd_repair_blk_t * blk ) {
  fd_repair_blk_t * pool = self->blk_pool;
  if( FD_UNLIKELY( !blk->telemetry.reported && self->telemetry.report ) ) self->telemetry.report( self->telemetry.ctx, blk );
  for( ulong k=0UL; k<self->fec_blk_max; k++ ) {
    if( FD_LIKELY( blk->fecs[ k ]==fd_repair_fec_pool_idx_null( self->fec_pool ) ) ) continue;
    int held = 0;
    for( fd_repair_blk_t const * other = fd_repair_blk_map_ele_query_const( self->blk_map, &blk->slot, NULL, pool );
                                 other && !held;
                                 other = fd_repair_blk_map_ele_next_const( other, NULL, pool ) ) {
      held = other!=blk && other->fecs[ k ]==blk->fecs[ k ];
    }
    if( FD_UNLIKELY( held ) ) continue;
    fd_repair_fec_t * fec = fd_repair_fec_pool_ele( self->fec_pool, blk->fecs[ k ] );
    fd_repair_fec_map_ele_remove_fast( self->fec_map, fec, self->fec_pool );
    fd_repair_fec_pool_ele_release   ( self->fec_pool, fec );
  }
  unlink( self, blk );
  if( FD_UNLIKELY( blk!=self->root_blk && blk->parent==fd_repair_blk_pool_idx_null( pool ) && memcmp( &blk->parent_blk_mr, &hash_null, sizeof(fd_mr32_t) ) ) ) {
    fd_repair_orphan_map_ele_remove_fast( self->orphan_map, blk, pool );
  }
  blk_treap_remove( self, blk );
  fd_repair_slot_meta_t * meta = fd_repair_slot_meta( self, blk->slot );
  if( FD_UNLIKELY( meta->eager==fd_repair_blk_pool_idx( pool, blk ) ) ) meta->eager = fd_repair_blk_pool_idx_null( pool );
  if( FD_UNLIKELY( meta->notar==fd_repair_blk_pool_idx( pool, blk ) ) ) meta->notar = fd_repair_blk_pool_idx_null( pool );
  if( FD_UNLIKELY( meta->final==fd_repair_blk_pool_idx( pool, blk ) ) ) meta->final = fd_repair_blk_pool_idx_null( pool );
  fd_repair_blk_map_ele_remove_fast( self->blk_map, blk, pool );
  fd_repair_blk_pool_ele_release   ( pool, blk );
}

/* dedup checks for a duplicate of eager among the notar blks.  Only the
   eager blk can be duplicated, since notar blk DMRs are known a priori.

   Merge strategy if a duplicate is found:
   - eager is kept, notar is freed
   - eager inherits notar's children
   - eager takes notar's parent if it has none, as same DMR implies same
     parent

   Replay builds one bank for the block until then: consume holds notar
   behind eager, which delivers the FEC sets they share. */

static void
dedup( fd_repair_t *     self,
       fd_repair_blk_t * eager,
       long              ts ) {
  fd_repair_blk_t * pool = self->blk_pool;
  ulong             null = fd_repair_blk_pool_idx_null( pool );
  ulong             idx  = fd_repair_blk_pool_idx( pool, eager );

  fd_repair_blk_t * notar = fd_repair_blk_map_ele_query( self->blk_map, &eager->slot, NULL, pool );
  while( notar && ( notar==eager || memcmp( &notar->dmr, &eager->dmr, sizeof(fd_mr32_t) ) ) ) {
    notar = (fd_repair_blk_t *)fd_repair_blk_map_ele_next_const( notar, NULL, pool );
  }
  fd_repair_slot_meta_t * meta = fd_repair_slot_meta( self, eager->slot );
  if( FD_UNLIKELY( !notar && meta->final!=null ) ) {
    eager->telemetry.cancelled_ts     = fd_long_if( !eager->telemetry.cancelled_reason, ts, eager->telemetry.cancelled_ts );
    eager->telemetry.cancelled_reason = (uchar)FD_EVENT_BLOCK_RECEIVED_CANCELLED_REASON_NOTARIZED_VERSION;
    prune( self, eager );
    return;
  } /* turbine built a blk the cluster did not finalize */
  if( FD_LIKELY( !notar ) ) return;

  ulong next;
  for( ulong c=notar->child; c!=null; c=next ) {
    next                                       = fd_repair_blk_pool_ele( pool, c )->sibling;
    fd_repair_blk_pool_ele( pool, c )->parent  = idx;
    fd_repair_blk_pool_ele( pool, c )->sibling = eager->child;
    eager->child                               = c;
  }
  notar->child = null;
  if( FD_UNLIKELY( notar->parent!=null && eager->parent==null ) ) {
    if( FD_LIKELY( eager!=self->root_blk /* && eager->parent==null */ && memcmp( &eager->parent_blk_mr, &hash_null, sizeof(fd_mr32_t) ) ) ) {
      fd_repair_orphan_map_ele_remove_fast( self->orphan_map, eager, pool );
    }
    eager->parent                                        = notar->parent;
    eager->sibling                                       = fd_repair_blk_pool_ele( pool, notar->parent )->child;
    fd_repair_blk_pool_ele( pool, notar->parent )->child = idx;
  }
  blk_treap_remove( self, notar );
  if( FD_UNLIKELY( meta->final==fd_repair_blk_pool_idx( pool, notar ) ) ) { meta->final = null; promote( self, eager, &meta->final ); }
  if( FD_UNLIKELY( meta->notar==fd_repair_blk_pool_idx( pool, notar ) ) ) { meta->notar = null; promote( self, eager, &meta->notar ); }
  notar->telemetry.reported = 1; /* the same block lives on as eager, we won't report two different lines for this */

  eager->telemetry.req_window_cnt    += notar->telemetry.req_window_cnt;
  eager->telemetry.req_highest_cnt   += notar->telemetry.req_highest_cnt;
  eager->telemetry.req_orphan_cnt    += notar->telemetry.req_orphan_cnt;
  eager->telemetry.req_shred_bid_cnt += notar->telemetry.req_shred_bid_cnt;
  eager->telemetry.req_parent_cnt    += notar->telemetry.req_parent_cnt;
  eager->telemetry.req_fec_root_cnt  += notar->telemetry.req_fec_root_cnt;
  eager->telemetry.shred_res_cnt     += notar->telemetry.shred_res_cnt;
  eager->telemetry.parent_res_cnt    += notar->telemetry.parent_res_cnt;
  eager->telemetry.fec_root_res_cnt  += notar->telemetry.fec_root_res_cnt;
  /* first timestamps */
  eager->telemetry.first_req_ts       = fd_long_if( !eager->telemetry.first_req_ts      || ( notar->telemetry.first_req_ts      && notar->telemetry.first_req_ts     <eager->telemetry.first_req_ts      ), notar->telemetry.first_req_ts,      eager->telemetry.first_req_ts      );
  eager->telemetry.first_meta_res_ts  = fd_long_if( !eager->telemetry.first_meta_res_ts || ( notar->telemetry.first_meta_res_ts && notar->telemetry.first_meta_res_ts<eager->telemetry.first_meta_res_ts ), notar->telemetry.first_meta_res_ts, eager->telemetry.first_meta_res_ts );
  eager->telemetry.last_shred_res_ts  = fd_long_max( eager->telemetry.last_shred_res_ts, notar->telemetry.last_shred_res_ts );
  prune( self, notar );
  connect_ancestors( self, eager );
}

FD_FN_CONST ulong
fd_repair_align( void ) {
  return fd_ulong_max( alignof(fd_repair_t), 128UL );
}

FD_FN_CONST ulong
fd_repair_footprint( ulong slot_max,
                     ulong fec_max,
                     ulong fec_blk_max ) {
  ulong blk_max = ( 5UL*slot_max+1UL )/2UL;
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
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_INIT,
      fd_repair_align(),              sizeof(fd_repair_t)                                                        ),
      alignof(fd_repair_slot_meta_t), sizeof(fd_repair_slot_meta_t)*slot_max                                     ),
      fd_repair_blk_pool_align(),     fd_repair_blk_pool_footprint ( blk_max                                   ) ),
      alignof(ulong),                 sizeof(ulong)*blk_max*fec_blk_max                                          ),
      fd_repair_blk_map_align(),      fd_repair_blk_map_footprint   ( fd_repair_blk_map_chain_cnt_est( blk_max ) ) ),
      fd_repair_orphan_map_align(),   fd_repair_orphan_map_footprint( fd_repair_orphan_map_chain_cnt_est( blk_max ) ) ),
      fd_repair_fec_pool_align(),     fd_repair_fec_pool_footprint  ( fec_max                                    ) ),
      fd_repair_fec_map_align(),      fd_repair_fec_map_footprint   ( fd_repair_fec_map_chain_cnt_est( fec_max ) ) ),
      fd_repair_deque_align(),        fd_repair_deque_footprint     ( fec_max                                    ) ),
      fd_repair_treap_align(),        fd_repair_treap_footprint     ( blk_max                                    ) ),
      fd_repair_treap_align(),        fd_repair_treap_footprint     ( blk_max                                    ) ),
      fd_repair_treap_align(),        fd_repair_treap_footprint     ( blk_max                                    ) ),
    fd_repair_align() );
}

void *
fd_repair_new( void * shmem,
               ulong  slot_max,
               ulong  fec_max,
               ulong  fec_blk_max,
               ulong  seed ) {
  ulong footprint = fd_repair_footprint( slot_max, fec_max, fec_blk_max );
  if( FD_UNLIKELY( !footprint || fec_blk_max<FD_FEC_BLK_MAX || fec_blk_max>UINT_MAX ) ) {
    FD_LOG_WARNING(( "bad footprint: %lu %lu %lu", slot_max, fec_max, fec_blk_max ));
    return NULL;
  }

  fd_memset( shmem, 0, footprint );
  fd_repair_t * repair;

  ulong blk_max = ( 5UL*slot_max+1UL )/2UL;

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  repair             = FD_SCRATCH_ALLOC_APPEND( l, fd_repair_align(),              sizeof(fd_repair_t)                                                         );
  void * slot_meta   = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_repair_slot_meta_t), sizeof(fd_repair_slot_meta_t)*slot_max                                      );
  void * blk_pool    = FD_SCRATCH_ALLOC_APPEND( l, fd_repair_blk_pool_align(),     fd_repair_blk_pool_footprint ( blk_max                                   )  );
  ulong * blk_fecs   = FD_SCRATCH_ALLOC_APPEND( l, alignof(ulong),                 sizeof(ulong)*blk_max*fec_blk_max                                           );
  void * blk_map     = FD_SCRATCH_ALLOC_APPEND( l, fd_repair_blk_map_align(),      fd_repair_blk_map_footprint  ( fd_repair_blk_map_chain_cnt_est( blk_max ) ) );
  void * orphan_map  = FD_SCRATCH_ALLOC_APPEND( l, fd_repair_orphan_map_align(),   fd_repair_orphan_map_footprint( fd_repair_orphan_map_chain_cnt_est( blk_max ) ) );
  void * fec_pool    = FD_SCRATCH_ALLOC_APPEND( l, fd_repair_fec_pool_align(),     fd_repair_fec_pool_footprint ( fec_max                                    ) );
  void * fec_map     = FD_SCRATCH_ALLOC_APPEND( l, fd_repair_fec_map_align(),      fd_repair_fec_map_footprint  ( fd_repair_fec_map_chain_cnt_est( fec_max ) ) );
  void * reasm_deque = FD_SCRATCH_ALLOC_APPEND( l, fd_repair_deque_align(),        fd_repair_deque_footprint    ( fec_max                                    ) );
  void * eager_treap = FD_SCRATCH_ALLOC_APPEND( l, fd_repair_treap_align(),        fd_repair_treap_footprint    ( blk_max                                    ) );
  void * notar_treap = FD_SCRATCH_ALLOC_APPEND( l, fd_repair_treap_align(),        fd_repair_treap_footprint    ( blk_max                                    ) );
  void * final_treap = FD_SCRATCH_ALLOC_APPEND( l, fd_repair_treap_align(),        fd_repair_treap_footprint    ( blk_max                                    ) );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, fd_repair_align() ) == (ulong)shmem + footprint );

  repair->root        = ULONG_MAX;
  repair->slot_max    = slot_max;
  repair->fec_blk_max = fec_blk_max;
  repair->slot_meta   = (fd_repair_slot_meta_t *)slot_meta;
  for( ulong i=0UL; i<slot_max; i++ ) repair->slot_meta[ i ].slot = ULONG_MAX;
  repair->blk_pool    = fd_repair_blk_pool_join( fd_repair_blk_pool_new( blk_pool,    blk_max                                         ) );
  for( ulong i=0UL; i<blk_max; i++ ) repair->blk_pool[ i ].fecs = blk_fecs + i*fec_blk_max;
  repair->blk_map     = fd_repair_blk_map_join ( fd_repair_blk_map_new ( blk_map,     fd_repair_blk_map_chain_cnt_est( blk_max ), seed ) );
  repair->orphan_map  = fd_repair_orphan_map_join( fd_repair_orphan_map_new( orphan_map, fd_repair_orphan_map_chain_cnt_est( blk_max ), seed ) );
  repair->fec_pool    = fd_repair_fec_pool_join( fd_repair_fec_pool_new( fec_pool,    fec_max                                          ) );
  repair->fec_map     = fd_repair_fec_map_join ( fd_repair_fec_map_new ( fec_map,     fd_repair_fec_map_chain_cnt_est( fec_max ), seed ) );
  repair->reasm_deque = fd_repair_deque_join   ( fd_repair_deque_new   ( reasm_deque, fec_max                                          ) );
  fd_repair_treap_seed( repair->blk_pool, blk_max, seed ); /* the treaps share each blk's prio */
  repair->eager_treap = fd_repair_treap_join( fd_repair_treap_new( eager_treap, blk_max ) );
  repair->notar_treap = fd_repair_treap_join( fd_repair_treap_new( notar_treap, blk_max ) );
  repair->final_treap = fd_repair_treap_join( fd_repair_treap_new( final_treap, blk_max ) );

  return shmem;
}

fd_repair_t *
fd_repair_join( void * shrepair ) {
  return (fd_repair_t *)shrepair;
}

void *
fd_repair_leave( fd_repair_t const * self ) {
  return (void *)self;
}

void *
fd_repair_delete( void * shrepair ) {
  return shrepair;
}

void
fd_repair_init( fd_repair_t *         self,
                ulong                 root,
                fd_mr32_t const *     root_blk_mr,
                fd_repair_report_fn_t report,
                void *                report_ctx ) {
  self->telemetry.report = report;
  self->telemetry.ctx    = report_ctx;
  fd_repair_blk_t * blk = blk_insert( self, root, root_blk_mr );
  blk->telemetry.reported = 1; /* the root is not a received block */
  blk_treap_remove( self, blk ); /* the root is never repaired */
  fd_repair_slot_meta( self, root )->final = fd_repair_blk_pool_idx( self->blk_pool, blk );
  fd_repair_slot_meta( self, root )->eager = fd_repair_blk_pool_idx_null( self->blk_pool ); /* the genesis root has a null dmr, but is not turbine's */
  blk->eager           = 0;
  self->root           = root;
  self->root_blk       = blk;
  self->catchup_slot   = root;
}

void
fd_repair_fini( fd_repair_t * self ) {
  for( ulong i=0UL; i<self->slot_max; i++ ) self->slot_meta[ i ].slot = ULONG_MAX;
  fd_repair_blk_map_reset( self->blk_map );
  fd_repair_orphan_map_reset( self->orphan_map );
  fd_repair_blk_pool_reset( self->blk_pool );
  fd_repair_fec_map_reset( self->fec_map );
  fd_repair_fec_pool_reset( self->fec_pool );
  fd_repair_deque_remove_all( self->reasm_deque );
  self->eager_treap = fd_repair_treap_join( fd_repair_treap_new( fd_repair_treap_leave( self->eager_treap ), fd_repair_blk_pool_max( self->blk_pool ) ) );
  self->notar_treap = fd_repair_treap_join( fd_repair_treap_new( fd_repair_treap_leave( self->notar_treap ), fd_repair_blk_pool_max( self->blk_pool ) ) );
  self->final_treap = fd_repair_treap_join( fd_repair_treap_new( fd_repair_treap_leave( self->final_treap ), fd_repair_blk_pool_max( self->blk_pool ) ) );
  self->root         = ULONG_MAX;
  self->root_blk     = NULL;
  self->catchup_slot = 0UL;
  self->reconsume    = 0;
}

void
fd_repair_blk_dead( fd_repair_t *     self,
                    ulong             slot,
                    fd_mr32_t const * blk_mr,
                    uint              latest_fec_idx ) {
  fd_repair_blk_t * dead = fd_repair_blk_map_ele_query( self->blk_map, &slot, NULL, self->blk_pool );
  while( dead && memcmp( &dead->dmr, blk_mr, sizeof(fd_mr32_t) ) ) dead = (fd_repair_blk_t *)fd_repair_blk_map_ele_next_const( dead, NULL, self->blk_pool );
  if( FD_UNLIKELY( !dead ) ) return;

  fd_repair_slot_meta_t * meta   = fd_repair_slot_meta( self, slot );
  int                     eager  = meta->eager==fd_repair_blk_pool_idx( self->blk_pool, dead );
  uint                    bound  = dead->init_fec_cnt ? dead->init_fec_cnt*FD_FEC_SHRED_CNT : UINT_MAX; /* UINT_MAX latest_fec_idx (no FLH) is never a prefix */
  int                     prefix = eager && fd_is_start_of_window( slot ) && latest_fec_idx<bound;
  if( FD_UNLIKELY( prefix ) ) return; /* the optimistic prefix died, the block may still replay from an UpdateParent */

  blk_treap_remove( self, dead ); /* replay rejected it, no point repairing the rest */
  if( FD_LIKELY( !eager || meta->invalidated ) ) return;

  meta->invalidated = 1; /* turbine must not rebuild it */
  dead->eager       = 0; /* never repaired by position */
  if( FD_LIKELY( dead->parent!=fd_repair_blk_pool_idx_null( self->blk_pool ) ) ) cascade( self, fd_repair_blk_pool_ele( self->blk_pool, dead->parent ) ); /* delivers the notar blks held behind it */
}

fd_repair_blk_t *
fd_repair_blk_finalized( fd_repair_t *     self,
                         ulong             slot,
                         fd_mr32_t const * blk_mr,
                         long              ts ) {
  fd_repair_slot_meta_t * meta = fd_repair_slot_meta( self, slot );

  fd_repair_blk_t * fin = fd_repair_blk_map_ele_query( self->blk_map, &slot, NULL, self->blk_pool );
  while( fin && memcmp( &fin->dmr, blk_mr, sizeof(fd_mr32_t) ) ) fin = (fd_repair_blk_t *)fd_repair_blk_map_ele_next_const( fin, NULL, self->blk_pool );
  if( FD_UNLIKELY( !fin ) ) fin = fd_repair_blk_notarized( self, slot, blk_mr );
  if( FD_UNLIKELY( !fin ) ) return NULL; /* the slot is already finalized with another blk */

  fd_repair_blk_t * pool = self->blk_pool;
  promote( self, fin, &meta->final );
  /* The eager blk keeps its positional repair: peers without the whole
     block still serve its shreds, which by-id repair cannot ask them for. */

  /* Remove all equivocating blocks except the finalized one.  Their
     children name them, not the finalized blk, and are unlinked. */

  fd_repair_blk_t * next;
  for( fd_repair_blk_t * blk = fd_repair_blk_map_ele_query( self->blk_map, &slot, NULL, pool );
                         blk;
                         blk = next ) {
    next = (fd_repair_blk_t *)fd_repair_blk_map_ele_next_const( blk, NULL, pool );
    if( FD_LIKELY( blk==fin ) ) continue;
    if( FD_UNLIKELY( meta->eager==fd_repair_blk_pool_idx( pool, blk ) && !meta->invalidated && !memcmp( &blk->dmr, &hash_null, sizeof(fd_mr32_t) ) ) ) continue; /* turbine may still complete as the finalized blk, see dedup */
    blk->telemetry.cancelled_ts     = fd_long_if( !blk->telemetry.cancelled_reason, ts, blk->telemetry.cancelled_ts );
    blk->telemetry.cancelled_reason = (uchar)fd_int_if( !blk->telemetry.cancelled_reason, FD_EVENT_BLOCK_RECEIVED_CANCELLED_REASON_NOTARIZED_VERSION, blk->telemetry.cancelled_reason ); /* an invalidated eager blk keeps its reason */
    prune( self, blk );
  }
  connect_ancestors( self, fin );
  return fin;
}

fd_repair_blk_t *
fd_repair_blk_notarized( fd_repair_t *     self,
                         ulong             slot,
                         fd_mr32_t const * blk_mr ) {
  fd_repair_slot_meta_t *       meta = fd_repair_slot_meta( self, slot );
  if( FD_UNLIKELY( !memcmp( blk_mr, &hash_null, sizeof(fd_mr32_t) ) ) ) return NULL; /* never a real blk id, only turbine makes an eager blk */
  if( FD_UNLIKELY( meta->final!=fd_repair_blk_pool_idx_null( self->blk_pool ) || meta->skipped ) ) return NULL; /* the slot is settled */
  for( fd_repair_blk_t * dup = fd_repair_blk_map_ele_query( self->blk_map, &slot, NULL, self->blk_pool );
                         dup;
                         dup = (fd_repair_blk_t *)fd_repair_blk_map_ele_next_const( dup, NULL, self->blk_pool ) ) {
    if( FD_UNLIKELY( memcmp( &dup->dmr, blk_mr, sizeof(fd_mr32_t) ) ) ) continue;
    if( FD_LIKELY( meta->notar==fd_repair_blk_pool_idx_null( self->blk_pool ) ) ) promote( self, dup, &meta->notar ); /* already have it, now named */
    connect_ancestors( self, dup );
    return NULL;
  }
  fd_repair_blk_t * blk = blk_insert( self, slot, blk_mr );
  link_children( self, blk );
  return blk;
}

fd_repair_blk_t *
fd_repair_blk_parented( fd_repair_t *     self,
                        ulong             slot,
                        fd_mr32_t const * blk_mr,
                        ulong             parent_slot,
                        fd_mr32_t const * parent_blk_mr,
                        uint              fec_set_cnt,
                        long              ts ) {
  fd_repair_blk_t * blk = fd_repair_blk_map_ele_query( self->blk_map, &slot, NULL, self->blk_pool );
  while( FD_LIKELY( blk && memcmp( &blk->dmr, blk_mr, sizeof(fd_mr32_t) ) ) ) blk = (fd_repair_blk_t *)fd_repair_blk_map_ele_next_const( blk, NULL, self->blk_pool );
  if( FD_UNLIKELY( !blk                         ) ) return NULL; /* blk was pruned while the response was in flight */
  blk->telemetry.parent_res_cnt++;
  blk->telemetry.first_meta_res_ts = fd_long_if( !blk->telemetry.first_meta_res_ts, ts, blk->telemetry.first_meta_res_ts );

  if( FD_UNLIKELY( blk->parent_slot!=ULONG_MAX ) ) return NULL; /* duplicate response, eg. a retried request */
  if( FD_UNLIKELY( parent_slot>=slot           ) ) return NULL; /* a blk's parent precedes it */

  blk->parent_slot   = parent_slot;
  blk->parent_blk_mr = *parent_blk_mr;
  blk->cmpl_fec_cnt  = fec_set_cnt;
  blk_treap_insert( self, blk ); /* its FEC sets can be discovered now */

  if( FD_LIKELY( blk!=self->root_blk && blk->parent==fd_repair_blk_pool_idx_null( self->blk_pool ) && memcmp( &blk->parent_blk_mr, &hash_null, sizeof(fd_mr32_t) ) ) ) {
    fd_repair_orphan_map_ele_insert( self->orphan_map, blk, self->blk_pool ); /* names a parent now, link_parent takes it out if the parent is held */
  }

  fd_repair_blk_t * parent  = link_parent( self, blk );
  fd_repair_blk_t * created = NULL;
  if( FD_LIKELY( !parent )  ) parent = created = fd_repair_blk_notarized( self, parent_slot, parent_blk_mr ); /* links the child blks naming it */
  if( FD_LIKELY( parent ) ) {
    if( FD_UNLIKELY( fd_repair_slot_meta( self, slot )->final==fd_repair_blk_pool_idx( self->blk_pool, blk ) ) ) promote( self, parent, &fd_repair_slot_meta( self, parent_slot )->final ); /* finalized ancestry */
    consume( self, blk );
    if( FD_UNLIKELY( blk->cmpl_fec_cnt && blk->cons_fec_cnt==blk->cmpl_fec_cnt ) ) cascade( self, blk );
    if( FD_LIKELY( !created ) ) connect_ancestors( self, parent ); /* a held parent may itself be orphaned */
  }
  return created;
}

void
fd_repair_slot_catchup( fd_repair_t * self,
                        ulong         slot ) {
  for( ulong s=fd_ulong_max( self->root+1UL, self->catchup_slot ); s<slot; s++ ) {
    fd_repair_slot_meta_t * meta = fd_repair_slot_meta( self, s );
    if( FD_UNLIKELY( meta->skipped || meta->invalidated || meta->final!=fd_repair_blk_pool_idx_null( self->blk_pool ) || meta->eager!=fd_repair_blk_pool_idx_null( self->blk_pool ) ) ) continue;
    meta->eager = fd_repair_blk_pool_idx( self->blk_pool, blk_insert( self, s, &hash_null ) );
  }
  self->catchup_slot = fd_ulong_max( self->catchup_slot, slot );
}

fd_repair_fec_t *
fd_repair_fec_complete( fd_repair_t *      self,
                        fd_shred_t const * last_shred,
                        fd_mr32_t const *  fec_mr,
                        int                is_leader,
                        uint               turbine_cnt,
                        uint               repair_cnt,
                        uint               recovered_cnt,
                        uint               data_rcvd,
                        uint               parity_rcvd,
                        uint               repair_rcvd,
                        long               ts ) {
  fd_repair_shred_insert( self, last_shred, fec_mr, 0, ts ); /* the last shred's header, its source was given when it arrived */

  fd_mr20_t key;
  memcpy( key.uc, fec_mr->uc, sizeof(fd_mr20_t) );
  fd_repair_fec_t * fec = fd_repair_fec_map_ele_query( self->fec_map, &key, NULL, self->fec_pool );
  if( FD_UNLIKELY( !fec ) ) return NULL; /* fd_repair_shred_insert dropped it as conflicting with the eager blk */

  int first_complete = !fec->complete;
  fec->cmpl_ts       = fd_long_if( first_complete, ts, fec->cmpl_ts );
  fec->final_src     = fd_int_if( first_complete && is_leader, FD_EVENT_BLOCK_RECEIVED_FEC_SETS_FINAL_SHRED_SOURCE_LEADER, fec->final_src );
  fec->data_rcvd     = fd_uint_if( first_complete, data_rcvd,   fec->data_rcvd   );
  fec->parity_rcvd   = fd_uint_if( first_complete, parity_rcvd, fec->parity_rcvd );
  fec->repair_rcvd   = fd_uint_if( first_complete, repair_rcvd, fec->repair_rcvd );
  fec->mr32          = *fec_mr;
  fec->rcvd          = UINT_MAX;
  fec->complete      = 1;
  fec->data_complete = !!( last_shred->data.flags & FD_SHRED_DATA_FLAG_DATA_COMPLETE );
  fec->is_leader    |= !!is_leader; /* a completion again from the network does not clear our own */

  ulong                   slot  = last_shred->slot; /* fd_shred_t is packed, the map query needs an aligned key */
  fd_repair_slot_meta_t * meta  = fd_repair_slot_meta( self, slot );
  fd_repair_blk_t *       pool  = self->blk_pool;
  fd_repair_blk_t *       eager = fd_repair_blk_pool_ele( pool, meta->eager );
  int                     cmpl  = eager && !meta->invalidated && eager->cmpl_fec_cnt && !memcmp( &eager->dmr, &hash_null, sizeof(fd_mr32_t) );
  for( uint k=0U; cmpl && k<eager->cmpl_fec_cnt; k++ ) {
    cmpl = eager->fecs[ k ]!=fd_repair_fec_pool_idx_null( self->fec_pool ) && fd_repair_fec_pool_ele( self->fec_pool, eager->fecs[ k ] )->complete;
  }
  meta->leader |= (uint)!!is_leader;
  if( FD_UNLIKELY( is_leader && eager ) ) eager->eager = 0; /* our own, never repaired */
  if( FD_UNLIKELY( is_leader && eager && meta->final!=meta->eager && meta->notar!=meta->eager ) ) blk_treap_remove( self, eager );
  if( FD_UNLIKELY( cmpl ) ) {
    compute_dmr( self, eager );
    link_children( self, eager ); /* the blks naming its dmr waited for it */
    dedup( self, eager, ts );
    if( FD_UNLIKELY( fd_repair_fec_map_ele_query( self->fec_map, &key, NULL, self->fec_pool )!=fec ) ) return NULL; /* dedup pruned eager and with it the FEC set */
  }

  for( fd_repair_blk_t * blk = fd_repair_blk_map_ele_query( self->blk_map, &slot, NULL, pool );
                         blk;
                         blk = (fd_repair_blk_t *)fd_repair_blk_map_ele_next_const( blk, NULL, pool ) ) {
    if( FD_LIKELY( blk->fecs[ fec->fec_idx ]!=fd_repair_fec_pool_idx( self->fec_pool, fec ) ) ) continue;
    uint end = fd_uint_if( !!blk->cmpl_fec_cnt, blk->cmpl_fec_cnt, (uint)self->fec_blk_max );
    while(    blk->buff_fec_cnt<end
           && blk->fecs[ blk->buff_fec_cnt ]!=fd_repair_fec_pool_idx_null( self->fec_pool )
           && fd_repair_fec_pool_ele( self->fec_pool, blk->fecs[ blk->buff_fec_cnt ] )->complete ) {
      blk->buff_fec_cnt++;
    }
    if( FD_LIKELY( first_complete ) ) {
      blk->telemetry.turbine_shred_cnt   += turbine_cnt;
      blk->telemetry.repair_shred_cnt    += repair_cnt;
      blk->telemetry.recovered_shred_cnt += recovered_cnt;
      blk->telemetry.last_cmpl_fec_idx    = fec->fec_idx*FD_FEC_SHRED_CNT;
    }
    blk->telemetry.last_shred_ts = fd_long_if( blk->cmpl_fec_cnt && blk->buff_fec_cnt==blk->cmpl_fec_cnt && !blk->telemetry.last_shred_ts, ts, blk->telemetry.last_shred_ts );
    if( FD_UNLIKELY( blk->cmpl_fec_cnt && blk->buff_fec_cnt==blk->cmpl_fec_cnt && !blk->telemetry.reported && self->telemetry.report ) ) { blk->telemetry.reported = 1; self->telemetry.report( self->telemetry.ctx, blk ); }
    consume( self, blk );
    if( FD_UNLIKELY( blk->cmpl_fec_cnt && blk->cons_fec_cnt==blk->cmpl_fec_cnt ) ) cascade( self, blk );
  }
  return fec;
}

void
fd_repair_fec_evicted( fd_repair_t *     self,
                       ulong             slot,
                       uint              fec_set_idx,
                       fd_mr20_t const * fec_mr ) {
  uint              k   = fec_set_idx/FD_FEC_SHRED_CNT;
  fd_repair_fec_t * fec = fd_repair_fec_map_ele_query( self->fec_map, fec_mr, NULL, self->fec_pool );
  if( FD_UNLIKELY(  !fec || fec->complete || fec->slot!=slot || fec->fec_idx!=k ) ) return;

  fec->rcvd = 0U; /* its req, still waiting since the set is incomplete, asks for every shred again */
}

fd_repair_fec_t *
fd_repair_fec_notarized( fd_repair_t *     self,
                         ulong             slot,
                         fd_mr32_t const * blk_mr,
                         uint              fec_set_idx,
                         fd_mr20_t const * fec_mr,
                         long              ts ) {

  uint fec_idx = fec_set_idx / FD_FEC_SHRED_CNT;

  fd_repair_blk_t * blk = fd_repair_blk_map_ele_query( self->blk_map, &slot, NULL, self->blk_pool );
  while( blk && memcmp( &blk->dmr, blk_mr, sizeof(fd_mr32_t) ) ) blk = (fd_repair_blk_t *)fd_repair_blk_map_ele_next_const( blk, NULL, self->blk_pool );
  if( FD_UNLIKELY( !blk ) ) return NULL; /* blk was pruned while the response was in flight */
  blk->telemetry.fec_root_res_cnt++;
  blk->telemetry.first_meta_res_ts = fd_long_if( !blk->telemetry.first_meta_res_ts, ts, blk->telemetry.first_meta_res_ts );

  if( FD_UNLIKELY( blk->fecs[ fec_idx ]!=fd_repair_fec_pool_idx_null( self->fec_pool ) ) ) return NULL; /* duplicate response, eg. a retried request */

  fd_repair_slot_meta_t * meta  = fd_repair_slot_meta( self, slot );
  fd_repair_blk_t *       eager = fd_repair_blk_pool_ele( self->blk_pool, meta->eager );
  int                     eqvoc = eager && eager->fecs[ fec_idx ]!=fd_repair_fec_pool_idx_null( self->fec_pool ) && memcmp( &fd_repair_fec_pool_ele( self->fec_pool, eager->fecs[ fec_idx ] )->key, fec_mr, sizeof(fd_mr20_t) );
  if( FD_UNLIKELY( eqvoc  ) ) fd_repair_slot_invalidated( self, slot, FD_EVENT_BLOCK_RECEIVED_CANCELLED_REASON_MERKLE_ROOT_MISMATCH, ts );

  fd_repair_fec_t * fec = fd_repair_fec_map_ele_query( self->fec_map, fec_mr, NULL, self->fec_pool );
  if( FD_UNLIKELY( fec && ( fec->slot!=slot || fec->fec_idx!=fec_idx ) ) ) return NULL; /* a FEC set root commits to its slot and index, so this leaf names no FEC set a shred can fill */
  if( FD_UNLIKELY( !fec ) ) {
    FD_TEST( fd_repair_fec_pool_free( self->fec_pool ) );
    fec                = fd_repair_fec_pool_ele_acquire( self->fec_pool );
    fec->key           = *fec_mr;
    fec->mr32          = hash_null;
    fec->fec_idx       = fec_idx;
    fec->slot          = slot;
    fec->rcvd          = 0U;
    fec->complete      = 0;
    fec->data_complete = 0;
    fec->final_src     = 0;
    fec->first_ts      = 0L;
    fec->cmpl_ts       = 0L;
    fec->is_leader     = 0;
    fec->data_rcvd     = 0U;
    fec->parity_rcvd   = 0U;
    fec->repair_rcvd   = 0U;
    fec->update_parent.new_parent_slot = ULONG_MAX;
    fd_repair_fec_map_ele_insert( self->fec_map, fec, self->fec_pool );
  }
  fec->notarized       = 1;
  blk->fecs[ fec_idx ] = fd_repair_fec_pool_idx( self->fec_pool, fec );

  if( FD_UNLIKELY( fec->update_parent.new_parent_slot!=ULONG_MAX ) ) handle_update_parent( self, slot, fec_idx,    ts );
  if( FD_UNLIKELY( fec->data_complete                            ) ) handle_update_parent( self, slot, fec_idx+1U, ts );

  if( FD_LIKELY( !fec->complete ) ) return fec;

  uint end = fd_uint_if( !!blk->cmpl_fec_cnt, blk->cmpl_fec_cnt, (uint)self->fec_blk_max );
  while(    blk->buff_fec_cnt<end
         && blk->fecs[ blk->buff_fec_cnt ]!=fd_repair_fec_pool_idx_null( self->fec_pool )
         && fd_repair_fec_pool_ele( self->fec_pool, blk->fecs[ blk->buff_fec_cnt ] )->complete ) {
    blk->buff_fec_cnt++;
  }
  if( FD_UNLIKELY( blk->cmpl_fec_cnt && blk->buff_fec_cnt==blk->cmpl_fec_cnt && !blk->telemetry.reported && self->telemetry.report ) ) { blk->telemetry.reported = 1; self->telemetry.report( self->telemetry.ctx, blk ); }
  consume( self, blk );
  if( FD_UNLIKELY( blk->cmpl_fec_cnt && blk->cons_fec_cnt==blk->cmpl_fec_cnt ) ) cascade( self, blk );
  return fec;
}

void
fd_repair_root_advanced( fd_repair_t *     self,
                         ulong             slot,
                         fd_mr32_t const * blk_mr ) {
  ulong             root     = self->root;
  fd_repair_blk_t * root_blk = NULL; /* the new root, if held. self->root_blk is the old root until freed below: it left orphan_map on becoming root and must not be removed again */
  for( ulong s=root; s<=slot; s++ ) {
    fd_repair_blk_t * next;
    for( fd_repair_blk_t * blk = fd_repair_blk_map_ele_query( self->blk_map, &s, NULL, self->blk_pool );
                           blk;
                           blk = next ) {
      next = (fd_repair_blk_t *)fd_repair_blk_map_ele_next_const( blk, NULL, self->blk_pool );
      if( FD_UNLIKELY( !blk->telemetry.reported && self->telemetry.report ) ) { blk->telemetry.reported = 1; self->telemetry.report( self->telemetry.ctx, blk ); }
      for( ulong k=0UL; k<self->fec_blk_max; k++ ) {
        ulong idx = blk->fecs[ k ];
        blk->fecs[ k ] = fd_repair_fec_pool_idx_null( self->fec_pool );
        if( FD_LIKELY( idx==fd_repair_fec_pool_idx_null( self->fec_pool ) ) ) continue;
        fd_repair_fec_t * fec = fd_repair_fec_pool_ele( self->fec_pool, idx );
        if( FD_LIKELY( fd_repair_fec_map_ele_query( self->fec_map, &fec->key, NULL, self->fec_pool )!=fec ) ) continue; /* freed through a sibling */
        fd_repair_fec_map_ele_remove_fast( self->fec_map, fec, self->fec_pool );
        fd_repair_fec_pool_ele_release   ( self->fec_pool, fec );
      }
      if( FD_UNLIKELY( s==slot && !memcmp( &blk->dmr, blk_mr, sizeof(fd_mr32_t) ) ) ) { /* the new root */
        blk_treap_remove( self, blk ); /* the root is never repaired */
        if( FD_LIKELY( blk!=self->root_blk && blk->parent==fd_repair_blk_pool_idx_null( self->blk_pool ) && memcmp( &blk->parent_blk_mr, &hash_null, sizeof(fd_mr32_t) ) ) ) {
          fd_repair_orphan_map_ele_remove_fast( self->orphan_map, blk, self->blk_pool ); /* its parent was just freed, the root waits for nothing */
        }
        fd_repair_slot_meta( self, slot )->final = fd_repair_blk_pool_idx( self->blk_pool, blk );
        blk->eager = 0;
        root_blk   = blk;
        continue;
      }

      unlink( self, blk );
      if( FD_UNLIKELY( blk!=self->root_blk && blk->parent==fd_repair_blk_pool_idx_null( self->blk_pool ) && memcmp( &blk->parent_blk_mr, &hash_null, sizeof(fd_mr32_t) ) ) ) fd_repair_orphan_map_ele_remove_fast( self->orphan_map, blk, self->blk_pool );
      blk_treap_remove( self, blk );
      fd_repair_slot_meta_t * meta = fd_repair_slot_meta( self, s );
      if( FD_UNLIKELY( meta->eager==fd_repair_blk_pool_idx( self->blk_pool, blk ) ) ) meta->eager = fd_repair_blk_pool_idx_null( self->blk_pool ); /* the root slot's meta stays live, its roles must not name freed blks */
      if( FD_UNLIKELY( meta->notar==fd_repair_blk_pool_idx( self->blk_pool, blk ) ) ) meta->notar = fd_repair_blk_pool_idx_null( self->blk_pool );
      fd_repair_blk_map_ele_remove_fast( self->blk_map, blk, self->blk_pool );
      fd_repair_blk_pool_ele_release   ( self->blk_pool, blk );
    }
  }
  self->root_blk = root_blk;
  self->root     = slot;
}

void
fd_repair_shred_insert( fd_repair_t *      self,
                        fd_shred_t const * shred,
                        fd_mr32_t const *  fec_mr,
                        int                src,
                        long               ts ) {

  fd_mr20_t key;
  memcpy( key.uc, fec_mr->uc, sizeof(fd_mr20_t) );

  /* First, handle a Notar shred (shred for a FEC set that has already
     reached a notarized status ie. SafeToNotar or stronger).  It also
     belongs to the eager blk, so fall through. */

  fd_repair_fec_t * fec     = fd_repair_fec_map_ele_query( self->fec_map, &key, NULL, self->fec_pool );
  uint              fec_idx = shred->idx / FD_FEC_SHRED_CNT;
  if( FD_UNLIKELY(  fec && ( fec->slot!=shred->slot || fec->fec_idx!=fec_idx ) ) ) return; /* a 20-byte root collision */
  if( FD_UNLIKELY(  fec && fec->notarized ) ) fec->rcvd = fd_uint_set_bit( fec->rcvd, (int)( shred->idx - fec_idx * FD_FEC_SHRED_CNT ) );
  if( FD_UNLIKELY(  fec && !fec->first_ts ) ) fec->first_ts = ts;
  if( FD_LIKELY( fec && src && !fec->complete ) ) fec->final_src = src; /* frozen once complete */

  fd_block_marker_t update[1];
  int update_parent = shred->idx%FD_FEC_SHRED_CNT==0U && shred->idx && !fd_block_marker_de( update, fd_shred_data_payload( shred ), fd_shred_payload_sz( shred ) ) && update->kind==FD_BLOCK_MARKER_KIND_UPDATE_PARENT;
  int data_complete = !!( shred->data.flags & FD_SHRED_DATA_FLAG_DATA_COMPLETE );

  if( FD_UNLIKELY( update_parent && fec ) ) { fec->update_parent = update->update_parent; handle_update_parent( self, shred->slot, fec_idx,    ts ); }
  if( FD_UNLIKELY( data_complete && fec ) ) { fec->data_complete = 1;                     handle_update_parent( self, shred->slot, fec_idx+1U, ts ); }

  /* Second, handle an Eager shred (from Turbine or Eager Repair). */

  ulong                   parent_slot = shred->slot - shred->data.parent_off;
  fd_repair_blk_t *       pool        = self->blk_pool;
  ulong                   null        = fd_repair_blk_pool_idx_null( pool );
  fd_repair_slot_meta_t * meta        = fd_repair_slot_meta( self, shred->slot );
  fd_repair_blk_t const * fin         = fd_repair_blk_pool_ele_const( pool, meta->final );
  int                     fin_done    = fin && fin->cmpl_fec_cnt && fin->buff_fec_cnt==fin->cmpl_fec_cnt;

  if( FD_UNLIKELY( meta->skipped || meta->invalidated || ( fin_done && meta->eager==null ) ) ) return; /* a final cert ahead of turbine still lets turbine build the blk, dedup merges it */
  if( FD_UNLIKELY( meta->eager==null ) ) meta->eager = fd_repair_blk_pool_idx( pool, blk_insert( self, shred->slot, &hash_null ) );
  fd_repair_blk_t * blk = fd_repair_blk_pool_ele( pool, meta->eager );
  if( FD_UNLIKELY( blk->parent_slot==ULONG_MAX      ) ) blk->parent_slot      = parent_slot; /* created empty by a child or catchup */
  if( FD_UNLIKELY( blk->init_parent_slot==ULONG_MAX ) ) blk->init_parent_slot = parent_slot;

  /* Check for misbehavior that can invalidate the eager block. */

  fd_block_marker_t marker[1];
  int               bad_header    = shred->idx==0U && ( fd_block_marker_de( marker, fd_shred_data_payload( shred ), fd_shred_payload_sz( shred ) ) || marker->kind!=FD_BLOCK_MARKER_KIND_HEADER || marker->header.parent_slot!=parent_slot );
  fd_mr32_t const * parent_blk_mr = ( shred->idx==0U && !blk->init_fec_cnt ) ? &marker->header.parent_block_id : NULL;

  int slot_complete     = !!( shred->data.flags & FD_SHRED_DATA_FLAG_SLOT_COMPLETE );
  int eqvoc             = blk->fecs[ fec_idx ]!=fd_repair_fec_pool_idx_null( self->fec_pool ) && blk->fecs[ fec_idx ]!=fd_repair_fec_pool_idx( self->fec_pool, fec ); /* the leader signed two FEC sets at this index, eg. two shred 0s */
  int parent_conflict   = bad_header || blk->init_parent_slot!=parent_slot;
  int complete_conflict = ( blk->cmpl_fec_cnt && fec_idx>=blk->cmpl_fec_cnt ) || ( slot_complete && fec_idx+1U<blk->rcvd_fec_cnt );
  if( FD_UNLIKELY( eqvoc ) )             { fd_repair_slot_invalidated( self, shred->slot, FD_EVENT_BLOCK_RECEIVED_CANCELLED_REASON_MERKLE_ROOT_MISMATCH, ts ); return; }
  if( FD_UNLIKELY( parent_conflict ) )   { fd_repair_slot_invalidated( self, shred->slot, bad_header ? FD_EVENT_BLOCK_RECEIVED_CANCELLED_REASON_INVALID_BLOCK_HEADER : FD_EVENT_BLOCK_RECEIVED_CANCELLED_REASON_PARENT_OFF_MISMATCH, ts ); return; }
  if( FD_UNLIKELY( complete_conflict ) ) { fd_repair_slot_invalidated( self, shred->slot, FD_EVENT_BLOCK_RECEIVED_CANCELLED_REASON_SLOT_COMPLETE_MISMATCH, ts ); return; }
  if( FD_UNLIKELY( shred->idx==0U && blk->init_fec_cnt && marker->header.parent_slot==blk->parent_slot && !memcmp( &marker->header.parent_block_id, &blk->parent_blk_mr, sizeof(fd_mr32_t) ) ) ) {
    /* a late shred 0 header == UpdateParent's parent */
    fd_repair_slot_invalidated( self, shred->slot, FD_EVENT_BLOCK_RECEIVED_CANCELLED_REASON_INVALID_UPDATE_PARENT, ts );
    return;
  }

  if( FD_UNLIKELY( parent_blk_mr ) ) { /* shred 0 again names the same parent, the key must not change while in orphan_map */
    if( FD_UNLIKELY( blk!=self->root_blk && blk->parent==null && memcmp( &blk->parent_blk_mr, &hash_null, sizeof(fd_mr32_t) ) ) ) fd_repair_orphan_map_ele_remove_fast( self->orphan_map, blk, pool );
    blk->parent_blk_mr = *parent_blk_mr;
    if( FD_LIKELY  ( blk!=self->root_blk && blk->parent==null && memcmp( &blk->parent_blk_mr, &hash_null, sizeof(fd_mr32_t) ) ) ) fd_repair_orphan_map_ele_insert     ( self->orphan_map, blk, pool );
  }
  if( FD_UNLIKELY( parent_blk_mr && blk->parent==null && !link_parent( self, blk ) ) ) { /* waits unlinked for the named parent to be held, eg. to complete on turbine */
    fd_repair_slot_meta_t * pmeta = fd_repair_slot_meta( self, parent_slot );
    if( FD_UNLIKELY( pmeta->eager==null && pmeta->final==null && !pmeta->skipped && !pmeta->invalidated ) ) blk_insert( self, parent_slot, &hash_null ); /* seed the parent slot's eager blk, turbine may have lost it */
  }
  if( FD_UNLIKELY( slot_complete ) ) blk->cmpl_fec_cnt = fec_idx+1U;
  if( FD_UNLIKELY( slot_complete || fec_idx+1U>blk->rcvd_fec_cnt ) ) { /* its repair limit moved */
    blk->rcvd_fec_ts = fd_long_if( fec_idx+1U>blk->rcvd_fec_cnt, ts, blk->rcvd_fec_ts );
    blk_treap_insert( self, blk );
  }

  if( FD_UNLIKELY( !fec ) ) {
    FD_TEST( fd_repair_fec_pool_free( self->fec_pool ) );
    fec                = fd_repair_fec_pool_ele_acquire( self->fec_pool );
    fec->key           = key;
    fec->mr32          = hash_null;
    fec->fec_idx       = fec_idx;
    fec->slot          = shred->slot;
    fec->rcvd          = 0U;
    fec->complete      = 0;
    fec->data_complete = 0;
    fec->final_src     = src;
    fec->first_ts      = ts;
    fec->cmpl_ts       = 0L;
    fec->is_leader     = 0;
    fec->notarized     = 0;
    fec->data_rcvd     = 0U;
    fec->parity_rcvd   = 0U;
    fec->repair_rcvd   = 0U;
    fec->update_parent.new_parent_slot = ULONG_MAX;
    fd_repair_fec_map_ele_insert( self->fec_map, fec, self->fec_pool );
  }
  blk->fecs[ fec_idx ] = fd_repair_fec_pool_idx( self->fec_pool, fec );
  blk->rcvd_fec_cnt    = fd_uint_max( blk->rcvd_fec_cnt, fec_idx+1U );
  fec->rcvd            = fd_uint_set_bit( fec->rcvd, (int)( shred->idx - fec_idx*FD_FEC_SHRED_CNT ) );

  if( FD_UNLIKELY( update_parent ) ) { fec->update_parent = update->update_parent; handle_update_parent( self, shred->slot, fec_idx,    ts ); }
  if( FD_UNLIKELY( data_complete ) ) { fec->data_complete = 1;                     handle_update_parent( self, shred->slot, fec_idx+1U, ts ); }
}

void
fd_repair_slot_invalidated( fd_repair_t * self,
                            ulong         slot,
                            int           reason,
                            long          ts ) {
  fd_repair_slot_meta_t * meta  = fd_repair_slot_meta( self, slot );
  fd_repair_blk_t *       eager = fd_repair_blk_pool_ele( self->blk_pool, meta->eager );
  int                     first = !meta->invalidated;
  meta->invalidated = 1;
  if( FD_LIKELY( eager ) ) {
    eager->telemetry.cancelled_ts     = fd_long_if( !eager->telemetry.cancelled_reason, ts, eager->telemetry.cancelled_ts );
    eager->telemetry.cancelled_reason = (uchar)reason;
    eager->eager = 0;
  }
  if( FD_LIKELY( eager && meta->final!=meta->eager && meta->notar!=meta->eager ) ) blk_treap_remove( self, eager ); /* still the eager blk, never repaired */
  if( FD_LIKELY( first && eager && eager->parent!=fd_repair_blk_pool_idx_null( self->blk_pool ) ) ) cascade( self, fd_repair_blk_pool_ele( self->blk_pool, eager->parent ) ); /* delivers the notar blks held behind it */
}

fd_repair_slot_meta_t *
fd_repair_slot_meta( fd_repair_t * self,
                     ulong         slot ) {
  fd_repair_slot_meta_t * meta = &self->slot_meta[ slot % self->slot_max ];
  if( FD_UNLIKELY( meta->slot!=slot ) ) {
    meta->slot        = slot;
    meta->eager       = fd_repair_blk_pool_idx_null( self->blk_pool );
    meta->notar       = fd_repair_blk_pool_idx_null( self->blk_pool );
    meta->final       = fd_repair_blk_pool_idx_null( self->blk_pool );
    meta->invalidated = 0;
    meta->skipped     = 0;
    meta->leader      = 0;
  }
  return meta;
}

void
fd_repair_slot_skipped( fd_repair_t * self,
                        ulong         slot ) {
  fd_repair_slot_meta_t * meta = fd_repair_slot_meta( self, slot );
  meta->skipped = 1; /* late repair requests or shreds for the slot must not recreate blks in it */

  fd_repair_blk_t * next;
  for( fd_repair_blk_t * blk = fd_repair_blk_map_ele_query( self->blk_map, &slot, NULL, self->blk_pool );
                         blk;
                         blk = next ) {
    next = (fd_repair_blk_t *)fd_repair_blk_map_ele_next_const( blk, NULL, self->blk_pool );
    prune( self, blk );
  }
}
