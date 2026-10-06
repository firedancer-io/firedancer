#include "fd_rotor.h"
#include "../../ballet/bmtree/fd_bmtree.h"
#include "../../ballet/sha256/fd_sha256.h"
#include "../../flamenco/alpenglow/fd_block_marker_serde.h"
#include "../../disco/events/generated/fd_event_gen.h"

static void
blk_treap_insert( fd_rotor_t *     rotor,
                  fd_rotor_blk_t * blk ) {
  fd_rotor_slot_meta_t const * meta = fd_rotor_slot_meta( rotor, blk->slot );
  ulong                        idx  = blk_pool_idx( rotor->blk_pool, blk );
  if( FD_UNLIKELY( blk->in_blk_treap ) ) return;
  if( FD_UNLIKELY( meta->final!=idx && meta->notar!=idx && meta->eager==idx && !blk->eager ) ) return;
  fd_rotor_treap_ele_insert( meta->final==idx ? rotor->final_treap : meta->notar==idx ? rotor->notar_treap : rotor->eager_treap, blk, rotor->blk_pool );
  blk->in_blk_treap = 1;
}

static void
blk_treap_remove( fd_rotor_t *     rotor,
                  fd_rotor_blk_t * blk ) {
  if( FD_LIKELY( !blk->in_blk_treap ) ) return;
  fd_rotor_slot_meta_t const * meta = fd_rotor_slot_meta( rotor, blk->slot );
  ulong                        idx  = blk_pool_idx( rotor->blk_pool, blk );
  fd_rotor_treap_ele_remove( meta->final==idx ? rotor->final_treap : meta->notar==idx ? rotor->notar_treap : rotor->eager_treap, blk, rotor->blk_pool );
  blk->in_blk_treap = 0;
}

/* blk_insert creates a blk of slot named dmr (null for an eager blk)
   with nothing received yet.  An eager blk is the slot's eager blk. */

static fd_rotor_blk_t *
blk_insert( fd_rotor_t *      rotor,
            ulong             slot,
            fd_mr32_t const * dmr ) {
  FD_TEST( blk_pool_free( rotor->blk_pool ) );
  fd_rotor_slot_meta_t *       meta = fd_rotor_slot_meta( rotor, slot );
  fd_rotor_blk_t *             blk  = blk_pool_ele_acquire( rotor->blk_pool );
  blk->slot          = slot;
  blk->dmr           = *dmr;
  blk->parent        = blk_pool_idx_null( rotor->blk_pool );
  blk->child         = blk_pool_idx_null( rotor->blk_pool );
  blk->sibling       = blk_pool_idx_null( rotor->blk_pool );
  blk->connected     = 0;
  blk->cmpl_fec_cnt  = 0U;
  blk->rcvd_fec_cnt  = 0U;
  blk->buff_fec_cnt  = 0U;
  blk->cons_fec_cnt  = 0U;
  blk->wait_fec_cnt  = 0U;
  blk->parent_slot   = ULONG_MAX;
  blk->parent_blk_mr = hash_null;
  blk->in_blk_treap  = 0;
  blk->eager         = (!memcmp( dmr, &hash_null, sizeof(fd_mr32_t)) && !meta->invalidated && meta->final==blk_pool_idx_null( rotor->blk_pool ) && !meta->leader );
  blk->meta_req      = 0;
  blk->highest_req   = 0;
  blk->orphan_req    = 0;
  blk->telemetry.cancelled_reason = 0;
  blk->telemetry.reported         = 0;
  blk->rcvd_fec_ts   = 0L;
  for( ulong k=0UL; k<FD_FEC_BLK_MAX; k++ ) blk->fecs[ k ] = fec_pool_idx_null( rotor->fec_pool );
  blk_map_ele_insert( rotor->blk_map, blk, rotor->blk_pool );
  if     ( !memcmp( dmr, &hash_null, sizeof(fd_mr32_t) )    ) meta->eager = blk_pool_idx( rotor->blk_pool, blk );
  else if( meta->notar==blk_pool_idx_null( rotor->blk_pool ) ) meta->notar = blk_pool_idx( rotor->blk_pool, blk );
  blk_treap_insert( rotor, blk );
  return blk;
}

/* compute_dmr computes the double merkle root of a complete eager blk:
   the merkle tree over its FEC set roots, then a parent info leaf. */

static void
compute_dmr( fd_rotor_t *     rotor,
             fd_rotor_blk_t * blk ) {
  uint fec_set_cnt = blk->cmpl_fec_cnt;

  uchar tree_mem[ FD_BMTREE_COMMIT_FOOTPRINT( 0UL ) ] __attribute__((aligned(FD_BMTREE_COMMIT_ALIGN)));
  fd_bmtree_commit_t * tree = fd_bmtree_commit_init( tree_mem, FD_SHRED_MERKLE_NODE_SZ, FD_BMTREE_LONG_PREFIX_SZ, 0UL );
  for( uint k=0U; k<fec_set_cnt; k++ ) {
    fd_bmtree_node_t leaf[1];
    memcpy( leaf->hash, fec_pool_ele( rotor->fec_pool, blk->fecs[ k ] )->mr32.uc, sizeof(fd_mr32_t) );
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

/* consume pushes buffered FECs onto the reasm queue. */

static void
consume( fd_rotor_t *     rotor,
         fd_rotor_blk_t * blk ) {
  fd_rotor_slot_meta_t const * meta = fd_rotor_slot_meta( rotor, blk->slot );
  if( FD_UNLIKELY( meta->invalidated && !memcmp( &blk->dmr, &hash_null, sizeof(fd_mr32_t) ) ) ) return;
  if( FD_UNLIKELY( blk->parent==blk_pool_idx_null( rotor->blk_pool ) ) ) return; /* orphaned, even if partly consumed */
  if( FD_UNLIKELY( !blk->cons_fec_cnt ) ) {
    fd_rotor_blk_t const * parent = blk_pool_ele_const( rotor->blk_pool, blk->parent );
    if( FD_LIKELY( parent->slot!=rotor->root && ( !parent->cmpl_fec_cnt || parent->cons_fec_cnt!=parent->cmpl_fec_cnt ) ) ) return;
  }
  ulong idx = blk_pool_idx( rotor->blk_pool, blk );
  if( FD_UNLIKELY( meta->leader && meta->eager==idx ) ) { /* our leader blk goes first, in FEC order */
    for( uint k=blk->buff_fec_cnt; k>blk->cons_fec_cnt; k-- ) fd_rotor_deque_push_head( rotor->reasm_deque, (fd_rotor_deque_t){ .blk_idx = (uint)idx, .fec_idx = k-1U } );
    blk->cons_fec_cnt = blk->buff_fec_cnt;
    return;
  }
  for( ; blk->cons_fec_cnt<blk->buff_fec_cnt; blk->cons_fec_cnt++ ) fd_rotor_deque_push_tail( rotor->reasm_deque, (fd_rotor_deque_t){ .blk_idx = (uint)idx, .fec_idx = blk->cons_fec_cnt } );
}

/* cascade performs a stackless (ie. O(1) space) preorder traversal. */

static void
cascade( fd_rotor_t *     rotor,
         fd_rotor_blk_t * root ) {
  fd_rotor_blk_t * pool = rotor->blk_pool;
  ulong            null = blk_pool_idx_null( pool );
  ulong            tidx = blk_pool_idx( pool, root );
  ulong            idx  = root->child;
  while( FD_LIKELY( idx!=null ) ) {
    fd_rotor_blk_t * blk = blk_pool_ele( pool, idx );
    consume( rotor, blk );
    if( FD_LIKELY( blk->cmpl_fec_cnt && blk->cons_fec_cnt==blk->cmpl_fec_cnt && blk->child!=null ) ) { idx = blk->child; continue; }
    while( FD_LIKELY( idx!=tidx && blk_pool_ele( pool, idx )->sibling==null ) ) idx = blk_pool_ele( pool, idx )->parent;
    if( FD_UNLIKELY( idx==tidx ) ) break;
    idx = blk_pool_ele( pool, idx )->sibling;
  }
}

/* promote gives blk the slot_meta role (notar or final), moving it to
   that role's treap if it was in one.  A blk with a role is not
   repaired by position. */

static void
promote( fd_rotor_t *     rotor,
         fd_rotor_blk_t * blk,
         ulong *          role ) {
  if( FD_LIKELY( *role==blk_pool_idx( rotor->blk_pool, blk ) ) ) return;
  int in_blk_treap = blk->in_blk_treap;
  blk_treap_remove( rotor, blk );
  *role      = blk_pool_idx( rotor->blk_pool, blk );
  blk->eager = 0;
  if( FD_LIKELY( in_blk_treap ) ) blk_treap_insert( rotor, blk );
}

/* connect_ancestors links a notar or final blk to its ancestors via
   parent dmr until a connected one, marking each blk it walks stale (-1)
   and returning the highest ancestor walked for connect_descendants. */

static fd_rotor_blk_t *
connect_ancestors( fd_rotor_t *     rotor,
                   fd_rotor_blk_t * blk ) {
  fd_rotor_blk_t * pool = rotor->blk_pool;
  ulong            null = blk_pool_idx_null( pool );
  for(;;) {
    blk->connected = -1; /* on the path connect_descendants walks */
    if( FD_UNLIKELY( blk->parent_slot==ULONG_MAX || blk->parent_slot<rotor->root ) ) break;
    fd_rotor_slot_meta_t * meta   = fd_rotor_slot_meta( rotor, blk->slot );
    fd_rotor_slot_meta_t * pmeta  = fd_rotor_slot_meta( rotor, blk->parent_slot );
    int                    final  = meta->final==blk_pool_idx( pool, blk );
    fd_rotor_blk_t *       linked = blk_pool_ele( pool, blk->parent );
    fd_rotor_blk_t *       parent = blk_map_ele_query( rotor->blk_map, &blk->parent_slot, NULL, pool );
    while( FD_LIKELY( parent && ( memcmp( &parent->dmr, &blk->parent_blk_mr, sizeof(fd_mr32_t) ) || ( blk->parent_slot!=rotor->root && !memcmp( &parent->dmr, &hash_null, sizeof(fd_mr32_t) ) ) ) ) ) {
      parent = (fd_rotor_blk_t *)blk_map_ele_next_const( parent, NULL, pool );
    }
    if( FD_UNLIKELY( !parent && blk->parent_slot==rotor->root ) ) break; /* names a root other than ours */
    int held = !!parent;
    if( FD_UNLIKELY( !parent ) ) parent = fd_rotor_blk_notarized( rotor, blk->parent_slot, &blk->parent_blk_mr );
    if( FD_UNLIKELY( !parent ) ) break; /* the parent slot is settled otherwise */
    if( FD_UNLIKELY( !held ) ) blk_treap_insert( rotor, blk ); /* its tile asks ORPHAN for eager ancestry, which may merge with the named parents */
    if( FD_UNLIKELY( linked!=parent ) ) {
      if( FD_UNLIKELY( linked ) ) { /* an unfinished eager blk turbine guessed */
        ulong * link = &linked->child;
        while( *link!=blk_pool_idx( pool, blk ) ) link = &blk_pool_ele( pool, *link )->sibling;
        *link = blk->sibling;
      }
      blk->parent   = blk_pool_idx( pool, parent );
      blk->sibling  = parent->child;
      parent->child = blk_pool_idx( pool, blk );
    }
    if( FD_UNLIKELY( final && pmeta->final==null ) ) promote( rotor, parent, &pmeta->final );
    consume( rotor, blk );
    if( FD_UNLIKELY( blk->cmpl_fec_cnt && blk->cons_fec_cnt==blk->cmpl_fec_cnt ) ) cascade( rotor, blk );
    if( FD_LIKELY( parent->connected==1 ) ) break;
    blk = parent;
  }
  return blk;
}

/* connect_descendants sets blk's connected bit from its parent and
   copies it down its subtree, skipping children that already match. */

static void
connect_descendants( fd_rotor_t *     rotor,
                     fd_rotor_blk_t * blk ) {
  fd_rotor_blk_t *       pool      = rotor->blk_pool;
  ulong                  null      = blk_pool_idx_null( pool );
  fd_rotor_blk_t const * parent    = blk_pool_ele_const( pool, blk->parent );
  int                    connected = ( ( blk->slot==rotor->root && fd_rotor_slot_meta( rotor, blk->slot )->final==blk_pool_idx( pool, blk ) ) || ( parent && parent->connected==1 ) );
  if( FD_LIKELY( blk->connected==connected ) ) return;
  blk->connected = connected ? 1 : 0;
  ulong tidx = blk_pool_idx( pool, blk );
  ulong idx  = blk->child;
  while( FD_LIKELY( idx!=null ) ) {
    fd_rotor_blk_t * c = blk_pool_ele( pool, idx );
    if( FD_LIKELY( c->connected!=connected ) ) {
      c->connected = connected ? 1 : 0;
      if( FD_LIKELY( c->child!=null ) ) { idx = c->child; continue; }
    }
    while( FD_LIKELY( idx!=tidx && blk_pool_ele( pool, idx )->sibling==null ) ) idx = blk_pool_ele( pool, idx )->parent;
    if( FD_UNLIKELY( idx==tidx ) ) break;
    idx = blk_pool_ele( pool, idx )->sibling;
  }
}

static void
unlink( fd_rotor_t *     rotor,
        fd_rotor_blk_t * blk ) {
  fd_rotor_blk_t * pool = rotor->blk_pool;
  ulong            null = blk_pool_idx_null( pool );
  ulong            idx  = blk_pool_idx( pool, blk );
  if( FD_LIKELY( blk->parent!=null ) ) {
    ulong * link = &blk_pool_ele( pool, blk->parent )->child;
    while( *link!=idx ) link = &blk_pool_ele( pool, *link )->sibling;
    *link = blk->sibling;
  }
  ulong next;
  for( ulong c=blk->child; c!=null; c=next ) {
    next                             = blk_pool_ele( pool, c )->sibling;
    blk_pool_ele( pool, c )->parent  = null;
    blk_pool_ele( pool, c )->sibling = null;
    connect_descendants( rotor, blk_pool_ele( pool, c ) );
  }
}

static void
prune( fd_rotor_t *     rotor,
       fd_rotor_blk_t * blk ) {
  fd_rotor_blk_t * pool = rotor->blk_pool;
  if( FD_UNLIKELY( !blk->telemetry.reported && rotor->telemetry.report ) ) rotor->telemetry.report( rotor->telemetry.ctx, blk );
  for( ulong k=0UL; k<FD_FEC_BLK_MAX; k++ ) {
    if( FD_LIKELY( blk->fecs[ k ]==fec_pool_idx_null( rotor->fec_pool ) ) ) continue;
    int held = 0;
    for( fd_rotor_blk_t const * other = blk_map_ele_query_const( rotor->blk_map, &blk->slot, NULL, pool );
                                other && !held;
                                other = blk_map_ele_next_const( other, NULL, pool ) ) {
      held = other!=blk && other->fecs[ k ]==blk->fecs[ k ];
    }
    if( FD_UNLIKELY( held ) ) continue;
    fd_rotor_fec_t * fec = fec_pool_ele( rotor->fec_pool, blk->fecs[ k ] );
    fec_map_ele_remove_fast( rotor->fec_map, fec, rotor->fec_pool );
    fec_pool_ele_release   ( rotor->fec_pool, fec );
  }
  unlink( rotor, blk );
  blk_treap_remove( rotor, blk );
  fd_rotor_slot_meta_t * meta = fd_rotor_slot_meta( rotor, blk->slot );
  if( FD_UNLIKELY( meta->eager==blk_pool_idx( pool, blk ) ) ) meta->eager = blk_pool_idx_null( pool );
  if( FD_UNLIKELY( meta->notar==blk_pool_idx( pool, blk ) ) ) meta->notar = blk_pool_idx_null( pool );
  if( FD_UNLIKELY( meta->final==blk_pool_idx( pool, blk ) ) ) meta->final = blk_pool_idx_null( pool );
  blk_map_ele_remove_fast( rotor->blk_map, blk, pool );
  blk_pool_ele_release   ( pool, blk );
}

/* dedup checks for a duplicate of eager among the notar blks.  Only the
   eager blk can be duplicated, since notar blk DMRs are known a priori.

   Merge strategy if a duplicate is found:
   - eager is kept, notar is freed
   - eager inherits notar's children
   - eager replaces with notar's parent if its own parent has no DMR yet
     (unfinished), as same DMR implies same parent

   Two banks may replay the same block until then; fine, since the notar
   one never completes. */

static void
dedup( fd_rotor_t *     rotor,
       fd_rotor_blk_t * eager ) {
  fd_rotor_blk_t * pool = rotor->blk_pool;
  ulong            null = blk_pool_idx_null( pool );
  ulong            idx  = blk_pool_idx( pool, eager );

  fd_rotor_blk_t * notar = blk_map_ele_query( rotor->blk_map, &eager->slot, NULL, pool );
  while( notar && ( notar==eager || memcmp( &notar->dmr, &eager->dmr, sizeof(fd_mr32_t) ) ) ) {
    notar = (fd_rotor_blk_t *)blk_map_ele_next_const( notar, NULL, pool );
  }
  fd_rotor_slot_meta_t * meta = fd_rotor_slot_meta( rotor, eager->slot );
  if( FD_UNLIKELY( !notar && meta->final!=null ) ) { eager->telemetry.cancelled_reason = FD_EVENT_BLOCK_RECEIVED_CANCELLED_REASON_NOTARIZED_VERSION; prune( rotor, eager ); return; } /* turbine built a blk the cluster did not finalize */
  if( FD_LIKELY( !notar ) ) return;

  ulong next;
  for( ulong c=notar->child; c!=null; c=next ) {
    next                             = blk_pool_ele( pool, c )->sibling;
    blk_pool_ele( pool, c )->parent  = idx;
    blk_pool_ele( pool, c )->sibling = eager->child;
    eager->child                     = c;
    connect_descendants( rotor, blk_pool_ele( pool, c ) );
  }
  notar->child = null;
  if( FD_UNLIKELY(    notar->parent!=null
                   && (    eager->parent==null
                        || !memcmp( &blk_pool_ele( pool, eager->parent )->dmr, &hash_null, sizeof(fd_mr32_t) ) ) ) ) {
    if( FD_LIKELY( eager->parent!=null ) ) {
      ulong * link = &blk_pool_ele( pool, eager->parent )->child;
      while( *link!=idx ) link = &blk_pool_ele( pool, *link )->sibling;
      *link = eager->sibling;
    }
    eager->parent                              = notar->parent;
    eager->sibling                             = blk_pool_ele( pool, notar->parent )->child;
    blk_pool_ele( pool, notar->parent )->child = idx;
    connect_descendants( rotor, eager );
  }
  blk_treap_remove( rotor, notar );
  if( FD_UNLIKELY( meta->final==blk_pool_idx( pool, notar ) ) ) { meta->final = null; promote( rotor, eager, &meta->final ); }
  if( FD_UNLIKELY( meta->notar==blk_pool_idx( pool, notar ) ) ) { meta->notar = null; promote( rotor, eager, &meta->notar ); }
  notar->telemetry.reported = 1; /* the same block lives on as eager */
  prune( rotor, notar );
  fd_rotor_blk_t * root = connect_ancestors( rotor, eager );
  connect_descendants( rotor, root );
}

FD_FN_CONST ulong
fd_rotor_align( void ) {
  return fd_ulong_max( alignof(fd_rotor_t), 128UL );
}

FD_FN_CONST ulong
fd_rotor_footprint( ulong slot_max,
                    ulong fec_max ) {
  ulong blk_max = slot_max*( 4UL+AG_EQVOC_BLOCK_HASH_MAX )/5UL; /* 80% of leaders make one blk a slot, 20% every hash */
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
    FD_LAYOUT_INIT,
      fd_rotor_align(),              sizeof(fd_rotor_t)                                            ),
      alignof(fd_rotor_slot_meta_t), sizeof(fd_rotor_slot_meta_t)*slot_max                         ),
      blk_pool_align(),              blk_pool_footprint       ( blk_max                          ) ),
      blk_map_align(),               blk_map_footprint        ( blk_map_chain_cnt_est( blk_max ) ) ),
      fec_pool_align(),              fec_pool_footprint       ( fec_max                          ) ),
      fec_map_align(),               fec_map_footprint        ( fec_map_chain_cnt_est( fec_max ) ) ),
      fd_rotor_deque_align(),        fd_rotor_deque_footprint ( fec_max                          ) ),
      fd_rotor_treap_align(),        fd_rotor_treap_footprint ( blk_max                          ) ),
      fd_rotor_treap_align(),        fd_rotor_treap_footprint ( blk_max                          ) ),
      fd_rotor_treap_align(),        fd_rotor_treap_footprint ( blk_max                          ) ),
    fd_rotor_align() );
}

void *
fd_rotor_new( void * shmem,
              ulong  slot_max,
              ulong  fec_max,
              ulong  seed ) {
  ulong footprint = fd_rotor_footprint( slot_max, fec_max );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "bad footprint: %lu %lu", slot_max, fec_max ));
    return NULL;
  }

  fd_memset( shmem, 0, footprint );
  fd_rotor_t * rotor;

  ulong blk_max = slot_max*( 4UL+AG_EQVOC_BLOCK_HASH_MAX )/5UL; /* 80% of leaders make one blk a slot, 20% every hash */

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  rotor              = FD_SCRATCH_ALLOC_APPEND( l, fd_rotor_align(),              sizeof(fd_rotor_t)                                            );
  void * slot_meta   = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_rotor_slot_meta_t), sizeof(fd_rotor_slot_meta_t)*slot_max                         );
  void * blk_pool    = FD_SCRATCH_ALLOC_APPEND( l, blk_pool_align(),              blk_pool_footprint       ( blk_max                          ) );
  void * blk_map     = FD_SCRATCH_ALLOC_APPEND( l, blk_map_align(),               blk_map_footprint        ( blk_map_chain_cnt_est( blk_max ) ) );
  void * fec_pool    = FD_SCRATCH_ALLOC_APPEND( l, fec_pool_align(),              fec_pool_footprint       ( fec_max                          ) );
  void * fec_map     = FD_SCRATCH_ALLOC_APPEND( l, fec_map_align(),               fec_map_footprint        ( fec_map_chain_cnt_est( fec_max ) ) );
  void * reasm_deque = FD_SCRATCH_ALLOC_APPEND( l, fd_rotor_deque_align(),        fd_rotor_deque_footprint ( fec_max                          ) );
  void * eager_treap = FD_SCRATCH_ALLOC_APPEND( l, fd_rotor_treap_align(),        fd_rotor_treap_footprint ( blk_max                          ) );
  void * notar_treap = FD_SCRATCH_ALLOC_APPEND( l, fd_rotor_treap_align(),        fd_rotor_treap_footprint ( blk_max                          ) );
  void * final_treap = FD_SCRATCH_ALLOC_APPEND( l, fd_rotor_treap_align(),        fd_rotor_treap_footprint ( blk_max                          ) );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, fd_rotor_align() ) == (ulong)shmem + footprint );

  rotor->root        = ULONG_MAX;
  rotor->slot_max    = slot_max;
  rotor->slot_meta   = (fd_rotor_slot_meta_t *)slot_meta;
  for( ulong i=0UL; i<slot_max; i++ ) rotor->slot_meta[ i ].slot = ULONG_MAX;
  rotor->blk_pool    = blk_pool_join      ( blk_pool_new      ( blk_pool,    blk_max                                ) );
  rotor->blk_map     = blk_map_join       ( blk_map_new       ( blk_map,     blk_map_chain_cnt_est( blk_max ), seed ) );
  rotor->fec_pool    = fec_pool_join      ( fec_pool_new      ( fec_pool,    fec_max                                ) );
  rotor->fec_map     = fec_map_join       ( fec_map_new       ( fec_map,     fec_map_chain_cnt_est( fec_max ), seed ) );
  rotor->reasm_deque = fd_rotor_deque_join( fd_rotor_deque_new( reasm_deque, fec_max                                ) );
  fd_rotor_treap_seed( rotor->blk_pool, blk_max, seed ); /* the treaps share each blk's prio */
  rotor->eager_treap = fd_rotor_treap_join( fd_rotor_treap_new( eager_treap, blk_max ) );
  rotor->notar_treap = fd_rotor_treap_join( fd_rotor_treap_new( notar_treap, blk_max ) );
  rotor->final_treap = fd_rotor_treap_join( fd_rotor_treap_new( final_treap, blk_max ) );

  return shmem;
}

fd_rotor_t *
fd_rotor_join( void * shrotor ) {
  return (fd_rotor_t *)shrotor;
}

void *
fd_rotor_leave( fd_rotor_t const * rotor ) {
  return (void *)rotor;
}

void *
fd_rotor_delete( void * shrotor ) {
  return shrotor;
}

void
fd_rotor_init( fd_rotor_t *         rotor,
               ulong                root,
               fd_mr32_t const *    root_blk_mr,
               fd_rotor_report_fn_t report,
               void *               report_ctx ) {
  rotor->telemetry.report = report;
  rotor->telemetry.ctx    = report_ctx;
  fd_rotor_blk_t * blk = blk_insert( rotor, root, root_blk_mr );
  blk->telemetry.reported = 1; /* the root is not a received block */
  blk_treap_remove( rotor, blk ); /* the root is never repaired */
  fd_rotor_slot_meta( rotor, root )->final = blk_pool_idx( rotor->blk_pool, blk );
  fd_rotor_slot_meta( rotor, root )->eager = blk_pool_idx_null( rotor->blk_pool ); /* the genesis root has a null dmr, but is not turbine's */
  blk->eager     = 0;
  blk->connected = 1;
  rotor->root         = root;
  rotor->catchup_slot = root;
}

void
fd_rotor_fini( fd_rotor_t * rotor ) {
  for( ulong i=0UL; i<rotor->slot_max; i++ ) rotor->slot_meta[ i ].slot = ULONG_MAX;
  blk_map_reset( rotor->blk_map );
  blk_pool_reset( rotor->blk_pool );
  fec_map_reset( rotor->fec_map );
  fec_pool_reset( rotor->fec_pool );
  fd_rotor_deque_remove_all( rotor->reasm_deque );
  rotor->eager_treap = fd_rotor_treap_join( fd_rotor_treap_new( fd_rotor_treap_leave( rotor->eager_treap ), blk_pool_max( rotor->blk_pool ) ) );
  rotor->notar_treap = fd_rotor_treap_join( fd_rotor_treap_new( fd_rotor_treap_leave( rotor->notar_treap ), blk_pool_max( rotor->blk_pool ) ) );
  rotor->final_treap = fd_rotor_treap_join( fd_rotor_treap_new( fd_rotor_treap_leave( rotor->final_treap ), blk_pool_max( rotor->blk_pool ) ) );
  rotor->root         = ULONG_MAX;
  rotor->catchup_slot = 0UL;
}

void
fd_rotor_blk_dead( fd_rotor_t *      rotor,
                   ulong             slot,
                   fd_mr32_t const * blk_mr ) {
  fd_rotor_blk_t * dead = blk_map_ele_query( rotor->blk_map, &slot, NULL, rotor->blk_pool );
  while( dead && memcmp( &dead->dmr, blk_mr, sizeof(fd_mr32_t) ) ) dead = (fd_rotor_blk_t *)blk_map_ele_next_const( dead, NULL, rotor->blk_pool );
  if( FD_UNLIKELY( !dead ) ) return;

  fd_rotor_slot_meta_t * meta = fd_rotor_slot_meta( rotor, slot );
  if( FD_UNLIKELY( meta->eager==blk_pool_idx( rotor->blk_pool, dead ) ) ) meta->invalidated = 1; /* turbine must not rebuild it */
  prune( rotor, dead );
}

fd_rotor_blk_t *
fd_rotor_blk_finalized( fd_rotor_t *      rotor,
                        ulong             slot,
                        fd_mr32_t const * blk_mr ) {
  fd_rotor_slot_meta_t * meta = fd_rotor_slot_meta( rotor, slot );

  fd_rotor_blk_t * fin = blk_map_ele_query( rotor->blk_map, &slot, NULL, rotor->blk_pool );
  while( fin && memcmp( &fin->dmr, blk_mr, sizeof(fd_mr32_t) ) ) fin = (fd_rotor_blk_t *)blk_map_ele_next_const( fin, NULL, rotor->blk_pool );
  if( FD_UNLIKELY( !fin ) ) fin = fd_rotor_blk_notarized( rotor, slot, blk_mr );
  if( FD_UNLIKELY( !fin ) ) return NULL; /* the slot is already finalized with another blk */

  fd_rotor_blk_t * pool = rotor->blk_pool;
  ulong            null = blk_pool_idx_null( pool );
  promote( rotor, fin, &meta->final );
  fd_rotor_blk_t * eager = blk_pool_ele( pool, meta->eager );
  if( FD_LIKELY( eager ) ) eager->eager = 0;
  if( FD_LIKELY( eager && meta->final!=meta->eager && meta->notar!=meta->eager ) ) blk_treap_remove( rotor, eager ); /* still the eager blk, never repaired */

  /* Remove all equivocating blocks except the finalized one.  Their
     children that named the finalized blk move to it. */

  fd_rotor_blk_t * next;
  for( fd_rotor_blk_t * blk = blk_map_ele_query( rotor->blk_map, &slot, NULL, pool );
                        blk;
                        blk = next ) {
    next = (fd_rotor_blk_t *)blk_map_ele_next_const( blk, NULL, pool );
    if( FD_LIKELY( blk==fin ) ) continue;
    ulong cnext;
    for( ulong c=blk->child; c!=null; c=cnext ) {
      cnext = blk_pool_ele( pool, c )->sibling;
      if( FD_LIKELY( !memcmp( &blk_pool_ele( pool, c )->parent_blk_mr, &fin->dmr, sizeof(fd_mr32_t) ) ) ) {
        blk_pool_ele( pool, c )->parent  = meta->final;
        blk_pool_ele( pool, c )->sibling = fin->child;
        fin->child                       = c;
      } else {
        blk_pool_ele( pool, c )->parent  = null;
        blk_pool_ele( pool, c )->sibling = null;
      }
      connect_descendants( rotor, blk_pool_ele( pool, c ) );
    }
    blk->child = null;
    if( FD_UNLIKELY( meta->eager==blk_pool_idx( pool, blk ) && !memcmp( &blk->dmr, &hash_null, sizeof(fd_mr32_t) ) ) ) continue; /* turbine may still complete as the finalized blk, see dedup */
    blk->telemetry.cancelled_reason = FD_EVENT_BLOCK_RECEIVED_CANCELLED_REASON_NOTARIZED_VERSION;
    prune( rotor, blk );
  }
  fd_rotor_blk_t * root = connect_ancestors( rotor, fin );
  connect_descendants( rotor, root );
  if( FD_UNLIKELY( fin->cmpl_fec_cnt && fin->cons_fec_cnt==fin->cmpl_fec_cnt ) ) cascade( rotor, fin );
  return fin;
}

fd_rotor_blk_t *
fd_rotor_blk_notarized( fd_rotor_t *      rotor,
                        ulong             slot,
                        fd_mr32_t const * blk_mr ) {
  fd_rotor_slot_meta_t *       meta = fd_rotor_slot_meta( rotor, slot );
  if( FD_UNLIKELY( !memcmp( blk_mr, &hash_null, sizeof(fd_mr32_t) ) ) ) return NULL; /* never a real blk id, only turbine makes an eager blk */
  if( FD_UNLIKELY( meta->final!=blk_pool_idx_null( rotor->blk_pool ) || meta->skipped ) ) return NULL; /* the slot is settled */
  for( fd_rotor_blk_t * dup = blk_map_ele_query( rotor->blk_map, &slot, NULL, rotor->blk_pool );
                        dup;
                        dup = (fd_rotor_blk_t *)blk_map_ele_next_const( dup, NULL, rotor->blk_pool ) ) {
    if( FD_UNLIKELY( memcmp( &dup->dmr, blk_mr, sizeof(fd_mr32_t) ) ) ) continue;
    if( FD_LIKELY( meta->notar==blk_pool_idx_null( rotor->blk_pool ) ) ) promote( rotor, dup, &meta->notar ); /* already have it, now named */
    fd_rotor_blk_t * root = connect_ancestors( rotor, dup );
    connect_descendants( rotor, root );
    return NULL;
  }
  return blk_insert( rotor, slot, blk_mr );
}

fd_rotor_blk_t *
fd_rotor_blk_parented( fd_rotor_t *      rotor,
                       ulong             slot,
                       fd_mr32_t const * blk_mr,
                       ulong             parent_slot,
                       fd_mr32_t const * parent_blk_mr,
                       uint              fec_set_cnt ) {
  fd_rotor_blk_t * blk = blk_map_ele_query( rotor->blk_map, &slot, NULL, rotor->blk_pool );
  while( FD_LIKELY( blk && memcmp( &blk->dmr, blk_mr, sizeof(fd_mr32_t) ) ) ) blk = (fd_rotor_blk_t *)blk_map_ele_next_const( blk, NULL, rotor->blk_pool );
  if( FD_UNLIKELY( !blk                         ) ) return NULL; /* blk was pruned while the response was in flight */
  if( FD_UNLIKELY( blk->parent_slot!=ULONG_MAX ) ) return NULL; /* duplicate response, eg. a retried request */
  if( FD_UNLIKELY( parent_slot>=slot            ) ) return NULL; /* a blk's parent precedes it */

  blk->parent_slot   = parent_slot;
  blk->parent_blk_mr = *parent_blk_mr;
  blk->cmpl_fec_cnt  = fec_set_cnt;
  blk_treap_insert( rotor, blk ); /* its FEC sets can be discovered now */

  ulong            eager  = fd_rotor_slot_meta( rotor, parent_slot )->eager;
  fd_rotor_blk_t * parent = blk_map_ele_query( rotor->blk_map, &parent_slot, NULL, rotor->blk_pool );
  while(    parent
         && (    memcmp( &parent->dmr, parent_blk_mr, sizeof(fd_mr32_t) )
              || ( blk_pool_idx( rotor->blk_pool, parent )==eager && !memcmp( &parent->dmr, &hash_null, sizeof(fd_mr32_t) ) ) ) ) {
    parent = (fd_rotor_blk_t *)blk_map_ele_next_const( parent, NULL, rotor->blk_pool );
  }
  fd_rotor_blk_t * created = NULL;
  if( FD_LIKELY( !parent ) ) parent = created = fd_rotor_blk_notarized( rotor, parent_slot, parent_blk_mr );
  if( FD_LIKELY( parent ) ) {
    blk->parent   = blk_pool_idx( rotor->blk_pool, parent );
    blk->sibling  = parent->child;
    parent->child = blk_pool_idx( rotor->blk_pool, blk );
    connect_descendants( rotor, blk );
    if( FD_UNLIKELY( fd_rotor_slot_meta( rotor, slot )->final==blk_pool_idx( rotor->blk_pool, blk ) ) ) promote( rotor, parent, &fd_rotor_slot_meta( rotor, parent_slot )->final ); /* finalized ancestry */
    consume( rotor, blk );
    if( FD_UNLIKELY( blk->cmpl_fec_cnt && blk->cons_fec_cnt==blk->cmpl_fec_cnt ) ) cascade( rotor, blk );
    if( FD_LIKELY( !created ) ) { /* a held parent may itself be orphaned */
      fd_rotor_blk_t * root = connect_ancestors( rotor, parent );
      connect_descendants( rotor, root );
    }
  }
  return created;
}

void
fd_rotor_slot_catchup( fd_rotor_t * rotor,
                       ulong        slot ) {
  for( ulong s=fd_ulong_max( rotor->root+1UL, rotor->catchup_slot ); s<slot; s++ ) {
    fd_rotor_slot_meta_t * meta = fd_rotor_slot_meta( rotor, s );
    if( FD_UNLIKELY( meta->skipped || meta->invalidated || meta->final!=blk_pool_idx_null( rotor->blk_pool ) || meta->eager!=blk_pool_idx_null( rotor->blk_pool ) ) ) continue;
    meta->eager = blk_pool_idx( rotor->blk_pool, blk_insert( rotor, s, &hash_null ) );
  }
  rotor->catchup_slot = fd_ulong_max( rotor->catchup_slot, slot );
}

fd_rotor_fec_t *
fd_rotor_fec_complete( fd_rotor_t *       rotor,
                       fd_shred_t const * last_shred,
                       fd_mr32_t const *  fec_mr,
                       int                is_leader,
                       long               ts ) {
  fd_rotor_shred_insert( rotor, last_shred, fec_mr, ts );

  fd_mr20_t key;
  memcpy( key.uc, fec_mr->uc, sizeof(fd_mr20_t) );
  fd_rotor_fec_t * fec = fec_map_ele_query( rotor->fec_map, &key, NULL, rotor->fec_pool );
  if( FD_UNLIKELY( !fec ) ) return NULL; /* fd_rotor_shred_insert dropped it as conflicting with the eager blk */

  fec->mr32          = *fec_mr;
  fec->rcvd          = UINT_MAX;
  fec->complete      = 1;
  fec->data_complete = !!( last_shred->data.flags & FD_SHRED_DATA_FLAG_DATA_COMPLETE );
  fec->is_leader    |= is_leader; /* a completion again from the network does not clear our own */

  ulong                  slot  = last_shred->slot; /* fd_shred_t is packed, the map query needs an aligned key */
  fd_rotor_slot_meta_t * meta  = fd_rotor_slot_meta( rotor, slot );
  fd_rotor_blk_t *       pool  = rotor->blk_pool;
  ulong                  null  = blk_pool_idx_null( pool );
  fd_rotor_blk_t *       eager = blk_pool_ele( pool, meta->eager );
  int                    cmpl  = eager && !meta->invalidated && eager->cmpl_fec_cnt && !memcmp( &eager->dmr, &hash_null, sizeof(fd_mr32_t) );
  for( uint k=0U; cmpl && k<eager->cmpl_fec_cnt; k++ ) {
    cmpl = eager->fecs[ k ]!=fec_pool_idx_null( rotor->fec_pool ) && fec_pool_ele( rotor->fec_pool, eager->fecs[ k ] )->complete;
  }
  meta->leader |= (uint)!!is_leader;
  if( FD_UNLIKELY( is_leader && eager ) ) eager->eager = 0; /* our own, never repaired */
  if( FD_UNLIKELY( is_leader && eager && meta->final!=meta->eager && meta->notar!=meta->eager ) ) blk_treap_remove( rotor, eager );
  if( FD_UNLIKELY( cmpl ) ) {
    compute_dmr( rotor, eager );
    ulong keep = null;
    ulong next;
    for( ulong c=eager->child; c!=null; c=next ) {
      next = blk_pool_ele( pool, c )->sibling;
      if( FD_LIKELY( !memcmp( &blk_pool_ele( pool, c )->parent_blk_mr, &eager->dmr, sizeof(fd_mr32_t) ) ) ) { blk_pool_ele( pool, c )->sibling = keep; keep = c; continue; }
      blk_pool_ele( pool, c )->parent  = null;
      blk_pool_ele( pool, c )->sibling = null;
      connect_descendants( rotor, blk_pool_ele( pool, c ) );
    }
    eager->child = keep;

    dedup( rotor, eager );
    if( FD_UNLIKELY( fec_map_ele_query( rotor->fec_map, &key, NULL, rotor->fec_pool )!=fec ) ) return NULL; /* dedup pruned eager and with it the FEC set */
  }

  for( fd_rotor_blk_t * blk = blk_map_ele_query( rotor->blk_map, &slot, NULL, pool );
                        blk;
                        blk = (fd_rotor_blk_t *)blk_map_ele_next_const( blk, NULL, pool ) ) {
    if( FD_LIKELY( blk->fecs[ fec->fec_idx ]!=fec_pool_idx( rotor->fec_pool, fec ) ) ) continue;
    uint end = fd_uint_if( !!blk->cmpl_fec_cnt, blk->cmpl_fec_cnt, (uint)FD_FEC_BLK_MAX );
    while(    blk->buff_fec_cnt<end
           && blk->fecs[ blk->buff_fec_cnt ]!=fec_pool_idx_null( rotor->fec_pool )
           && fec_pool_ele( rotor->fec_pool, blk->fecs[ blk->buff_fec_cnt ] )->complete ) {
      blk->buff_fec_cnt++;
    }
    if( FD_UNLIKELY( blk->cmpl_fec_cnt && blk->buff_fec_cnt==blk->cmpl_fec_cnt && !blk->telemetry.reported && rotor->telemetry.report ) ) { blk->telemetry.reported = 1; rotor->telemetry.report( rotor->telemetry.ctx, blk ); }
    consume( rotor, blk );
    if( FD_UNLIKELY( blk->cmpl_fec_cnt && blk->cons_fec_cnt==blk->cmpl_fec_cnt ) ) cascade( rotor, blk );
  }
  return fec;
}

void
fd_rotor_fec_evicted( fd_rotor_t *      rotor,
                      ulong             slot,
                      uint              fec_set_idx,
                      fd_mr20_t const * fec_mr ) {
  uint             k   = fec_set_idx/FD_FEC_SHRED_CNT;
  fd_rotor_fec_t * fec = fec_map_ele_query( rotor->fec_map, fec_mr, NULL, rotor->fec_pool );
  if( FD_UNLIKELY( !fec || fec->complete || fec->slot!=slot || fec->fec_idx!=k ) ) return;

  fec->rcvd = 0U; /* its req, still waiting since the set is incomplete, asks for every shred again */
}

fd_rotor_fec_t *
fd_rotor_fec_notarized( fd_rotor_t *      rotor,
                        ulong             slot,
                        fd_mr32_t const * blk_mr,
                        uint              fec_set_idx,
                        fd_mr20_t const * fec_mr ) {

  uint fec_idx = fec_set_idx / FD_FEC_SHRED_CNT;

  fd_rotor_blk_t * blk = blk_map_ele_query( rotor->blk_map, &slot, NULL, rotor->blk_pool );
  while( blk && memcmp( &blk->dmr, blk_mr, sizeof(fd_mr32_t) ) ) blk = (fd_rotor_blk_t *)blk_map_ele_next_const( blk, NULL, rotor->blk_pool );
  if( FD_UNLIKELY( !blk ) ) return NULL; /* blk was pruned while the response was in flight */
  if( FD_UNLIKELY( blk->fecs[ fec_idx ]!=fec_pool_idx_null( rotor->fec_pool ) ) ) return NULL; /* duplicate response, eg. a retried request */

  fd_rotor_slot_meta_t * meta  = fd_rotor_slot_meta( rotor, slot );
  fd_rotor_blk_t *       eager = blk_pool_ele( rotor->blk_pool, meta->eager );
  int                    eqvoc = eager && eager->fecs[ fec_idx ]!=fec_pool_idx_null( rotor->fec_pool ) && memcmp( &fec_pool_ele( rotor->fec_pool, eager->fecs[ fec_idx ] )->key, fec_mr, sizeof(fd_mr20_t) );
  if( FD_UNLIKELY( eqvoc ) ) fd_rotor_slot_invalidated( rotor, slot, FD_EVENT_BLOCK_RECEIVED_CANCELLED_REASON_MERKLE_ROOT_MISMATCH );

  fd_rotor_fec_t * fec = fec_map_ele_query( rotor->fec_map, fec_mr, NULL, rotor->fec_pool );
  if( FD_UNLIKELY( fec && ( fec->slot!=slot || fec->fec_idx!=fec_idx ) ) ) return NULL; /* a FEC set root commits to its slot and index, so this leaf names no FEC set a shred can fill */
  if( FD_UNLIKELY( !fec ) ) {
    FD_TEST( fec_pool_free( rotor->fec_pool ) );
    fec                = fec_pool_ele_acquire( rotor->fec_pool );
    fec->key           = *fec_mr;
    fec->mr32          = hash_null;
    fec->fec_idx       = fec_idx;
    fec->slot          = slot;
    fec->rcvd          = 0U;
    fec->complete      = 0;
    fec->data_complete = 0;
    fec->first_ts      = 0L;
    fec->is_leader     = 0;
    fec_map_ele_insert( rotor->fec_map, fec, rotor->fec_pool );
  }
  fec->notarized       = 1;
  blk->fecs[ fec_idx ] = fec_pool_idx( rotor->fec_pool, fec );
  if( FD_LIKELY( !fec->complete ) ) return fec;

  uint end = fd_uint_if( !!blk->cmpl_fec_cnt, blk->cmpl_fec_cnt, (uint)FD_FEC_BLK_MAX );
  while(    blk->buff_fec_cnt<end
         && blk->fecs[ blk->buff_fec_cnt ]!=fec_pool_idx_null( rotor->fec_pool )
         && fec_pool_ele( rotor->fec_pool, blk->fecs[ blk->buff_fec_cnt ] )->complete ) {
    blk->buff_fec_cnt++;
  }
  if( FD_UNLIKELY( blk->cmpl_fec_cnt && blk->buff_fec_cnt==blk->cmpl_fec_cnt && !blk->telemetry.reported && rotor->telemetry.report ) ) { blk->telemetry.reported = 1; rotor->telemetry.report( rotor->telemetry.ctx, blk ); }
  consume( rotor, blk );
  if( FD_UNLIKELY( blk->cmpl_fec_cnt && blk->cons_fec_cnt==blk->cmpl_fec_cnt ) ) cascade( rotor, blk );
  return fec;
}

void
fd_rotor_fec_reconsume( fd_rotor_t * rotor ) {
  for( ulong s=rotor->root+1UL; s<rotor->root+rotor->slot_max; s++ ) {
    for( fd_rotor_blk_t * blk = blk_map_ele_query( rotor->blk_map, &s, NULL, rotor->blk_pool );
                          blk;
                          blk = (fd_rotor_blk_t *)blk_map_ele_next_const( blk, NULL, rotor->blk_pool ) ) {
      blk->cons_fec_cnt = 0U;
    }
  }
  cascade( rotor, blk_pool_ele( rotor->blk_pool, fd_rotor_slot_meta( rotor, rotor->root )->final ) );
}

void
fd_rotor_root_advanced( fd_rotor_t *      rotor,
                        ulong             slot,
                        fd_mr32_t const * blk_mr ) {
  ulong root  = rotor->root;
  rotor->root = slot; /* connect_descendants sees the new root while freed ancestors drop their children */
  for( ulong s=root; s<=slot; s++ ) {
    fd_rotor_blk_t * next;
    for( fd_rotor_blk_t * blk = blk_map_ele_query( rotor->blk_map, &s, NULL, rotor->blk_pool );
                          blk;
                          blk = next ) {
      next = (fd_rotor_blk_t *)blk_map_ele_next_const( blk, NULL, rotor->blk_pool );
      if( FD_UNLIKELY( !blk->telemetry.reported && rotor->telemetry.report ) ) { blk->telemetry.reported = 1; rotor->telemetry.report( rotor->telemetry.ctx, blk ); }
      for( ulong k=0UL; k<FD_FEC_BLK_MAX; k++ ) {
        ulong idx = blk->fecs[ k ];
        blk->fecs[ k ] = fec_pool_idx_null( rotor->fec_pool );
        if( FD_LIKELY( idx==fec_pool_idx_null( rotor->fec_pool ) ) ) continue;
        fd_rotor_fec_t * fec = fec_pool_ele( rotor->fec_pool, idx );
        if( FD_LIKELY( fec_map_ele_query( rotor->fec_map, &fec->key, NULL, rotor->fec_pool )!=fec ) ) continue; /* freed through a sibling */
        fec_map_ele_remove_fast( rotor->fec_map, fec, rotor->fec_pool );
        fec_pool_ele_release   ( rotor->fec_pool, fec );
      }
      if( FD_UNLIKELY( s==slot && !memcmp( &blk->dmr, blk_mr, sizeof(fd_mr32_t) ) ) ) { /* the new root */
        blk_treap_remove( rotor, blk ); /* the root is never repaired */
        fd_rotor_slot_meta( rotor, slot )->final = blk_pool_idx( rotor->blk_pool, blk );
        blk->eager = 0;
        connect_descendants( rotor, blk );
        continue;
      }
      unlink( rotor, blk );
      blk_treap_remove( rotor, blk );
      blk_map_ele_remove_fast( rotor->blk_map, blk, rotor->blk_pool );
      blk_pool_ele_release   ( rotor->blk_pool, blk );
    }
  }
}

void
fd_rotor_shred_insert( fd_rotor_t *       rotor,
                       fd_shred_t const * shred,
                       fd_mr32_t const *  fec_mr,
                       long               ts ) {

  fd_mr20_t key;
  memcpy( key.uc, fec_mr->uc, sizeof(fd_mr20_t) );

  /* First, handle a Notar shred (shred for a FEC set that has already
     reached a notarized status ie. SafeToNotar or stronger).  It also
     belongs to the eager blk, so fall through. */

  fd_rotor_fec_t * fec     = fec_map_ele_query( rotor->fec_map, &key, NULL, rotor->fec_pool );
  uint             fec_idx = shred->idx / FD_FEC_SHRED_CNT;
  if( FD_UNLIKELY( fec && ( fec->slot!=shred->slot || fec->fec_idx!=fec_idx ) ) ) return; /* a 20-byte root collision */
  if( FD_UNLIKELY( fec && fec->notarized ) ) fec->rcvd = fd_uint_set_bit( fec->rcvd, (int)( shred->idx - fec_idx * FD_FEC_SHRED_CNT ) );
  if( FD_UNLIKELY( fec && !fec->first_ts ) ) fec->first_ts = ts;

  /* Second, handle an Eager shred (from Turbine or Eager Repair). */

  ulong                  parent_slot = shred->slot - shred->data.parent_off;
  fd_rotor_blk_t *       pool        = rotor->blk_pool;
  ulong                  null        = blk_pool_idx_null( pool );
  fd_rotor_slot_meta_t * meta        = fd_rotor_slot_meta( rotor, shred->slot );
  if( FD_UNLIKELY( meta->skipped || meta->invalidated || ( meta->final!=null && meta->eager==null ) ) ) return;
  if( FD_UNLIKELY( meta->eager==null ) ) meta->eager = blk_pool_idx( pool, blk_insert( rotor, shred->slot, &hash_null ) );
  fd_rotor_blk_t * blk = blk_pool_ele( pool, meta->eager );
  if( FD_UNLIKELY( blk->parent_slot==ULONG_MAX ) ) blk->parent_slot = parent_slot; /* created empty by a child or catchup */

  /* Check for misbehavior that can invalidate the eager block. */

  fd_block_marker_t marker[1];
  int               bad_header    = shred->idx==0U && ( fd_block_marker_de( marker, fd_shred_data_payload( shred ), fd_shred_payload_sz( shred ) ) || marker->kind!=FD_BLOCK_MARKER_KIND_HEADER || marker->header.parent_slot!=parent_slot );
  fd_mr32_t const * parent_blk_mr = shred->idx==0U ? &marker->header.parent_block_id : NULL;

  int slot_complete     = !!( shred->data.flags & FD_SHRED_DATA_FLAG_SLOT_COMPLETE );
  int eqvoc             = blk->fecs[ fec_idx ]!=fec_pool_idx_null( rotor->fec_pool ) && blk->fecs[ fec_idx ]!=fec_pool_idx( rotor->fec_pool, fec ); /* the leader signed two FEC sets at this index, eg. two shred 0s */
  int parent_conflict   = bad_header || blk->parent_slot!=parent_slot;
  int complete_conflict = ( blk->cmpl_fec_cnt && fec_idx>=blk->cmpl_fec_cnt ) || ( slot_complete && fec_idx+1U<blk->rcvd_fec_cnt );
  if( FD_UNLIKELY( eqvoc || parent_conflict || complete_conflict ) ) {
    fd_rotor_slot_invalidated( rotor, shred->slot, fd_int_if( eqvoc, FD_EVENT_BLOCK_RECEIVED_CANCELLED_REASON_MERKLE_ROOT_MISMATCH, fd_int_if( bad_header, FD_EVENT_BLOCK_RECEIVED_CANCELLED_REASON_INVALID_BLOCK_HEADER, fd_int_if( parent_conflict, FD_EVENT_BLOCK_RECEIVED_CANCELLED_REASON_PARENT_OFF_MISMATCH, FD_EVENT_BLOCK_RECEIVED_CANCELLED_REASON_SLOT_COMPLETE_MISMATCH ) ) ) );
    return;
  }

  if( FD_UNLIKELY( parent_blk_mr ) ) blk->parent_blk_mr = *parent_blk_mr;
  if( FD_UNLIKELY( parent_blk_mr && blk->parent==null ) ) {
    fd_rotor_slot_meta_t * pmeta  = fd_rotor_slot_meta( rotor, parent_slot );
    fd_rotor_blk_t *       parent = blk_map_ele_query( rotor->blk_map, &parent_slot, NULL, pool );
    while( parent && memcmp( &parent->dmr, parent_blk_mr, sizeof(fd_mr32_t) ) ) {
      parent = (fd_rotor_blk_t *)blk_map_ele_next_const( parent, NULL, pool );
    }
    if( FD_LIKELY(    !parent
                   && pmeta->final==null
                   && !pmeta->skipped
                   && ( pmeta->eager==null || !memcmp( &blk_pool_ele( pool, pmeta->eager )->dmr, &hash_null, sizeof(fd_mr32_t) ) ) ) ) { /* the parent slot's unfinished eager blk, its dmr is checked when it completes */
      if( FD_UNLIKELY( pmeta->eager==null ) ) pmeta->eager = blk_pool_idx( pool, blk_insert( rotor, parent_slot, &hash_null ) );
      parent = blk_pool_ele( pool, pmeta->eager );
    }
    if( FD_LIKELY( parent ) ) {
      blk->parent   = blk_pool_idx( pool, parent );
      blk->sibling  = parent->child;
      parent->child = blk_pool_idx( pool, blk );
      connect_descendants( rotor, blk );
    }
  }
  if( FD_UNLIKELY( slot_complete ) ) blk->cmpl_fec_cnt = fec_idx+1U;
  if( FD_UNLIKELY( slot_complete || fec_idx+1U>blk->rcvd_fec_cnt ) ) { /* its repair limit moved */
    blk->rcvd_fec_ts = fd_long_if( fec_idx+1U>blk->rcvd_fec_cnt, ts, blk->rcvd_fec_ts );
    blk_treap_insert( rotor, blk );
  }

  if( FD_UNLIKELY( !fec ) ) {
    FD_TEST( fec_pool_free( rotor->fec_pool ) );
    fec                = fec_pool_ele_acquire( rotor->fec_pool );
    fec->key           = key;
    fec->mr32          = hash_null;
    fec->fec_idx       = fec_idx;
    fec->slot          = shred->slot;
    fec->rcvd          = 0U;
    fec->complete      = 0;
    fec->data_complete = 0;
    fec->first_ts      = ts;
    fec->is_leader     = 0;
    fec->notarized     = 0;
    fec_map_ele_insert( rotor->fec_map, fec, rotor->fec_pool );
  }
  blk->fecs[ fec_idx ] = fec_pool_idx( rotor->fec_pool, fec );
  blk->rcvd_fec_cnt    = fd_uint_max( blk->rcvd_fec_cnt, fec_idx+1U );
  fec->rcvd            = fd_uint_set_bit( fec->rcvd, (int)( shred->idx - fec_idx*FD_FEC_SHRED_CNT ) );
}

void
fd_rotor_slot_invalidated( fd_rotor_t * rotor,
                           ulong        slot,
                           int          reason ) {
  fd_rotor_slot_meta_t * meta  = fd_rotor_slot_meta( rotor, slot );
  fd_rotor_blk_t *       eager = blk_pool_ele( rotor->blk_pool, meta->eager );
  meta->invalidated = 1;
  if( FD_LIKELY( eager ) ) eager->eager = 0;
  if( FD_LIKELY( eager ) ) eager->telemetry.cancelled_reason = (uchar)reason;
  if( FD_LIKELY( eager && meta->final!=meta->eager && meta->notar!=meta->eager ) ) blk_treap_remove( rotor, eager ); /* still the eager blk, never repaired */
}

fd_rotor_slot_meta_t *
fd_rotor_slot_meta( fd_rotor_t * rotor,
                    ulong        slot ) {
  fd_rotor_slot_meta_t * meta = &rotor->slot_meta[ slot % rotor->slot_max ];
  if( FD_UNLIKELY( meta->slot!=slot ) ) {
    meta->slot        = slot;
    meta->eager       = blk_pool_idx_null( rotor->blk_pool );
    meta->notar       = blk_pool_idx_null( rotor->blk_pool );
    meta->final       = blk_pool_idx_null( rotor->blk_pool );
    meta->invalidated = 0;
    meta->skipped     = 0;
    meta->leader      = 0;
  }
  return meta;
}

void
fd_rotor_slot_skipped( fd_rotor_t * rotor,
                       ulong        slot ) {
  fd_rotor_slot_meta_t * meta = fd_rotor_slot_meta( rotor, slot );
  meta->skipped = 1; /* late repair requests or shreds for the slot must not recreate blks in it */

  fd_rotor_blk_t * next;
  for( fd_rotor_blk_t * blk = blk_map_ele_query( rotor->blk_map, &slot, NULL, rotor->blk_pool );
                        blk;
                        blk = next ) {
    next = (fd_rotor_blk_t *)blk_map_ele_next_const( blk, NULL, rotor->blk_pool );
    prune( rotor, blk );
  }
}
