#include "fd_rotor.h"
#include "../../ballet/bmtree/fd_bmtree.h"
#include "../../ballet/sha256/fd_sha256.h"

static fd_rotor_blk_t * blk_insert( fd_rotor_t * rotor, ulong            slot, fd_hash_t const * block_id );
static fd_rotor_fec_t * fec_insert( fd_rotor_t * rotor, fd_rotor_blk_t * blk,  uint              fec_idx  );

FD_FN_CONST ulong
fd_rotor_align( void ) {
  return fd_ulong_max( alignof(fd_rotor_t), 128UL );
}

FD_FN_CONST ulong
fd_rotor_footprint( ulong slot_max ) {
  ulong blk_max = ( slot_max + 1UL ) * AG_EQVOC_BLOCK_HASH_MAX;
  ulong fec_max = blk_max * FD_FEC_BLK_MAX;
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
      fd_rotor_align(),       sizeof(fd_rotor_t)                                           ),
      blk_pool_align(),       blk_pool_footprint      ( blk_max                          ) ),
      blk_map_align(),        blk_map_footprint       ( blk_map_chain_cnt_est( blk_max ) ) ),
      fec_pool_align(),       fec_pool_footprint      ( fec_max                          ) ),
      fec_map_align(),        fec_map_footprint       ( fec_map_chain_cnt_est( fec_max ) ) ),
      fd_rotor_treap_align(), fd_rotor_treap_footprint( fec_max                          ) ),
      fd_rotor_treap_align(), fd_rotor_treap_footprint( fec_max                          ) ),
      reasm_queue_align(),    reasm_queue_footprint   ( fec_max                          ) ),
    fd_rotor_align() );
}

void *
fd_rotor_new( void * shmem,
              ulong  slot_max,
              ulong  seed ) {
  ulong footprint = fd_rotor_footprint( slot_max );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "bad footprint: %lu", slot_max ));
    return NULL;
  }

  fd_memset( shmem, 0, footprint );
  fd_rotor_t * rotor;

  ulong blk_max = ( slot_max + 1UL ) * AG_EQVOC_BLOCK_HASH_MAX;
  ulong fec_max = blk_max * FD_FEC_BLK_MAX;

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  rotor              = FD_SCRATCH_ALLOC_APPEND( l, fd_rotor_align(),       sizeof(fd_rotor_t)                                           );
  void * blk_pool    = FD_SCRATCH_ALLOC_APPEND( l, blk_pool_align(),       blk_pool_footprint      ( blk_max                          ) );
  void * blk_map     = FD_SCRATCH_ALLOC_APPEND( l, blk_map_align(),        blk_map_footprint       ( blk_map_chain_cnt_est( blk_max ) ) );
  void * fec_pool    = FD_SCRATCH_ALLOC_APPEND( l, fec_pool_align(),       fec_pool_footprint      ( fec_max                          ) );
  void * fec_map     = FD_SCRATCH_ALLOC_APPEND( l, fec_map_align(),        fec_map_footprint       ( fec_map_chain_cnt_est( fec_max ) ) );
  void * eager_treap = FD_SCRATCH_ALLOC_APPEND( l, fd_rotor_treap_align(), fd_rotor_treap_footprint( fec_max                          ) );
  void * notar_treap = FD_SCRATCH_ALLOC_APPEND( l, fd_rotor_treap_align(), fd_rotor_treap_footprint( fec_max                          ) );
  void * reasm_queue = FD_SCRATCH_ALLOC_APPEND( l, reasm_queue_align(),    reasm_queue_footprint   ( fec_max                          ) );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, fd_rotor_align() ) == (ulong)shmem + footprint );

  rotor->root        = ULONG_MAX;
  rotor->slot_max    = slot_max;
  rotor->blk_pool    = blk_pool_join      ( blk_pool_new      ( blk_pool,    blk_max                                ) );
  rotor->blk_map     = blk_map_join       ( blk_map_new       ( blk_map,     blk_map_chain_cnt_est( blk_max ), seed ) );
  rotor->fec_pool    = fec_pool_join      ( fec_pool_new      ( fec_pool,    fec_max                                ) );
  rotor->fec_map     = fec_map_join       ( fec_map_new       ( fec_map,     fec_map_chain_cnt_est( fec_max ), seed ) );
  rotor->eager_treap = fd_rotor_treap_join( fd_rotor_treap_new( eager_treap, fec_max                                ) );
  rotor->notar_treap = fd_rotor_treap_join( fd_rotor_treap_new( notar_treap, fec_max                                ) );
  rotor->reasm_queue = reasm_queue_join   ( reasm_queue_new   ( reasm_queue, fec_max                                ) );
  fd_rotor_treap_seed( rotor->fec_pool, fec_max, seed ^ 0x5eedUL );

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
fd_rotor_init( fd_rotor_t *      rotor,
               ulong             root,
               fd_hash_t const * root_block_id ) {
  rotor->root = root;
  fd_rotor_blk_t * blk = blk_insert( rotor, root, root_block_id );
  blk->complete_fec_idx = 0U;
  blk->parent_slot      = root;
  fd_rotor_fec_t * fec = fec_insert( rotor, blk, 0U );
  fec->rcvd      = UINT_MAX;
  fec->complete  = 1;
  fec->connected = 1;
  fd_rotor_treap_ele_remove( rotor->notar_treap, fec, rotor->fec_pool );
  fec->treap = 0;
}

void
fd_rotor_fini( fd_rotor_t * rotor ) {
  fd_rotor_blk_t * blk_pool = rotor->blk_pool;
  blk_map_t      * blk_map  = rotor->blk_map;
  fd_rotor_fec_t * fec_pool = rotor->fec_pool;
  fec_map_t      * fec_map  = rotor->fec_map;

  for( ulong i=0UL; i<=rotor->slot_max; i++ ) {
    ulong slot = rotor->root + i;
    fd_rotor_blk_t * next;
    for( fd_rotor_blk_t * blk = blk_map_ele_query( blk_map, &slot, NULL, blk_pool );
                              blk;
                          blk = next ) {
      next = (fd_rotor_blk_t *)blk_map_ele_next_const( blk, NULL, blk_pool );
      for( uint k=0U; k<FD_FEC_BLK_MAX && blk->fecs[k]!=UINT_MAX; k++ ) {
        fd_rotor_fec_t * fec = fec_pool_ele( fec_pool, blk->fecs[k] );
        if( FD_LIKELY( fec->treap ) ) { fd_rotor_treap_ele_remove( fd_hash_check_zero( &blk->block_id ) ? rotor->eager_treap : rotor->notar_treap, fec, fec_pool ); fec->treap = 0; }
        if( FD_LIKELY( fec->root  ) ) fec_map_ele_remove_fast( fec_map, fec, fec_pool );
        fec_pool_ele_release( fec_pool, fec );
      }
      blk_map_ele_remove_fast( blk_map, blk, blk_pool );
      blk_pool_ele_release( blk_pool, blk );
    }
  }
  reasm_queue_remove_all( rotor->reasm_queue );
  rotor->root = ULONG_MAX;
}

static fd_rotor_blk_t *
blk_insert( fd_rotor_t *      rotor,
            ulong             slot,
            fd_hash_t const * block_id ) {
  FD_TEST( blk_pool_free( rotor->blk_pool ) );
  fd_rotor_blk_t * blk = blk_pool_ele_acquire( rotor->blk_pool );
  blk->slot             = slot;
  blk->final            = 0;
  blk->complete_fec_idx = UINT_MAX;
  blk->parent_slot      = ULONG_MAX;
  if( FD_LIKELY( block_id ) ) blk->block_id = *block_id;
  else                        fd_memset( &blk->block_id, 0, sizeof(fd_hash_t) );
  fd_memset( &blk->parent_block_id, 0,    sizeof(fd_hash_t) );
  fd_memset( blk->fecs,             0xFF, sizeof(blk->fecs) );
  blk_map_ele_insert( rotor->blk_map, blk, rotor->blk_pool );
  return blk;
}

static fd_rotor_fec_t *
fec_insert( fd_rotor_t *     rotor,
            fd_rotor_blk_t * blk,
            uint             fec_idx ) {
  FD_TEST( fec_pool_free( rotor->fec_pool ) );
  fd_rotor_fec_t * fec = fec_pool_ele_acquire( rotor->fec_pool );
  fec->slot          = blk->slot;
  fec->fec_idx       = fec_idx;
  fec->rcvd          = 0U;
  fec->root          = 0;
  fec->complete      = 0;
  fec->connected     = 0;
  fec->data_complete = 0;
  fec->is_leader     = 0;
  fec->treap         = 1;
  fd_memset( &fec->merkle_root, 0, sizeof(fd_rotor_dmr_t) );
  blk->fecs[ fec_idx ] = (uint)fec_pool_idx( rotor->fec_pool, fec );
  fd_rotor_treap_ele_insert( fd_hash_check_zero( &blk->block_id ) ? rotor->eager_treap : rotor->notar_treap, fec, rotor->fec_pool );
  return fec;
}

static int
derive_dmr( fd_rotor_t *     rotor,
            fd_rotor_blk_t * blk ) {
  if( FD_UNLIKELY( blk->complete_fec_idx==UINT_MAX || blk->parent_slot==ULONG_MAX || fd_hash_check_zero( &blk->parent_block_id ) ) ) return 0;

  uint fec_set_cnt = blk->complete_fec_idx + 1U;
  uchar tree_mem[ FD_BMTREE_COMMIT_FOOTPRINT( 0UL ) ] __attribute__((aligned(FD_BMTREE_COMMIT_ALIGN)));
  fd_bmtree_commit_t * tree = fd_bmtree_commit_init( tree_mem, FD_SHRED_MERKLE_NODE_SZ, FD_BMTREE_LONG_PREFIX_SZ, 0UL );

  for( uint k=0U; k<fec_set_cnt; k++ ) {
    fd_rotor_fec_t * fec = fd_rotor_fec_query( rotor, blk, k );
    if( FD_UNLIKELY( !fec || !fec->root ) ) return 0;
    fd_bmtree_node_t leaf[1] = {0};
    memcpy( leaf->hash, fec->merkle_root.uc, sizeof(fd_rotor_dmr_t) );
    fd_bmtree_commit_append( tree, leaf, 1UL );
  }

  fd_bmtree_node_t parent_info[1];
  fd_sha256_t sha[1];
  fd_sha256_init  ( sha );
  fd_sha256_append( sha, &blk->parent_slot,       sizeof(ulong)     );
  fd_sha256_append( sha, blk->parent_block_id.uc, sizeof(fd_hash_t) );
  fd_sha256_append( sha, &fec_set_cnt,            sizeof(uint)      );
  fd_sha256_fini  ( sha, parent_info->hash );
  fd_bmtree_commit_append( tree, parent_info, 1UL );

  memcpy( blk->block_id.uc, fd_bmtree_commit_fini( tree ), sizeof(fd_hash_t) );
  return 1;
}

void
fd_rotor_blk_final( fd_rotor_t *      rotor,
                    ulong             slot,
                    fd_hash_t const * block_id ) {
  if( FD_UNLIKELY( slot<=rotor->root || slot>rotor->root+rotor->slot_max || fd_hash_check_zero( block_id ) ) ) return;

  fd_rotor_blk_t * blk_pool = rotor->blk_pool;
  blk_map_t      * blk_map  = rotor->blk_map;
  fd_rotor_fec_t * fec_pool = rotor->fec_pool;
  fec_map_t      * fec_map  = rotor->fec_map;

  fd_rotor_blk_t * blk    = NULL;
  int              refuse = 0;
  for( fd_rotor_blk_t * v = blk_map_ele_query( blk_map, &slot, NULL, blk_pool );
                          v;
                      v = (fd_rotor_blk_t *)blk_map_ele_next_const( v, NULL, blk_pool ) ) {
    if( FD_LIKELY( fd_hash_eq( &v->block_id, block_id ) ) ) blk = v;
    else if( FD_UNLIKELY( v->final ) )                     refuse = 1;
  }
  if( FD_UNLIKELY( !blk && !refuse ) ) { blk = blk_insert( rotor, slot, block_id ); fec_insert( rotor, blk, 0U ); }
  if( FD_UNLIKELY( !blk ) ) { FD_LOG_WARNING(( "final for slot %lu names a refused version", slot )); return; }

  fd_rotor_blk_t * next;
  for( fd_rotor_blk_t * b=blk;; ) {
    b->final = 1;

    for( fd_rotor_blk_t * sibling = blk_map_ele_query( blk_map, &b->slot, NULL, blk_pool );
                                    sibling;
                          sibling = next ) {
      next = (fd_rotor_blk_t *)blk_map_ele_next_const( sibling, NULL, blk_pool );
      if( FD_LIKELY( sibling==b ) ) continue;
      for( uint k=0U; k<FD_FEC_BLK_MAX && sibling->fecs[k]!=UINT_MAX; k++ ) {
        fd_rotor_fec_t * fec = fec_pool_ele( fec_pool, sibling->fecs[k] );
        if( FD_LIKELY( fec->treap ) ) { fd_rotor_treap_ele_remove( fd_hash_check_zero( &sibling->block_id ) ? rotor->eager_treap : rotor->notar_treap, fec, fec_pool ); fec->treap = 0; }
        if( FD_LIKELY( fec->root  ) ) fec_map_ele_remove_fast( fec_map, fec, fec_pool );
        fec_pool_ele_release( fec_pool, fec );
      }
      blk_map_ele_remove_fast( blk_map, sibling, blk_pool );
      blk_pool_ele_release( blk_pool, sibling );
    }

    if( FD_UNLIKELY( b->parent_slot==ULONG_MAX || fd_hash_check_zero( &b->parent_block_id ) ) ) break;
    for( ulong s=b->parent_slot+1UL; s<b->slot; s++ ) fd_rotor_slot_skip( rotor, s );
    if( FD_UNLIKELY( b->parent_slot<=rotor->root ) ) break;

    fd_rotor_blk_t * p       = NULL;
    int              prefuse = 0;
    for( fd_rotor_blk_t * v = blk_map_ele_query( blk_map, &b->parent_slot, NULL, blk_pool );
                            v;
                        v = (fd_rotor_blk_t *)blk_map_ele_next_const( v, NULL, blk_pool ) ) {
      if( FD_LIKELY( fd_hash_eq( &v->block_id, &b->parent_block_id ) ) ) p = v;
      else if( FD_UNLIKELY( v->final ) )                                prefuse = 1;
    }
    if( FD_UNLIKELY( !p && !prefuse ) ) { p = blk_insert( rotor, b->parent_slot, &b->parent_block_id ); fec_insert( rotor, p, 0U ); }
    if( FD_LIKELY( !p || p->final ) ) break;
    b = p;
  }
}

void
fd_rotor_blk_notar( fd_rotor_t *      rotor,
                    ulong             slot,
                    fd_hash_t const * block_id ) {
  if( FD_UNLIKELY( slot<=rotor->root || slot>rotor->root+rotor->slot_max || fd_hash_check_zero( block_id ) ) ) return;

  fd_rotor_blk_t * blk_pool = rotor->blk_pool;
  blk_map_t      * blk_map  = rotor->blk_map;
  fd_rotor_fec_t * fec_pool = rotor->fec_pool;
  fec_map_t      * fec_map  = rotor->fec_map;

  fd_rotor_blk_t * eager  = NULL;
  int              refuse = 0;
  for( fd_rotor_blk_t * v = blk_map_ele_query( blk_map, &slot, NULL, blk_pool );
                          v;
                      v = (fd_rotor_blk_t *)blk_map_ele_next_const( v, NULL, blk_pool ) ) {
    if( FD_LIKELY( fd_hash_check_zero( &v->block_id ) ) )                       eager  = v;
    else if( FD_UNLIKELY( v->final || fd_hash_eq( &v->block_id, block_id ) ) ) refuse = 1;
  }

  if( FD_LIKELY( eager ) ) {
    for( uint k=0U; k<FD_FEC_BLK_MAX && eager->fecs[k]!=UINT_MAX; k++ ) {
      fd_rotor_fec_t * fec = fec_pool_ele( fec_pool, eager->fecs[k] );
      if( FD_LIKELY( fec->treap ) ) { fd_rotor_treap_ele_remove( rotor->eager_treap, fec, fec_pool ); fec->treap = 0; }
      if( FD_LIKELY( fec->root  ) ) fec_map_ele_remove_fast( fec_map, fec, fec_pool );
      fec_pool_ele_release( fec_pool, fec );
    }
    blk_map_ele_remove_fast( blk_map, eager, blk_pool );
    blk_pool_ele_release( blk_pool, eager );
  }

  if( FD_UNLIKELY( refuse ) ) return;
  fec_insert( rotor, blk_insert( rotor, slot, block_id ), 0U );
}

void
fd_rotor_blk_parent( fd_rotor_t *      rotor,
                     ulong             slot,
                     fd_hash_t const * block_id,
                     ulong             parent_slot,
                     fd_hash_t const * parent_block_id,
                     uint              complete_fec_idx ) {
  if( FD_UNLIKELY( slot<=rotor->root || slot>rotor->root+rotor->slot_max ) ) return;
  if( FD_UNLIKELY( complete_fec_idx!=UINT_MAX && complete_fec_idx>=FD_FEC_BLK_MAX ) ) return;

  fd_rotor_blk_t * blk_pool = rotor->blk_pool;
  blk_map_t      * blk_map  = rotor->blk_map;
  fd_rotor_fec_t * fec_pool = rotor->fec_pool;
  fec_map_t      * fec_map  = rotor->fec_map;

  fd_hash_t         null = {0};
  fd_hash_t const * id   = block_id ? block_id : &null;
  fd_rotor_blk_t *  blk  = NULL;
  for( fd_rotor_blk_t * v = blk_map_ele_query( blk_map, &slot, NULL, blk_pool );
                          v;
                      v = (fd_rotor_blk_t *)blk_map_ele_next_const( v, NULL, blk_pool ) ) {
    if( FD_LIKELY( fd_hash_eq( &v->block_id, id ) ) ) blk = v;
  }
  if( FD_UNLIKELY( !blk ) ) return;
  int eager = !block_id;
  if( FD_UNLIKELY( !eager && ( complete_fec_idx==UINT_MAX || blk->complete_fec_idx!=UINT_MAX ) ) ) return;

  int bad = parent_slot<rotor->root || parent_slot>=slot || fd_hash_check_zero( parent_block_id );
  if( FD_UNLIKELY( eager && blk->parent_slot!=ULONG_MAX && blk->parent_slot!=parent_slot ) ) bad = 1;
  if( FD_UNLIKELY( eager && !fd_hash_check_zero( &blk->parent_block_id ) && !fd_hash_eq( &blk->parent_block_id, parent_block_id ) ) ) bad = 1;
  if( FD_UNLIKELY( eager && !bad && complete_fec_idx!=UINT_MAX ) ) {
    if( FD_UNLIKELY( blk->complete_fec_idx!=UINT_MAX && blk->complete_fec_idx!=complete_fec_idx ) ) bad = 1;
    if( FD_UNLIKELY( fd_rotor_fec_query( rotor, blk, complete_fec_idx+1U ) ) )                    bad = 1;
  }
  if( FD_UNLIKELY( bad ) ) {
    for( uint k=0U; k<FD_FEC_BLK_MAX && blk->fecs[k]!=UINT_MAX; k++ ) {
      fd_rotor_fec_t * fec = fec_pool_ele( fec_pool, blk->fecs[k] );
      if( FD_LIKELY( fec->treap ) ) { fd_rotor_treap_ele_remove( eager ? rotor->eager_treap : rotor->notar_treap, fec, fec_pool ); fec->treap = 0; }
      if( FD_LIKELY( fec->root  ) ) fec_map_ele_remove_fast( fec_map, fec, fec_pool );
      fec_pool_ele_release( fec_pool, fec );
    }
    blk_map_ele_remove_fast( blk_map, blk, blk_pool );
    blk_pool_ele_release( blk_pool, blk );
    return;
  }

  if( FD_UNLIKELY( !eager ) ) {
    fd_rotor_blk_t * p       = NULL;
    int              prefuse = 0;
    for( fd_rotor_blk_t * v = blk_map_ele_query( blk_map, &parent_slot, NULL, blk_pool );
                            v;
                        v = (fd_rotor_blk_t *)blk_map_ele_next_const( v, NULL, blk_pool ) ) {
      if( FD_LIKELY( fd_hash_eq( &v->block_id, parent_block_id ) ) ) p = v;
      else if( FD_UNLIKELY( v->final ) )                            prefuse = 1;
    }
    if( FD_UNLIKELY( !p && !prefuse && parent_slot>rotor->root ) ) fec_insert( rotor, blk_insert( rotor, parent_slot, parent_block_id ), 0U );
  }

  blk->parent_slot     = parent_slot;
  blk->parent_block_id = *parent_block_id;
  if( FD_UNLIKELY( complete_fec_idx!=UINT_MAX ) ) {
    blk->complete_fec_idx = complete_fec_idx;
    for( uint k=0U; k<=complete_fec_idx; k++ ) if( FD_UNLIKELY( !fd_rotor_fec_query( rotor, blk, k ) ) ) fec_insert( rotor, blk, k );
  }
  fd_rotor_fec_t * fec0 = fd_rotor_fec_query( rotor, blk, 0U );
  if( FD_UNLIKELY( fec0 && fec0->complete && fec0->treap ) ) {
    fd_rotor_treap_ele_remove( eager ? rotor->eager_treap : rotor->notar_treap, fec0, fec_pool );
    fec0->treap = 0;
  }

  fd_rotor_blk_t * next;
  if( FD_UNLIKELY( blk->final ) ) for( fd_rotor_blk_t * b=blk;; ) {
    if( FD_UNLIKELY( b->parent_slot==ULONG_MAX || fd_hash_check_zero( &b->parent_block_id ) ) ) break;
    for( ulong s=b->parent_slot+1UL; s<b->slot; s++ ) fd_rotor_slot_skip( rotor, s );
    if( FD_UNLIKELY( b->parent_slot<=rotor->root ) ) break;
    fd_rotor_blk_t * p = NULL;
    for( fd_rotor_blk_t * v = blk_map_ele_query( blk_map, &b->parent_slot, NULL, blk_pool );
                            v;
                        v = (fd_rotor_blk_t *)blk_map_ele_next_const( v, NULL, blk_pool ) ) {
      if( FD_LIKELY( fd_hash_eq( &v->block_id, &b->parent_block_id ) ) ) p = v;
    }
    if( FD_LIKELY( !p || p->final ) ) break;
    p->final = 1;
    for( fd_rotor_blk_t * sibling = blk_map_ele_query( blk_map, &p->slot, NULL, blk_pool );
                                    sibling;
                          sibling = next ) {
      next = (fd_rotor_blk_t *)blk_map_ele_next_const( sibling, NULL, blk_pool );
      if( FD_LIKELY( sibling==p ) ) continue;
      for( uint k=0U; k<FD_FEC_BLK_MAX && sibling->fecs[k]!=UINT_MAX; k++ ) {
        fd_rotor_fec_t * fec = fec_pool_ele( fec_pool, sibling->fecs[k] );
        if( FD_LIKELY( fec->treap ) ) { fd_rotor_treap_ele_remove( fd_hash_check_zero( &sibling->block_id ) ? rotor->eager_treap : rotor->notar_treap, fec, fec_pool ); fec->treap = 0; }
        if( FD_LIKELY( fec->root  ) ) fec_map_ele_remove_fast( fec_map, fec, fec_pool );
        fec_pool_ele_release( fec_pool, fec );
      }
      blk_map_ele_remove_fast( blk_map, sibling, blk_pool );
      blk_pool_ele_release( blk_pool, sibling );
    }
    b = p;
  }

  if( FD_UNLIKELY( eager && blk->complete_fec_idx!=UINT_MAX ) ) {
    int whole = 1;
    for( uint k=0U; k<=blk->complete_fec_idx; k++ ) {
      fd_rotor_fec_t * fec = fd_rotor_fec_query( rotor, blk, k );
      if( FD_UNLIKELY( !fec || !fec->complete ) ) { whole = 0; break; }
    }
    if( FD_LIKELY( whole && derive_dmr( rotor, blk ) ) ) {
      for( uint k=0U; k<=blk->complete_fec_idx; k++ ) {
        fd_rotor_fec_t * fec = fd_rotor_fec_query( rotor, blk, k );
        if( FD_UNLIKELY( fec->treap ) ) { fd_rotor_treap_ele_remove( rotor->eager_treap, fec, fec_pool ); fec->treap = 0; }
      }
      for( fd_rotor_blk_t * sibling = blk_map_ele_query( blk_map, &slot, NULL, blk_pool );
                                      sibling;
                            sibling = next ) {
        next = (fd_rotor_blk_t *)blk_map_ele_next_const( sibling, NULL, blk_pool );
        if( FD_LIKELY( sibling==blk ) ) continue;
        fd_rotor_blk_t * gone = NULL;
        if( FD_UNLIKELY( fd_hash_eq( &sibling->block_id, &blk->block_id ) ) ) { blk->final |= sibling->final; gone = sibling; }
        else if( FD_UNLIKELY( sibling->final ) )                               gone = blk;
        if( FD_LIKELY( !gone ) ) continue;
        for( uint k=0U; k<FD_FEC_BLK_MAX && gone->fecs[k]!=UINT_MAX; k++ ) {
          fd_rotor_fec_t * fec = fec_pool_ele( fec_pool, gone->fecs[k] );
          if( FD_UNLIKELY( fec->treap ) ) { fd_rotor_treap_ele_remove( rotor->notar_treap, fec, fec_pool ); fec->treap = 0; }
          if( FD_LIKELY( fec->root    ) ) fec_map_ele_remove_fast( fec_map, fec, fec_pool );
          fec_pool_ele_release( fec_pool, fec );
        }
        blk_map_ele_remove_fast( blk_map, gone, blk_pool );
        blk_pool_ele_release( blk_pool, gone );
        if( FD_UNLIKELY( gone==blk ) ) return;
      }
    }
  }

  for( ulong s=slot; s<=rotor->root+rotor->slot_max; s++ ) {
    for( fd_rotor_blk_t * b = blk_map_ele_query( blk_map, &s, NULL, blk_pool );
                            b;
                        b = (fd_rotor_blk_t *)blk_map_ele_next_const( b, NULL, blk_pool ) ) {
      if( FD_UNLIKELY( fd_hash_check_zero( &b->parent_block_id ) ) ) continue;
      int chained = 0;
      for( fd_rotor_blk_t * p = blk_map_ele_query( blk_map, &b->parent_slot, NULL, blk_pool );
                              p;
                          p = (fd_rotor_blk_t *)blk_map_ele_next_const( p, NULL, blk_pool ) ) {
        if( FD_UNLIKELY( !fd_hash_eq( &p->block_id, &b->parent_block_id ) ) ) continue;
        fd_rotor_fec_t * last = p->complete_fec_idx!=UINT_MAX ? fd_rotor_fec_query( rotor, p, p->complete_fec_idx ) : NULL;
        chained = last && last->connected;
        break;
      }
      for( uint k=0U; chained && k<FD_FEC_BLK_MAX; k++ ) {
        fd_rotor_fec_t * fec = fd_rotor_fec_query( rotor, b, k );
        if( FD_UNLIKELY( !fec || !fec->complete ) ) break;
        if( FD_LIKELY( fec->connected ) ) continue;
        fec->connected = 1;
        if( FD_UNLIKELY( reasm_queue_full( rotor->reasm_queue ) ) ) FD_LOG_CRIT(( "rotor reasm_queue full" ));
        reasm_queue_push( rotor->reasm_queue, (reasm_t){ .blk_idx = (uint)blk_pool_idx( blk_pool, b ), .fec_idx = k } );
      }
    }
  }
}

int
fd_rotor_fec_complete( fd_rotor_t *           rotor,
                       ulong                  slot,
                       uint                   fec_idx,
                       fd_rotor_dmr_t const * merkle_root,
                       int                    slot_complete,
                       int                    data_complete,
                       int                    is_leader ) {
  if( FD_UNLIKELY( slot<=rotor->root || slot>rotor->root+rotor->slot_max ) ) return -1;
  if( FD_UNLIKELY( fec_idx>=FD_FEC_BLK_MAX ) ) return -1;

  fd_rotor_blk_t * blk_pool = rotor->blk_pool;
  blk_map_t      * blk_map  = rotor->blk_map;
  fd_rotor_fec_t * fec_pool = rotor->fec_pool;
  fec_map_t      * fec_map  = rotor->fec_map;

  fd_rotor_blk_t * eager = NULL;
  fd_rotor_fec_t * fec   = fec_map_ele_query( fec_map, merkle_root, NULL, fec_pool );
  if( FD_LIKELY( fec ) ) {
    if( FD_UNLIKELY( fec->slot!=slot || fec->fec_idx!=fec_idx ) ) return -1;
    for( fd_rotor_blk_t * v = blk_map_ele_query( blk_map, &slot, NULL, blk_pool );
                            v;
                        v = (fd_rotor_blk_t *)blk_map_ele_next_const( v, NULL, blk_pool ) ) {
      if( FD_LIKELY( fd_hash_check_zero( &v->block_id ) && v->fecs[ fec_idx ]==fec_pool_idx( fec_pool, fec ) ) ) eager = v;
    }
  } else {
    if( FD_UNLIKELY( !blk_map_ele_query( blk_map, &slot, NULL, blk_pool ) ) ) blk_insert( rotor, slot, NULL );
    for( fd_rotor_blk_t * v = blk_map_ele_query( blk_map, &slot, NULL, blk_pool );
                            v;
                        v = (fd_rotor_blk_t *)blk_map_ele_next_const( v, NULL, blk_pool ) ) {
      if( FD_LIKELY( fd_hash_check_zero( &v->block_id ) ) ) eager = v;
    }
    if( FD_UNLIKELY( !eager ) ) return -1;
    fec = fd_rotor_fec_query( rotor, eager, fec_idx );
    if( FD_UNLIKELY( ( eager->complete_fec_idx!=UINT_MAX && fec_idx>eager->complete_fec_idx ) || ( fec && fec->root ) ) ) {
      for( uint k=0U; k<FD_FEC_BLK_MAX && eager->fecs[k]!=UINT_MAX; k++ ) {
        fd_rotor_fec_t * f = fec_pool_ele( fec_pool, eager->fecs[k] );
        if( FD_LIKELY( f->treap ) ) { fd_rotor_treap_ele_remove( rotor->eager_treap, f, fec_pool ); f->treap = 0; }
        if( FD_LIKELY( f->root  ) ) fec_map_ele_remove_fast( fec_map, f, fec_pool );
        fec_pool_ele_release( fec_pool, f );
      }
      blk_map_ele_remove_fast( blk_map, eager, blk_pool );
      blk_pool_ele_release( blk_pool, eager );
      return -1;
    }
    for( uint k=0U; k<=fec_idx; k++ ) if( FD_UNLIKELY( !fd_rotor_fec_query( rotor, eager, k ) ) ) fec_insert( rotor, eager, k );
    fec              = fd_rotor_fec_query( rotor, eager, fec_idx );
    fec->merkle_root = *merkle_root;
    fec->root        = 1;
    fec_map_ele_insert( fec_map, fec, fec_pool );
  }

  if( FD_UNLIKELY( fec->complete ) ) return 0;
  fec->complete       = 1;
  fec->rcvd           = UINT_MAX;
  fec->data_complete |= !!data_complete;
  fec->is_leader     |= !!is_leader;
  if( FD_LIKELY( fec->treap && !( eager && !fec_idx && fd_hash_check_zero( &eager->parent_block_id ) ) ) ) {
    fd_rotor_treap_ele_remove( eager ? rotor->eager_treap : rotor->notar_treap, fec, fec_pool );
    fec->treap = 0;
  }

  if( FD_UNLIKELY( eager && slot_complete ) ) {
    if( FD_UNLIKELY( ( eager->complete_fec_idx!=UINT_MAX && eager->complete_fec_idx!=fec_idx ) || fd_rotor_fec_query( rotor, eager, fec_idx+1U ) ) ) {
      for( uint k=0U; k<FD_FEC_BLK_MAX && eager->fecs[k]!=UINT_MAX; k++ ) {
        fd_rotor_fec_t * f = fec_pool_ele( fec_pool, eager->fecs[k] );
        if( FD_UNLIKELY( f->treap ) ) { fd_rotor_treap_ele_remove( rotor->eager_treap, f, fec_pool ); f->treap = 0; }
        if( FD_LIKELY( f->root    ) ) fec_map_ele_remove_fast( fec_map, f, fec_pool );
        fec_pool_ele_release( fec_pool, f );
      }
      blk_map_ele_remove_fast( blk_map, eager, blk_pool );
      blk_pool_ele_release( blk_pool, eager );
      return 0;
    }
    eager->complete_fec_idx = fec_idx;
  }

  if( FD_UNLIKELY( eager && eager->complete_fec_idx!=UINT_MAX ) ) {
    int whole = 1;
    for( uint k=0U; k<=eager->complete_fec_idx; k++ ) {
      fd_rotor_fec_t * f = fd_rotor_fec_query( rotor, eager, k );
      if( FD_UNLIKELY( !f || !f->complete ) ) { whole = 0; break; }
    }
    if( FD_LIKELY( whole && derive_dmr( rotor, eager ) ) ) {
      for( uint k=0U; k<=eager->complete_fec_idx; k++ ) {
        fd_rotor_fec_t * f = fd_rotor_fec_query( rotor, eager, k );
        if( FD_UNLIKELY( f->treap ) ) { fd_rotor_treap_ele_remove( rotor->eager_treap, f, fec_pool ); f->treap = 0; }
      }
      fd_rotor_blk_t * next;
      for( fd_rotor_blk_t * sibling = blk_map_ele_query( blk_map, &slot, NULL, blk_pool );
                                      sibling;
                            sibling = next ) {
        next = (fd_rotor_blk_t *)blk_map_ele_next_const( sibling, NULL, blk_pool );
        if( FD_LIKELY( sibling==eager ) ) continue;
        fd_rotor_blk_t * gone = NULL;
        if( FD_UNLIKELY( fd_hash_eq( &sibling->block_id, &eager->block_id ) ) ) { eager->final |= sibling->final; gone = sibling; }
        else if( FD_UNLIKELY( sibling->final ) )                                 gone = eager;
        if( FD_LIKELY( !gone ) ) continue;
        for( uint k=0U; k<FD_FEC_BLK_MAX && gone->fecs[k]!=UINT_MAX; k++ ) {
          fd_rotor_fec_t * f = fec_pool_ele( fec_pool, gone->fecs[k] );
          if( FD_UNLIKELY( f->treap ) ) { fd_rotor_treap_ele_remove( rotor->notar_treap, f, fec_pool ); f->treap = 0; }
          if( FD_LIKELY( f->root    ) ) fec_map_ele_remove_fast( fec_map, f, fec_pool );
          fec_pool_ele_release( fec_pool, f );
        }
        blk_map_ele_remove_fast( blk_map, gone, blk_pool );
        blk_pool_ele_release( blk_pool, gone );
        if( FD_UNLIKELY( gone==eager ) ) return 0;
      }
    }
  }

  for( ulong s=slot; s<=rotor->root+rotor->slot_max; s++ ) {
    for( fd_rotor_blk_t * b = blk_map_ele_query( blk_map, &s, NULL, blk_pool );
                            b;
                        b = (fd_rotor_blk_t *)blk_map_ele_next_const( b, NULL, blk_pool ) ) {
      if( FD_UNLIKELY( fd_hash_check_zero( &b->parent_block_id ) ) ) continue;
      int chained = 0;
      for( fd_rotor_blk_t * p = blk_map_ele_query( blk_map, &b->parent_slot, NULL, blk_pool );
                              p;
                          p = (fd_rotor_blk_t *)blk_map_ele_next_const( p, NULL, blk_pool ) ) {
        if( FD_UNLIKELY( !fd_hash_eq( &p->block_id, &b->parent_block_id ) ) ) continue;
        fd_rotor_fec_t * last = p->complete_fec_idx!=UINT_MAX ? fd_rotor_fec_query( rotor, p, p->complete_fec_idx ) : NULL;
        chained = last && last->connected;
        break;
      }
      for( uint k=0U; chained && k<FD_FEC_BLK_MAX; k++ ) {
        fd_rotor_fec_t * f = fd_rotor_fec_query( rotor, b, k );
        if( FD_UNLIKELY( !f || !f->complete ) ) break;
        if( FD_LIKELY( f->connected ) ) continue;
        f->connected = 1;
        if( FD_UNLIKELY( reasm_queue_full( rotor->reasm_queue ) ) ) FD_LOG_CRIT(( "rotor reasm_queue full" ));
        reasm_queue_push( rotor->reasm_queue, (reasm_t){ .blk_idx = (uint)blk_pool_idx( blk_pool, b ), .fec_idx = k } );
      }
    }
  }
  return 0;
}

fd_rotor_fec_t *
fd_rotor_fec_query( fd_rotor_t const *     rotor,
                    fd_rotor_blk_t const * blk,
                    uint                   fec_idx ) {
  if( FD_UNLIKELY( fec_idx>=FD_FEC_BLK_MAX ) ) return NULL;
  uint idx = blk->fecs[ fec_idx ];
  return idx==UINT_MAX ? NULL : fec_pool_ele( rotor->fec_pool, idx );
}

void
fd_rotor_shred_insert( fd_rotor_t *           rotor,
                       ulong                  slot,
                       uint                   shred_idx,
                       fd_rotor_dmr_t const * merkle_root ) {
  if( FD_UNLIKELY( slot<=rotor->root || slot>rotor->root+rotor->slot_max ) ) return;
  uint fec_idx = shred_idx / FD_FEC_SHRED_CNT;
  if( FD_UNLIKELY( fec_idx>=FD_FEC_BLK_MAX ) ) return;

  fd_rotor_blk_t * blk_pool = rotor->blk_pool;
  blk_map_t      * blk_map  = rotor->blk_map;
  fd_rotor_fec_t * fec_pool = rotor->fec_pool;
  fec_map_t      * fec_map  = rotor->fec_map;

  fd_rotor_fec_t * fec = fec_map_ele_query( fec_map, merkle_root, NULL, fec_pool );
  if( FD_LIKELY( fec ) ) {
    if( FD_UNLIKELY( fec->slot!=slot || fec->fec_idx!=fec_idx ) ) return;
  } else {
    if( FD_UNLIKELY( !blk_map_ele_query( blk_map, &slot, NULL, blk_pool ) ) ) blk_insert( rotor, slot, NULL );
    fd_rotor_blk_t * eager = NULL;
    for( fd_rotor_blk_t * v = blk_map_ele_query( blk_map, &slot, NULL, blk_pool );
                            v;
                        v = (fd_rotor_blk_t *)blk_map_ele_next_const( v, NULL, blk_pool ) ) {
      if( FD_LIKELY( fd_hash_check_zero( &v->block_id ) ) ) eager = v;
    }
    if( FD_UNLIKELY( !eager ) ) return;
    fec = fd_rotor_fec_query( rotor, eager, fec_idx );
    if( FD_UNLIKELY( ( eager->complete_fec_idx!=UINT_MAX && fec_idx>eager->complete_fec_idx ) || ( fec && fec->root ) ) ) {
      for( uint k=0U; k<FD_FEC_BLK_MAX && eager->fecs[k]!=UINT_MAX; k++ ) {
        fd_rotor_fec_t * f = fec_pool_ele( fec_pool, eager->fecs[k] );
        if( FD_LIKELY( f->treap ) ) { fd_rotor_treap_ele_remove( rotor->eager_treap, f, fec_pool ); f->treap = 0; }
        if( FD_LIKELY( f->root  ) ) fec_map_ele_remove_fast( fec_map, f, fec_pool );
        fec_pool_ele_release( fec_pool, f );
      }
      blk_map_ele_remove_fast( blk_map, eager, blk_pool );
      blk_pool_ele_release( blk_pool, eager );
      return;
    }
    for( uint k=0U; k<=fec_idx; k++ ) if( FD_UNLIKELY( !fd_rotor_fec_query( rotor, eager, k ) ) ) fec_insert( rotor, eager, k );
    fec              = fd_rotor_fec_query( rotor, eager, fec_idx );
    fec->merkle_root = *merkle_root;
    fec->root        = 1;
    fec_map_ele_insert( fec_map, fec, fec_pool );
  }
  if( FD_LIKELY( !fec->complete ) ) fec->rcvd |= 1U << ( shred_idx - fec_idx*FD_FEC_SHRED_CNT );
}

void
fd_rotor_slot_eqvoc( fd_rotor_t * rotor,
                     ulong        slot ) {
  if( FD_UNLIKELY( slot<=rotor->root || slot>rotor->root+rotor->slot_max ) ) return;
  for( fd_rotor_blk_t * blk = blk_map_ele_query( rotor->blk_map, &slot, NULL, rotor->blk_pool );
                            blk;
                        blk = (fd_rotor_blk_t *)blk_map_ele_next_const( blk, NULL, rotor->blk_pool ) ) {
    if( FD_UNLIKELY( !fd_hash_check_zero( &blk->block_id ) ) ) continue;
    for( uint k=0U; k<FD_FEC_BLK_MAX && blk->fecs[k]!=UINT_MAX; k++ ) {
      fd_rotor_fec_t * fec = fec_pool_ele( rotor->fec_pool, blk->fecs[k] );
      if( FD_LIKELY( fec->treap ) ) { fd_rotor_treap_ele_remove( rotor->eager_treap, fec, rotor->fec_pool ); fec->treap = 0; }
      if( FD_LIKELY( fec->root  ) ) fec_map_ele_remove_fast( rotor->fec_map, fec, rotor->fec_pool );
      fec_pool_ele_release( rotor->fec_pool, fec );
    }
    blk_map_ele_remove_fast( rotor->blk_map, blk, rotor->blk_pool );
    blk_pool_ele_release( rotor->blk_pool, blk );
    return;
  }
}

void
fd_rotor_slot_inval( fd_rotor_t * rotor,
                     ulong        slot ) {
  if( FD_UNLIKELY( slot<=rotor->root || slot>rotor->root+rotor->slot_max ) ) return;
  for( fd_rotor_blk_t * blk = blk_map_ele_query( rotor->blk_map, &slot, NULL, rotor->blk_pool );
                            blk;
                        blk = (fd_rotor_blk_t *)blk_map_ele_next_const( blk, NULL, rotor->blk_pool ) ) {
    if( FD_UNLIKELY( !fd_hash_check_zero( &blk->block_id ) ) ) continue;
    for( uint k=0U; k<FD_FEC_BLK_MAX && blk->fecs[k]!=UINT_MAX; k++ ) {
      fd_rotor_fec_t * fec = fec_pool_ele( rotor->fec_pool, blk->fecs[k] );
      if( FD_LIKELY( fec->treap ) ) { fd_rotor_treap_ele_remove( rotor->eager_treap, fec, rotor->fec_pool ); fec->treap = 0; }
      if( FD_LIKELY( fec->root  ) ) fec_map_ele_remove_fast( rotor->fec_map, fec, rotor->fec_pool );
      fec_pool_ele_release( rotor->fec_pool, fec );
    }
    blk_map_ele_remove_fast( rotor->blk_map, blk, rotor->blk_pool );
    blk_pool_ele_release( rotor->blk_pool, blk );
    return;
  }
}

void
fd_rotor_slot_skip( fd_rotor_t * rotor,
                    ulong        slot ) {
  if( FD_UNLIKELY( slot<=rotor->root || slot>rotor->root+rotor->slot_max ) ) return;

  fd_rotor_blk_t * blk_pool = rotor->blk_pool;
  blk_map_t      * blk_map  = rotor->blk_map;
  fd_rotor_fec_t * fec_pool = rotor->fec_pool;
  fec_map_t      * fec_map  = rotor->fec_map;

  fd_rotor_blk_t * next;
  for( fd_rotor_blk_t * blk = blk_map_ele_query( blk_map, &slot, NULL, blk_pool );
                            blk;
                        blk = next ) {
    next = (fd_rotor_blk_t *)blk_map_ele_next_const( blk, NULL, blk_pool );
    for( uint k=0U; k<FD_FEC_BLK_MAX && blk->fecs[k]!=UINT_MAX; k++ ) {
      fd_rotor_fec_t * fec = fec_pool_ele( fec_pool, blk->fecs[k] );
      if( FD_LIKELY( fec->treap ) ) { fd_rotor_treap_ele_remove( fd_hash_check_zero( &blk->block_id ) ? rotor->eager_treap : rotor->notar_treap, fec, fec_pool ); fec->treap = 0; }
      if( FD_LIKELY( fec->root  ) ) fec_map_ele_remove_fast( fec_map, fec, fec_pool );
      fec_pool_ele_release( fec_pool, fec );
    }
    blk_map_ele_remove_fast( blk_map, blk, blk_pool );
    blk_pool_ele_release( blk_pool, blk );
  }
}
