#include "fd_chainer.h"

#define FD_CHAINER_SLOT_VER_MAX 4 /* should be FD_POOL_NF_CERT_MAX + 1 */

static inline ulong
version( ulong key ) {
  return key & 0x3;
}

fd_fec_t *
fec_exists( fd_fec_chainer_t * chainer, ulong slot, ulong fec_set_idx ) {
  fd_fec_map_t * ancestry = fd_chainer_fec_ancestry( chainer );
  fd_fec_map_t * frontier = fd_chainer_fec_frontier( chainer );
  fd_fec_map_t * subtrees = fd_chainer_fec_subtrees( chainer );
  fd_fec_map_t * orphaned = fd_chainer_fec_orphaned( chainer );
  fd_fec_t     * fec_pool = fd_chainer_fec_pool( chainer );

  ulong fec_key0 = FD_CHAINER_FEC_KEY( slot, fec_set_idx, 0 );
  fd_fec_t * fec =       fd_fec_map_ele_query( ancestry, &fec_key0, NULL, fec_pool );
  fec = fd_ptr_if( !fec, fd_fec_map_ele_query( frontier, &fec_key0, NULL, fec_pool ), fec );
  fec = fd_ptr_if( !fec, fd_fec_map_ele_query( subtrees, &fec_key0, NULL, fec_pool ), fec );
  fec = fd_ptr_if( !fec, fd_fec_map_ele_query( orphaned, &fec_key0, NULL, fec_pool ), fec );
  return fec;
}

fd_fec_t *
fec_query( fd_fec_chainer_t * chainer, ulong slot, ulong fec_set_idx, fd_hash_t const * mr ) {
  fd_fec_map_t * ancestry = fd_chainer_fec_ancestry( chainer );
  fd_fec_map_t * frontier = fd_chainer_fec_frontier( chainer );
  fd_fec_map_t * subtrees = fd_chainer_fec_subtrees( chainer );
  fd_fec_map_t * orphaned = fd_chainer_fec_orphaned( chainer );
  fd_fec_t     * fec_pool = fd_chainer_fec_pool( chainer );

  for( int i = 0; i < FD_CHAINER_SLOT_VER_MAX; i++ ) {
    ulong fec_key = FD_CHAINER_FEC_KEY( slot, fec_set_idx, i );
    fd_fec_t * fec =       fd_fec_map_ele_query( ancestry, &fec_key, NULL, fec_pool );
    fec = fd_ptr_if( !fec, fd_fec_map_ele_query( frontier, &fec_key, NULL, fec_pool ), fec );
    fec = fd_ptr_if( !fec, fd_fec_map_ele_query( subtrees, &fec_key, NULL, fec_pool ), fec );
    fec = fd_ptr_if( !fec, fd_fec_map_ele_query( orphaned, &fec_key, NULL, fec_pool ), fec );
    if( FD_LIKELY( fec ) ) if( FD_UNLIKELY( fd_hash_eq( &fec->merkle_root, mr ) ) ) return fec;
  }
  return NULL;
}

fd_fec_t *
acquire_fec( fd_fec_chainer_t * chainer,
             ulong              slot,
             ulong              fec_set_idx,
             fd_hash_t        * mr ) {
  fd_fec_t * fec_pool = fd_chainer_fec_pool( chainer );
  ulong      null     = fd_fec_pool_idx_null( fec_pool );

  if( FD_UNLIKELY( !fd_fec_pool_free( fec_pool ) ) ) FD_LOG_CRIT(("fec_pool is full. possible not possible?"));
  fd_fec_t * fec = fd_fec_pool_ele_acquire( fec_pool );
  fec->key = FD_CHAINER_FEC_KEY( slot, fec_set_idx, UINT_MAX /* TODO set version / or change to map multi */ );
  fec->merkle_root   = *mr;
  fec->slot_complete = 0;
  fec->parent        = null;
  fec->child         = null;
  fec->sibling       = null;
  return fec;
}

ulong
parse_update_parent( fd_shred_t * shred ) {


}

void
fd_chainer_shred_insert( fd_fec_chainer_t * chainer,
                         ulong              slot,
                         ulong              parent_off,
                         ulong              update_parent_slot,
                         ulong              fec_set_idx,
                         uint               shred_idx,
                         int                slot_complete,
                         fd_hash_t        * mr ) {
  fd_slot_t      * slot_pool  = fd_chainer_slot_pool( chainer );
  fd_slot_map_t  * slot_map   = fd_chainer_slot_map( chainer );
  fd_eslot_t     * eslot_pool = fd_chainer_eslot_pool( chainer );
  fd_eslot_map_t * eslot_map  = fd_chainer_eslot_map( chainer );


  fd_fec_t * fec = NULL;
  if( FD_UNLIKELY( !(fec = fec_exists( chainer, slot, fec_set_idx ) ) ) ) {
    /* FEC doesn't exist, but neither does any other version.
       first appearance of this FEC idx, create new FEC. chain to parent / child */
    fec = acquire_fec( chainer, slot, fec_set_idx, mr );
    ulong eslot_key = FD_CHAINER_ESLOT_KEY( slot, 0 );
    fd_eslot_t * eslot = fd_eslot_map_ele_query( eslot_map, &eslot_key, NULL, eslot_pool );

    if( FD_UNLIKELY( !eslot ) ) {
      eslot = acquire_eslot( chainer, slot );
    }

    fd_fec_t * parent = fec_exists( chainer, slot, fec_set_idx - 32 );




  } else if( FD_LIKELY( fec = fec_query( chainer, slot, fec_set_idx, mr ) ) ) {
    /* FEC already exists, update FEC */
    if( FD_UNLIKELY( slot_complete ) ) fec->slot_complete = 1;

    ulong    eslot_key = FD_CHAINER_ESLOT_KEY( slot, version(fec->key) );
    fd_eslot_t * eslot = fd_eslot_map_ele_query( eslot_map, &eslot_key, NULL, eslot_pool );
    FD_CHECK_CRIT( !!eslot, "eslot should exist" );

    /* update shred indexing */
    fd_shred_idxs_insert( &eslot->shred_idxs, shred_idx );
    eslot->complete_idx = fd_uint_if( slot_complete, shred_idx, eslot->complete_idx );
    while( eslot->buffered_idx + 1 < FD_SHRED_BLK_MAX && fd_shred_idxs_test( &eslot->shred_idxs, eslot->buffered_idx + 1U ) ) {
      eslot->buffered_idx++;
    }
    /* If equivocating, buffered_idx needs to be clamped to complete_idx */
    if( FD_UNLIKELY( eslot->buffered_idx != UINT_MAX && eslot->buffered_idx > eslot->complete_idx ) ) eslot->buffered_idx = eslot->complete_idx;
  }

  /* FEC doesn't exist, some other version exists. we should only
     accept this FEC if we have gotten a notar fallback that warrants
     this FEC. But in that case we would have completed getSliceHash
     for this FEC first, and that would get folded into case 2.
     Therefore it's safe to drop this shred. */
  return;
}

/* should get called by repair_tile on getSliceHash responses, after
   verifying the hash is correct for a notarfallback-ed block */

void
fd_chainer_verified_hash_insert( fd_fec_chainer_t * chainer,
                                 ulong              slot,
                                 ulong              fec_set_idx,
                                 fd_hash_t        * mr ) {



}


