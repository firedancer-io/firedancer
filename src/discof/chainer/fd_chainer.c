#include "fd_chainer.h"
#include "../../disco/shred/fd_fec_set.h"
#include "../../ballet/bmtree/fd_bmtree.h"
#include "../../ballet/sha256/fd_sha256.h"

#include <stdio.h>

void *
fd_chainer_new( void * shmem,
                ulong  ele_max,
                ulong  max_shreds_per_block,
                ulong  seed ) {
  ulong footprint = fd_chainer_footprint( ele_max, max_shreds_per_block );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "bad footprint: %lu %lu", ele_max, max_shreds_per_block ));
    return NULL;
  }

  fd_wksp_t * wksp = fd_wksp_containing( shmem );
  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_WARNING(( "shmem must be part of a workspace" ));
    return NULL;
  }

  fd_memset( shmem, 0, footprint );
  fd_chainer_t * chainer;

  ulong blk_max       = fd_chainer_blk_max( ele_max );
  ulong fec_blk_max   = max_shreds_per_block / FD_FEC_SHRED_CNT;
  ulong fec_max       = blk_max * fec_blk_max;
  ulong fec_chain_cnt = fd_fec_map_chain_cnt_est( fec_max );
  ulong blk_chain_cnt = fd_slotv_map_chain_cnt_est( blk_max );

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  chainer             = FD_SCRATCH_ALLOC_APPEND( l, fd_chainer_align(),      sizeof(fd_chainer_t)                       );
  void * fec_pool     = FD_SCRATCH_ALLOC_APPEND( l, fd_fec_pool_align(),     fd_fec_pool_footprint    ( fec_max       ) );
  void * fec_map      = FD_SCRATCH_ALLOC_APPEND( l, fd_fec_map_align(),      fd_fec_map_footprint     ( fec_chain_cnt ) );
  void * slotv_pool   = FD_SCRATCH_ALLOC_APPEND( l, fd_slotv_pool_align(),   fd_slotv_pool_footprint  ( blk_max       ) );
  void * fec_tbl      = FD_SCRATCH_ALLOC_APPEND( l, alignof(uint),           fec_max*sizeof(uint)                       );
  void * slotv_map    = FD_SCRATCH_ALLOC_APPEND( l, fd_slotv_map_align(),    fd_slotv_map_footprint   ( blk_chain_cnt ) );
  void * eager_treap  = FD_SCRATCH_ALLOC_APPEND( l, fd_rotor_treap_align(),  fd_rotor_treap_footprint ( fec_max       ) );
  void * notar_treap  = FD_SCRATCH_ALLOC_APPEND( l, fd_rotor_treap_align(),  fd_rotor_treap_footprint ( fec_max       ) );
  void * bfs          = FD_SCRATCH_ALLOC_APPEND( l, bfs_align(),             bfs_footprint            ( blk_max       ) );
  void * out_queue    = FD_SCRATCH_ALLOC_APPEND( l, out_queue_align(),       out_queue_footprint      ( fec_max       ) );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, fd_chainer_align() ) == (ulong)shmem + footprint );

  chainer->root             = ULONG_MAX;
  chainer->highest_repaired = 0UL;
  chainer->wksp_gaddr       = fd_wksp_gaddr_fast( wksp, chainer );
  chainer->fec_pool         = fd_fec_pool_join  ( fd_fec_pool_new    ( fec_pool,     fec_max             ) );
  chainer->fec_map          = fd_fec_map_join   ( fd_fec_map_new     ( fec_map,      fec_chain_cnt, seed ) );
  chainer->slotv_pool       = fd_slotv_pool_join( fd_slotv_pool_new  ( slotv_pool,   blk_max             ) );
  chainer->fec_tbl          = fec_tbl;
  chainer->fec_blk_max      = fec_blk_max;
  chainer->slotv_map        = fd_slotv_map_join  ( fd_slotv_map_new   ( slotv_map,    blk_chain_cnt, seed ) );
  chainer->eager_treap      = fd_rotor_treap_join( fd_rotor_treap_new ( eager_treap,  fec_max             ) );
  chainer->notar_treap      = fd_rotor_treap_join( fd_rotor_treap_new ( notar_treap,  fec_max             ) );
  chainer->bfs              = bfs_join           ( bfs_new            ( bfs,          blk_max             ) );
  chainer->out_queue        = out_queue_join     ( out_queue_new      ( out_queue,    fec_max             ) );

  fd_rotor_treap_seed( chainer->fec_pool, fec_max, seed );

  FD_COMPILER_MFENCE();
  FD_VOLATILE( chainer->magic ) = FD_CHAINER_MAGIC;
  FD_COMPILER_MFENCE();

  return shmem;
}

fd_chainer_t *
fd_chainer_join( void * shchainer ) {
  fd_chainer_t * chainer = (fd_chainer_t *)shchainer;
  if( FD_UNLIKELY( chainer->magic!=FD_CHAINER_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }
  return chainer;
}

/* slotv_iter_{init,next} iterate the versions of a slot via the
   MAP_MULTI chain.  Usage:
     for( ulong i=fd_chainer_slotv_iter_init(chainer,slot); i!=ULONG_MAX; i=fd_chainer_slotv_iter_next(chainer,i) ) {
       fd_chainer_slotv_t * slotv = fd_chainer_slotv_iter_ele( chainer, i );
       ...
     } */

/* acquire_slotv allocates, initializes, and map-inserts a fresh
   (turbine, i.e. all-zero block_id) version of slot.  Callers that know
   the version's block_id (notar-fallback, parent discovery) set it after. */

static fd_chainer_slotv_t *
acquire_slotv( fd_chainer_t * chainer, ulong slot ) {
  fd_slotv_map_t     * slotv_map  = chainer->slotv_map;
  fd_chainer_slotv_t * slotv_pool = chainer->slotv_pool;
  FD_TEST( fd_slotv_pool_free( slotv_pool ) );

  ulong slotv_cnt = 0UL;
  for( ulong i=fd_chainer_slotv_iter_init( chainer, slot ); i!=ULONG_MAX; i=fd_chainer_slotv_iter_next( chainer, i ) ) {
    slotv_cnt++;
  }
  if( FD_UNLIKELY( slotv_cnt>=FD_CHAINER_SLOT_VER_MAX ) ) FD_LOG_CRIT(( "slots stored exceeds protocol limits, %lu versions of slot %lu already stored", slotv_cnt, slot ));

  fd_chainer_slotv_t * slotv = fd_slotv_pool_ele_acquire( slotv_pool );
  slotv->slot              = slot;
  slotv->turbine           = 0;
  slotv->final             = 0;
  slotv->parent_slot       = AG_UNKNOWN_SLOT;
  slotv->parent_slot_batch = UINT_MAX;
  slotv->complete_idx      = UINT_MAX;
  slotv->buffered_idx      = UINT_MAX;
  slotv->buffered_fec_idx  = UINT_MAX;
  slotv->delivered_idx     = UINT_MAX;
  slotv->connected         = 0;

  memset( &slotv->metrics, 0, sizeof(slotv->metrics) );
  slotv->metrics.last_completed_fec_idx = UINT_MAX;

  fd_memset( &slotv->block_id,        0, sizeof(fd_hash_t) );
  fd_memset( &slotv->parent_block_id, 0, sizeof(fd_hash_t) );
  fd_memset( fd_chainer_slotv_fecs( chainer, slotv ), 0xff, chainer->fec_blk_max*sizeof(uint) ); /* UINT_MAX pool_idx sentinel */

  fd_slotv_map_ele_insert( slotv_map, slotv, slotv_pool );
  return slotv;
}

/* orphans_resolve calls orphan_remove on every orphan whose ancestry is now settled (parent is in map and all) */

void
fd_chainer_init( fd_chainer_t *    chainer,
                 ulong             slot,
                 fd_hash_t const * block_id ) {
  fd_chainer_slotv_t * slotv = acquire_slotv( chainer, slot );
  slotv->parent_slot       = slot;
  slotv->complete_idx      = 0;
  slotv->buffered_idx      = 0;
  slotv->connected         = 1;
  slotv->delivered_idx     = 0; /* must equal complete_idx at init */
  slotv->buffered_fec_idx  = UINT_MAX; /* no complete FEC set buffered; must
                                          be one-below a FD_FEC_SHRED_CNT
                                          multiple, which UINT_MAX satisfies */
  slotv->block_id          = *block_id;

  chainer->root             = slot;
  chainer->highest_repaired = slot;
}

/* slotv_fec returns the FEC that slotv owns at fec_set_idx, or NULL if
   it holds none there (or fec_set_idx is beyond max_shreds_per_block). */

static fd_chainer_fec_t *
slotv_fec( fd_chainer_t * chainer, fd_chainer_slotv_t const * slotv, uint fec_set_idx ) {
  ulong k = fec_set_idx / FD_FEC_SHRED_CNT;
  if( FD_UNLIKELY( k>=chainer->fec_blk_max ) ) return NULL;
  uint idx = fd_chainer_slotv_fecs( chainer, slotv )[ k ];
  if( FD_UNLIKELY( idx==UINT_MAX ) ) return NULL;
  return fd_fec_pool_ele( chainer->fec_pool, (ulong)idx );
}

fd_chainer_fec_t *
fd_chainer_fec_query( fd_chainer_t *    chainer,
                      ulong             slot,
                      uint              fec_set_idx,
                      fd_hash_t const * block_id ) {
  fd_chainer_slotv_t * slotv = fd_chainer_slot_version_query( chainer, slot, block_id );
  if( FD_UNLIKELY( !slotv ) ) return NULL;
  return slotv_fec( chainer, slotv, fec_set_idx );
}

/* fec_query returns the FEC whose merkle_root matches mr, or NULL. */

static fd_chainer_fec_t *
fec_query( fd_chainer_t * chainer, fd_hash_t const * mr ) {
  fd_fec_map_t     * fec_map  = chainer->fec_map;
  fd_chainer_fec_t * fec_pool = chainer->fec_pool;
  return fd_fec_map_ele_query( fec_map, mr, NULL, fec_pool );
}

/* fec_treap returns the worklist a version's incomplete sets belong
   to.  The turbine flag, not the block id, selects it: the turbine
   version keeps its own worklist after it derives its block id. */

static inline fd_rotor_treap_t *
fec_treap( fd_chainer_t * chainer, fd_chainer_slotv_t const * slotv ) {
  return slotv->turbine ? chainer->eager_treap : chainer->notar_treap;
}

/* fec_treap_remove takes fec off slotv's worklist, if it is on one. */

static inline void
fec_treap_remove( fd_chainer_t * chainer, fd_chainer_slotv_t const * slotv, fd_chainer_fec_t * fec ) {
  if( FD_LIKELY( !fec->treap ) ) return;
  fd_rotor_treap_ele_remove( fec_treap( chainer, slotv ), fec, chainer->fec_pool );
  fec->treap = 0;
}

/* mr_eq compares two roots over the 20-byte prefix fd_fec_map keys on. */

static inline int
mr_eq( fd_hash_t const * a, fd_hash_t const * b ) {
  return !memcmp( a->uc, b->uc, FD_SHRED_MERKLE_NODE_SZ );
}

static fd_chainer_fec_t *
fec_insert( fd_chainer_t * chainer, fd_chainer_slotv_t * slotv, uint fec_set_idx ) {
  FD_TEST( fd_fec_pool_free( chainer->fec_pool ) );

  fd_chainer_fec_t * fec = fd_fec_pool_ele_acquire( chainer->fec_pool );

  /* prio is seeded once per pool slot by fd_rotor_treap_seed and must
     survive the reset: it is what keeps the worklists balanced.  Zeroed
     priorities degrade the treap to a sorted list, and catch-up enrolls
     long ascending runs of (slot, fec_set_idx), so the insert cost
     becomes linear in the number of enrolled sets. */

  uint prio = fec->prio;
  memset( fec, 0, sizeof(fd_chainer_fec_t) );
  fec->prio        = prio;
  fec->slot        = (uint)slotv->slot;
  fec->fec_set_idx = fec_set_idx & ((1U<<26)-1U);
  fec->next_req_ts = 0;

  uint k = fec_set_idx / FD_FEC_SHRED_CNT;
  fd_chainer_slotv_fecs( chainer, slotv )[ k ] = (uint)fd_fec_pool_idx( chainer->fec_pool, fec );

  /* The entry joins its version's worklist straight away: its root is
     still zero, so it stands for "this set exists and I do not even
     know its root yet".  It is keyed into fd_fec_map only once a shred
     or a getFecSetRoot response fills the root in. */
  fd_rotor_treap_ele_insert( fec_treap( chainer, slotv ), fec, chainer->fec_pool );
  fec->treap = 1;
  return fec;
}

fd_chainer_slotv_t *
fd_chainer_fec_owner( fd_chainer_t *           chainer,
                      fd_chainer_fec_t const * fec ) {
  uint idx = (uint)fd_fec_pool_idx( chainer->fec_pool, fec );
  uint k   = fec->fec_set_idx / (uint)FD_FEC_SHRED_CNT;
  for( ulong i=fd_chainer_slotv_iter_init( chainer, (ulong)fec->slot ); i!=ULONG_MAX; i=fd_chainer_slotv_iter_next( chainer, i ) ) {
    fd_chainer_slotv_t * slotv = fd_chainer_slotv_iter_ele( chainer, i );
    if( FD_LIKELY( fd_chainer_slotv_fecs( chainer, slotv )[ k ]==idx ) ) return slotv;
  }
  return NULL;
}

void
fd_chainer_fec_rearm( fd_chainer_fec_t * fec,
                      long               next_req_ts ) {
  if( FD_UNLIKELY( !fec->treap ) ) return; /* already complete, no longer enrolled */
  fec->next_req_ts = next_req_ts;
}

uint
fd_chainer_fec_data_idxs( fd_chainer_t *           chainer,
                          fd_chainer_fec_t const * fec ) {
  if( FD_LIKELY( fec->root ) ) return fec->data_idxs;
  if( FD_UNLIKELY( fd_hash_check_zero( &fec->merkle_root ) ) ) return 0U;
  fd_chainer_fec_t const * root = fec_query( chainer, &fec->merkle_root );
  return root ? root->data_idxs : 0U;
}

int
fd_chainer_shred_test( fd_chainer_t *             chainer,
                       fd_chainer_slotv_t const * slotv,
                       uint                       shred_idx ) {
  fd_chainer_fec_t * fec = slotv_fec( chainer, slotv, shred_idx & ~( (uint)FD_FEC_SHRED_CNT - 1U ) );
  if( FD_UNLIKELY( !fec ) ) return 0;
  return !!( fd_chainer_fec_data_idxs( chainer, fec ) & ( 1U << ( shred_idx & ( (uint)FD_FEC_SHRED_CNT - 1U ) ) ) );
}

/* slotv_abandon removes a turbine slotv's current repair work. */

static void
slotv_abandon( fd_chainer_t * chainer, fd_chainer_slotv_t * slotv ) {
  FD_TEST( slotv->turbine );

  for( uint i=0U; i<chainer->fec_blk_max; i++ ) {
    uint idx = fd_chainer_slotv_fecs( chainer, slotv )[ i ];
    if( FD_UNLIKELY( idx!=UINT_MAX ) ) {
      fd_chainer_fec_t * fec = fd_fec_pool_ele( chainer->fec_pool, (ulong)idx );
      fec_treap_remove( chainer, slotv, fec ); /* completed sets already left the worklist */
    }
  }
}

static int
slot_has_notar( fd_chainer_t * chainer, ulong slot ) {
  for( ulong i=fd_chainer_slotv_iter_init( chainer, slot ); i!=ULONG_MAX; i=fd_chainer_slotv_iter_next( chainer, i ) ) {
    fd_chainer_slotv_t * slotv = fd_chainer_slotv_iter_ele( chainer, i );
    if( FD_UNLIKELY( !slotv->turbine ) ) return 1;
  }
  return 0;
}

/* finalize_block_id computes the slotv's double-merkle block_id and
   writes it to slotv->block_id.  Returns 1 on success, 0 on failure. */

static int
finalize_block_id( fd_chainer_t * chainer, fd_chainer_slotv_t * slotv ) {
  if( FD_UNLIKELY( slotv->complete_idx==UINT_MAX ) )                 return 0;
  if( FD_UNLIKELY( slotv->parent_slot==AG_UNKNOWN_SLOT ) )           return 0;
  if( FD_UNLIKELY( fd_hash_check_zero( &slotv->parent_block_id ) ) ) return 0;

  uint fec_set_cnt = ( slotv->complete_idx + 1U ) / FD_FEC_SHRED_CNT;
  uchar tree_mem[ FD_BMTREE_COMMIT_FOOTPRINT( 0UL ) ] __attribute__((aligned(FD_BMTREE_COMMIT_ALIGN)));
  fd_bmtree_commit_t * tree = fd_bmtree_commit_init( tree_mem, 20UL, FD_BMTREE_LONG_PREFIX_SZ, 0UL );

  for( uint i=0U; i<fec_set_cnt; i++ ) {
    fd_chainer_fec_t * fec = slotv_fec( chainer, slotv, i*FD_FEC_SHRED_CNT );
    if( FD_UNLIKELY( !fec ) ) return 0;

    fd_bmtree_node_t leaf[1];
    memcpy( leaf->hash, fec->merkle_root.uc, sizeof(fd_hash_t) );
    fd_bmtree_commit_append( tree, leaf, 1UL );
  }

  /* final parent-info leaf */
  fd_bmtree_node_t parent_info[1];
  fd_sha256_t sha[1];
  fd_sha256_init  ( sha );
  fd_sha256_append( sha, &slotv->parent_slot,       sizeof(ulong)     );
  fd_sha256_append( sha, slotv->parent_block_id.uc, sizeof(fd_hash_t) );
  fd_sha256_append( sha, &fec_set_cnt,              sizeof(uint)      );
  fd_sha256_fini  ( sha, parent_info->hash );
  fd_bmtree_commit_append( tree, parent_info, 1UL );

  uchar * root = fd_bmtree_commit_fini( tree );
  memcpy( slotv->block_id.uc, root, sizeof(fd_hash_t) );
  return 1;
}

void
fd_chainer_shred_insert( fd_chainer_t *        chainer,
                         ulong                 slot,
                         uint                  shred_idx,
                         int                   slot_complete,
                         int                   src,
                         long                  rx_ts,
                         fd_hash_t const *     mr,
                         ulong                 parent_slot,
                         fd_hash_t const *     parent_block_id ) {
  FD_TEST( slot>chainer->root );
  uint  fec_set_idx = shred_idx & ~( (uint)FD_FEC_SHRED_CNT - 1U );
  ulong k           = fec_set_idx / FD_FEC_SHRED_CNT;
  uint  shred_max   = (uint)( chainer->fec_blk_max*FD_FEC_SHRED_CNT );
  FD_TEST( k<chainer->fec_blk_max ); /* guaranteed by fec_resolver */

 fd_chainer_fec_t * fec = fec_query( chainer, mr );
  if( FD_LIKELY( fec ) ) {
    if( FD_UNLIKELY( (ulong)fec->slot!=slot || fec->fec_set_idx!=fec_set_idx ) ) return;
  } else {
    fd_chainer_slotv_t * turbine;
    if( FD_UNLIKELY( !fd_chainer_slot_query( chainer, slot ) ) ) {
      turbine = acquire_slotv( chainer, slot );
      turbine->turbine = 1;
    } else {
      turbine = fd_chainer_turbine_slotv_query( chainer, slot );
      if( FD_UNLIKELY( !turbine || !fd_hash_check_zero( &turbine->block_id ) || slot_has_notar( chainer, slot ) ) ) return;
    }

    fec = slotv_fec( chainer, turbine, fec_set_idx );
    if( FD_UNLIKELY( fec && !fd_hash_check_zero( &fec->merkle_root ) ) ) return; /* conflicting root */

    /* A shred this far in proves the earlier sets exist. */
    for( uint i=0U; i<=k; i++ ) {
      if( FD_UNLIKELY( fd_chainer_slotv_fecs( chainer, turbine )[ i ]==UINT_MAX ) ) fec_insert( chainer, turbine, i*(uint)FD_FEC_SHRED_CNT );
    }
    fec = slotv_fec( chainer, turbine, fec_set_idx );
    fec->merkle_root = *mr;
    fec->root = 1;
    fd_fec_map_ele_insert( chainer->fec_map, fec, chainer->fec_pool );
  }

  int new_shred = !( fec->data_idxs & ( 1U << ( shred_idx - fec_set_idx ) ) );
  fec->data_idxs |= 1U << ( shred_idx - fec_set_idx );
  if( FD_UNLIKELY( slot_complete ) ) fec->slot_complete = 1;

  /* Update every version holding this root at this position.  Entries
     are matched by root. */

  for( ulong _i =fd_chainer_slotv_iter_init( chainer, slot );
             _i!=ULONG_MAX;
             _i =fd_chainer_slotv_iter_next( chainer, _i ) ) {
    fd_chainer_slotv_t * slotv   = fd_chainer_slotv_iter_ele( chainer, _i );
    fd_chainer_fec_t *   fec_cpy = slotv_fec( chainer, slotv, fec_set_idx );
    if( FD_UNLIKELY( !fec_cpy || !mr_eq( &fec_cpy->merkle_root, mr ) ) ) continue;

    if( FD_UNLIKELY( slot_complete ) ) fec_cpy->slot_complete = 1;

    /* A getFecSetRoot response only carries the 20-byte prefix, so a
       version can be holding a zero-padded root.  The wire root is the
       full one; adopt it.  The map key is the prefix, so this does not
       disturb the entry's place in fd_fec_map. */
    fec_cpy->merkle_root = *mr;

    /* update reception statistics */
    if( FD_LIKELY( new_shred ) ) {
      slotv->metrics.turbine_cnt   += ( src==FD_CHAINER_SRC_TURBINE   );
      slotv->metrics.repair_cnt    += ( src==FD_CHAINER_SRC_REPAIR    );
      slotv->metrics.recovered_cnt += ( src==FD_CHAINER_SRC_RECOVERED );
    }

    /* A version created late adopts FECs whose shreds predate it. */
    if( FD_UNLIKELY( rx_ts && ( !slotv->metrics.first_shred_ts || rx_ts<slotv->metrics.first_shred_ts ) ) ) slotv->metrics.first_shred_ts = rx_ts;

    /* update slot-level shred indexing */
    if( FD_UNLIKELY( slot_complete ) ) slotv->complete_idx = shred_idx;
    while( slotv->buffered_idx + 1 < shred_max && fd_chainer_shred_test( chainer, slotv, slotv->buffered_idx + 1U ) ) {
      slotv->buffered_idx++;
    }

    /* If equivocating, buffered_idx needs to be clamped to complete_idx */
    if( FD_UNLIKELY( slotv->buffered_idx != UINT_MAX && slotv->complete_idx != UINT_MAX && slotv->buffered_idx > slotv->complete_idx ) ) slotv->buffered_idx = slotv->complete_idx;

    /* Stamped once, when the version first becomes contiguous */
    if( FD_UNLIKELY( rx_ts && !slotv->metrics.last_shred_ts && slotv->complete_idx!=UINT_MAX && slotv->buffered_idx==slotv->complete_idx ) ) {
      slotv->metrics.last_shred_ts = rx_ts;
      FD_LOG_NOTICE(( "slot %lu complete in %ld ms. complete_idx %u, turbine %u repair %u recovered %u code %u", slot, ( rx_ts - slotv->metrics.first_shred_ts )/1000000L, slotv->complete_idx, slotv->metrics.turbine_cnt, slotv->metrics.repair_cnt, slotv->metrics.recovered_cnt, slotv->metrics.parity_cnt ));
    }

    /* parent_slot_batch tracks which batch the information came from
       so a later UpdateParent supersedes the header (it may only move
       forward).  UINT_MAX means "nothing known yet", so it is not a
       batch index to compare against. */
    if( FD_UNLIKELY( parent_slot!=AG_UNKNOWN_SLOT && ( slotv->parent_slot_batch==UINT_MAX || shred_idx>slotv->parent_slot_batch ) ) ) {
      FD_TEST( parent_block_id ); /* TODO handholding check */

      slotv->parent_slot       = parent_slot;
      slotv->parent_slot_batch = shred_idx;
      slotv->parent_block_id   = *parent_block_id;

      fd_chainer_slotv_t * parent = fd_chainer_slot_version_query( chainer, parent_slot, parent_block_id );
      if( FD_LIKELY( parent && parent->connected ) ) slotv->connected = 1;
      if( FD_UNLIKELY( !parent && parent_slot>chainer->root && !fd_hash_check_zero( parent_block_id ) ) ) {
        /* currently needed for any level of efficient repair - create ctx for the parent */
        fd_chainer_verified_block_insert( chainer, parent_slot, *parent_block_id );
      }
    }
  }
}

void
fd_chainer_code_shred_insert( fd_chainer_t *    chainer,
                              ulong             slot,
                              uint              fec_set_idx,
                              long              rx_ts,
                              fd_hash_t const * mr ) {
  ulong k = fec_set_idx / FD_FEC_SHRED_CNT;
  if( FD_UNLIKELY( k>=chainer->fec_blk_max ) ) return;

  /* Purely metrics, so best effort tracing.  Coding shreds do not create
     fec entries. */

  fd_chainer_fec_t * fec = fec_query( chainer, mr );
  if( FD_UNLIKELY( !fec ) ) return;

  for( ulong i =fd_chainer_slotv_iter_init( chainer, slot );
             i!=ULONG_MAX;
             i =fd_chainer_slotv_iter_next( chainer, i ) ) {
    fd_chainer_slotv_t * slotv = fd_chainer_slotv_iter_ele( chainer, i );
    fd_chainer_fec_t * shared = slotv_fec( chainer, slotv, fec_set_idx );
    if( FD_UNLIKELY( !shared || !mr_eq( &shared->merkle_root, mr ) ) ) continue;
    slotv->metrics.parity_cnt++;
    slotv->metrics.turbine_cnt++;
    if( FD_UNLIKELY( rx_ts && ( !slotv->metrics.first_shred_ts || rx_ts<slotv->metrics.first_shred_ts ) ) ) slotv->metrics.first_shred_ts = rx_ts;
  }
}

/* chainer_deliver queues a delivered FEC for publish to replay.  The
   rotor tile drains the out_queue in after_credit. */

static void
chainer_deliver( fd_chainer_t *       chainer,
                 fd_chainer_slotv_t * slotv,
                 fd_chainer_fec_t *   fec ) {
  out_ele_t * out_queue = chainer->out_queue;
  if( FD_UNLIKELY( out_queue_full( out_queue ) ) ) FD_LOG_CRIT(( "chainer out_queue full" ));
  out_queue_push_tail( out_queue, (out_ele_t){ .slotv_idx = (uint)fd_slotv_pool_idx( chainer->slotv_pool, slotv ),
                                               .fec_idx   = (uint)fd_fec_pool_idx  ( chainer->fec_pool,   fec   ) } );
}

/* chainer_advance delivers as many contiguous completed FEC sets as
   possible from `root` slotv, then cascades: when an slotv's
   slot_complete FEC is delivered, every child slotv (parent_block_id ==
   this slotv's block_id) becomes connected and is drained in turn. */

static void
chainer_advance( fd_chainer_t * chainer, fd_chainer_slotv_t * root ) {
  fd_slotv_map_t     * slotv_map  = chainer->slotv_map;
  fd_chainer_slotv_t * slotv_pool = chainer->slotv_pool;
  ulong              * bfs        = chainer->bfs;

  bfs_push_tail( bfs, fd_slotv_pool_idx( slotv_pool, root ) );

  while( FD_LIKELY( !bfs_empty( bfs ) ) ) {
    fd_chainer_slotv_t * slotv = fd_slotv_pool_ele( slotv_pool, bfs_pop_head( bfs ) );
    if( FD_UNLIKELY( !slotv->connected ) ) continue;
    if( FD_UNLIKELY( slotv->turbine && fd_hash_check_zero( &slotv->block_id ) && slot_has_notar( chainer, slotv->slot ) ) ) continue;

    fd_chainer_slotv_t * parent = fd_chainer_slot_version_query( chainer, slotv->parent_slot, &slotv->parent_block_id );
    if( FD_UNLIKELY( !parent || parent->complete_idx==UINT_MAX || parent->delivered_idx!=parent->complete_idx ) ) continue;

    for(;;) {
      uint next = slotv->delivered_idx==UINT_MAX ? 0U
                                                 : slotv->delivered_idx + 1;
      fd_chainer_fec_t * fec = slotv_fec( chainer, slotv, next );
      if( FD_LIKELY( !fec || !fec->complete ) ) break; /* next FEC not completed yet */

      chainer_deliver( chainer, slotv, fec );
      slotv->delivered_idx = next + (FD_FEC_SHRED_CNT - 1);

      if( FD_UNLIKELY( fec->slot_complete ) ) {
        fd_chainer_fec_t * f0 = slotv_fec( chainer, slotv, 0U );
        fec_treap_remove( chainer, slotv, f0 ); /* remove sentinel from worklist */

        chainer->highest_repaired = fd_ulong_max( chainer->highest_repaired, slotv->slot );
        FD_TEST( !fd_hash_check_zero( &slotv->block_id ) );

        /* Scan for children. TODO could index children by
           parent_block_id; O(n) scan for now. */
        for( fd_slotv_map_iter_t it = fd_slotv_map_iter_init( slotv_map, slotv_pool );
                                     !fd_slotv_map_iter_done( it, slotv_map, slotv_pool );
                                 it = fd_slotv_map_iter_next( it, slotv_map, slotv_pool ) ) {
          fd_chainer_slotv_t * child = fd_slotv_map_iter_ele( it, slotv_map, slotv_pool );
          if( FD_UNLIKELY( fd_hash_eq( &child->parent_block_id, &slotv->block_id ) ) ) {
            child->connected = 1;
            bfs_push_tail( bfs, fd_slotv_pool_idx( slotv_pool, child ) );
          }
        }
        break;
      }
    }
  }
}

int
fd_chainer_fec_complete( fd_chainer_t * chainer,
                         ulong          slot,
                         uint           fec_set_idx_,
                         int            slot_complete,
                         int            data_complete,
                         int            is_leader,
                         long           rx_ts,
                         fd_hash_t *    mr ) {
  FD_TEST( slot>chainer->root );
  uint  fec_set_idx = (uint)fec_set_idx_;
  ulong k           = fec_set_idx / FD_FEC_SHRED_CNT;
  FD_TEST( k<chainer->fec_blk_max ); /* guaranteed by fec_resolver */

  fd_chainer_fec_t * root = fec_query( chainer, mr );
  if( FD_UNLIKELY( !root || (ulong)root->slot!=slot || root->fec_set_idx!=fec_set_idx ) ) return 1;

  uint recovered_cnt = (uint)fd_uint_popcnt( ~root->data_idxs );
  root->data_idxs = UINT_MAX;

  /* Entries are private per version, so completing this set means
     completing every version's own entry that carries the root. */

  for( ulong _i=fd_chainer_slotv_iter_init( chainer, slot ); _i!=ULONG_MAX; _i=fd_chainer_slotv_iter_next( chainer, _i ) ) {
    fd_chainer_slotv_t * slotv = fd_chainer_slotv_iter_ele( chainer, _i );
    fd_chainer_fec_t * fec = slotv_fec( chainer, slotv, fec_set_idx );
    if( FD_UNLIKELY( !fec || !mr_eq( &fec->merkle_root, mr ) ) ) continue;

    fec->merkle_root = *mr; /* upgrade a 20-byte prefix to the full root */
    fec->complete = 1; /* set is now reconstructable -> deliverable */
    if( FD_UNLIKELY( slot_complete ) ) fec->slot_complete = 1;
    if( FD_UNLIKELY( data_complete ) ) fec->data_complete = 1;
    if( FD_UNLIKELY( is_leader ) )     fec->is_leader     = 1;
    if( FD_LIKELY  ( fec_set_idx != 0U ) ) fec_treap_remove( chainer, slotv, fec ); /* nothing left to repair here */

    slotv->metrics.recovered_cnt += recovered_cnt;
    if( FD_UNLIKELY( rx_ts && ( !slotv->metrics.first_shred_ts || rx_ts<slotv->metrics.first_shred_ts ) ) ) slotv->metrics.first_shred_ts = rx_ts;

    if( FD_UNLIKELY( slot_complete ) ) slotv->complete_idx = fec_set_idx + (uint)FD_FEC_SHRED_CNT - 1U;
    uint shred_max = (uint)( chainer->fec_blk_max*FD_FEC_SHRED_CNT );
    while( slotv->buffered_idx+1U<shred_max && fd_chainer_shred_test( chainer, slotv, slotv->buffered_idx+1U ) ) slotv->buffered_idx++;
    if( FD_UNLIKELY( slotv->complete_idx!=UINT_MAX && slotv->buffered_idx!=UINT_MAX && slotv->buffered_idx>slotv->complete_idx ) ) slotv->buffered_idx = slotv->complete_idx;

    /* Stamped once, when the version first becomes contiguous */
    if( FD_UNLIKELY( rx_ts && !slotv->metrics.last_shred_ts && slotv->complete_idx!=UINT_MAX && slotv->buffered_idx==slotv->complete_idx ) ) {
      slotv->metrics.last_shred_ts = rx_ts;
      FD_LOG_INFO(( "slot %lu complete in %ld ms. complete_idx %u, turbine %u repair %u recovered %u code %u", slot, ( rx_ts - slotv->metrics.first_shred_ts )/1000000L, slotv->complete_idx, slotv->metrics.turbine_cnt, slotv->metrics.repair_cnt, slotv->metrics.recovered_cnt, slotv->metrics.parity_cnt ));
    }

    /* An abandoned version keeps its FEC state accurate -- the shreds
       are the same shreds -- but never advances or delivers. */
    if( FD_UNLIKELY( slotv->turbine && fd_hash_check_zero( &slotv->block_id ) && slot_has_notar( chainer, slotv->slot ) ) ) continue;

    slotv->metrics.last_completed_fec_idx = fec_set_idx;

    for(;;) {
      fd_chainer_fec_t * next = slotv_fec( chainer, slotv, slotv->buffered_fec_idx + 1U );
      if( !next || !next->complete ) break;
      slotv->buffered_fec_idx += FD_FEC_SHRED_CNT;
    }

    /* clamp buffered_fec_idx to complete_idx always. should never happen for non-turbine versions */
    if( FD_UNLIKELY( slotv->complete_idx!=UINT_MAX && slotv->buffered_fec_idx!=UINT_MAX &&
                     slotv->buffered_fec_idx>slotv->complete_idx ) ) slotv->buffered_fec_idx = slotv->complete_idx;

    if( FD_LIKELY( slotv->turbine ) ) {
      /* slot is complete implies we can record the block_id.  Only the
         turbine version needs its block_id computed. */
      fd_chainer_slotv_t * turbine = slotv;
      if( FD_UNLIKELY( turbine->complete_idx!=UINT_MAX &&
                       turbine->buffered_fec_idx==turbine->complete_idx &&
                       fd_hash_check_zero( &turbine->block_id ) ) ) {
        if( FD_UNLIKELY( !finalize_block_id( chainer, turbine ) ) ) FD_LOG_WARNING(( "failed to finalize block_id for slot %lu, parent_slot %lu parent_bid is zero %d", slot, turbine->parent_slot, fd_hash_check_zero( &turbine->parent_block_id ) ));
      }
    }

    chainer_advance( chainer, slotv );
  }
  return 0;
}

void
fd_chainer_fec_evicted( fd_chainer_t * chainer,
                        ulong          slot,
                        uint           fec_set_idx,
                        fd_hash_t    * merkle_root ) {
  fd_chainer_fec_t * fec = fec_query( chainer, merkle_root );
  if( FD_UNLIKELY( !fec ) ) return;
  ulong k = fec_set_idx / FD_FEC_SHRED_CNT;
  FD_TEST( k<chainer->fec_blk_max ); /* guaranteed by fec_resolver */

  /* We choose not to remove the FEC from the chainer.  If this FEC
     belongs to a turbine slot and we are having trouble completing it
     (the leader gave up on disseminating the shreds), then eventually
     this slot will get skipped or we will repair a different version
     through a votor repair block id event. If this FEC is part of a
     votor cert, then we should keep it in the chainer because the
     merkle root is verified and we definitely want to continue
     repairing it; it is getting evicted only because fec_resolver is
     under pressure. */
  fec->data_idxs = 0U;
  for( ulong _i=fd_chainer_slotv_iter_init( chainer, slot ); _i!=ULONG_MAX; _i=fd_chainer_slotv_iter_next( chainer, _i ) ) {
    fd_chainer_slotv_t * slotv = fd_chainer_slotv_iter_ele( chainer, _i );
    fd_chainer_fec_t * shared = slotv_fec( chainer, slotv, fec_set_idx );
    if( FD_UNLIKELY( !shared || !mr_eq( &shared->merkle_root, merkle_root ) ) ) continue;

    /* rederive buffered_idx */
    if( FD_UNLIKELY( slotv->buffered_idx!=UINT_MAX && slotv->buffered_idx>=fec_set_idx ) ) {
      slotv->buffered_idx = fec_set_idx - 1U;
    }
  }
}

void
fd_chainer_verified_parent_fec_count( fd_chainer_t * chainer,
                                      ulong          slot,
                                      fd_hash_t    * block_id,
                                      uint           fec_set_cnt,
                                      ulong          parent_slot,
                                      fd_hash_t    * parent_block_id ) {
  fd_chainer_slotv_t * slotv = fd_chainer_slot_version_query( chainer, slot, block_id );
  if( FD_UNLIKELY( !slotv ) ) return; /* version finalized away while response was in flight */

  FD_TEST( fec_set_cnt>0U && fec_set_cnt<=chainer->fec_blk_max );
  slotv->complete_idx    = ( fec_set_cnt*FD_FEC_SHRED_CNT ) - 1;
  slotv->parent_slot     = parent_slot;
  slotv->parent_block_id = *parent_block_id;

  fd_chainer_slotv_t * parent_slotv = fd_chainer_slot_version_query( chainer, parent_slot, parent_block_id );
  if( FD_UNLIKELY( !parent_slotv ) ) {
    if( FD_UNLIKELY( parent_slot<=chainer->root ) ) return; /* dead fork */

    parent_slotv = fd_chainer_verified_block_insert( chainer, parent_slot, *parent_block_id );
    if( FD_UNLIKELY( !parent_slotv ) ) return; /* a different parent version is final */
  }

  for( uint i=0; i<fec_set_cnt; i++ ) {
    if( FD_UNLIKELY( fd_chainer_slotv_fecs( chainer, slotv )[ i ]==UINT_MAX ) ) {
      fec_insert( chainer, slotv, i*32U ); /* cert-named: due now */
    }
  }
  /* parent now identified, connect this slotv if the parent is. */
  if( FD_UNLIKELY( parent_slotv->connected ) ) slotv->connected = 1;
}

void
fd_chainer_verified_hash_insert( fd_chainer_t * chainer,
                                 ulong          slot,
                                 fd_hash_t *    block_id,
                                 uint           fec_set_idx,
                                 uchar const    mr_prefix[ static FD_SHRED_MERKLE_NODE_SZ ] ) {
  fd_chainer_slotv_t * slotv = fd_chainer_slot_version_query( chainer, slot, block_id );
  if( FD_UNLIKELY( !slotv ) ) return; /* version finalized away while response was in flight */

  fd_hash_t mr = {0};
  memcpy( mr.uc, mr_prefix, FD_SHRED_MERKLE_NODE_SZ );

  /* This version owns its own entry at fec_set_idx.  It usually exists
     already, as a rootless placeholder created when the set count was
     learned; otherwise create it now. */
  fd_chainer_fec_t * fec = slotv_fec( chainer, slotv, fec_set_idx );
  if( FD_UNLIKELY( !fec ) ) fec = fec_insert( chainer, slotv, fec_set_idx );

  /* One version owns the root-map entry and received bitmap; siblings
     query it by root. */
  if( FD_LIKELY( fd_hash_check_zero( &fec->merkle_root ) ) ) {
    fec->merkle_root = mr;
    if( FD_LIKELY( !fd_fec_map_ele_query( chainer->fec_map, &mr, NULL, chainer->fec_pool ) ) ) {
      fd_fec_map_ele_insert( chainer->fec_map, fec, chainer->fec_pool );
      fec->root = 1;
    }
  } else if( FD_UNLIKELY( !mr_eq( &fec->merkle_root, &mr ) ) ) {
    return; /* the response contradicts the root this version already holds */
  }

  if( FD_UNLIKELY( fec_set_idx==slotv->complete_idx - ( FD_FEC_SHRED_CNT-1 ) ) ) fec->slot_complete = 1;


  /* Adopt shreds received before this version learned the root, even
     if the shared set is still incomplete. */
  fd_chainer_fec_t const * peer = fec_query( chainer, &mr );
  if( FD_UNLIKELY( peer!=fec ) ) {
    fec->merkle_root = peer->merkle_root;
    // uint shred_max = (uint)( chainer->fec_blk_max*FD_FEC_SHRED_CNT );
    // while( slotv->buffered_idx+1U<shred_max && fd_chainer_shred_test( chainer, slotv, slotv->buffered_idx+1U ) ) slotv->buffered_idx++;
    // if( FD_UNLIKELY( slotv->complete_idx!=UINT_MAX && slotv->buffered_idx!=UINT_MAX && slotv->buffered_idx>slotv->complete_idx ) ) slotv->buffered_idx = slotv->complete_idx;
    if( FD_UNLIKELY( peer->complete ) ) {
      fd_hash_t peer_mr = peer->merkle_root;
      fd_chainer_fec_complete( chainer, slot, fec_set_idx, peer->slot_complete, peer->data_complete, peer->is_leader, 0L /* arrival time unknown */, &peer_mr );
    }
  }
  chainer_advance( chainer, slotv );
}

fd_chainer_slotv_t *
fd_chainer_verified_block_insert( fd_chainer_t * chainer,
                                  ulong          slot,
                                  fd_hash_t      block_id ) {
  FD_TEST( slot>chainer->root );

  if( FD_LIKELY( fd_chainer_slot_version_query( chainer, slot, &block_id ) ) ) return NULL;
  for( ulong i=fd_chainer_slotv_iter_init( chainer, slot ); i!=ULONG_MAX; i=fd_chainer_slotv_iter_next( chainer, i ) ) {
    if( FD_UNLIKELY( fd_chainer_slotv_iter_ele( chainer, i )->final ) ) return NULL;
  }

  fd_chainer_slotv_t * slotv = acquire_slotv( chainer, slot );
  slotv->block_id = block_id;

  fec_insert( chainer, slotv, 0 ); /* cert-named: due now */

  fd_chainer_slotv_t * turbine = fd_chainer_turbine_slotv_query( chainer, slot );
  if( FD_UNLIKELY( turbine && fd_hash_check_zero( &turbine->block_id ) ) ) {
    /* Turbine slotv is not yet complete, but votor repair events for
       this slot have already started arriving, suggesting we are way
       behind on repairing this slot.  At this point just abandon the
       turbine version and only deliver votor verified versions. */
    slotv_abandon( chainer, turbine );
  }
  return slotv;
}

void
fd_chainer_slot_inval( fd_chainer_t * chainer,
                       ulong          slot ) {
  if( FD_UNLIKELY( slot<=chainer->root ) ) return;
  fd_chainer_slotv_t * turbine = fd_chainer_turbine_slotv_query( chainer, slot );
  if( FD_UNLIKELY( !turbine || !fd_hash_check_zero( &turbine->block_id ) ) ) return;
  slotv_abandon( chainer, turbine );
}

void
fd_chainer_blk_final( fd_chainer_t *    chainer,
                      ulong             slot,
                      fd_hash_t const * block_id,
                      fd_store_t *      store ) {
  if( FD_UNLIKELY( slot<=chainer->root || fd_hash_check_zero( block_id ) ) ) return;
  fd_chainer_slotv_t * final = fd_chainer_slot_version_query( chainer, slot, block_id );
  for( ulong i=fd_chainer_slotv_iter_init( chainer, slot ); i!=ULONG_MAX; i=fd_chainer_slotv_iter_next( chainer, i ) ) {
    fd_chainer_slotv_t * v = fd_chainer_slotv_iter_ele( chainer, i );
    if( FD_UNLIKELY( v->final && !fd_hash_eq( &v->block_id, block_id ) ) ) return;
  }
  if( final ) final->final = 1;

  /* Filter queued deliveries before releasing any pool indices. */
  uint final_idx = final ? (uint)fd_slotv_pool_idx( chainer->slotv_pool, final ) : UINT_MAX;
  for( ulong n=out_queue_cnt( chainer->out_queue ); n; n-- ) {
    out_ele_t out = out_queue_pop_head( chainer->out_queue );
    if( FD_UNLIKELY( out.slotv_idx==UINT_MAX ) ) continue;
    fd_chainer_slotv_t * v = fd_slotv_pool_ele( chainer->slotv_pool, out.slotv_idx );
    if( FD_LIKELY( v->slot!=slot || out.slotv_idx==final_idx ) ) out_queue_push_tail( chainer->out_queue, out );
  }

  fd_store_map_t store_map[1];
  if( store ) FD_TEST( fd_store_map_ljoin( store, store_map ) );
  for( ulong i=fd_chainer_slotv_iter_init( chainer, slot ); i!=ULONG_MAX; ) {
    fd_chainer_slotv_t * v    = fd_chainer_slotv_iter_ele( chainer, i );
    ulong                next = fd_chainer_slotv_iter_next( chainer, i );
    if( FD_LIKELY( v!=final ) ) {
      for( uint k=0U; k<chainer->fec_blk_max; k++ ) {
        fd_chainer_fec_t * fec = slotv_fec( chainer, v, k*(uint)FD_FEC_SHRED_CNT );
        if( FD_UNLIKELY( !fec ) ) continue;
        fec_treap_remove( chainer, v, fec );
        if( FD_LIKELY( fec->root ) ) {
          fd_fec_map_ele_remove_fast( chainer->fec_map, fec, chainer->fec_pool );
          fd_chainer_fec_t * shared = final ? slotv_fec( chainer, final, k*(uint)FD_FEC_SHRED_CNT ) : NULL;
          if( FD_UNLIKELY( shared && mr_eq( &shared->merkle_root, &fec->merkle_root ) ) ) {
            shared->merkle_root = fec->merkle_root;
            shared->data_idxs = fec->data_idxs;
            shared->root = 1;
            fd_fec_map_ele_insert( chainer->fec_map, shared, chainer->fec_pool );
          } else if( store && fec->complete ) {
            fd_store_remove( store, store_map, &fec->merkle_root );
          }
        }
        fd_fec_pool_ele_release( chainer->fec_pool, fec );
      }
      fd_memset( fd_chainer_slotv_fecs( chainer, v ), 0xff, chainer->fec_blk_max*sizeof(uint) );
      fd_slotv_map_ele_remove_fast( chainer->slotv_map, v, chainer->slotv_pool );
      fd_slotv_pool_ele_release( chainer->slotv_pool, v );
    }
    i = next;
  }
  /* Prune first so a previously unknown final version can replace a
     slot already at the version limit. */
  if( FD_UNLIKELY( !final ) ) {
    final = fd_chainer_verified_block_insert( chainer, slot, *block_id );
    FD_TEST( final );
    final->final = 1;
  }
}

void
fd_chainer_publish( fd_chainer_t *    chainer,
                    ulong             new_root,
                    fd_hash_t const * new_root_block_id,
                    fd_store_t *      store ) {
  fd_store_map_t store_map[1];
  if( store ) FD_TEST( fd_store_map_ljoin( store, store_map ) );

  fd_slotv_map_t     * slotv_map  = chainer->slotv_map;
  fd_chainer_slotv_t * slotv_pool = chainer->slotv_pool;
  out_ele_t * out_queue = chainer->out_queue;
  if( FD_UNLIKELY( !out_queue_empty( out_queue ) ) ) FD_LOG_CRIT(( "chainer out_queue not empty before publish" ));

  ulong root = chainer->root;
  if( FD_UNLIKELY( root==ULONG_MAX ) ) return;
  FD_TEST( root<new_root );
  FD_TEST( fd_chainer_slot_query( chainer, new_root ) );

  /* Identify the canonical (rooted) version of new_root.  Every other
     version of it is an equivocating sibling that is now dead.  If no
     version matches, keep them all rather than guess wrong and prune
     the version we are actually rooted on.  TODO: block_id is now
     always wired through from replay, so this could be a CRIT. */
  fd_chainer_slotv_t * canonical = new_root_block_id ? fd_chainer_slot_version_query( chainer, new_root, new_root_block_id ) : NULL;
  if( FD_UNLIKELY( !canonical ) ) {
    FD_LOG_DEBUG(( "chainer publish %lu: no version matches the rooted block_id; keeping all versions", new_root ));
  }

  /* Prune every version of every slot in [root, new_root]: release the
     FECs it owns, drop it from the worklists, and free it.  Only the
     canonical version of new_root survives (all of them if canonical is
     unknown) and its FEC list is cleared, since a rooted slot's FEC
     data is never needed again. */
  for( ulong slot=root; slot<=new_root; slot++ ) {
    for( ulong i=fd_chainer_slotv_iter_init( chainer, slot ); i!=ULONG_MAX; ) {
      fd_chainer_slotv_t * s    = fd_chainer_slotv_iter_ele( chainer, i );
      ulong                next = fd_chainer_slotv_iter_next( chainer, i );

      for( uint k=0U; k<chainer->fec_blk_max; k++ ) {
        fd_chainer_fec_t * fec = slotv_fec( chainer, s, k * FD_FEC_SHRED_CNT );
        if( FD_UNLIKELY( !fec ) ) continue;

        fec_treap_remove( chainer, s, fec );
        if( FD_LIKELY( fec->root ) ) {
          fd_fec_map_ele_remove_fast( chainer->fec_map, fec, chainer->fec_pool );
          if( FD_LIKELY( store && fec->complete ) ) fd_store_remove( store, store_map, &fec->merkle_root );
        }

        fd_fec_pool_ele_release( chainer->fec_pool, fec );
      }
      fd_memset( fd_chainer_slotv_fecs( chainer, s ), 0xff, chainer->fec_blk_max*sizeof(uint) );


      int survives = slot==new_root && ( !canonical || s==canonical );
      if( FD_LIKELY( !survives ) ) {
        fd_slotv_map_ele_remove_fast( slotv_map, s, slotv_pool );
        fd_slotv_pool_ele_release( slotv_pool, s );
      }
      i = next;
    }
  }

  chainer->root = new_root;

  /* Connect the surviving version(s) of the new root. */
  for( ulong i=fd_chainer_slotv_iter_init( chainer, new_root ); i!=ULONG_MAX; i=fd_chainer_slotv_iter_next( chainer, i ) ) {
    fd_chainer_slotv_t * s = fd_chainer_slotv_iter_ele( chainer, i );
    if( FD_UNLIKELY( s->parent_slot==AG_UNKNOWN_SLOT ) ) s->parent_slot = new_root;
    s->connected        = 1;
    s->complete_idx     = 0U;
    s->buffered_idx     = 0U;
    s->delivered_idx    = 0U;
    s->buffered_fec_idx = UINT_MAX; /* rooted slot has no buffered FEC set */
  }

  /* The new root becomes a delivered anchor here WITHOUT going through
     chainer_advance's slot_complete cascade, so children that already
     completed while waiting on it were never connected/delivered.
     Cascade to them now, mirroring chainer_advance's child scan. */
  for( ulong i=fd_chainer_slotv_iter_init( chainer, new_root ); i!=ULONG_MAX; i=fd_chainer_slotv_iter_next( chainer, i ) ) {
    fd_chainer_slotv_t * s = fd_chainer_slotv_iter_ele( chainer, i );
    if( FD_UNLIKELY( fd_hash_check_zero( &s->block_id ) ) ) continue;
    for( fd_slotv_map_iter_t it = fd_slotv_map_iter_init( slotv_map, slotv_pool );
                                 !fd_slotv_map_iter_done( it, slotv_map, slotv_pool );
                             it = fd_slotv_map_iter_next( it, slotv_map, slotv_pool ) ) {
      fd_chainer_slotv_t * child = fd_slotv_map_iter_ele( it, slotv_map, slotv_pool );
      if( FD_UNLIKELY( fd_hash_eq( &child->parent_block_id, &s->block_id ) ) ) {
        child->connected = 1;
        chainer_advance( chainer, child );
      }
    }
  }
}

void
fd_chainer_print( fd_chainer_t * chainer ) {
  if( FD_UNLIKELY( chainer->root==ULONG_MAX ) ) return;

  fd_chainer_slotv_t * slotv_pool = chainer->slotv_pool;
  fd_slotv_map_t     * slotv_map  = chainer->slotv_map;

  printf( "\n[Chainer] root: %lu, highest repaired: %lu\n", chainer->root, chainer->highest_repaired );

  ulong cnt = 0UL;
  for( fd_slotv_map_iter_t it = fd_slotv_map_iter_init( slotv_map, slotv_pool );
                               !fd_slotv_map_iter_done( it, slotv_map, slotv_pool );
                           it = fd_slotv_map_iter_next( it, slotv_map, slotv_pool ) ) {
    fd_chainer_slotv_t * o = fd_slotv_map_iter_ele( it, slotv_map, slotv_pool );

    ulong slot = o->slot;

    FD_BASE58_ENCODE_32_BYTES( o->block_id.uc, out )
    if( FD_UNLIKELY( o->parent_slot==AG_UNKNOWN_SLOT ) ) {
      printf( "%lu - ???: shreds: (%u/%u) turb: %d block_id: %s \n", slot, o->buffered_idx+1U, o->complete_idx+1U, o->turbine, out );
    }
    else {
      printf( "%lu - %lu: shreds: (%u/%u) turb: %d block_id: %s connected: %d\n ", slot, o->parent_slot, o->buffered_idx+1U, o->complete_idx+1U, o->turbine, out, o->connected );
    }
    cnt++;
  }
  printf( "(%lu total slotvs)\n", cnt );
  fflush( stdout );
}


int
fd_chainer_verify( fd_chainer_t const * chainer ) {
# define FAIL( msg ) do { FD_LOG_WARNING(( "fd_chainer_verify: %s", msg )); return -1; } while(0)

  if( FD_UNLIKELY( !chainer                                                   ) ) FAIL( "NULL chainer" );
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)chainer, fd_chainer_align() ) ) ) FAIL( "misaligned chainer" );
  if( FD_UNLIKELY( !fd_wksp_containing( chainer )                             ) ) FAIL( "chainer must be part of a workspace" );
  if( FD_UNLIKELY( chainer->magic!=FD_CHAINER_MAGIC                           ) ) FAIL( "bad magic" );

  fd_chainer_t * chainer_ = (fd_chainer_t *)chainer;

  fd_chainer_slotv_t const * slotv_pool = chainer_->slotv_pool;
  fd_slotv_map_t     const * slotv_map  = chainer_->slotv_map;
  fd_chainer_fec_t   const * fec_pool   = chainer_->fec_pool;
  fd_fec_map_t       const * fec_map    = chainer_->fec_map;

  if( FD_UNLIKELY( fd_slotv_map_verify( slotv_map, fd_slotv_pool_max( slotv_pool ), slotv_pool )==-1 ) ) FAIL( "slotv map corrupted" );
  if( FD_UNLIKELY( fd_fec_map_verify  ( fec_map,   fd_fec_pool_max  ( fec_pool   ), fec_pool   )==-1 ) ) FAIL( "fec map corrupted"   );

  /* The root, if set, must have at least one connected version -- it is
     by definition the start of every ancestry chain.  Uniquely among
     slots, the root need not have a version 0: publish prunes the
     non-canonical versions of the new root, and version 0 may have been
     one of them.  Its FEC list is released along with it, which is fine
     because a rooted slot's FEC data is never needed again. */

  if( FD_LIKELY( chainer->root!=ULONG_MAX ) ) {
    int   root_present   = 0;
    int   root_connected = 0;
    ulong root           = chainer->root;
    for( ulong i = fd_slotv_map_idx_query_const( slotv_map, &root, ULONG_MAX, slotv_pool );
               i != ULONG_MAX;
               i = fd_slotv_map_idx_next_const( i, ULONG_MAX, slotv_pool ) ) {
      fd_chainer_slotv_t const * root_slotv = fd_slotv_pool_ele_const( slotv_pool, i );
      root_present    = 1;
      root_connected |= !!root_slotv->connected;
    }
    if( FD_UNLIKELY( !root_present   ) ) FAIL( "root has no slotv" );
    if( FD_UNLIKELY( !root_connected ) ) FAIL( "no root slotv is connected" );
  }

  for( fd_slotv_map_iter_t it = fd_slotv_map_iter_init( slotv_map, slotv_pool );
                               !fd_slotv_map_iter_done( it, slotv_map, slotv_pool );
                           it = fd_slotv_map_iter_next( it, slotv_map, slotv_pool ) ) {
    fd_chainer_slotv_t const * slotv = fd_slotv_map_iter_ele_const( it, slotv_map, slotv_pool );

    ulong slot = slotv->slot;

    /* Nothing below the root may survive a publish. */

    if( FD_UNLIKELY( chainer->root!=ULONG_MAX && slot<chainer->root ) ) FAIL( "slotv below the root" );

    /* Shred index bookkeeping */

    if( FD_UNLIKELY( slotv->complete_idx!=UINT_MAX && slotv->buffered_idx !=UINT_MAX &&
                     slotv->buffered_idx >slotv->complete_idx ) ) FAIL( "buffered_idx > complete_idx" );
    if( FD_UNLIKELY( slotv->complete_idx!=UINT_MAX && slotv->delivered_idx!=UINT_MAX &&
                     slotv->delivered_idx>slotv->complete_idx ) ) FAIL( "delivered_idx > complete_idx" );

    /* buffered_fec_idx is the last shred idx of a FEC set, so it is
       always one below a multiple of FD_FEC_SHRED_CNT (UINT_MAX, the
       "none" sentinel, satisfies this too). */

    if( FD_UNLIKELY( ( slotv->buffered_fec_idx + 1U ) % FD_FEC_SHRED_CNT ) ) FAIL( "buffered_fec_idx is not the last idx of a FEC set" );

    /* A buffered FEC set means all of its shreds are in hand, so the
       contiguous FEC prefix can never run ahead of the contiguous shred
       prefix. */

    if( FD_UNLIKELY( slotv->buffered_fec_idx!=UINT_MAX &&
                     ( slotv->buffered_idx==UINT_MAX ||
                       slotv->buffered_idx<slotv->buffered_fec_idx ) ) ) FAIL( "buffered_fec_idx runs ahead of buffered_idx" );
  }

  /* No treap may hold an ele not accounted for in the work map. */


  for( fd_fec_map_iter_t it = fd_fec_map_iter_init( fec_map, fec_pool );
                             !fd_fec_map_iter_done( it, fec_map, fec_pool );
                         it = fd_fec_map_iter_next( it, fec_map, fec_pool ) ) {
    fd_chainer_fec_t const * fec = fd_fec_map_iter_ele_const( it, fec_map, fec_pool );

    ulong slot        = fec->slot;
    uint  fec_set_idx = fec->fec_set_idx;
    uint  fec_idx     = (uint)fd_fec_pool_idx( fec_pool, fec );

    if( FD_UNLIKELY( fec_set_idx % FD_FEC_SHRED_CNT                            ) ) FAIL( "fec_set_idx is not a multiple of FD_FEC_SHRED_CNT" );
    if( FD_UNLIKELY( fec_set_idx / FD_FEC_SHRED_CNT >= chainer->fec_blk_max    ) ) FAIL( "fec_set_idx out of range" );

    if( FD_UNLIKELY( chainer->root!=ULONG_MAX && slot<chainer->root ) ) FAIL( "fec below the root" );

    /* A slot with a FEC must have at least one version to anchor the list
       and own the FEC -- without one publish could never reach it. */

    if( FD_UNLIKELY( !fd_chainer_slot_query( chainer_, slot ) ) ) FAIL( "slot has a fec but no version to anchor the list" );

    /* A FEC is owned by every version whose fec_tbl row points at it,
       and at least one must -- otherwise it is unreachable garbage that
       publish would leak. */

    int owned = 0;
    for( ulong i = fd_slotv_map_idx_query_const( slotv_map, &slot, ULONG_MAX, slotv_pool );
               i != ULONG_MAX;
               i = fd_slotv_map_idx_next_const( i, ULONG_MAX, slotv_pool ) ) {
      fd_chainer_slotv_t const * slotv = fd_slotv_pool_ele_const( slotv_pool, i );
      if( FD_LIKELY( fd_chainer_slotv_fecs( chainer, slotv )[ fec_set_idx / FD_FEC_SHRED_CNT ]==fec_idx ) ) owned = 1;
    }
    if( FD_UNLIKELY( !owned ) ) FAIL( "fec claimed by no version" );
  }

  return 0;
}
#undef FAIL
