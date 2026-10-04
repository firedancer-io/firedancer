#include "fd_rotor.h"
#include "../../disco/shred/fd_fec_set.h"
#include "../../ballet/bmtree/fd_bmtree.h"
#include "../../ballet/sha256/fd_sha256.h"

#include <stdio.h>

void *
fd_rotor_new( void * shmem,
              ulong  ele_max,
              ulong  max_shreds_per_block,
              ulong  seed ) {
  ulong footprint = fd_rotor_footprint( ele_max, max_shreds_per_block );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "bad footprint: %lu %lu", ele_max, max_shreds_per_block ));
    return NULL;
  }

  fd_wksp_t * wksp = fd_wksp_containing( shmem );
  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_WARNING(( "shmem must be part of a workspace" ));
    return NULL;
  }

  fd_memset( shmem, 0, sizeof(fd_rotor_t) );
  fd_rotor_t * rotor;

  ulong blk_max       = fd_rotor_blk_max( ele_max );
  ulong fec_blk_max   = max_shreds_per_block / FD_FEC_SHRED_CNT;
  ulong fec_max       = blk_max * fec_blk_max;
  ulong fec_chain_cnt = fd_fec_map_chain_cnt_est( fec_max );
  ulong blk_chain_cnt = fd_block_map_chain_cnt_est( blk_max );

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  rotor             = FD_SCRATCH_ALLOC_APPEND( l, fd_rotor_align(),      sizeof(fd_rotor_t)                       );
  void * fec_pool   = FD_SCRATCH_ALLOC_APPEND( l, fd_fec_pool_align(),   fd_fec_pool_footprint  ( fec_max )       );
  void * fec_map    = FD_SCRATCH_ALLOC_APPEND( l, fd_fec_map_align(),    fd_fec_map_footprint   ( fec_chain_cnt ) );
  void * block_pool = FD_SCRATCH_ALLOC_APPEND( l, fd_block_pool_align(), fd_block_pool_footprint( blk_max )       );
  void * fec_tbl    = FD_SCRATCH_ALLOC_APPEND( l, alignof(uint),         fec_max*sizeof(uint)                     );
  void * block_map  = FD_SCRATCH_ALLOC_APPEND( l, fd_block_map_align(),  fd_block_map_footprint ( blk_chain_cnt ) );
  void * bfs        = FD_SCRATCH_ALLOC_APPEND( l, bfs_align(),           bfs_footprint          ( blk_max )       );
  void * out_queue  = FD_SCRATCH_ALLOC_APPEND( l, out_queue_align(),     out_queue_footprint    ( fec_max )       );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, fd_rotor_align() ) == (ulong)shmem + footprint );

  rotor->root             = ULONG_MAX;
  rotor->highest_repaired = 0UL;
  rotor->wksp_gaddr       = fd_wksp_gaddr_fast( wksp, rotor );
  rotor->fec_pool         = fd_fec_pool_join  ( fd_fec_pool_new   ( fec_pool,   fec_max             ) );
  rotor->fec_map          = fd_fec_map_join   ( fd_fec_map_new    ( fec_map,    fec_chain_cnt, seed ) );
  rotor->block_pool       = fd_block_pool_join( fd_block_pool_new ( block_pool, blk_max             ) );
  rotor->fec_tbl          = fec_tbl;
  rotor->fec_blk_max      = fec_blk_max;
  rotor->block_map        = fd_block_map_join ( fd_block_map_new  ( block_map,  blk_chain_cnt, seed ) );
  rotor->bfs              = bfs_join          ( bfs_new           ( bfs,        blk_max             ) );
  rotor->out_queue        = out_queue_join    ( out_queue_new     ( out_queue,  fec_max             ) );

  FD_COMPILER_MFENCE();
  FD_VOLATILE( rotor->magic ) = FD_ROTOR_MAGIC;
  FD_COMPILER_MFENCE();

  return shmem;
}

fd_rotor_t *
fd_rotor_join( void * shrotor ) {
  fd_rotor_t * rotor = (fd_rotor_t *)shrotor;
  if( FD_UNLIKELY( rotor->magic!=FD_ROTOR_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }
  return rotor;
}

/* block_iter_{init,next} iterate the versions of a slot via the
   MAP_MULTI chain.  Usage:
     for( ulong i=block_iter_init(rotor,slot); i!=ULONG_MAX; i=block_iter_next(rotor,i) ) {
       fd_rotor_blk_t * block = block_iter_ele( rotor, i );
       ...
     } */

static inline ulong
block_iter_init( fd_rotor_t * rotor, ulong slot ) {
  return fd_block_map_idx_query_const( rotor->block_map, &slot, ULONG_MAX, rotor->block_pool );
}

static inline ulong
block_iter_next( fd_rotor_t * rotor, ulong idx ) {
  return fd_block_map_idx_next_const( idx, ULONG_MAX, rotor->block_pool );
}

static inline fd_rotor_blk_t *
block_iter_ele( fd_rotor_t * rotor, ulong idx ) {
  return fd_block_pool_ele( rotor->block_pool, idx );
}

/* acquire_block allocates, initializes, and map-inserts a fresh
   (turbine, i.e. all-zero block_id) version of slot.  Callers that know
   the version's block_id (notar-fallback, parent discovery) set it after. */

static fd_rotor_blk_t *
acquire_block( fd_rotor_t * rotor, ulong slot ) {
  fd_block_map_t * block_map  = rotor->block_map;
  fd_rotor_blk_t * block_pool = rotor->block_pool;
  FD_TEST( fd_block_pool_free( block_pool ) );

  ulong block_cnt = 0UL;
  for( ulong i=block_iter_init( rotor, slot ); i!=ULONG_MAX; i=block_iter_next( rotor, i ) ) {
    block_cnt++;
  }
  if( FD_UNLIKELY( block_cnt>=FD_ROTOR_SLOT_VER_MAX ) ) FD_LOG_CRIT(( "slots stored exceeds protocol limits, %lu versions of slot %lu already stored", block_cnt, slot ));

  fd_rotor_blk_t * block = fd_block_pool_ele_acquire( block_pool );
  block->slot              = slot;
  block->turbine           = 0;
  block->is_leader         = 0;
  block->abandoned         = 0;
  block->parent_off        = 0;
  block->parent_slot       = AG_UNKNOWN_SLOT;
  block->parent_slot_batch = UINT_MAX;
  block->complete_idx      = UINT_MAX;
  block->buffered_idx      = UINT_MAX;
  block->buffered_fec_idx  = UINT_MAX;
  block->delivered_idx     = UINT_MAX;
  block->connected         = 0;

  block->metrics.abandoned_reason           = 0;
  block->metrics.turbine_cnt                = 0U;
  block->metrics.repair_cnt                 = 0U;
  block->metrics.recovered_cnt              = 0U;
  block->metrics.parity_cnt                 = 0U;
  block->metrics.first_meta_ts              = 0L;
  block->metrics.abandoned_ts               = 0L;
  block->metrics.first_shred_ts             = 0L;
  block->metrics.last_shred_ts              = 0L;
  block->metrics.req_window_cnt             = 0U;
  block->metrics.req_highest_cnt            = 0U;
  block->metrics.req_orphan_cnt             = 0U;
  block->metrics.req_shred_bid_cnt          = 0U;
  block->metrics.req_parent_cnt             = 0U;
  block->metrics.req_fec_root_cnt           = 0U;
  block->metrics.req_retransmit_cnt         = 0U;
  block->metrics.shred_repair_responses     = 0U;
  block->metrics.parent_fec_count_responses = 0U;
  block->metrics.fec_root_responses         = 0U;
  block->metrics.first_req_ts               = 0L;
  block->metrics.last_repair_resp_ts        = 0L;
  block->metrics.last_completed_fec_idx     = UINT_MAX;

  fd_memset( &block->block_id,        0, sizeof(fd_hash_t) );
  fd_memset( &block->parent_block_id, 0, sizeof(fd_hash_t) );
  fd_memset( fd_rotor_block_fecs( rotor, block ), 0xff, rotor->fec_blk_max*sizeof(uint) ); /* UINT_MAX pool_idx sentinel */

  fd_block_map_ele_insert( block_map, block, block_pool );
  return block;
}

void
fd_rotor_init( fd_rotor_t *            rotor,
               ulong                   slot,
               fd_hash_t const *       block_id,
               fd_rotor_block_event_fn block_event_fn,
               void *                  block_event_ctx ) {
  fd_rotor_blk_t * block = acquire_block( rotor, slot );
  block->parent_slot       = slot;
  block->complete_idx      = 0;
  block->buffered_idx      = 0;
  block->connected         = 1;
  block->delivered_idx     = 0; /* must equal complete_idx at init */
  block->buffered_fec_idx  = UINT_MAX; /* no complete FEC set buffered; must
                                          be one-below a FD_FEC_SHRED_CNT
                                          multiple, which UINT_MAX satisfies */
  block->block_id          = *block_id;

  rotor->root             = slot;
  rotor->highest_repaired = slot;

  rotor->block_event_fn   = block_event_fn;
  rotor->block_event_ctx  = block_event_ctx;
}

/* block_fec returns the FEC that block owns at fec_set_idx, or NULL if
   it holds none there (or fec_set_idx is beyond max_shreds_per_block). */

static fd_rotor_fec_t *
block_fec( fd_rotor_t * rotor, fd_rotor_blk_t const * block, uint fec_set_idx ) {
  ulong k = fec_set_idx / FD_FEC_SHRED_CNT;
  if( FD_UNLIKELY( k>=rotor->fec_blk_max ) ) return NULL;
  uint idx = fd_rotor_block_fecs( rotor, block )[ k ];
  if( FD_UNLIKELY( idx==UINT_MAX ) ) return NULL;
  return fd_fec_pool_ele( rotor->fec_pool, (ulong)idx );
}

fd_rotor_fec_t *
fd_rotor_fec_query( fd_rotor_t *      rotor,
                    ulong             slot,
                    uint              fec_set_idx,
                    fd_hash_t const * block_id ) {
  fd_rotor_blk_t * block = fd_rotor_slot_version_query( rotor, slot, block_id );
  if( FD_UNLIKELY( !block ) ) return NULL;
  return block_fec( rotor, block, fec_set_idx );
}

/* fec_join records that block includes the FEC at (slot, fec_set_idx)
   with root mr, creating the entry if this root has not been seen yet. */

static fd_rotor_fec_t *
fec_join( fd_rotor_t *      rotor,
          ulong             slot,
          uint              fec_set_idx,
          fd_rotor_blk_t *  block,
          fd_hash_t const * mr ) {
  if( FD_UNLIKELY( slot>(ulong)UINT_MAX ) ) FD_LOG_CRIT(( "slot %lu exceeds uint range", slot ));
  ulong k = fec_set_idx / FD_FEC_SHRED_CNT;
  FD_TEST( k<rotor->fec_blk_max );

  fd_fec_map_t   * fec_map  = rotor->fec_map;
  fd_rotor_fec_t * fec_pool = rotor->fec_pool;
  fd_rotor_fec_t * fec      = fd_fec_map_ele_query( fec_map, mr, NULL, fec_pool );
  if( FD_UNLIKELY( !fec ) ) {
    if( FD_UNLIKELY( !fd_fec_pool_free( fec_pool ) ) ) FD_LOG_CRIT(( "fec_pool is full" ));
    fec = fd_fec_pool_ele_acquire( fec_pool );
    fec->merkle_root   = *mr;
    fec->slot          = (uint)slot;
    fec->fec_set_idx   = fec_set_idx & ((1U<<28)-1U);
    fec->data_idxs     = 0U;
    fec->complete      = 0;
    fec->slot_complete = 0;
    fec->data_complete = 0;
    fec->is_leader     = 0;
    fd_memset( &fec->metrics, 0, sizeof(fec->metrics) );
    fd_fec_map_ele_insert( fec_map, fec, fec_pool );
  }
  fd_rotor_block_fecs( rotor, block )[ k ] = (uint)fd_fec_pool_idx( fec_pool, fec );
  return fec;
}

int
fd_rotor_shred_test( fd_rotor_t *           rotor,
                     fd_rotor_blk_t const * block,
                     uint                   shred_idx ) {
  fd_rotor_fec_t * fec = block_fec( rotor, block, shred_idx & ~( (uint)FD_FEC_SHRED_CNT - 1U ) );
  if( FD_UNLIKELY( !fec ) ) return 0;
  return !!( fec->data_idxs & ( 1U << ( shred_idx & ( (uint)FD_FEC_SHRED_CNT - 1U ) ) ) );
}

static void
rotor_invalidate( fd_rotor_blk_t * block, long rx_ts, int reason ) {
  if( !fd_hash_check_zero( &block->block_id ) || block->abandoned ) return;
  block->abandoned = 1;
  block->metrics.abandoned_ts = rx_ts;
  block->metrics.abandoned_reason = reason;
}

/* turbine_block_query returns the turbine version of slot, or NULL. */

fd_rotor_blk_t *
fd_rotor_turbine_block_query( fd_rotor_t const * rotor, ulong slot ) {
  for( ulong i =fd_block_map_idx_query_const( rotor->block_map, &slot, ULONG_MAX, rotor->block_pool );
             i!=ULONG_MAX;
             i =fd_block_map_idx_next_const( i, ULONG_MAX, rotor->block_pool ) ) {
    fd_rotor_blk_t * block = fd_block_pool_ele( rotor->block_pool, i );
    if( FD_LIKELY( block->turbine ) ) return block;
  }
  return NULL;
}

/* turbine_block_insert returns the turbine version of slot -- creating
   it if none exists. */

static fd_rotor_blk_t *
turbine_block_insert( fd_rotor_t * rotor, ulong slot ) {
  fd_rotor_blk_t * block = fd_rotor_turbine_block_query( rotor, slot );
  if( FD_LIKELY( block ) ) return block;
  block = acquire_block( rotor, slot );
  block->turbine = 1;
  return block;
}

/* finalize_block_id computes the block's double-merkle block_id and
   writes it to block->block_id.  Returns 1 on success, 0 on failure. */

static int
finalize_block_id( fd_rotor_t * rotor, fd_rotor_blk_t * block ) {
  if( FD_UNLIKELY( block->complete_idx==UINT_MAX ) )                 return 0;
  if( FD_UNLIKELY( block->parent_slot==AG_UNKNOWN_SLOT ) )           return 0;
  if( FD_UNLIKELY( fd_hash_check_zero( &block->parent_block_id ) ) ) return 0;

  uint fec_set_cnt = ( block->complete_idx + 1U ) / FD_FEC_SHRED_CNT;
  uchar tree_mem[ FD_BMTREE_COMMIT_FOOTPRINT( 0UL ) ] __attribute__((aligned(FD_BMTREE_COMMIT_ALIGN)));
  fd_bmtree_commit_t * tree = fd_bmtree_commit_init( tree_mem, 20UL, FD_BMTREE_LONG_PREFIX_SZ, 0UL );

  for( uint i=0U; i<fec_set_cnt; i++ ) {
    fd_rotor_fec_t * fec = block_fec( rotor, block, i*FD_FEC_SHRED_CNT );
    if( FD_UNLIKELY( !fec ) ) return 0;

    fd_bmtree_node_t leaf[1];
    memcpy( leaf->hash, fec->merkle_root.uc, sizeof(fd_hash_t) );
    fd_bmtree_commit_append( tree, leaf, 1UL );
  }

  /* final parent-info leaf */
  fd_bmtree_node_t parent_info[1];
  fd_sha256_t sha[1];
  fd_sha256_init  ( sha );
  fd_sha256_append( sha, &block->parent_slot,       sizeof(ulong)     );
  fd_sha256_append( sha, block->parent_block_id.uc, sizeof(fd_hash_t) );
  fd_sha256_append( sha, &fec_set_cnt,              sizeof(uint)      );
  fd_sha256_fini  ( sha, parent_info->hash );
  fd_bmtree_commit_append( tree, parent_info, 1UL );

  uchar * root = fd_bmtree_commit_fini( tree );
  memcpy( block->block_id.uc, root, sizeof(fd_hash_t) );
  return 1;
}

static void
fec_shred_received( fd_rotor_fec_t * fec, int src, long rx_ts ) {
  fec->metrics.last_shred_src = src;
  if( FD_UNLIKELY( rx_ts && ( !fec->metrics.first_shred_ts || rx_ts<fec->metrics.first_shred_ts ) ) )
    fec->metrics.first_shred_ts = rx_ts;
}


fd_rotor_blk_t *
fd_rotor_shred_insert( fd_rotor_t *      rotor,
                       ulong             slot,
                       uint              shred_idx,
                       int               slot_complete,
                       int               src,
                       long              rx_ts,
                       fd_hash_t const * mr,
                       ushort            parent_off,
                       ulong             parent_slot,
                       fd_hash_t const * parent_block_id ) {
  FD_TEST( slot>rotor->root );
  uint  fec_set_idx = shred_idx & ~( (uint)FD_FEC_SHRED_CNT - 1U );
  ulong k           = fec_set_idx / FD_FEC_SHRED_CNT;

  /* The turbine version is created here if no notar version exists yet */

  fd_rotor_blk_t * created = NULL;
  fd_rotor_blk_t * turbine = fd_rotor_turbine_block_query( rotor, slot );
  if( FD_UNLIKELY( !turbine && !fd_rotor_slot_query( rotor, slot ) ) ) {
    turbine = turbine_block_insert( rotor, slot );
    created = turbine;
  }

  /* If we have a turbine version:
       - if it has no FEC for this position, use this one
       - it it has a FEC, and it's the same mr, we're good
       - it it has a FEC, and it's different, mark it abandoned */

  if( FD_LIKELY( turbine ) ) {
    fd_rotor_fec_t * fect = block_fec( rotor, turbine, fec_set_idx );
    if     ( FD_UNLIKELY( !fect ) )                                 fec_join( rotor, slot, fec_set_idx, turbine, mr );
    else if( FD_UNLIKELY( !fd_hash_eq( &fect->merkle_root, mr ) &&
                           fd_hash_check_zero( &turbine->block_id ) ) ) rotor_invalidate( turbine, rx_ts, ABANDON_REASON_MERKLE_ROOT_MISMATCH );
  }

  fd_rotor_fec_t * fec = fd_fec_map_ele_query( rotor->fec_map, mr, NULL, rotor->fec_pool );
  if( FD_UNLIKELY( !fec ) ) {
    return created; /* shred dropped, no block has an interest */
  }

  /* A sentinel holds only the zero-padded prefix until now.  Fill in
     the full root the shred carries. */
  fec->merkle_root = *mr;

  uint bit        = 1U << ( shred_idx - fec_set_idx );
  int  new_shred  = !( fec->data_idxs & bit );
  fec->data_idxs |= bit;
  if( FD_UNLIKELY( slot_complete ) ) fec->slot_complete = 1;

  /* Reconstructed notifications must not replace the source of the
     network shred that enabled recovery. */
  if( FD_LIKELY( new_shred && !fec->complete && ( src==FD_ROTOR_SRC_TURBINE || src==FD_ROTOR_SRC_REPAIR ) ) ) {
    fec->metrics.data_received |= bit;
    if( src==FD_ROTOR_SRC_REPAIR ) fec->metrics.repair_received |= bit;
    fec_shred_received( fec, src, rx_ts );
  }

  /* Update every version that owns this FEC root at this position. */

  uint fec_idx = (uint)fd_fec_pool_idx( rotor->fec_pool, fec );
  for( ulong i =block_iter_init( rotor, slot ); i!=ULONG_MAX; i =block_iter_next( rotor, i ) ) {
    fd_rotor_blk_t * block = block_iter_ele( rotor, i );
    if( FD_UNLIKELY( fd_rotor_block_fecs( rotor, block )[ k ]!=fec_idx ) ) continue;

    /* Every data shred of a slot carries the same parent_off (see
       Parent Discovery).  0 means the caller has no shred header. */
    if( FD_LIKELY( parent_off ) ) {
      if( FD_UNLIKELY( !block->parent_off ) ) block->parent_off = parent_off;
      if( FD_UNLIKELY( block->parent_off!=parent_off && block->turbine ) ) rotor_invalidate( block, rx_ts, ABANDON_REASON_PARENT_OFF_MISMATCH );
    }

    /* update reception statistics */
    if( FD_LIKELY( new_shred ) ) {
      block->metrics.turbine_cnt   += ( src==FD_ROTOR_SRC_TURBINE   );
      block->metrics.repair_cnt    += ( src==FD_ROTOR_SRC_REPAIR    );
      block->metrics.recovered_cnt += ( src==FD_ROTOR_SRC_RECOVERED );
    }

    /* A version created late adopts FECs whose shreds predate it. */
    if( FD_UNLIKELY( rx_ts && ( !block->metrics.first_shred_ts || rx_ts<block->metrics.first_shred_ts ) ) ) block->metrics.first_shred_ts = rx_ts;

    /* update slot-level shred indexing */
    uint shred_max = (uint)( rotor->fec_blk_max*FD_FEC_SHRED_CNT );
    if( FD_UNLIKELY( slot_complete ) ) block->complete_idx = shred_idx;
    while( block->buffered_idx + 1 < shred_max && fd_rotor_shred_test( rotor, block, block->buffered_idx + 1U ) ) {
      block->buffered_idx++;
    }

    /* If equivocating, buffered_idx needs to be clamped to complete_idx */
    if( FD_UNLIKELY( block->buffered_idx != UINT_MAX && block->complete_idx != UINT_MAX && block->buffered_idx > block->complete_idx ) ) block->buffered_idx = block->complete_idx;

    /* Stamped once, when the version first becomes contiguous */
    if( FD_UNLIKELY( rx_ts && !block->metrics.last_shred_ts && block->complete_idx!=UINT_MAX && block->buffered_idx==block->complete_idx ) ) {
      block->metrics.last_shred_ts = rx_ts;
    }

    /* parent_slot_batch tracks which batch the information came from
       so a later UpdateParent supersedes the header (it may only move
       forward).  UINT_MAX means "nothing known yet", so it is not a
       batch index to compare against. */
    if( FD_UNLIKELY( parent_slot!=AG_UNKNOWN_SLOT && ( block->parent_slot_batch==UINT_MAX || shred_idx>block->parent_slot_batch ) ) ) {
      FD_TEST( parent_block_id ); /* TODO handholding check */

      block->parent_slot       = parent_slot;
      block->parent_slot_batch = shred_idx;
      block->parent_block_id   = *parent_block_id;

      fd_rotor_blk_t * parent = fd_rotor_slot_version_query( rotor, parent_slot, parent_block_id );
      if( FD_LIKELY( parent && parent->connected ) ) block->connected = 1;
    }
  }
  return created;
}

void
fd_rotor_code_shred_insert( fd_rotor_t *      rotor,
                            ulong             slot,
                            uint              fec_set_idx,
                            uint              code_idx,
                            long              rx_ts,
                            fd_hash_t const * mr ) {
  ulong k = fec_set_idx / FD_FEC_SHRED_CNT;
  if( FD_UNLIKELY( k>=rotor->fec_blk_max || code_idx>=FD_FEC_SHRED_CNT ) ) return;

  /* Best effort: coding shreds do not create FEC entries. */
  fd_rotor_fec_t * fec = fd_fec_map_ele_query( rotor->fec_map, mr, NULL, rotor->fec_pool );
  if( FD_UNLIKELY( !fec || fec->complete ) ) return;

  uint bit = 1U << code_idx;
  if( FD_UNLIKELY( fec->metrics.parity_received & bit ) ) return;
  fec->metrics.parity_received |= bit;
  fec_shred_received( fec, FD_ROTOR_SRC_TURBINE, rx_ts );

  uint fec_idx = (uint)fd_fec_pool_idx( rotor->fec_pool, fec );
  for( ulong i =block_iter_init( rotor, slot );
             i!=ULONG_MAX;
             i =block_iter_next( rotor, i ) ) {
    fd_rotor_blk_t * block = block_iter_ele( rotor, i );
    if( FD_UNLIKELY( fd_rotor_block_fecs( rotor, block )[ k ]!=fec_idx ) ) continue;
    block->metrics.parity_cnt++;
    block->metrics.turbine_cnt++;
    if( FD_UNLIKELY( rx_ts && ( !block->metrics.first_shred_ts || rx_ts<block->metrics.first_shred_ts ) ) ) block->metrics.first_shred_ts = rx_ts;
  }
}

/* rotor_deliver queues a delivered FEC for publish to replay.  The
   rotor tile drains the out_queue in after_credit. */

static void
rotor_deliver( fd_rotor_t *     rotor,
               fd_rotor_blk_t * block,
               fd_rotor_fec_t * fec ) {
  out_ele_t * out_queue = rotor->out_queue;
  if( FD_UNLIKELY( out_queue_full( out_queue ) ) ) FD_LOG_CRIT(( "rotor out_queue full" ));
  out_queue_push_tail( out_queue, (out_ele_t){ .block_idx = (uint)fd_block_pool_idx( rotor->block_pool, block ),
                                               .fec_idx   = (uint)fd_fec_pool_idx  ( rotor->fec_pool,   fec   ) } );
}

/* rotor_advance delivers as many contiguous completed FEC sets as
   possible from `root` block, then cascades: when a block's
   slot_complete FEC is delivered, every child block (parent_block_id ==
   this block's block_id) becomes connected and is drained in turn. */

static void
rotor_advance( fd_rotor_t * rotor, fd_rotor_blk_t * root ) {
  fd_block_map_t * block_map  = rotor->block_map;
  fd_rotor_blk_t * block_pool = rotor->block_pool;
  ulong          * bfs        = rotor->bfs;

  bfs_push_tail( bfs, fd_block_pool_idx( block_pool, root ) );

  while( FD_LIKELY( !bfs_empty( bfs ) ) ) {
    fd_rotor_blk_t * block = fd_block_pool_ele( block_pool, bfs_pop_head( bfs ) );
    if( FD_UNLIKELY( !block->connected ) ) continue;
    if( FD_UNLIKELY(  block->abandoned ) ) continue;

    fd_rotor_blk_t * parent = fd_rotor_slot_version_query( rotor, block->parent_slot, &block->parent_block_id );
    if( FD_UNLIKELY( !parent || parent->complete_idx==UINT_MAX || parent->delivered_idx!=parent->complete_idx ) ) continue;

    for(;;) {
      uint next = block->delivered_idx==UINT_MAX ? 0U
                                                 : block->delivered_idx + 1;
      fd_rotor_fec_t * fec = block_fec( rotor, block, next );
      if( FD_LIKELY( !fec || !fec->complete ) ) break; /* next FEC not completed yet */

      rotor_deliver( rotor, block, fec );
      block->delivered_idx = next + (FD_FEC_SHRED_CNT - 1);

      if( FD_UNLIKELY( fec->slot_complete ) ) {
        rotor->highest_repaired = fd_ulong_max( rotor->highest_repaired, block->slot );
        FD_TEST( !fd_hash_check_zero( &block->block_id ) );

        /* Scan for children. TODO could index children by
           parent_block_id; O(n) scan for now. */
        for( fd_block_map_iter_t it = fd_block_map_iter_init( block_map, block_pool );
                                 !fd_block_map_iter_done( it, block_map, block_pool );
                                 it = fd_block_map_iter_next( it, block_map, block_pool ) ) {
          fd_rotor_blk_t * child = fd_block_map_iter_ele( it, block_map, block_pool );
          if( FD_UNLIKELY( fd_hash_eq( &child->parent_block_id, &block->block_id ) ) ) {
            child->connected = 1;
            bfs_push_tail( bfs, fd_block_pool_idx( block_pool, child ) );
          }
        }
        break;
      }
    }
  }
}

fd_rotor_blk_t *
fd_rotor_fec_complete( fd_rotor_t *      rotor,
                       ulong             slot,
                       uint              fec_set_idx_,
                       int               slot_complete,
                       int               data_complete,
                       int               is_leader,
                       long              rx_ts,
                       fd_hash_t *       mr,
                       int *             opt_rejected,
                       fd_rotor_blk_t ** opt_turbine_finalized ) {
  FD_TEST( slot>rotor->root );
  uint  fec_set_idx = (uint)fec_set_idx_;
  ulong k           = fec_set_idx / FD_FEC_SHRED_CNT;
  FD_TEST( k<rotor->fec_blk_max ); /* guaranteed by fec_resolver */

  if( opt_rejected ) *opt_rejected = 0;
  if( opt_turbine_finalized ) *opt_turbine_finalized = NULL;

  fd_rotor_blk_t * created = NULL;
  for( uint i=0U; i<FD_FEC_SHRED_CNT; i++ ) {
    fd_rotor_blk_t * c = fd_rotor_shred_insert( rotor, slot, fec_set_idx_ + i, slot_complete && ( i==FD_FEC_SHRED_CNT-1 ), is_leader ? FD_ROTOR_SRC_LEADER : FD_ROTOR_SRC_RECOVERED, rx_ts, mr, 0, AG_UNKNOWN_SLOT, NULL );
    if( FD_UNLIKELY( c ) ) created = c; /* only the first insert can create */
  }

  /* By the time we get here the FEC exists unless turbine refused an
     unauthorized equivocating root -- in which case it was dropped and
     there is nothing to complete. */

  fd_rotor_fec_t * fec = fd_fec_map_ele_query( rotor->fec_map, mr, NULL, rotor->fec_pool );
  if( FD_UNLIKELY( !fec ) ) {
    if( opt_rejected ) *opt_rejected = 1;
    return created;
  }

  if( FD_LIKELY( !fec->complete ) ) {
    fec->metrics.completed_ts = rx_ts;
    if( FD_UNLIKELY( is_leader ) ) fec_shred_received( fec, FD_ROTOR_SRC_LEADER, rx_ts );
  }

  fec->complete = 1; /* set is now reconstructable -> deliverable */
  if( FD_UNLIKELY( slot_complete ) ) fec->slot_complete = 1;
  if( FD_UNLIKELY( data_complete ) ) fec->data_complete = 1;
  if( FD_UNLIKELY( is_leader ) )     fec->is_leader     = 1;

  uint fec_idx = (uint)fd_fec_pool_idx( rotor->fec_pool, fec );

  for( ulong i=block_iter_init( rotor, slot ); i!=ULONG_MAX; i=block_iter_next( rotor, i ) ) {
    fd_rotor_blk_t * block = block_iter_ele( rotor, i );
    if( FD_UNLIKELY( fd_rotor_block_fecs( rotor, block )[ k ]!=fec_idx || block->abandoned ) ) continue;

    block->metrics.last_completed_fec_idx = fec_set_idx;
    if( FD_UNLIKELY( is_leader && block->turbine ) ) block->is_leader = 1;

    int was_complete = block->complete_idx!=UINT_MAX && block->buffered_fec_idx==block->complete_idx;
    for(;;) {
      fd_rotor_fec_t * next = block_fec( rotor, block, block->buffered_fec_idx + 1U );
      if( !next || !next->complete ) break;
      block->buffered_fec_idx += FD_FEC_SHRED_CNT;
    }

    /* clamp buffered_fec_idx to complete_idx always. should never happen for non-turbine versions */
    if( FD_UNLIKELY( block->complete_idx!=UINT_MAX && block->buffered_fec_idx!=UINT_MAX &&
                     block->buffered_fec_idx>block->complete_idx ) ) block->buffered_fec_idx = block->complete_idx;

    if( FD_LIKELY( block->turbine ) ) {
      /* slot is complete implies we can record the block_id.  Only the
         turbine version needs its block_id computed. */
      fd_rotor_blk_t * turbine = block;
      if( FD_UNLIKELY( turbine->complete_idx!=UINT_MAX &&
                       turbine->buffered_fec_idx==turbine->complete_idx &&
                       fd_hash_check_zero( &turbine->block_id ) ) ) {
        if( FD_LIKELY( finalize_block_id( rotor, turbine ) ) ) {
          if( opt_turbine_finalized ) *opt_turbine_finalized = turbine;
          if( FD_UNLIKELY( rotor->block_event_fn && !block->abandoned ) ) rotor->block_event_fn( rotor->block_event_ctx, block );
        } else {
          FD_LOG_WARNING(( "failed to finalize block_id for slot %lu, parent_slot %lu parent_bid is zero %d", slot, turbine->parent_slot, fd_hash_check_zero( &turbine->parent_block_id ) ));
        }
      }
    } else if( FD_UNLIKELY( !was_complete && block->complete_idx!=UINT_MAX &&
                           block->buffered_fec_idx==block->complete_idx && rotor->block_event_fn ) ) {
      rotor->block_event_fn( rotor->block_event_ctx, block );
    }

    rotor_advance( rotor, block );
  }
  return created;
}

void
fd_rotor_fec_evicted( fd_rotor_t * rotor,
                      ulong        slot,
                      uint         fec_set_idx,
                      fd_hash_t *  merkle_root ) {
  fd_rotor_fec_t * fec = fd_fec_map_ele_query( rotor->fec_map, merkle_root, NULL, rotor->fec_pool );
  if( FD_UNLIKELY( !fec ) ) return;
  ulong k = fec_set_idx / FD_FEC_SHRED_CNT;
  FD_TEST( k<rotor->fec_blk_max ); /* guaranteed by fec_resolver */

  /* We choose not to remove the FEC from the rotor.  If this FEC
     belongs to a turbine slot and we are having trouble completing it
     (the leader gave up on disseminating the shreds), then eventually
     this slot will get skipped or we will repair a different version
     through a votor repair block id event. If this FEC is part of a
     votor cert, then we should keep it in the rotor because the
     merkle root is verified and we definitely want to continue
     repairing it; it is getting evicted only because fec_resolver is
     under pressure. */

  fec->data_idxs = 0U;
  fd_memset( &fec->metrics, 0, sizeof(fec->metrics) );
  uint fec_idx = (uint)fd_fec_pool_idx( rotor->fec_pool, fec );

  /* find slots that have this FEC root */
  for( ulong _i=block_iter_init( rotor, slot ); _i!=ULONG_MAX; _i=block_iter_next( rotor, _i ) ) {
    fd_rotor_blk_t * block = block_iter_ele( rotor, _i );
    if( FD_UNLIKELY( fd_rotor_block_fecs( rotor, block )[ k ]!=fec_idx ) ) continue;

    /* rederive buffered_idx */
    if( FD_UNLIKELY( block->buffered_idx!=UINT_MAX && block->buffered_idx>=fec_set_idx ) ) {
      block->buffered_idx = fec_set_idx - 1U;
    }
  }
}

fd_rotor_blk_t *
fd_rotor_verified_parent_fec_count( fd_rotor_t * rotor,
                                    ulong        slot,
                                    fd_hash_t *  block_id,
                                    uint         fec_set_cnt,
                                    ulong        parent_slot,
                                    fd_hash_t *  parent_block_id,
                                    long         rx_ts ) {
  fd_rotor_blk_t * block = fd_rotor_slot_version_query( rotor, slot, block_id );
  if( FD_UNLIKELY( !block ) ) FD_LOG_CRIT(( "block not found for slot %lu", slot ));

  FD_TEST( fec_set_cnt>0U && fec_set_cnt<=rotor->fec_blk_max );
  block->complete_idx    = ( fec_set_cnt*FD_FEC_SHRED_CNT ) - 1;
  block->parent_slot     = parent_slot;
  block->parent_block_id = *parent_block_id;

  if( FD_LIKELY( !block->metrics.first_meta_ts ) ) block->metrics.first_meta_ts = rx_ts;

  fd_rotor_blk_t * parent_block = fd_rotor_slot_version_query( rotor, parent_slot, parent_block_id );
  if( FD_UNLIKELY( !parent_block ) ) {
    if( FD_UNLIKELY( parent_slot<=rotor->root ) ) {
      /* Names a parent that is a dead fork. */
      return NULL;
    }
    parent_block = acquire_block( rotor, parent_slot );
    parent_block->block_id = *parent_block_id;

    for( ulong i=block_iter_init( rotor, parent_slot ); i!=ULONG_MAX; i=block_iter_next( rotor, i ) ) {
      fd_rotor_blk_t * block = block_iter_ele( rotor, i );
      if( FD_LIKELY( !block->turbine || block->abandoned ) ) continue;
      rotor_invalidate( block, rx_ts, ABANDON_REASON_VOTOR_BLOCK_ID_PARENT );
    }
  }

  /* parent now identified, connect this block if the parent is. */
  if( FD_UNLIKELY( parent_block->connected ) ) block->connected = 1;
  return parent_block;
}

fd_rotor_blk_t *
fd_rotor_verified_hash_insert( fd_rotor_t * rotor,
                               ulong        slot,
                               fd_hash_t *  block_id,
                               uint         fec_set_idx,
                               uchar const  mr_prefix[ static FD_SHRED_MERKLE_NODE_SZ ],
                               long         rx_ts ) {
  fd_rotor_blk_t * block = fd_rotor_slot_version_query( rotor, slot, block_id );
  if( FD_UNLIKELY( !block ) ) FD_LOG_CRIT(( "block not found for slot %lu - verify this is a CRIT", slot ));

  /* Stamp before the early return: a verified answer for an already
     known FEC set still counts as metadata received. */
  if( FD_LIKELY( !block->metrics.first_meta_ts ) ) block->metrics.first_meta_ts = rx_ts;

  /* Already have this version's FEC entry -> nothing to fetch. */
  if( FD_UNLIKELY( block_fec( rotor, block, fec_set_idx ) ) ) return NULL;

  fd_hash_t mr = {0};
  memcpy( mr.uc, mr_prefix, FD_SHRED_MERKLE_NODE_SZ );

  /* The same root may have already started progress through repairing
     another slot version.  If so, create this version's entry
     already-complete and replay the completion through
     fd_rotor_fec_complete.  Otherwise create an incomplete entry that
     is awaiting shreds. */
  fd_rotor_fec_t * shared          = fd_fec_map_ele_query( rotor->fec_map, &mr, NULL, rotor->fec_pool );
  int              shared_complete = shared && shared->complete;

  fd_rotor_fec_t * fec = fec_join( rotor, slot, fec_set_idx, block, &mr );
  if( FD_UNLIKELY( fec_set_idx==block->complete_idx - ( FD_FEC_SHRED_CNT-1 ) ) ) {
    fec->slot_complete = 1;
  }

  fd_rotor_blk_t * created = NULL;
  if( FD_LIKELY( shared_complete ) ) {
    /* Replay with the full root the shared FEC already holds, never the
       prefix */
    fd_hash_t shared_mr = shared->merkle_root;
    created = fd_rotor_fec_complete( rotor, slot, fec_set_idx, shared->slot_complete, shared->data_complete, shared->is_leader, shared->metrics.first_shred_ts, &shared_mr, NULL, NULL );
  }
  rotor_advance( rotor, block );
  return created;
}

fd_rotor_blk_t *
fd_rotor_verified_block_insert( fd_rotor_t * rotor,
                                ulong        slot,
                                fd_hash_t    block_id,
                                long         now ) {
  FD_TEST( slot>rotor->root );

  if( FD_LIKELY( fd_rotor_slot_version_query( rotor, slot, &block_id ) ) ) return NULL;

  fd_rotor_blk_t * block = acquire_block( rotor, slot );
  block->block_id = block_id;

  fd_rotor_blk_t * turbine = fd_rotor_turbine_block_query( rotor, slot );
  if( FD_UNLIKELY( turbine && fd_hash_check_zero( &turbine->block_id ) ) ) {
    /* Turbine block is not yet complete, but votor repair events for
       this slot have already started arriving, suggesting we are way
       behind on repairing this slot.  At this point just abandon the
       turbine version and only deliver votor verified versions. */
    rotor_invalidate( turbine, now, ABANDON_REASON_VOTOR_BLOCK_ID_EVENT );
  }
  return block;
}

void
fd_rotor_invalidate( fd_rotor_t * rotor,
                     ulong        slot,
                     long         rx_ts,
                     int          reason ) {
  fd_rotor_blk_t * turbine = turbine_block_insert( rotor, slot );
  rotor_invalidate( turbine, rx_ts, reason );
}

void
fd_rotor_publish( fd_rotor_t *      rotor,
                  ulong             new_root,
                  fd_hash_t const * new_root_block_id,
                  fd_store_t *      store ) {
  fd_store_map_t store_map[1];
  if( store ) FD_TEST( fd_store_map_ljoin( store, store_map ) );

  fd_block_map_t * block_map  = rotor->block_map;
  fd_rotor_blk_t * block_pool = rotor->block_pool;
  fd_rotor_fec_t * fec_pool   = rotor->fec_pool;
  fd_fec_map_t   * fec_map    = rotor->fec_map;

  out_ele_t * out_queue = rotor->out_queue;
  if( FD_UNLIKELY( !out_queue_empty( out_queue ) ) ) FD_LOG_CRIT(( "rotor out_queue not empty before publish" ));

  ulong root = rotor->root;
  if( FD_UNLIKELY( root==ULONG_MAX ) ) return;
  FD_TEST( root<new_root );
  FD_TEST( fd_rotor_slot_query( rotor, new_root ) );

  /* Identify the canonical (rooted) version of new_root.  Every other
     version of it is an equivocating sibling that is now dead.  If no
     version matches, keep them all rather than guess wrong and prune
     the version we are actually rooted on.  TODO: block_id is now
     always wired through from replay, so this could be a CRIT. */
  fd_rotor_blk_t * canonical = new_root_block_id ? fd_rotor_slot_version_query( rotor, new_root, new_root_block_id ) : NULL;
  if( FD_UNLIKELY( !canonical ) ) {
    FD_LOG_DEBUG(( "rotor publish %lu: no version matches the rooted block_id; keeping all versions", new_root ));
  }

  /* Prune every version of every slot in [root, new_root]: release the
     FECs it owns, drop it from the worklists, and free it.  Only the
     canonical version of new_root survives (all of them if canonical is
     unknown) and its FEC list is cleared, since a rooted slot's FEC
     data is never needed again. */
  for( ulong slot=root; slot<=new_root; slot++ ) {
    /* All siblings must report before releasing their shared FECs. */
    if( FD_UNLIKELY( rotor->block_event_fn ) ) {
      for( ulong i=block_iter_init( rotor, slot ); i!=ULONG_MAX; i=block_iter_next( rotor, i ) ) {
        fd_rotor_blk_t * s = block_iter_ele( rotor, i );
        if( FD_UNLIKELY( s->abandoned || s->complete_idx==UINT_MAX || s->buffered_idx!=s->complete_idx ) )
          rotor->block_event_fn( rotor->block_event_ctx, s );
      }
    }
    for( ulong i=block_iter_init( rotor, slot ); i!=ULONG_MAX; ) {
      fd_rotor_blk_t * s    = block_iter_ele ( rotor, i );
      ulong            next = block_iter_next( rotor, i );

      for( uint k=0U; k<rotor->fec_blk_max; k++ ) {
        fd_rotor_fec_t * fec = block_fec( rotor, s, k * FD_FEC_SHRED_CNT );
        /* FEC pool eles can be shared across versions of an equivocating
           slot, so check the map to avoid double-freeing one a sibling
           already released. */
        if( FD_UNLIKELY( fec && fd_fec_map_ele_query_const( fec_map, &fec->merkle_root, NULL, fec_pool ) ) ) {
          if( FD_LIKELY( store && fec->complete ) ) fd_store_remove( store, store_map, &fec->merkle_root ); /* only complete FECs are in the store */
          fd_fec_map_ele_remove_fast( fec_map, fec, fec_pool );
          fd_fec_pool_ele_release( fec_pool, fec );
        }
      }
      fd_memset( fd_rotor_block_fecs( rotor, s ), 0xff, rotor->fec_blk_max*sizeof(uint) );

      int survives = slot==new_root && ( !canonical || s==canonical );
      if( FD_LIKELY( !survives ) ) {
        fd_block_map_ele_remove_fast( block_map, s, block_pool );
        fd_block_pool_ele_release( block_pool, s );
      }
      i = next;
    }
  }

  rotor->root = new_root;

  /* Connect the surviving version(s) of the new root. */
  for( ulong i=block_iter_init( rotor, new_root ); i!=ULONG_MAX; i=block_iter_next( rotor, i ) ) {
    fd_rotor_blk_t * s = block_iter_ele( rotor, i );
    if( FD_UNLIKELY( s->parent_slot==AG_UNKNOWN_SLOT ) ) s->parent_slot = new_root;
    s->connected        = 1;
    s->complete_idx     = 0U;
    s->buffered_idx     = 0U;
    s->delivered_idx    = 0U;
    s->buffered_fec_idx = UINT_MAX; /* rooted slot has no buffered FEC set */
  }

  /* The new root becomes a delivered anchor here WITHOUT going through
     rotor_advance's slot_complete cascade, so children that already
     completed while waiting on it were never connected/delivered.
     Cascade to them now, mirroring rotor_advance's child scan. */
  for( ulong i=block_iter_init( rotor, new_root ); i!=ULONG_MAX; i=block_iter_next( rotor, i ) ) {
    fd_rotor_blk_t * s = block_iter_ele( rotor, i );
    if( FD_UNLIKELY( fd_hash_check_zero( &s->block_id ) ) ) continue;
    for( fd_block_map_iter_t it = fd_block_map_iter_init( block_map, block_pool );
                             !fd_block_map_iter_done( it, block_map, block_pool );
                             it = fd_block_map_iter_next( it, block_map, block_pool ) ) {
      fd_rotor_blk_t * child = fd_block_map_iter_ele( it, block_map, block_pool );
      if( FD_UNLIKELY( fd_hash_eq( &child->parent_block_id, &s->block_id ) ) ) {
        child->connected = 1;
        rotor_advance( rotor, child );
      }
    }
  }
}

void
fd_rotor_print( fd_rotor_t * rotor ) {
  if( FD_UNLIKELY( rotor->root==ULONG_MAX ) ) return;

  fd_rotor_blk_t * block_pool = rotor->block_pool;
  fd_block_map_t * block_map  = rotor->block_map;

  printf( "\n[Rotor] root: %lu, highest repaired: %lu\n", rotor->root, rotor->highest_repaired );

  ulong cnt = 0UL;
  for( fd_block_map_iter_t it = fd_block_map_iter_init( block_map, block_pool );
                           !fd_block_map_iter_done( it, block_map, block_pool );
                           it = fd_block_map_iter_next( it, block_map, block_pool ) ) {
    fd_rotor_blk_t * o = fd_block_map_iter_ele( it, block_map, block_pool );

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
  printf( "(%lu total blocks)\n", cnt );
  fflush( stdout );
}

int
fd_rotor_verify( fd_rotor_t const * rotor ) {
# define FAIL( msg ) do { FD_LOG_WARNING(( "fd_rotor_verify: %s", msg )); return -1; } while(0)

  if( FD_UNLIKELY( !rotor                                                 ) ) FAIL( "NULL rotor" );
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)rotor, fd_rotor_align() ) ) ) FAIL( "misaligned rotor" );
  if( FD_UNLIKELY( !fd_wksp_containing( rotor )                           ) ) FAIL( "rotor must be part of a workspace" );
  if( FD_UNLIKELY( rotor->magic!=FD_ROTOR_MAGIC                           ) ) FAIL( "bad magic" );

  fd_rotor_t * rotor_ = (fd_rotor_t *)rotor;

  fd_rotor_blk_t const * block_pool = rotor_->block_pool;
  fd_block_map_t const * block_map  = rotor_->block_map;
  fd_rotor_fec_t const * fec_pool   = rotor_->fec_pool;
  fd_fec_map_t const   * fec_map    = rotor_->fec_map;

  if( FD_UNLIKELY( fd_block_map_verify( block_map, fd_block_pool_max( block_pool ), block_pool )==-1 ) ) FAIL( "block map corrupted" );
  if( FD_UNLIKELY( fd_fec_map_verify  ( fec_map,   fd_fec_pool_max  ( fec_pool   ), fec_pool   )==-1 ) ) FAIL( "fec map corrupted"   );

  /* The root, if set, must have at least one connected version -- it is
     by definition the start of every ancestry chain.  Uniquely among
     slots, the root need not have a version 0: publish prunes the
     non-canonical versions of the new root, and version 0 may have been
     one of them.  Its FEC list is released along with it, which is fine
     because a rooted slot's FEC data is never needed again. */

  if( FD_LIKELY( rotor->root!=ULONG_MAX ) ) {
    int   root_present   = 0;
    int   root_connected = 0;
    ulong root           = rotor->root;
    for( ulong i = fd_block_map_idx_query_const( block_map, &root, ULONG_MAX, block_pool );
               i != ULONG_MAX;
               i = fd_block_map_idx_next_const( i, ULONG_MAX, block_pool ) ) {
      fd_rotor_blk_t const * root_block = fd_block_pool_ele_const( block_pool, i );
      root_present    = 1;
      root_connected |= !!root_block->connected;
    }
    if( FD_UNLIKELY( !root_present   ) ) FAIL( "root has no block" );
    if( FD_UNLIKELY( !root_connected ) ) FAIL( "no root block is connected" );
  }

  for( fd_block_map_iter_t it = fd_block_map_iter_init( block_map, block_pool );
                           !fd_block_map_iter_done( it, block_map, block_pool );
                           it = fd_block_map_iter_next( it, block_map, block_pool ) ) {
    fd_rotor_blk_t const * block = fd_block_map_iter_ele_const( it, block_map, block_pool );

    ulong slot = block->slot;

    /* Nothing below the root may survive a publish. */

    if( FD_UNLIKELY( rotor->root!=ULONG_MAX && slot<rotor->root ) ) FAIL( "block below the root" );

    /* Shred index bookkeeping */

    if( FD_UNLIKELY( block->complete_idx!=UINT_MAX && block->buffered_idx !=UINT_MAX &&
                     block->buffered_idx >block->complete_idx ) ) FAIL( "buffered_idx > complete_idx" );
    if( FD_UNLIKELY( block->complete_idx!=UINT_MAX && block->delivered_idx!=UINT_MAX &&
                     block->delivered_idx>block->complete_idx ) ) FAIL( "delivered_idx > complete_idx" );

    /* buffered_fec_idx is the last shred idx of a FEC set, so it is
       always one below a multiple of FD_FEC_SHRED_CNT (UINT_MAX, the
       "none" sentinel, satisfies this too). */

    if( FD_UNLIKELY( ( block->buffered_fec_idx + 1U ) % FD_FEC_SHRED_CNT ) ) FAIL( "buffered_fec_idx is not the last idx of a FEC set" );

    /* A buffered FEC set means all of its shreds are in hand, so the
       contiguous FEC prefix can never run ahead of the contiguous shred
       prefix. */

    if( FD_UNLIKELY( block->buffered_fec_idx!=UINT_MAX &&
                     ( block->buffered_idx==UINT_MAX ||
                       block->buffered_idx<block->buffered_fec_idx ) ) ) FAIL( "buffered_fec_idx runs ahead of buffered_idx" );

    /* An abandoned version is always a turbine version and never on a
       worklist. */

    if( FD_UNLIKELY( block->abandoned && !block->turbine ) ) FAIL( "abandoned non-turbine block" );
  }

  for( fd_fec_map_iter_t it = fd_fec_map_iter_init( fec_map, fec_pool );
                             !fd_fec_map_iter_done( it, fec_map, fec_pool );
                         it = fd_fec_map_iter_next( it, fec_map, fec_pool ) ) {
    fd_rotor_fec_t const * fec = fd_fec_map_iter_ele_const( it, fec_map, fec_pool );

    ulong slot        = fec->slot;
    uint  fec_set_idx = fec->fec_set_idx;
    uint  fec_idx     = (uint)fd_fec_pool_idx( fec_pool, fec );

    if( FD_UNLIKELY( fec_set_idx % FD_FEC_SHRED_CNT                            ) ) FAIL( "fec_set_idx is not a multiple of FD_FEC_SHRED_CNT" );
    if( FD_UNLIKELY( fec_set_idx / FD_FEC_SHRED_CNT >= rotor->fec_blk_max    ) ) FAIL( "fec_set_idx out of range" );

    if( FD_UNLIKELY( rotor->root!=ULONG_MAX && slot<rotor->root ) ) FAIL( "fec below the root" );

    /* A slot with a FEC must have at least one version to anchor the list
       and own the FEC -- without one publish could never reach it. */

    if( FD_UNLIKELY( !fd_rotor_slot_query( rotor_, slot ) ) ) FAIL( "slot has a fec but no version to anchor the list" );

    /* A FEC is owned by every version whose fec_tbl row points at it,
       and at least one must -- otherwise it is unreachable garbage that
       publish would leak. */

    int owned = 0;
    for( ulong i = fd_block_map_idx_query_const( block_map, &slot, ULONG_MAX, block_pool );
               i != ULONG_MAX;
               i = fd_block_map_idx_next_const( i, ULONG_MAX, block_pool ) ) {
      fd_rotor_blk_t const * block = fd_block_pool_ele_const( block_pool, i );
      if( FD_LIKELY( fd_rotor_block_fecs( rotor, block )[ fec_set_idx / FD_FEC_SHRED_CNT ]==fec_idx ) ) owned = 1;
    }
    if( FD_UNLIKELY( !owned ) ) FAIL( "fec claimed by no version" );
  }

  return 0;
}
#undef FAIL
