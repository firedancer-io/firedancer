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

  ulong blk_max       = ele_max * FD_CHAINER_SLOT_VER_MAX;
  ulong fec_blk_max   = max_shreds_per_block / FD_FEC_SHRED_CNT;
  ulong fec_max       = blk_max * fec_blk_max;
  ulong fec_chain_cnt = fd_fec_map_chain_cnt_est( fec_max );
  ulong blk_chain_cnt = fd_block_map_chain_cnt_est( blk_max );

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  chainer             = FD_SCRATCH_ALLOC_APPEND( l, fd_chainer_align(),    sizeof(fd_chainer_t)                     );
  void * fec_pool   = FD_SCRATCH_ALLOC_APPEND( l, fd_fec_pool_align(),   fd_fec_pool_footprint  ( fec_max       ) );
  void * fec_map    = FD_SCRATCH_ALLOC_APPEND( l, fd_fec_map_align(),    fd_fec_map_footprint   ( fec_chain_cnt ) );
  void * block_pool = FD_SCRATCH_ALLOC_APPEND( l, fd_block_pool_align(), fd_block_pool_footprint( blk_max       ) );
  void * fec_tbl    = FD_SCRATCH_ALLOC_APPEND( l, alignof(uint),         fec_max*sizeof(uint)                     );
  void * block_map  = FD_SCRATCH_ALLOC_APPEND( l, fd_block_map_align(),  fd_block_map_footprint ( blk_chain_cnt ) );
  void * bfs        = FD_SCRATCH_ALLOC_APPEND( l, bfs_align(),           bfs_footprint          ( blk_max       ) );
  void * out_queue  = FD_SCRATCH_ALLOC_APPEND( l, out_queue_align(),     out_queue_footprint    ( fec_max       ) );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, fd_chainer_align() ) == (ulong)shmem + footprint );

  chainer->root             = ULONG_MAX;
  chainer->highest_repaired = 0UL;
  chainer->wksp_gaddr       = fd_wksp_gaddr_fast( wksp, chainer );
  chainer->fec_pool         = fd_fec_pool_join  ( fd_fec_pool_new  ( fec_pool,     fec_max             ) );
  chainer->fec_map          = fd_fec_map_join   ( fd_fec_map_new   ( fec_map,      fec_chain_cnt, seed ) );
  chainer->block_pool       = fd_block_pool_join( fd_block_pool_new( block_pool,   blk_max             ) );
  chainer->block_map        = fd_block_map_join ( fd_block_map_new ( block_map,    blk_chain_cnt, seed ) );
  chainer->bfs              = bfs_join          ( bfs_new          ( bfs,          blk_max             ) );
  chainer->out_queue        = out_queue_join    ( out_queue_new    ( out_queue,    fec_max             ) );
  chainer->fec_tbl          = fec_tbl;
  chainer->fec_blk_max      = fec_blk_max;

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

/* acquire_block allocates, initializes, and map-inserts a fresh version
   of slot with block_id (NULL for the turbine version, whose block_id
   is all-zero until the block is whole). */

static fd_chainer_block_t *
acquire_block( fd_chainer_t * chainer, ulong slot, fd_hash_t const * block_id ) {
  fd_block_map_t     * block_map  = chainer->block_map;
  fd_chainer_block_t * block_pool = chainer->block_pool;
  FD_TEST( fd_block_pool_free( block_pool ) );

  ulong block_cnt = 0UL;
  for( ulong i=fd_chainer_block_iter_init( chainer, slot ); i!=ULONG_MAX; i=fd_chainer_block_iter_next( chainer, i ) ) {
    block_cnt++;
  }
  if( FD_UNLIKELY( block_cnt>=FD_CHAINER_SLOT_VER_MAX ) ) FD_LOG_CRIT(( "slots stored exceeds protocol limits, %lu versions of slot %lu already stored", block_cnt, slot ));

  fd_chainer_block_t * block = fd_block_pool_ele_acquire( block_pool );
  block->slot              = slot;
  block->turbine           = 0;
  block->parent_slot       = AG_UNKNOWN_SLOT;
  block->parent_slot_batch = UINT_MAX;
  block->complete_idx      = UINT_MAX;
  block->buffered_idx      = UINT_MAX;
  block->buffered_fec_idx  = UINT_MAX;
  block->delivered_idx     = UINT_MAX;
  block->connected         = 0;
  block->complete_ts       = 0L;

  if( FD_LIKELY( block_id ) ) block->block_id = *block_id;
  else                        fd_memset( &block->block_id, 0, sizeof(fd_hash_t) );
  fd_memset( &block->parent_block_id, 0, sizeof(fd_hash_t) );
  fd_memset( fd_chainer_block_fecs( chainer, block ), 0xff, chainer->fec_blk_max*sizeof(uint) ); /* UINT_MAX pool_idx sentinel */

  fd_block_map_ele_insert( block_map, block, block_pool );
  return block;
}

void
fd_chainer_init( fd_chainer_t *    chainer,
                 ulong             slot,
                 fd_hash_t const * block_id ) {
  fd_chainer_block_t * block = acquire_block( chainer, slot, block_id );
  block->parent_slot       = slot;
  block->complete_idx      = 0;
  block->buffered_idx      = 0;
  block->connected         = 1;
  block->delivered_idx     = 0; /* must equal complete_idx at init */
  block->buffered_fec_idx  = UINT_MAX; /* no complete FEC set buffered; must
                                          be one-below a FD_FEC_SHRED_CNT
                                          multiple, which UINT_MAX satisfies */
  chainer->root             = slot;
  chainer->highest_repaired = slot;
}

/* block_fec returns the FEC that block owns at fec_set_idx, or NULL if
   it holds none there (or fec_set_idx is beyond max_shreds_per_block). */

static fd_chainer_fec_t *
block_fec( fd_chainer_t const * chainer, fd_chainer_block_t const * block, uint fec_set_idx ) {
  ulong k = fec_set_idx / FD_FEC_SHRED_CNT;
  if( FD_UNLIKELY( k>=chainer->fec_blk_max ) ) return NULL;
  uint idx = fd_chainer_block_fecs( chainer, block )[ k ];
  if( FD_UNLIKELY( idx==UINT_MAX ) ) return NULL;
  return fd_fec_pool_ele( chainer->fec_pool, (ulong)idx );
}

fd_chainer_fec_t *
fd_chainer_fec_query( fd_chainer_t const * chainer,
                      ulong                slot,
                      uint                 fec_set_idx,
                      fd_hash_t const *    block_id ) {
  fd_chainer_block_t * block = fd_chainer_block_query( chainer, slot, block_id );
  if( FD_UNLIKELY( !block ) ) return NULL;
  return block_fec( chainer, block, fec_set_idx );
}

/* fec_query returns the FEC whose merkle_root matches mr, or NULL. */

static fd_chainer_fec_t *
fec_query( fd_chainer_t * chainer, fd_hash_t const * mr ) {
  fd_fec_map_t     * fec_map  = chainer->fec_map;
  fd_chainer_fec_t * fec_pool = chainer->fec_pool;
  return fd_fec_map_ele_query( fec_map, mr, NULL, fec_pool );
}

/* fec_join records that block includes the FEC at (slot, fec_set_idx)
   with root mr, creating the entry if this root has not been seen yet. */

static fd_chainer_fec_t *
fec_join( fd_chainer_t *       chainer,
          ulong                slot,
          uint                 fec_set_idx,
          fd_chainer_block_t * block,
          fd_hash_t const *    mr ) {
  if( FD_UNLIKELY( slot>(ulong)UINT_MAX ) ) FD_LOG_CRIT(( "slot %lu exceeds uint range", slot ));
  ulong k = fec_set_idx / FD_FEC_SHRED_CNT;
  FD_TEST( k<chainer->fec_blk_max );

  fd_fec_map_t     * fec_map  = chainer->fec_map;
  fd_chainer_fec_t * fec_pool = chainer->fec_pool;
  fd_chainer_fec_t * fec      = fd_fec_map_ele_query( fec_map, mr, NULL, fec_pool );
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
    fd_fec_map_ele_insert( fec_map, fec, fec_pool );
  }
  fd_chainer_block_fecs( chainer, block )[ k ] = (uint)fd_fec_pool_idx( fec_pool, fec );
  return fec;
}

int
fd_chainer_shred_test( fd_chainer_t const *       chainer,
                       fd_chainer_block_t const * block,
                       uint                       shred_idx ) {
  fd_chainer_fec_t * fec = block_fec( chainer, block, shred_idx & ~( (uint)FD_FEC_SHRED_CNT - 1U ) );
  if( FD_UNLIKELY( !fec ) ) return 0;
  return !!( fec->data_idxs & ( 1U << ( shred_idx & ( (uint)FD_FEC_SHRED_CNT - 1U ) ) ) );
}

/* finalize_block_id computes the block's double-merkle block_id and
   writes it to block->block_id.  Returns 1 on success, 0 on failure. */

static int
finalize_block_id( fd_chainer_t * chainer, fd_chainer_block_t * block ) {
  if( FD_UNLIKELY( block->complete_idx==UINT_MAX ) )                 return 0;
  if( FD_UNLIKELY( block->parent_slot==AG_UNKNOWN_SLOT ) )           return 0;
  if( FD_UNLIKELY( fd_hash_check_zero( &block->parent_block_id ) ) ) return 0;

  uint fec_set_cnt = ( block->complete_idx + 1U ) / FD_FEC_SHRED_CNT;
  uchar tree_mem[ FD_BMTREE_COMMIT_FOOTPRINT( 0UL ) ] __attribute__((aligned(FD_BMTREE_COMMIT_ALIGN)));
  fd_bmtree_commit_t * tree = fd_bmtree_commit_init( tree_mem, 20UL, FD_BMTREE_LONG_PREFIX_SZ, 0UL );

  for( uint i=0U; i<fec_set_cnt; i++ ) {
    fd_chainer_fec_t * fec = block_fec( chainer, block, i*FD_FEC_SHRED_CNT );
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
fec_rekey( fd_chainer_t *        chainer,
           fd_chainer_fec_t *    sentinel,
           fd_hash_t const *     full_mr );

fd_chainer_block_t *
fd_chainer_shred_insert( fd_chainer_t *        chainer,
                         ulong                 slot,
                         uint                  shred_idx,
                         int                   slot_complete,
                         fd_hash_t const *     mr,
                         ulong                 parent_slot,
                         fd_hash_t const *     parent_block_id ) {
  FD_TEST( slot>chainer->root );
  uint  fec_set_idx = shred_idx & ~( (uint)FD_FEC_SHRED_CNT - 1U );
  ulong k           = fec_set_idx / FD_FEC_SHRED_CNT;
  uint  shred_max   = (uint)( chainer->fec_blk_max*FD_FEC_SHRED_CNT );
  FD_TEST( k<chainer->fec_blk_max ); /* guaranteed by fec_resolver */

  /* find or create the turbine block.  This happens before the rekey
     below so the nested shred_inserts a rekey can replay never create
     anything: this call is the only one that can. */

  fd_chainer_block_t * created = NULL;
  fd_chainer_block_t * turbine = fd_chainer_turbine_block_query( chainer, slot );
  if( FD_UNLIKELY( !turbine ) ) {
    turbine = acquire_block( chainer, slot, NULL );
    turbine->turbine = 1;
    created = turbine;
  }


  /* rekey 20-byte prefix sentinel if it exists */

  fd_hash_t prefix = {0};
  memcpy( prefix.uc, mr->uc, FD_SHRED_MERKLE_NODE_SZ );
  if( FD_LIKELY( !fd_hash_eq( &prefix, mr ) ) ) {
    fd_chainer_fec_t * sentinel = fec_query( chainer, &prefix );
    if( FD_UNLIKELY( sentinel && sentinel->slot==(uint)slot && sentinel->fec_set_idx==fec_set_idx ) ) {
      fec_rekey( chainer, sentinel, mr );
    }
  }

  /* Find or create the FEC for this shred's root

     If the turbine version holds no root at this position it adopts
     this one, whether it is newly seen FEC or an entry a getFecRoot
     sentinel already created.  If turbine already holds a *different*
     root here and nothing authorized this one, the shred is an
     unauthorized equivocation and is dropped. */

  fd_chainer_fec_t * fec         = fec_query( chainer, mr );
  fd_chainer_fec_t * turbine_fec = block_fec( chainer, turbine, fec_set_idx );
  if( FD_LIKELY( !turbine_fec ) ) {
    fec = fec_join( chainer, slot, fec_set_idx, turbine, mr );
  } else if( FD_UNLIKELY( !fec ) ) {
    return created; /* shred dropped, but the block it made is real */
  }

  fec->data_idxs |= 1U << ( shred_idx - fec_set_idx );
  if( FD_UNLIKELY( slot_complete ) ) fec->slot_complete = 1;

  /* Update every version that owns this FEC root at this position. */

  uint fec_idx = (uint)fd_fec_pool_idx( chainer->fec_pool, fec );
  for( ulong i =fd_chainer_block_iter_init( chainer, slot );
             i!=ULONG_MAX;
             i =fd_chainer_block_iter_next( chainer, i ) ) {

    fd_chainer_block_t * block = fd_chainer_block_iter_ele( chainer, i );
    if( FD_UNLIKELY( fd_chainer_block_fecs( chainer, block )[ k ]!=fec_idx ) ) continue;

    /* update slot-level shred indexing */
    if( FD_UNLIKELY( slot_complete ) ) block->complete_idx = shred_idx;
    while( block->buffered_idx + 1 < shred_max && fd_chainer_shred_test( chainer, block, block->buffered_idx + 1U ) ) {
      block->buffered_idx++;
    }

    /* If equivocating, buffered_idx needs to be clamped to complete_idx */
    if( FD_UNLIKELY( block->buffered_idx != UINT_MAX && block->complete_idx != UINT_MAX && block->buffered_idx > block->complete_idx ) )
      block->buffered_idx = block->complete_idx;

    if( FD_UNLIKELY( parent_slot!=AG_UNKNOWN_SLOT && ( block->parent_slot_batch==UINT_MAX || shred_idx>block->parent_slot_batch ) ) ) {
      FD_TEST( parent_block_id ); /* TODO handholding check */

      block->parent_slot       = parent_slot;
      block->parent_slot_batch = shred_idx;
      block->parent_block_id   = *parent_block_id;

      fd_chainer_block_t * parent = fd_chainer_block_query( chainer, parent_slot, parent_block_id );
      if( FD_LIKELY( parent && parent->connected ) ) block->connected = 1;
    }
  }
  return created;
}

/* chainer_deliver queues a delivered FEC for publish to replay.  The
   rotor tile drains the out_queue in after_credit. */

static void
chainer_deliver( fd_chainer_t *       chainer,
                 fd_chainer_block_t * block,
                 fd_chainer_fec_t *   fec ) {
  out_ele_t * out_queue = chainer->out_queue;
  if( FD_UNLIKELY( out_queue_full( out_queue ) ) ) FD_LOG_CRIT(( "chainer out_queue full" ));
  out_queue_push_tail( out_queue, (out_ele_t){ .block_idx = (uint)fd_block_pool_idx( chainer->block_pool, block ),
                                               .fec_idx   = (uint)fd_fec_pool_idx  ( chainer->fec_pool,   fec   ) } );
}

/* chainer_advance delivers as many contiguous completed FEC sets as
   possible from `root` block, then cascades: when an block's
   slot_complete FEC is delivered, every child block (parent_block_id ==
   this block's block_id) becomes connected and is drained in turn. */

static void
chainer_advance( fd_chainer_t * chainer, fd_chainer_block_t * root ) {
  fd_block_map_t     * block_map  = chainer->block_map;
  fd_chainer_block_t * block_pool = chainer->block_pool;
  ulong              * bfs        = chainer->bfs;

  bfs_push_tail( bfs, fd_block_pool_idx( block_pool, root ) );

  while( FD_LIKELY( !bfs_empty( bfs ) ) ) {
    fd_chainer_block_t * block = fd_block_pool_ele( block_pool, bfs_pop_head( bfs ) );
    if( FD_UNLIKELY( !block->connected ) ) continue;

    fd_chainer_block_t * parent = fd_chainer_block_query( chainer, block->parent_slot, &block->parent_block_id );
    if( FD_UNLIKELY( !parent || parent->complete_idx==UINT_MAX || parent->delivered_idx!=parent->complete_idx ) ) continue;

    for(;;) {
      uint next = block->delivered_idx==UINT_MAX ? 0U
                                                 : block->delivered_idx + 1;
      fd_chainer_fec_t * fec = block_fec( chainer, block, next );
      if( FD_LIKELY( !fec || !fec->complete ) ) break; /* next FEC not completed yet */

      chainer_deliver( chainer, block, fec );
      block->delivered_idx = next + (FD_FEC_SHRED_CNT - 1);

      if( FD_UNLIKELY( fec->slot_complete ) ) {
        chainer->highest_repaired = fd_ulong_max( chainer->highest_repaired, block->slot );
        FD_TEST( !fd_hash_check_zero( &block->block_id ) );

        /* Scan for children. TODO could index children by
           parent_block_id; O(n) scan for now. */
        for( fd_block_map_iter_t it = fd_block_map_iter_init( block_map, block_pool );
                                     !fd_block_map_iter_done( it, block_map, block_pool );
                                 it = fd_block_map_iter_next( it, block_map, block_pool ) ) {
          fd_chainer_block_t * child = fd_block_map_iter_ele( it, block_map, block_pool );
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

fd_chainer_block_t *
fd_chainer_fec_complete( fd_chainer_t *        chainer,
                         ulong                 slot,
                         uint                  fec_set_idx_,
                         int                   slot_complete,
                         int                   data_complete,
                         int                   is_leader,
                         fd_hash_t *           mr,
                         int *                 opt_rejected ) {
  FD_TEST( slot>chainer->root );
  uint  fec_set_idx = (uint)fec_set_idx_;
  ulong k           = fec_set_idx / FD_FEC_SHRED_CNT;
  FD_TEST( k<chainer->fec_blk_max ); /* guaranteed by fec_resolver */

  if( opt_rejected ) *opt_rejected = 0;

  fd_chainer_block_t * created = NULL;
  for( uint i=0U; i<FD_FEC_SHRED_CNT; i++ ) {
    fd_chainer_block_t * c = fd_chainer_shred_insert( chainer, slot, fec_set_idx_ + i, slot_complete && ( i==FD_FEC_SHRED_CNT-1 ), mr, AG_UNKNOWN_SLOT, NULL );
    if( FD_UNLIKELY( c ) ) created = c; /* only the first insert can create */
  }

  /* By the time we get here the FEC exists unless turbine refused an
     unauthorized equivocating root -- in which case it was dropped and
     there is nothing to complete. */

  fd_chainer_fec_t * fec = fec_query( chainer, mr );
  if( FD_UNLIKELY( !fec ) ) {
    if( opt_rejected ) *opt_rejected = 1;
    return created;
  }

  fec->complete = 1;
  if( FD_UNLIKELY( slot_complete ) ) fec->slot_complete = 1;
  if( FD_UNLIKELY( data_complete ) ) fec->data_complete = 1;
  if( FD_UNLIKELY( is_leader ) )     fec->is_leader     = 1;

  uint fec_idx = (uint)fd_fec_pool_idx( chainer->fec_pool, fec );

  for( ulong i =fd_chainer_block_iter_init( chainer, slot );
             i!=ULONG_MAX;
             i =fd_chainer_block_iter_next( chainer, i ) ) {
    fd_chainer_block_t * block = fd_chainer_block_iter_ele( chainer, i );

    if( FD_UNLIKELY( fd_chainer_block_fecs( chainer, block )[ k ]!=fec_idx ) ) continue;

    for(;;) {
      fd_chainer_fec_t * next = block_fec( chainer, block, block->buffered_fec_idx + 1U );
      if( !next || !next->complete ) break;
      block->buffered_fec_idx += FD_FEC_SHRED_CNT;
    }

    /* clamp buffered_fec_idx to complete_idx always. should never happen for non-turbine versions */
    if( FD_UNLIKELY( block->complete_idx!=UINT_MAX && block->buffered_fec_idx!=UINT_MAX &&
                     block->buffered_fec_idx>block->complete_idx ) ) block->buffered_fec_idx = block->complete_idx;

    if( FD_LIKELY( block->turbine ) ) {
      /* slot is complete implies we can record the block_id.  Only the
         turbine version needs its block_id computed. */
      fd_chainer_block_t * turbine = block;
      if( FD_UNLIKELY( turbine->complete_idx!=UINT_MAX &&
                       turbine->buffered_fec_idx==turbine->complete_idx &&
                       fd_hash_check_zero( &turbine->block_id ) ) ) {
        if( FD_UNLIKELY( !finalize_block_id( chainer, turbine ) ) ) FD_LOG_WARNING(( "failed to finalize block_id for slot %lu, parent_slot %lu parent_bid is zero %d", slot, turbine->parent_slot, fd_hash_check_zero( &turbine->parent_block_id ) ));
      }
    }

    /* unfortunate but useful placement */
    if( FD_UNLIKELY( fd_chainer_block_complete( block ) && !block->complete_ts ) ) {
      block->complete_ts = fd_log_wallclock();
      FD_BASE58_ENCODE_32_BYTES( block->block_id.uc, out );
      FD_LOG_INFO(( "slot is complete %lu block_id %s", slot, out ));
    }

    chainer_advance( chainer, block );
  }
  return created;
}

void
fd_chainer_fec_evicted( fd_chainer_t * chainer,
                        ulong          slot,
                        uint           fec_set_idx,
                        fd_hash_t *    merkle_root ) {
  fd_chainer_fec_t * fec = fec_query( chainer, merkle_root );
  if( FD_UNLIKELY( !fec ) ) return;
  ulong k = fec_set_idx / FD_FEC_SHRED_CNT;
  FD_TEST( k<chainer->fec_blk_max ); /* guaranteed by fec_resolver */

  /* The reason we choose not to remove the FEC from the chainer is
     because if this FEC belongs to a turbine slot and we are having
     trouble completing it (the leader gave up on disseminating the
     shreds), then eventually this slot will get skipped or we will
     repair a different version through a votor repair block id event.
     If this FEC is part of a votor cert, then we should keep it in the
     chainer because the merkle root is verified and we definitely want
     to continue repairing it; it is getting evicted only because
     fec_resolver is under pressure. */

  fec->data_idxs = 0U;
  uint fec_idx = (uint)fd_fec_pool_idx( chainer->fec_pool, fec );

  /* find slots that have this FEC root */
  for( ulong _i=fd_chainer_block_iter_init( chainer, slot ); _i!=ULONG_MAX; _i=fd_chainer_block_iter_next( chainer, _i ) ) {
    fd_chainer_block_t * block = fd_chainer_block_iter_ele( chainer, _i );
    if( FD_UNLIKELY( fd_chainer_block_fecs( chainer, block )[ k ]!=fec_idx ) ) continue;

    /* rederive buffered_idx */
    if( FD_UNLIKELY( block->buffered_idx!=UINT_MAX && block->buffered_idx>=fec_set_idx ) ) {
      block->buffered_idx = fec_set_idx - 1U;
    }
  }
}

fd_chainer_block_t *
fd_chainer_verified_parent_fec_count( fd_chainer_t * chainer,
                                      ulong          slot,
                                      fd_hash_t *    block_id,
                                      uint           fec_set_cnt,
                                      ulong          parent_slot,
                                      fd_hash_t *    parent_block_id ) {
  fd_chainer_block_t * created = NULL;
  fd_chainer_block_t * block   = fd_chainer_block_query( chainer, slot, block_id );
  if( FD_UNLIKELY( !block ) ) FD_LOG_CRIT(( "block not found for slot %lu", slot ));
  FD_TEST( fec_set_cnt>0U && fec_set_cnt<=chainer->fec_blk_max );

  block->complete_idx    = ( fec_set_cnt*FD_FEC_SHRED_CNT ) - 1;
  block->parent_slot     = parent_slot;
  block->parent_block_id = *parent_block_id;

  fd_chainer_block_t * parent_block = fd_chainer_block_query( chainer, parent_slot, parent_block_id );
  if( FD_UNLIKELY( !parent_block ) ) {
    parent_block = acquire_block( chainer, parent_slot, parent_block_id );
    created      = parent_block;
  }

  /* connect this block if the parent is. */
  if( FD_UNLIKELY( parent_block->connected ) ) block->connected = 1;
  return created;
}

fd_chainer_block_t *
fd_chainer_verified_hash_insert( fd_chainer_t *        chainer,
                                 ulong                 slot,
                                 fd_hash_t *           block_id,
                                 uint                  fec_set_idx,
                                 fd_hash_t *           mr ) {
  fd_chainer_block_t * block = fd_chainer_block_query( chainer, slot, block_id );
  if( FD_UNLIKELY( !block ) ) FD_LOG_CRIT(( "block not found for slot %lu - verify this is a CRIT", slot ));

  /* Already have this version's FEC entry -> nothing to fetch. */
  if( FD_UNLIKELY( block_fec( chainer, block, fec_set_idx ) ) ) return NULL;

  /* The same root may have already started progress through repairing
     another slot version.  If so, create this version's entry
     already-complete and replay the completion through
     fd_chainer_fec_complete.  Otherwise create an incomplete entry that
     is awaiting shreds. */
  fd_chainer_fec_t * shared          = fec_query( chainer, mr );
  int                shared_complete = shared && shared->complete;

  fd_chainer_fec_t * fec = fec_join( chainer, slot, fec_set_idx, block, mr );
  if( FD_UNLIKELY( fec_set_idx==block->complete_idx - ( FD_FEC_SHRED_CNT-1 ) ) ) {
    fec->slot_complete = 1;
  }
  fd_chainer_block_t * created = NULL;
  if( FD_LIKELY( shared_complete ) ) {
    created = fd_chainer_fec_complete( chainer, slot, fec_set_idx, shared->slot_complete, shared->data_complete, 0, mr, NULL );
  }
  chainer_advance( chainer, block );
  return created;
}

/* fec_rekey re-keys sentinel, a FEC created from a getFecRoot response
   and  keyed by only its zero-padded 20-byte root prefix, to the
   full merkle root full_mr that a shred just delivered.  If a FEC keyed
   by full_mr already exists (e.g. turbine saw the set first), the
   sentinel is merged into it instead: every version pointing at the
   sentinel is repointed and, if the existing FEC is already complete,
   its completion is replayed so those versions deliver it. */

static void
fec_rekey( fd_chainer_t *     chainer,
           fd_chainer_fec_t * sentinel,
           fd_hash_t const *  full_mr ) {
  fd_chainer_fec_t * existing = fec_query( chainer, full_mr );
  if( FD_LIKELY( !existing ) ) {
    fd_fec_map_ele_remove_fast( chainer->fec_map, sentinel, chainer->fec_pool );
    sentinel->merkle_root = *full_mr;
    fd_fec_map_ele_insert( chainer->fec_map, sentinel, chainer->fec_pool );
    return;
  }

  ulong slot         = sentinel->slot;
  uint  fec_set_idx  = sentinel->fec_set_idx;
  uint  k            = fec_set_idx / FD_FEC_SHRED_CNT;
  uint  sentinel_idx = (uint)fd_fec_pool_idx( chainer->fec_pool, sentinel );
  uint  existing_idx = (uint)fd_fec_pool_idx( chainer->fec_pool, existing );

  fd_chainer_block_t * repointed[ FD_CHAINER_SLOT_VER_MAX ];
  ulong                repointed_cnt = 0UL;
  for( ulong i =fd_chainer_block_iter_init( chainer, slot );
             i!=ULONG_MAX;
             i =fd_chainer_block_iter_next( chainer, i ) ) {
    fd_chainer_block_t * block = fd_chainer_block_iter_ele( chainer, i );
    uint               * fecs  = fd_chainer_block_fecs( chainer, block );
    if( FD_LIKELY( fecs[ k ]!=sentinel_idx ) ) continue;
    fecs[ k ] = existing_idx;
    repointed[ repointed_cnt++ ] = block;
  }
  fd_fec_map_ele_remove_fast( chainer->fec_map, sentinel, chainer->fec_pool );
  fd_fec_pool_ele_release   ( chainer->fec_pool, sentinel );

  if( FD_LIKELY( existing->complete ) ) {
    fd_hash_t full = *full_mr;
    fd_chainer_fec_complete( chainer, slot, fec_set_idx, existing->slot_complete, existing->data_complete, 0, &full, NULL ); /* cannot create: the caller's shred_insert already made the turbine block */
  }
  for( ulong i=0UL; i<repointed_cnt; i++ ) {
    chainer_advance( chainer, repointed[ i ] );
  }
}

fd_chainer_block_t *
fd_chainer_verified_block_insert( fd_chainer_t * chainer,
                                  ulong          slot,
                                  fd_hash_t      block_id ) {
  FD_TEST( slot>chainer->root );
  if( FD_UNLIKELY( fd_chainer_block_query( chainer, slot, &block_id ) ) ) return NULL; /* already have it */
  return acquire_block( chainer, slot, &block_id );
}

void
fd_chainer_publish( fd_chainer_t *    chainer,
                    ulong             new_root,
                    fd_hash_t const * new_root_block_id,
                    fd_store_t *      store ) {
  fd_store_map_t store_map[1];
  if( store ) FD_TEST( fd_store_map_ljoin( store, store_map ) );

  fd_block_map_t     * block_map  = chainer->block_map;
  fd_chainer_block_t * block_pool = chainer->block_pool;
  fd_chainer_fec_t   * fec_pool   = chainer->fec_pool;
  fd_fec_map_t       * fec_map    = chainer->fec_map;

  out_ele_t          * out_queue  = chainer->out_queue;
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
  fd_chainer_block_t * canonical = new_root_block_id ? fd_chainer_block_query( chainer, new_root, new_root_block_id ) : NULL;
  if( FD_UNLIKELY( !canonical ) ) {
    FD_LOG_DEBUG(( "chainer publish %lu: no version matches the rooted block_id; keeping all versions", new_root ));
  }

  /* Prune every version of every slot in [root, new_root]: release the
     FECs it owns, drop it from the worklists, and free it.  Only the
     canonical version of new_root survives (all of them if canonical is
     unknown) and its FEC list is cleared, since a rooted slot's FEC
     data is never needed again. */
  for( ulong slot=root; slot<=new_root; slot++ ) {
    for( ulong i=fd_chainer_block_iter_init( chainer, slot ); i!=ULONG_MAX; ) {
      fd_chainer_block_t * s    = fd_chainer_block_iter_ele ( chainer, i );
      ulong                next = fd_chainer_block_iter_next( chainer, i );

      for( uint k=0U; k<chainer->fec_blk_max; k++ ) {
        fd_chainer_fec_t * fec = block_fec( chainer, s, k * FD_FEC_SHRED_CNT );
        /* FEC pool eles can be shared across versions of an equivocating
           slot, so check the map to avoid double-freeing one a sibling
           already released. */
        if( FD_UNLIKELY( fec && fd_fec_map_ele_query_const( fec_map, &fec->merkle_root, NULL, fec_pool ) ) ) {
          if( FD_LIKELY( store && fec->complete ) ) fd_store_remove( store, store_map, &fec->merkle_root ); /* only complete FECs are in the store */
          fd_fec_map_ele_remove_fast( fec_map, fec, fec_pool );
          fd_fec_pool_ele_release( fec_pool, fec );
        }
      }
      fd_memset( fd_chainer_block_fecs( chainer, s ), 0xff, chainer->fec_blk_max*sizeof(uint) );

      int survives = slot==new_root && ( !canonical || s==canonical );
      if( FD_LIKELY( !survives ) ) {
        fd_block_map_ele_remove_fast( block_map, s, block_pool );
        fd_block_pool_ele_release( block_pool, s );
      }
      i = next;
    }
  }

  chainer->root = new_root;

  /* Connect the surviving version(s) of the new root. */
  for( ulong i=fd_chainer_block_iter_init( chainer, new_root ); i!=ULONG_MAX; i=fd_chainer_block_iter_next( chainer, i ) ) {
    fd_chainer_block_t * s = fd_chainer_block_iter_ele( chainer, i );
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
  for( ulong i=fd_chainer_block_iter_init( chainer, new_root ); i!=ULONG_MAX; i=fd_chainer_block_iter_next( chainer, i ) ) {
    fd_chainer_block_t * s = fd_chainer_block_iter_ele( chainer, i );
    if( FD_UNLIKELY( fd_hash_check_zero( &s->block_id ) ) ) continue;
    for( fd_block_map_iter_t it = fd_block_map_iter_init( block_map, block_pool );
                                 !fd_block_map_iter_done( it, block_map, block_pool );
                             it = fd_block_map_iter_next( it, block_map, block_pool ) ) {
      fd_chainer_block_t * child = fd_block_map_iter_ele( it, block_map, block_pool );
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

  fd_chainer_block_t * block_pool = chainer->block_pool;
  fd_block_map_t     * block_map  = chainer->block_map;

  printf( "\n[Chainer] root: %lu, highest repaired: %lu\n", chainer->root, chainer->highest_repaired );

  ulong cnt = 0UL;
  for( fd_block_map_iter_t it = fd_block_map_iter_init( block_map, block_pool );
                               !fd_block_map_iter_done( it, block_map, block_pool );
                           it = fd_block_map_iter_next( it, block_map, block_pool ) ) {
    fd_chainer_block_t * o = fd_block_map_iter_ele( it, block_map, block_pool );

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
fd_chainer_verify( fd_chainer_t const * chainer ) {
# define FAIL( msg ) do { FD_LOG_WARNING(( "fd_chainer_verify: %s", msg )); return -1; } while(0)

  if( FD_UNLIKELY( !chainer                                                   ) ) FAIL( "NULL chainer" );
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)chainer, fd_chainer_align() ) ) ) FAIL( "misaligned chainer" );
  if( FD_UNLIKELY( !fd_wksp_containing( chainer )                             ) ) FAIL( "chainer must be part of a workspace" );
  if( FD_UNLIKELY( chainer->magic!=FD_CHAINER_MAGIC                           ) ) FAIL( "bad magic" );

  fd_chainer_t             * chainer_   = (fd_chainer_t *)chainer;

  fd_chainer_block_t const * block_pool = chainer_->block_pool;
  fd_block_map_t     const * block_map  = chainer_->block_map;
  fd_chainer_fec_t   const * fec_pool   = chainer_->fec_pool;
  fd_fec_map_t       const * fec_map    = chainer_->fec_map;

  if( FD_UNLIKELY( fd_block_map_verify( block_map, fd_block_pool_max( block_pool ), block_pool )==-1 ) ) FAIL( "block map corrupted" );
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
    for( ulong i = fd_block_map_idx_query_const( block_map, &root, ULONG_MAX, block_pool );
               i != ULONG_MAX;
               i = fd_block_map_idx_next_const( i, ULONG_MAX, block_pool ) ) {
      fd_chainer_block_t const * root_block = fd_block_pool_ele_const( block_pool, i );
      root_present    = 1;
      root_connected |= !!root_block->connected;
    }
    if( FD_UNLIKELY( !root_present   ) ) FAIL( "root has no block" );
    if( FD_UNLIKELY( !root_connected ) ) FAIL( "no root block is connected" );
  }

  for( fd_block_map_iter_t it = fd_block_map_iter_init( block_map, block_pool );
                               !fd_block_map_iter_done( it, block_map, block_pool );
                           it = fd_block_map_iter_next( it, block_map, block_pool ) ) {
    fd_chainer_block_t const * block = fd_block_map_iter_ele_const( it, block_map, block_pool );

    ulong slot = block->slot;

    /* Nothing below the root may survive a publish. */

    if( FD_UNLIKELY( chainer->root!=ULONG_MAX && slot<chainer->root ) ) FAIL( "block below the root" );

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
    for( ulong i = fd_block_map_idx_query_const( block_map, &slot, ULONG_MAX, block_pool );
               i != ULONG_MAX;
               i = fd_block_map_idx_next_const( i, ULONG_MAX, block_pool ) ) {
      fd_chainer_block_t const * block = fd_block_pool_ele_const( block_pool, i );
      if( FD_LIKELY( fd_chainer_block_fecs( chainer, block )[ fec_set_idx / FD_FEC_SHRED_CNT ]==fec_idx ) ) owned = 1;
    }
    if( FD_UNLIKELY( !owned ) ) FAIL( "fec claimed by no version" );
  }

  return 0;
}
#undef FAIL
