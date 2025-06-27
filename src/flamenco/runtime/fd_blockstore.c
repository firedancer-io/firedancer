#include "fd_blockstore.h"
#include <fcntl.h>
#include <string.h>
#include <stdio.h> /* snprintf */
#include <unistd.h>
#include <errno.h>

void *
fd_blockstore_new( void * shmem,
                   ulong  wksp_tag,
                   ulong  seed,
                   ulong  shred_max,
                   ulong  block_max,
                   ulong  idx_max,
                   ulong  txn_max ) {
  /* TODO temporary fix to make sure block_max is a power of 2, as
     required for slot map para. We should change to err in config
     verification eventually */
  block_max = fd_ulong_pow2_up( block_max );
  ulong lock_cnt = fd_ulong_min( block_max, BLOCK_INFO_LOCK_CNT );

  fd_blockstore_shmem_t * blockstore_shmem = (fd_blockstore_shmem_t *)shmem;

  if( FD_UNLIKELY( !blockstore_shmem ) ) {
    FD_LOG_WARNING(( "NULL blockstore_shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned((ulong)blockstore_shmem, fd_blockstore_align() ) )) {
    FD_LOG_WARNING(( "misaligned blockstore_shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !wksp_tag ) ) {
    FD_LOG_WARNING(( "bad wksp_tag" ));
    return NULL;
  }

  fd_wksp_t * wksp = fd_wksp_containing( blockstore_shmem );
  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_WARNING(( "shmem must be part of a workspace" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_pow2( shred_max ) ) ) {
    shred_max = fd_ulong_pow2_up( shred_max );
    FD_LOG_WARNING(( "blockstore implementation requires shred_max to be a power of two, rounding it up to %lu", shred_max ));
  }

  fd_memset( blockstore_shmem, 0, fd_blockstore_footprint( shred_max, block_max, idx_max, txn_max ) );

  int   lg_idx_max   = fd_ulong_find_msb( fd_ulong_pow2_up( idx_max ) );

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  blockstore_shmem  = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_blockstore_shmem_t), sizeof(fd_blockstore_shmem_t) );
  void * shreds     = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_buf_shred_t),        sizeof(fd_buf_shred_t) * shred_max );
  void * shred_pool = FD_SCRATCH_ALLOC_APPEND( l, fd_buf_shred_pool_align(),      fd_buf_shred_pool_footprint() );
  void * shred_map  = FD_SCRATCH_ALLOC_APPEND( l, fd_buf_shred_map_align(),       fd_buf_shred_map_footprint( shred_max ) );
  void * blocks     = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_block_info_t),       sizeof(fd_block_info_t) * block_max );
  void * block_map  = FD_SCRATCH_ALLOC_APPEND( l, fd_block_map_align(),           fd_block_map_footprint( block_max, lock_cnt, BLOCK_INFO_PROBE_CNT ) );
  void * block_idx  = FD_SCRATCH_ALLOC_APPEND( l, fd_block_idx_align(),           fd_block_idx_footprint( lg_idx_max ) );
  void * slot_deque = FD_SCRATCH_ALLOC_APPEND( l, fd_slot_deque_align(),          fd_slot_deque_footprint( block_max ) );
  void * txn_map    = FD_SCRATCH_ALLOC_APPEND( l, fd_txn_map_align(),             fd_txn_map_footprint( txn_max ) );
  void * alloc      = FD_SCRATCH_ALLOC_APPEND( l, fd_alloc_align(),               fd_alloc_footprint() );
  ulong  top        = FD_SCRATCH_ALLOC_FINI( l, fd_blockstore_align() );
  FD_TEST( fd_ulong_align_up( top - (ulong)shmem, fd_alloc_align() ) == fd_ulong_align_up( fd_blockstore_footprint( shred_max, block_max, idx_max, txn_max ), fd_alloc_align() ) );

  (void)shreds;
  fd_buf_shred_pool_new( shred_pool );
  fd_buf_shred_map_new ( shred_map, shred_max, seed );
  memset( blocks, 0, sizeof(fd_block_info_t) * block_max );
  FD_TEST( fd_block_map_new ( block_map, block_max, lock_cnt, BLOCK_INFO_PROBE_CNT, seed ) );

  /* Caller is in charge of freeing map_slot_para element store set.
     We need to explicitly do this since blocks is memset to 0, which
     is not a "freed" state in map_slot_para (slot 0 is a valid key). */
  fd_block_info_t * blocks_ = (fd_block_info_t *)blocks;
  for( ulong i=0UL; i<block_max; i++ ) {
    fd_block_map_private_ele_free( NULL, /* Not needed, avoids a join on block_map */
                                   &blocks_[i] );
  }

  blockstore_shmem->block_idx_gaddr  = fd_wksp_gaddr( wksp, fd_block_idx_join( fd_block_idx_new( block_idx, lg_idx_max ) ) );
  blockstore_shmem->slot_deque_gaddr = fd_wksp_gaddr( wksp, fd_slot_deque_join (fd_slot_deque_new( slot_deque, block_max ) ) );
  blockstore_shmem->txn_map_gaddr    = fd_wksp_gaddr( wksp, fd_txn_map_join (fd_txn_map_new( txn_map, txn_max, seed ) ) );
  blockstore_shmem->alloc_gaddr      = fd_wksp_gaddr( wksp, fd_alloc_join (fd_alloc_new( alloc, wksp_tag ), wksp_tag ) );

  FD_TEST( blockstore_shmem->block_idx_gaddr  );
  FD_TEST( blockstore_shmem->slot_deque_gaddr );
  FD_TEST( blockstore_shmem->txn_map_gaddr    );
  FD_TEST( blockstore_shmem->alloc_gaddr      );

  blockstore_shmem->blockstore_gaddr = fd_wksp_gaddr_fast( wksp, blockstore_shmem );
  blockstore_shmem->wksp_tag         = wksp_tag;
  blockstore_shmem->seed             = seed;

  blockstore_shmem->archiver = (fd_blockstore_archiver_t){
      .fd_size_max = FD_BLOCKSTORE_ARCHIVE_MIN_SIZE,
      .head        = FD_BLOCKSTORE_ARCHIVE_START,
      .tail        = FD_BLOCKSTORE_ARCHIVE_START,
      .num_blocks  = 0,
  };

  blockstore_shmem->lps = FD_SLOT_NULL;
  blockstore_shmem->hcs = FD_SLOT_NULL;
  blockstore_shmem->wmk = FD_SLOT_NULL;

  blockstore_shmem->shred_max  = shred_max;
  blockstore_shmem->block_max  = block_max;
  blockstore_shmem->idx_max    = idx_max;
  blockstore_shmem->txn_max    = txn_max;

  FD_COMPILER_MFENCE();
  FD_VOLATILE( blockstore_shmem->magic ) = FD_BLOCKSTORE_MAGIC;
  FD_COMPILER_MFENCE();

  return (void *)blockstore_shmem;
}

fd_blockstore_t *
fd_blockstore_join( void * ljoin, void * shblockstore ) {
  fd_blockstore_t *       join       = (fd_blockstore_t *)ljoin;
  fd_blockstore_shmem_t * blockstore = (fd_blockstore_shmem_t *)shblockstore;

  if( FD_UNLIKELY( !join ) ) {
    FD_LOG_WARNING(( "NULL ljoin" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)join, alignof(fd_blockstore_t) ) ) ) {
    FD_LOG_WARNING(( "misaligned ljoin" ));
    return NULL;
  }

  if( FD_UNLIKELY( !blockstore ) ) {
    FD_LOG_WARNING(( "NULL shblockstore" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)blockstore, fd_blockstore_align() ) )) {
    FD_LOG_WARNING(( "misaligned shblockstore" ));
    return NULL;
  }

  if( FD_UNLIKELY( blockstore->magic != FD_BLOCKSTORE_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT( l, shblockstore );
  blockstore        = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_blockstore_shmem_t), sizeof(fd_blockstore_shmem_t) );
  void * shreds     = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_buf_shred_t),        sizeof(fd_buf_shred_t) * blockstore->shred_max );
  void * shred_pool = FD_SCRATCH_ALLOC_APPEND( l, fd_buf_shred_pool_align(),      fd_buf_shred_pool_footprint() );
  void * shred_map  = FD_SCRATCH_ALLOC_APPEND( l, fd_buf_shred_map_align(),       fd_buf_shred_map_footprint( blockstore->shred_max ) );
  void * blocks     = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_block_info_t),        sizeof(fd_block_info_t) * blockstore->block_max );
  void * block_map  = FD_SCRATCH_ALLOC_APPEND( l, fd_block_map_align(),           fd_block_map_footprint( blockstore->block_max,
                                                                                                          fd_ulong_min(blockstore->block_max, BLOCK_INFO_LOCK_CNT),
                                                                                                          BLOCK_INFO_PROBE_CNT ) );
  FD_SCRATCH_ALLOC_FINI( l, fd_blockstore_align() );

  join->shmem = blockstore;
  fd_buf_shred_pool_join( join->shred_pool, shred_pool, shreds, blockstore->shred_max );
  fd_buf_shred_map_join ( join->shred_map,  shred_map,  shreds, blockstore->shred_max );
  fd_block_map_join     ( join->block_map,  block_map,  blocks );

  FD_TEST( fd_buf_shred_pool_verify( join->shred_pool ) == FD_POOL_SUCCESS );
  FD_TEST( fd_buf_shred_map_verify ( join->shred_map  ) == FD_MAP_SUCCESS );
  FD_TEST( fd_block_map_verify     ( join->block_map  ) == FD_MAP_SUCCESS );

  return join;
}

void *
fd_blockstore_leave( fd_blockstore_t * blockstore ) {

  if( FD_UNLIKELY( !blockstore ) ) {
    FD_LOG_WARNING(( "NULL blockstore" ));
    return NULL;
  }

  fd_wksp_t * wksp = fd_wksp_containing( blockstore );
  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_WARNING(( "shmem must be part of a workspace" ));
    return NULL;
  }

  FD_TEST( fd_buf_shred_pool_leave( blockstore->shred_pool ) );
  FD_TEST( fd_buf_shred_map_leave( blockstore->shred_map ) );
  FD_TEST( fd_block_map_leave( blockstore->block_map ) );
  FD_TEST( fd_block_idx_leave( fd_blockstore_block_idx( blockstore ) ) );
  FD_TEST( fd_slot_deque_leave( fd_blockstore_slot_deque( blockstore ) ) );
  FD_TEST( fd_txn_map_leave( fd_blockstore_txn_map( blockstore ) ) );
  FD_TEST( fd_alloc_leave( fd_blockstore_alloc( blockstore ) ) );

  return (void *)blockstore;
}

void *
fd_blockstore_delete( void * shblockstore ) {
  fd_blockstore_t * blockstore = (fd_blockstore_t *)shblockstore;

  if( FD_UNLIKELY( !blockstore ) ) {
    FD_LOG_WARNING(( "NULL shblockstore" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned((ulong)blockstore, fd_blockstore_align() ) )) {
    FD_LOG_WARNING(( "misaligned shblockstore" ));
    return NULL;
  }

  if( FD_UNLIKELY( blockstore->shmem->magic != FD_BLOCKSTORE_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  fd_wksp_t * wksp = fd_wksp_containing( blockstore );
  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_WARNING(( "shmem must be part of a workspace" ));
    return NULL;
  }

  /* Delete all structures. */

  FD_TEST( fd_buf_shred_pool_delete( &blockstore->shred_pool ) );
  FD_TEST( fd_buf_shred_map_delete( &blockstore->shred_map ) );
  FD_TEST( fd_block_map_delete( &blockstore->block_map ) );
  FD_TEST( fd_block_idx_delete( fd_blockstore_block_idx( blockstore ) ) );
  FD_TEST( fd_slot_deque_delete( fd_blockstore_slot_deque( blockstore ) ) );
  FD_TEST( fd_txn_map_delete( fd_blockstore_txn_map( blockstore ) ) );
  FD_TEST( fd_alloc_delete( fd_blockstore_alloc( blockstore ) ) );

  FD_COMPILER_MFENCE();
  FD_VOLATILE( blockstore->shmem->magic ) = 0UL;
  FD_COMPILER_MFENCE();

  return blockstore;
}

#define check_read_err_safe( cond, msg )            \
  do {                                              \
    if( FD_UNLIKELY( cond ) ) {                     \
      FD_LOG_WARNING(( "[%s] %s", __func__, msg )); \
      return FD_BLOCKSTORE_ERR_SLOT_MISSING;        \
    }                                               \
} while(0);

fd_blockstore_t *
fd_blockstore_init( fd_blockstore_t *      blockstore,
                    int                    fd,
                    ulong                  fd_size_max,
                    ulong                  slot ) {

  if( fd_size_max < FD_BLOCKSTORE_ARCHIVE_MIN_SIZE ) {
    FD_LOG_ERR(( "archive file size too small" ));
    return NULL;
  }
  blockstore->shmem->archiver.fd_size_max = fd_size_max;

  //build_idx( blockstore, fd );
  lseek( fd, 0, SEEK_END );

  /* initialize fields using slot bank */

  ulong smr = slot;

  blockstore->shmem->lps = smr;
  blockstore->shmem->hcs = smr;
  blockstore->shmem->wmk = smr;

  fd_block_map_query_t query[1];

  int err = fd_block_map_prepare( blockstore->block_map, &smr, NULL, query, FD_MAP_FLAG_BLOCKING );
  fd_block_info_t * ele = fd_block_map_query_ele( query );
  if ( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "failed to prepare block map for slot %lu", smr ));

  ele->slot = smr;
  memset( ele->child_slots, UCHAR_MAX, FD_BLOCKSTORE_CHILD_SLOT_MAX * sizeof( ulong ) );
  ele->child_slot_cnt = 0;
  ele->flags          = fd_uchar_set_bit(
                      fd_uchar_set_bit(
                      fd_uchar_set_bit(
                      fd_uchar_set_bit(
                      fd_uchar_set_bit( ele->flags,
                                        FD_BLOCK_FLAG_COMPLETED ),
                                        FD_BLOCK_FLAG_PROCESSED ),
                                        FD_BLOCK_FLAG_EQVOCSAFE ),
                                        FD_BLOCK_FLAG_CONFIRMED ),
                                        FD_BLOCK_FLAG_FINALIZED );
  // ele->ref_tick = 0;
  ele->ts             = 0;
  ele->consumed_idx   = 0;
  ele->received_idx   = 0;
  ele->buffered_idx   = 0;
  ele->data_complete_idx = 0;
  ele->slot_complete_idx = 0;
  ele->ticks_consumed        = 0;
  ele->tick_hash_count_accum = 0;
  fd_block_set_null( ele->data_complete_idxs );

  /* Set all fields to 0. Caller's responsibility to check gaddr and sz != 0. */

  fd_block_map_publish( query );

  return blockstore;
}

void
fd_blockstore_fini( fd_blockstore_t * blockstore ) {
  /* Free all allocations by removing all slots (whether they are
     complete or not). */
  fd_block_info_t * ele0 = (fd_block_info_t *)fd_block_map_shele( blockstore->block_map );
  ulong block_max = fd_block_map_ele_max( blockstore->block_map );
  for( ulong ele_idx=0; ele_idx<block_max; ele_idx++ ) {
    fd_block_info_t * ele = ele0 + ele_idx;
    if( ele->slot == 0 ) continue; /* unused */
    fd_blockstore_slot_remove( blockstore, ele->slot );
  }
}

/* txn map helpers */

FD_FN_PURE int
fd_txn_key_equal( fd_txn_key_t const * k0, fd_txn_key_t const * k1 ) {
  for( ulong i = 0; i < FD_ED25519_SIG_SZ / sizeof( ulong ); ++i )
    if( k0->v[i] != k1->v[i] ) return 0;
  return 1;
}

FD_FN_PURE ulong
fd_txn_key_hash( fd_txn_key_t const * k, ulong seed ) {
  ulong h = seed;
  for( ulong i = 0; i < FD_ED25519_SIG_SZ / sizeof( ulong ); ++i )
    h ^= k->v[i];
  return h;
}

/* Remove a slot from blockstore. Needs to currently be under a blockstore_write
   lock due to txn_map access. */
void
fd_blockstore_slot_remove( fd_blockstore_t * blockstore, ulong slot ) {
  FD_LOG_DEBUG(( "[%s] slot: %lu", __func__, slot ));

  /* It is not safe to remove a replaying block. */
  fd_block_map_query_t query[1] = { 0 };
  ulong parent_slot  = FD_SLOT_NULL;
  ulong received_idx = 0;
  int    err  = FD_MAP_ERR_AGAIN;
  while( err == FD_MAP_ERR_AGAIN ) {
    err = fd_block_map_query_try( blockstore->block_map, &slot, NULL, query, 0 );
    if( FD_UNLIKELY( err == FD_MAP_ERR_AGAIN ) ) continue;
    if( FD_UNLIKELY( err == FD_MAP_ERR_KEY ) ) return; /* slot not found */
    fd_block_info_t * block_info = fd_block_map_query_ele( query );
    if( FD_UNLIKELY( fd_uchar_extract_bit( block_info->flags, FD_BLOCK_FLAG_REPLAYING ) ) ) {
      FD_LOG_WARNING(( "[%s] slot %lu has replay in progress. not removing.", __func__, slot ));
      return;
    }
    parent_slot  = block_info->parent_slot;
    received_idx = block_info->received_idx;
    err = fd_block_map_query_test( query );
  }

  err = fd_block_map_remove( blockstore->block_map, &slot, query, FD_MAP_FLAG_BLOCKING );
  /* not possible to fail */
  FD_TEST( !fd_blockstore_block_info_test( blockstore, slot ) );

  /* Unlink slot from its parent only if it is not published. */
  err = fd_block_map_prepare( blockstore->block_map, &parent_slot, NULL, query, FD_MAP_FLAG_BLOCKING );
  fd_block_info_t * parent_block_info = fd_block_map_query_ele( query );
  if( FD_LIKELY( parent_block_info ) ) {
    for( ulong i = 0; i < parent_block_info->child_slot_cnt; i++ ) {
      if( FD_LIKELY( parent_block_info->child_slots[i] == slot ) ) {
        parent_block_info->child_slots[i] =
            parent_block_info->child_slots[--parent_block_info->child_slot_cnt];
      }
    }
  }
  fd_block_map_publish( query );

  /* Remove buf_shreds. */
  for( uint idx = 0; idx < received_idx; idx++ ) {
    fd_blockstore_shred_remove( blockstore, slot, idx );
  }

  return;
}

void
fd_blockstore_publish( fd_blockstore_t * blockstore,
                       int fd FD_PARAM_UNUSED,
                       ulong wmk ) {
  FD_LOG_NOTICE(( "[%s] wmk %lu => smr %lu", __func__, blockstore->shmem->wmk, wmk ));

  /* Caller is incorrectly calling publish. */

  if( FD_UNLIKELY( blockstore->shmem->wmk == wmk ) ) {
    FD_LOG_WARNING(( "[%s] attempting to re-publish when wmk %lu already at smr %lu", __func__, blockstore->shmem->wmk, wmk ));
    return;
  }

  /* q uses the slot_deque as the BFS queue */

  ulong * q = fd_blockstore_slot_deque( blockstore );

  /* Clear the deque, preparing it to be reused. */

  fd_slot_deque_remove_all( q );

  /* Push the watermark onto the queue. */

  fd_slot_deque_push_tail( q, blockstore->shmem->wmk );

  /* Conduct a BFS to find slots to prune or archive. */

  while( !fd_slot_deque_empty( q ) ) {
    ulong slot = fd_slot_deque_pop_head( q );
    fd_block_map_query_t query[1];
    /* Blocking read -- we need the block_info ptr to be valid for the
       whole time that we are writing stuff to the archiver file. */
    int err = fd_block_map_prepare( blockstore->block_map, &slot, NULL, query, FD_MAP_FLAG_BLOCKING );
    if( FD_UNLIKELY( err ) ) {
      FD_LOG_WARNING(( "[%s] failed to prepare block map for blockstore publishing %lu", __func__, slot ));
      continue;
    }
    fd_block_info_t * block_info = fd_block_map_query_ele( query );

    /* Add slot's children to the queue. */

    for( ulong i = 0; i < block_info->child_slot_cnt; i++ ) {

      /* Stop upon reaching the SMR. */

      if( FD_LIKELY( block_info->child_slots[i] != wmk ) ) {
        fd_slot_deque_push_tail( q, block_info->child_slots[i] );
      }
    }

    /* Archive the block into a file if it is finalized. */

    /* if( fd_uchar_extract_bit( block_info->flags, FD_BLOCK_FLAG_FINALIZED ) ) {
      fd_block_t * block = fd_wksp_laddr_fast( fd_blockstore_wksp( blockstore ), block_info->block_gaddr );
      uchar * data = fd_wksp_laddr_fast( fd_blockstore_wksp( blockstore ), block->data_gaddr );

      fd_block_idx_t * block_idx = fd_blockstore_block_idx( blockstore );

      if( FD_UNLIKELY( fd_block_idx_query( block_idx, slot, NULL ) ) ) {
        FD_LOG_ERR(( "[%s] invariant violation. attempted to re-archive finalized block: %lu", __func__, slot ));
      } else {
        fd_blockstore_ser_t ser = {
          .block_map = block_info,
          .block     = block,
          .data      = data
        };
        fd_blockstore_block_checkpt( blockstore, &ser, fd, slot );
      }
    } */
    fd_block_map_cancel( query ); // TODO: maybe we should not make prepare so large and instead call prepare again in helpers
    fd_blockstore_slot_remove( blockstore, slot );
  }

  /* Scan to clean up any orphaned blocks or shreds < new SMR. */

  for (ulong slot = blockstore->shmem->wmk; slot < wmk; slot++) {
    fd_blockstore_slot_remove( blockstore, slot );
  }

  blockstore->shmem->wmk = wmk;

  return;
}

void
fd_blockstore_shred_remove( fd_blockstore_t * blockstore, ulong slot, uint idx ) {
  fd_shred_key_t key = { slot, idx };

  fd_buf_shred_map_query_t query[1] = { 0 };
  int err = fd_buf_shred_map_remove( blockstore->shred_map, &key, NULL, query, FD_MAP_FLAG_BLOCKING );
  if( FD_UNLIKELY( err == FD_MAP_ERR_CORRUPT ) ) FD_LOG_ERR(( "[%s] map corrupt: shred %lu %u", __func__, slot, idx ));

  if( FD_LIKELY( err == FD_MAP_SUCCESS ) ) {
    fd_buf_shred_t * shred = fd_buf_shred_map_query_ele( query );
    int err = fd_buf_shred_pool_release( blockstore->shred_pool, shred, 1 );
    if( FD_UNLIKELY( err == FD_POOL_ERR_INVAL ) ) FD_LOG_ERR(( "[%s] pool error: shred %lu %u not in pool", __func__, slot, idx ));
    if( FD_UNLIKELY( err == FD_POOL_ERR_CORRUPT ) ) FD_LOG_ERR(( "[%s] pool corrupt: shred %lu %u", __func__, slot, idx ));
    FD_TEST( !err );
  }
  // FD_TEST( fd_buf_shred_pool_verify( blockstore->shred_pool ) == FD_POOL_SUCCESS );
  // FD_TEST( fd_buf_shred_map_verify ( blockstore->shred_map  ) == FD_MAP_SUCCESS );
}

void
fd_blockstore_shred_insert( fd_blockstore_t * blockstore, fd_shred_t const * shred ) {
  // FD_LOG_NOTICE(( "[%s] slot %lu idx %u", __func__, shred->slot, shred->idx ));

  ulong slot = shred->slot;

  if( FD_UNLIKELY( !fd_shred_is_data( shred->variant ) ) ) FD_LOG_ERR(( "Expected data shred" ));

  if( FD_UNLIKELY( slot < blockstore->shmem->wmk ) ) {
    FD_LOG_DEBUG(( "[%s] slot %lu < wmk %lu. not inserting shred", __func__, slot, blockstore->shmem->wmk ));
    return;
  }

  fd_shred_key_t key = { slot, .idx = shred->idx };

  /* Test if the blockstore already contains this shred key. */

  if( FD_UNLIKELY( fd_blockstore_shred_test( blockstore, slot, shred->idx ) ) ) {

    /* If we receive a shred with the same key (slot and shred idx) but
       different payload as one we already have, we'll only keep the
       first. Once we receive the full block, we'll use merkle chaining
       from the last FEC set to determine whether we have the correct
       shred at every index.

       Later, if the block fails to replay (dead block) or the block
       hash doesn't match the one we observe from votes, we'll dump the
       entire block and use repair to recover the one a majority (52%)
       of the cluster has voted on. */

    for(;;) {
      fd_buf_shred_map_query_t query[1]  = { 0 };
      int err = fd_buf_shred_map_query_try( blockstore->shred_map, &key, NULL, query, 0 );
      if( FD_UNLIKELY( err == FD_MAP_ERR_CORRUPT ) ) FD_LOG_ERR(( "[%s] %s. shred: (%lu, %u)", __func__, fd_buf_shred_map_strerror( err ), slot, shred->idx ));
      if( FD_UNLIKELY( err == FD_MAP_ERR_AGAIN ) ) continue;
      fd_buf_shred_t * buf_shred = fd_buf_shred_map_query_ele( query );
      /* An existing shred has the same key.  Eqvoc iff the payload is different */
      buf_shred->eqvoc = fd_shred_payload_sz( &buf_shred->hdr ) != fd_shred_payload_sz( shred ) ||
                         0!=memcmp( fd_shred_data_payload( &buf_shred->hdr ), fd_shred_data_payload( shred ), fd_shred_payload_sz( shred ) );
      err = fd_buf_shred_map_query_test( query );
      if( FD_LIKELY( err == FD_MAP_SUCCESS) ) break;
    }
    return;
  }

  /* Insert the new shred. */

  int err;
  fd_buf_shred_t * ele = fd_buf_shred_pool_acquire( blockstore->shred_pool, NULL, 1, &err );
  if( FD_UNLIKELY( err == FD_POOL_ERR_EMPTY ) )   FD_LOG_ERR(( "[%s] %s. increase blockstore shred_max.", __func__, fd_buf_shred_pool_strerror( err ) ));
  if( FD_UNLIKELY( err == FD_POOL_ERR_CORRUPT ) ) FD_LOG_ERR(( "[%s] %s.", __func__, fd_buf_shred_pool_strerror( err ) ));

  ele->key = key;
  ele->hdr = *shred;
  fd_memcpy( &ele->buf, shred, fd_shred_sz( shred ) );
  err = fd_buf_shred_map_insert( blockstore->shred_map, ele, FD_MAP_FLAG_BLOCKING );
  if( FD_UNLIKELY( err == FD_MAP_ERR_INVAL ) ) FD_LOG_ERR(( "[%s] map error. ele not in pool.", __func__ ));

  /* Update shred's associated slot meta */

  if( FD_UNLIKELY( !fd_blockstore_block_info_test( blockstore, slot ) ) ) {
    fd_block_map_query_t query[1] = { 0 };
    /* Prepare will succeed regardless of if the key is in the map or not. It either returns
       the element at that idx, or it will return a spot to insert new stuff. So we need to check
       if that space is actually unused, to signify that we are adding a new entry. */

    /* Try to insert slot into block_map TODO make non blocking? */

    err = fd_block_map_prepare( blockstore->block_map, &slot, NULL, query, FD_MAP_FLAG_BLOCKING );
    fd_block_info_t * block_info = fd_block_map_query_ele( query );

    if( FD_UNLIKELY( err == FD_MAP_ERR_FULL ) ){
      FD_LOG_ERR(( "[%s] OOM: failed to insert new block map entry. blockstore needs to save metadata for all slots >= SMR, so increase memory or check for issues with publishing new SMRs.", __func__ ));
    }

    /* Initialize the block_info. Note some fields are initialized
       to dummy values because we do not have all the necessary metadata
       yet. */

    block_info->slot = slot;

    block_info->parent_slot = slot - shred->data.parent_off;
    memset( block_info->child_slots, UCHAR_MAX, FD_BLOCKSTORE_CHILD_SLOT_MAX * sizeof(ulong) );
    block_info->child_slot_cnt = 0;

    block_info->block_height   = 0;
    block_info->block_hash     = ( fd_hash_t ){ 0 };
    block_info->bank_hash      = ( fd_hash_t ){ 0 };
    block_info->flags          = fd_uchar_set_bit( 0, FD_BLOCK_FLAG_RECEIVING );
    block_info->ts             = 0;
    // block_info->ref_tick = (uchar)( (int)shred->data.flags &
                                              //  (int)FD_SHRED_DATA_REF_TICK_MASK );
    block_info->buffered_idx   = UINT_MAX;
    block_info->received_idx   = 0;
    block_info->consumed_idx   = UINT_MAX;

    block_info->data_complete_idx = UINT_MAX;
    block_info->slot_complete_idx = UINT_MAX;

    block_info->ticks_consumed        = 0;
    block_info->tick_hash_count_accum = 0;

    fd_block_set_null( block_info->data_complete_idxs );

    block_info->block_gaddr    = 0;

    fd_block_map_publish( query );

    FD_TEST( fd_blockstore_block_info_test( blockstore, slot ) );
  }
  fd_block_map_query_t query[1] = { 0 };
  err = fd_block_map_prepare( blockstore->block_map, &slot, NULL, query, FD_MAP_FLAG_BLOCKING );
  fd_block_info_t * block_info = fd_block_map_query_ele( query );   /* should be impossible for this to fail */

  /* Advance the buffered_idx watermark. */

  uint prev_buffered_idx = block_info->buffered_idx;
  while( FD_LIKELY( fd_blockstore_shred_test( blockstore, slot, block_info->buffered_idx + 1 ) ) ) {
    block_info->buffered_idx++;
  }

  /* Mark the ending shred idxs of entry batches. */

  fd_block_set_insert_if( block_info->data_complete_idxs, shred->data.flags & FD_SHRED_DATA_FLAG_DATA_COMPLETE, shred->idx );

  /* Advance the data_complete_idx watermark using the shreds in between
     the previous consumed_idx and current consumed_idx. */

  for (uint idx = prev_buffered_idx + 1; block_info->buffered_idx != FD_SHRED_IDX_NULL && idx <= block_info->buffered_idx; idx++) {
    if( FD_UNLIKELY( fd_block_set_test( block_info->data_complete_idxs, idx ) ) ) {
      block_info->data_complete_idx = idx;
    }
  }

  /* Update received_idx and slot_complete_idx.  */

  block_info->received_idx = fd_uint_max( block_info->received_idx, shred->idx + 1 );
  if( FD_UNLIKELY( shred->data.flags & FD_SHRED_DATA_FLAG_SLOT_COMPLETE ) ) {
    // FD_LOG_NOTICE(( "slot %lu %u complete", slot, shred->idx ));
    block_info->slot_complete_idx = shred->idx;
  }

  ulong parent_slot       = block_info->parent_slot;

  FD_LOG_DEBUG(( "shred: (%lu, %u). consumed: %u, received: %u, complete: %u",
               slot,
               shred->idx,
               block_info->buffered_idx,
               block_info->received_idx,
               block_info->slot_complete_idx ));
  fd_block_map_publish( query );

  /* Update ancestry metadata: parent_slot, is_connected, next_slot.

     If the parent_slot happens to be very old, there's a chance that
     it's hash probe could collide with an existing slot in the block
     map, and cause what looks like an OOM. Instead of using map_prepare
     and hitting this collision, we can either check that the
     parent_slot lives in the map with a block_info_test, or use the
     shmem wmk value as a more general guard against querying for
     parents that are too old. */

  if( FD_LIKELY( parent_slot < blockstore->shmem->wmk ) ) return;

  err = fd_block_map_prepare( blockstore->block_map, &parent_slot, NULL, query, FD_MAP_FLAG_BLOCKING );
  fd_block_info_t * parent_block_info = fd_block_map_query_ele( query );

  /* Add this slot to its parent's child slots if not already there. */

  if( FD_LIKELY( parent_block_info && parent_block_info->slot == parent_slot ) ) {
    int found = 0;
    for( ulong i = 0; i < parent_block_info->child_slot_cnt; i++ ) {
      if( FD_LIKELY( parent_block_info->child_slots[i] == slot ) ) {
        found = 1;
        break;
      }
    }
    if( FD_UNLIKELY( !found ) ) { /* add to parent's child slots if not already there */
      if( FD_UNLIKELY( parent_block_info->child_slot_cnt == FD_BLOCKSTORE_CHILD_SLOT_MAX ) ) {
        FD_LOG_ERR(( "failed to add slot %lu to parent %lu's children. exceeding child slot max",
                      slot,
                      parent_block_info->slot ));
      }
      parent_block_info->child_slots[parent_block_info->child_slot_cnt++] = slot;
    }
  }
  if( FD_LIKELY( err == FD_MAP_SUCCESS ) ) {
    fd_block_map_publish( query );
  } else {
    /* err is FD_MAP_ERR_FULL. Not in a valid prepare. Can happen if we
       are about to OOM, or if the parents are so far away that it just
       happens to chain longer than the probe_max. Somewhat covered by
       the early return, but there are some edge cases where we reach
       here, and it shouldn't be a LOG_ERR */
    FD_LOG_WARNING(( "block info not found for parent slot %lu. Have we seen it before?", parent_slot ));
  }

  //FD_TEST( fd_block_map_verify( blockstore->block_map ) == FD_MAP_SUCCESS );
}

int
fd_blockstore_shred_test( fd_blockstore_t * blockstore, ulong slot, uint idx ) {
  fd_shred_key_t key = { slot, idx };
  fd_buf_shred_map_query_t query[1] = { 0 };

  for(;;) {
    int err = fd_buf_shred_map_query_try( blockstore->shred_map, &key, NULL, query, 0 );
    if( FD_UNLIKELY( err == FD_MAP_ERR_CORRUPT ) ) FD_LOG_ERR(( "[%s] slot: %lu idx: %u. %s", __func__, slot, idx, fd_buf_shred_map_strerror( err ) ));
    if( FD_LIKELY( !fd_buf_shred_map_query_test( query ) ) ) return err != FD_MAP_ERR_KEY;
  }
}

int
fd_blockstore_block_info_test( fd_blockstore_t * blockstore, ulong slot ) {
  int err = FD_MAP_ERR_AGAIN;
  while( err == FD_MAP_ERR_AGAIN ){
    fd_block_map_query_t query[1] = { 0 };
    err = fd_block_map_query_try( blockstore->block_map, &slot, NULL, query, 0 );
    if( err == FD_MAP_ERR_AGAIN ) continue;
    if( err == FD_MAP_ERR_KEY ) return 0;
    err = fd_block_map_query_test( query );
  }
  return 1;
}

fd_block_info_t *
fd_blockstore_block_map_query( fd_blockstore_t * blockstore, ulong slot ){
  fd_block_map_query_t quer[1] = { 0 };
  int err = fd_block_map_query_try( blockstore->block_map, &slot, NULL, quer, FD_MAP_FLAG_BLOCKING );
  fd_block_info_t * meta = fd_block_map_query_ele( quer );
  if( err ) return NULL;
  return meta;
}

int
fd_blockstore_block_info_remove( fd_blockstore_t * blockstore, ulong slot ){
   int err = FD_MAP_ERR_AGAIN;
   while( err == FD_MAP_ERR_AGAIN ){
     err = fd_block_map_remove( blockstore->block_map, &slot, NULL, 0 );
     if( err == FD_MAP_ERR_KEY ) return FD_BLOCKSTORE_ERR_SLOT_MISSING;
   }
  return FD_BLOCKSTORE_SUCCESS;
}

long
fd_buf_shred_query_copy_data( fd_blockstore_t * blockstore, ulong slot, uint idx, void * buf, ulong buf_sz ) {
  if( buf_sz < FD_SHRED_MAX_SZ ) return -1;
  fd_shred_key_t key = { slot, idx };
  ulong          sz  = 0;
  int            err = FD_MAP_ERR_AGAIN;
  while( err == FD_MAP_ERR_AGAIN ) {
    fd_buf_shred_map_query_t query[1] = { 0 };
    err = fd_buf_shred_map_query_try( blockstore->shred_map, &key, NULL, query, 0 );
    if( FD_UNLIKELY( err == FD_MAP_ERR_KEY ) ) return -1;
    if( FD_UNLIKELY( err == FD_MAP_ERR_CORRUPT ) ) FD_LOG_ERR(( "[%s] map corrupt. shred %lu %u", __func__, slot, idx ));
    if( FD_UNLIKELY( err == FD_MAP_ERR_AGAIN ) ) continue;
    fd_buf_shred_t const * shred = fd_buf_shred_map_query_ele_const( query );
    sz = fd_shred_sz( &shred->hdr );
    memcpy( buf, shred->buf, sz );
    err = fd_buf_shred_map_query_test( query );
  }
  FD_TEST( !err );
  return (long)sz;
}

int
fd_blockstore_block_hash_query( fd_blockstore_t * blockstore, ulong slot, fd_hash_t * hash_out ) {
  for(;;) { /* Speculate */
    fd_block_map_query_t query[1] = { 0 };
    int err = fd_block_map_query_try( blockstore->block_map, &slot, NULL, query, 0 );
    if( FD_UNLIKELY( err == FD_MAP_ERR_KEY ) )   return FD_BLOCKSTORE_ERR_KEY;
    if( FD_UNLIKELY( err == FD_MAP_ERR_AGAIN ) ) continue;
    fd_block_info_t * block_info = fd_block_map_query_ele( query );
    *hash_out = block_info->block_hash;
    if( FD_LIKELY( fd_block_map_query_test( query ) == FD_MAP_SUCCESS ) ) return FD_BLOCKSTORE_SUCCESS;
  }
}

int
fd_blockstore_bank_hash_query( fd_blockstore_t * blockstore, ulong slot, fd_hash_t * hash_out ) {
  for(;;) { /* Speculate */
    fd_block_map_query_t query[1] = { 0 };
    int err = fd_block_map_query_try( blockstore->block_map, &slot, NULL, query, 0 );
    if( FD_UNLIKELY( err == FD_MAP_ERR_KEY ) )   return FD_BLOCKSTORE_ERR_KEY;
    if( FD_UNLIKELY( err == FD_MAP_ERR_AGAIN ) ) continue;
    fd_block_info_t * block_info = fd_block_map_query_ele( query );
    *hash_out = block_info->bank_hash;
    if( FD_LIKELY( fd_block_map_query_test( query ) == FD_MAP_SUCCESS ) ) return FD_BLOCKSTORE_SUCCESS;
  }
}

ulong
fd_blockstore_parent_slot_query( fd_blockstore_t * blockstore, ulong slot ) {
  int err = FD_MAP_ERR_AGAIN;
  ulong parent_slot = FD_SLOT_NULL;
  while( err == FD_MAP_ERR_AGAIN ){
    fd_block_map_query_t query[1] = { 0 };
    err = fd_block_map_query_try( blockstore->block_map, &slot, NULL, query, 0 );
    fd_block_info_t * block_info = fd_block_map_query_ele( query );

    if( FD_UNLIKELY( err == FD_MAP_ERR_KEY ) ) return FD_SLOT_NULL;
    if( FD_UNLIKELY( err == FD_MAP_ERR_AGAIN ) ) continue;

    parent_slot = block_info->parent_slot;
    err = fd_block_map_query_test( query );
  }
  return parent_slot;
}

int
fd_blockstore_slice_query( fd_blockstore_t * blockstore,
                           ulong             slot,
                           uint              start_idx,
                           uint              end_idx /* inclusive */,
                           ulong             max,
                           uchar *           buf,
                           ulong *           buf_sz ) {
  /* verify that the batch idxs provided is at batch boundaries*/

  // FD_LOG_NOTICE(( "querying for %lu %u %u", slot, start_idx, end_idx ));

  ulong off = 0;
  for(uint idx = start_idx; idx <= end_idx; idx++) {
    ulong payload_sz = 0;

    for(;;) { /* speculative copy one shred */
      fd_shred_key_t key = { slot, idx };
      fd_buf_shred_map_query_t query[1] = { 0 };
      int err = fd_buf_shred_map_query_try( blockstore->shred_map, &key, NULL, query, 0 );
      if( FD_UNLIKELY( err == FD_MAP_ERR_CORRUPT ) ){
        FD_LOG_WARNING(( "[%s] key: (%lu, %u) %s", __func__, slot, idx, fd_buf_shred_map_strerror( err ) ));
        return FD_BLOCKSTORE_ERR_CORRUPT;
      }
      if( FD_UNLIKELY( err == FD_MAP_ERR_KEY ) ){
        FD_LOG_WARNING(( "[%s] key: (%lu, %u) %s", __func__, slot, idx, fd_buf_shred_map_strerror( err ) ));
        return FD_BLOCKSTORE_ERR_KEY;
      }
      if( FD_UNLIKELY( err == FD_MAP_ERR_AGAIN ) ) continue;

      fd_buf_shred_t const * shred      = fd_buf_shred_map_query_ele_const( query );
      uchar const *          payload    = fd_shred_data_payload( &shred->hdr );
      payload_sz                        = fd_shred_payload_sz( &shred->hdr );
      if( FD_UNLIKELY( off + payload_sz > max ) ) {
        FD_LOG_WARNING(( "[%s] increase `max`", __func__ )); /* caller needs to increase max */
        return FD_BLOCKSTORE_ERR_INVAL;
      }

      if( FD_UNLIKELY( payload_sz > FD_SHRED_DATA_PAYLOAD_MAX ) ) return FD_BLOCKSTORE_ERR_SHRED_INVALID;
      if( FD_UNLIKELY( off + payload_sz > max ) ) return FD_BLOCKSTORE_ERR_NO_MEM;
      fd_memcpy( buf + off, payload, payload_sz );
      err = fd_buf_shred_map_query_test( query );
      if( FD_LIKELY( err == FD_MAP_SUCCESS ) ) break;
    }; /* successful speculative copy */

    off += payload_sz;
  }
  *buf_sz = off;
  return FD_BLOCKSTORE_SUCCESS;
}

int
fd_blockstore_shreds_complete( fd_blockstore_t * blockstore, ulong slot ){
  //fd_block_t * block_exists = fd_blockstore_block_query( blockstore,  slot );
  fd_block_map_query_t query[1];
  int complete = 0;
  int err     = FD_MAP_ERR_AGAIN;
  while( err == FD_MAP_ERR_AGAIN ){
    err = fd_block_map_query_try( blockstore->block_map, &slot, NULL, query, 0 );
    fd_block_info_t * block_info = fd_block_map_query_ele( query );
    if( FD_UNLIKELY( err == FD_MAP_ERR_KEY ) ) return 0;
    if( FD_UNLIKELY( err == FD_MAP_ERR_AGAIN ) ) continue;
    complete = ( block_info->buffered_idx != FD_SHRED_IDX_NULL ) &&
               ( block_info->slot_complete_idx == block_info->buffered_idx );
    err = fd_block_map_query_test( query );
  }
  return complete;

  /* When replacing block_query( slot ) != NULL with this function:
     There are other things verified in a successful deshred & scan block that are not verified here.
     scan_block does a round of well-formedness checks like parsing txns, and no premature end of batch
     like needing cnt, microblock, microblock format.

     This maybe should be fine in places where we check both
     shreds_complete and flag PROCESSED/REPLAYING is set, because validation has been for sure done
     if the block has been replayed

     Should be careful in places that call this now that happen before the block is replayed, if we want
     to assume the shreds are well-formed we can't. */

}

int
fd_blockstore_block_map_query_volatile( fd_blockstore_t * blockstore,
                                        int               fd,
                                        ulong             slot,
                                        fd_block_info_t *  block_info_out ) {

  /* WARNING: this code is extremely delicate. Do NOT modify without
     understanding all the invariants. In particular, we must never
     dereference through a corrupt pointer. It's OK for the destination
     data to be overwritten/invalid as long as the memory location is
     valid. As long as we don't crash, we can validate the data after it
     is read. */

  fd_block_idx_t * block_idx = fd_blockstore_block_idx( blockstore );

  ulong off = ULONG_MAX;
  for( ;; ) {
    fd_block_idx_t * idx_entry = fd_block_idx_query( block_idx, slot, NULL );
    if( FD_LIKELY( idx_entry ) ) off = idx_entry->off;
    break;
  }

  if( FD_UNLIKELY( off < ULONG_MAX ) ) { /* optimize for non-archival queries */
    if( FD_UNLIKELY( lseek( fd, (long)off, SEEK_SET ) == -1 ) ) {
      FD_LOG_WARNING(( "failed to seek" ));
      return FD_BLOCKSTORE_ERR_SLOT_MISSING;
    }
    ulong rsz;
    int   err = fd_io_read( fd, block_info_out, sizeof( fd_block_info_t ), sizeof( fd_block_info_t ), &rsz );
    if( FD_UNLIKELY( err ) ) {
      FD_LOG_WARNING(( "failed to read block map entry" ));
      return FD_BLOCKSTORE_ERR_SLOT_MISSING;
    }
    return FD_BLOCKSTORE_SUCCESS;
  }

  int err = FD_MAP_ERR_AGAIN;
  while( err == FD_MAP_ERR_AGAIN ) {
    fd_block_map_query_t quer[1] = { 0 };
    err = fd_block_map_query_try( blockstore->block_map, &slot, NULL, quer, 0 );
    fd_block_info_t const * query = fd_block_map_query_ele_const( quer );
    if( FD_UNLIKELY( err == FD_MAP_ERR_KEY ) ) return FD_BLOCKSTORE_ERR_SLOT_MISSING;

    *block_info_out = *query;

    err = fd_block_map_query_test( quer );
  }
  return FD_BLOCKSTORE_SUCCESS;
}

fd_txn_map_t *
fd_blockstore_txn_query( fd_blockstore_t * blockstore, uchar const sig[FD_ED25519_SIG_SZ] ) {
  fd_txn_key_t key;
  fd_memcpy( &key, sig, sizeof( key ) );
  return fd_txn_map_query( fd_blockstore_txn_map( blockstore ), &key, NULL );
}

int
fd_blockstore_txn_query_volatile( fd_blockstore_t * blockstore,
                                  int               fd,
                                  uchar const       sig[FD_ED25519_SIG_SZ],
                                  fd_txn_map_t *    txn_out,
                                  long *            blk_ts,
                                  uchar *           blk_flags,
                                  uchar             txn_data_out[FD_TXN_MTU] ) {
  /* WARNING: this code is extremely delicate. Do NOT modify without
     understanding all the invariants. In particular, we must never
     dereference through a corrupt pointer. It's OK for the
     destination data to be overwritten/invalid as long as the memory
     location is valid. As long as we don't crash, we can validate the
     data after it is read. */
  (void)blockstore;
  (void)fd;
  (void)sig;
  (void)txn_out;
  (void)blk_ts;
  (void)blk_flags;
  (void)txn_data_out;
  return FD_BLOCKSTORE_ERR_SLOT_MISSING;
#if BLOCK_ARCHIVING
  fd_wksp_t * wksp = fd_blockstore_wksp( blockstore );
  fd_txn_map_t * txn_map = fd_blockstore_txn_map( blockstore );

  for(;;) {
    fd_txn_key_t key;
    memcpy( &key, sig, sizeof(key) );
    fd_txn_map_t const * txn_map_entry = fd_txn_map_query_safe( txn_map, &key, NULL );
    if( FD_UNLIKELY( txn_map_entry == NULL ) ) return FD_BLOCKSTORE_ERR_TXN_MISSING;
    memcpy( txn_out, txn_map_entry, sizeof(fd_txn_map_t) );
    break;
  }

  fd_block_idx_t * block_idx = fd_blockstore_block_idx( blockstore );

  ulong off = ULONG_MAX;
  for(;;) {
    fd_block_idx_t * idx_entry = fd_block_idx_query( block_idx, txn_out->slot, NULL );
    if( FD_LIKELY( idx_entry ) ) off = idx_entry->off;
    break;
  }

  if ( FD_UNLIKELY( off < ULONG_MAX ) ) { /* optimize for non-archival */
    if( FD_UNLIKELY( lseek( fd, (long)off, SEEK_SET ) == -1 ) ) {
      FD_LOG_WARNING(( "failed to seek" ));
      return FD_BLOCKSTORE_ERR_SLOT_MISSING;
    }
    fd_block_info_t block_info;
    ulong rsz; int err;
    err = fd_io_read( fd, &block_info, sizeof(fd_block_info_t), sizeof(fd_block_info_t), &rsz );
    check_read_write_err( err );
    err = fd_io_read( fd, txn_data_out, txn_out->sz, txn_out->sz, &rsz );
    check_read_write_err( err );
    err = (int)lseek( fd, (long)off + (long)txn_out->offset, SEEK_SET );
    check_read_write_err( err );
    err = fd_io_read( fd, txn_data_out, txn_out->sz, txn_out->sz, &rsz );
    check_read_write_err( err);
    return FD_BLOCKSTORE_SUCCESS;
  }

  for(;;) {
    fd_block_map_query_t quer[1] = { 0 };
    fd_block_map_query_try( blockstore->block_map, &txn_out->slot, NULL, quer, 0 );
    fd_block_info_t const * query = fd_block_map_query_ele_const( quer );

    if( FD_UNLIKELY( !query ) ) return FD_BLOCKSTORE_ERR_TXN_MISSING;
    ulong blk_gaddr = query->block_gaddr;
    if( FD_UNLIKELY( !blk_gaddr ) ) return FD_BLOCKSTORE_ERR_TXN_MISSING;

    if( fd_block_map_query_test( quer ) ) continue;

    fd_block_t * blk = fd_wksp_laddr_fast( wksp, blk_gaddr );
    if( blk_ts ) *blk_ts = query->ts;
    if( blk_flags ) *blk_flags = query->flags;
    ulong ptr = blk->data_gaddr;
    ulong sz = blk->data_sz;
    if( txn_out->offset + txn_out->sz > sz || txn_out->sz > FD_TXN_MTU ) continue;

    if( FD_UNLIKELY( fd_block_map_query_test( quer ) ) ) continue;

    if( txn_data_out == NULL ) return FD_BLOCKSTORE_SUCCESS;
    uchar const * data = fd_wksp_laddr_fast( wksp, ptr );
    fd_memcpy( txn_data_out, data + txn_out->offset, txn_out->sz );

    if( FD_UNLIKELY( fd_block_map_query_test( quer ) ) ) continue;

    return FD_BLOCKSTORE_SUCCESS;
  }
#endif
}

void
fd_blockstore_block_height_update( fd_blockstore_t * blockstore, ulong slot, ulong height ) {
  fd_block_map_query_t query[1] = { 0 };
  // TODO make nonblocking
  int err = fd_block_map_prepare( blockstore->block_map, &slot, NULL, query, FD_MAP_FLAG_BLOCKING );
  fd_block_info_t * block_info = fd_block_map_query_ele( query );
  if( FD_UNLIKELY( err || block_info->slot != slot ) ) {
    fd_block_map_cancel( query );
    return;
  };
  block_info->block_height = height;
  fd_block_map_publish( query );
}

ulong
fd_blockstore_block_height_query( fd_blockstore_t * blockstore, ulong slot ) {
  ulong block_entry_height = 0;
  for(;;){
    fd_block_map_query_t query[1] = { 0 };
    int err = fd_block_map_query_try( blockstore->block_map, &slot, NULL, query, FD_MAP_FLAG_BLOCKING );
    fd_block_info_t * block_info = fd_block_map_query_ele( query );
    if( FD_UNLIKELY( err == FD_MAP_ERR_KEY   ) ) FD_LOG_ERR(( "Failed to query blockstore for slot %lu", slot ));
    if( FD_UNLIKELY( err == FD_MAP_ERR_AGAIN ) ) continue;
    block_entry_height = block_info->block_height;
    if( FD_UNLIKELY( fd_block_map_query_test( query ) == FD_MAP_SUCCESS ) ) break;
  }
  return block_entry_height;
}

void
fd_blockstore_log_block_status( fd_blockstore_t * blockstore, ulong around_slot ) {
  fd_block_map_query_t query[1] = { 0 };
  uint received_idx = 0;
  uint buffered_idx = 0;
  uint slot_complete_idx = 0;

  for( ulong i = around_slot - 5; i < around_slot + 20; ++i ) {
    int err = FD_MAP_ERR_AGAIN;
    while( err == FD_MAP_ERR_AGAIN ){
      err = fd_block_map_query_try( blockstore->block_map, &i, NULL, query, 0 );
      fd_block_info_t * slot_entry = fd_block_map_query_ele( query );
      if( err == FD_MAP_ERR_KEY ) break;
      if( err == FD_MAP_ERR_AGAIN ) continue;
      received_idx = slot_entry->received_idx;
      buffered_idx = slot_entry->buffered_idx;
      slot_complete_idx = slot_entry->slot_complete_idx;
      err = fd_block_map_query_test( query );
      if( err == FD_MAP_ERR_KEY ) break;
    }

    if( err == FD_MAP_ERR_KEY ) continue;

    FD_LOG_NOTICE(( "%sslot=%lu received=%u consumed=%u finished=%u",
                    ( i == around_slot ? "*" : " " ),
                    i,
                    received_idx,
                    buffered_idx,
                    slot_complete_idx ));
  }
}

static char *
fd_smart_size( ulong sz, char * tmp, size_t tmpsz ) {
  if( sz <= (1UL<<7) )
    snprintf( tmp, tmpsz, "%lu B", sz );
  else if( sz <= (1UL<<17) )
    snprintf( tmp, tmpsz, "%.3f KB", ((double)sz/((double)(1UL<<10))) );
  else if( sz <= (1UL<<27) )
    snprintf( tmp, tmpsz, "%.3f MB", ((double)sz/((double)(1UL<<20))) );
  else
    snprintf( tmp, tmpsz, "%.3f GB", ((double)sz/((double)(1UL<<30))) );
  return tmp;
}

void
fd_blockstore_log_mem_usage( fd_blockstore_t * blockstore ) {
  char tmp1[100];

  FD_LOG_NOTICE(( "blockstore base footprint: %s",
                  fd_smart_size( sizeof(fd_blockstore_t), tmp1, sizeof(tmp1) ) ));
  ulong shred_max = fd_buf_shred_pool_ele_max( blockstore->shred_pool );
  FD_LOG_NOTICE(( "shred pool footprint: %s %lu entries)",
                  fd_smart_size( fd_buf_shred_pool_footprint(), tmp1, sizeof(tmp1) ),
                  shred_max ));
  ulong shred_map_cnt = fd_buf_shred_map_chain_cnt( blockstore->shred_map );
  FD_LOG_NOTICE(( "shred map footprint: %s (%lu chains, load is %.3f)",
                  fd_smart_size( fd_buf_shred_map_footprint( shred_map_cnt ), tmp1, sizeof(tmp1) ),
                  shred_map_cnt,
                  (double)shred_map_cnt) );

  /*fd_block_info_t * slot_map = fd_blockstore_block_map( blockstore );
  ulong slot_map_cnt = fd_block_map_key_cnt( slot_map );
  ulong slot_map_max = fd_block_map_key_max( slot_map );
  FD_LOG_NOTICE(( "slot map footprint: %s (%lu entries used out of %lu, %lu%%)",
                  fd_smart_size( fd_block_map_footprint( slot_map_max ), tmp1, sizeof(tmp1) ),
                  slot_map_cnt,
                  slot_map_max,
                  (100U*slot_map_cnt)/slot_map_max )); */

  fd_txn_map_t * txn_map = fd_blockstore_txn_map( blockstore );
  ulong txn_map_cnt = fd_txn_map_key_cnt( txn_map );
  ulong txn_map_max = fd_txn_map_key_max( txn_map );
  FD_LOG_NOTICE(( "txn map footprint: %s (%lu entries used out of %lu, %lu%%)",
                  fd_smart_size( fd_txn_map_footprint( txn_map_max ), tmp1, sizeof(tmp1) ),
                  txn_map_cnt,
                  txn_map_max,
                  (100U*txn_map_cnt)/txn_map_max ));
  ulong block_cnt = 0;

  ulong * q = fd_blockstore_slot_deque( blockstore );
  fd_slot_deque_remove_all( q );
  fd_slot_deque_push_tail( q, blockstore->shmem->wmk );
  while( !fd_slot_deque_empty( q ) ) {
    ulong curr = fd_slot_deque_pop_head( q );

    fd_block_map_query_t query[1] = { 0 };
    int err = fd_block_map_query_try( blockstore->block_map, &curr, NULL, query, FD_MAP_FLAG_BLOCKING );
    fd_block_info_t * block_info = fd_block_map_query_ele( query );
    if( FD_UNLIKELY( err == FD_MAP_ERR_KEY || !block_info ) ) continue;

    for( ulong i = 0; i < block_info->child_slot_cnt; i++ ) {
      fd_slot_deque_push_tail( q, block_info->child_slots[i] );
    }
  }

  if( block_cnt )
    FD_LOG_NOTICE(( "block cnt: %lu",
                    block_cnt ));
}
