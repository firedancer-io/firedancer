#include "fd_blockstore.h"
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h> /* snprintf */
#include <unistd.h>

void *
fd_blockstore_new( void * shmem,
                   ulong  wksp_tag,
                   ulong  seed,
                   ulong  shred_max,
                   ulong  block_max,
                   ulong  idx_max,
                   ulong  txn_max ) {
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

  fd_memset( blockstore_shmem, 0, fd_blockstore_footprint( shred_max, block_max, idx_max, txn_max ) );

  int   lg_idx_max   = fd_ulong_find_msb( fd_ulong_pow2_up( idx_max ) );
  ulong lock_cnt_est = fd_block_map_lock_cnt_est( block_max );
  ulong probe_est    = fd_block_map_probe_max_est( block_max );

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  blockstore_shmem  = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_blockstore_shmem_t), sizeof(fd_blockstore_shmem_t) );
  void * shreds     = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_buf_shred_t),        sizeof(fd_buf_shred_t) * shred_max );
  void * shred_pool = FD_SCRATCH_ALLOC_APPEND( l, fd_buf_shred_pool_align(),      fd_buf_shred_pool_footprint() );
  void * shred_map  = FD_SCRATCH_ALLOC_APPEND( l, fd_buf_shred_map_align(),       fd_buf_shred_map_footprint( shred_max ) );
  void * blocks     = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_block_map_t),        sizeof(fd_block_map_t) * block_max );
  void * block_map  = FD_SCRATCH_ALLOC_APPEND( l, fd_block_map_align(),           fd_block_map_footprint( block_max, lock_cnt_est, probe_est ) );
  void * block_idx  = FD_SCRATCH_ALLOC_APPEND( l, fd_block_idx_align(),           fd_block_idx_footprint( lg_idx_max ) );
  void * slot_deque = FD_SCRATCH_ALLOC_APPEND( l, fd_slot_deque_align(),          fd_slot_deque_footprint( block_max ) );
  void * txn_map    = FD_SCRATCH_ALLOC_APPEND( l, fd_txn_map_align(),             fd_txn_map_footprint( txn_max ) );
  void * alloc      = FD_SCRATCH_ALLOC_APPEND( l, fd_alloc_align(),               fd_alloc_footprint() );
  ulong top = FD_SCRATCH_ALLOC_FINI( l, fd_blockstore_align() );
  FD_TEST( top - (ulong)shmem == fd_blockstore_footprint( shred_max, block_max, idx_max, txn_max ) );

  (void)shreds;
  (void)blocks;
  fd_buf_shred_pool_new( shred_pool );
  fd_buf_shred_map_new ( shred_map, shred_max, seed );
  fd_block_map_new     ( block_map, block_max, lock_cnt_est, probe_est, seed );

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

  FD_COMPILER_MFENCE();
  fd_rwseq_new( &blockstore_shmem->lock );
  FD_COMPILER_MFENCE();

  blockstore_shmem->archiver = (fd_blockstore_archiver_t){
      .fd_size_max = FD_BLOCKSTORE_ARCHIVE_MIN_SIZE,
      .head        = FD_BLOCKSTORE_ARCHIVE_START,
      .tail        = FD_BLOCKSTORE_ARCHIVE_START,
      .num_blocks  = 0,
  };

  blockstore_shmem->lps = FD_SLOT_NULL;
  blockstore_shmem->hcs = FD_SLOT_NULL;
  blockstore_shmem->smr = FD_SLOT_NULL;

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
  void * blocks     = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_block_map_t),        sizeof(fd_block_map_t) * blockstore->block_max );
  void * block_map  = FD_SCRATCH_ALLOC_APPEND( l, fd_block_map_align(),           fd_block_map_footprint( blockstore->block_max, 
                                                                                                          fd_block_map_lock_cnt_est( blockstore->block_max ),  
                                                                                                          fd_block_map_probe_max_est( blockstore->block_max )) );
  FD_LOG_NOTICE(( "shreds %p", shreds ));
  FD_LOG_NOTICE(( "shred_pool %p", shred_pool ));
  FD_LOG_NOTICE(( "shred_map %p", shred_map ));
  FD_SCRATCH_ALLOC_FINI( l, fd_blockstore_align() );

  join->shmem = blockstore;
  fd_buf_shred_pool_join( join->shred_pool, shred_pool, shreds, blockstore->shred_max );
  fd_buf_shred_map_join ( join->shred_map,  shred_map,  shreds, blockstore->shred_max );
  fd_block_map_join     ( join->block_map,  block_map,  blocks );

  // FD_TEST( fd_buf_shred_pool_verify( join->shred_pool ) == FD_POOL_SUCCESS );
  // FD_TEST( fd_buf_shred_map_verify ( join->shred_map  ) == FD_MAP_SUCCESS );
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

static inline void check_read_write_err( int err ) {
  if( FD_UNLIKELY( err < 0 ) ) {
    FD_LOG_ERR(( "unexpected EOF %s", strerror( errno ) ));
  }
  if( FD_UNLIKELY( err > 0 ) ) {
    FD_LOG_ERR(( "unable to read/write %s", strerror( errno ) ));
  }
}

ulong
fd_blockstore_archiver_lrw_slot( fd_blockstore_t * blockstore, int fd, fd_block_meta_t * lrw_block_meta, fd_block_t * lrw_block_out ) {
  fd_block_idx_t * block_idx = fd_blockstore_block_idx( blockstore );
  if ( FD_UNLIKELY ( fd_block_idx_key_cnt( block_idx ) == 0 ) ) {
    return FD_SLOT_NULL;
  }

  fd_block_idx_t lrw_block_idx = { 0 };
  lrw_block_idx.off = blockstore->shmem->archiver.head;
  int err = fd_blockstore_block_meta_restore( &blockstore->shmem->archiver, fd, &lrw_block_idx, lrw_block_meta,  lrw_block_out );
  check_read_write_err( err );
  return lrw_block_meta->slot;
}

bool
fd_blockstore_archiver_verify( fd_blockstore_t * blockstore, fd_blockstore_archiver_t * fd_metadata ) {
  return ( fd_metadata->head < FD_BLOCKSTORE_ARCHIVE_START )
         || ( fd_metadata->tail < FD_BLOCKSTORE_ARCHIVE_START )
         || ( fd_metadata->fd_size_max != blockstore->shmem->archiver.fd_size_max ); // should be initialized same as archive file
}

#define check_read_err_safe( cond, msg )            \
  do {                                              \
    if( FD_UNLIKELY( cond ) ) {                     \
      FD_LOG_WARNING(( "[%s] %s", __func__, msg )); \
      return FD_BLOCKSTORE_ERR_SLOT_MISSING;        \
    }                                               \
  } while(0);

/* Where read_off is where to start reading from */
/* Guarantees that read_off is at the end of what we just finished on return. */
static int read_with_wraparound( fd_blockstore_archiver_t * archvr,
                                 int fd,
                                 uchar * dst,
                                 ulong dst_sz,
                                 ulong * rsz,
                                 ulong * read_off ) {
  check_read_err_safe( lseek( fd, (long)*read_off, SEEK_SET ) == -1,
                       "failed to seek to read offset" );

  ulong remaining_sz = archvr->fd_size_max - *read_off;
  if ( remaining_sz < dst_sz ) {
    int err = fd_io_read( fd, dst, remaining_sz, remaining_sz, rsz );
    check_read_err_safe( err, "failed to read file near end" );
    *read_off = FD_BLOCKSTORE_ARCHIVE_START;
    check_read_err_safe( lseek( fd, (long)*read_off, SEEK_SET ) == -1,
                         "failed to seek to file start" );
    err = fd_io_read( fd, dst + remaining_sz, dst_sz - remaining_sz, dst_sz - remaining_sz, rsz );
    check_read_err_safe( err, "failed to read file near start" );
    *read_off = FD_BLOCKSTORE_ARCHIVE_START + *rsz;
  } else {
    int err = fd_io_read( fd, dst, dst_sz, dst_sz, rsz );
    check_read_err_safe( err, "failed to read file" );
    *read_off += *rsz;
  }
  // if we read to EOF, set read_off ready for next read
  // In reality should never be > blockstore->fd_size_max
  if ( *read_off >= archvr->fd_size_max ) {
    *read_off = FD_BLOCKSTORE_ARCHIVE_START;
  }

  return FD_BLOCKSTORE_OK;
}

static ulong
wrap_offset( fd_blockstore_archiver_t * archvr, ulong off ) {
  if ( off == archvr->fd_size_max ) {
    return FD_BLOCKSTORE_ARCHIVE_START;
  } else if ( off > archvr->fd_size_max ) {
    return FD_BLOCKSTORE_ARCHIVE_START + ( off - archvr->fd_size_max );
  } else {
    return off;
  }
}

/* Build the archival file index */

static inline void FD_FN_UNUSED
build_idx( fd_blockstore_t * blockstore, int fd ) {
  if ( FD_UNLIKELY( fd == -1 ) ) {
    return;
  }

  FD_LOG_NOTICE(( "[%s] building index of blockstore archival file", __func__ ));

  fd_block_idx_t * block_idx = fd_blockstore_block_idx( blockstore );
  fd_block_meta_t block_map_out = { 0 };
  fd_block_t      block_out     = { 0 };

  off_t sz = lseek( fd, 0, SEEK_END );
  if ( FD_UNLIKELY( sz == -1 ) ) {
    FD_LOG_ERR(( "unable to seek to end of archival file %s", strerror( errno ) ));
  } else if ( FD_UNLIKELY( sz == 0 ) ) { /* empty file */
    return;
  }

  lseek( fd, 0, SEEK_SET );
  int err = 0;
  ulong rsz = 0;

  fd_blockstore_archiver_t metadata;
  err = fd_io_read( fd, &metadata, sizeof(fd_blockstore_archiver_t), sizeof(fd_blockstore_archiver_t), &rsz );
  check_read_write_err( err );
  if ( fd_blockstore_archiver_verify( blockstore, &metadata ) ) {
    FD_LOG_ERR(( "[%s] archival file was invalid: blockstore may have been crashed or been killed mid-write.", __func__ ));
    return;
  }

  blockstore->shmem->archiver = metadata;
  ulong off          = metadata.head;
  ulong total_blocks = metadata.num_blocks;
  ulong blocks_read  = 0;

  /* If the file has content, but is perfectly filled, then off == end at the start.
    Then it is impossible to distinguish from an empty file except for num_blocks field. */

  while ( FD_LIKELY( blocks_read < total_blocks ) ) {
    blocks_read++;
    fd_block_idx_t block_idx_entry = { 0 };
    block_idx_entry.off = off;
    err = fd_blockstore_block_meta_restore( &blockstore->shmem->archiver, fd, &block_idx_entry, &block_map_out,  &block_out );
    check_read_write_err( err );

    if( FD_UNLIKELY( fd_block_idx_key_cnt( block_idx ) == fd_block_idx_key_max( block_idx ) )  ) {
      /* evict a block */
      fd_block_meta_t lrw_block_map;
      fd_block_t      lrw_block;
      ulong lrw_slot = fd_blockstore_archiver_lrw_slot( blockstore, fd, &lrw_block_map, &lrw_block );

      fd_block_idx_t * lrw_block_index = fd_block_idx_query( block_idx, lrw_slot, NULL );
      fd_block_idx_remove( block_idx, lrw_block_index );

      blockstore->shmem->archiver.head = wrap_offset(&blockstore->shmem->archiver, blockstore->shmem->archiver.head + lrw_block.data_sz + sizeof(fd_block_map_t) + sizeof(fd_block_t));;
      blockstore->shmem->archiver.num_blocks--;
    }
    fd_block_idx_t * idx_entry = fd_block_idx_query( block_idx, block_map_out.slot, NULL );
    if ( FD_UNLIKELY( idx_entry ) ) {
      FD_LOG_WARNING(( "[%s] archival file contained duplicates of slot %lu", __func__, block_map_out.slot ));
      fd_block_idx_remove( block_idx, idx_entry );
    }

    idx_entry = fd_block_idx_insert( block_idx, block_map_out.slot );
    idx_entry->off             = off;
    idx_entry->block_hash      = block_map_out.block_hash;
    idx_entry->bank_hash       = block_map_out.bank_hash;
    blockstore->shmem->mrw_slot       = block_map_out.slot;

    FD_LOG_NOTICE(( "[%s] read block (%lu/%lu) at offset: %lu. slot no: %lu", __func__, blocks_read, total_blocks, off, block_map_out.slot ));

    /* seek past data */
    off = wrap_offset( &blockstore->shmem->archiver, off + sizeof(fd_block_map_t) + sizeof(fd_block_t) + block_out.data_sz );
    check_read_write_err( lseek( fd, (long)off, SEEK_SET ) == -1);
  }
  FD_LOG_NOTICE(( "[%s] successfully indexed blockstore archival file. entries: %lu", __func__, fd_block_idx_key_cnt( block_idx ) ));
}

fd_blockstore_t *
fd_blockstore_init( fd_blockstore_t * blockstore, int fd, ulong fd_size_max, fd_slot_bank_t const * slot_bank ) {

  if ( fd_size_max < FD_BLOCKSTORE_ARCHIVE_MIN_SIZE ) {
    FD_LOG_ERR(( "archive file size too small" ));
    return NULL;
  }
  blockstore->shmem->archiver.fd_size_max = fd_size_max;

  build_idx( blockstore, fd );
  lseek( fd, 0, SEEK_END );

  /* initialize fields using slot bank */

  ulong smr       = slot_bank->slot;

  blockstore->shmem->lps = smr;
  blockstore->shmem->hcs = smr;
  blockstore->shmem->smr = smr;
  blockstore->shmem->wmk = smr;

  fd_block_map_query_t query[1];

  int err = fd_block_map_prepare( blockstore->block_map, &smr, NULL, query, FD_MAP_FLAG_BLOCKING );
  fd_block_meta_t * ele = fd_block_map_query_ele( query );
  if ( FD_UNLIKELY( err ) ) {
    FD_LOG_ERR(( "failed to prepare block map for slot %lu", smr ));
    return NULL;
  } else {
    ele->slot = smr;
    ele->parent_slot = slot_bank->prev_slot;
    memset( ele->child_slots, UCHAR_MAX, FD_BLOCKSTORE_CHILD_SLOT_MAX * sizeof( ulong ) );
    ele->child_slot_cnt = 0;
    ele->block_height = slot_bank->block_height;
    memcpy( &ele->block_hash, slot_bank->block_hash_queue.last_hash, sizeof(fd_hash_t) );
    ele->bank_hash = slot_bank->banks_hash;
    ele->block_hash = slot_bank->poh;
    ele->flags                      = fd_uchar_set_bit(
                                     fd_uchar_set_bit(
                                     fd_uchar_set_bit(
                                     fd_uchar_set_bit(
                                     fd_uchar_set_bit( ele->flags,
                                       FD_BLOCK_FLAG_COMPLETED ),
                                       FD_BLOCK_FLAG_PROCESSED ),
                                       FD_BLOCK_FLAG_EQVOCSAFE ),
                                       FD_BLOCK_FLAG_CONFIRMED ),
                                       FD_BLOCK_FLAG_FINALIZED );
    ele->reference_tick = 0;
    ele->ts             = 0;

    ele->consumed_idx   = 0;
    ele->received_idx   = 0;
    ele->replayed_idx   = 0;

    ele->data_complete_idx = 0;
    ele->slot_complete_idx = 0;

    fd_block_set_null( ele->data_complete_idxs );

    /* This creates an empty allocation for a block, to "facade" that we
     have this particular block (even though we don't).  This is useful
     to avoid special-casing various blockstore APIs.

     This should only ever be done for the snapshot slot, after booting
     up from the snapshot. */

    fd_block_t * block = fd_alloc_malloc( fd_blockstore_alloc( blockstore ),
                                        alignof(fd_block_t),
                                        sizeof(fd_block_t) );

    /* Point to the fake block. */
  
    ele->block_gaddr = fd_wksp_gaddr_fast( fd_blockstore_wksp( blockstore ), block );
  
    /* Set all fields to 0. Caller's responsibility to check gaddr and sz != 0. */
  
    memset( block, 0, sizeof(fd_block_t) );

    fd_block_map_publish( query );
  }

  return blockstore;
}

void
fd_blockstore_fini( fd_blockstore_t * blockstore FD_PARAM_UNUSED ) {

  /* Free all allocations by removing all slots (whether they are
     complete or not). */

  /*for( fd_block_map_iter_t iter = fd_block_map_iter_init( blockstore->block_map );
       !fd_block_map_iter_done( fd_blockstore_block_map( blockstore ), iter );
       iter = fd_block_map_iter_next( fd_blockstore_block_map( blockstore ), iter ) ) {
    fd_block_map_t * ele = fd_block_map_iter_ele( fd_blockstore_block_map( blockstore ), iter );
    fd_blockstore_slot_remove( blockstore, ele->slot );
  }*/
}

/* txn map helpers */

int
fd_txn_key_equal( fd_txn_key_t const * k0, fd_txn_key_t const * k1 ) {
  for( ulong i = 0; i < FD_ED25519_SIG_SZ / sizeof( ulong ); ++i )
    if( k0->v[i] != k1->v[i] ) return 0;
  return 1;
}

ulong
fd_txn_key_hash( fd_txn_key_t const * k, ulong seed ) {
  ulong h = seed;
  for( ulong i = 0; i < FD_ED25519_SIG_SZ / sizeof( ulong ); ++i )
    h ^= k->v[i];
  return h;
}

void
fd_blockstore_scan_block( fd_blockstore_t * blockstore, ulong slot, fd_block_t * block ) {

  fd_block_micro_t * micros = fd_alloc_malloc( fd_blockstore_alloc( blockstore ),
                                               alignof( fd_block_micro_t ),
                                               sizeof( *micros ) * FD_MICROBLOCK_MAX_PER_SLOT );
  fd_block_txn_t *   txns   = fd_alloc_malloc( fd_blockstore_alloc( blockstore ),
                                               alignof( fd_block_txn_t ),
                                               sizeof( *txns ) * FD_TXN_MAX_PER_SLOT );

  /*
   * Agave decodes precisely one array of microblocks from each batch.
   * As of bincode version 1.3.3, the default deserializer used when
   * decoding a batch in the blockstore allows for trailing bytes to be
   * ignored.
   * https://github.com/anza-xyz/agave/blob/v2.1.0/ledger/src/blockstore.rs#L3764
   */
  uchar allow_trailing = 1UL;

  uchar const * data = fd_blockstore_block_data_laddr( blockstore, block );
  FD_LOG_DEBUG(( "scanning slot %lu, ptr %p, sz %lu", slot, (void *)data, block->data_sz ));

  fd_block_entry_batch_t const * batch_laddr = fd_blockstore_block_batch_laddr( blockstore, block );
  ulong const                    batch_cnt   = block->batch_cnt;

  ulong micros_cnt = 0UL;
  ulong txns_cnt   = 0UL;
  ulong blockoff   = 0UL;
  for( ulong batch_i = 0UL; batch_i < batch_cnt; batch_i++ ) {
    ulong const batch_end_off = batch_laddr[ batch_i ].end_off;
    if( blockoff + sizeof( ulong ) > batch_end_off ) FD_LOG_ERR(( "premature end of batch" ));
    ulong mcount = FD_LOAD( ulong, data + blockoff );
    blockoff += sizeof( ulong );

    /* Loop across microblocks */
    for( ulong mblk = 0; mblk < mcount; ++mblk ) {
      if( blockoff + sizeof( fd_microblock_hdr_t ) > batch_end_off )
        FD_LOG_ERR(( "premature end of batch" ));
      if( micros_cnt < FD_MICROBLOCK_MAX_PER_SLOT ) {
        fd_block_micro_t * m = micros + ( micros_cnt++ );
        m->off               = blockoff;
      }
      fd_microblock_hdr_t * hdr = (fd_microblock_hdr_t *)( data + blockoff );
      blockoff += sizeof( fd_microblock_hdr_t );

      /* Loop across transactions */
      for( ulong txn_idx = 0; txn_idx < hdr->txn_cnt; txn_idx++ ) {
        uchar         txn_out[FD_TXN_MAX_SZ];
        uchar const * raw    = data + blockoff;
        ulong         pay_sz = 0;
        ulong         txn_sz = fd_txn_parse_core( (uchar const *)raw,
                                          fd_ulong_min( batch_end_off - blockoff, FD_TXN_MTU ),
                                          txn_out,
                                          NULL,
                                          &pay_sz );
        if( txn_sz == 0 || txn_sz > FD_TXN_MTU ) {
          FD_LOG_ERR(( "failed to parse transaction %lu in microblock %lu in slot %lu. txn size: %lu",
                        txn_idx,
                        mblk,
                        slot,
                        txn_sz ));
        }
        fd_txn_t const * txn = (fd_txn_t const *)txn_out;

        if( pay_sz == 0UL )
          FD_LOG_ERR(( "failed to parse transaction %lu in microblock %lu in slot %lu",
                        txn_idx,
                        mblk,
                        slot ));

        fd_txn_key_t const * sigs =
            (fd_txn_key_t const *)( (ulong)raw + (ulong)txn->signature_off );
        fd_txn_map_t * txn_map = fd_blockstore_txn_map( blockstore );
        for( ulong j = 0; j < txn->signature_cnt; j++ ) {
          if( FD_UNLIKELY( fd_txn_map_key_cnt( txn_map ) ==
                           fd_txn_map_key_max( txn_map ) ) ) {
            break;
          }
          fd_txn_key_t sig;
          fd_memcpy( &sig, sigs + j, sizeof( sig ) );
          fd_txn_map_t * elem = fd_txn_map_insert( txn_map, &sig );
          if( elem == NULL ) { break; }
          elem->slot       = slot;
          elem->offset     = blockoff;
          elem->sz         = pay_sz;
          elem->meta_gaddr = 0;
          elem->meta_sz    = 0;

          if( txns_cnt < FD_TXN_MAX_PER_SLOT ) {
            fd_block_txn_t * ref = &txns[txns_cnt++];
            ref->txn_off                  = blockoff;
            ref->id_off                   = (ulong)( sigs + j ) - (ulong)data;
            ref->sz                       = pay_sz;
          }
        }

        blockoff += pay_sz;
      }
    }
    if( FD_UNLIKELY( blockoff > batch_end_off ) ) {
      FD_LOG_ERR(( "parser error: shouldn't have been allowed to read past batch boundary" ));
    }
    if( FD_UNLIKELY( blockoff < batch_end_off ) ) {
      if( FD_LIKELY( allow_trailing ) ) {
        FD_LOG_DEBUG(( "ignoring %lu trailing bytes in slot %lu batch %lu", batch_end_off-blockoff, slot, batch_i ));
      }
      if( FD_UNLIKELY( !allow_trailing ) ) {
        FD_LOG_ERR(( "%lu trailing bytes in slot %lu batch %lu", batch_end_off-blockoff, slot, batch_i ));
      }
    }
    blockoff = batch_end_off;
  }

  fd_block_micro_t * micros_laddr =
      fd_alloc_malloc( fd_blockstore_alloc( blockstore ),
                       alignof( fd_block_micro_t ),
                       sizeof( fd_block_micro_t ) * micros_cnt );
  fd_memcpy( micros_laddr, micros, sizeof( fd_block_micro_t ) * micros_cnt );
  block->micros_gaddr = fd_wksp_gaddr_fast( fd_blockstore_wksp( blockstore ), micros_laddr );
  block->micros_cnt   = micros_cnt;

  fd_block_txn_t * txns_laddr =
      fd_alloc_malloc( fd_blockstore_alloc( blockstore ),
                       alignof( fd_block_txn_t ),
                       sizeof( fd_block_txn_t ) * txns_cnt );
  fd_memcpy( txns_laddr, txns, sizeof( fd_block_txn_t ) * txns_cnt );
  block->txns_gaddr = fd_wksp_gaddr_fast( fd_blockstore_wksp( blockstore ), txns_laddr );
  block->txns_cnt   = txns_cnt;

  fd_alloc_free( fd_blockstore_alloc( blockstore ), micros );
  fd_alloc_free( fd_blockstore_alloc( blockstore ), txns );
}

/* Remove a slot from blockstore */
void
fd_blockstore_slot_remove( fd_blockstore_t * blockstore, ulong slot ) {
  FD_LOG_NOTICE(( "[%s] slot: %lu", __func__, slot ));

  fd_block_map_query_t query[1]; 
  int err = fd_block_map_remove( blockstore->block_map, &slot, query, FD_MAP_FLAG_BLOCKING );
  if( FD_UNLIKELY( err ) ) return;

  /* It is not safe to remove a replaying block. */

  fd_block_meta_t * block_map_entry = fd_block_map_query_ele( query );
  if( FD_UNLIKELY( fd_uchar_extract_bit( block_map_entry->flags, FD_BLOCK_FLAG_REPLAYING ) ) ) {
    FD_LOG_WARNING(( "[%s] slot %lu has replay in progress. not removing.", __func__, slot ));
    return;
  }

  /* Unlink slot from its parent only if it is not published. */
  // TODO: no blocking no blocking!!!!
  err = fd_block_map_prepare( blockstore->block_map, &block_map_entry->parent_slot, NULL, query, FD_MAP_FLAG_BLOCKING );
  fd_block_meta_t * parent_block_map_entry = fd_block_map_query_ele( query );
  if( FD_LIKELY( parent_block_map_entry ) ) {
    for( ulong i = 0; i < parent_block_map_entry->child_slot_cnt; i++ ) {
      if( FD_LIKELY( parent_block_map_entry->child_slots[i] == slot ) ) {
        parent_block_map_entry->child_slots[i] =
            parent_block_map_entry->child_slots[--parent_block_map_entry->child_slot_cnt];
      }
    }
    fd_block_map_publish( query );
  }

  /* block_gaddr 0 indicates it hasn't received all shreds yet.

     TODO refactor to use FD_BLOCK_FLAG_COMPLETED. */

  if( FD_LIKELY( block_map_entry->block_gaddr == 0 ) ) {

    /* Remove buf_shreds if there's no block yet (we haven't received all shreds). */

    for( uint idx = 0; idx < block_map_entry->received_idx; idx++ ) {
      fd_blockstore_shred_remove( blockstore, block_map_entry->slot, idx );
    }

    /* Return early because there are no allocations without a block. */

    return;
  }

  /* Remove all the allocations relating to a block. */

  fd_wksp_t *  wksp  = fd_blockstore_wksp( blockstore );
  fd_alloc_t * alloc = fd_blockstore_alloc( blockstore );

  fd_txn_map_t * txn_map = fd_blockstore_txn_map( blockstore );
  fd_block_t *   block   = fd_wksp_laddr_fast( wksp, block_map_entry->block_gaddr );

  /* DO THIS FIRST FOR THREAD SAFETY */
  FD_COMPILER_MFENCE();
  block_map_entry->block_gaddr = 0;

  uchar *              data = fd_wksp_laddr_fast( wksp, block->data_gaddr );
  fd_block_txn_t * txns = fd_wksp_laddr_fast( wksp, block->txns_gaddr );
  for( ulong j = 0; j < block->txns_cnt; ++j ) {
    fd_txn_key_t sig;
    fd_memcpy( &sig, data + txns[j].id_off, sizeof( sig ) );
    fd_txn_map_remove( txn_map, &sig );
  }
  if( block->micros_gaddr ) fd_alloc_free( alloc, fd_wksp_laddr_fast( wksp, block->micros_gaddr ) );
  if( block->txns_gaddr ) fd_alloc_free( alloc, txns );
  ulong mgaddr = block->txns_meta_gaddr;
  while( mgaddr ) {
    ulong * laddr = fd_wksp_laddr_fast( wksp, mgaddr );
    ulong mgaddr2 = laddr[0]; /* link to next allocation */
    fd_alloc_free( alloc, laddr );
    mgaddr = mgaddr2;
  }
  fd_alloc_free( alloc, block );
  return;
}

/** Where write_off is where we want to write to, and we return
    the next valid location to write to (either wraparound, or
    right after where we just wrote ) */
static ulong write_with_wraparound( fd_blockstore_archiver_t * archvr,
                                   int fd,
                                   uchar * src,
                                   ulong src_sz,
                                   ulong write_off ) {

  if ( FD_UNLIKELY( lseek( fd, (long)write_off, SEEK_SET ) == -1 ) ) {
    FD_LOG_ERR(( "[%s] failed to seek to offset %lu", __func__, write_off ));
  }
  ulong wsz;
  ulong remaining_sz = archvr->fd_size_max - write_off;
  if ( remaining_sz < src_sz ) {
    int err = fd_io_write( fd, src, remaining_sz, remaining_sz, &wsz );
    check_read_write_err( err );
    write_off = FD_BLOCKSTORE_ARCHIVE_START;
    if ( FD_UNLIKELY( lseek( fd, (long)write_off, SEEK_SET ) == -1 ) ) {
      FD_LOG_ERR(( "[%s] failed to seek to offset %lu", __func__, write_off ));
    }
    err = fd_io_write( fd, src + remaining_sz, src_sz - remaining_sz, src_sz - remaining_sz, &wsz );
    check_read_write_err( err );
    write_off += wsz;
  } else {
    int err = fd_io_write( fd, src, src_sz, src_sz, &wsz );
    check_read_write_err( err );
    write_off += wsz;
  }
  if ( write_off >= archvr->fd_size_max ) {
    write_off = FD_BLOCKSTORE_ARCHIVE_START;
  }
  return write_off;
}

static void start_archive_write( fd_blockstore_archiver_t * archvr, int fd ) {
  /* Invalidates the blocks that will be overwritten by marking them as free space */
  if ( FD_UNLIKELY( lseek( fd, 0, SEEK_SET ) == -1 ) ) {
    FD_LOG_ERR(( "[%s] failed to seek to start", __func__ ));
  }
  ulong wsz;
  int err = fd_io_write( fd, archvr, sizeof(fd_blockstore_archiver_t), sizeof(fd_blockstore_archiver_t), &wsz );
  check_read_write_err( err );
}

static void end_archive_write( fd_blockstore_archiver_t * archvr,
                               int fd ) {
  if ( FD_UNLIKELY( lseek( fd, 0, SEEK_SET ) == -1 ) ) {
    FD_LOG_ERR(( "[%s] failed to seek to start", __func__ ));
  }
  ulong wsz;
  int err = fd_io_write( fd, archvr, sizeof(fd_blockstore_archiver_t), sizeof(fd_blockstore_archiver_t), &wsz );
  check_read_write_err( err );
}

/* Clears any to be overwritten blocks in the archive from the index and updates archvr */
static void
fd_blockstore_lrw_archive_clear( fd_blockstore_t * blockstore, int fd, ulong wsz, ulong write_off ) {
  fd_blockstore_archiver_t * archvr = &blockstore->shmem->archiver;
  fd_block_idx_t * block_idx        = fd_blockstore_block_idx( blockstore );

  ulong non_wrapped_end = write_off + wsz;
  ulong wrapped_end     = wrap_offset(archvr, non_wrapped_end);
  bool mrw_wraps        = non_wrapped_end > archvr->fd_size_max;

  if ( FD_UNLIKELY( fd_block_idx_key_cnt( block_idx ) == 0 ) ) {
    return;
  }

  fd_block_meta_t lrw_block_map;
  fd_block_t      lrw_block;

  ulong lrw_slot = fd_blockstore_archiver_lrw_slot( blockstore, fd, &lrw_block_map, &lrw_block );
  fd_block_idx_t * lrw_block_index = fd_block_idx_query( block_idx, lrw_slot, NULL );

  while( lrw_block_index &&
        ( ( lrw_block_index->off >= write_off && lrw_block_index->off < non_wrapped_end ) ||
          ( mrw_wraps && lrw_block_index->off < wrapped_end ) ) ){
      /* evict blocks */
      FD_LOG_DEBUG(( "[%s] overwriting lrw block %lu", __func__, lrw_block_map.slot ));
      fd_block_idx_remove( block_idx, lrw_block_index );

      archvr->head = wrap_offset(archvr, archvr->head + lrw_block.data_sz + sizeof(fd_block_map_t) + sizeof(fd_block_t));
      archvr->num_blocks--;

      lrw_slot        = fd_blockstore_archiver_lrw_slot( blockstore, fd, &lrw_block_map, &lrw_block );
      lrw_block_index = fd_block_idx_query(block_idx, lrw_slot, NULL);

      if ( lrw_block_index && (lrw_block_index->off != archvr->head) ){
        FD_LOG_ERR(( "[%s] block index mismatch %lu != %lu", __func__, lrw_block_index->off, archvr->head ));
      }
  }
}

/* Performs any block index & updates mrw after archiving a block. We start guaranteed having */

static void 
fd_blockstore_post_checkpt_update( fd_blockstore_t * blockstore,
                                   fd_blockstore_ser_t * ser,
                                   int fd,
                                   ulong slot,
                                   ulong wsz,
                                   ulong write_off ) {
  fd_blockstore_archiver_t * archvr = &blockstore->shmem->archiver;
  fd_block_idx_t * block_idx        = fd_blockstore_block_idx( blockstore );

  /* Successfully archived block, so update index and offset. */

  if ( fd_block_idx_key_cnt( block_idx ) == fd_block_idx_key_max( block_idx ) ){
    /* make space if needed */
    fd_block_meta_t lrw_block_map_out;
    fd_block_t      lrw_block_out;
    ulong lrw_slot = fd_blockstore_archiver_lrw_slot( blockstore, fd, &lrw_block_map_out, &lrw_block_out );
    fd_block_idx_t * lrw_block_index  = fd_block_idx_query(block_idx, lrw_slot, NULL);
    fd_block_idx_remove( block_idx, lrw_block_index );

    archvr->head = wrap_offset(archvr, archvr->head + lrw_block_out.data_sz + sizeof(fd_block_map_t) + sizeof(fd_block_t));
    archvr->num_blocks--;
  }

  fd_block_idx_t * idx_entry = fd_block_idx_insert( fd_blockstore_block_idx( blockstore ), slot );
  idx_entry->off             = write_off;
  idx_entry->block_hash      = ser->block_map->block_hash;
  idx_entry->bank_hash       = ser->block_map->bank_hash;

  archvr->num_blocks++;
  archvr->tail = wrap_offset( archvr, write_off + wsz);;
  blockstore->shmem->mrw_slot = slot;
}

ulong
fd_blockstore_block_checkpt( fd_blockstore_t * blockstore,
                             fd_blockstore_ser_t * ser,
                             int fd,
                             ulong slot ) {
  ulong write_off = blockstore->shmem->archiver.tail;
  ulong og_write_off = write_off;
  if ( FD_UNLIKELY( fd == -1 ) ) {
    FD_LOG_DEBUG(( "[%s] fd is -1", __func__ ));
    return 0;
  }
  if ( FD_UNLIKELY( lseek( fd, (long)write_off, SEEK_SET ) == -1 ) ) {
    FD_LOG_ERR(( "[%s] failed to seek to offset %lu", __func__, write_off ));
  }

  ulong total_wsz = sizeof(fd_block_map_t) + sizeof(fd_block_t) + ser->block->data_sz;

  /* clear any potential overwrites */
  fd_blockstore_lrw_archive_clear( blockstore, fd, total_wsz, write_off );

  start_archive_write( &blockstore->shmem->archiver, fd );

  write_off = write_with_wraparound( &blockstore->shmem->archiver, fd, (uchar*)ser->block_map, sizeof(fd_block_map_t), write_off );
  write_off = write_with_wraparound( &blockstore->shmem->archiver, fd, (uchar*)ser->block, sizeof(fd_block_t), write_off );
  write_off = write_with_wraparound( &blockstore->shmem->archiver, fd, ser->data, ser->block->data_sz, write_off );

  fd_blockstore_post_checkpt_update( blockstore, ser, fd, slot, total_wsz, og_write_off );

  end_archive_write( &blockstore->shmem->archiver, fd );

  FD_LOG_NOTICE(( "[%s] archived block %lu at %lu: size %lu", __func__, slot, og_write_off, total_wsz ));
  return total_wsz;
}

int
fd_blockstore_block_meta_restore( fd_blockstore_archiver_t * archvr,
                                  int fd,
                                  fd_block_idx_t * block_idx_entry,
                                  fd_block_meta_t * block_map_entry_out,
                                  fd_block_t * block_out ) {
  ulong rsz;
  ulong read_off = block_idx_entry->off;
  int err = read_with_wraparound( archvr,
                                  fd,
                                  (uchar *)fd_type_pun(block_map_entry_out),
                                  sizeof(fd_block_map_t),
                                  &rsz,
                                  &read_off );
  check_read_err_safe( err, "failed to read block map" );
  err = read_with_wraparound( archvr,
                              fd,
                              (uchar *)fd_type_pun(block_out),
                              sizeof(fd_block_t),
                              &rsz,
                              &read_off );
  check_read_err_safe( err, "failed to read block" );
  return FD_BLOCKSTORE_OK;
}

int
fd_blockstore_block_data_restore( fd_blockstore_archiver_t * archvr,
                                  int fd,
                                  fd_block_idx_t * block_idx_entry,
                                  uchar * buf_out,
                                  ulong buf_max,
                                  ulong data_sz ) {
  ulong data_off = wrap_offset(archvr, block_idx_entry->off + sizeof(fd_block_map_t) + sizeof(fd_block_t));
  if( FD_UNLIKELY( buf_max < data_sz ) ) {
    FD_LOG_ERR(( "[%s] data_out_sz %lu < data_sz %lu", __func__, buf_max, data_sz ));
    return -1;
  }
  if( FD_UNLIKELY( lseek( fd, (long)data_off, SEEK_SET ) == -1 ) ) {
    FD_LOG_WARNING(( "failed to seek" ));
    return FD_BLOCKSTORE_ERR_SLOT_MISSING;
  }
  ulong rsz;
  int err = read_with_wraparound( archvr, fd, buf_out, data_sz, &rsz, &data_off );
  check_read_err_safe( err, "failed to read block data" );
  return FD_BLOCKSTORE_OK;
}

void
fd_blockstore_publish( fd_blockstore_t * blockstore, int fd, ulong wmk ) {
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
    int err = fd_block_map_prepare( blockstore->block_map, &slot, NULL, query, FD_MAP_FLAG_BLOCKING );
    if( FD_UNLIKELY( err ) ) {
      FD_LOG_WARNING(( "[%s] failed to prepare block map for blockstore publishing %lu", __func__, slot ));
      continue;
    }
    fd_block_meta_t * block_map_entry = fd_block_map_query_ele( query );

    /* Add slot's children to the queue. */

    for( ulong i = 0; i < block_map_entry->child_slot_cnt; i++ ) {

      /* Stop upon reaching the SMR. */

      if( FD_LIKELY( block_map_entry->child_slots[i] != wmk ) ) {
        fd_slot_deque_push_tail( q, block_map_entry->child_slots[i] );
      }
    }

    /* Archive the block into a file if it is finalized. */

    if( fd_uchar_extract_bit( block_map_entry->flags, FD_BLOCK_FLAG_FINALIZED ) ) {
      fd_block_t * block = fd_wksp_laddr_fast( fd_blockstore_wksp( blockstore ), block_map_entry->block_gaddr );
      uchar * data = fd_wksp_laddr_fast( fd_blockstore_wksp( blockstore ), block->data_gaddr );

      fd_block_idx_t * block_idx = fd_blockstore_block_idx( blockstore );

      if( FD_UNLIKELY( fd_block_idx_query( block_idx, slot, NULL ) ) ) {
        FD_LOG_ERR(( "[%s] invariant violation. attempted to re-archive finalized block: %lu", __func__, slot ));
      } else {
        fd_blockstore_ser_t ser = {
          .block_map = block_map_entry,
          .block     = block,
          .data      = data
        };
        fd_blockstore_block_checkpt( blockstore, &ser, fd, slot );
      }
    }
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
  // if ( fd_buf_shred_pool_verify( blockstore->shred_pool ) != FD_POOL_SUCCESS || fd_buf_shred_map_verify ( blockstore->shred_map  ) != FD_MAP_SUCCESS ) {
  //   FD_LOG_NOTICE(( "slot %lu idx %u", slot, idx ));
  //   __asm__("int $3");
  // }
  fd_shred_key_t key = { slot, idx };

  fd_buf_shred_map_query_t query[1] = { 0 };;
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

/* Deshred into a block once we've received all shreds for a slot. */

static int
deshred( fd_blockstore_t * blockstore, ulong slot ) {
  FD_LOG_NOTICE(( "[%s] slot %lu", __func__, slot ));

  fd_block_map_query_t query[1];
  int err = fd_block_map_prepare( blockstore->block_map, &slot, NULL, query, FD_MAP_FLAG_BLOCKING );
  fd_block_meta_t * block_map_entry = fd_block_map_query_ele( query );
  if( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "[%s] failed to prepare block map for slot %lu", __func__, slot ));

  FD_TEST( block_map_entry->block_gaddr == 0 ); /* FIXME duplicate blocks are not supported */

  block_map_entry->ts = fd_log_wallclock();
  ulong shred_cnt = block_map_entry->slot_complete_idx + 1;
  fd_block_map_publish( query );

  ulong block_sz  = 0UL;
  ulong batch_cnt = 0UL;
  fd_shred_t shred_hdr;
  for( uint idx = 0; idx < shred_cnt; idx++ ) {
    fd_shred_key_t key = { slot, idx };
    int err = FD_MAP_ERR_AGAIN;
    while( err == FD_MAP_ERR_AGAIN ) {
      fd_buf_shred_map_query_t query[1] = { 0 };;
      err = fd_buf_shred_map_query_try( blockstore->shred_map, &key, NULL, query );
      fd_buf_shred_t const * shred = fd_buf_shred_map_query_ele_const( query );
      shred_hdr = shred->hdr;
      err = fd_buf_shred_map_query_test( query );
      if( FD_UNLIKELY( err == FD_MAP_ERR_KEY ) ) FD_LOG_ERR(( "[%s] map missing shred %lu %u while deshredding", __func__, slot, idx ));
      if( FD_UNLIKELY( err == FD_MAP_ERR_CORRUPT ) ) FD_LOG_ERR(( "[%s] map corrupt. shred %lu %u", __func__, slot, idx ));
    }
    FD_TEST( !err );
    block_sz += fd_shred_payload_sz( &shred_hdr );
    if( FD_LIKELY( ( shred_hdr.data.flags & FD_SHRED_DATA_FLAG_SLOT_COMPLETE ) ||
                     shred_hdr.data.flags & FD_SHRED_DATA_FLAG_DATA_COMPLETE ) ) {
      batch_cnt++;
    }
  }

  // alloc mem for the block
  ulong data_off  = fd_ulong_align_up( sizeof(fd_block_t), 128UL );
  ulong shred_off = fd_ulong_align_up( data_off + block_sz, alignof(fd_block_shred_t) );
  ulong batch_off = fd_ulong_align_up( shred_off + (sizeof(fd_block_shred_t) * shred_cnt), alignof(fd_block_entry_batch_t) );
  ulong tot_sz    = batch_off + (sizeof(fd_block_entry_batch_t) * batch_cnt);

  fd_alloc_t * alloc = fd_blockstore_alloc( blockstore );
  fd_wksp_t *  wksp  = fd_blockstore_wksp( blockstore );
  fd_block_t * block = fd_alloc_malloc( alloc, 128UL, tot_sz );
  if( FD_UNLIKELY( !block ) ) {
    FD_LOG_ERR(( "[%s] OOM: failed to alloc block. blockstore needs to hold in memory all blocks for slots >= SMR, so either increase memory or check for issues with publishing new SMRs.", __func__ ));
  }

  fd_memset( block, 0, sizeof(fd_block_t) );

  uchar * data_laddr  = (uchar *)((ulong)block + data_off);
  block->data_gaddr   = fd_wksp_gaddr_fast( wksp, data_laddr );
  block->data_sz      = block_sz;
  fd_block_shred_t * shreds_laddr = (fd_block_shred_t *)((ulong)block + shred_off);
  block->shreds_gaddr = fd_wksp_gaddr_fast( wksp, shreds_laddr );
  block->shreds_cnt   = shred_cnt;
  fd_block_entry_batch_t * batch_laddr = (fd_block_entry_batch_t *)((ulong)block + batch_off);
  block->batch_gaddr = fd_wksp_gaddr_fast( wksp, batch_laddr );
  block->batch_cnt    = batch_cnt;

  ulong off     = 0UL;
  ulong batch_i = 0UL;
  for( uint idx = 0; idx < shred_cnt; idx++ ) {
    // TODO can do this in one iteration with block sz loop... massage with deshredder API
    fd_shred_key_t key        = { slot, idx };
    ulong          payload_sz = 0UL;
    uchar          flags      = 0;
    int err = FD_MAP_ERR_AGAIN;
    while( err == FD_MAP_ERR_AGAIN ) {
      fd_buf_shred_map_query_t query[1] = { 0 };;
      err = fd_buf_shred_map_query_try( blockstore->shred_map, &key, NULL, query );
      fd_shred_t const * shred = &fd_buf_shred_map_query_ele_const( query )->hdr;
      memcpy( data_laddr + off, fd_shred_data_payload( shred ), fd_shred_payload_sz( shred ) );

      shreds_laddr[idx].hdr = *shred;
      shreds_laddr[idx].off = off;
      FD_TEST( 0 == memcmp( &shreds_laddr[idx].hdr, shred, sizeof( fd_shred_t ) ) );
      FD_TEST( 0 == memcmp( data_laddr + shreds_laddr[idx].off, fd_shred_data_payload( shred ), fd_shred_payload_sz( shred ) ) );

      payload_sz = fd_shred_payload_sz( shred );
      flags      = shred->data.flags;

      err = fd_buf_shred_map_query_test( query );
      if( FD_UNLIKELY( err == FD_MAP_ERR_KEY ) ) FD_LOG_ERR(( "[%s] map missing shred %lu %u while deshredding", __func__, slot, idx ));
      if( FD_UNLIKELY( err == FD_MAP_ERR_CORRUPT ) ) FD_LOG_ERR(( "[%s] map corrupt. shred %lu %u", __func__, slot, idx ));
    }
    FD_TEST( !err );
    off += payload_sz;
    if( FD_LIKELY( (flags & FD_SHRED_DATA_FLAG_SLOT_COMPLETE) || flags & FD_SHRED_DATA_FLAG_DATA_COMPLETE ) ) {
      batch_laddr[ batch_i++ ].end_off = off;
    }
    fd_blockstore_shred_remove( blockstore, slot, idx );
  }
  if( FD_UNLIKELY( batch_cnt != batch_i ) ) {
    FD_LOG_ERR(( "batch_cnt(%lu)!=batch_i(%lu) potential memory corruption", batch_cnt, batch_i ));
  }

  fd_blockstore_scan_block( blockstore, slot, block );

  /* Do this last when it's safe */
  FD_COMPILER_MFENCE();
  err = fd_block_map_prepare( blockstore->block_map, &slot, NULL, query, FD_MAP_FLAG_BLOCKING );
  block_map_entry = fd_block_map_query_ele( query );
  block_map_entry->block_gaddr     = fd_wksp_gaddr_fast( wksp, block );
  fd_block_micro_t *    micros     = fd_wksp_laddr_fast( wksp, block->micros_gaddr );
  uchar *               data       = fd_wksp_laddr_fast( wksp, block->data_gaddr );
  fd_microblock_hdr_t * last_micro = (fd_microblock_hdr_t *)( data +
                                                              micros[block->micros_cnt - 1].off );
  memcpy( &block_map_entry->block_hash, last_micro->hash, sizeof( fd_hash_t ) );

  block_map_entry->flags = fd_uchar_clear_bit( block_map_entry->flags, FD_BLOCK_FLAG_RECEIVING );
  block_map_entry->flags = fd_uchar_set_bit( block_map_entry->flags, FD_BLOCK_FLAG_COMPLETED );
  fd_block_map_publish( query );

  return FD_BLOCKSTORE_OK;
}


/* Check if we're seeing a different payload for the same shred key,
   which indicates equivocation. */

FD_FN_UNUSED static int
is_eqvoc_fec( fd_shred_t * old, fd_shred_t const * new ) {
  if( FD_UNLIKELY( fd_shred_type( old->variant ) != fd_shred_type( new->variant ) ) ) {
    FD_LOG_WARNING(( "[%s] shred %lu %u not both resigned", __func__, old->slot, old->idx ));
    return 1;
  }

  if( FD_UNLIKELY( fd_shred_payload_sz( old ) != fd_shred_payload_sz( new ) ) ) {
    FD_LOG_WARNING(( "[%s] shred %lu %u payload_sz not eq", __func__, old->slot, old->idx ));
    return 1;
  }

  ulong memcmp_sz = fd_ulong_if( fd_shred_payload_sz( old ) > FD_SHRED_SIGNATURE_SZ &&
                                     fd_shred_is_resigned( fd_shred_type( old->variant ) ),
                                 fd_shred_payload_sz( old ) - FD_SHRED_SIGNATURE_SZ,
                                 fd_shred_payload_sz( old ) );
  if( FD_UNLIKELY( 0 != memcmp( fd_shred_data_payload( old ), fd_shred_data_payload( new ), memcmp_sz ) ) ) {
    FD_LOG_WARNING(( "[%s] shred %lu %u payload not eq", __func__, old->slot, old->idx ));
    return 1;
  }

  return 0;
}

int
fd_blockstore_shred_insert( fd_blockstore_t * blockstore, fd_shred_t const * shred ) {
  // FD_TEST( fd_buf_shred_pool_verify( blockstore->shred_pool ) == FD_POOL_SUCCESS );
  // FD_TEST( fd_buf_shred_map_verify ( blockstore->shred_map  ) == FD_MAP_SUCCESS );

  /* Check this shred > SMR. We ignore shreds before the SMR because by
     it is invariant that we must have a connected, linear chain for the
     SMR and its ancestors. */

  if( FD_UNLIKELY( shred->slot <= blockstore->shmem->smr ) ) {
    return FD_BLOCKSTORE_OK;
  }

  /* Check if we already have this shred */

  fd_shred_key_t shred_key = { .slot = shred->slot, .idx = shred->idx };

  /* Test if this shred's key is already in the map */

  if( FD_UNLIKELY( fd_blockstore_shred_test( blockstore, shred->slot, shred->idx ) ) ) {

    /* FIXME we currently cannot handle equivocating shreds. */

    // if( FD_UNLIKELY( is_eqvoc_fec( &shred_->hdr, shred ) ) ) {
    //   FD_LOG_WARNING(( "equivocating shred detected %lu %u. halting.", shred->slot, shred->idx ));
    //   return FD_BLOCKSTORE_OK;
    // }

    /* Short-circuit if we already have the shred. */

    return FD_BLOCKSTORE_OK;
  }
  // FD_LOG_NOTICE(( "[%s] slot %lu idx %u", __func__, shred->slot, shred->idx ));

  /* Insert the new shred. */

  int err;
  fd_buf_shred_t * ele = fd_buf_shred_pool_acquire( blockstore->shred_pool, NULL, 1, &err );
  if( FD_UNLIKELY( err == FD_POOL_ERR_EMPTY ) )   FD_LOG_ERR(( "[%s] %s. increase blockstore's shred_max.", __func__, fd_buf_shred_pool_strerror( err ) ));
  if( FD_UNLIKELY( err == FD_POOL_ERR_CORRUPT ) ) FD_LOG_ERR(( "[%s] %s.", __func__, fd_buf_shred_pool_strerror( err ) ));

  ele->key = shred_key;
  ele->hdr = *shred;
  fd_memcpy( &ele->buf, shred, fd_shred_sz( shred ) );
  err = fd_buf_shred_map_insert( blockstore->shred_map, ele, FD_MAP_FLAG_BLOCKING );
  if( FD_UNLIKELY( err == FD_MAP_ERR_INVAL ) ) FD_LOG_ERR(( "[%s] map error. ele not in pool.", __func__ ));
  FD_TEST( !err );

  /* Update shred's associated slot meta */

  ulong slot = shred->slot;
  //fd_block_map_t * block_map = fd_blockstore_block_map( blockstore );
  fd_block_map_query_t query[1];

  if( FD_UNLIKELY( !fd_blockstore_block_map_test( blockstore, slot ) ) ) { // TODO: check fishiness
    /* Prepare will succeed regardless of if the key is in the map or not. It either returns 
       the element at that idx, or it will return a spot to insert new stuff. So we need to check
       if that space is actually unused, to signify that we are adding a new entry. */

    /* Try to insert slot into block_map */

    err = fd_block_map_prepare( blockstore->block_map, &slot, NULL, query, FD_MAP_FLAG_BLOCKING );
    fd_block_meta_t * block_map_entry = fd_block_map_query_ele( query );

    if( FD_UNLIKELY( err == FD_MAP_ERR_FULL )){
      FD_LOG_ERR(( "[%s] OOM: failed to insert new block map entry. blockstore needs to save metadata for all slots >= SMR, so increase memory or check for issues with publishing new SMRs.", __func__ ));
    }

    /* Initialize the block_map_entry. Note some fields are initialized
       to dummy values because we do not have all the necessary metadata
       yet. */

    block_map_entry->slot = block_map_entry->slot;

    block_map_entry->parent_slot = shred->slot - shred->data.parent_off;
    memset( block_map_entry->child_slots, UCHAR_MAX, FD_BLOCKSTORE_CHILD_SLOT_MAX * sizeof(ulong) );
    block_map_entry->child_slot_cnt = 0;

    block_map_entry->block_height         = 0;
    block_map_entry->block_hash     = ( fd_hash_t ){ 0 };
    block_map_entry->bank_hash      = ( fd_hash_t ){ 0 };
    block_map_entry->flags          = fd_uchar_set_bit( 0, FD_BLOCK_FLAG_RECEIVING );
    block_map_entry->ts             = 0;
    block_map_entry->reference_tick = (uchar)( (int)shred->data.flags &
                                               (int)FD_SHRED_DATA_REF_TICK_MASK );
    block_map_entry->consumed_idx   = UINT_MAX;
    block_map_entry->received_idx   = 0;
    block_map_entry->replayed_idx   = UINT_MAX;

    block_map_entry->data_complete_idx = UINT_MAX;
    block_map_entry->slot_complete_idx = UINT_MAX;

    fd_block_set_null( block_map_entry->data_complete_idxs );

    block_map_entry->block_gaddr    = 0;
    fd_block_map_publish( query );
  }

  err = fd_block_map_prepare( blockstore->block_map, &slot, NULL, query, FD_MAP_FLAG_BLOCKING );
  fd_block_meta_t * block_map_entry = fd_block_map_query_ele( query );   /* should be impossible for this to fail */

  FD_LOG_DEBUG(( "shred: (%lu, %u). consumed: %u, received: %u, complete: %u",
                 shred->slot,
                 shred->idx,
                 block_map_entry->consumed_idx,
                 block_map_entry->received_idx,
                 block_map_entry->slot_complete_idx ));

  /* Advance the consumed_idx watermark. */

  uint prev_consumed_idx = block_map_entry->consumed_idx;
  while( FD_LIKELY( fd_blockstore_shred_test( blockstore, slot, block_map_entry->consumed_idx + 1 ) ) ) {
    block_map_entry->consumed_idx++;
  }

  /* Mark the ending shred idxs of entry batches. */

  fd_block_set_insert_if( block_map_entry->data_complete_idxs, shred->data.flags & FD_SHRED_DATA_FLAG_DATA_COMPLETE, shred->idx );

  /* Advance the data_complete_idx watermark using the shreds in between
     the previous consumed_idx and current consumed_idx. */

  for (uint idx = prev_consumed_idx + 1; block_map_entry->consumed_idx != FD_SHRED_IDX_NULL && idx <= block_map_entry->consumed_idx; idx++) {
    if ( FD_UNLIKELY( fd_block_set_test( block_map_entry->data_complete_idxs, idx ) ) ) {
      block_map_entry->data_complete_idx = idx;
    }
  }

  /* Update received_idx and slot_complete_idx.  */

  block_map_entry->received_idx = fd_uint_max( block_map_entry->received_idx, shred->idx + 1 );
  if( FD_UNLIKELY( shred->data.flags & FD_SHRED_DATA_FLAG_SLOT_COMPLETE ) ) {
    // FD_LOG_NOTICE(( "slot %lu %u complete", slot, shred->idx ));
    block_map_entry->slot_complete_idx = shred->idx;
  }

  ulong consumed_idx      = block_map_entry->consumed_idx;
  ulong slot_complete_idx = block_map_entry->slot_complete_idx;
  ulong parent_slot       = block_map_entry->parent_slot;
  fd_block_map_publish( query );

  /* Update ancestry metadata: parent_slot, is_connected, next_slot. */

  err = fd_block_map_prepare( blockstore->block_map, &parent_slot, NULL, query, FD_MAP_FLAG_BLOCKING );
  fd_block_meta_t * parent_block_map_entry = fd_block_map_query_ele( query );

  /* Add this slot to its parent's child slots if not already there. */

  if( FD_LIKELY( parent_block_map_entry ) ) { // TODO: check fishiness
    int found = 0;
    for( ulong i = 0; i < parent_block_map_entry->child_slot_cnt; i++ ) {
      if( FD_LIKELY( parent_block_map_entry->child_slots[i] == slot ) ) {
        found = 1;
        break;
      }
    }
    if( FD_UNLIKELY( !found ) ) {
      if( FD_UNLIKELY( parent_block_map_entry->child_slot_cnt == FD_BLOCKSTORE_CHILD_SLOT_MAX )) {
        FD_LOG_ERR(( "failed to add slot %lu to parent %lu's children. exceeding child slot max",
                      slot,
                      parent_block_map_entry->slot ));
      }
      parent_block_map_entry->child_slots[parent_block_map_entry->child_slot_cnt++] = slot;
    }
  }
  fd_block_map_publish( query );

  // if ( fd_buf_shred_pool_verify( blockstore->shred_pool ) != FD_POOL_SUCCESS || fd_buf_shred_map_verify ( blockstore->shred_map  ) != FD_MAP_SUCCESS ) {
  //   FD_LOG_NOTICE(( "slot %lu idx %u", shred->slot, shred->idx ));
  //   __asm__("int $3");
  // }


  if( FD_LIKELY( consumed_idx == UINT_MAX ||
                 consumed_idx != slot_complete_idx ) ) {
    return FD_BLOCKSTORE_OK;
  }

  /* Received all shreds, so try to assemble a block. */
  FD_LOG_DEBUG(( "received all shreds for slot %lu - now building a block", shred->slot ));

  int rc = deshred( blockstore, shred->slot );

  switch( rc ) {
  case FD_BLOCKSTORE_OK:
    return FD_BLOCKSTORE_OK_SLOT_COMPLETE;
  case FD_BLOCKSTORE_ERR_SLOT_FULL:
    FD_LOG_DEBUG(( "already deshredded slot %lu. ignoring.", shred->slot ));
    return FD_BLOCKSTORE_OK;
  case FD_BLOCKSTORE_ERR_DESHRED_INVALID:
    FD_LOG_DEBUG(( "failed to deshred slot %lu. ignoring.", shred->slot ));
    return FD_BLOCKSTORE_OK;
  default:
    /* FIXME */
    FD_LOG_ERR(( "deshred err %d", rc ));
  }
}

int
fd_blockstore_shred_test( fd_blockstore_t * blockstore, ulong slot, uint idx ) {
  fd_shred_key_t key = { slot, idx };
  fd_buf_shred_map_query_t query[1] = { 0 };

  for(;;) {
    int err = fd_buf_shred_map_query_try( blockstore->shred_map, &key, NULL, query );
    if( FD_UNLIKELY( err == FD_MAP_ERR_CORRUPT ) ) {
      FD_TEST( blockstore->shmem->magic == FD_BLOCKSTORE_MAGIC );
      __asm__("int $3");
      FD_LOG_ERR(( "[%s] slot: %lu idx: %u. %s", __func__, slot, idx, fd_buf_shred_map_strerror( err ) ));
    }
    if( FD_LIKELY( !fd_buf_shred_map_query_test( query ) ) ) return err != FD_MAP_ERR_KEY;
  }
}

int
fd_blockstore_block_map_test( fd_blockstore_t * blockstore, ulong slot ) {
  fd_block_map_query_t query[1] = { 0 };

  for(;;) {
    int err = fd_block_map_query_try( blockstore->block_map, &slot, NULL, query, 0 );
    if( err == FD_MAP_ERR_KEY ) return 0;

    if( FD_LIKELY( !fd_block_map_query_test( query ) ) ) return err != FD_MAP_ERR_KEY;
  }
}

long
fd_buf_shred_query_copy_data( fd_blockstore_t * blockstore, ulong slot, uint idx, void * buf, ulong buf_sz ) {
  if( buf_sz < FD_SHRED_MAX_SZ ) return -1;
  fd_shred_key_t key = { slot, idx };
  ulong          sz  = 0;
  int            err = FD_MAP_ERR_AGAIN;
  while( err == FD_MAP_ERR_AGAIN ) {
    fd_buf_shred_map_query_t query[1] = { 0 };
    err = fd_buf_shred_map_query_try( blockstore->shred_map, &key, NULL, query );
    fd_buf_shred_t const * shred = fd_buf_shred_map_query_ele_const( query );
    sz = fd_shred_sz( &shred->hdr );
    memcpy( buf, shred->buf, sz );
    err = fd_buf_shred_map_query_test( query );
    if( FD_UNLIKELY( err == FD_MAP_ERR_KEY ) ) return -1;
    if( FD_UNLIKELY( err == FD_MAP_ERR_CORRUPT ) ) FD_LOG_ERR(( "[%s] map corrupt. shred %lu %u", __func__, slot, idx ));
  }
  FD_TEST( !err );
  return (long)sz;
}

fd_block_t *
fd_blockstore_block_query( fd_blockstore_t * blockstore, ulong slot ) {
  fd_block_map_t * query = fd_block_map_query( fd_blockstore_block_map( blockstore ), &slot, NULL );
  /* later change this to all shreds recieved */
  if( FD_UNLIKELY( !query || query->block_gaddr == 0 ) ) return NULL;
  return fd_wksp_laddr_fast( fd_blockstore_wksp( blockstore ), query->block_gaddr );
}

int
fd_blockstore_block_hash_query( fd_blockstore_t * blockstore, ulong slot, fd_hash_t * hash_out ) {
  int err = FD_MAP_ERR_AGAIN;
  while( err == FD_MAP_ERR_AGAIN ){
    fd_block_map_query_t query[1] = { 0 };
    err = fd_block_map_query_try( blockstore->block_map, &slot, NULL, query, 0 );
    fd_block_meta_t * block_map_entry = fd_block_map_query_ele( query );

    if( FD_UNLIKELY( err == FD_MAP_ERR_KEY ) ) return FD_BLOCKSTORE_ERR_SLOT_MISSING;

    fd_memcpy( hash_out, &block_map_entry->block_hash, sizeof( fd_hash_t ) );
    err = fd_block_map_query_test( query );

    if( FD_UNLIKELY( err == FD_MAP_ERR_KEY ) ) return FD_BLOCKSTORE_ERR_SLOT_MISSING;
  }
  return FD_BLOCKSTORE_OK;
}

int
fd_blockstore_bank_hash_query( fd_blockstore_t * blockstore, ulong slot, fd_hash_t * hash_out ) {
  int err = FD_MAP_ERR_AGAIN;
  while( err == FD_MAP_ERR_AGAIN ){
    fd_block_map_query_t query[1] = { 0 };
    err = fd_block_map_query_try( blockstore->block_map, &slot, NULL, query, 0 );
    fd_block_meta_t * block_map_entry = fd_block_map_query_ele( query );

    if( FD_UNLIKELY( err == FD_MAP_ERR_KEY ) ) return FD_BLOCKSTORE_ERR_SLOT_MISSING;

    fd_memcpy( hash_out, &block_map_entry->bank_hash, sizeof( fd_hash_t ) );
    err = fd_block_map_query_test( query );

    if( FD_UNLIKELY( err == FD_MAP_ERR_KEY ) ) return FD_BLOCKSTORE_ERR_SLOT_MISSING;
  }
  return FD_BLOCKSTORE_OK;
}

fd_block_map_t *
fd_blockstore_block_map_query_bye( fd_blockstore_t * blockstore, ulong slot ) { /* TODO KMSSSSSS*/
  return fd_block_map_query( fd_blockstore_block_map( blockstore ), &slot, NULL );
}

ulong
fd_blockstore_parent_slot_query( fd_blockstore_t * blockstore, ulong slot ) {
  int err = FD_MAP_ERR_AGAIN;
  ulong parent_slot = FD_SLOT_NULL;
  while( err == FD_MAP_ERR_AGAIN ){
    fd_block_map_query_t query[1] = { 0 };
    err = fd_block_map_query_try( blockstore->block_map, &slot, NULL, query, 0 );
    fd_block_meta_t * block_map_entry = fd_block_map_query_ele( query );

    if( FD_UNLIKELY( err == FD_MAP_ERR_KEY ) ) return FD_SLOT_NULL;
    parent_slot = block_map_entry->parent_slot;
    err = fd_block_map_query_test( query );

    if( FD_UNLIKELY( err == FD_MAP_ERR_KEY ) ) return FD_SLOT_NULL;
  }
  return parent_slot;
}

int
fd_blockstore_batch_query( fd_blockstore_t * blockstore,
                           ulong             slot,
                           uint              batch_idx,
                           ulong             batch_data_max,
                           uchar *           batch_data_out,
                           ulong *           batch_data_sz ) {

  fd_block_map_query_t quer[1] = { 0 };
  int err = fd_block_map_query_try( blockstore->block_map, &slot, NULL, quer, FD_MAP_FLAG_BLOCKING );
  fd_block_meta_t * query = fd_block_map_query_ele( quer );
  if( FD_UNLIKELY( err == FD_MAP_ERR_KEY ) ) return FD_BLOCKSTORE_ERR_SLOT_MISSING;

  if( batch_idx > 0 ) { /* verify that the batch_idx provided is actually the start of a batch */
    fd_block_set_t * data_complete_idxs = query->data_complete_idxs;
    if ( !fd_block_set_test( data_complete_idxs, batch_idx - 1 ) || batch_idx > query->slot_complete_idx ) {
      return FD_BLOCKSTORE_ERR_SHRED_INVALID;
    }
  }
  // end, query_test. TODO: make not blocking 

  ulong mbatch_sz = 0;
  for (uint idx = batch_idx; ; idx++) {
    fd_blockstore_start_read( blockstore );

    /* FIXME assumes only calling when we have a full block */

    fd_block_t * block = fd_blockstore_block_query( blockstore, slot );
    if( FD_UNLIKELY( !block ) ) return FD_BLOCKSTORE_ERR_SLOT_MISSING;

    fd_wksp_t *        wksp   = fd_blockstore_wksp( blockstore );
    fd_block_shred_t * shreds = fd_wksp_laddr_fast( wksp, block->shreds_gaddr );
    uchar *            data   = fd_wksp_laddr_fast( wksp, block->data_gaddr );

    uchar * payload  = data + shreds[idx].off;
    ulong payload_sz = ( idx + 1 != block->shreds_cnt ) ? ( shreds[idx + 1].off - shreds[idx].off )
                                                        : ( block->data_sz - shreds[idx].off );
    int is_batch_end = (shreds[idx].hdr.data.flags & FD_SHRED_DATA_FLAG_DATA_COMPLETE) 
                    || (shreds[idx].hdr.data.flags & FD_SHRED_DATA_FLAG_SLOT_COMPLETE);

    if( FD_UNLIKELY( payload_sz > FD_SHRED_DATA_PAYLOAD_MAX ) ) return FD_BLOCKSTORE_ERR_SHRED_INVALID;
    if( FD_UNLIKELY( mbatch_sz + payload_sz > batch_data_max ) ) return FD_BLOCKSTORE_ERR_NO_MEM;
    fd_memcpy( batch_data_out + mbatch_sz, payload, payload_sz );

    fd_blockstore_end_read( blockstore );

    mbatch_sz += payload_sz;
    if( FD_UNLIKELY( is_batch_end ) ){ 
      /* likely has trailing 0s */
      break;
    }
  }
  *batch_data_sz = mbatch_sz;
  return FD_BLOCKSTORE_OK;
}

int
fd_blockstore_shreds_complete( fd_blockstore_t * blockstore, ulong slot ){
  //fd_block_t * block_exists = fd_blockstore_block_query( blockstore,  slot );

  fd_block_map_query_t query[1];
  int complete = 0;
  int err     = FD_MAP_ERR_AGAIN;
  while( err == FD_MAP_ERR_AGAIN ){
    err = fd_block_map_query_try( blockstore->block_map, &slot, NULL, query, 0 );
    fd_block_meta_t * block_map_entry = fd_block_map_query_ele( query );
    if( FD_UNLIKELY( err == FD_MAP_ERR_KEY ) ) return 0;
    complete = ( block_map_entry->consumed_idx != FD_SHRED_IDX_NULL ) && 
               ( block_map_entry->slot_complete_idx == block_map_entry->consumed_idx );
    err = fd_block_map_query_test( query );
    if( FD_UNLIKELY( err == FD_MAP_ERR_KEY ) ) return 0;
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
fd_blockstore_block_data_query_volatile( fd_blockstore_t *    blockstore,
                                         int                  fd,
                                         ulong                slot,
                                         fd_valloc_t          alloc,
                                         fd_hash_t *          parent_block_hash_out,
                                         fd_block_map_t *     block_map_entry_out,
                                         fd_block_rewards_t * block_rewards_out,
                                         uchar **             block_data_out,
                                         ulong *              block_data_sz_out ) {

  /* WARNING: this code is extremely delicate. Do NOT modify without
     understanding all the invariants. In particular, we must never
     dereference through a corrupt pointer. It's OK for the destination
     data to be overwritten/invalid as long as the memory location is
     valid. As long as we don't crash, we can validate the data after it
     is read. */

  fd_wksp_t *      wksp      = fd_blockstore_wksp( blockstore );
  fd_block_idx_t * block_idx = fd_blockstore_block_idx( blockstore );
  fd_block_idx_t * idx_entry = NULL;

  ulong off = ULONG_MAX;
  for(;;) {
    uint seqnum;
    if( FD_UNLIKELY( fd_rwseq_start_concur_read( &blockstore->shmem->lock, &seqnum ) ) ) continue;
    idx_entry = fd_block_idx_query( block_idx, slot, NULL );
    if( FD_LIKELY( idx_entry ) ) off = idx_entry->off;
    if( FD_UNLIKELY( fd_rwseq_check_concur_read( &blockstore->shmem->lock, seqnum ) ) ) continue;
    else break;
  }

  if ( FD_UNLIKELY( off < ULONG_MAX ) ) { /* optimize for non-archival queries */
    FD_LOG_DEBUG( ( "Querying archive for block %lu", slot ) );
    fd_block_t block_out;
    int err = fd_blockstore_block_meta_restore( &blockstore->shmem->archiver, fd, idx_entry, block_map_entry_out, &block_out );
    if( FD_UNLIKELY( err ) ) {
      return FD_BLOCKSTORE_ERR_SLOT_MISSING;
    }
    uchar * block_data = fd_valloc_malloc( alloc, 128UL, block_out.data_sz );
    err = fd_blockstore_block_data_restore( &blockstore->shmem->archiver,
                                            fd,
                                            idx_entry,
                                            block_data,
                                            block_out.data_sz,
                                            block_out.data_sz);
    if( FD_UNLIKELY( err ) ) {
      return FD_BLOCKSTORE_ERR_SLOT_MISSING;
    }
    fd_block_idx_t * parent_idx_entry = fd_block_idx_query( block_idx, block_map_entry_out->parent_slot, NULL );
    if( FD_UNLIKELY( !parent_idx_entry ) ) {
      return FD_BLOCKSTORE_ERR_SLOT_MISSING;
    }
    *parent_block_hash_out = parent_idx_entry->block_hash;
    *block_map_entry_out   = *block_map_entry_out; /* no op */
    *block_rewards_out     = block_out.rewards;
    *block_data_out        = block_data;
    *block_data_sz_out     = block_out.data_sz;
    return FD_BLOCKSTORE_OK;
  }

  /*fd_block_map_t const * block_map = fd_blockstore_block_map( blockstore );
  uchar * prev_data_out = NULL;
  ulong prev_sz = 0;
  for(;;) {
    uint seqnum;
    if( FD_UNLIKELY( fd_rwseq_start_concur_read( &blockstore->shmem->lock, &seqnum ) ) ) continue;

    fd_block_map_t const * query = fd_block_map_query_safe( block_map, &slot, NULL );
    if( FD_UNLIKELY( !query ) ) return FD_BLOCKSTORE_ERR_SLOT_MISSING;

    memcpy( block_map_entry_out, query, sizeof( fd_block_map_t ) );
    ulong blk_gaddr = query->block_gaddr;
    if( FD_UNLIKELY( !blk_gaddr ) ) return FD_BLOCKSTORE_ERR_SLOT_MISSING;

    if( FD_UNLIKELY( fd_rwseq_check_concur_read( &blockstore->shmem->lock, seqnum ) ) ) continue;

    fd_block_t * blk = fd_wksp_laddr_fast( wksp, blk_gaddr );
    if( block_rewards_out ) memcpy( block_rewards_out, &blk->rewards, sizeof(fd_block_rewards_t) );
    ulong blk_data_gaddr = blk->data_gaddr;
    if( FD_UNLIKELY( !blk_data_gaddr ) ) return FD_BLOCKSTORE_ERR_SLOT_MISSING;
    ulong sz = *block_data_sz_out = blk->data_sz;
    if( sz >= FD_SHRED_MAX_PER_SLOT * FD_SHRED_MAX_SZ ) continue;

    if( FD_UNLIKELY( fd_rwseq_check_concur_read( &blockstore->shmem->lock, seqnum ) ) ) continue;

    uchar * data_out;
    if( prev_sz >= sz ) {
      data_out = prev_data_out;
    } else {
      if( prev_data_out != NULL ) {
        fd_valloc_free( alloc, prev_data_out );
      }
      prev_data_out = data_out = fd_valloc_malloc( alloc, 128UL, sz );
      prev_sz = sz;
    }
    if( FD_UNLIKELY( data_out == NULL ) ) return FD_BLOCKSTORE_ERR_SLOT_MISSING;*/
    /* sets data_out to block data */
    /*ulong    batch_idx = 0;
    ulong     batch_sz = 0;
    ulong total_blk_sz = 0;
    while( batch_idx <= query->slot_complete_idx ){
      int err = fd_blockstore_batch_query( blockstore, 
                                               slot, 
                                               (uint)batch_idx, 
                                               sz - total_blk_sz, 
                                               data_out + total_blk_sz, 
                                               &batch_sz );
      if( FD_UNLIKELY( err ) ) return FD_BLOCKSTORE_ERR_SLOT_MISSING;
      total_blk_sz += batch_sz;

      if( FD_UNLIKELY( batch_idx == 0 ) ){
        batch_idx = fd_block_set_const_iter_init( query->data_complete_idxs ) + 1;
      } else {
        batch_idx = fd_block_set_const_iter_next( query->data_complete_idxs, batch_idx - 1 ) + 1;
      }
    }

    if( FD_UNLIKELY( fd_rwseq_check_concur_read( &blockstore->shmem->lock, seqnum ) ) ) {
      fd_valloc_free( alloc, data_out );
      continue;
    }

    *block_data_out = data_out;
    *block_data_sz_out = total_blk_sz;

    if( parent_block_hash_out ) {
      if(( query = fd_block_map_query_safe( block_map, &block_map_entry_out->parent_slot, NULL )) == NULL ) {
        memset( parent_block_hash_out, 0, sizeof(fd_hash_t) );
      } else {
        fd_memcpy( parent_block_hash_out, query->block_hash.uc, sizeof(fd_hash_t) );

        if( FD_UNLIKELY( fd_rwseq_check_concur_read( &blockstore->shmem->lock, seqnum ) ) ) {
          fd_valloc_free( alloc, data_out );
          continue;
        }
      }
    }

    return FD_BLOCKSTORE_OK;
  }*/
}


int
fd_blockstore_block_map_query_volatile( fd_blockstore_t * blockstore,
                                        int               fd,
                                        ulong             slot,
                                        fd_block_map_t *  block_map_entry_out ) {

  /* WARNING: this code is extremely delicate. Do NOT modify without
     understanding all the invariants. In particular, we must never
     dereference through a corrupt pointer. It's OK for the destination
     data to be overwritten/invalid as long as the memory location is
     valid. As long as we don't crash, we can validate the data after it
     is read. */

  fd_block_idx_t * block_idx = fd_blockstore_block_idx( blockstore );

  ulong off = ULONG_MAX;
  for( ;; ) {
    uint seqnum;
    if( FD_UNLIKELY( fd_rwseq_start_concur_read( &blockstore->shmem->lock, &seqnum ) ) ) continue;
    fd_block_idx_t * idx_entry = fd_block_idx_query( block_idx, slot, NULL );
    if( FD_LIKELY( idx_entry ) ) off = idx_entry->off;
    if( FD_UNLIKELY( fd_rwseq_check_concur_read( &blockstore->shmem->lock, seqnum ) ) ) continue;
    else break;
  }

  if( FD_UNLIKELY( off < ULONG_MAX ) ) { /* optimize for non-archival queries */
    if( FD_UNLIKELY( lseek( fd, (long)off, SEEK_SET ) == -1 ) ) {
      FD_LOG_WARNING(( "failed to seek" ));
      return FD_BLOCKSTORE_ERR_SLOT_MISSING;
    }
    ulong rsz;
    int   err = fd_io_read( fd, block_map_entry_out, sizeof( fd_block_map_t ), sizeof( fd_block_map_t ), &rsz );
    if( FD_UNLIKELY( err ) ) {
      FD_LOG_WARNING(( "failed to read block map entry" ));
      return FD_BLOCKSTORE_ERR_SLOT_MISSING;
    }
    return FD_BLOCKSTORE_OK;
  }

  int err = FD_MAP_ERR_AGAIN;
  while( err == FD_MAP_ERR_AGAIN ) {
    fd_block_map_query_t quer[1] = { 0 };
    err = fd_block_map_query_try( blockstore->block_map, &slot, NULL, quer, 0 );
    fd_block_meta_t const * query = fd_block_map_query_ele_const( quer );
    if( FD_UNLIKELY( err == FD_MAP_ERR_KEY ) ) return FD_BLOCKSTORE_ERR_SLOT_MISSING;

    fd_memcpy( block_map_entry_out, query, sizeof( fd_block_meta_t ) );

    err = fd_block_map_query_test( quer );
    if( FD_UNLIKELY( err == FD_MAP_ERR_KEY ) ) return FD_BLOCKSTORE_ERR_SLOT_MISSING;
  }
  return FD_BLOCKSTORE_OK;
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
  fd_wksp_t * wksp = fd_blockstore_wksp( blockstore );
  fd_txn_map_t * txn_map = fd_blockstore_txn_map( blockstore );

  for(;;) {
    uint seqnum;
    if( FD_UNLIKELY( fd_rwseq_start_concur_read( &blockstore->shmem->lock, &seqnum ) ) ) continue;

    fd_txn_key_t key;
    memcpy( &key, sig, sizeof(key) );
    fd_txn_map_t const * txn_map_entry = fd_txn_map_query_safe( txn_map, &key, NULL );
    if( FD_UNLIKELY( txn_map_entry == NULL ) ) return FD_BLOCKSTORE_ERR_TXN_MISSING;
    memcpy( txn_out, txn_map_entry, sizeof(fd_txn_map_t) );
    if( FD_UNLIKELY( fd_rwseq_check_concur_read( &blockstore->shmem->lock, seqnum ) ) ) continue;
    else break;
  }

  fd_block_idx_t * block_idx = fd_blockstore_block_idx( blockstore );

  ulong off = ULONG_MAX;
  for(;;) {
    uint seqnum;
    if( FD_UNLIKELY( fd_rwseq_start_concur_read( &blockstore->shmem->lock, &seqnum ) ) ) continue;
    fd_block_idx_t * idx_entry = fd_block_idx_query( block_idx, txn_out->slot, NULL );
    if( FD_LIKELY( idx_entry ) ) off = idx_entry->off;
    if( FD_UNLIKELY( fd_rwseq_check_concur_read( &blockstore->shmem->lock, seqnum ) ) ) continue;
    else break;
  }

  if ( FD_UNLIKELY( off < ULONG_MAX ) ) { /* optimize for non-archival */
    if( FD_UNLIKELY( lseek( fd, (long)off, SEEK_SET ) == -1 ) ) {
      FD_LOG_WARNING(( "failed to seek" ));
      return FD_BLOCKSTORE_ERR_SLOT_MISSING;
    }
    fd_block_map_t block_map_entry;
    ulong rsz; int err;
    err = fd_io_read( fd, &block_map_entry, sizeof(fd_block_map_t), sizeof(fd_block_map_t), &rsz );
    check_read_write_err( err );
    err = fd_io_read( fd, txn_data_out, txn_out->sz, txn_out->sz, &rsz );
    check_read_write_err( err );
    err = (int)lseek( fd, (long)off + (long)txn_out->offset, SEEK_SET );
    check_read_write_err( err );
    err = fd_io_read( fd, txn_data_out, txn_out->sz, txn_out->sz, &rsz );
    check_read_write_err( err);
    return FD_BLOCKSTORE_OK;
  }

  for(;;) {
    uint seqnum;
    if( FD_UNLIKELY( fd_rwseq_start_concur_read( &blockstore->shmem->lock, &seqnum ) ) ) continue;

    fd_block_map_t const * query = fd_block_map_query_safe( block_map, &txn_out->slot, NULL );
    if( FD_UNLIKELY( !query ) ) return FD_BLOCKSTORE_ERR_TXN_MISSING;
    ulong blk_gaddr = query->block_gaddr;
    if( FD_UNLIKELY( !blk_gaddr ) ) return FD_BLOCKSTORE_ERR_TXN_MISSING;

    if( FD_UNLIKELY( fd_rwseq_check_concur_read( &blockstore->shmem->lock, seqnum ) ) ) continue;

    fd_block_t * blk = fd_wksp_laddr_fast( wksp, blk_gaddr );
    if( blk_ts ) *blk_ts = query->ts;
    if( blk_flags ) *blk_flags = query->flags;
    ulong ptr = blk->data_gaddr;
    ulong sz = blk->data_sz;
    if( txn_out->offset + txn_out->sz > sz || txn_out->sz > FD_TXN_MTU ) continue;

    if( FD_UNLIKELY( fd_rwseq_check_concur_read( &blockstore->shmem->lock, seqnum ) ) ) continue;

    if( txn_data_out == NULL ) return FD_BLOCKSTORE_OK;
    uchar const * data = fd_wksp_laddr_fast( wksp, ptr );
    fd_memcpy( txn_data_out, data + txn_out->offset, txn_out->sz );

    if( FD_UNLIKELY( fd_rwseq_check_concur_read( &blockstore->shmem->lock, seqnum ) ) ) continue;

    return FD_BLOCKSTORE_OK;
  }
}

void
fd_blockstore_block_height_update( fd_blockstore_t * blockstore, ulong slot, ulong height ) {
  fd_block_map_query_t query[1] = { 0 };
  int err = fd_block_map_prepare( blockstore->block_map, &slot, NULL, query, FD_MAP_FLAG_BLOCKING );
  fd_block_meta_t * block_map_entry = fd_block_map_query_ele( query );
  if( FD_UNLIKELY( err || block_map_entry->slot != slot ) ) return;
  block_map_entry->block_height = height;
  fd_block_map_publish( query );
}

void
fd_blockstore_log_block_status( fd_blockstore_t * blockstore, ulong around_slot ) {
  fd_block_map_query_t query[1] = { 0 };
  uint received_idx = 0;
  uint consumed_idx = 0;
  uint slot_complete_idx = 0;

  for( ulong i = around_slot - 5; i < around_slot + 20; ++i ) {
    int err = FD_MAP_ERR_AGAIN;
    while( err == FD_MAP_ERR_AGAIN ){
      int err = fd_block_map_query_try( blockstore->block_map, &i, NULL, query, 0 );
      fd_block_meta_t * slot_entry = fd_block_map_query_ele( query );
      if( err == FD_MAP_ERR_KEY ) break;
      received_idx = slot_entry->received_idx;
      consumed_idx = slot_entry->consumed_idx;
      slot_complete_idx = slot_entry->slot_complete_idx;
      err = fd_block_map_query_test( query );
      if( err == FD_MAP_ERR_KEY ) break;
    }

    if( err == FD_MAP_ERR_KEY ) continue;
    
    FD_LOG_NOTICE(( "%sslot=%lu received=%u consumed=%u finished=%u",
                    ( i == around_slot ? "*" : " " ),
                    i,
                    received_idx,
                    consumed_idx,
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
  char tmp2[100];
  char tmp3[100];

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

  /*fd_block_map_t * slot_map = fd_blockstore_block_map( blockstore );
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
  ulong data_tot = 0;
  ulong data_max = 0;
  ulong txn_tot = 0;
  ulong txn_max = 0;

  ulong * q = fd_blockstore_slot_deque( blockstore );
  fd_slot_deque_remove_all( q );
  fd_slot_deque_push_tail( q, blockstore->shmem->smr );
  while( !fd_slot_deque_empty( q ) ) {
    ulong curr = fd_slot_deque_pop_head( q );

    fd_block_map_t * block_map_entry = fd_blockstore_block_map_query( blockstore, curr );
    if( FD_UNLIKELY( !block_map_entry || !block_map_entry->block_gaddr ) ) continue;
    fd_block_t * block = fd_wksp_laddr_fast( fd_blockstore_wksp( blockstore ), block_map_entry->block_gaddr );
    if( block->data_gaddr ) {
      block_cnt++;
      data_tot += block->data_sz;
      data_max = fd_ulong_max( data_max, block->data_sz );
      txn_tot += block->txns_cnt;
      txn_max = fd_ulong_max( txn_max, block->txns_cnt );
    }

    ulong * child_slots    = NULL;
    ulong   child_slot_cnt = 0;

/**


static int
fd_blockstore_child_slots_query( fd_blockstore_t * blockstore, ulong slot, ulong ** slots_out, ulong * slot_cnt_out ) {
  fd_block_map_t * query = fd_blockstore_block_map_query( blockstore, slot );
  if( FD_UNLIKELY( !query ) ) return FD_BLOCKSTORE_ERR_SLOT_MISSING;
  *slots_out    = query->child_slots;
  *slot_cnt_out = query->child_slot_cnt;
  return FD_BLOCKSTORE_OK;
}
 */
    int     rc = fd_blockstore_child_slots_query( blockstore, curr, &child_slots, &child_slot_cnt );
    if( FD_UNLIKELY( rc != FD_BLOCKSTORE_OK ) ) {
      continue;
    }

    for( ulong i = 0; i < child_slot_cnt; i++ ) {
      fd_slot_deque_push_tail( q, child_slots[i] );
    }
  }

  if( block_cnt )
    FD_LOG_NOTICE(( "block cnt: %lu, total size: %s, avg size: %s, max size: %s, avg txns per block: %lu, max txns: %lu",
                    block_cnt,
                    fd_smart_size( data_tot, tmp1, sizeof(tmp1) ),
                    fd_smart_size( data_tot/block_cnt, tmp2, sizeof(tmp2) ),
                    fd_smart_size( data_max, tmp3, sizeof(tmp3) ),
                    txn_tot/block_cnt,
                    txn_max ));
}
