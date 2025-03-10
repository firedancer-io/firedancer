#include "fd_blockstore_archive.h"
#include <errno.h>
#include <unistd.h>

static inline void check_read_write_err( int err ) {
  if( FD_UNLIKELY( err < 0 ) ) {
    FD_LOG_ERR(( "unexpected EOF %s", strerror( errno ) ));
  }
  if( FD_UNLIKELY( err > 0 ) ) {
    FD_LOG_ERR(( "unable to read/write %s", strerror( errno ) ));
  }
}

#define check_read_err_safe( cond, msg )            \
  do {                                              \
    if( FD_UNLIKELY( cond ) ) {                     \
      FD_LOG_WARNING(( "[%s] %s", __func__, msg )); \
      return FD_BLOCKSTORE_ERR_SLOT_MISSING;        \
    }                                               \
} while(0);

ulong
fd_blockstore_archiver_lrw_slot( fd_blockstore_t * blockstore, int fd, fd_block_info_t * lrw_block_info, fd_block_t * lrw_block_out ) {
  fd_block_idx_t * block_idx = fd_blockstore_block_idx( blockstore );
  if ( FD_UNLIKELY ( fd_block_idx_key_cnt( block_idx ) == 0 ) ) {
    return FD_SLOT_NULL;
  }

  fd_block_idx_t lrw_block_idx = { 0 };
  lrw_block_idx.off = blockstore->shmem->archiver.head;
  int err = fd_blockstore_block_info_restore( &blockstore->shmem->archiver, fd, &lrw_block_idx, lrw_block_info,  lrw_block_out );
  check_read_write_err( err );
  return lrw_block_info->slot;
}

bool
fd_blockstore_archiver_verify( fd_blockstore_t * blockstore, fd_blockstore_archiver_t * fd_metadata ) {
  return ( fd_metadata->head < FD_BLOCKSTORE_ARCHIVE_START )
         || ( fd_metadata->tail < FD_BLOCKSTORE_ARCHIVE_START )
         || ( fd_metadata->fd_size_max != blockstore->shmem->archiver.fd_size_max ); // should be initialized same as archive file
}

/* Where read_off is where to start reading from */
/* Guarantees that read_off is at the end of what we just finished on return. */
static int
read_with_wraparound( fd_blockstore_archiver_t * archvr,
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

  return FD_BLOCKSTORE_SUCCESS;
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
  fd_block_info_t block_map_out = { 0 };
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
    err = fd_blockstore_block_info_restore( &blockstore->shmem->archiver, fd, &block_idx_entry, &block_map_out,  &block_out );
    check_read_write_err( err );

    if( FD_UNLIKELY( fd_block_idx_key_cnt( block_idx ) == fd_block_idx_key_max( block_idx ) )  ) {
      /* evict a block */
      fd_block_info_t lrw_block_map;
      fd_block_t      lrw_block;
      ulong lrw_slot = fd_blockstore_archiver_lrw_slot( blockstore, fd, &lrw_block_map, &lrw_block );

      fd_block_idx_t * lrw_block_index = fd_block_idx_query( block_idx, lrw_slot, NULL );
      fd_block_idx_remove( block_idx, lrw_block_index );

      blockstore->shmem->archiver.head = wrap_offset(&blockstore->shmem->archiver, blockstore->shmem->archiver.head + lrw_block.data_sz + sizeof(fd_block_info_t) + sizeof(fd_block_t));;
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
    off = wrap_offset( &blockstore->shmem->archiver, off + sizeof(fd_block_info_t) + sizeof(fd_block_t) + block_out.data_sz );
    check_read_write_err( lseek( fd, (long)off, SEEK_SET ) == -1);
  }
  FD_LOG_NOTICE(( "[%s] successfully indexed blockstore archival file. entries: %lu", __func__, fd_block_idx_key_cnt( block_idx ) ));
}

/* Where write_off is where we want to write to, and we return
   the next valid location to write to (either wraparound, or
   right after where we just wrote ) */
static ulong
write_with_wraparound( fd_blockstore_archiver_t * archvr,
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

static void
start_archive_write( fd_blockstore_archiver_t * archvr, int fd ) {
  /* Invalidates the blocks that will be overwritten by marking them as free space */
  if ( FD_UNLIKELY( lseek( fd, 0, SEEK_SET ) == -1 ) ) {
    FD_LOG_ERR(( "[%s] failed to seek to start", __func__ ));
  }
  ulong wsz;
  int err = fd_io_write( fd, archvr, sizeof(fd_blockstore_archiver_t), sizeof(fd_blockstore_archiver_t), &wsz );
  check_read_write_err( err );
}

static void
end_archive_write( fd_blockstore_archiver_t * archvr,
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

  fd_block_info_t lrw_block_map;
  fd_block_t      lrw_block;

  ulong lrw_slot = fd_blockstore_archiver_lrw_slot( blockstore, fd, &lrw_block_map, &lrw_block );
  fd_block_idx_t * lrw_block_index = fd_block_idx_query( block_idx, lrw_slot, NULL );

  while( lrw_block_index &&
       ( ( lrw_block_index->off >= write_off && lrw_block_index->off < non_wrapped_end ) ||
       ( mrw_wraps && lrw_block_index->off < wrapped_end ) ) ){
      /* evict blocks */
    FD_LOG_DEBUG(( "[%s] overwriting lrw block %lu", __func__, lrw_block_map.slot ));
    fd_block_idx_remove( block_idx, lrw_block_index );

    archvr->head = wrap_offset(archvr, archvr->head + lrw_block.data_sz + sizeof(fd_block_info_t) + sizeof(fd_block_t));
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
    fd_block_info_t lrw_block_map_out;
    fd_block_t      lrw_block_out;
    ulong lrw_slot = fd_blockstore_archiver_lrw_slot( blockstore, fd, &lrw_block_map_out, &lrw_block_out );
    fd_block_idx_t * lrw_block_index = fd_block_idx_query(block_idx, lrw_slot, NULL);
    fd_block_idx_remove( block_idx, lrw_block_index );

    archvr->head = wrap_offset(archvr, archvr->head + lrw_block_out.data_sz + sizeof(fd_block_info_t) + sizeof(fd_block_t));
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

  ulong total_wsz = sizeof(fd_block_info_t) + sizeof(fd_block_t) + ser->block->data_sz;

  /* clear any potential overwrites */
  fd_blockstore_lrw_archive_clear( blockstore, fd, total_wsz, write_off );

  start_archive_write( &blockstore->shmem->archiver, fd );

  write_off = write_with_wraparound( &blockstore->shmem->archiver, fd, (uchar*)ser->block_map, sizeof(fd_block_info_t), write_off );
  write_off = write_with_wraparound( &blockstore->shmem->archiver, fd, (uchar*)ser->block, sizeof(fd_block_t), write_off );
  write_off = write_with_wraparound( &blockstore->shmem->archiver, fd, ser->data, ser->block->data_sz, write_off );

  fd_blockstore_post_checkpt_update( blockstore, ser, fd, slot, total_wsz, og_write_off );

  end_archive_write( &blockstore->shmem->archiver, fd );

  FD_LOG_NOTICE(( "[%s] archived block %lu at %lu: size %lu", __func__, slot, og_write_off, total_wsz ));
  return total_wsz;
}

int
fd_blockstore_block_info_restore( fd_blockstore_archiver_t * archvr,
                                  int fd,
                                  fd_block_idx_t  * block_idx_entry,
                                  fd_block_info_t * block_info_out,
                                  fd_block_t      * block_out ) {
  ulong rsz;
  ulong read_off = block_idx_entry->off;
  int err = read_with_wraparound( archvr,
                                  fd,
                                  (uchar *)fd_type_pun(block_info_out),
                                  sizeof(fd_block_info_t),
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
  return FD_BLOCKSTORE_SUCCESS;
}

int
fd_blockstore_block_data_restore( fd_blockstore_archiver_t * archvr,
                                  int fd,
                                  fd_block_idx_t * block_idx_entry,
                                  uchar * buf_out,
                                  ulong buf_max,
                                  ulong data_sz ) {
  ulong data_off = wrap_offset(archvr, block_idx_entry->off + sizeof(fd_block_info_t) + sizeof(fd_block_t));
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
  return FD_BLOCKSTORE_SUCCESS;
}

