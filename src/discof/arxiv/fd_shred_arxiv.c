#include "fd_shred_arxiv.h"
#include <unistd.h>
#include <errno.h>

void *
fd_shred_arxiv_new( void * shmem, ulong fd_size_max ) {
  if ( fd_size_max < FD_SHRED_ARXIV_MIN_SIZE ) {
    FD_LOG_ERR(( "archive file size too small" ));
    return NULL;
  }

  ulong shred_max = fd_size_max / FD_SHRED_ARXIV_UNIT_SZ;

  fd_shred_arxiver_t * arxiver = (fd_shred_arxiver_t *)shmem;
  if( FD_UNLIKELY( !arxiver ) ) {
    FD_LOG_WARNING(( "NULL arxiver" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned((ulong)arxiver, fd_shred_arxiv_align() ) )) {
    FD_LOG_WARNING(( "misaligned arxiver" ));
    return NULL;
  }

  fd_memset( arxiver, 0, fd_shred_arxiv_footprint( fd_size_max ) );

  int lg_shred_max = fd_ulong_find_msb( fd_ulong_pow2_up( shred_max ) ) + 1;

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  arxiver = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_shred_arxiver_t), sizeof(fd_shred_arxiver_t) );
  void * shred_idx = FD_SCRATCH_ALLOC_APPEND( l, fd_shred_idx_align(), fd_shred_idx_footprint( lg_shred_max ) );
  void * shred_off = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_shred_off_t), shred_max * sizeof(fd_shred_off_t) );
  ulong top = FD_SCRATCH_ALLOC_FINI( l, fd_shred_arxiv_align() );
  FD_TEST( top - (ulong)shmem == fd_shred_arxiv_footprint( fd_size_max ) );

  fd_memset( shred_off, 0, shred_max * sizeof(fd_shred_off_t) );

  arxiver->shred_idx   = fd_shred_idx_new( shred_idx, lg_shred_max );
  arxiver->shred_off   = (fd_shred_off_t *)shred_off;
  arxiver->fd_size_max = fd_size_max;
  arxiver->shred_max   = shred_max;
  return (void *)arxiver;
}

fd_shred_arxiver_t *
fd_shred_arxiv_join( void * shmem ) {
  fd_shred_arxiver_t * arxiver = (fd_shred_arxiver_t *)shmem;
  if( FD_UNLIKELY( !arxiver ) ) {
    FD_LOG_WARNING(( "NULL arxiver" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned((ulong)arxiver, fd_shred_arxiv_align() ) )) {
    FD_LOG_WARNING(( "misaligned arxiver" ));
    return NULL;
  }
  arxiver->shred_idx = fd_shred_idx_join( arxiver->shred_idx );

  return arxiver;
}

void *
fd_shred_arxiv_leave( fd_shred_arxiver_t * arxiver ) {
  if( FD_UNLIKELY( !arxiver ) ) {
    FD_LOG_WARNING(( "NULL arxiver" ));
    return NULL;
  }

  fd_shred_idx_leave( arxiver->shred_idx );
  return (void *)arxiver;
}

void *
fd_shred_arxiv_delete( void * shmem ) {
  fd_shred_arxiver_t * arxiver = (fd_shred_arxiver_t *)shmem;
  if( FD_UNLIKELY( !arxiver ) ) {
    FD_LOG_WARNING(( "NULL arxiver" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned((ulong)arxiver, fd_shred_arxiv_align() ) )) {
    FD_LOG_WARNING(( "misaligned arxiver" ));
    return NULL;
  }

  fd_shred_idx_delete( arxiver->shred_idx );
  return (void *)arxiver;
}

static inline ulong
shred_off_get( fd_shred_arxiver_t * arxiv,
               ulong off ) {
  ulong idx = off / FD_SHRED_ARXIV_UNIT_SZ;
  return arxiv->shred_off[idx].key;
}

static void
prepare_write( fd_shred_arxiver_t * arxiv ) {
  if( FD_UNLIKELY( arxiv->tail >= arxiv->fd_size_max ) ) {
    arxiv->tail = 0;
  }

  ulong shred_key = shred_off_get( arxiv, arxiv->tail );
  if( shred_key != 0 ) {
    /* Overwriting something, so we need to evict this one. */
    fd_shred_idx_t * idx = fd_shred_idx_query( arxiv->shred_idx, shred_key, NULL );
    FD_TEST( idx );
    fd_shred_idx_remove( arxiv->shred_idx, idx );
    arxiv->shred_off[arxiv->tail / FD_SHRED_ARXIV_UNIT_SZ].key = 0;
  }
}

static int
shred_write( fd_shred_arxiver_t * arxiv,
             fd_shred_t        * shred ) {
  ulong write_off = arxiv->tail;
  if ( FD_UNLIKELY( lseek( arxiv->fd, (long)write_off, SEEK_SET ) == -1 ) ) {
    FD_LOG_ERR(( "[%s] failed to seek to offset %lu", __func__, write_off ));
  }
  ulong wsz;
  int err = fd_io_write( arxiv->fd, shred, fd_shred_sz( shred ), fd_shred_sz( shred ), &wsz );
  return err;
}

/* there's an extra subtlety where if we try to checkpt something
    but it's not successful, we evict first, in the spirit of invalidating
    the metadata first before updating the file. */
void
fd_shreds_checkpt( fd_shred_arxiver_t * arxiv,
                   fd_blockstore_t    * blockstore,
                   ulong slot,
                   uint  start_idx,
                   uint  end_idx /* inclusive */ ) {
  for( uint i = start_idx; i <= end_idx; i++ ) {
    fd_shred_key_t buf_key   = { slot, i };
    ulong          arxiv_key = slot << 32 | i;

    fd_shred_idx_t * idx = fd_shred_idx_query( arxiv->shred_idx, arxiv_key, NULL );
    if( FD_UNLIKELY( idx ) ){
      FD_LOG_WARNING(( "[%s] shred idx %lu %u already exists", __func__, slot, i ));
      continue;
    }

    prepare_write( arxiv );
    ulong wsz     = 0;
    int   success = 0;

    for(;;){
      success = 0;
      fd_buf_shred_map_query_t query[1] = { 0 };
      int err = fd_buf_shred_map_query_try( blockstore->shred_map, &buf_key, NULL, query );
      if( FD_UNLIKELY( err == FD_MAP_ERR_KEY ) ) {
        FD_LOG_WARNING(( "[%s] key: (%lu, %u) %s", __func__, slot, i, fd_buf_shred_map_strerror( err ) ));
        break;
      }
      if( FD_UNLIKELY( err == FD_MAP_ERR_AGAIN ) ) continue;
      fd_buf_shred_t * buf_shred = fd_buf_shred_map_query_ele( query );
      fd_shred_t * shred = (fd_shred_t *)buf_shred->buf;

      int werr = shred_write( arxiv, shred );
      (void)werr;
      wsz     = fd_shred_sz( shred );
      success = 1;

      err = fd_buf_shred_map_query_test( query );
      if( FD_LIKELY( err == FD_MAP_SUCCESS) ) break;
    }

    if( FD_UNLIKELY( !success ) ) continue;

    idx = fd_shred_idx_insert( arxiv->shred_idx, arxiv_key );
    idx->off = arxiv->tail;
    idx->sz  = wsz;

    arxiv->shred_off[arxiv->tail / FD_SHRED_ARXIV_UNIT_SZ].key = arxiv_key;
    arxiv->tail += FD_SHRED_ARXIV_UNIT_SZ;

    /* remove shred from buf_shred map */
    fd_blockstore_shred_remove( blockstore, slot, i );
  }
}

static int
shred_read( fd_shred_arxiver_t * arxiv,
             fd_shred_idx_t    * shred_idx,
             uchar             * buf_out,
             ulong               buf_max,
             ulong             * rsz ) {
  ulong read_off = shred_idx->off;
  if( shred_idx->sz > buf_max ) {
    FD_LOG_WARNING(( "[%s] buffer size %lu < shred size %lu", __func__, buf_max, shred_idx->sz ));
    return -1;
  }
  if ( FD_UNLIKELY( lseek( arxiv->fd, (long)read_off, SEEK_SET ) == -1 ) ) {
    FD_LOG_ERR(( "[%s] failed to seek to offset %lu", __func__, read_off ));
  }
  int err = fd_io_read( arxiv->fd, buf_out, shred_idx->sz, shred_idx->sz, rsz );
  return err;
}

static int FD_FN_UNUSED
shred_payload_read( fd_shred_arxiver_t * arxiv,
                   fd_shred_idx_t * shred_idx,
                   uchar * buf_out,
                   ulong buf_max ) {
  ulong read_off = shred_idx->off + FD_SHRED_DATA_HEADER_SZ;
  ulong pay_sz  = shred_idx->sz - FD_SHRED_DATA_HEADER_SZ;
  if( pay_sz > buf_max ) {
    FD_LOG_WARNING(( "[%s] buffer size %lu < shred size %lu", __func__, buf_max, pay_sz ));
    return -1;
  }
  ulong rsz;
  if ( FD_UNLIKELY( lseek( arxiv->fd, (long)read_off, SEEK_SET ) == -1 ) ) {
    FD_LOG_ERR(( "[%s] failed to seek to offset %lu", __func__, read_off ));
  }
  int err = fd_io_read( arxiv->fd, buf_out, pay_sz, pay_sz, &rsz );
  return err;
}

int
fd_shred_restore( fd_shred_arxiver_t * arxiv,
                   fd_shred_idx_t * shred_idx,
                   uchar * buf_out,
                   ulong buf_max ) {
  ulong rsz;
  int err = shred_read( arxiv, shred_idx, buf_out, buf_max, &rsz );
  return err;
}

int
fd_shred_arxiv_verify( fd_shred_arxiver_t * arxiv ){
  ulong total_stored = 0;
  for( ulong i = 0; i < arxiv->shred_max; i++ ) {
    fd_shred_off_t * off = &arxiv->shred_off[i];
    if( off->key == 0 ) continue;
    fd_shred_idx_t * idx = fd_shred_idx_query( arxiv->shred_idx, off->key, NULL );
    if( FD_UNLIKELY( !idx ) ) {
      return -1;
    }
    total_stored++;
  }
  if( FD_UNLIKELY( total_stored != fd_shred_idx_key_cnt( arxiv->shred_idx ) ) ) {
    return -1;
  }
  return 0;
}

