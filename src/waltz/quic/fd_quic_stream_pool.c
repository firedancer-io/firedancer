#include "fd_quic_stream_pool.h"

#include "../../util/fd_util.h"

/* returns the required footprint of fd_quic_stream_pool_t

   args
     count        the number of streams the pool will manage
     tx_buf_sz    the size of the tx buffer
                  should be 0 for RX only streams */
FD_FN_CONST
ulong
fd_quic_stream_pool_footprint( ulong count, ulong tx_buf_sz ) {
  ulong foot =  fd_ulong_align_up( sizeof( fd_quic_stream_pool_t ),
      FD_QUIC_STREAM_POOL_ALIGN );

  ulong stream_foot = fd_quic_stream_footprint( tx_buf_sz );

  return foot + stream_foot * count;
}

/* returns a newly initialized stream pool

   args
     mem          the memory aligned to fd_quic_stream_pool_align, and at least fd_quic_stream_pool_footprint
                    bytes
     count        the number of streams the pool will manage
     type         the stream type used for the streams managed by this pool */
fd_quic_stream_pool_t *
fd_quic_stream_pool_new( void * mem, ulong count, ulong tx_buf_sz ) {
  ulong offs   = 0;
  ulong ul_mem = (ulong)mem;

  fd_quic_stream_pool_t * pool = (fd_quic_stream_pool_t*)ul_mem;
  memset( pool, 0, sizeof( fd_quic_stream_pool_t ) );

  pool->cap     = count;
  pool->cur_cnt = 0UL;

  offs += fd_ulong_align_up( sizeof( fd_quic_stream_pool_t ), FD_QUIC_STREAM_POOL_ALIGN );

  ulong stream_foot = fd_quic_stream_footprint( tx_buf_sz );

  FD_QUIC_STREAM_LIST_SENTINEL( pool->head );

  /* allocate count streams */
  for( ulong j = 0; j < count; ++j ) {
    fd_quic_stream_t * stream = fd_quic_stream_new( (void*)( ul_mem + offs ), NULL, tx_buf_sz );

    FD_QUIC_STREAM_LIST_INIT_STREAM( stream );
    FD_QUIC_STREAM_LIST_INSERT_BEFORE( pool->head, stream );
    pool->cur_cnt++;

    offs += stream_foot;

  }

  return pool;
}


/* delete a stream pool

   this will also delete all the associated streams

   All streams should be freed back to the pool before this function is called

   args
     stream_pool  the stream pool to free */
void
fd_quic_stream_pool_delete( fd_quic_stream_pool_t * stream_pool ) {
  (void)stream_pool;
}


/* allocates a stream from the pool 

   args
     stream_pool  the pool from which to obtain the stream

   returns
     the newly allocated stream, or NULL if no streams are available */
fd_quic_stream_t *
fd_quic_stream_pool_alloc( fd_quic_stream_pool_t * pool ) {
  fd_quic_stream_t * stream_sentinel = pool->head;
  fd_quic_stream_t * stream          = stream_sentinel->next;

  if( FD_UNLIKELY( stream == stream_sentinel ) ) {
    /* no streams left in free list, return NULL */
    return NULL;
  }

  /* remove from free list */
  FD_QUIC_STREAM_LIST_REMOVE( stream );
  pool->cur_cnt--;

  return stream;
}

/* free a stream to the specified pool

   args
     stream_pool  the pool to return the stream to
     stream       the stream to return */
void
fd_quic_stream_pool_free( fd_quic_stream_pool_t * pool,
                          fd_quic_stream_t *      stream ) {
  FD_QUIC_STREAM_LIST_INSERT_BEFORE( pool->head, stream );
  pool->cur_cnt++;
}


