#ifndef HEADER_fd_src_tango_quic_fd_quic_stream_pool_h
#define HEADER_fd_src_tango_quic_fd_quic_stream_pool_h

#include "fd_quic_stream.h"

/* stream pool alignment */
#define FD_QUIC_STREAM_POOL_ALIGN 128ul

struct fd_quic_stream_pool {
  ulong              cap;     /* the capacity of the pool */
  ulong              cur_cnt; /* the current number of streams in the pool */
  fd_quic_stream_t   head[1]; /* the head of the linked list of free streams, or NULL if none */
};

typedef struct fd_quic_stream_pool fd_quic_stream_pool_t;

FD_PROTOTYPES_BEGIN

/* returns the alignment of the fd_quic_stream_pool_t */
FD_FN_CONST inline
ulong
fd_quic_stream_pool_align( void ) {
  return FD_QUIC_STREAM_POOL_ALIGN;
}

/* returns the required footprint of fd_quic_stream_pool_t

   args
     count        the number of streams the pool will manage */
FD_FN_CONST
ulong
fd_quic_stream_pool_footprint( ulong count, ulong tx_buf_sz );

/* returns a newly initialized stream pool

   args
     mem          the memory aligned to fd_quic_stream_pool_align, and at least fd_quic_stream_pool_footprint
                    bytes
     count        the number of streams the pool will manage
     type         the stream type used for the streams managed by this pool */
fd_quic_stream_pool_t *
fd_quic_stream_pool_new( void * mem, ulong count, ulong tx_buf_sz );

/* delete a stream pool

   this will also delete all the associated streams

   All streams should be freed back to the pool before this function is called

   args
     stream_pool  the stream pool to free */
void
fd_quic_stream_pool_delete( fd_quic_stream_pool_t * stream_pool );

/* allocates a stream from the pool

   args
     stream_pool  the pool from which to obtain the stream

   returns
     the newly allocated stream, or NULL if no streams are available */
fd_quic_stream_t *
fd_quic_stream_pool_alloc( fd_quic_stream_pool_t * pool );

/* free a stream to the specified pool

   args
     stream_pool  the pool to return the stream to
     stream       the stream to return */
void
fd_quic_stream_pool_free( fd_quic_stream_pool_t * pool, fd_quic_stream_t * stream );

FD_PROTOTYPES_END

#endif

