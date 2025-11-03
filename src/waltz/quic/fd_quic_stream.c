#include "fd_quic_stream.h"
#include "fd_quic_enum.h"

/* buffer helper functions */
/* fd_quic_buffer_store
   store data into circular buffer */
void
fd_quic_buffer_store( fd_quic_buffer_t * buf,
                      uchar const *      data,
                      ulong              data_sz ) {
  /* do we have space to buffer data? */
  /* see fd_quic_stream.h for invariants */
  uchar * raw   = buf->buf;
  ulong   cap   = buf->cap;
  ulong   head  = buf->head;
  ulong   free  = cap - head;

  /* not enough room - caller responsible for checking available space */
  if( data_sz > free ) {
    return;
  }

  fd_memcpy( raw + head, data, data_sz );

  buf->head += data_sz;
}

/* fd_quic_buffer_load
   load data from circular buffer */
void
fd_quic_buffer_load( fd_quic_buffer_t * buf,
                     ulong              offs,
                     uchar *            data,
                     ulong              data_sz ) {
  uchar * raw   = buf->buf;
  ulong   head  = buf->head;

  /* caller responsible for checking operation valid */
  if( FD_UNLIKELY( offs+data_sz > head ) ) return;

  /* two cases:
     1. data fits within free contiguous space at m_tail
     2. data is split

     used is in [offs,head) */

  fd_memcpy( data, raw + offs, data_sz );
}


extern
ulong
fd_quic_stream_align( void );

ulong
fd_quic_stream_footprint( ulong tx_buf_sz ) {
  ulong align           = fd_quic_stream_align();
  ulong offs            = 0ul;

  ulong tx_ack_sz       = (tx_buf_sz >> 3ul)+1UL;
  ulong align_stream_sz = fd_ulong_align_up( sizeof( fd_quic_stream_t ), align );
  ulong align_tx_ack_sz = fd_ulong_align_up( tx_ack_sz, align );
  ulong align_tx_buf_sz = fd_ulong_align_up( tx_buf_sz, align );

  offs += align_stream_sz; /* space for stream instance */
  offs += align_tx_buf_sz; /* space for tx_buf */
  offs += align_tx_ack_sz; /* space for tx_ack */

  return offs;
}

/* returns a newly initialized stream

   args
     mem          the memory aligned to fd_quic_stream_align, and at least fd_quic_stream_footprint
                    bytes
     tx_buf_sz    the size of the tx buffer */
fd_quic_stream_t *
fd_quic_stream_new( void * mem, fd_quic_conn_t * conn, ulong tx_buf_sz ) {
  ulong align = fd_quic_stream_align();

  ulong tx_ack_sz       = (tx_buf_sz >> 3ul)+1UL;
  ulong align_stream_sz = fd_ulong_align_up( sizeof( fd_quic_stream_t ), align );
  ulong align_tx_buf_sz = fd_ulong_align_up( tx_buf_sz, align );
  ulong align_tx_ack_sz = fd_ulong_align_up( tx_ack_sz, align );

  ulong offs = 0;
  ulong base = (ulong)mem;

  /* allocate memory for the stream */
  fd_quic_stream_t * stream = (fd_quic_stream_t*)mem;

  offs += align_stream_sz;

  /* allocate memory for the tx buffer */
  stream->tx_buf.buf = (uchar*)( base + offs );
  stream->tx_buf.cap = tx_buf_sz;

  offs += align_tx_buf_sz;

  /* allocate memory for the tx ack buffer */
  stream->tx_ack = (uchar*)( base + offs );

  offs += align_tx_ack_sz;

  if( offs != fd_quic_stream_footprint( tx_buf_sz ) ) {
    FD_LOG_ERR(( "fd_quic_stream_new : allocated size of stream does not match footprint" ));
  }

  stream->conn      = conn;
  stream->stream_id = FD_QUIC_STREAM_ID_UNUSED;

  /* stream pointing to itself is not a member of any list */
  stream->next = stream->prev = stream;

  return stream;
}

/* delete a stream

   args
     stream       the stream to free */
void
fd_quic_stream_delete( fd_quic_stream_t * stream ) {
  /* stream pointing to itself is not a member of any list */
  stream->next = stream->prev = stream;
  stream->list_memb = FD_QUIC_STREAM_LIST_MEMB_NONE;
}


/* set stream context

   args
     stream      the stream with which to associate the context
     context     the user-defined context associated with the stream */
void
fd_quic_stream_set_context( fd_quic_stream_t * stream, void * context ) {
  stream->context = context;
}


/* get stream context

   args
     stream      the stream from which to obtain the context

   returns
     context     the user defined context associated with the stream */
void *
fd_quic_stream_get_context( fd_quic_stream_t * stream ) {
  return stream->context;
}
