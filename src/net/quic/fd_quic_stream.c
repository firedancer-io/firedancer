#include "fd_quic_stream.h"

extern
ulong
fd_quic_stream_align();

ulong
fd_quic_stream_footprint( ulong tx_buf_sz, ulong rx_buf_sz ) {
  ulong align           = fd_quic_stream_align();
  ulong offs            = 0ul;

  ulong tx_ack_sz       = tx_buf_sz >> 3ul;
  ulong align_stream_sz = FD_QUIC_POW2_ALIGN( sizeof( fd_quic_stream_t ), align );
  ulong align_tx_ack_sz = FD_QUIC_POW2_ALIGN( tx_ack_sz, align );
  ulong align_tx_buf_sz = FD_QUIC_POW2_ALIGN( tx_buf_sz, align );
  ulong align_rx_buf_sz = FD_QUIC_POW2_ALIGN( rx_buf_sz, align );

  offs += align_stream_sz; /* space for stream instance */
  offs += align_tx_buf_sz; /* space for tx_buf */
  offs += align_tx_ack_sz; /* space for tx_ack */
  offs += align_rx_buf_sz; /* space for rx_buf */

  return offs;
}

/* returns a newly initialized stream

   args
     mem          the memory aligned to fd_quic_stream_align, and at least fd_quic_stream_footprint
                    bytes
     tx_buf_sz    the size of the tx buffer
     rx_buf_sz    the size of the rx buffer */
fd_quic_stream_t *
fd_quic_stream_new( void * mem, fd_quic_conn_t * conn, ulong tx_buf_sz, ulong rx_buf_sz ) {
  ulong align = fd_quic_stream_align();

  ulong tx_ack_sz       = tx_buf_sz >> 3ul;
  ulong align_stream_sz = FD_QUIC_POW2_ALIGN( sizeof( fd_quic_stream_t ), align );
  ulong align_tx_buf_sz = FD_QUIC_POW2_ALIGN( tx_buf_sz, align );
  ulong align_tx_ack_sz = FD_QUIC_POW2_ALIGN( tx_ack_sz, align );
  ulong align_rx_buf_sz = FD_QUIC_POW2_ALIGN( rx_buf_sz, align );

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

  /* allocate memory for the rx buffer */
  stream->rx_buf.buf = (uchar*)( base + offs );
  stream->rx_buf.cap = rx_buf_sz;
  
  offs += align_rx_buf_sz;

  if( offs != fd_quic_stream_footprint( tx_buf_sz, rx_buf_sz ) ) {
    FD_LOG_ERR(( "fd_quic_stream_new : allocated size of stream does not match footprint" ));
  }

  stream->conn      = conn;
  stream->stream_id = FD_QUIC_STREAM_ID_UNUSED;

  return stream;
}

/* delete a stream

   args
     stream       the stream to free */
void
fd_quic_stream_delete( fd_quic_stream_t * stream ) {
  /* nothing to do */
  (void)stream;
}
