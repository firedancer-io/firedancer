#ifndef HEADER_fd_quic_stream_h
#define HEADER_fd_quic_stream_h

#include "fd_quic_common.h"
#include "../../util/fd_util.h"

#define FD_QUIC_STREAM_ID_UNUSED (~0ul)

/* define a circular buffer

   cap is a power of 2
   head, tail are offsets from beginning of stream
     they should be masked before being used to access buf data
   head is first unused byte of stream
   tail is first byte of used range
   cap is capacity of buffer */
struct fd_quic_buffer {
  uchar * buf;
  ulong   cap;
  ulong   head;
  ulong   tail;
};
typedef struct fd_quic_buffer fd_quic_buffer_t;


/* buffer helper functions
   fd_quic_buffer_used  returns bytes used in buffer
   fd_quic_buffer_avail returns bytes available in buffer */
#define fd_quic_buffer_used(  buf ) ( (buf)->head - (buf)->tail )
#define fd_quic_buffer_avail( buf ) ( (buf)->cap - fd_quic_buffer_used(buf) )

/* fd_quic_buffer_store
   store data into cirular buffer */
void
fd_quic_buffer_store( fd_quic_buffer_t * buf,
                      uchar const *      data,
                      ulong              data_sz );

/* fd_quic_buffer_load
   load data from cirular buffer */
void
fd_quic_buffer_load( fd_quic_buffer_t * buf,
                     uchar *            data,
                     ulong              data_sz );

/* forward */
typedef struct fd_quic_conn fd_quic_conn_t;

struct fd_quic_stream {
  fd_quic_conn_t * conn;

  ulong            stream_id;                    /* all 1's indicates an unused stream object */
  void *           context;                      /* user context for callbacks */

  fd_quic_buffer_t tx_buf;                       /* transmit buffer */
  uchar *          tx_ack;                       /* ack - 1 bit per byte of tx_buf */
  ulong            tx_sent;                      /* first unsent byte of tx_buf */

  fd_quic_buffer_t rx_buf;                       /* receive reorder buffer */

  uint flags;   /* flags representing elements that require sending */
# define FD_QUIC_STREAM_FLAGS_TX_FIN          (1u<<0u)
# define FD_QUIC_STREAM_FLAGS_RX_FIN          (1u<<1u)
# define FD_QUIC_STREAM_FLAGS_MAX_STREAM_DATA (1u<<2u)
# define FD_QUIC_STREAM_FLAGS_UNSENT          (1u<<3u)


  /* flow control */
  ulong  tx_max_stream_data; /* the limit on the number of bytes we are allowed to send
                                  to the peer on this stream
                                  this includes bytes implied by offsets that have not
                                  been received yet */
  ulong  tx_tot_data;        /* the total number of bytes transmitted on this stream */

  ulong  rx_max_stream_data; /* the limit on the number of bytes we allow the peer to
                                  send to us */
  ulong  rx_tot_data;        /* the total number of bytes received on this stream */

  /* last tx packet num with max_stream_data frame refering to this stream
     set to next_pkt_number to indicate a new max_stream_data frame should be sent
     if we time out this packet (or possibly a later packet) we resend the frame
       and update this value */
  ulong upd_pkt_number;

  struct fd_quic_stream * next;

  /* TODO need a timeout on this data */
};
typedef struct fd_quic_stream fd_quic_stream_t;

/* returns the alignment of the fd_quic_stream_t */
FD_FN_CONST inline
ulong
fd_quic_stream_align() {
  return 128ul;
}

/* returns the required footprint of fd_quic_stream_t

   args
     tx_buf_sz    the size of the tx buffer
     rx_buf_sz    the size of the rx buffer */
FD_FN_CONST
ulong
fd_quic_stream_footprint( ulong tx_buf_sz, ulong rx_buf_sz );

/* returns a newly initialized stream

   args
     mem          the memory aligned to fd_quic_stream_align, and at least fd_quic_stream_footprint
                    bytes
     tx_buf_sz    the size of the tx buffer
     rx_buf_sz    the size of the rx buffer */
fd_quic_stream_t *
fd_quic_stream_new( void * mem, fd_quic_conn_t * conn,ulong tx_buf_sz, ulong rx_buf_sz );

/* delete a stream

   args
     stream       the stream to free */
void
fd_quic_stream_delete( fd_quic_stream_t * stream );

#endif

