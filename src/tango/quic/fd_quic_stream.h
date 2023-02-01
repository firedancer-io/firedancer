#ifndef HEADER_fd_quic_stream_h
#define HEADER_fd_quic_stream_h

#include "../../util/fd_util.h"

/* amount of buffering on TX side of each stream
   also represents the largest buffer that fd_quic_stream_send will accept
   must be <= 32K for the 16-bit head, tail, etc indices */
#define FD_QUIC_MAX_TX_BUF (1u<<12u)

/* forward */
typedef struct fd_quic_conn fd_quic_conn_t;

struct fd_quic_stream {
  fd_quic_conn_t * conn;

  ulong stream_id;                    /* all 1's indicates an unused stream object */
  void *   context;                      /* user context for callbacks */
  uchar    tx_buf[FD_QUIC_MAX_TX_BUF];   /* buffer data to allow resend */
  uchar    tx_ack[FD_QUIC_MAX_TX_BUF/8]; /* tx_ack[i] & (1<<j) indicates tx_buf byte i*8+j
                                            was acked */

  uint flags;   /* some flags */
# define FD_QUIC_STREAM_FLAGS_TX_FIN          (1u<<0u)
# define FD_QUIC_STREAM_FLAGS_RX_FIN          (1u<<1u)
# define FD_QUIC_STREAM_FLAGS_MAX_STREAM_DATA (1u<<2u)

  /* tx_buf is a circular queue
     invariants
       0  <= tx_tail <= tx_sent <= tx_head < 2 * sizeof( tx_buf )
             tx_tail < sizeof( tx_buf )
                          ( tx_head  - tx_tail ) == length of valid data (sent or pending)
                          ( tx_head  - tx_sent ) == length of unsent data
       sizeof( tx_buf ) - ( tx_head  - tx_tail ) == remaining capacity

       queuing moves head up
       sending moves sent up
       acking moves tail up - and adjusts to reestablish invariants

       */
  ushort tx_head; /* first unused byte of tx_buf */
  ushort tx_tail; /* first unacked (used) byte of tx_buf */
  ushort tx_sent; /* first unsent byte of tx_buf */
  ulong tx_offs; /* the offset of the (future) byte at tx_head */
  /* we don't track every ack'ed region
     instead we only process acks for the oldest data
     this limits the amount of bookkeeping required */

  /* flow control */
  ulong   tx_max_stream_data; /* the limit on the number of bytes we are allowed to send
                                  to the peer on this stream
                                  this includes bytes implied by offsets that have not
                                  been received yet */
  ulong   tx_tot_data;        /* the total number of bytes transmitted on this stream */

  ulong   rx_max_stream_data; /* the limit on the number of bytes we allow the peer to
                                  send to us */
  ulong   rx_tot_data;        /* the total number of bytes received on this stream */

  /* last tx packet num with max_stream_data frame refering to this stream
     set to next_pkt_number to indicate a new max_stream_data frame should be sent
     if we time out this packet (or possibly a later packet) we resend the frame
       and update this value */
  ulong upd_pkt_number;

  /* TODO need a timeout on this data */
};
typedef struct fd_quic_stream fd_quic_stream_t;

/* returns the alignment of the fd_quic_stream_t */
FD_FN_CONST inline
ulong
fd_quic_stream_align() {
  return alignof( fd_quic_stream_t );
}

/* returns the required footprint of fd_quic_stream_t */
FD_FN_CONST inline
ulong
fd_quic_stream_footprint() {
  return sizeof( fd_quic_stream_t );
}

#endif

