#ifndef HEADER_fd_src_waltz_quic_fd_quic_tx_buf_h
#define HEADER_fd_src_waltz_quic_fd_quic_tx_buf_h

/* fd_quic_tx_buf.h provides an API to assemble QUIC packets. */

#include "fd_quic_common.h"

/* fd_quic_tx_buf_t is used to assemble an outgoing QUIC packet.

   A tx_buf targets one encryption level of one connection.
   The user appends frames to the tx_buf until it is full.
   Then, headers are prepended and the content is encrypted in-place.

   Suitable for in-place operation.  Does not support concatenation of
   different encryption levels into the same UDP datagram (some clients
   do this to reduce handshake packet count). */

struct fd_quic_tx_buf {

  uchar * buf0;        /* [buf0,buf1) spans the entire buffer */
  uchar * buf1;        /* Includes net hdrs, frames, and MAC tag */

  uchar * frame0;      /* [frame0,frame1) is part of [buf0,buf1) */
  uchar * frame1;      /* Available space for frames */

  uchar * frame_next;  /* Points to next free byte */

  fd_quic_conn_t * conn;         /* Current conn */
  ushort           pkt_len_off;  /* relative to buf0, long header pkt len */
  uchar            enc_level;    /* Encryption level */
  ulong            pktnum;       /* Packet number */

};

typedef struct fd_quic_tx_buf fd_quic_tx_buf_t;

FD_PROTOTYPES_BEGIN

/* fd_quic_tx_buf_init initializes a tx_buf.  Prepares a new empty
   packet for the given QUIC instance, connection, and encryption level. */

fd_quic_tx_buf_t *
fd_quic_tx_buf_init( fd_quic_tx_buf_t * tx_buf,
                     uchar *            buf,
                     ulong              buf_sz,
                     fd_quic_conn_t *   conn,
                     uint               enc_level,
                     ulong              pkt_num );

/* fd_quic_tx_buf_fini turns tx_buf into a packet from IP layer
   upwards.  Returns a non-zero packet length on success.  tx_buf->buf0
   then points to the first byte of the IP header.  The resulting packet
   is ready to be sent over the wire.  On failure, returns zero.  The
   only expected failure reason is that no frames were appended.
   {src,dst}_{ip4,port} specify endpoints in the resulting packet. */

ulong
fd_quic_tx_buf_fini( fd_quic_tx_buf_t * tx_buf,
                     uint               src_ip4,
                     uint               dst_ip4,
                     ushort             src_port,
                     ushort             dst_port );

/* In-place frame publishing

   Typical usage like:
     ulong   max = fd_quic_tx_buf_avail( tx_buf )
     uchar * p   = fd_quic_tx_buf_prepare( tx_buf )
     ulong   sz  = ... calculate frame size up to 'max' ...
     ... encode frame, write to 'p' ...
     fd_quic_tx_buf_commit( tx_buf, sz ) */

/* fd_quic_tx_buf_prepare returns a pointer to where the next encoded
   frame should be placed by the caller.  If no bytes are free, the
   return value is out of bounds. */

static inline uchar *
fd_quic_tx_buf_prepare( fd_quic_tx_buf_t const * tx_buf ) {
  return tx_buf->frame_next;
}

/* fd_quic_tx_buf_avail returns the number of bytes remaining for frame
   data.  Useful in combination with fd_quic_tx_buf_{prepare,commit}. */

static inline ulong
fd_quic_tx_buf_avail( fd_quic_tx_buf_t const * tx_buf ) {
  ulong const frame_next = (ulong)tx_buf->frame_next;
  ulong const frame1     = (ulong)tx_buf->frame1;

  /* Defend against memory corruption */
  if( FD_UNLIKELY( frame_next>frame1 ) ) return 0UL;

  return frame1 - frame_next;
}

/* fd_quic_tx_buf_commit marks the next n bytes starting at prepare()
   as used. */

static inline void
fd_quic_tx_buf_commit( fd_quic_tx_buf_t * tx_buf,
                       ulong              n ) {
  tx_buf->frame_next += n;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_waltz_quic_fd_quic_tx_buf_h */
