#ifndef HEADER_fd_src_waltz_quic_fd_slow_tx_h
#define HEADER_fd_src_waltz_quic_fd_slow_tx_h

/* fd_slow_tx.h provides APIs for assembling QUIC packets. */

#include "fd_slow_conn.h"
#include "../../tango/mcache/fd_mcache.h"
#include "../../tango/dcache/fd_dcache.h"

/* fd_slow_tx_t takes in outgoing QUIC frames, packs them into QUIC
   packets, and finally encrypts and publishes them to a mcache/dcache
   link. */

struct fd_slow_tx {
  fd_frag_meta_t * mcache;
  uchar *          base;
  ulong *          chunk;
  ulong            chunk0;
  ulong            wmark;

  /* current packet */
  struct {
    uchar *                pkt;
    ulong                  pkt_max; /* excluding MAC tag */
    fd_slow_conn_t const * conn;
  } cur;
};

typedef struct fd_slow_tx fd_slow_tx_t;

FD_PROTOTYPES_BEGIN

fd_slow_tx_t *
fd_slow_tx_new( fd_slow_tx_t *   tx,
                fd_frag_meta_t * mcache,
                uchar *          dcache,
                ulong *          seq_max,
                ulong *          chunk );

/* fd_slow_tx_frame_max_est returns the max QUIC frame size that fits in
   a QUIC packet of size datagram_max.  (Counts bytes part of the UDP
   payload field, excluding UDP or IP headers). */

ulong
fd_slow_tx_frame_max_est( ulong datagram_max );

/* fd_slow_tx_frame_rem returns the remaining frame space in the packet
   currently being built.  This is useful for building packets close to
   MTU size when streaming data. */

ulong
fd_slow_tx_frame_rem( fd_slow_tx_t *         tx,
                      fd_slow_conn_t const * conn );

/* fd_slow_tx_alloc reserves buffer space for an outgoing QUIC frame.
   The caller writes their data into the buffer.  Does not always
   immediately produce a packet in anticipation for more packet data.

   Not flow-controlled, may drop older buffers. */

uchar *
fd_slow_tx_alloc( fd_slow_tx_t *         tx,
                  fd_slow_conn_t const * conn,
                  uint                   enc_level,
                  ulong                  frame_max );

/* fd_slow_tx_commit finishes appending a previous frame. */

ulong
fd_slow_tx_commit( fd_slow_tx_t * tx,
                   ulong          frame_sz );

/* fd_slow_tx_is_dirty returns 1 if not all commits operations have been
   flushed to mcache/dcache, 0 otherwise. */

static inline int
fd_slow_tx_is_dirty( fd_slow_tx_t const * tx ) {
  /* FIXME implement */
  (void)tx;
  return 1;
}

/* fd_slow_tx_flush pushes out any committed frame data as packets.
   No-op if fd_slow_tx_is_dirty returns 0. */

void
fd_slow_tx_flush( fd_slow_tx_t * tx );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_waltz_quic_fd_slow_tx_h */
