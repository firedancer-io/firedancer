#ifndef HEADER_fd_src_waltz_h2_fd_h2_tx_h
#define HEADER_fd_src_waltz_h2_fd_h2_tx_h

/* fd_h2_tx.h helps doing flow-controlled TX work. */

#include "fd_h2_proto.h"

struct fd_h2_tx_op {
  void const * chunk;
  ulong        chunk_sz;
  ulong        fin : 1;
};

typedef struct fd_h2_tx_op fd_h2_tx_op_t;

FD_PROTOTYPES_BEGIN

/* fd_h2_tx_op_init starts a send operation of chunk_sz bytes.  chunk
   points to the buffer to send.  flags==FD_H2_FLAG_END_STREAM closes
   the stream once all DATA frames have been generated.  chunk_sz must
   be non-zero. */

static inline fd_h2_tx_op_t *
fd_h2_tx_op_init( fd_h2_tx_op_t * tx_op,
                  void const *    chunk,
                  ulong           chunk_sz,
                  uint            flags ) {
  *tx_op = (fd_h2_tx_op_t) {
    .chunk    = chunk,
    .chunk_sz = chunk_sz
  };
  if( flags & FD_H2_FLAG_END_STREAM ) tx_op->fin = 1;
  return tx_op;
}

/* fd_h2_tx_op_copy copies as much enqueued tx data out to rbuf_tx as
   possible.  Advances tx_op->chunk and reduces tx_op->chunk_sz.  Stops
   copying when one of the following limits is hit: {rbuf_tx is full,
   out of conn TX quota, out of stream TX quota, no more tx_op bytes
   queued}. */

void
fd_h2_tx_op_copy( fd_h2_conn_t *   conn,
                  fd_h2_stream_t * stream,
                  fd_h2_rbuf_t *   rbuf_tx,
                  fd_h2_tx_op_t *  tx_op );

/* FIXME Add sendmsg-gather API here for streamlined transmit of
   multiple frames via sockets? */

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_waltz_h2_fd_h2_tx_h */
