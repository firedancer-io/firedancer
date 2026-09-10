#include "fd_h2_tx.h"
#include "fd_h2_conn.h"
#include "fd_h2_stream.h"

void
fd_h2_tx_op_copy( fd_h2_conn_t *   conn,
                  fd_h2_stream_t * stream,
                  fd_h2_rbuf_t *   rbuf_tx,
                  fd_h2_tx_op_t *  tx_op ) {
  long quota = fd_long_min( conn->tx_wnd, stream->tx_wnd );
  if( FD_UNLIKELY( quota<0L ) ) return;

  if( FD_UNLIKELY( stream->state == FD_H2_STREAM_STATE_CLOSED ) ) return;
  if( FD_UNLIKELY( stream->state != FD_H2_STREAM_STATE_OPEN &&
                   stream->state != FD_H2_STREAM_STATE_CLOSING_RX ) ) {
    return;
  }

  do {
    /* Calculate how much we can send in this frame */
    long const rem_sz    = (long)tx_op->chunk_sz;
    long const buf_spc   = (long)fd_h2_rbuf_free_sz( rbuf_tx ) - (long)sizeof(fd_h2_frame_hdr_t);
    long const frame_max = (long)conn->peer_settings.max_frame_size;

    long payload_sz = fd_long_min( quota, rem_sz );
    /**/ payload_sz = fd_long_min( payload_sz, buf_spc   );
    /**/ payload_sz = fd_long_min( payload_sz, frame_max );
    if( FD_UNLIKELY( payload_sz<=0L ) ) break;
    long const next_rem_sz = rem_sz-payload_sz;

    /* END_STREAM flag */
    uint flags = 0U;
    if( (next_rem_sz==0) & (!!tx_op->fin) ) {
      flags |= FD_H2_FLAG_END_STREAM;
      fd_h2_stream_close_tx( stream, conn );
    }

    fd_h2_tx_prepare( conn, rbuf_tx, FD_H2_FRAME_TYPE_DATA, flags, stream->stream_id );
    fd_h2_rbuf_push( rbuf_tx, tx_op->chunk, (ulong)payload_sz );
    fd_h2_tx_commit( conn, rbuf_tx );

    tx_op->chunk        = (void *)( (ulong)tx_op->chunk + (ulong)payload_sz );
    tx_op->chunk_sz     = (ulong)next_rem_sz;
    conn->tx_wnd       -= (uint)payload_sz;
    stream->tx_wnd     -= (uint)payload_sz;
    quota              -= payload_sz;
  } while( quota );
}
