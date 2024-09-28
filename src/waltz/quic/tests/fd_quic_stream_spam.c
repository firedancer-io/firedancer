#include "fd_quic_stream_spam.h"
#include "../fd_quic_conn.h"

#define FD_QUIC_STREAM_SPAM_ALIGN (32UL)

ulong
fd_quic_stream_spam_service( fd_quic_conn_t *        conn,
                             fd_quic_stream_spam_t * spam ) {

  ulong streams_sent = 0UL;
  while( conn->state == FD_QUIC_CONN_STATE_ACTIVE ) {
    ulong seq = spam->seq++;

    /* Generate stream payload */
    uchar payload_buf[ FD_TXN_MTU ];
    ulong payload_sz = spam->gen_fn( spam->gen_ctx, payload_buf, seq );

    /* Send data */
    int rc = fd_quic_stream_uni_send( conn, payload_buf, payload_sz );
    if( rc!=FD_QUIC_SUCCESS ) break;

    streams_sent++;
  }

  return streams_sent;
}

ulong
fd_quic_stream_spam_gen( void * ctx,
                         uchar  data[ FD_TXN_MTU ],
                         ulong  seq ) {
  (void)ctx;

  /* Derive random bytes to send */
  fd_rng_t _rng[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, (uint)seq, 0UL ) );

  ulong data_sz = fd_rng_ulong_roll( rng, FD_TXN_MTU );

  for( ulong i=0; i<fd_ulong_align_up( data_sz, 8UL ); i+=8 )
    *(ulong *)( data+i ) = fd_rng_ulong( rng );
  fd_rng_delete( fd_rng_leave( rng ) );

  return data_sz;
}

