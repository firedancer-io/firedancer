#include "fd_quic_stream_spam.h"

void *
fd_quic_stream_spam_new( void *                    mem,
                         fd_quic_stream_gen_spam_t gen_fn,
                         void *                    gen_ctx ){

  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, alignof(fd_quic_stream_spam_t) ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  fd_quic_stream_spam_t * spam = mem;
  memset( spam, 0, sizeof(fd_quic_stream_spam_t) );
  spam->gen_fn  = gen_fn;
  spam->gen_ctx = gen_ctx;

  return (void *)spam;
}

fd_quic_stream_spam_t *
fd_quic_stream_spam_join( void * shspam ) {

  if( FD_UNLIKELY( !shspam ) ) {
    FD_LOG_WARNING(( "NULL shspam" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shspam, alignof(fd_quic_stream_spam_t) ) ) ) {
    FD_LOG_WARNING(( "misaligned shspam" ));
    return NULL;
  }

  return (fd_quic_stream_spam_t *)shspam;
}

void *
fd_quic_stream_spam_leave( fd_quic_stream_spam_t * spam ) {
  return (void *)spam;
}

void *
fd_quic_stream_spam_delete( void * shspam ) {
  return shspam;
}

long
fd_quic_stream_spam_service( fd_quic_conn_t *        conn,
                             fd_quic_stream_spam_t * spam ) {

  long streams_sent = 0L;
  for(;;) {

    fd_quic_stream_t * stream = spam->stream;
    if( !stream ) stream = fd_quic_conn_new_stream( conn );
    if( !stream ) break;
    ulong stream_id = stream->stream_id;
    spam->stream = NULL;

    /* Generate stream payload */
    uchar payload_buf[ 4096UL ];
    fd_aio_pkt_info_t batch[1] = { { .buf=payload_buf, .buf_sz=4096UL } };
    spam->gen_fn( /* ctx */ NULL, &batch[ 0 ], stream );

    /* Send data */
    int rc = fd_quic_stream_send( stream, payload_buf, batch->buf_sz, /* fin */ 1 );
    if( rc==FD_QUIC_SUCCESS ) {
      /* Stream send successful, close triggered via fin bit */
      //FD_LOG_DEBUG(( "sent stream=%lu sz=%u", stream_id, batch->buf_sz ));
      streams_sent++;
      break;
    } else {
      if( FD_UNLIKELY( rc!=FD_QUIC_SEND_ERR_FLOW ) ) {
        FD_LOG_WARNING(( "failed to send stream=%lu error=%d", stream_id, rc ));
        streams_sent = -1L;
        /* FIXME Ensure stuck stream is freed */
      } else {
        spam->stream = stream;
      }
      goto fin;
    }

  }

fin:
  return streams_sent;
}

void
fd_quic_stream_spam_notify( fd_quic_stream_t * stream,
                            void *             stream_ctx,
                            int                notify_type ) {

  /* Stream is about to be deallocated */

  (void)stream;
  (void)notify_type;

  /* Nothing to do for completed streams */
  if( FD_LIKELY( !stream_ctx ) ) return;

  /* Stream still is still in pending stack.  ctx points to position in
     pending list.  Mark it as a "tombstone" so it's skipped when
     unwinding the pending stack. */
  fd_quic_stream_t ** slot = (fd_quic_stream_t **)stream_ctx;
  *slot = NULL;
}

void
fd_quic_stream_spam_gen( void *              ctx,
                         fd_aio_pkt_info_t * pkt,
                         fd_quic_stream_t *  stream ) {
  (void)ctx;

  /* Derive random bytes to send */
  fd_rng_t _rng[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, (uint)stream->stream_id, 0UL ) );

  ulong data_sz = fd_rng_ulong_roll( rng, pkt->buf_sz );
  pkt->buf_sz   = (ushort)data_sz;

  for( ulong i=0; i<fd_ulong_align_up( data_sz, 8UL ); i+=8 )
    *(ulong *)( (uchar *)pkt->buf+i ) = fd_rng_ulong( rng );
  fd_rng_delete( fd_rng_leave( rng ) );
}

