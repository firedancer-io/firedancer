#include "fd_quic_stream_spam.h"
#include "fd_quic_test_helpers.h"

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
  ulong stream_type = conn->server ? FD_QUIC_STREAM_TYPE_UNI_SERVER : FD_QUIC_STREAM_TYPE_UNI_CLIENT;
  ulong stream_id   = stream_type + 4UL*spam->stream_cnt;

  /* Generate stream payload */
  uchar payload_buf[ 1024UL ];
  fd_aio_pkt_info_t batch[1] = { { .buf=payload_buf, .buf_sz=1024UL } };
  spam->gen_fn( /* ctx */ NULL, &batch[ 0 ], stream_id );

  if( FD_UNLIKELY( !fd_quic_test_stream_send( conn, stream_id, payload_buf, batch->buf_sz, NULL ) ) ) return 0L;
  spam->stream_cnt++;
  return 1L;
}

void
fd_quic_stream_spam_gen( void *              ctx,
                         fd_aio_pkt_info_t * pkt,
                         ulong               stream_id ) {
  (void)ctx;

  /* Derive random bytes to send */
  fd_rng_t _rng[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, (uint)stream_id, 0UL ) );

  ulong data_sz = fd_rng_ulong_roll( rng, pkt->buf_sz );
  pkt->buf_sz   = (ushort)data_sz;

  for( ulong i=0; i<fd_ulong_align_up( data_sz, 8UL ); i+=8 )
    *(ulong *)( (uchar *)pkt->buf+i ) = fd_rng_ulong( rng );
  fd_rng_delete( fd_rng_leave( rng ) );
}

