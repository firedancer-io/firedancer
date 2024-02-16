#include "fd_quic_stream_spam.h"

/* Declare stack of pending streams */
#define STACK_NAME spam_pending
#define STACK_T    fd_quic_stream_t *
#include "../../../util/tmpl/fd_stack.c"

#define FD_QUIC_STREAM_SPAM_ALIGN (32UL)

struct fd_quic_stream_spam_private {
  fd_quic_stream_t ** pending;

  fd_quic_stream_gen_spam_t gen_fn;
  void *                    gen_ctx;
};

ulong
fd_quic_stream_spam_align( void ) {
  return alignof(fd_quic_stream_spam_t);
}

ulong
fd_quic_stream_spam_footprint( ulong stream_cnt ) {

  ulong freelist_footprint = spam_pending_footprint( stream_cnt );
  if( FD_UNLIKELY( !freelist_footprint ) ) {
    FD_LOG_WARNING(( "invalid footprint for config" ));
    return 0UL;
  }

  return FD_LAYOUT_FINI( FD_LAYOUT_APPEND( FD_LAYOUT_APPEND( FD_LAYOUT_INIT,
    alignof(fd_quic_stream_spam_t), sizeof(fd_quic_stream_spam_t) ),
    spam_pending_align(),           freelist_footprint            ),
    4096UL );
}

void *
fd_quic_stream_spam_new( void *                    mem,
                         ulong                     stream_cnt,
                         fd_quic_stream_gen_spam_t gen_fn,
                         void *                    gen_ctx ){

  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_quic_stream_spam_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !stream_cnt ) ) {
    FD_LOG_WARNING(( "zero stream_cnt" ));
    return NULL;
  }

  ulong cursor = (ulong)mem;

  cursor += FD_LAYOUT_INIT;
  fd_quic_stream_spam_t * spam = (fd_quic_stream_spam_t *)cursor;

  cursor += FD_LAYOUT_APPEND( FD_LAYOUT_INIT,
    alignof(fd_quic_stream_spam_t), sizeof(fd_quic_stream_spam_t) );
  fd_quic_stream_t ** pending = spam_pending_join( spam_pending_new( (void *)cursor, stream_cnt ) );
  if( FD_UNLIKELY( !pending ) ) {
    FD_LOG_WARNING(( "failed to create pending" ));
    return NULL;
  }

  memset( spam, 0, sizeof(fd_quic_stream_spam_t) );
  spam->pending = pending;
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
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shspam, fd_quic_stream_spam_align() ) ) ) {
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

  /* pending is a LIFO queue of streams created but waiting to send */
  fd_quic_stream_t ** pending = spam->pending;

  /* Count number of streams sent */
  long streams_sent = 0L;

  /* Create new streams
     Stop when QUIC quota runs out or stack limit reached */

  for( ulong avail=spam_pending_avail( pending ); avail>0; avail-- ) {
    fd_quic_stream_t * stream = fd_quic_conn_new_stream( conn, FD_QUIC_TYPE_UNIDIR );
    if( !stream ) break;

    /* Insert stream into stack, set back reference */
    spam_pending_push( pending, stream );
    stream->context = &pending[ spam_pending_cnt( pending )-1UL ];
  }

  /* Send streams */

  for( ulong cnt=spam_pending_cnt( pending ); cnt>0; cnt-- ) {
    fd_quic_stream_t * stream = spam_pending_pop( pending );
    if( !stream ) continue; /* stream dead */
    stream->context = NULL; /* remove back reference, as stream no longer in stack */

    /* Generate stream payload */
    uchar payload_buf[ 4096UL ];
    fd_aio_pkt_info_t batch[1] = { { .buf=payload_buf, .buf_sz=4096UL } };
    spam->gen_fn( /* ctx */ NULL, &batch[ 0 ], stream );

    /* Send data */
    int rc = fd_quic_stream_send( stream, batch, /* batch_cnt */ 1UL, /* fin */ 1 );
    switch( rc ) {
    case 1:
      /* Stream send successful, close triggered via fin bit */
      FD_LOG_DEBUG(( "sent stream=%lu pending=%lu", stream->stream_id, cnt ));
      streams_sent++;
      break;
    case 0:
      /* Stream send failed due to backpressure, retry later */
      spam_pending_push( pending, stream );
      stream->context = &pending[ spam_pending_cnt( pending )-1UL ];
      FD_LOG_INFO(( "backpressured" ));
      break;
    default:
      /* Fatal error */
      FD_LOG_WARNING(( "failed to send stream=%lu error=%d", stream->stream_id, rc ));
      return -1L;
    }
  }

  return streams_sent;
}

void
fd_quic_stream_spam_notify( fd_quic_stream_t * stream,
                            void *             stream_ctx,
                            int                notify_type ) {

  /* Stream is about to be deallocated */

  (void)stream;
  (void)notify_type;

  //FD_LOG_DEBUG(( "client notify stream=%lu notify_type=%d", stream->stream_id, notify_type ));

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

