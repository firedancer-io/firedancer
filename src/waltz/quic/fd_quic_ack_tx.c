#include "fd_quic_ack_tx.h"
#include "fd_quic_private.h"

#include "fd_quic_proto.h"
#include "fd_quic_proto.c"

static inline int
fd_quic_range_can_extend( fd_quic_range_t const * range,
                          ulong                   idx ) {
  return idx+1UL >= range->offset_lo && idx <= range->offset_hi;
}

static inline int
fd_quic_range_extend( fd_quic_range_t * range,
                      ulong             idx ) {
  int lo_decreased = idx <  range->offset_lo;
  int hi_increased = idx >= range->offset_hi;
  range->offset_lo = fd_ulong_min( range->offset_lo, idx );
  range->offset_hi = fd_ulong_max( range->offset_hi, idx+1UL );
  return lo_decreased || hi_increased;
}

void
fd_quic_ack_pkt( fd_quic_ack_gen_t * gen,
                 ulong               pkt_number,
                 uint                enc_level,
                 ulong               now ) {

  if( pkt_number == FD_QUIC_PKT_NUM_UNUSED ) return;

  /* Can we merge pkt_number into the most recent ACK? */
  uint            cached_seq = gen->head - 1U;
  fd_quic_ack_t * cached_ack = fd_quic_ack_queue_ele( gen, cached_seq );
  if( ( enc_level == cached_ack->enc_level ) &
      fd_quic_range_can_extend( &cached_ack->pkt_number, pkt_number ) ) {

    /* update timestamp */
    if( pkt_number >= cached_ack->pkt_number.offset_hi ) {
      cached_ack->ts = now;
    }

    /* add packet number to existing range */
    int changed = fd_quic_range_extend( &cached_ack->pkt_number, pkt_number );

    /* re-enqueue most recent ACK for sending */
    if( changed && gen->head==gen->tail ) {
      gen->tail = cached_seq;
    }

    FD_ACK_DEBUG( FD_LOG_DEBUG(( "gen=%p queue ACK for enc=%u pkt_num=%lu range=[%lu,%lu) seq=%u (merged)",
        (void *)gen, enc_level, pkt_number, cached_ack->pkt_number.offset_lo, cached_ack->pkt_number.offset_hi, cached_seq )); )
    return;

  }

  /* Attempt to allocate another ACK queue entry */
  if( gen->head - gen->tail >= FD_QUIC_ACK_QUEUE_CNT ) {
    FD_DEBUG( FD_LOG_DEBUG(( "ACK queue overflow! (excessive reordering)" )); )
    /* FIXME count to metrics */
    return;
  }

  /* Start new pending ACK */
  FD_ACK_DEBUG( FD_LOG_DEBUG(( "gen=%p queue ACK for enc=%u pkt_num=%lu seq=%u",
    (void *)gen, enc_level, pkt_number, gen->head )); )
  fd_quic_ack_t * next_ack = fd_quic_ack_queue_ele( gen, gen->head );
  *next_ack = (fd_quic_ack_t) {
    .pkt_number = { .offset_lo = pkt_number, .offset_hi = pkt_number+1UL },
    .enc_level  = (uchar)enc_level,
    .ts         = now
  };
  gen->head += 1U;
}

void
fd_quic_ack_gen_abandon_enc_level( fd_quic_ack_gen_t * gen,
                                   uint                enc_level ) {
  for( ; gen->tail != gen->head; gen->tail++ ) {
    fd_quic_ack_t const * ack = fd_quic_ack_queue_ele( gen, gen->tail );
    if( ack->enc_level > enc_level ) break;
    FD_DEBUG( FD_LOG_DEBUG(( "gen=%p discard ACK for enc=%u range=[%lu,%lu) seq=%u",
        (void *)gen, enc_level, ack->pkt_number.offset_lo, ack->pkt_number.offset_hi, gen->tail )); )
  }
}

extern ulong
fd_quic_encode_ack_frame( uchar *               buf,
                          ulong                 sz,
                          fd_quic_ack_frame_t * frame );

uchar *
fd_quic_gen_ack_frames( fd_quic_ack_gen_t * gen,
                        uchar *             payload_ptr,
                        uchar *             payload_end,
                        uint                enc_level,
                        ulong               now ) {

  FD_ACK_DEBUG( FD_LOG_DEBUG(( "[ACK gen] elicited=%d", gen->is_elicited )); )
  /* Never generate an ACK frame if no ACK-eliciting packet is pending.
     This prevents an infinite ACK loop. */
  if( !gen->is_elicited ) return payload_ptr;

  /* Attempt to send all ACK ranges */
  for( ; gen->tail != gen->head; gen->tail++ ) {
    fd_quic_ack_t * ack = fd_quic_ack_queue_ele( gen, gen->tail );
    if( ack->enc_level != enc_level ) {
      FD_ACK_DEBUG( FD_LOG_DEBUG(( "need encryption level %u for ACKs but have %u", ack->enc_level, enc_level )); )
      break;
    }

    if( FD_UNLIKELY( ack->pkt_number.offset_lo == ack->pkt_number.offset_hi ) ) continue;
    fd_quic_ack_frame_t ack_frame = {
      .type            = 0x02, /* type 0x02 is the base ack, 0x03 indicates ECN */
      .largest_ack     = ack->pkt_number.offset_hi - 1U,
      .ack_delay       = fd_ulong_sat_sub( now, ack->ts ) / 1000, /* microseconds */
      .ack_range_count = 0, /* no fragments */
      .first_ack_range = ack->pkt_number.offset_hi - ack->pkt_number.offset_lo - 1U,
    };
    ulong frame_sz = fd_quic_encode_ack_frame( payload_ptr, (ulong)( payload_end - payload_ptr ), &ack_frame );
    if( FD_UNLIKELY( frame_sz==FD_QUIC_ENCODE_FAIL ) ) {
      FD_DEBUG( FD_LOG_DEBUG(( "insufficient buffer space to send ACK" )); )
      break;
    }
    payload_ptr += frame_sz;
    FD_ACK_DEBUG( FD_LOG_DEBUG(( "gen=%p sending ACK enc=%u range=[%lu,%lu) seq=%u sz=%lu",
        (void *)gen, enc_level, ack->pkt_number.offset_lo, ack->pkt_number.offset_hi, gen->tail, frame_sz )); )
  }

  /* If all frames were flushed, reset status bits. */
  if( gen->head == gen->tail ) {
    gen->is_elicited = 0;
  } else {
    FD_ACK_DEBUG( FD_LOG_DEBUG(( "Not all ACK frames were flushed" )); )
  }

  return payload_ptr;
}
