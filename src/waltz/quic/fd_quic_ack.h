#ifndef HEADER_fd_src_waltz_quic_fd_quic_ack_h
#define HEADER_fd_src_waltz_quic_fd_quic_ack_h

/* fd_quic_ack.h provides helpers for generating ACK frames. */

#include "fd_quic_common.h"

/* fd_quic_ack_t builds a contiguous range of packet numbers to ACK.
   Whenever an fd_quic_t instance successfully processes a packet, it
   accumulates the packet number into an fd_quic_ack_t.

   The 'low timestamp' is the time at which the oldest packet finished
   processing.  The 'high timestamp' is the time at which the packet
   with the highest packet number finished processing.  (Usually the
   most recent packet.)  Uncompressed timestamps are in nanoseconds
   since unix epoch.  ts_lo_comp is the low timestamp right shifted by
   FD_QUIC_ACK_TS_SHIFT.  ts_hi_delta_comp is the difference between the
   high and low timestamp right shifted by FD_QUIC_ACK_TS_SHIFT.
   The max distance between the old and new timestamp is approx 2 hours.
   (2ns^(32+FD_QUIC_ACK_TS_SHIFT))  U.B. if a timestamp is >= 2^64.*/

#define FD_QUIC_ACK_TS_SHIFT (10)

struct __attribute__((aligned(16))) fd_quic_ack {
  fd_quic_range_t pkt_number;       /* Range of packet numbers being ACKed */
  ulong           ts_lo_comp;       /* (low timestamp) >> FD_QUIC_ACK_TS_SHIFT */
  uint            ts_hi_delta_comp; /* (hi timestamp - low timestamp) >> FD_QUIC_ACK_TS_SHIFT */
  uchar           enc_level;        /* in [0,4) */
  uchar           lazy;             /* no ACK-eliciting frames pending ACK in this range */
  /* Tuned to 32 byte size */
};

typedef struct fd_quic_ack fd_quic_ack_t;

FD_PROTOTYPES_BEGIN

/* fd_quic_ack_set_ts sets the low and high timestamp to ts. */

static inline void
fd_quic_ack_set_ts( fd_quic_ack_t * ack,
                    ulong           ts ) {
  ack->ts_lo_comp       = ts >> FD_QUIC_ACK_TS_SHIFT;
  ack->ts_hi_delta_comp = 0U;
}

/* fd_quic_ack_set_ts_hi sets the high timestamp to ts.  May mangle the
   low timestamp if the max distance between the {low,hi} timestamps is
   exceeded. */

static inline void
fd_quic_ack_set_ts_hi( fd_quic_ack_t * ack,
                       ulong           ts ) {
  ulong ts_hi_comp = ts >> FD_QUIC_ACK_TS_SHIFT;
  ulong delta      = ts_hi_comp - ack->ts_lo_comp;
  if( FD_UNLIKELY( delta>UINT_MAX ) ) {
    ack->ts_lo_comp = ts_hi_comp - UINT_MAX;
    delta           = UINT_MAX;
  }
  ack->ts_hi_delta_comp = (uint)delta;
}

/* fd_quic_ack_ts_lo returns the low timestamp. */

FD_FN_PURE static inline ulong
fd_quic_ack_ts_lo( fd_quic_ack_t const * ack ) {
  return ack->ts_lo_comp << FD_QUIC_ACK_TS_SHIFT;
}

/* fd_quic_ack_ts_hi returns the high timestamp. */

FD_FN_PURE static inline ulong
fd_quic_ack_ts_hi( fd_quic_ack_t const * ack ) {
  return (ack->ts_lo_comp + ack->ts_hi_delta_comp) << FD_QUIC_ACK_TS_SHIFT;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_waltz_quic_fd_quic_ack_h */
