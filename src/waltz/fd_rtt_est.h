#ifndef HEADER_fd_waltz_fd_rtt_est_h
#define HEADER_fd_waltz_fd_rtt_est_h

/* fd_rtt_est.h provides an API to estimate RTT (round trip time) for
   packet transmissions to a single destination.  The 'duration' unit in
   this file is arbitrary.  Typically, it is measured in TSC ticks or
   nanoseconds. */

#include "../util/bits/fd_bits.h"
#include <math.h>

/* fd_rtt_estimate_t calculates RTT from samples according to RFC 9002
   Section 5: https://datatracker.ietf.org/doc/html/rfc9002#section-5 */

struct fd_rtt_estimate {
  /* Nanoseconds */
  float latest_rtt;    /* Latest sample */
  float min_rtt;       /* Smallest end-to-end RTT (trusted) */
  float smoothed_rtt;  /* EMA of last few samples */
  float var_rtt;       /* EMA of sample variance */

  /* is_rtt_valid indicates at least one proper sample exists of rtt */
  int is_rtt_valid;
};

typedef struct fd_rtt_estimate fd_rtt_estimate_t;

FD_PROTOTYPES_BEGIN

/* fd_rtt_sample adds a RTT sample to the estimate.

   latest_rtt is the duration elapsed since a request was sent and a
   corresponding reply was received (this value originates from local
   timestamping).  ack_delay is the duration that the peer delayed the
   reply by after receiving the request (this value is reported by the
   peer in the response).  Outside of QUIC, ack_delay is typically
   zero/unknown.

   est->{latest_rtt,min_rtt,smoothed_rtt,var_rtt} are updated on return.
   fd_rtt_sample is robust against a maliciously chosen ack_delay.
   smoothed_rtt and latest_rtt are bounded by the smallest end-to-end
   RTT observation _before_ adjusting by ack_delay (min_rtt). */

static inline void
fd_rtt_sample( fd_rtt_estimate_t * est,
               float               latest_rtt,
               float               ack_delay ) {
  float prev_min_rtt = fd_float_if( est->is_rtt_valid, est->min_rtt, FLT_MAX );

  /* min_rtt is estimated from rtt_ticks without adjusting for ack_delay */
  est->min_rtt = fminf( prev_min_rtt, latest_rtt );

  est->latest_rtt = latest_rtt;

  /* smoothed_rtt is calculated from adjusted rtt_ticks
     except: ack_delay must not be subtracted if the result would be less than minrtt */
  float adj_rtt = fmaxf( est->min_rtt, latest_rtt - ack_delay );

  /* Taken directly from RFC 9002 Section 5.3 */
  if( FD_UNLIKELY( !est->is_rtt_valid ) ) {
    est->smoothed_rtt = adj_rtt;
    est->var_rtt      = adj_rtt * 0.5f;
    est->is_rtt_valid = 1;
  } else {
    est->smoothed_rtt = (7.f/8.f) * est->smoothed_rtt + (1.f/8.f) * adj_rtt;
    float var_rtt_sample = fabsf( est->smoothed_rtt - adj_rtt );
    est->var_rtt = (3.f/4.f) * est->var_rtt + (1.f/4.f) * var_rtt_sample;
  }
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_waltz_fd_rtt_est_h */
