#ifndef HEADER_fd_src_disco_bundle_fd_keepalive_h
#define HEADER_fd_src_disco_bundle_fd_keepalive_h

/* fd_keepalive.h provides an API to periodically generate keepalive
   events.  The general usage is as follows:
   - Configure a target keepalive interval and timeout
   - Periodically check back whether a keepalive is due, or whether a
     keepalive timed out
   - Notify the object whenever a keepalive was sent or a keepalive ACK
     was received. */

#include "../../util/rng/fd_rng.h"

struct fd_keepalive {
  long ts_next_tx;   /* Timestamp when to send next ping */
  long ts_deadline;  /* Timestamp by which ping ACK is expected to be received */
  long interval;
  long timeout;

  long ts_last_tx;   /* Timestamp of last ping sent */
  long ts_last_rx;   /* Timestamp of last ping ACK received */

  uint inflight : 1;
};

typedef struct fd_keepalive fd_keepalive_t;

FD_PROTOTYPES_BEGIN

static inline long
fd_keepalive_interval_reload( fd_rng_t * rng,
                              long       interval ) {
  long i2 = interval>>1;
  return i2 + (long)fd_rng_ulong_roll( rng, (ulong)i2 );
}

static inline fd_keepalive_t *
fd_keepalive_init( fd_keepalive_t * ka,
                   fd_rng_t *       rng,
                   long             interval,
                   long             timeout,
                   long             now ) {
  memset( ka, 0, sizeof(fd_keepalive_t) );
  if( FD_UNLIKELY( interval<2L || !timeout ) ) return NULL;
  ka->interval = interval;
  ka->timeout  = timeout;
  ka->ts_next_tx = now + (long)fd_keepalive_interval_reload( rng, ka->interval );
  return ka;
}

/* fd_keepalive_should_tx returns 1 if the caller should send out a new
   keepalive probe.  Otherwise, returns 0.  Always returns 0 if interval
   is zero (thus has no-op behavior for a zeroed keepalive struct). */

static inline int
fd_keepalive_should_tx( fd_keepalive_t const * ka,
                        long                   now ) {
  return (!!ka->interval) & (ka->ts_next_tx <= now) & (!ka->inflight);
}

static inline void
fd_keepalive_tx( fd_keepalive_t * ka,
                 fd_rng_t *       rng,
                 long             now ) {
  long delay = (long)fd_keepalive_interval_reload( rng, ka->interval );
  ka->ts_last_tx  = now;
  ka->ts_next_tx += delay;
  if( FD_UNLIKELY( ka->ts_next_tx < now ) ) {
    ka->ts_next_tx = now + delay;
  }
  ka->ts_deadline = ka->ts_last_tx + ka->timeout;
  ka->inflight    = 1;
}

static inline int
fd_keepalive_is_timeout( fd_keepalive_t const * ka,
                         long                   now ) {
  return (!!ka->inflight) & (ka->ts_deadline <= now);
}

static inline long
fd_keepalive_rx( fd_keepalive_t * ka,
                 long             now ) {
  long rtt = now - ka->ts_last_tx;
  if( !ka->inflight ) rtt = 0L;
  ka->ts_deadline = 0L;
  ka->ts_last_rx  = now;
  ka->inflight    = 0;
  return rtt;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_bundle_fd_keepalive_h */
