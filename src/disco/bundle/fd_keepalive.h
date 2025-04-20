#ifndef HEADER_fd_src_disco_bundle_fd_bundle_ping_h
#define HEADER_fd_src_disco_bundle_fd_bundle_ping_h

/* fd_keepalive.h provides timing logic for keep alives. */

#include "../../util/fd_util_base.h"

/* fd_keepalive_timer_t provides an oracle when to generate a
  'keep alive'/ping packet.  The oracle triggers after a randomized
  wait time.  These wait times are uniformly distributed in a window
  where the median is 'delay_m', the  */

struct fd_keepalive_timer {
  ulong delay_min;
  ulong delay_mask;
};

typedef struct fd_keepalive_timer fd_keepalive_timer_t;

FD_PROTOTYPES_BEGIN

/* fd_keepalive_timer_init initializes a timer.  delay_ticks specifies
   the median idle wait time before a ping is generated.  window_exp
   controls the variance of the random wait time. */

static inline void
fd_keepalive_timer_init( fd_keepalive_timer_t * ctx,
                         long                   delay_ticks,
                         int                    window_exp ) {

}

static inline int
fd_bundle_client_

static inline void
fd_bundle_ping_reload( fd_bundle_ping_t * ctx,
                       fd_rng_t *         rng,
                       long               now ) {
  ctx->last_activity_ts = now;
  ctx->next_ping_ts = now + (long)fd_tempo_async_reload( rng, ctx->ping_delay_min );
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_bundle_fd_bundle_ping_h */
