#ifndef HEADER_fd_src_discof_failover_fd_failover_log_h
#define HEADER_fd_src_discof_failover_fd_failover_log_h

#include "../../util/fd_util_base.h"

/* A quiet period belongs to a bounded event category, never an address
   supplied by a peer.  Every occurrence is counted; the next line gives
   the number suppressed.  A clock regression cannot create a burst. */
#define FD_FAILOVER_LOG_INTERVAL_NANOS (60000000000L)

struct fd_failover_log {
  long  at;
  ulong count;
  ulong suppressed;
};
typedef struct fd_failover_log fd_failover_log_t;

static inline int
fd_failover_log_take( fd_failover_log_t * log,
                      long                now,
                      ulong *             suppressed ) {
  int due = !log->count || ( now>=log->at && fd_long_sat_sub( now, log->at )>=FD_FAILOVER_LOG_INTERVAL_NANOS );
  log->count = fd_ulong_sat_add( log->count, 1UL );
  if( FD_LIKELY( !due ) ) {
    log->suppressed = fd_ulong_sat_add( log->suppressed, 1UL );
    return 0;
  }
  log->at = now;
  *suppressed = log->suppressed;
  log->suppressed = 0UL;
  return 1;
}

#endif /* HEADER_fd_src_discof_failover_fd_failover_log_h */
