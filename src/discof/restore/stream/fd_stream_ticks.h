#ifndef HEADER_fd_src_discof_restore_stream_fd_stream_ticks_h
#define HEADER_fd_src_discof_restore_stream_fd_stream_ticks_h

#include "../../../util/fd_util_base.h"
#include "../../../tango/tempo/fd_tempo.h"

struct fd_stream_ticks {
  ulong housekeeping_ticks;
  ulong prefrag_ticks;
  ulong async_min;
  long  lazy;
  long  now;
  long  then;
};
typedef struct fd_stream_ticks fd_stream_ticks_t;

static inline void
fd_stream_ticks_init( fd_stream_ticks_t * ticks,
                      ulong event_cnt,
                      long lazy ) {
  fd_memset( ticks, 0, sizeof(fd_stream_ticks_t) );
  ticks->lazy = lazy;
  ticks->async_min = fd_tempo_async_min( ticks->lazy,
                                         event_cnt,
                                         (float)fd_tempo_tick_per_ns( NULL ) );
  if( FD_UNLIKELY( !ticks->async_min ) ) FD_LOG_ERR(( "bad lazy %lu %lu", (ulong)ticks->lazy, event_cnt ));
}

static inline void
fd_stream_ticks_init_timer( fd_stream_ticks_t * ticks ) {
  ticks->then = fd_tickcount();
  ticks->now  = ticks->then;
}

static inline int
fd_stream_ticks_is_housekeeping_time( fd_stream_ticks_t * ticks ) {
  ticks->housekeeping_ticks = 0UL;
  return (ticks->now - ticks->then) >= 0L;
}

static inline void
fd_stream_ticks_reload_housekeeping( fd_stream_ticks_t * ticks, fd_rng_t * rng ) {
  ticks->then = ticks->now + (long)fd_tempo_async_reload( rng, ticks->async_min );
  long next = fd_tickcount();
  ticks->housekeeping_ticks = (ulong)(next - ticks->now);
  ticks->now = next;
}

static inline void
fd_stream_ticks_reload_backpressure( fd_stream_ticks_t * ticks ) {
  long next = fd_tickcount();
  ticks->now = next;
}

#endif /* HEADER_fd_src_discof_restore_stream_fd_stream_ticks_h */
