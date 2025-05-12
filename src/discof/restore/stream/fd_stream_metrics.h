#ifndef HEADER_fd_src_discof_restore_stream_fd_stream_metrics_h
#define HEADER_fd_src_discof_restore_stream_fd_stream_metrics_h

#include "../../../util/fd_util_base.h"
#include "../../../disco/metrics/fd_metrics.h"

struct fd_stream_metrics {
  ulong in_backp;
  ulong backp_cnt;
  ulong regime_ticks[9];
};
typedef struct fd_stream_metrics fd_stream_metrics_t;

typedef void fd_metrics_write_fn_t( void * ctx );

FD_PROTOTYPES_BEGIN

static inline void
fd_stream_metrics_init( fd_stream_metrics_t * metrics ) {
  metrics->in_backp = 1UL;
  metrics->backp_cnt = 0UL;
  fd_memset( metrics->regime_ticks, 0, sizeof(metrics->regime_ticks) );
}

static inline void
fd_stream_metrics_update_external( fd_stream_metrics_t *   metrics,
                                   long                    now,
                                   fd_metrics_write_fn_t * metrics_write,
                                   void *                  ctx ) {
  FD_COMPILER_MFENCE();
  FD_MGAUGE_SET( TILE, HEARTBEAT,                 (ulong)now );
  FD_MGAUGE_SET( TILE, IN_BACKPRESSURE,           metrics->in_backp );
  FD_MCNT_INC  ( TILE, BACKPRESSURE_COUNT,        metrics->backp_cnt );
  FD_MCNT_ENUM_COPY( TILE, REGIME_DURATION_NANOS, metrics->regime_ticks );

  if( metrics_write ) {
    metrics_write( ctx );
  }

  FD_COMPILER_MFENCE();
  metrics->backp_cnt = 0UL;
}

static inline void
fd_stream_metrics_update_backpressure( fd_stream_metrics_t * metrics,
                                       ulong                 housekeeping_ticks ) {
  metrics->backp_cnt += (ulong)!metrics->in_backp;
  metrics->in_backp   = 1UL;
  FD_SPIN_PAUSE();
  metrics->regime_ticks[2] += housekeeping_ticks;
}

static inline void
fd_stream_metrics_update_poll( fd_stream_metrics_t * metrics,
                                       ulong                 housekeeping_ticks,
                                       ulong                 prefrag_ticks,
                                       long *               now) {
  metrics->regime_ticks[1] += housekeeping_ticks;
  metrics->regime_ticks[4] += prefrag_ticks;
  long next = fd_tickcount();
  metrics->regime_ticks[7] += (ulong)(next - *now);
  *now = next;
}

static inline void
fd_stream_metrics_update_poll_idle( fd_stream_metrics_t * metrics,
                                       ulong                 housekeeping_ticks,
                                       ulong                 prefrag_ticks,
                                       long *               now) {
  metrics->regime_ticks[0] += housekeeping_ticks;
  metrics->regime_ticks[3] += prefrag_ticks;
  long next = fd_tickcount();
  metrics->regime_ticks[6] += (ulong)(next - *now);
  *now = next;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_restore_stream_fd_stream_metrics_h */
