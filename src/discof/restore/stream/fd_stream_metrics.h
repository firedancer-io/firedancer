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
  FD_MCNT_ENUM_COPY( TILE, REGIME_DURATION_NANOS, metrics->regime_ticks );

  if( metrics_write ) {
    metrics_write( ctx );
  }

  FD_COMPILER_MFENCE();
  metrics->backp_cnt = 0UL;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_restore_stream_fd_stream_metrics_h */
