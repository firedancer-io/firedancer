#ifndef HEADER_fd_src_discof_restore_stream_fd_stream_ctx_h
#define HEADER_fd_src_discof_restore_stream_fd_stream_ctx_h

#include "../../../disco/topo/fd_topo.h"
#include "fd_stream_reader.h"
#include "fd_stream_writer.h"
#include "fd_event_map.h"
#include "fd_stream_ticks.h"
#include "fd_stream_metrics.h"

struct fd_stream_ctx;
typedef struct fd_stream_ctx fd_stream_ctx_t;

typedef void
(* fd_tile_ctx_init_run_loop_fn_t)( void *            ctx,
                                    fd_stream_ctx_t * stream_ctx );

typedef void
(* fd_tile_update_in_fn_t)( fd_stream_reader_t * reader );

typedef void
(* fd_tile_housekeeping_fn_t)( void *            ctx,
                               fd_stream_ctx_t * stream_ctx );

typedef void
(* fd_tile_metrics_write_fn_t)( void * ctx );

typedef void
(* fd_tile_run_fn_t)( void *            ctx,
                      fd_stream_ctx_t * stream_ctx,
                      int *             opt_poll_in );

typedef int
(* fd_tile_on_stream_frag_fn_t)( void *                        ctx,
                                 fd_stream_reader_t *          reader,
                                 fd_stream_frag_meta_t const * frag,
                                 ulong *                       sz );

struct fd_stream_ctx {
  fd_stream_reader_t *         in;
  fd_stream_reader_t **        in_ptrs;
  fd_event_map_t *             event_map;
  ulong                        in_cnt;
  ulong                        out_cnt;
  ulong                        in_seq;
  fd_rng_t                     rng[1];
  fd_stream_ticks_t            ticks[1];
  fd_stream_metrics_t          metrics[1];
  fd_stream_writer_t **        writers;
  fd_tile_update_in_fn_t       tile_update_in;
  fd_tile_housekeeping_fn_t    tile_housekeeping;
  fd_tile_metrics_write_fn_t   tile_metrics_write;
  fd_tile_run_fn_t             tile_run;
  fd_tile_on_stream_frag_fn_t  tile_on_stream_frag;
};
typedef struct fd_stream_ctx fd_stream_ctx_t;

FD_PROTOTYPES_BEGIN

FD_FN_PURE ulong
fd_stream_ctx_align( void );

ulong
fd_stream_ctx_footprint( fd_topo_t const *      topo,
                         fd_topo_tile_t const * tile );

fd_stream_ctx_t *
fd_stream_ctx_new( void *                 mem,
                   fd_topo_t const *      topo,
                   fd_topo_tile_t const * tile );

static inline void
fd_stream_ctx_init_run_loop( fd_stream_ctx_t *              ctx,
                             void *                         tile_ctx,
                             fd_tile_ctx_init_run_loop_fn_t tile_init_run_loop,
                             fd_tile_update_in_fn_t         tile_update_in,
                             fd_tile_housekeeping_fn_t      tile_housekeeping,
                             fd_tile_metrics_write_fn_t     tile_metrics_write,
                             fd_tile_run_fn_t               tile_run,
                             fd_tile_on_stream_frag_fn_t    tile_on_stream_frag ) {
  if( ctx->in_cnt && !tile_update_in ) {
    FD_LOG_ERR(( "tile_update_in function cannot be null if there are producers to this tile!" ));
  }

  if( ctx->in_cnt && !tile_on_stream_frag ) {
    FD_LOG_ERR(( "tile_on_stream_frag function cannot be null if there are producers to this tile!" ));
  }

  ctx->tile_update_in      = tile_update_in;
  ctx->tile_housekeeping   = tile_housekeeping;
  ctx->tile_metrics_write  = tile_metrics_write;
  ctx->tile_run            = tile_run;
  ctx->tile_on_stream_frag = tile_on_stream_frag;

  FD_MGAUGE_SET( TILE, STATUS, 1UL );
  fd_stream_ticks_init_timer( ctx->ticks );

  if( tile_init_run_loop ) {
    tile_init_run_loop( tile_ctx, ctx );
  }
}

static inline void
fd_stream_ctx_calculate_backpressure( fd_stream_ctx_t * ctx ) {
  /* Recalculate flow control credits */
  for( ulong i=0UL; i<ctx->out_cnt; i++ ) {
    fd_stream_writer_calculate_backpressure( ctx->writers[i] );
  }
}

static inline void
fd_stream_ctx_housekeeping_advance( fd_stream_ctx_t * ctx ) {
  /* Select which event to do next (randomized round robin) and
     reload the housekeeping timer. */
  fd_event_map_advance( ctx->event_map,
                        ctx->rng,
                        (void **)ctx->in_ptrs,
                        ctx->in_cnt );

  /* Reload housekeeping timer */
  fd_stream_ticks_reload_housekeeping( ctx->ticks,
                                       ctx->rng);
}

static inline void
fd_stream_ctx_do_housekeeping( fd_stream_ctx_t * ctx,
                               void *            tile_ctx ) {
  if( FD_UNLIKELY( fd_stream_ticks_is_housekeeping_time( ctx->ticks ) ) ) {
    ulong event_idx = fd_event_map_get_event( ctx->event_map );

    if( FD_LIKELY( event_idx<ctx->out_cnt ) ) { /* receive credits */
      ulong out_idx = event_idx;

      /* Receive flow control credits from this out. */
      fd_stream_writer_receive_flow_control_credits( ctx->writers[ out_idx ] );

    } else if( event_idx>ctx->out_cnt) { /* send credits */
      ulong in_idx = event_idx - ctx->out_cnt - 1UL;
      ctx->tile_update_in( &ctx->in[ in_idx ] );

    } else { /* event_idx==out_cnt, housekeeping event */

      /* Update metrics counters to external viewers */
      fd_stream_metrics_update_external( ctx->metrics,
                                         ctx->ticks->now,
                                         ctx->tile_metrics_write,
                                         tile_ctx );
      fd_stream_ctx_calculate_backpressure( ctx );

      if( ctx->tile_housekeeping ) {
        ctx->tile_housekeeping( tile_ctx, ctx );
      }
    }

    fd_stream_ctx_housekeeping_advance( ctx );
  }
}

static inline void
fd_stream_ctx_process_backpressure( fd_stream_ctx_t * ctx ) {
  ctx->metrics->backp_cnt += (ulong)!ctx->metrics->in_backp;
  ctx->metrics->in_backp   = 1UL;
  FD_SPIN_PAUSE();
  ctx->metrics->regime_ticks[2] += ctx->ticks->housekeeping_ticks;
  long next = fd_tickcount();
  ctx->metrics->regime_ticks[5] += (ulong)(next - ctx->ticks->now);
  ctx->ticks->now = next;
}

static inline int
fd_stream_ctx_is_backpressured( fd_stream_ctx_t * ctx ) {
  int backpressured = ctx->out_cnt > 0UL ? 1UL : 0UL;
  for( ulong i=0UL; i<ctx->out_cnt; i++ ) {
    backpressured &= !fd_stream_writer_publish_sz_max( ctx->writers[i] );
  }
  return backpressured;
}

static inline void
fd_stream_ctx_advance_poll_empty( fd_stream_ctx_t * ctx ) {
  ctx->metrics->regime_ticks[0] += ctx->ticks->housekeeping_ticks;
  long next                      = fd_tickcount();
  ctx->metrics->regime_ticks[3] += (ulong)(next - ctx->ticks->now);
  ctx->ticks->now                = next;
}

static inline void
fd_stream_ctx_advance_poll( fd_stream_ctx_t * ctx ) {
  ctx->metrics->regime_ticks[1] += ctx->ticks->housekeeping_ticks;
  ctx->metrics->regime_ticks[4] += ctx->ticks->prefrag_ticks;
  long next                      = fd_tickcount();
  ctx->metrics->regime_ticks[7] += (ulong)(next - ctx->ticks->now);
  ctx->ticks->now                = next;
}

static inline void
fd_stream_ctx_advance_poll_idle( fd_stream_ctx_t * ctx ) {
  ctx->metrics->regime_ticks[0] += ctx->ticks->housekeeping_ticks;
  ctx->metrics->regime_ticks[3] += ctx->ticks->prefrag_ticks;
  long next                      = fd_tickcount();
  ctx->metrics->regime_ticks[6] += (ulong)(next - ctx->ticks->now);
  ctx->ticks->now                = next;
}

static inline void
fd_stream_ctx_advance_skip_poll( fd_stream_ctx_t * ctx ) {
  ctx->metrics->regime_ticks[1] += ctx->ticks->housekeeping_ticks;
  long next = fd_tickcount();
  ctx->metrics->regime_ticks[4] += (ulong)(next - ctx->ticks->now);
  ctx->ticks->now = next;
}

static inline void
fd_stream_ctx_poll( fd_stream_ctx_t * ctx,
                    void *            tile_ctx ) {
  ctx->metrics->in_backp = 0UL;

  if( FD_UNLIKELY( !ctx->in_cnt ) ) {
    fd_stream_ctx_advance_poll_empty( ctx );
    return;
  }

  ctx->ticks->prefrag_ticks = 0UL;

  /* select input to poll */
  fd_stream_reader_t * this_in = &ctx->in[ ctx->in_seq ];
  ctx->in_seq++;
  if( ctx->in_seq>=ctx->in_cnt ) {
    ctx->in_seq = 0UL; /* cmov */
  }

  fd_frag_reader_consume_ctx_t consume_ctx;
  long diff = fd_stream_reader_poll_frag( this_in,
                                          &consume_ctx );

  if( FD_UNLIKELY( diff<0L ) ) {
    /* overrun case, technically impossible with reliable streams */
    fd_stream_ctx_advance_poll( ctx );

    fd_stream_reader_process_overrun( this_in,
                                      &consume_ctx,
                                      diff );
  }
  else if ( FD_UNLIKELY( diff ) ) {
    /* nothing new to poll */
    fd_stream_ctx_advance_poll_idle( ctx );
  }
  else {
    FD_COMPILER_MFENCE();
    ulong sz = 0UL;
    fd_stream_frag_meta_t const * frag = fd_type_pun_const( consume_ctx.mline  );
    int consumed_frag = ctx->tile_on_stream_frag( tile_ctx, this_in, frag, &sz );

    fd_stream_reader_consume_bytes( this_in, sz );

    if( FD_LIKELY( consumed_frag ) ) {
      fd_stream_reader_consume_frag( this_in,
                                     &consume_ctx );
    }

    fd_stream_ctx_advance_poll( ctx );
  }
}

static inline void
fd_stream_ctx_run_loop( fd_stream_ctx_t * ctx,
                        void *            tile_ctx ) {
  for(;;) {
    fd_stream_ctx_do_housekeeping( ctx, tile_ctx );

    if( FD_UNLIKELY( fd_stream_ctx_is_backpressured( ctx ) ) ) {
      fd_stream_ctx_process_backpressure( ctx );
      continue;
    }

    /* equivalent of after credit */
    if( ctx->tile_run ) {
      int poll_in = 1;
      ctx->tile_run( tile_ctx, ctx, &poll_in );

      if( FD_UNLIKELY( !poll_in ) ) {
        fd_stream_ctx_advance_skip_poll( ctx );
        continue;
      }
    }

    fd_stream_ctx_poll( ctx, tile_ctx );
  }
}

static inline void
fd_stream_ctx_run( fd_stream_ctx_t *              ctx,
                   void *                         tile_ctx,
                   fd_tile_ctx_init_run_loop_fn_t tile_init_run_loop,
                   fd_tile_update_in_fn_t         tile_update_in,
                   fd_tile_housekeeping_fn_t      tile_housekeeping,
                   fd_tile_metrics_write_fn_t     tile_metrics_write,
                   fd_tile_run_fn_t               tile_run,
                   fd_tile_on_stream_frag_fn_t    tile_on_stream_frag ) {
  fd_stream_ctx_init_run_loop( ctx,
                               tile_ctx,
                               tile_init_run_loop,
                               tile_update_in,
                               tile_housekeeping,
                               tile_metrics_write,
                               tile_run,
                               tile_on_stream_frag );

  fd_stream_ctx_run_loop( ctx, tile_ctx );
}

static inline void *
fd_stream_ctx_delete( fd_stream_ctx_t * ctx ) {
  for( ulong i=0UL; i<ctx->in_cnt; i++ ) {
    fd_stream_reader_delete( &ctx->in[ i ] );
    ctx->in_ptrs[ i ] = NULL;
  }

  fd_event_map_delete( ctx->event_map );
  fd_memset(ctx, 0, sizeof(fd_stream_ctx_t) );
  return (void *)ctx;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_restore_stream_fd_stream_ctx_h */
