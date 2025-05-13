#ifndef HEADER_fd_src_discof_restore_stream_fd_stream_ctx_h
#define HEADER_fd_src_discof_restore_stream_fd_stream_ctx_h

#include "../../../disco/topo/fd_topo.h"
#include "fd_stream_reader.h"
#include "fd_stream_writer.h"
#include "fd_event_map.h"
#include "fd_stream_ticks.h"
#include "fd_stream_metrics.h"

struct fd_consumer_ctx {
  fd_stream_writer_t * writer;
  ulong                writer_cons_idx;
};
typedef struct fd_consumer_ctx fd_consumer_ctx_t;

struct fd_stream_ctx;
typedef struct fd_stream_ctx fd_stream_ctx_t;

typedef void fd_tile_ctx_init_run_loop_fn_t( void *            ctx,
                                             fd_stream_ctx_t * stream_ctx );
typedef void fd_tile_update_in_fn_t( fd_stream_reader_t * reader );
typedef void fd_tile_housekeeping_fn_t( void *            ctx,
                                        fd_stream_ctx_t * stream_ctx );
typedef void fd_tile_metrics_write_fn_t( void * ctx );
typedef int fd_on_stream_frag_fn_t( void *               ctx,
                                    fd_stream_reader_t * reader,
                                    fd_stream_frag_meta_t const * frag,
ulong * sz );

struct fd_stream_ctx {
  fd_stream_reader_t *         in;
  fd_stream_reader_t **        in_ptrs;
  ulong **                     cons_fseq;
  ulong **                     cons_slow;
  fd_event_map_t *             event_map;
  ulong                        in_cnt;
  ulong                        cons_cnt;
  ulong                        out_cnt;
  ulong                        in_seq;
  fd_rng_t                     rng[1];
  fd_stream_ticks_t            ticks[1];
  fd_stream_metrics_t          metrics[1];
  fd_stream_writer_t *         writers;
  fd_consumer_ctx_t *          consumer_ctx;
  fd_tile_update_in_fn_t *     tile_update_in;
  fd_tile_housekeeping_fn_t *  tile_housekeeping;
  fd_tile_metrics_write_fn_t * tile_metrics_write;
};
typedef struct fd_stream_ctx fd_stream_ctx_t;

FD_PROTOTYPES_BEGIN

FD_FN_PURE static inline ulong
fd_stream_ctx_scratch_align( void ) {
  return FD_STEM_SCRATCH_ALIGN;
}

FD_FN_PURE static inline ulong
fd_stream_ctx_scratch_footprint( ulong in_cnt,
                                 ulong cons_cnt,
                                 ulong out_cnt ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_stream_ctx_t),      sizeof(fd_stream_ctx_t) );
  l = FD_LAYOUT_APPEND( l, alignof(fd_stream_reader_t),   in_cnt*sizeof(fd_stream_reader_t)   );        /* in */
  l = FD_LAYOUT_APPEND( l, alignof(fd_stream_reader_t *), in_cnt*sizeof(fd_stream_reader_t *) );        /* in_ptrs */
  l = FD_LAYOUT_APPEND( l, alignof(ulong const *),        cons_cnt*sizeof(ulong const *)      );        /* cons_fseq */
  l = FD_LAYOUT_APPEND( l, alignof(ulong *),              cons_cnt*sizeof(ulong *)            );        /* cons_slow */
  l = FD_LAYOUT_APPEND( l, fd_event_map_align(),          fd_event_map_footprint( in_cnt, cons_cnt ) ); /* event_map */
  l = FD_LAYOUT_APPEND( l, alignof(fd_consumer_ctx_t),    sizeof(fd_consumer_ctx_t)*out_cnt );
  return FD_LAYOUT_FINI( l, fd_stream_ctx_scratch_align() );
}

fd_stream_ctx_t *
fd_stream_ctx_new( void * mem,
                   fd_topo_t *      topo,
                   fd_topo_tile_t * tile,
                   ulong  in_cnt,
                   ulong  cons_cnt,
                   ulong  out_cnt );

void
fd_stream_ctx_init( fd_stream_ctx_t * ctx,
                    fd_topo_t *      topo,
                    fd_topo_tile_t * tile );

static inline void
fd_stream_ctx_update_cons_slow( fd_stream_ctx_t * ctx,
                                ulong slowest_cons ) {
  if( FD_LIKELY( slowest_cons!=ULONG_MAX ) ) {
    FD_COMPILER_MFENCE();
    (*ctx->cons_slow[ slowest_cons ]) += ctx->metrics->in_backp;
    FD_COMPILER_MFENCE();
  }
}

static inline void
fd_stream_ctx_init_run_loop( fd_stream_ctx_t *                ctx,
                             void *                           tile_ctx,
                             fd_tile_ctx_init_run_loop_fn_t * tile_init_run_loop,
                             fd_tile_update_in_fn_t *         tile_update_in,
                             fd_tile_housekeeping_fn_t *      tile_housekeeping,
                             fd_tile_metrics_write_fn_t *     tile_metrics_write ) {
  FD_MGAUGE_SET( TILE, STATUS, 1UL );
  fd_stream_ticks_init_timer( ctx->ticks );

  for( ulong i=0UL; i<ctx->out_cnt; i++ ) {
    fd_stream_writer_init_flow_control_credits( &ctx->writers[ i ] );
  }

  if( tile_init_run_loop ) {
    tile_init_run_loop( tile_ctx, ctx );
  }

  if( ctx->in_cnt && !tile_update_in ) {
    FD_LOG_ERR(( "tile_update_in function cannot be null if there are producers to this tile!" ));
  }

  ctx->tile_update_in = tile_update_in;
  ctx->tile_housekeeping = tile_housekeeping;
  ctx->tile_metrics_write = tile_metrics_write;
}

static inline void
fd_stream_ctx_update_flow_control_credits( fd_stream_ctx_t * ctx ) {
  /* Recalculate flow control credits */
  ulong slowest_cons = ULONG_MAX;
  ulong global_cons_idx = 0UL;
  for( ulong i=0UL; i<ctx->out_cnt; i++ ) {
    ulong slowest_local_cons = ULONG_MAX;
    fd_stream_writer_update_flow_control_credits( &ctx->writers[i],
                                                  &slowest_local_cons );
    slowest_cons = fd_ulong_if( slowest_local_cons!=ULONG_MAX, global_cons_idx + slowest_local_cons, slowest_cons );
    global_cons_idx += ctx->writers[i].cons_cnt;
  }

  fd_stream_ctx_update_cons_slow( ctx,
                                  slowest_cons );
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

    if( FD_LIKELY( event_idx<ctx->cons_cnt ) ) { /* receive credits */
      ulong cons_idx = event_idx;

      /* Receive flow control credits from this out. */
      fd_stream_writer_receive_flow_control_credits( ctx->consumer_ctx[ cons_idx ].writer,
                                                     ctx->consumer_ctx[ cons_idx ].writer_cons_idx );

    } else if( event_idx>ctx->cons_cnt) { /* send credits */
      ulong in_idx = event_idx - ctx->cons_cnt - 1UL;
      ctx->tile_update_in( &ctx->in[ in_idx ] );

    } else { /* event_idx==cons_cnt, housekeeping event */

      /* Update metrics counters to external viewers */
      fd_stream_metrics_update_external( ctx->metrics,
                                         ctx->ticks->now,
                                         ctx->tile_metrics_write,
                                         ctx );
      fd_stream_ctx_update_flow_control_credits( ctx );

      if( ctx->tile_housekeeping ) {
        ctx->tile_housekeeping( tile_ctx, ctx );
      }
    }
    fd_stream_ctx_housekeeping_advance( ctx );
  }
}

static inline void
fd_stream_ctx_process_backpressure( fd_stream_ctx_t * ctx ) {
  fd_stream_metrics_update_backpressure( ctx->metrics,
                                         ctx->ticks->housekeeping_ticks );
  fd_stream_ticks_reload_backpressure( ctx->ticks );
}

static inline void
fd_stream_ctx_poll( fd_stream_ctx_t * ctx,
                    void * tile_ctx,
                    fd_on_stream_frag_fn_t * on_stream_frag ) {
  ctx->metrics->in_backp = 0UL;
  ctx->ticks->prefrag_ticks = 0UL;

  /* select input to poll */
  fd_stream_reader_t * this_in = &ctx->in[ ctx->in_seq ];
  ctx->in_seq++;
  if( ctx->in_seq>=ctx->in_cnt ) {
    ctx->in_seq = 0UL; /* cmov */
  }

  fd_frag_reader_consume_ctx_t consume_ctx;
  long diff = fd_stream_reader_poll_frag( this_in,
                                          ctx->in_seq,
                                          &consume_ctx );

  if( FD_UNLIKELY( diff<0L ) ) {
    fd_stream_metrics_update_poll( ctx->metrics,
                                   ctx->ticks->housekeeping_ticks,
                                   ctx->ticks->prefrag_ticks,
                                   &ctx->ticks->now);

    fd_stream_reader_process_overrun( this_in,
                                      &consume_ctx,
                                      diff );
  }
  else if ( FD_UNLIKELY( diff ) ) {
    fd_stream_metrics_update_poll_idle( ctx->metrics,
                                        ctx->ticks->housekeeping_ticks,
                                        ctx->ticks->prefrag_ticks,
                                        &ctx->ticks->now );
  }
  else {
    FD_COMPILER_MFENCE();
    ulong sz = 0U;
    fd_stream_frag_meta_t const * frag = fd_type_pun_const( consume_ctx.mline  );
    int consumed_frag = on_stream_frag( tile_ctx, this_in, frag, &sz );

    fd_stream_reader_consume_bytes( this_in, sz );

    if( FD_LIKELY( consumed_frag ) ) {
      fd_stream_reader_consume_frag( this_in,
                                     &consume_ctx );
    }

    fd_stream_metrics_update_poll( ctx->metrics,
                                   ctx->ticks->housekeeping_ticks,
                                   ctx->ticks->prefrag_ticks,
                                   &ctx->ticks->now );
  }
}

static inline void *
fd_stream_ctx_delete( fd_stream_ctx_t * ctx ) {
  for( ulong i=0UL; i<ctx->in_cnt; i++ ) {
    fd_stream_reader_delete( &ctx->in[ i ] );
    ctx->in_ptrs[ i ] = NULL;
  }

  for( ulong i=0UL; i<ctx->cons_cnt; i++ ) {
    ctx->cons_fseq[ i ] = NULL;
    ctx->cons_slow[ i ] = NULL;
  }

  fd_event_map_delete( ctx->event_map );
  fd_memset(ctx, 0, sizeof(fd_stream_ctx_t) );
  return (void *)ctx;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_restore_stream_fd_stream_ctx_h */
