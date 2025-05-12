#ifndef HEADER_fd_src_discof_restore_stream_fd_stream_ctx_h
#define HEADER_fd_src_discof_restore_stream_fd_stream_ctx_h

#include "../../../disco/topo/fd_topo.h"
#include "fd_stream_reader.h"
#include "fd_event_map.h"
#include "fd_stream_ticks.h"
#include "fd_stream_metrics.h"

struct fd_stream_ctx {
  fd_stream_reader_t *  in;
  fd_stream_reader_t ** in_ptrs;
  ulong **              cons_fseq;
  ulong **              cons_slow;
  fd_event_map_t *      event_map;
  ulong                 in_cnt;
  ulong                 cons_cnt;
  ulong                 in_seq;
  fd_rng_t              rng[1];
  fd_stream_ticks_t     ticks[1];
  fd_stream_metrics_t   metrics[1];
};
typedef struct fd_stream_ctx fd_stream_ctx_t;

FD_PROTOTYPES_BEGIN

FD_FN_PURE static inline ulong
fd_stream_ctx_scratch_align( void ) {
  return FD_STEM_SCRATCH_ALIGN;
}

FD_FN_PURE static inline ulong
fd_stream_ctx_scratch_footprint( ulong in_cnt,
                                 ulong cons_cnt ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_stream_ctx_t),      sizeof(fd_stream_ctx_t) );
  l = FD_LAYOUT_APPEND( l, alignof(fd_stream_reader_t),   in_cnt*sizeof(fd_stream_reader_t)   );        /* in */
  l = FD_LAYOUT_APPEND( l, alignof(fd_stream_reader_t *), in_cnt*sizeof(fd_stream_reader_t *) );        /* in_ptrs */
  l = FD_LAYOUT_APPEND( l, alignof(ulong const *),        cons_cnt*sizeof(ulong const *)      );        /* cons_fseq */
  l = FD_LAYOUT_APPEND( l, alignof(ulong *),              cons_cnt*sizeof(ulong *)            );        /* cons_slow */
  l = FD_LAYOUT_APPEND( l, fd_event_map_align(),          fd_event_map_footprint( in_cnt, cons_cnt ) ); /* event_map */
  return FD_LAYOUT_FINI( l, fd_stream_ctx_scratch_align() );
}

fd_stream_ctx_t *
fd_stream_ctx_new( void * mem,
                   fd_topo_t *      topo,
                   fd_topo_tile_t * tile,
                   ulong  in_cnt,
                   ulong  cons_cnt );

void
fd_stream_ctx_init( fd_stream_ctx_t * ctx,
                    fd_topo_t *      topo,
                    fd_topo_tile_t * tile );

void *
fd_stream_ctx_destroy( fd_stream_ctx_t * ctx );

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
fd_stream_ctx_init_run_loop( fd_stream_ctx_t * ctx  ) {
  FD_MGAUGE_SET( TILE, STATUS, 1UL );
  fd_stream_ticks_init_timer( ctx->ticks );
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
fd_stream_ctx_process_backpressure( fd_stream_ctx_t * ctx ) {
  fd_stream_metrics_update_backpressure( ctx->metrics,
                                         ctx->ticks->housekeeping_ticks );
  fd_stream_ticks_reload_backpressure( ctx->ticks );
}

typedef int fd_on_stream_frag_fn_t( void * ctx,
                            fd_stream_reader_t * reader,
                            fd_stream_frag_meta_t const * frag,
                            ulong * sz );

static inline void
fd_stream_ctx_poll( fd_stream_ctx_t * stream_ctx,
                    void * ctx,
                    fd_on_stream_frag_fn_t * on_stream_frag ) {
  stream_ctx->metrics->in_backp = 0UL;
  stream_ctx->ticks->prefrag_ticks = 0UL;

  /* select input to poll */
  fd_stream_reader_t * this_in = &stream_ctx->in[ stream_ctx->in_seq ];
  stream_ctx->in_seq++;
  if( stream_ctx->in_seq>=stream_ctx->in_cnt ) {
    stream_ctx->in_seq = 0UL; /* cmov */
  }

  fd_frag_reader_consume_ctx_t consume_ctx;
  long diff = fd_stream_reader_poll_frag( this_in,
                                          stream_ctx->in_seq,
                                          &consume_ctx );

  if( FD_UNLIKELY( diff<0L ) ) {
    fd_stream_metrics_update_poll( stream_ctx->metrics,
                                   stream_ctx->ticks->housekeeping_ticks,
                                   stream_ctx->ticks->prefrag_ticks,
                                   &stream_ctx->ticks->now);

    fd_stream_reader_process_overrun( this_in,
                                      &consume_ctx,
                                      diff );
  }
  else if ( FD_UNLIKELY( diff ) ) {
    fd_stream_metrics_update_poll_idle( stream_ctx->metrics,
                                        stream_ctx->ticks->housekeeping_ticks,
                                        stream_ctx->ticks->prefrag_ticks,
                                        &stream_ctx->ticks->now );
  }
  else {
    FD_COMPILER_MFENCE();
    ulong sz = 0U;
    fd_stream_frag_meta_t const * frag = fd_type_pun_const( consume_ctx.mline  );
    int consumed_frag = on_stream_frag( ctx, this_in, frag, &sz );

    fd_stream_reader_consume_bytes( this_in, sz );

    if( FD_LIKELY( consumed_frag ) ) {
      fd_stream_reader_consume_frag( this_in,
                                     &consume_ctx );
    }

    fd_stream_metrics_update_poll( stream_ctx->metrics,
                                   stream_ctx->ticks->housekeeping_ticks,
                                   stream_ctx->ticks->prefrag_ticks,
                                   &stream_ctx->ticks->now );
  }

}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_restore_stream_fd_stream_ctx_h */
