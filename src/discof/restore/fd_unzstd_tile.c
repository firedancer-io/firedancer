#include "../../disco/topo/fd_topo.h"
#include "../../ballet/zstd/fd_zstd.h"
#include "fd_stream_writer.h"
#include "fd_stream_reader.h"
#include <errno.h>
#include <unistd.h>

#define NAME "unzstd"
#define ZSTD_WINDOW_SZ (33554432UL)
#define ZSTD_FRAME_SZ 16384UL
#define LINK_IN_MAX 1

struct fd_unzstd_tile {
  fd_stream_frag_meta_ctx_t in_state; /* input mcache context */
  fd_zstd_dstream_t *       dstream;  /* zstd decompress reader */
  fd_stream_writer_t *      writer;   /* stream writer object */
};

typedef struct fd_unzstd_tile fd_unzstd_tile_t;

FD_FN_PURE static ulong
scratch_align( void ) {
  return fd_ulong_max( alignof(fd_unzstd_tile_t), fd_zstd_dstream_align() );
}

FD_FN_PURE static ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_unzstd_tile_t), sizeof(fd_unzstd_tile_t)         );
  l = FD_LAYOUT_APPEND( l, fd_zstd_dstream_align(),   fd_zstd_dstream_footprint( ZSTD_WINDOW_SZ ) );
  l = FD_LAYOUT_APPEND( l, fd_stream_writer_align(), fd_stream_writer_footprint() );
  return l;
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  FD_SCRATCH_ALLOC_INIT( l, fd_topo_obj_laddr( topo, tile->tile_obj_id ) );
  fd_unzstd_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_unzstd_tile_t), sizeof(fd_unzstd_tile_t) );
  void * zstd_mem        = FD_SCRATCH_ALLOC_APPEND( l, fd_zstd_dstream_align(), fd_zstd_dstream_footprint( ZSTD_WINDOW_SZ ) );
  void * writer_mem      = FD_SCRATCH_ALLOC_APPEND( l, fd_stream_writer_align(), fd_stream_writer_footprint() );

  void * out_dcache = fd_dcache_join( fd_topo_obj_laddr( topo, topo->links[ tile->out_link_id[ 0 ] ].dcache_obj_id ) );
  FD_TEST( out_dcache );

  fd_memset( ctx, 0, sizeof(fd_unzstd_tile_t) );

  ctx->in_state.in_buf = (uchar const *)topo->workspaces[ topo->objs[ topo->links[ tile->in_link_id[ 0 ] ].dcache_obj_id ].wksp_id ].wksp;
  ctx->dstream         = fd_zstd_dstream_new( zstd_mem, ZSTD_WINDOW_SZ );
  ctx->writer          = fd_stream_writer_new( writer_mem, topo, tile, 0, ZSTD_WINDOW_SZ, 512UL, 2UL );

  fd_zstd_dstream_reset( ctx->dstream );
}

static void
during_housekeeping( fd_unzstd_tile_t * ctx ) {
  (void)ctx;
}

static void
metrics_write( fd_unzstd_tile_t * ctx ) {
  (void)ctx;
}

static int
on_stream_frag( fd_unzstd_tile_t *            ctx,
                fd_stream_reader_t *          reader FD_PARAM_UNUSED,
                fd_stream_frag_meta_t const * frag,
                ulong *                       sz ) {
  uchar const * chunk0 = ctx->in_state.in_buf + frag->loff;
  uchar const * chunk_start = chunk0 + ctx->in_state.in_skip;
  uchar const * chunk_end   = chunk0 + frag->sz;

  ulong total_decompressed = 0UL;
  uint dirty = 0;
  int consume_frag = 1;
  for(;;) {
    uchar const * prev_chunk_start = chunk_start;

    if( !dirty && chunk_start==chunk_end ) {
      fd_stream_writer_publish( ctx->writer, total_decompressed );
      ctx->in_state.in_skip = 0UL;
      break;
    }

    uchar * buf_write_start = fd_stream_writer_get_write_ptr( ctx->writer );
    uchar * out             = buf_write_start;
    ulong dst_max           = fd_stream_writer_get_avail_bytes( ctx->writer );
    uchar * out_end         = buf_write_start + dst_max;

    if( dst_max==0 ) {
      /* we are blocked by downstream */
      fd_stream_writer_publish( ctx->writer, total_decompressed );
      // FD_LOG_WARNING(("we are blocked by downstream! consumed %lu bytes frag size is %u", ctx->in_state.in_skip, frag->sz));
      consume_frag=0;
      break;
    }

    int zstd_err = fd_zstd_dstream_read( ctx->dstream, &chunk_start, chunk_end, &out, out_end, NULL );
    if( FD_UNLIKELY( zstd_err>0) ) {
      FD_LOG_WARNING(( "fd_zstd_dstream_read failed" ));
      consume_frag=0;
      break;
    }

    ulong decompress_sz = (ulong)out - (ulong)buf_write_start;
    total_decompressed += decompress_sz;
    ctx->in_state.in_skip += (ulong)chunk_start - (ulong)prev_chunk_start;
    dirty = (out==out_end);

    fd_stream_writer_advance( ctx->writer, decompress_sz );
  }

  *sz = frag->sz;
  return consume_frag;
}

static void
fd_unzstd_in_update( fd_stream_reader_t * in ) {
  // FD_LOG_WARNING(("unzstd: in fseq is %lu", (ulong)in->base.fseq));
  FD_COMPILER_MFENCE();
  FD_VOLATILE( in->base.fseq[0] ) = in->base.seq;
  FD_VOLATILE( in->base.fseq[1] ) = in->goff;
  FD_COMPILER_MFENCE();

  ulong volatile * metrics = fd_metrics_link_in( fd_metrics_base_tl, in->base.idx );

  uint * accum = in->base.accum;
  ulong a0 = accum[0]; ulong a1 = accum[1]; ulong a2 = accum[2];
  ulong a3 = accum[3]; ulong a4 = accum[4]; ulong a5 = accum[5];
  FD_COMPILER_MFENCE();
  metrics[0] += a0;    metrics[1] += a1;    metrics[2] += a2;
  metrics[3] += a3;    metrics[4] += a4;    metrics[5] += a5;
  FD_COMPILER_MFENCE();
  accum[0] = 0U;       accum[1] = 0U;       accum[2] = 0U;
  accum[3] = 0U;       accum[4] = 0U;       accum[5] = 0U;
}

__attribute__((noreturn)) static void
fd_unzstd_shutdown( void ) {
  FD_MGAUGE_SET( TILE, STATUS, 2UL );
  /* FIXME set final sequence number */
  FD_COMPILER_MFENCE();
  FD_LOG_INFO(( "Finished parsing snapshot" ));

  for(;;) pause();
}

/* ?? */
__attribute__((noinline)) static void
fd_unzstd_run1(
  fd_unzstd_tile_t *         ctx,
  ulong                      in_cnt,
  fd_stream_reader_t *       in,         /* [in_cnt] */
  ulong                      out_cnt FD_PARAM_UNUSED,
  fd_stream_frag_meta_t **   out_mcache_arr FD_PARAM_UNUSED,
  ulong                      cons_cnt,
  ushort * restrict          event_map,  /* [1+in_cnt+cons_cnt] */
  ulong *                    cons_out FD_PARAM_UNUSED,   /* [cons_cnt] */
  ulong **                   cons_fseq FD_PARAM_UNUSED,  /* [cons_cnt] */
  ulong volatile ** restrict cons_slow FD_PARAM_UNUSED,  /* [cons_cnt] */
  ulong * restrict           cons_seq FD_PARAM_UNUSED,   /* [cons_cnt] */
  long                       lazy,
  fd_rng_t *                 rng ) {

  /* in frag stream state */
  ulong in_seq;

  /* housekeeping state */
  ulong    event_cnt;
  ulong    event_seq;
  ulong    async_min; /* min number of ticks between a housekeeping event */

  /* performance metrics */
  ulong metric_in_backp;
  ulong metric_backp_cnt;
  ulong metric_regime_ticks[9];

  metric_in_backp  = 1UL;
  metric_backp_cnt = 0UL;
  memset( metric_regime_ticks, 0, sizeof( metric_regime_ticks ) );

  /* in frag stream init */

  in_seq = 0UL;

  /* out frag stream init */

  ulong const burst_byte = 512UL; /* don't producing frags smaller than this */
  ulong const burst_frag =   2UL;

  fd_stream_writer_init_flow_control_credits( ctx->writer );

  /* housekeeping init */

  //if( lazy<=0L ) lazy = fd_tempo_lazy_default( out_depth );
  lazy = 1e3L;
  FD_LOG_INFO(( "Configuring housekeeping (lazy %li ns)", lazy ));
  ulong const volatile * restrict shutdown_signal = fd_mcache_seq_laddr_const( in[0].base.mcache->f ) + 3;

  /* Initial event sequence */

  event_cnt = in_cnt + 1UL + cons_cnt;
  event_seq = 0UL;
  event_map[ event_seq++ ] = (ushort)cons_cnt;
  for( ulong in_idx=0UL; in_idx<in_cnt; in_idx++ ) {
    event_map[ event_seq ] = (ushort)(in_idx+cons_cnt+1UL);
    event_seq++;
  }
  for( ulong cons_idx=0UL; cons_idx<cons_cnt; cons_idx++ ) {
    event_map[ event_seq ] = (ushort)cons_idx;
    event_seq++;
  }
  event_seq = 0UL;

  async_min = fd_tempo_async_min( lazy, event_cnt, (float)fd_tempo_tick_per_ns( NULL ) );
  if( FD_UNLIKELY( !async_min ) ) FD_LOG_ERR(( "bad lazy %lu %lu", (ulong)lazy, event_cnt ));

  FD_LOG_INFO(( "Running unzstd tile" ));
  FD_MGAUGE_SET( TILE, STATUS, 1UL );
  long then = fd_tickcount();
  long now  = then;
  for(;;) {

    /* Do housekeeping at a low rate in the background */
    ulong housekeeping_ticks = 0UL;
    if( FD_UNLIKELY( (now-then)>=0L ) ) {
      ulong event_idx = (ulong)event_map[ event_seq ];

      if( FD_LIKELY( event_idx<cons_cnt ) ) {
        ulong cons_idx = event_idx;

        /* Receive flow control credits from this out. */
        fd_stream_writer_receive_flow_control_credits( ctx->writer, cons_idx );

        ulong const in_seq_max = FD_VOLATILE_CONST( *shutdown_signal );
        if( FD_UNLIKELY( in_seq_max == in[ 0 ].base.seq && in_seq_max != 0) ) {
          FD_LOG_WARNING(("zstd shutting down! in_seq_max is %lu in[0].base.seq is %lu", in_seq_max, in[0].base.seq));
          fd_unzstd_shutdown();
        }

      } else if( event_idx>cons_cnt) {
        ulong in_idx = event_idx - cons_cnt - 1UL;
        fd_unzstd_in_update( &in[ in_idx ] );
      }
      else { /* event_idx==cons_cnt, housekeeping event */

        /* Update metrics counters to external viewers */
        FD_COMPILER_MFENCE();
        FD_MGAUGE_SET( TILE, HEARTBEAT,                 (ulong)now );
        FD_MGAUGE_SET( TILE, IN_BACKPRESSURE,           metric_in_backp );
        FD_MCNT_INC  ( TILE, BACKPRESSURE_COUNT,        metric_backp_cnt );
        FD_MCNT_ENUM_COPY( TILE, REGIME_DURATION_NANOS, metric_regime_ticks );
        metrics_write( ctx );
        FD_COMPILER_MFENCE();
        metric_backp_cnt = 0UL;

        /* Receive flow control credits */
        ulong slowest_cons = ULONG_MAX;
        fd_stream_writer_update_flow_control_credits( ctx->writer, &slowest_cons );

        if( FD_LIKELY( slowest_cons!=ULONG_MAX ) ) {
          FD_COMPILER_MFENCE();
          (*cons_slow[ slowest_cons ]) += metric_in_backp;
          FD_COMPILER_MFENCE();
        }

        during_housekeeping( ctx );
      }

      /* Select which event to do next (randomized round robin) and
         reload the housekeeping timer. */

      event_seq++;
      if( FD_UNLIKELY( event_seq>=event_cnt ) ) {
        event_seq = 0UL;
        // ulong  swap_idx = (ulong)fd_rng_uint_roll( rng, (uint)event_cnt );
        // ushort map_tmp        = event_map[ swap_idx ];
        // event_map[ swap_idx ] = event_map[ 0        ];
        // event_map[ 0        ] = map_tmp;
      }

      /* Reload housekeeping timer */
      then = now + (long)fd_tempo_async_reload( rng, async_min );
      long next = fd_tickcount();
      housekeeping_ticks = (ulong)(next - now);
      now = next;
    }

    /* Check if we are backpressured. */

    if( FD_UNLIKELY( ctx->writer->cr_byte_avail<burst_byte || ctx->writer->cr_frag_avail<burst_frag ) ) {
      metric_backp_cnt += (ulong)!metric_in_backp;
      metric_in_backp   = 1UL + (ctx->writer->cr_byte_avail<burst_byte);
      FD_SPIN_PAUSE();
      metric_regime_ticks[2] += housekeeping_ticks;
      long next = fd_tickcount();
      metric_regime_ticks[5] += (ulong)(next - now);
      now = next;
      continue;
    }
    metric_in_backp = 0UL;

    ulong prefrag_ticks = 0UL;

    fd_stream_reader_t * this_in = &in[ in_seq ];
    in_seq++;
    if( in_seq>=in_cnt ) in_seq = 0UL; /* cmov */

    /* Check if this in has any new fragments to mux */
    
    fd_frag_reader_consume_ctx_t consume_ctx;
    long diff = fd_stream_reader_poll_frag( this_in, in_seq, &consume_ctx );
    if( FD_UNLIKELY( diff ) ) {
      ulong * housekeeping_regime = &metric_regime_ticks[0];
      ulong * prefrag_regime = &metric_regime_ticks[3];
      ulong * finish_regime = &metric_regime_ticks[6];
      if( FD_UNLIKELY( diff<0L ) ) {
        housekeeping_regime = &metric_regime_ticks[1];
        prefrag_regime = &metric_regime_ticks[4];
        finish_regime = &metric_regime_ticks[7];

        fd_stream_reader_process_overrun( this_in, &consume_ctx, diff );
      }

      /* Don't bother with spin as polling multiple locations */
      *housekeeping_regime += housekeeping_ticks;
      *prefrag_regime += prefrag_ticks;
      long next = fd_tickcount();
      *finish_regime += (ulong)(next - now);
      now = next;
      continue;
    }

    FD_COMPILER_MFENCE();
    ulong sz = 0U;
    int consumed_frag = on_stream_frag( ctx, this_in, fd_type_pun_const( consume_ctx.mline  ), &sz );

    if( FD_LIKELY( consumed_frag ) ) {
      // FD_LOG_WARNING(("consuming frag with sz: %lu", sz));
      fd_stream_reader_consume_frag( this_in, &consume_ctx, sz );
    }

    metric_regime_ticks[1] += housekeeping_ticks;
    metric_regime_ticks[4] += prefrag_ticks;
    long next = fd_tickcount();
    metric_regime_ticks[7] += (ulong)(next - now);
    now = next;
  }
}

static void
fd_unzstd_run( fd_topo_t * topo,
               fd_topo_tile_t * tile ) {
  fd_stream_frag_meta_t * in_mcache[ LINK_IN_MAX ];
  ulong *                 in_fseq  [ LINK_IN_MAX ];
  fd_memset(in_mcache, 0, sizeof(fd_stream_frag_meta_t *)*LINK_IN_MAX);
  fd_memset(in_fseq, 0, sizeof(ulong *)*LINK_IN_MAX );

  ulong polled_in_cnt = 0UL;
  for( ulong i=0UL; i<tile->in_cnt; i++ ) {
    if( FD_UNLIKELY( !tile->in_link_poll[ i ] ) ) continue;

    in_mcache[ polled_in_cnt ] = fd_type_pun( topo->links[ tile->in_link_id[ i ] ].mcache );
    FD_TEST( in_mcache[ polled_in_cnt ] );
    in_fseq[ polled_in_cnt ]   = tile->in_link_fseq[ i ];
    FD_TEST( in_fseq[ polled_in_cnt ] );
    polled_in_cnt += 1;
  }
  FD_TEST( polled_in_cnt<=LINK_IN_MAX );

  fd_stream_frag_meta_t * out_mcache[ tile->out_cnt ];
  for( ulong i=0UL; i<tile->out_cnt; i++ ) {
    out_mcache[ i ] = fd_type_pun( topo->links[ tile->out_link_id[ i ] ].mcache );
    FD_TEST( out_mcache[ i ] );
  }

  ulong   reliable_cons_cnt = 0UL;
  ulong   cons_out[ FD_TOPO_MAX_LINKS ];
  ulong * cons_fseq[ FD_TOPO_MAX_LINKS ];
  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t * consumer_tile = &topo->tiles[ i ];
    for( ulong j=0UL; j<consumer_tile->in_cnt; j++ ) {
      for( ulong k=0UL; k<tile->out_cnt; k++ ) {
        if( FD_UNLIKELY( consumer_tile->in_link_id[ j ]==tile->out_link_id[ k ] && consumer_tile->in_link_reliable[ j ] ) ) {
          cons_out[ reliable_cons_cnt ] = k;
          cons_fseq[ reliable_cons_cnt ] = consumer_tile->in_link_fseq[ j ];
          FD_TEST( cons_fseq[ reliable_cons_cnt ] );
          reliable_cons_cnt++;
          FD_TEST( reliable_cons_cnt<FD_TOPO_MAX_LINKS );
        }
      }
    }
  }

  fd_rng_t rng[1];
  FD_TEST( fd_rng_join( fd_rng_new( rng, 0, 0UL ) ) );

  fd_stream_reader_t polled_in[ polled_in_cnt ];
  for( ulong i=0UL; i<polled_in_cnt; i++ ) {
    fd_stream_reader_t * this_in = &polled_in[ i ];

    fd_stream_reader_init( this_in, fd_type_pun_const( in_mcache[ i ] ), in_fseq[ i ], i );
  }

  fd_unzstd_tile_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_LOG_WARNING(("reliable_cons_count is %lu", reliable_cons_cnt));
  ushort           event_map[ 1+reliable_cons_cnt+polled_in_cnt ];
  ulong volatile * cons_slow[   reliable_cons_cnt ];
  ulong            cons_seq [   2*reliable_cons_cnt+1 ];

  FD_LOG_WARNING(("event map is located at %lx", (ulong)event_map));
      FD_LOG_WARNING(("cons fseq is located at %lx", (ulong)cons_fseq));
      FD_LOG_WARNING(("cons seq is located at %lx", (ulong)cons_seq));

  fd_unzstd_run1( ctx,
                  polled_in_cnt,
                  polled_in,
                  reliable_cons_cnt,
                  out_mcache,
                  reliable_cons_cnt,
                  event_map,
                  cons_out,
                  cons_fseq,
                  cons_slow,
                  cons_seq,
                  (ulong)10e3,
                  rng );
}

#ifndef FD_TILE_TEST
fd_topo_run_tile_t fd_tile_snapshot_restore_Unzstd = {
  .name              = "Unzstd",
  .scratch_align     = scratch_align,
  .scratch_footprint = scratch_footprint,
  .unprivileged_init = unprivileged_init,
  .run               = fd_unzstd_run,
};
#endif