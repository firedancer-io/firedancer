#include "fd_stream_ctx.h"

void
fd_stream_ctx_init( fd_stream_ctx_t * ctx,
                 fd_topo_t *          topo,
                 fd_topo_tile_t *     tile ) {
  /* init in */
  ulong in_idx = 0UL;
  for( ulong i=0UL; i<ctx->in_cnt; i++ ) {
    if( FD_UNLIKELY( !tile->in_link_poll[ i ] ) ) continue;

    fd_stream_reader_init( &ctx->in[ in_idx ],
                           fd_type_pun( topo->links[ tile->in_link_id[ i ] ].mcache ),
                           tile->in_link_fseq[ i ],
                           in_idx );
    in_idx++;
  }

  /* init in_ptrs */
  for( ulong i=0UL; i<ctx->in_cnt; i++ ) {
    ctx->in_ptrs[ i ] = &ctx->in[ i ];
  }

  /* init writers */
  for( ulong i=0UL; i<ctx->out_cnt; i++ ) {
    fd_stream_frag_meta_t * out_mcache = fd_type_pun( topo->links[ tile->out_link_id[ i ] ].mcache );
    void * dcache                      = fd_dcache_join( fd_topo_obj_laddr( topo, topo->links[ tile->out_link_id[ i ] ].dcache_obj_id ) );
    fd_topo_link_t const * link        = &topo->links[ tile->out_link_id[ i ] ];
    ulong writer_cons_cnt              = fd_topo_link_reliable_consumer_cnt( topo, link );
    fd_stream_writer_new( &ctx->writers[i],
                          out_mcache,
                          dcache,
                          writer_cons_cnt,
                          512UL,
                          2UL );
  }

  /* init cons_fseq */
  ulong cons_idx = 0UL;
  for( ulong i=0UL; i<tile->out_cnt; i++ ) {
    ulong local_cons_idx = 0UL;
    for( ulong j=0UL; j<topo->tile_cnt; j++ ) {
      fd_topo_tile_t * consumer_tile = &topo->tiles[ j ];
      for( ulong k=0UL; k<consumer_tile->in_cnt; k++ ) {
        if( FD_UNLIKELY( consumer_tile->in_link_id[ k ]==tile->out_link_id[ i ] && consumer_tile->in_link_reliable[ k ] ) ) {
          ctx->cons_fseq[ cons_idx ] = consumer_tile->in_link_fseq[ k ];
          if( FD_UNLIKELY( !ctx->cons_fseq[ cons_idx ] ) ) FD_LOG_ERR(( "NULL cons_fseq[%lu]", cons_idx ));
          fd_stream_writer_set_cons_fseq( &ctx->writers[i], local_cons_idx, consumer_tile->in_link_fseq[ k ] );
          ctx->consumer_ctx[ cons_idx ].writer = &ctx->writers[ i ];
          ctx->consumer_ctx[ cons_idx ].writer_cons_idx = local_cons_idx;
          cons_idx++;
          local_cons_idx++;
        }
      }
    }
  }

  fd_stream_ticks_init( ctx->ticks, ctx->event_map->event_cnt, 1e3L );
  fd_stream_metrics_init( ctx->metrics );
  FD_TEST( fd_rng_join( fd_rng_new( ctx->rng, 0, 0UL ) ) );

  /* init metrics link for cons_slow */
  cons_idx = 0UL;
  for( ; cons_idx<ctx->cons_cnt; cons_idx++ ) {
    ctx->cons_slow[ cons_idx ] = (ulong *)(fd_metrics_link_out( fd_metrics_base_tl, cons_idx ) + FD_METRICS_COUNTER_LINK_SLOW_COUNT_OFF);
  }
}

fd_stream_ctx_t *
fd_stream_ctx_new( void *           mem,
                fd_topo_t *         topo,
                fd_topo_tile_t *    tile,
                ulong               in_cnt,
                ulong               cons_cnt,
                ulong               out_cnt ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_stream_ctx_scratch_align() ) ) ) {
    FD_LOG_WARNING(( "unaligned mem" ));
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_stream_ctx_t * self = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_stream_ctx_t), sizeof(fd_stream_ctx_t) );

  self->in             = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_stream_reader_t),   in_cnt*sizeof(fd_stream_reader_t) );
  self->in_ptrs        = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_stream_reader_t *), in_cnt*sizeof(fd_stream_reader_t *) );
  self->cons_fseq      = FD_SCRATCH_ALLOC_APPEND( l, alignof(ulong const *),        cons_cnt*sizeof(ulong const *) );
  self->cons_slow      = FD_SCRATCH_ALLOC_APPEND( l, alignof(ulong *),              cons_cnt*sizeof(ulong *) );
  void * event_map_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_event_map_align(),          fd_event_map_footprint( in_cnt, cons_cnt ) );
  self->consumer_ctx   = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_consumer_ctx_t),    sizeof(fd_consumer_ctx_t)*out_cnt );
  self->writers        = FD_SCRATCH_ALLOC_APPEND( l, fd_stream_writer_align(),      sizeof(fd_stream_writer_t)*out_cnt );

  self->in_cnt   = in_cnt;
  self->cons_cnt = cons_cnt;
  self->out_cnt  = out_cnt;

  self->event_map = fd_event_map_new( event_map_mem, in_cnt, cons_cnt );
  fd_stream_ctx_init( self, topo, tile );
  self->in_seq = 0UL;

  return self;
}
