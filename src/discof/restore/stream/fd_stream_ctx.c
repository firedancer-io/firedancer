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
  /* FIXME: make burst_byte and burst_frag configurable */
  for( ulong i=0UL; i<ctx->out_cnt; i++ ) {
    fd_stream_writer_new( &ctx->writers[i],
                          topo,
                          tile,
                          i,
                          512UL,
                          2UL );
  }

  fd_stream_ticks_init( ctx->ticks, ctx->event_map->event_cnt, 1e3L );
  fd_stream_metrics_init( ctx->metrics );

  /* FIXME: rng seed should not be 0 */
  FD_TEST( fd_rng_join( fd_rng_new( ctx->rng, 0, 0UL ) ) );
}

fd_stream_ctx_t *
fd_stream_ctx_new( void *           mem,
                fd_topo_t *         topo,
                fd_topo_tile_t *    tile,
                ulong               in_cnt,
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
  void * event_map_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_event_map_align(),          fd_event_map_footprint( in_cnt, out_cnt ) );
  self->writers        = FD_SCRATCH_ALLOC_APPEND( l, fd_stream_writer_align(),      sizeof(fd_stream_writer_t)*out_cnt );

  self->in_cnt   = in_cnt;
  self->out_cnt  = out_cnt;

  self->event_map = fd_event_map_new( event_map_mem, in_cnt, out_cnt );
  fd_stream_ctx_init( self, topo, tile );
  self->in_seq = 0UL;

  return self;
}
