#include "fd_stream_ctx.h"
#include "fd_stream_writer.h"

FD_FN_PURE ulong
fd_stream_ctx_align( void ) {
  return 128UL;
}

ulong
fd_stream_ctx_footprint( fd_topo_t const *      topo,
                         fd_topo_tile_t const * tile ) {
  ulong const in_cnt  = fd_topo_tile_producer_cnt( topo, tile );
  ulong const out_cnt = tile->out_cnt;

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_stream_ctx_t),      sizeof(fd_stream_ctx_t) );
  l = FD_LAYOUT_APPEND( l, alignof(fd_stream_reader_t),   in_cnt*sizeof(fd_stream_reader_t) );
  l = FD_LAYOUT_APPEND( l, alignof(fd_stream_reader_t *), in_cnt*sizeof(fd_stream_reader_t *) );
  l = FD_LAYOUT_APPEND( l, alignof(fd_event_map_t),       fd_event_map_footprint( in_cnt, out_cnt ) );
  l = FD_LAYOUT_APPEND( l, alignof(fd_stream_writer_t *), out_cnt*sizeof(fd_stream_writer_t *) );
  for( ulong i=0UL; i<tile->out_cnt; i++ ) {
    fd_topo_link_t const * link = &topo->links[ tile->out_link_id[ i ] ];
    ulong writer_fp = fd_stream_writer_footprint( fd_topo_link_reliable_consumer_cnt( topo, link ) );
    FD_TEST( writer_fp );
    l = FD_LAYOUT_APPEND( l, fd_stream_writer_align(), writer_fp );
  }
  return FD_LAYOUT_FINI( l, fd_stream_ctx_align() );
}

fd_stream_ctx_t *
fd_stream_ctx_new( void *                 mem,
                   fd_topo_t const *      topo,
                   fd_topo_tile_t const * tile ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_stream_ctx_align() ) ) ) {
    FD_LOG_WARNING(( "unaligned mem" ));
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_stream_ctx_t * self = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_stream_ctx_t), sizeof(fd_stream_ctx_t) );
  fd_memset( self, 0, sizeof(fd_stream_ctx_t) );

  ulong const in_cnt  = fd_topo_tile_producer_cnt( topo, tile );
  ulong const out_cnt = tile->out_cnt;

  self->in             = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_stream_reader_t),   in_cnt*sizeof(fd_stream_reader_t) );
  self->in_ptrs        = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_stream_reader_t *), in_cnt*sizeof(fd_stream_reader_t *) );
  void * event_map_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_event_map_align(),          fd_event_map_footprint( in_cnt, out_cnt ) );
  self->writers        = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_stream_writer_t *), out_cnt*sizeof(fd_stream_writer_t *) );

  for( ulong i=0UL; i<tile->out_cnt; i++ ) {
    fd_topo_link_t const * link     = &topo->links[ tile->out_link_id[ i ] ];
    ulong const            cons_cnt = fd_topo_link_reliable_consumer_cnt( topo, link );
    void *                 writer   = FD_SCRATCH_ALLOC_APPEND( l, fd_stream_writer_align(), fd_stream_writer_footprint( cons_cnt ) );

    self->writers[ i ] = fd_stream_writer_new_topo(
        writer,
        fd_topo_link_reliable_consumer_cnt( topo, link ),
        topo,
        tile,
        i
    );
    if( FD_UNLIKELY( !self->writers[ i ] ) ) return NULL; /* logs warning */
  }

  self->in_cnt   = in_cnt;
  self->out_cnt  = out_cnt;

  self->event_map = fd_event_map_new( event_map_mem, in_cnt, out_cnt );
  self->in_seq = 0UL;

  /* init in */
  ulong in_idx = 0UL;
  for( ulong i=0UL; i<self->in_cnt; i++ ) {
    if( FD_UNLIKELY( !tile->in_link_poll[ i ] ) ) continue;

    fd_stream_reader_init( &self->in[ in_idx ],
                           fd_type_pun( topo->links[ tile->in_link_id[ i ] ].mcache ),
                           tile->in_link_fseq[ i ],
                           in_idx );
    in_idx++;
  }

  /* init in_ptrs */
  for( ulong i=0UL; i<self->in_cnt; i++ ) {
    self->in_ptrs[ i ] = &self->in[ i ];
  }

  /* init writers */
  for( ulong i=0UL; i<self->out_cnt; i++ ) {
    fd_stream_writer_new_topo(
        self->writers[i],
        self->out_cnt,
        topo,
        tile,
        i
    );
  }

  fd_stream_ticks_init( self->ticks, self->event_map->event_cnt, 1e3L );
  fd_stream_metrics_init( self->metrics );
  FD_TEST( fd_rng_join( fd_rng_new( self->rng, 0, 0UL ) ) );

  FD_SCRATCH_ALLOC_FINI( l, fd_stream_ctx_align() );
  return self;
}
