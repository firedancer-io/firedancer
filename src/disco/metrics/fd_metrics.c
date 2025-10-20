#include "fd_metrics.h"
#include "../trace/fd_trace_target.h"

FD_TL ulong * fd_metrics_base_tl;
FD_TL volatile ulong * fd_metrics_tl;

static FD_TL fd_fxt_pub_t default_fxt_pub;

void *
fd_metrics_new( void * shmem,
                ulong  in_link_cnt,
                ulong  out_link_consumer_cnt ) {
  ulong footprint = FD_METRICS_FOOTPRINT(in_link_cnt, out_link_consumer_cnt);
  fd_memset( shmem, 0, footprint  );

  /* Counter metrics */
  fd_metrics_hdr_t * hdr = fd_type_pun( shmem );
  hdr->in_link_cnt           = in_link_cnt;
  hdr->out_link_consumer_cnt = out_link_consumer_cnt;

  /* Trace metrics */
  ulong mcache_sz      = fd_mcache_footprint( FD_METRICS_TRACE_DEPTH, 0UL );
  ulong dcache_data_sz = fd_dcache_req_data_sz( FD_METRICS_TRACE_MTU, FD_METRICS_TRACE_DEPTH, 1UL, 1 );
  ulong dcache_sz      = fd_dcache_footprint( dcache_data_sz, 0UL );
  FD_TEST( mcache_sz ); FD_TEST( dcache_data_sz ); FD_TEST( dcache_sz );
  FD_SCRATCH_ALLOC_INIT( l, (void *)( (ulong)shmem + FD_METRICS_COUNTERS_FOOTPRINT( in_link_cnt, out_link_consumer_cnt ) ) );
  void * mcache = FD_SCRATCH_ALLOC_APPEND( l, fd_mcache_align(), mcache_sz );
  void * dcache = FD_SCRATCH_ALLOC_APPEND( l, fd_dcache_align(), dcache_sz );
  ulong end = FD_SCRATCH_ALLOC_FINI( l, FD_METRICS_ALIGN );
  FD_TEST( end==(ulong)shmem+footprint );
  FD_TEST( fd_mcache_new( mcache, FD_METRICS_TRACE_DEPTH, 0UL, 0UL ) );
  FD_TEST( fd_dcache_new( dcache, dcache_data_sz, 0UL ) );
  hdr->trace_mcache_off = (ulong)mcache - (ulong)shmem;
  hdr->trace_dcache_off = (ulong)dcache - (ulong)shmem;

  return shmem;
}

ulong *
fd_metrics_register_ext( ulong * metrics,
                         ulong   tile_id ) {
  if( FD_UNLIKELY( !metrics ) ) FD_LOG_ERR(( "NULL metrics" ));

  fd_metrics_base_tl = metrics;
  fd_metrics_tl = fd_metrics_tile( metrics );

  fd_fxt_pub_init(
      &default_fxt_pub,
      fd_metrics_fxt_mcache( metrics ),
      fd_metrics_fxt_dcache( metrics ),
      FD_METRICS_TRACE_MTU,
      tile_id+1UL );  /* thread refs 1-indexed */
  fd_fxt_pub_cur = &default_fxt_pub;

  return metrics;
}
