#include "fd_pkt_buf.h"
#include "../../tango/mcache/fd_mcache.h"

ulong
fd_pkt_buf_align( void ) {
  return fd_ulong_max( alignof(fd_pkt_buf_t), fd_ulong_max( fd_mcache_align(), fd_dcache_align() ) );
}

ulong
fd_pkt_buf_footprint( ulong depth,
                      ulong mtu ) {
  ulong data_sz = fd_dcache_req_data_sz( mtu, depth, 1UL, 1 );
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_pkt_buf_t), sizeof(fd_pkt_buf_t)                );
  l = FD_LAYOUT_APPEND( l, fd_mcache_align(),     fd_mcache_footprint( depth,   0UL ) );
  l = FD_LAYOUT_APPEND( l, fd_dcache_align(),     fd_dcache_footprint( data_sz, 0UL ) );
  return FD_LAYOUT_FINI( l, fd_pkt_buf_align() );
}

fd_pkt_buf_t *
fd_pkt_buf_new( void * mem,
                ulong  depth,
                ulong  mtu ) {
  ulong data_sz = fd_dcache_req_data_sz( mtu, depth, 1UL, 1 );
  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_pkt_buf_t * buf        = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_pkt_buf_t), sizeof(fd_pkt_buf_t)                );
  void *         mcache_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_mcache_align(),     fd_mcache_footprint( depth,   0UL ) );
  void *         dcache_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_dcache_align(),     fd_dcache_footprint( data_sz, 0UL ) );
  FD_SCRATCH_ALLOC_FINI( l, fd_pkt_buf_align() );

  fd_frag_meta_t * mcache = fd_mcache_join( fd_mcache_new( mcache_mem, depth,   0UL, 0UL ) ); FD_TEST( mcache );
  uchar *          dcache = fd_dcache_join( fd_dcache_new( dcache_mem, data_sz, 0UL      ) ); FD_TEST( dcache );
  FD_TEST( fd_pkt_w_tango_new( &buf->writer, mcache, dcache, mem, mtu ) );

  return buf;
}

void *
fd_pkt_buf_delete( fd_pkt_buf_t * buf ) {

  if( FD_UNLIKELY( !buf ) ) {
    FD_LOG_WARNING(( "NULL buf" ));
    return NULL;
  }

  memset( buf, 0, sizeof(fd_pkt_buf_t) );
  return buf;
}

int
fd_pkt_buf_next( fd_pkt_buf_t * buf ) {
  ulong tail_seq  = fd_seq_inc( buf->tail_seq, 1UL );
  ulong depth     = buf->depth;
  ulong line_idx  = fd_mcache_line_idx( tail_seq, depth );
  ulong found_seq = buf->mcache[ line_idx ].seq;
  if( fd_seq_eq( found_seq, tail_seq ) ) {
    buf->tail_seq = tail_seq;
    return 1;
  }
  if( FD_LIKELY( fd_seq_lt( found_seq, tail_seq ) ) ) return 0;
  buf->tail_seq = found_seq;
  return 2;
}

fd_pb_less_t *
fd_pkt_buf_pb( fd_pkt_buf_t * buf,
               void *         scratch,
               ulong          scratch_sz ) {
  return fd_pb_less_parse( scratch, scratch_sz, fd_pkt_buf_msg( buf ), fd_pkt_buf_msg_sz( buf ) );
}
