#include "fd_pkt_w_tango.h"
#include "../../tango/mcache/fd_mcache.h"

void
fd_pkt_w_tango_post( void * self,
                     ulong  sz ) {
  fd_pkt_w_tango_t * w = (fd_pkt_w_tango_t *)self;
  ulong chunk = w->base.chunk;
  fd_mcache_publish( w->out_mcache, w->out_depth, w->out_seq, 0UL, chunk, sz, 0UL, 0UL, 0UL );
}

void
fd_pkt_w_tango_flush( void * self ) {
  fd_pkt_w_tango_t * w = (fd_pkt_w_tango_t *)self;
  fd_mcache_seq_update( fd_mcache_seq_laddr( w->out_mcache ), w->out_seq );
}

void
fd_pkt_w_tango_fini( void * self ) {
  fd_pkt_w_tango_flush( self );
}

static fd_pkt_writer_vt_t const fd_pkt_w_tango_vt = {
  .fini  = fd_pkt_w_tango_fini,
  .post  = fd_pkt_w_tango_post,
  .flush = fd_pkt_w_tango_flush
};

fd_pkt_writer_t *
fd_pkt_w_tango_new( fd_pkt_w_tango_t * w,
                    fd_frag_meta_t *   mcache,
                    uchar *            dcache,
                    void *             base,
                    ulong              mtu ) {
  ulong depth       = fd_mcache_depth( mcache );
  ulong req_data_sz = fd_dcache_req_data_sz( mtu, depth, 1UL, 1 );
  ulong data_sz     = fd_dcache_data_sz( dcache );
  if( FD_UNLIKELY( data_sz<req_data_sz ) ) {
    FD_LOG_WARNING(( "dcache data region too small for depth=%lu mtu=%lu (want %lu bytes, have %lu bytes)",
                     depth, mtu, req_data_sz, data_sz ));
    return NULL;
  }

  *w = (fd_pkt_w_tango_t) {
    .base = {
      .vt     = &fd_pkt_w_tango_vt,
      .mtu    = mtu,
      .quota  = 0UL,
      .base   = base,
      .chunk0 = fd_dcache_compact_chunk0( base, dcache ),
      .wmark  = fd_dcache_compact_wmark ( base, dcache, mtu ),
      .chunk  = fd_dcache_compact_chunk0( base, dcache )
    },
    .out_mcache = mcache,
    .out_depth  = depth,
    .out_seq    = fd_mcache_seq0( mcache )
  };

  return &w->base;
}
