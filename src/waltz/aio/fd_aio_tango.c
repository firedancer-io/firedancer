#include "fd_aio_tango.h"

static void
fd_aio_tango_send1( fd_aio_tango_tx_t *       self,
                    fd_aio_pkt_info_t const * pkt ) {

  fd_frag_meta_t * mcache  = self->mcache;
  void *           base    = self->base;
  ulong            depth   = self->depth;
  ulong            mtu     = self->mtu;
  ulong            orig    = self->orig;
  ulong            chunk0  = self->chunk0;
  ulong            wmark   = self->wmark;
  uchar const *    data    = pkt->buf;
  ulong            data_sz = pkt->buf_sz;
  ulong            ts      = fd_frag_meta_ts_comp( fd_tickcount() );

  int som = 1;
  int eom = 0;
  do {
    ulong   frag_sz = fd_ulong_min( data_sz, mtu );
    uchar * frag    = fd_chunk_to_laddr( base, self->chunk );
    /*   */ eom     = frag_sz == data_sz;
    ulong   ctl     = fd_frag_meta_ctl( orig, som, eom, 0 );

    fd_memcpy( frag, data, frag_sz );
    fd_mcache_publish( mcache, depth, self->seq, 0UL, self->chunk, frag_sz, ctl, ts, ts );

    self->seq   = fd_seq_inc( self->seq, 1UL );
    self->chunk = fd_dcache_compact_next( self->chunk, frag_sz, chunk0, wmark );
    data       += frag_sz;
    data_sz    -= frag_sz;
    som         = 0;
  } while( FD_UNLIKELY( !eom ) );

}

static int
fd_aio_tango_send( void *                    ctx,
                   fd_aio_pkt_info_t const * batch,
                   ulong                     batch_cnt,
                   ulong *                   opt_batch_idx,
                   int                       flush ) {
  (void)opt_batch_idx; /* only set on failure, but this can't fail */
  (void)flush;         /* always immediately publish to mcache */
  for( ulong j=0UL; j<batch_cnt; j++ ) {
    fd_aio_tango_send1( ctx, batch+j );
  }
  return FD_AIO_SUCCESS;
}

fd_aio_tango_tx_t *
fd_aio_tango_tx_new( fd_aio_tango_tx_t * self,
                     fd_frag_meta_t *    mcache,
                     void *              dcache,
                     void *              base,
                     ulong               mtu,
                     ulong               orig ) {
  ulong depth = fd_mcache_depth( mcache );
  ulong chunk = fd_dcache_compact_chunk0( base, dcache );
  ulong wmark = fd_dcache_compact_wmark ( base, dcache, mtu );
  ulong seq   = fd_mcache_seq0( mcache );
  *self = (fd_aio_tango_tx_t) {
    .mcache = mcache,
    .dcache = dcache,
    .base   = base,
    .chunk0 = chunk,
    .wmark  = wmark,
    .depth  = depth,
    .mtu    = mtu,
    .orig   = orig,
    .chunk  = chunk,
    .seq    = seq,
  };
  fd_aio_new( &self->aio, self, fd_aio_tango_send );
  return self;
}

void *
fd_aio_tango_delete( fd_aio_tango_tx_t * self ) {
  fd_aio_delete( &self->aio );
  return self;
}
