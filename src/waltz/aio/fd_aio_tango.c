#include "fd_aio_tango.h"

static void
fd_aio_tango_send1( fd_aio_tango_tx_t *       self,
                    fd_aio_pkt_info_t const * pkt ) {

  fd_frag_meta_t * mcache  = self->mcache;
  void *           base    = self->base;
  ulong            depth   = self->depth;
  ulong            mtu     = self->mtu;
  ulong            orig    = self->orig;
  ulong            sig     = self->sig;
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
    fd_mcache_publish( mcache, depth, self->seq, sig, self->chunk, frag_sz, ctl, ts, ts );

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
fd_aio_tango_tx_delete( fd_aio_tango_tx_t * self ) {
  fd_aio_delete( &self->aio );
  return self;
}


fd_aio_tango_rx_t *
fd_aio_tango_rx_new( fd_aio_tango_rx_t *    self,
                     fd_aio_t const *       aio,
                     fd_frag_meta_t const * mcache,
                     ulong                  seq0,
                     void *                 base ) {
  ulong depth = fd_mcache_depth( mcache );
  *self = (fd_aio_tango_rx_t) {
    .mcache = mcache,
    .depth  = depth,
    .base   = base,
    .seq    = seq0,
    .aio    = aio,
  };
  return self;
}

void *
fd_aio_tango_rx_delete( fd_aio_tango_rx_t * self ) {
  return self;
}

void
fd_aio_tango_rx_poll( fd_aio_tango_rx_t * self ) {
  fd_frag_meta_t const * mcache = self->mcache;
  ulong                  depth  = self->depth;
  void *                 base   = self->base;
  fd_aio_t const *       aio    = self->aio;

# define RX_BATCH (64UL)
  fd_aio_pkt_info_t batch[ RX_BATCH ];
  ulong             batch_idx;
  for( batch_idx=0UL; batch_idx<RX_BATCH; batch_idx++ ) {

    /* Poll next fragment */
    ulong seq_expected = self->seq;
    fd_frag_meta_t const * mline = mcache + fd_mcache_line_idx( seq_expected, depth );
    FD_COMPILER_MFENCE();
    ulong seq_found = mline->seq;
    FD_COMPILER_MFENCE();
    ulong chunk  = mline->chunk;
    ulong sz     = mline->sz;
    ulong ctl    = mline->ctl;
    FD_COMPILER_MFENCE();
    ulong seq_test = mline->seq;
    FD_COMPILER_MFENCE();
    if( !fd_seq_eq( seq_found, seq_test ) ) break; /* overrun */

    if( fd_seq_gt( seq_expected, seq_found ) ) {
      /* caught up */
      break;
    }

    if( fd_seq_lt( seq_expected, seq_found ) ) {
      /* overrun */
      self->seq = seq_found;
      break;
    }

    if( fd_frag_meta_ctl_err( ctl ) || !fd_frag_meta_ctl_som( ctl ) ) {
      batch_idx--;
    } else {
      batch[ batch_idx ].buf    = fd_chunk_to_laddr( base, chunk );
      batch[ batch_idx ].buf_sz = (ushort)sz;
    }

    self->seq = fd_seq_inc( seq_expected, 1UL );

  }

  if( batch_idx==0UL ) return;
  ulong batch_cons;
  fd_aio_send( aio, batch, batch_idx, &batch_cons, 1 );
}
