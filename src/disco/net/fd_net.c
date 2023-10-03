#include "fd_net.h"

#include "../mux/fd_mux.h"

typedef struct {
  ulong xsk_aio_cnt;
  fd_xsk_aio_t ** xsk_aio;

  ulong round_robin_cnt;
  ulong round_robin_id;

  const fd_aio_t * tx;

  uchar frame[ FD_NET_MTU ];

  fd_mux_context_t * mux;

  void * in_wksp;
  ulong  in_chunk0;
  ulong  in_wmark;

  void  * out_wksp;
  ulong   out_chunk0;
  ulong   out_wmark;
  ulong   out_chunk;
} fd_net_ctx_t;

/* net_rx_aio_send is a callback invoked by aio when new data is
   received on an incoming xsk.  The xsk might be bound to any interface
   or ports, so the purpose of this callback is to determine if the
   packet might be a valid transaction, and whether it is QUIC or
   non-QUIC (raw UDP) before forwarding to the appropriate handler.

   This callback is supposed to return the number of packets in the
   batch which were successfully processed, but we always return
   batch_cnt since there is no logic in place to backpressure this far
   up the stack there is no sane way to "not handle" an incoming packet.
   */
static int
net_rx_aio_send( void *                    _ctx,
                 fd_aio_pkt_info_t const * batch,
                 ulong                     batch_cnt,
                 ulong *                   opt_batch_idx,
                 int                       flush ) {
  (void)flush;

  fd_net_ctx_t * ctx = (fd_net_ctx_t *)_ctx;

  for( ulong i=0; i<batch_cnt; i++ ) {
    uchar const * packet = batch[i].buf;
    uchar const * packet_end = packet + batch[i].buf_sz;

    if( FD_UNLIKELY( batch[i].buf_sz > FD_NET_MTU ) )
      FD_LOG_ERR(( "received a UDP packet with a too large payload (%u)", batch[i].buf_sz ));

    uchar const * iphdr = packet + 14U;

    /* Filter for UDP/IPv4 packets. Test for ethtype and ipproto in 1
       branch */
    uint test_ethip = ( (uint)packet[12] << 16u ) | ( (uint)packet[13] << 8u ) | (uint)packet[23];
    if( FD_UNLIKELY( test_ethip!=0x080011 ) )
      FD_LOG_ERR(( "Firedancer received a packet from the XDP program that was either "
                   "not an IPv4 packet, or not a UDP packet. It is likely your XDP program "
                   "is not configured correctly." ));

    /* IPv4 is variable-length, so lookup IHL to find start of UDP */
    uint iplen = ( ( (uint)iphdr[0] ) & 0x0FU ) * 4U;
    uchar const * udp = iphdr + iplen;

    /* Ignore if UDP header is too short */
    if( FD_UNLIKELY( udp+4U > packet_end ) ) continue;

    /* Extract IP dest addr and UDP dest port */
    uint ip_srcaddr    = *(uint   *)( iphdr+12UL );
    ushort udp_dstport = *(ushort *)( udp+2UL    );

    fd_memcpy( fd_chunk_to_laddr( ctx->out_wksp, ctx->out_chunk ), packet, batch[i].buf_sz );

    /* tile can decide how to partition based on src ip addr and port */
    ulong sig = fd_disco_netmux_sig( ip_srcaddr, fd_ushort_bswap( udp_dstport ), SRC_TILE_NET, 0 );

    ulong tspub  = (ulong)fd_frag_meta_ts_comp( fd_tickcount() );
    fd_mux_publish( ctx->mux, sig, ctx->out_chunk, batch[i].buf_sz, 0, 0, tspub );

    ctx->out_chunk = fd_dcache_compact_next( ctx->out_chunk, FD_NET_MTU, ctx->out_chunk0, ctx->out_wmark );
  }

  if( FD_LIKELY( opt_batch_idx ) ) {
    *opt_batch_idx = batch_cnt;
  }

  return FD_AIO_SUCCESS;
}

static void
before_credit( void * _ctx,
               fd_mux_context_t * mux ) {
  fd_net_ctx_t * ctx = (fd_net_ctx_t *)_ctx;

  ctx->mux = mux;

  for( ulong i=0; i<ctx->xsk_aio_cnt; i++ ) {
    fd_xsk_aio_service( ctx->xsk_aio[i] );
  }
}

static void
before_frag( void * _ctx,
             ulong  in_idx,
             ulong  seq,
             ulong  sig,
             int *  opt_filter ) {
  (void)in_idx;

  fd_net_ctx_t * ctx = (fd_net_ctx_t *)_ctx;

  ushort src_tile = fd_disco_netmux_sig_src_tile( sig );

  /* round robin by sequence number for now, quic should be modified to
     echo the net tile index back so we can transmit on the same queue */
  int handled_packet = (seq % ctx->round_robin_cnt) == ctx->round_robin_id;
  if( FD_UNLIKELY( src_tile == SRC_TILE_NET || !handled_packet ) ) {
    *opt_filter = 1;
  }
}

static void
during_frag( void * _ctx,
             ulong in_idx,
             ulong sig,
             ulong chunk,
             ulong sz,
             int * opt_filter ) {
  (void)in_idx;
  (void)sig;
  (void)opt_filter;

  fd_net_ctx_t * ctx = (fd_net_ctx_t *)_ctx;

  if( FD_UNLIKELY( chunk<ctx->in_chunk0 || chunk>=ctx->in_wmark || sz > FD_NET_MTU ) )
    FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu)", chunk, sz, ctx->in_chunk0, ctx->in_wmark ));

  uchar * src = (uchar *)fd_chunk_to_laddr( ctx->in_wksp, chunk );
  fd_memcpy( ctx->frame, src, sz ); // TODO: Change xsk_aio interface to eliminate this copy
}

static void
after_frag( void *  _ctx,
            ulong * opt_sig,
            ulong * opt_chunk,
            ulong * opt_sz,
            int *   opt_filter ) {
  (void)opt_sig;
  (void)opt_chunk;
  (void)opt_filter;

  fd_net_ctx_t * ctx = (fd_net_ctx_t *)_ctx;

  fd_aio_pkt_info_t aio_buf = { .buf = ctx->frame, .buf_sz = (ushort)*opt_sz };
  ctx->tx->send_func( ctx->xsk_aio[ 0 ], &aio_buf, 1, NULL, 1 );

  *opt_filter = 1;
}

int
fd_net_tile( fd_cnc_t *              cnc,
             ulong                   pid,
             ulong                   in_cnt,
             const fd_frag_meta_t ** in_mcache,
             ulong **                in_fseq,
             ulong                   round_robin_cnt,
             ulong                   round_robin_id,
             ulong                   xsk_aio_cnt,
             fd_xsk_aio_t **         xsk_aio,
             fd_frag_meta_t *        mcache,
             uchar *                 dcache,
             ulong                   cr_max,
             long                    lazy,
             fd_rng_t *              rng,
             void *                  scratch ) {
  fd_net_ctx_t ctx[1];

  fd_mux_callbacks_t callbacks[1] = { 0 };

  callbacks->before_credit = before_credit;
  callbacks->before_frag   = before_frag;
  callbacks->during_frag   = during_frag;
  callbacks->after_frag    = after_frag;

  ulong scratch_top = (ulong)scratch;

  do {
    if( FD_UNLIKELY( !dcache ) ) { FD_LOG_WARNING(( "NULL dcache" )); return 1; }

    ulong depth = fd_mcache_depth( mcache );
    if( FD_UNLIKELY( !fd_dcache_compact_is_safe( fd_wksp_containing( dcache ), dcache, FD_NET_MTU, depth  ) ) ) {
      FD_LOG_WARNING(( "dcache not compatible with wksp base and mcache depth" ));
      return 1;
    }

    if( FD_UNLIKELY( !xsk_aio_cnt ) ) { FD_LOG_WARNING(( "no xsk_aio" )); return 1; }

    fd_aio_t * net_rx_aio = fd_aio_join( fd_aio_new( SCRATCH_ALLOC( fd_aio_align(), fd_aio_footprint() ), ctx, net_rx_aio_send ) );
    for( ulong i=0; i<xsk_aio_cnt; i++ ) fd_xsk_aio_set_rx( xsk_aio[i], net_rx_aio );

    if( FD_UNLIKELY( !round_robin_cnt ) ) { FD_LOG_WARNING(( "round_robin_cnt is zero" )); return 1; }
    if( FD_UNLIKELY( round_robin_id >= round_robin_cnt ) ) { FD_LOG_WARNING(( "round_robin_id is too large" )); return 1; }
    ctx->round_robin_cnt = round_robin_cnt;
    ctx->round_robin_id  = round_robin_id;

    ctx->xsk_aio_cnt = xsk_aio_cnt;
    ctx->xsk_aio = xsk_aio;
    ctx->tx = fd_xsk_aio_get_tx( xsk_aio[ 0 ] );

    ctx->in_wksp = fd_wksp_containing( mcache );

    /* Put a bound on chunks we read from the input, to make sure they
       are within in the data region of the workspace. */
    ctx->in_chunk0 = fd_disco_compact_chunk0( ctx->in_wksp );
    ctx->in_wmark  = fd_disco_compact_wmark ( ctx->in_wksp, FD_NET_MTU );

    ctx->out_wksp   = fd_wksp_containing( dcache );
    ctx->out_chunk0 = fd_dcache_compact_chunk0( ctx->out_wksp, dcache );
    ctx->out_wmark  = fd_dcache_compact_wmark ( ctx->out_wksp, dcache, FD_NET_MTU );
    ctx->out_chunk  = ctx->out_chunk0;
  } while(0);

  return fd_mux_tile( cnc,
                      pid,
                      FD_MUX_FLAG_MANUAL_PUBLISH | FD_MUX_FLAG_COPY,
                      in_cnt,
                      in_mcache,
                      in_fseq,
                      mcache,
                      0, /* no reliable consumers, downstream tiles may be overrun */
                      NULL,
                      cr_max,
                      lazy,
                      rng,
                      (void*)fd_ulong_align_up( scratch_top, FD_MUX_TILE_SCRATCH_ALIGN ),
                      ctx,
                      callbacks );
}
