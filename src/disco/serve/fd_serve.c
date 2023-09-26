#include "fd_serve.h"

#include "../mux/fd_mux.h"

/* fd_serve_msg_ctx_t is the message context of a transaction being
   received by the serve tile over the TPU protocol.  It is used to
   detect dcache overruns by identifying which QUIC stream is currently
   bound to a dcache chunk.  An array of fd_serve_msg_ctx_t to fit
   <depth> entries forms the dcache's app region.

   This is necessary for stream defrag, during which multiple QUIC
   streams produce into multiple dcache chunks concurrently.  In the
   worst case, a defrag is started for every available chunk in the
   dcache.  When the producer wraps around to the first dcache entry, it
   will override the existing defrag process.  This overrun is then
   safely detected through a change in conn/stream IDs when this
   previous defrag process continues. */

typedef struct __attribute__((aligned(32UL))) {
  ulong   conn_id;
  ulong   stream_id;  /* ULONG_MAX marks completed msg */
  uchar * data;       /* Points to first byte of dcache entry */
  uint    sz;
  uint    tsorig;
} fd_serve_msg_ctx_t;

/* When QUIC is being serviced and a transaction is completely received
   from the network peer, the completed message will have been written
   to the outgoing dcache.  The QUIC completion callback will then
   append a pointer to this message into a simple queue so that the core
   tile code can later publish it the outgoing mcache. */
#define QUEUE_NAME pubq
#define QUEUE_T    fd_serve_msg_ctx_t *
#include "../../util/tmpl/fd_queue_dynamic.c"

typedef struct {
  fd_serve_msg_ctx_t ** pubq;

  fd_mux_context_t * mux;

  fd_quic_t *      quic;
  const fd_aio_t * quic_rx_aio;

  ushort legacy_transaction_port; /* port for receiving non-QUIC (raw UDP) transactions on*/

  ulong xsk_aio_cnt;
  fd_xsk_aio_t ** xsk_aio;

  ulong inflight_streams; /* number of QUIC network streams currently open, used for flow control */
  ulong conn_cnt; /* count of live connections, put into the cnc for diagnostics */
  ulong quic_conn_seq; /* current quic connection sequence number, put into cnc for idagnostics */

  void  * out_wksp;
  uchar * out_dcache_app;
  ulong   out_chunk0;
  ulong   out_wmark;
  ulong   out_chunk;
} fd_serve_ctx_t;

/* fd_serve_dcache_app_footprint returns the required footprint in bytes
   for the net tile's out dcache app region of the given depth. */

FD_FN_CONST ulong
fd_serve_dcache_app_footprint( ulong depth ) {
  return depth * sizeof(fd_serve_msg_ctx_t);
}

FD_FN_CONST ulong
fd_serve_tile_scratch_align( void ) {
  return FD_SERVE_TILE_SCRATCH_ALIGN;
}

FD_FN_CONST ulong
fd_serve_tile_scratch_footprint( ulong depth,
                                 ulong in_cnt,
                                 ulong out_cnt ) {
  if( FD_UNLIKELY( in_cnt >FD_MUX_TILE_IN_MAX  ) ) return 0UL;
  if( FD_UNLIKELY( out_cnt>FD_MUX_TILE_OUT_MAX ) ) return 0UL;
  ulong scratch_top = 0UL;

  SCRATCH_ALLOC( fd_aio_align(), fd_aio_footprint() );
  SCRATCH_ALLOC( pubq_align(), pubq_footprint( depth ) );
  SCRATCH_ALLOC( fd_mux_tile_scratch_align(), fd_mux_tile_scratch_footprint( in_cnt, out_cnt ) );
  return fd_ulong_align_up( scratch_top, fd_serve_tile_scratch_align() );
}

/* This tile always publishes messages downstream, even if there are no
   credits available.  It ignores the flow control of the downstream
   verify tile.  This is OK as the verify tile is written to expect this
   behavior, and enables the serve tile to publish as fast as it can.
   It would currently be difficult trying to backpressure further up the
   stack to the network itself. */
static inline void
before_credit( void * _ctx,
               fd_mux_context_t * mux ) {
  fd_serve_ctx_t * ctx = (fd_serve_ctx_t *)_ctx;
  ctx->mux = mux;

  /* Poll network backend */
  for( ulong i=0; i<ctx->xsk_aio_cnt; i++ ) fd_xsk_aio_service( ctx->xsk_aio[i] );

  /* Service QUIC clients */
  fd_quic_service( ctx->quic );

  /* Publish completed messages */
  ulong pub_cnt = pubq_cnt( ctx->pubq );
  for( ulong i=0; i<pub_cnt; i++ ) {
    fd_serve_msg_ctx_t * msg = ctx->pubq[ i ];

    if( FD_UNLIKELY( msg->stream_id != ULONG_MAX ) )
      continue;  /* overrun */

    /* Get byte slice backing serialized txn data */

    uchar * txn    = msg->data;
    ulong   txn_sz = msg->sz;

    FD_TEST( txn_sz<=FD_TPU_MTU );

    /* At this point dcache only contains raw payload of txn.
        Beyond end of txn, but within bounds of msg layout, add a trailer
        describing the txn layout.

        [ payload      ] (txn_sz bytes)
        [ pad-align 2B ] (? bytes)
        [ fd_txn_t     ] (? bytes)
        [ payload_sz   ] (2B) */

    /* Ensure sufficient space to store trailer */

    void * txn_t = (void *)( fd_ulong_align_up( (ulong)msg->data + txn_sz, 2UL ) );
    if( FD_UNLIKELY( (FD_TPU_DCACHE_MTU - ((ulong)txn_t - (ulong)msg->data)) < (FD_TXN_MAX_SZ+2UL) ) ) {
      FD_LOG_WARNING(( "dcache entry too small" ));
      continue;
    }

    /* Parse transaction */

    ulong txn_t_sz = fd_txn_parse( txn, txn_sz, txn_t, NULL );
    if( FD_UNLIKELY( !txn_t_sz ) ) {
      FD_LOG_DEBUG(( "fd_txn_parse(sz=%lu) failed", txn_sz ));
      continue; /* invalid txn (terminate conn?) */
    }

    /* Write payload_sz */

    ushort * payload_sz = (ushort *)( (ulong)txn_t + txn_t_sz );
    *payload_sz = (ushort)txn_sz;

    /* End of message */

    void * msg_end = (void *)( (ulong)payload_sz + 2UL );

    /* Create mcache entry */

    ulong chunk  = fd_laddr_to_chunk( ctx->out_wksp, msg->data );
    ulong sz     = (ulong)msg_end - (ulong)msg->data;
    ulong sig    = 0; /* A non-dummy entry representing a finished transaction */
    ulong ctl    = fd_frag_meta_ctl( 0, 1 /* som */, 1 /* eom */, 0 /* err */ );
    ulong tsorig = msg->tsorig;
    ulong tspub  = fd_frag_meta_ts_comp( fd_tickcount() );

    FD_TEST( sz<=FD_TPU_DCACHE_MTU );
    fd_mux_publish( mux, sig, chunk, sz, ctl, tsorig, tspub );
  }
  pubq_remove_all( ctx->pubq );
  ctx->inflight_streams -= pub_cnt;
}

static inline void
cnc_diag_write( void * _ctx,
                ulong * cnc_diag ) {
  fd_serve_ctx_t * ctx = (fd_serve_ctx_t *)_ctx;

  cnc_diag[ FD_SERVE_CNC_DIAG_CONN_LIVE_CNT ]  = ctx->conn_cnt;
  cnc_diag[ FD_SERVE_CNC_DIAG_QUIC_CONN_SEQ ]  = ctx->quic_conn_seq;
}

FD_FN_CONST static inline ulong
fd_serve_chunk_idx( ulong chunk0,
                    ulong chunk ) {
  return ((chunk-chunk0)*FD_CHUNK_FOOTPRINT) / fd_ulong_align_up( FD_TPU_DCACHE_MTU, FD_CHUNK_FOOTPRINT );
}

/* fd_net_dcache_msg_ctx returns a pointer to the TPU/QUIC message
   context struct for the given dcache app laddr and chunk.  app_laddr
   points to the first byte of the dcache's app region in the tile's
   local address space and has FD_DCACHE_ALIGN alignment (see
   fd_dcache_app_laddr()).  chunk must be within the valid bounds for
   this dcache. */

FD_FN_CONST static inline fd_serve_msg_ctx_t *
fd_serve_dcache_msg_ctx( uchar * app_laddr,
                         ulong   chunk0,
                         ulong   chunk ) {
  fd_serve_msg_ctx_t * msg_arr = (fd_serve_msg_ctx_t *)app_laddr;
  return &msg_arr[ fd_serve_chunk_idx( chunk0, chunk ) ];
}

/* quic_now is called by the QUIC engine to get the current timestamp in
   UNIX time.  */

static ulong
quic_now( void * ctx ) {
  (void)ctx;
  return (ulong)fd_log_wallclock();
}

/* Tile-local sequence number for conns */
static FD_TLS ulong quic_conn_seq = 0UL;

/* quic_conn_new is invoked by the QUIC engine whenever a new connection
   is being established. */
static void
quic_conn_new( fd_quic_conn_t * conn,
               void *           _ctx ) {

  conn->local_conn_id = ++quic_conn_seq;

  fd_serve_ctx_t * ctx = (fd_serve_ctx_t *)_ctx;
  ctx->quic_conn_seq = quic_conn_seq;
  ctx->conn_cnt++;
}

/* quic_conn_final is called back by the QUIC engine whenever a
   connection is closed.  This could be because it ended gracefully, or
   was terminated, or any other reason. */
static void
quic_conn_final( fd_quic_conn_t * conn,
                 void *           _ctx ) {
  (void)conn;

  fd_serve_ctx_t * ctx = (fd_serve_ctx_t *)_ctx;
  ctx->conn_cnt--;
}

/* By default the dcache only has headroom for one in-flight fragment,
   but QUIC might have many.  If we exceed the headroom, we publish a
   dummy mcache entry to evict the reader from this fragment we want to
   use so we can start using it.

   This is not ideal because if the reader is already done with the
   fragment we are writing a useless mcache entry, so we try and do it
   only when needed.

   The QUIC receive path might typically execute stream_create,
   stream_receive, and stream_notice serially, so it is often the case
   that even if we are handling multiple new connections in one receive
   batch, the in-flight count remains zero or one. */

static inline void
fd_tpu_dummy_dcache( fd_serve_ctx_t * ctx ) {
  if( FD_LIKELY( ctx->inflight_streams > 0 ) ) {
    ulong ctl   = fd_frag_meta_ctl( 0, 1 /* som */, 1 /* eom */, 0 /* err */ );
    ulong tsnow = fd_frag_meta_ts_comp( fd_tickcount() );
    fd_mux_publish( ctx->mux, 1, 0, 0, ctl, tsnow, tsnow );
  }
}

/* quic_stream_new is called back by the QUIC engine whenever an open
   connection creates a new stream, at the time this is called, both the
   client and server must have agreed to open the stream.  In case the
   client has opened this stream, it is assumed that the QUIC
   implementation has verified that the client has the necessary stream
   quota to do so. */

static void
quic_stream_new( fd_quic_stream_t * stream,
                 void *             _ctx,
                 int                type ) {

  (void)type; /* TODO reject bidi streams? */

  /* Load QUIC state */

  fd_serve_ctx_t * ctx = (fd_serve_ctx_t *)_ctx;

  ulong conn_id   = stream->conn->local_conn_id;
  ulong stream_id = stream->stream_id;

  /* Allocate new dcache entry */

  ulong chunk = fd_dcache_compact_next( ctx->out_chunk, FD_TPU_DCACHE_MTU, ctx->out_chunk0, ctx->out_wmark );

  fd_serve_msg_ctx_t * msg_ctx = fd_serve_dcache_msg_ctx( ctx->out_dcache_app, ctx->out_chunk0, chunk );
  msg_ctx->conn_id   = conn_id;
  msg_ctx->stream_id = stream_id;
  msg_ctx->data      = fd_chunk_to_laddr( ctx->out_wksp, chunk );
  msg_ctx->sz        = 0U;
  msg_ctx->tsorig    = (uint)fd_frag_meta_ts_comp( fd_tickcount() );

  fd_tpu_dummy_dcache( ctx );

  ctx->inflight_streams += 1;

  /* Wind up for next callback */

  ctx->out_chunk  = chunk;    /* Update dcache chunk index */
  stream->context = msg_ctx;  /* Update stream dcache entry */
}

/* quic_stream_receive is called back by the QUIC engine when any stream
   in any connection being serviced receives new data.  Currently we
   simply copy received data out of the xsk (network device memory) into
   a local dcache. */

static void
quic_stream_receive( fd_quic_stream_t * stream,
                     void *             stream_ctx,
                     uchar const *      data,
                     ulong              data_sz,
                     ulong              offset,
                     int                fin ) {

  (void)fin; /* TODO instantly publish if offset==0UL && fin */

  /* Bounds check */

  /* First check that we won't overflow computing total_sz */
  if( FD_UNLIKELY( offset>UINT_MAX || data_sz>UINT_MAX ) ) {
    //fd_quic_stream_close( stream, 0x03 ); /* FIXME fd_quic_stream_close not implemented */
    return;  /* oversz stream */
  }

  ulong total_sz = offset+data_sz;
  if( FD_UNLIKELY( total_sz>FD_TPU_MTU || total_sz<offset ) ) {
    //fd_quic_stream_close( stream, 0x03 ); /* FIXME fd_quic_stream_close not implemented */
    return;  /* oversz stream */
  }

  /* Load QUIC state */

  ulong conn_id   = stream->conn->local_conn_id;
  ulong stream_id = stream->stream_id;

  /* Load existing dcache chunk ctx */

  fd_serve_msg_ctx_t * msg_ctx = (fd_serve_msg_ctx_t *)stream_ctx;
  if( FD_UNLIKELY( msg_ctx->conn_id != conn_id || msg_ctx->stream_id != stream_id ) ) {
    //fd_quic_stream_close( stream, 0x03 ); /* FIXME fd_quic_stream_close not implemented */
    FD_LOG_WARNING(( "dcache overflow while demuxing %lu!=%lu %lu!=%lu", conn_id, msg_ctx->conn_id, stream_id, msg_ctx->stream_id ));
    return;  /* overrun */
  }

  /* Append data into chunk, we know this is valid  */

  FD_TEST( offset+data_sz <= FD_TPU_MTU ); /* paranoia */
  fd_memcpy( msg_ctx->data + offset, data, data_sz );
  FD_TEST( total_sz <= UINT_MAX ); /* paranoia, total_sz<=FD_TPU_MTU above*/
  msg_ctx->sz = (uint)total_sz;
}

/* quic_stream_notify is called back by the QUIC implementation when a
   stream is finished.  This could either be because it completed
   successfully after reading valid data, or it was closed prematurely
   for some other reason.  All streams must eventually notify.

   If we see a successful QUIC stream notify, it means we have received
   a full transaction and should publish it downstream to be verified
   and executed. */

static void
quic_stream_notify( fd_quic_stream_t * stream,
                    void *             stream_ctx,
                    int                type ) {
  /* Load QUIC state */

  fd_serve_msg_ctx_t * msg_ctx = (fd_serve_msg_ctx_t *)stream_ctx;
  fd_quic_conn_t *    conn    = stream->conn;
  fd_quic_t *         quic    = conn->quic;
  fd_serve_ctx_t *    ctx     = quic->cb.quic_ctx; /* TODO ugly */

  if( FD_UNLIKELY( type!=FD_QUIC_NOTIFY_END ) ) {
    ctx->inflight_streams -= 1;
    return;  /* not a successful stream close */
  }

  ulong conn_id   = stream->conn->local_conn_id;
  ulong stream_id = stream->stream_id;
  if( FD_UNLIKELY( msg_ctx->conn_id != conn_id || msg_ctx->stream_id != stream_id ) ) {
    ctx->inflight_streams -= 1;
    return;  /* overrun */
  }

  /* Mark message as completed */

  msg_ctx->stream_id = ULONG_MAX;

  /* Add to local publish queue */

  if( FD_UNLIKELY( pubq_full( ctx->pubq ) ) ) {
    FD_LOG_WARNING(( "pubq full, dropping" ));
    ctx->inflight_streams -= 1;
    return;
  }
  pubq_push( ctx->pubq, msg_ctx );
}

/* legacy_stream_notify is called when a non-QUIC transaction is
   received, that is, a regular unencrypted UDP packet transaction.  For
   now both QUIC and non-QUIC transactions are accepted, with traffic
   type determined by port.

   UDP transactions must fit in one packet and cannot be fragmented, and
   notify here means the entire packet was received. */

static void
legacy_stream_notify( void *        _ctx,
                      uchar const * packet,
                      uint          packet_sz ) {
  fd_serve_ctx_t * ctx = (fd_serve_ctx_t *)_ctx;

  if( FD_UNLIKELY( packet_sz > FD_TPU_MTU ) ) return;

  ulong chunk = fd_dcache_compact_next( ctx->out_chunk, FD_TPU_DCACHE_MTU, ctx->out_chunk0, ctx->out_wmark );

  fd_serve_msg_ctx_t * msg_ctx = fd_serve_dcache_msg_ctx( ctx->out_dcache_app, ctx->out_chunk0, chunk );
  msg_ctx->conn_id   = ULONG_MAX;
  msg_ctx->stream_id = ULONG_MAX;
  msg_ctx->data      = fd_chunk_to_laddr( ctx->out_wksp, chunk );
  msg_ctx->sz        = packet_sz;
  msg_ctx->tsorig    = (uint)fd_frag_meta_ts_comp( fd_tickcount() );

  fd_tpu_dummy_dcache( ctx );

  if( FD_UNLIKELY( pubq_full( ctx->pubq ) ) ) {
    FD_LOG_WARNING(( "pubq full, dropping" ));
    return;
  }

  ctx->inflight_streams += 1;

  FD_TEST( packet_sz <= FD_TPU_MTU ); /* paranoia */
  fd_memcpy( msg_ctx->data, packet, packet_sz );
  pubq_push( ctx->pubq, msg_ctx );

  ctx->out_chunk = chunk;
}

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
  fd_serve_ctx_t * ctx = (fd_serve_ctx_t *)_ctx;

  for( ulong i=0; i<batch_cnt; i++ ) {
    uchar const * packet = batch[i].buf;
    uchar const * packet_end = packet + batch[i].buf_sz;

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
    ulong  ip_dstaddr  = *(uint   *)( iphdr+16UL );
    (void) ip_dstaddr;
    ushort udp_dstport = *(ushort *)( udp+2UL    );

    uchar const * data = udp + 8U;
    uint data_sz = (uint)(packet_end - data);

    if( FD_LIKELY( fd_ushort_bswap( udp_dstport ) == ctx->quic->config.net.listen_udp_port ) )
      fd_aio_send( ctx->quic_rx_aio, batch + i, 1, NULL, flush );
    else if( FD_LIKELY( fd_ushort_bswap( udp_dstport ) == ctx->legacy_transaction_port ) )
      legacy_stream_notify( ctx, data, data_sz );
    else
      FD_LOG_ERR(( "Firedancer received a UDP packet on port %hu which was not expected. "
                  "Only ports %hu and %hu should be configured to forward packets. Do "
                  "you need to reload the XDP program?",
                  fd_ushort_bswap( udp_dstport ), ctx->quic->config.net.listen_udp_port, ctx->legacy_transaction_port ));
  }

  /* the assumption here at present is that any packet that could not be
     processed is simply dropped hence, all packets were consumed */
  if( FD_LIKELY( opt_batch_idx ) ) {
    *opt_batch_idx = batch_cnt;
  }

  return FD_AIO_SUCCESS;
}

int
fd_serve_tile( fd_cnc_t *       cnc,
               ulong            pid,
               fd_quic_t *      quic,
               ushort           legacy_transaction_port,
               ulong            xsk_aio_cnt,
               fd_xsk_aio_t **  xsk_aio,
               fd_frag_meta_t * mcache,
               uchar *          dcache,
               ulong            cr_max,
               long             lazy,
               fd_rng_t *       rng,
               void *           scratch ) {
  fd_serve_ctx_t ctx[1];

  fd_mux_callbacks_t callbacks[1] = { 0 };
  callbacks->before_credit = before_credit;
  callbacks->cnc_diag_write = cnc_diag_write;

  ulong scratch_top = (ulong)scratch;

  do {
    if( FD_UNLIKELY( !quic ) ) { FD_LOG_WARNING(( "NULL quic" )); return 1; }
    if( FD_UNLIKELY( !dcache ) ) { FD_LOG_WARNING(( "NULL dcache" )); return 1; }

    quic->cb.conn_new         = quic_conn_new;
    quic->cb.conn_hs_complete = NULL;
    quic->cb.conn_final       = quic_conn_final;
    quic->cb.stream_new       = quic_stream_new;
    quic->cb.stream_receive   = quic_stream_receive;
    quic->cb.stream_notify    = quic_stream_notify;
    quic->cb.now              = quic_now;
    quic->cb.now_ctx          = NULL;
    quic->cb.quic_ctx         = ctx;

    if( FD_UNLIKELY( !xsk_aio_cnt ) ) { FD_LOG_WARNING(( "no xsk_aio" )); return 1; }
    fd_quic_set_aio_net_tx( quic, fd_xsk_aio_get_tx( xsk_aio[0] ) );

    if( FD_UNLIKELY( !fd_quic_init( quic ) ) ) { FD_LOG_WARNING(( "fd_quic_init failed" )); return 1; }
    fd_aio_t * net_rx_aio = fd_aio_join( fd_aio_new( SCRATCH_ALLOC( fd_aio_align(), fd_aio_footprint() ), ctx, net_rx_aio_send ) );

    ulong depth = fd_mcache_depth( mcache );
    if( FD_UNLIKELY( !fd_dcache_compact_is_safe( fd_wksp_containing( dcache ), dcache, FD_TPU_DCACHE_MTU, depth  ) ) ) {
      FD_LOG_WARNING(( "dcache not compatible with wksp base and mcache depth" ));
      return 1;
    }

    if( FD_UNLIKELY( fd_dcache_app_sz( dcache ) < fd_serve_dcache_app_footprint( depth ) ) ) {
      FD_LOG_WARNING(( "dcache app sz too small (min=%lu have=%lu)",
                       fd_serve_dcache_app_footprint( depth ),
                       fd_dcache_app_sz( dcache ) ));
      return 1;
    }

    ctx->out_wksp       = fd_wksp_containing( dcache );
    ctx->out_dcache_app = fd_dcache_app_laddr( dcache );
    ctx->out_chunk0     = fd_dcache_compact_chunk0( ctx->out_wksp, dcache );
    ctx->out_wmark      = fd_dcache_compact_wmark ( ctx->out_wksp, dcache, FD_TPU_DCACHE_MTU );
    ctx->out_chunk      = ctx->out_chunk0;

    ctx->inflight_streams = 0UL;
    ctx->conn_cnt = 0UL;
    ctx->quic_conn_seq = 0UL;

    ctx->quic = quic;

    ctx->legacy_transaction_port = legacy_transaction_port;

    ctx->xsk_aio_cnt = xsk_aio_cnt;
    ctx->xsk_aio = xsk_aio;
    ctx->quic_rx_aio = fd_quic_get_aio_net_rx( quic );
    for( ulong i=0; i<xsk_aio_cnt; i++ ) fd_xsk_aio_set_rx( xsk_aio[i], net_rx_aio );

    ctx->pubq = pubq_join( pubq_new( SCRATCH_ALLOC( pubq_align(), pubq_footprint( depth ) ), depth ) );
  } while(0);

  return fd_mux_tile( cnc,
                      pid,
                      FD_MUX_FLAG_MANUAL_PUBLISH | FD_MUX_FLAG_COPY,
                      0,
                      NULL,
                      NULL,
                      mcache,
                      0, /* no reliable consumers, verify tiles may be overrun */
                      NULL,
                      cr_max,
                      lazy,
                      rng,
                      (void*)fd_ulong_align_up( scratch_top, FD_MUX_TILE_SCRATCH_ALIGN ),
                      ctx,
                      callbacks );
}
