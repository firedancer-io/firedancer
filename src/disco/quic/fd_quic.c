#include "fd_quic.h"

#include "../mux/fd_mux.h"

/* fd_quic_msg_ctx_t is the message context of a txn being received by
   the QUIC tile over the TPU protocol.  It is used to detect dcache
   overruns by identifying which QUIC stream is currently bound to a
   dcache chunk.  An array of fd_quic_msg_ctx_t to fit <depth> entries
   forms the dcache's app region.

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
} fd_quic_msg_ctx_t;

/* When QUIC is being serviced and a transaction is completely received
   from the network peer, the completed message will have been written
   to the outgoing dcache.  The QUIC completion callback will then
   append a pointer to this message into a simple queue so that the core
   tile code can later publish it the outgoing mcache. */
#define QUEUE_NAME pubq
#define QUEUE_T    fd_quic_msg_ctx_t *
#include "../../util/tmpl/fd_queue_dynamic.c"

typedef struct {
  fd_quic_msg_ctx_t ** pubq;

  fd_mux_context_t * mux;

  fd_quic_t *      quic;
  const fd_aio_t * quic_rx_aio;

  ushort legacy_transaction_port; /* port for receiving non-QUIC (raw UDP) transactions on*/

  uchar buffer[ FD_NET_MTU ];

  ulong inflight_streams; /* number of QUIC network streams currently open, used for flow control */
  ulong conn_cnt; /* count of live connections, put into the cnc for diagnostics */
  ulong conn_seq; /* current quic connection sequence number, put into cnc for idagnostics */

  ulong round_robin_cnt;
  ulong round_robin_id;

  void * in_wksp;
  ulong  in_chunk0;
  ulong  in_wmark;

  fd_frag_meta_t * net_out_mcache;
  ulong *          net_out_sync;
  ulong            net_out_depth;
  ulong            net_out_seq;

  void *  net_out_wksp;
  ulong   net_out_chunk0;
  ulong   net_out_wmark;
  ulong   net_out_chunk;

  void  * verify_out_wksp;
  uchar * verify_out_dcache_app;
  ulong   verify_out_chunk0;
  ulong   verify_out_wmark;
  ulong   verify_out_chunk;
} fd_quic_ctx_t;

/* fd_quic_dcache_app_footprint returns the required footprint in bytes
   for the QUIC tile's out dcache app region of the given depth. */

FD_FN_CONST ulong
fd_quic_dcache_app_footprint( ulong depth ) {
  return depth * sizeof(fd_quic_msg_ctx_t);
}

FD_FN_CONST ulong
fd_quic_tile_scratch_align( void ) {
  return FD_QUIC_TILE_SCRATCH_ALIGN;
}

FD_FN_CONST ulong
fd_quic_tile_scratch_footprint( ulong depth,
                                ulong in_cnt,
                                ulong out_cnt ) {
  if( FD_UNLIKELY( in_cnt >FD_MUX_TILE_IN_MAX  ) ) return 0UL;
  if( FD_UNLIKELY( out_cnt>FD_MUX_TILE_OUT_MAX ) ) return 0UL;
  ulong scratch_top = 0UL;

  SCRATCH_ALLOC( fd_aio_align(), fd_aio_footprint() );
  SCRATCH_ALLOC( pubq_align(), pubq_footprint( depth ) );
  SCRATCH_ALLOC( fd_mux_tile_scratch_align(), fd_mux_tile_scratch_footprint( in_cnt, out_cnt ) );
  return fd_ulong_align_up( scratch_top, fd_quic_tile_scratch_align() );
}

FD_FN_CONST static inline ulong
fd_quic_chunk_idx( ulong chunk0,
                   ulong chunk ) {
  return ((chunk-chunk0)*FD_CHUNK_FOOTPRINT) / fd_ulong_align_up( FD_TPU_DCACHE_MTU, FD_CHUNK_FOOTPRINT );
}

/* fd_quic_dcache_msg_ctx returns a pointer to the TPU/QUIC message
   context struct for the given dcache app laddr and chunk.  app_laddr
   points to the first byte of the dcache's app region in the tile's
   local address space and has FD_DCACHE_ALIGN alignment (see
   fd_dcache_app_laddr()).  chunk must be within the valid bounds for
   this dcache. */

FD_FN_CONST static inline fd_quic_msg_ctx_t *
fd_quic_dcache_msg_ctx( uchar * app_laddr,
                        ulong   chunk0,
                        ulong   chunk ) {
  fd_quic_msg_ctx_t * msg_arr = (fd_quic_msg_ctx_t *)app_laddr;
  return &msg_arr[ fd_quic_chunk_idx( chunk0, chunk ) ];
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
fd_tpu_dummy_dcache( fd_quic_ctx_t * ctx ) {
  if( FD_LIKELY( ctx->inflight_streams > 0 ) ) {
    ulong ctl   = fd_frag_meta_ctl( 0, 1 /* som */, 1 /* eom */, 0 /* err */ );
    ulong tsnow = fd_frag_meta_ts_comp( fd_tickcount() );
    fd_mux_publish( ctx->mux, 1, 0, 0, ctl, tsnow, tsnow );
  }
}

/* legacy_stream_notify is called when a non-QUIC transaction is
   received, that is, a regular unencrypted UDP packet transaction.  For
   now both QUIC and non-QUIC transactions are accepted, with traffic
   type determined by port.

   UDP transactions must fit in one packet and cannot be fragmented, and
   notify here means the entire packet was received. */

static void
legacy_stream_notify( fd_quic_ctx_t * ctx,
                      uchar *         packet,
                      uint            packet_sz ) {
  if( FD_UNLIKELY( packet_sz > FD_TPU_MTU ) ) FD_LOG_ERR(( "corrupt packet too large" ));

  ulong chunk = fd_dcache_compact_next( ctx->verify_out_chunk, FD_TPU_DCACHE_MTU, ctx->verify_out_chunk0, ctx->verify_out_wmark );

  fd_quic_msg_ctx_t * msg_ctx = fd_quic_dcache_msg_ctx( ctx->verify_out_dcache_app, ctx->verify_out_chunk0, chunk );
  msg_ctx->conn_id   = ULONG_MAX;
  msg_ctx->stream_id = ULONG_MAX;
  msg_ctx->data      = fd_chunk_to_laddr( ctx->verify_out_wksp, chunk );
  msg_ctx->sz        = packet_sz;
  msg_ctx->tsorig    = (uint)fd_frag_meta_ts_comp( fd_tickcount() );

  fd_tpu_dummy_dcache( ctx );

  ctx->inflight_streams += 1;

  if( FD_UNLIKELY( pubq_full( ctx->pubq ) ) ) {
    FD_LOG_WARNING(( "pubq full, dropping" ));
    return;
  }

  FD_TEST( packet_sz <= FD_TPU_MTU ); /* paranoia */
  fd_memcpy( msg_ctx->data, packet, packet_sz );
  pubq_push( ctx->pubq, msg_ctx );

  ctx->verify_out_chunk = chunk;
}

/* Because of the separate mcache for publishing network fragments
   back to networking tiles, which is not managed by the mux, we
   need to periodically update the sync. */
static void
during_housekeeping( void * _ctx ) {
  fd_quic_ctx_t * ctx = (fd_quic_ctx_t *)_ctx;

  fd_mcache_seq_update( ctx->net_out_sync, ctx->net_out_seq );
}

/* This tile always publishes messages downstream, even if there are
   no credits available.  It ignores the flow control of the downstream
   verify tile.  This is OK as the verify tile is written to expect
   this behavior, and enables the QUIC tile to publish as fast as it
   can.  It would currently be difficult trying to backpressure further
   up the stack to the network itself. */
static void
before_credit( void * _ctx,
               fd_mux_context_t * mux ) {
  fd_quic_ctx_t * ctx = (fd_quic_ctx_t *)_ctx;

  ctx->mux = mux;

  /* Service QUIC clients */
  fd_quic_service( ctx->quic );

  /* Publish completed messages */
  ulong pub_cnt = pubq_cnt( ctx->pubq );
  for( ulong i=0; i<pub_cnt; i++ ) {

    fd_quic_msg_ctx_t * msg = ctx->pubq[ i ];

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

    ulong chunk  = fd_laddr_to_chunk( ctx->verify_out_wksp, msg->data );
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
cnc_diag_write( void * _ctx, ulong * cnc_diag ) {
  fd_quic_ctx_t * ctx = (fd_quic_ctx_t *)_ctx;

  cnc_diag[ FD_QUIC_CNC_DIAG_TPU_CONN_LIVE_CNT ]  = ctx->conn_cnt;
  cnc_diag[ FD_QUIC_CNC_DIAG_TPU_CONN_SEQ      ]  = ctx->conn_seq;
}

static void
before_frag( void * _ctx,
             ulong  in_idx,
             ulong  seq,
             ulong  sig,
             int *  opt_filter ) {
  (void)in_idx;
  (void)seq;

  fd_quic_ctx_t * ctx = (fd_quic_ctx_t *)_ctx;

  ushort dst_port    = fd_disco_netmux_sig_port( sig );
  ulong  src_ip_addr = fd_disco_netmux_sig_ip_addr( sig );
  ushort src_tile    = fd_disco_netmux_sig_src_tile( sig );

  if( FD_UNLIKELY( src_tile != SRC_TILE_NET ) ) {
    *opt_filter = 1;
    return;
  }

  int handled_port = dst_port == ctx->legacy_transaction_port ||
                     dst_port == ctx->quic->config.net.listen_udp_port;

  if( FD_UNLIKELY( !handled_port ) ) {
    FD_LOG_ERR(( "Firedancer received a UDP packet on port %hu which was not expected. "
                 "Only ports %hu and %hu should be configured to forward packets. Do "
                 "you need to reload the XDP program?",
                 dst_port, ctx->quic->config.net.listen_udp_port, ctx->legacy_transaction_port ));
  }

  int handled_ip_address = (src_ip_addr % ctx->round_robin_cnt) == ctx->round_robin_id;

  if( FD_UNLIKELY( !handled_port || !handled_ip_address ) ) {
    *opt_filter = 1;
  }
}

static void
during_frag( void * _ctx,
             ulong  in_idx,
             ulong  sig,
             ulong  chunk,
             ulong  sz,
             int *  opt_filter ) {
  (void)in_idx;
  (void)sig;
  (void)opt_filter;

  fd_quic_ctx_t * ctx = (fd_quic_ctx_t *)_ctx;

  if( FD_UNLIKELY( chunk<ctx->in_chunk0 || chunk>ctx->in_wmark || sz > FD_NET_MTU ) )
    FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->in_chunk0, ctx->in_wmark ));

  uchar * src = (uchar *)fd_chunk_to_laddr( ctx->in_wksp, chunk );
  fd_memcpy( ctx->buffer, src, sz ); /* TODO: Eliminate copy... fd_aio needs refactoring */
}

static void
after_frag( void *  _ctx,
            ulong * opt_sig,
            ulong * opt_chunk,
            ulong * opt_sz,
            int *   opt_filter ) {
  (void)opt_chunk;
  (void)opt_filter;

  fd_quic_ctx_t * ctx = (fd_quic_ctx_t *)_ctx;

  ushort dst_port    = fd_disco_netmux_sig_port( *opt_sig );

  if( FD_LIKELY( dst_port == ctx->quic->config.net.listen_udp_port ) ) {
    fd_aio_pkt_info_t pkt = { .buf = ctx->buffer, .buf_sz = (ushort)*opt_sz };
    fd_aio_send( ctx->quic_rx_aio, &pkt, 1, NULL, 1 );
  } else if( FD_LIKELY( dst_port == ctx->legacy_transaction_port ) ) {
    if( FD_UNLIKELY( *opt_sz < 15U ) ) FD_LOG_ERR(( "corrupt packet received (%lu)", *opt_sz ));

    uchar * iphdr = ctx->buffer + 14U;
    uint iplen = ( ( (uint)iphdr[0] ) & 0x0FU ) * 4U;
    uchar * data = iphdr + iplen + 8U;

    if( FD_UNLIKELY( 8U + 14U + iplen >= *opt_sz ) ) FD_LOG_ERR(( "corrupt packet received (%lu)", *opt_sz ));
    legacy_stream_notify( ctx, data, (uint)(*opt_sz - 8UL - 14UL - iplen) );
  }
}

/* quic_now is called by the QUIC engine to get the current timestamp in
   UNIX time.  */

static ulong
quic_now( void * ctx ) {
  (void)ctx;
  return (ulong)fd_log_wallclock();
}

/* Tile-local sequence number for conns */
static FD_TL ulong conn_seq = 0UL;

/* quic_conn_new is invoked by the QUIC engine whenever a new connection
   is being established. */
static void
quic_conn_new( fd_quic_conn_t * conn,
               void *           _ctx ) {

  conn->local_conn_id = ++conn_seq;

  fd_quic_ctx_t * ctx = (fd_quic_ctx_t *)_ctx;
  ctx->conn_seq = conn_seq;
  ctx->conn_cnt++;
}

/* quic_conn_final is called back by the QUIC engine whenever a
   connection is closed.  This could be because it ended gracefully, or
   was terminated, or any other reason. */
static void
quic_conn_final( fd_quic_conn_t * conn,
                 void *           _ctx ) {
  (void)conn;

  fd_quic_ctx_t * ctx = (fd_quic_ctx_t *)_ctx;
  ctx->conn_cnt--;
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

  fd_quic_ctx_t * ctx = (fd_quic_ctx_t *)_ctx;

  ulong conn_id   = stream->conn->local_conn_id;
  ulong stream_id = stream->stream_id;

  /* Allocate new dcache entry */

  ulong chunk = fd_dcache_compact_next( ctx->verify_out_chunk, FD_TPU_DCACHE_MTU, ctx->verify_out_chunk0, ctx->verify_out_wmark );

  fd_quic_msg_ctx_t * msg_ctx = fd_quic_dcache_msg_ctx( ctx->verify_out_dcache_app, ctx->verify_out_chunk0, chunk );
  msg_ctx->conn_id   = conn_id;
  msg_ctx->stream_id = stream_id;
  msg_ctx->data      = fd_chunk_to_laddr( ctx->verify_out_wksp, chunk );
  msg_ctx->sz        = 0U;
  msg_ctx->tsorig    = (uint)fd_frag_meta_ts_comp( fd_tickcount() );

  fd_tpu_dummy_dcache( ctx );

  ctx->inflight_streams += 1;

  /* Wind up for next callback */

  ctx->verify_out_chunk  = chunk; /* Update dcache chunk index */
  stream->context = msg_ctx;      /* Update stream dcache entry */
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

  fd_quic_msg_ctx_t * msg_ctx = (fd_quic_msg_ctx_t *)stream_ctx;
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

  fd_quic_msg_ctx_t * msg_ctx = (fd_quic_msg_ctx_t *)stream_ctx;
  fd_quic_conn_t *    conn    = stream->conn;
  fd_quic_t *         quic    = conn->quic;
  fd_quic_ctx_t *     ctx     = quic->cb.quic_ctx; /* TODO ugly */

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

static int
quic_tx_aio_send( void *                    _ctx,
                  fd_aio_pkt_info_t const * batch,
                  ulong                     batch_cnt,
                  ulong *                   opt_batch_idx,
                  int                       flush ) {
  (void)flush;

  fd_quic_ctx_t * ctx = (fd_quic_ctx_t *)_ctx;

  for( ulong i=0; i<batch_cnt; i++ ) {
    void * dst = fd_chunk_to_laddr( ctx->net_out_wksp, ctx->net_out_chunk );
    fd_memcpy( dst, batch[ i ].buf, batch[ i ].buf_sz );

    /* send packets are just round-robined by sequence number, so for now
       just indicate where they came from so they don't bounce back */
    ulong sig = fd_disco_netmux_sig( 0, 0, SRC_TILE_QUIC, 0 );

    ulong tspub  = (ulong)fd_frag_meta_ts_comp( fd_tickcount() );
    fd_mcache_publish( ctx->net_out_mcache,
                       ctx->net_out_depth,
                       ctx->net_out_seq,
                       sig,
                       ctx->net_out_chunk,
                       batch[ i ].buf_sz,
                       0,
                       0,
                       tspub );

    ctx->net_out_seq   = fd_seq_inc( ctx->net_out_seq, 1UL );
    ctx->net_out_chunk = fd_dcache_compact_next( ctx->net_out_chunk, FD_NET_MTU, ctx->net_out_chunk0, ctx->net_out_wmark );
  }

  if( FD_LIKELY( opt_batch_idx ) ) {
    *opt_batch_idx = batch_cnt;
  }

  return FD_AIO_SUCCESS;
}

int
fd_quic_tile( fd_cnc_t *              cnc,
              ulong                   pid,
              ulong                   in_cnt,
              const fd_frag_meta_t ** in_mcache,
              ulong **                in_fseq,
              ulong                   round_robin_cnt,
              ulong                   round_robin_id,
              fd_frag_meta_t *        net_mcache,
              uchar *                 net_dcache,
              fd_quic_t *             quic,
              ushort                  legacy_transaction_port,
              fd_frag_meta_t *        mcache,
              uchar *                 dcache,
              ulong                   cr_max,
              long                    lazy,
              fd_rng_t *              rng,
              void *                  scratch ) {
  fd_quic_ctx_t ctx[1];

  fd_mux_callbacks_t callbacks[1] = { 0 };
  callbacks->during_housekeeping = during_housekeeping;
  callbacks->before_credit       = before_credit;
  callbacks->before_frag         = before_frag;
  callbacks->during_frag         = during_frag;
  callbacks->after_frag          = after_frag;
  callbacks->cnc_diag_write      = cnc_diag_write;

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

    fd_aio_t * quic_tx_aio = fd_aio_join( fd_aio_new( SCRATCH_ALLOC( fd_aio_align(), fd_aio_footprint() ), ctx, quic_tx_aio_send ) );
    fd_quic_set_aio_net_tx( quic, quic_tx_aio );

    if( FD_UNLIKELY( !fd_quic_init( quic ) ) ) { FD_LOG_WARNING(( "fd_quic_init failed" )); return 1; }

    ulong depth = fd_mcache_depth( mcache );
    if( FD_UNLIKELY( !fd_dcache_compact_is_safe( fd_wksp_containing( dcache ), dcache, FD_TPU_DCACHE_MTU, depth  ) ) ) {
      FD_LOG_WARNING(( "dcache not compatible with wksp base and mcache depth" ));
      return 1;
    }

    if( FD_UNLIKELY( fd_dcache_app_sz( dcache ) < fd_quic_dcache_app_footprint( depth ) ) ) {
      FD_LOG_WARNING(( "dcache app sz too small (min=%lu have=%lu)",
                       fd_quic_dcache_app_footprint( depth ),
                       fd_dcache_app_sz( dcache ) ));
      return 1;
    }

    ctx->in_wksp  = fd_wksp_containing( net_mcache );

    /* Put a bound on chunks we read from the input, to make sure they
       are within in the data region of the workspace. */
    ctx->in_chunk0 = fd_disco_compact_chunk0( ctx->in_wksp );
    ctx->in_wmark  = fd_disco_compact_wmark ( ctx->in_wksp, FD_NET_MTU );

    ctx->net_out_mcache = net_mcache;
    ctx->net_out_sync  = fd_mcache_seq_laddr( net_mcache );
    ctx->net_out_depth = fd_mcache_depth( net_mcache );
    ctx->net_out_seq    = fd_mcache_seq_query( ctx->net_out_sync );
    ctx->net_out_chunk0 = fd_dcache_compact_chunk0( fd_wksp_containing( net_dcache ), net_dcache );
    ctx->net_out_wksp   = fd_wksp_containing( net_dcache );
    ctx->net_out_wmark  = fd_dcache_compact_wmark ( ctx->net_out_wksp, net_dcache, FD_NET_MTU );
    ctx->net_out_chunk  = ctx->net_out_chunk0;

    ctx->verify_out_wksp       = fd_wksp_containing( dcache );
    ctx->verify_out_dcache_app = fd_dcache_app_laddr( dcache );
    ctx->verify_out_chunk0     = fd_dcache_compact_chunk0( ctx->verify_out_wksp, dcache );
    ctx->verify_out_wmark      = fd_dcache_compact_wmark ( ctx->verify_out_wksp, dcache, FD_TPU_DCACHE_MTU );
    ctx->verify_out_chunk      = ctx->verify_out_chunk0;

    ctx->inflight_streams = 0UL;
    ctx->conn_cnt = 0UL;
    ctx->conn_seq = 0UL;

    ctx->quic = quic;
    ctx->quic_rx_aio = fd_quic_get_aio_net_rx( quic );

    if( FD_UNLIKELY( !round_robin_cnt ) ) { FD_LOG_WARNING(( "round_robin_cnt is zero" )); return 1; }
    if( FD_UNLIKELY( round_robin_id >= round_robin_cnt ) ) { FD_LOG_WARNING(( "round_robin_id is too large" )); return 1; }
    ctx->round_robin_cnt = round_robin_cnt;
    ctx->round_robin_id  = round_robin_id;

    ctx->legacy_transaction_port = legacy_transaction_port;

    ctx->pubq = pubq_join( pubq_new( SCRATCH_ALLOC( pubq_align(), pubq_footprint( depth ) ), depth ) );
  } while(0);

  return fd_mux_tile( cnc,
                      pid,
                      FD_MUX_FLAG_MANUAL_PUBLISH | FD_MUX_FLAG_COPY,
                      in_cnt,
                      in_mcache,
                      in_fseq,
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
