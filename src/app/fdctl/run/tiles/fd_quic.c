#include "tiles.h"

#include "generated/quic_seccomp.h"
#include "../../../../disco/metrics/generated/fd_metrics_quic.h"
#include "../../../../tango/quic/fd_quic.h"
#include "../../../../tango/xdp/fd_xsk_aio.h"
#include "../../../../tango/xdp/fd_xsk.h"
#include "../../../../tango/ip/fd_netlink.h"
#include "../../../../tango/ip/fd_ip.h"
#include "../../../../disco/quic/fd_tpu.h"

#include <linux/unistd.h>
#include <sys/random.h>

/* fd_quic provides a QUIC server tile.

   This tile handles all incoming QUIC traffic.  Supported protocols
   currently include TPU/QUIC (transactions).

   At present, TPU is the only protocol deployed on QUIC.  It allows
   clients to send transactions to block producers (this tile).    In QUIC, this
   can occur in as little as a single packet (and an ACK by the server).

   The fd_quic tile acts as a plain old Tango producer writing to a cnc
   and an mcache.  The tile will defragment multi-packet TPU streams
   coming in from QUIC, such that each mcache/dcache pair forms a
   complete txn.  This requires the dcache mtu to be at least that of
   the largest allowed serialized txn size.

   QUIC tiles don't service network devices directly, but rely on
   packets being received by net tiles and forwarded on via. a mux
   (multiplexer).  An arbitrary number of QUIC tiles can be run, and
   these will round-robin packets from the networking queues based on
   the source IP address. */

typedef struct {
  fd_tpu_reasm_t * reasm;

  fd_mux_context_t * mux;

  fd_ip_t *        ip;
  fd_quic_t *      quic;
  const fd_aio_t * quic_rx_aio;

  ushort legacy_transaction_port; /* port for receiving non-QUIC (raw UDP) transactions on*/

  uchar buffer[ FD_NET_MTU ];

  ulong conn_seq; /* current quic connection sequence number */

  ulong round_robin_cnt;
  ulong round_robin_id;

  fd_wksp_t * in_mem;
  ulong       in_chunk0;
  ulong       in_wmark;

  fd_frag_meta_t * net_out_mcache;
  ulong *          net_out_sync;
  ulong            net_out_depth;
  ulong            net_out_seq;

  fd_wksp_t * net_out_mem;
  ulong       net_out_chunk0;
  ulong       net_out_wmark;
  ulong       net_out_chunk;

  fd_wksp_t * verify_out_mem;

  struct {
    ulong legacy_reasm_append [ FD_METRICS_COUNTER_QUIC_TILE_NON_QUIC_REASSEMBLY_APPEND_CNT ];
    ulong legacy_reasm_publish[ FD_METRICS_COUNTER_QUIC_TILE_NON_QUIC_REASSEMBLY_PUBLISH_CNT ];

    ulong reasm_append [ FD_METRICS_COUNTER_QUIC_TILE_REASSEMBLY_APPEND_CNT ];
    ulong reasm_publish[ FD_METRICS_COUNTER_QUIC_TILE_REASSEMBLY_PUBLISH_CNT ];
  } metrics;
} fd_quic_ctx_t;

FD_FN_CONST static inline fd_quic_limits_t
quic_limits( fd_topo_tile_t * tile ) {
  fd_quic_limits_t limits = {
    .conn_cnt                                      = tile->quic.max_concurrent_connections,
    .handshake_cnt                                 = tile->quic.max_concurrent_handshakes,

    /* While in TCP a connection is identified by (Source IP, Source
       Port, Dest IP, Dest Port) in QUIC a connection is uniquely
       identified by a connection ID. Because this isn't dependent on
       network identifiers, it allows connection migration and
       continuity across network changes. It can also offer enhanced
       privacy by obfuscating the client IP address and prevent
       connection-linking by observers.

       Additional connection IDs are simply aliases back to the same
       connection, and can be created and retired during a connection by
       either endpoint. This configuration determines how many different
       connection IDs the connection may have simultaneously.

       Currently this option must be hard coded to
       FD_QUIC_MAX_CONN_ID_PER_CONN because it cannot exceed a buffer
       size determined by that constant. */
    .conn_id_cnt                                   = FD_QUIC_MAX_CONN_ID_PER_CONN,
    .conn_id_sparsity                              = 0.0,
    .inflight_pkt_cnt                              = tile->quic.max_inflight_quic_packets,
    .tx_buf_sz                                     = tile->quic.tx_buf_size,
    .stream_cnt[ FD_QUIC_STREAM_TYPE_BIDI_CLIENT ] = 0,
    .stream_cnt[ FD_QUIC_STREAM_TYPE_BIDI_SERVER ] = 0,
    .stream_cnt[ FD_QUIC_STREAM_TYPE_UNI_CLIENT  ] = tile->quic.max_concurrent_streams_per_connection,
    .stream_cnt[ FD_QUIC_STREAM_TYPE_UNI_SERVER  ] = 0,
    .stream_sparsity                               = 0.0,
  };
  return limits;
}

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 4096UL;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t * tile ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof( fd_quic_ctx_t ), sizeof( fd_quic_ctx_t ) );
  l = FD_LAYOUT_APPEND( l, fd_ip_align(), fd_ip_footprint( 256UL, 256UL ) );
  l = FD_LAYOUT_APPEND( l, fd_aio_align(), fd_aio_footprint() );
  fd_quic_limits_t limits = quic_limits( tile );
  l = FD_LAYOUT_APPEND( l, fd_quic_align(), fd_quic_footprint( &limits ) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

FD_FN_CONST static inline void *
mux_ctx( void * scratch ) {
  return (void*)fd_ulong_align_up( (ulong)scratch, alignof( fd_quic_ctx_t ) );
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

  fd_mux_context_t * mux = ctx->mux;

  uint                  tsorig = (uint)fd_frag_meta_ts_comp( fd_tickcount() );
  fd_tpu_reasm_slot_t * slot   = fd_tpu_reasm_prepare( ctx->reasm, tsorig );

  int add_err = fd_tpu_reasm_append( ctx->reasm, slot, packet, packet_sz, 0UL );
  ctx->metrics.legacy_reasm_append[ add_err ]++;
  if( FD_UNLIKELY( add_err!=FD_TPU_REASM_SUCCESS ) ) return;

  uint   tspub = (uint)fd_frag_meta_ts_comp( fd_tickcount() );
  void * base  = ctx->verify_out_mem;
  ulong  seq   = *mux->seq;

  int pub_err = fd_tpu_reasm_publish( ctx->reasm, slot, mux->mcache, base, seq, tspub );
  ctx->metrics.legacy_reasm_publish[ pub_err ]++;
  if( FD_UNLIKELY( pub_err!=FD_TPU_REASM_SUCCESS ) ) return;

  fd_mux_advance( mux );
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

  /* Publishes to mcache via callbacks */
  fd_quic_service( ctx->quic );
}

static inline void
metrics_write( void * _ctx ) {
  fd_quic_ctx_t * ctx = (fd_quic_ctx_t *)_ctx;

  FD_MCNT_ENUM_COPY( QUIC_TILE, NON_QUIC_REASSEMBLY_APPEND,  ctx->metrics.legacy_reasm_append );
  FD_MCNT_ENUM_COPY( QUIC_TILE, NON_QUIC_REASSEMBLY_PUBLISH, ctx->metrics.legacy_reasm_publish );
  FD_MCNT_ENUM_COPY( QUIC_TILE, REASSEMBLY_APPEND,           ctx->metrics.reasm_append );
  FD_MCNT_ENUM_COPY( QUIC_TILE, REASSEMBLY_PUBLISH,          ctx->metrics.reasm_publish );

  FD_MCNT_SET(   QUIC, RECEIVED_PACKETS, ctx->quic->metrics.net_rx_pkt_cnt );
  FD_MCNT_SET(   QUIC, RECEIVED_BYTES,   ctx->quic->metrics.net_rx_byte_cnt );
  FD_MCNT_SET(   QUIC, SENT_PACKETS,     ctx->quic->metrics.net_tx_pkt_cnt );
  FD_MCNT_SET(   QUIC, SENT_BYTES,       ctx->quic->metrics.net_tx_byte_cnt );

  FD_MGAUGE_SET( QUIC, CONNECTIONS_ACTIVE,  ctx->quic->metrics.conn_active_cnt );
  FD_MCNT_SET(   QUIC, CONNECTIONS_CREATED, ctx->quic->metrics.conn_created_cnt );
  FD_MCNT_SET(   QUIC, CONNECTIONS_CLOSED,  ctx->quic->metrics.conn_closed_cnt );
  FD_MCNT_SET(   QUIC, CONNECTIONS_ABORTED, ctx->quic->metrics.conn_aborted_cnt );
  FD_MCNT_SET(   QUIC, CONNECTIONS_RETRIED, ctx->quic->metrics.conn_retry_cnt );

  FD_MCNT_SET(   QUIC, CONNECTION_ERROR_NO_SLOTS,   ctx->quic->metrics.conn_err_no_slots_cnt );
  FD_MCNT_SET(   QUIC, CONNECTION_ERROR_TLS_FAIL,   ctx->quic->metrics.conn_err_tls_fail_cnt );
  FD_MCNT_SET(   QUIC, CONNECTION_ERROR_RETRY_FAIL, ctx->quic->metrics.conn_err_retry_fail_cnt );

  FD_MCNT_SET(   QUIC, HANDSHAKES_CREATED,         ctx->quic->metrics.hs_created_cnt );
  FD_MCNT_SET(   QUIC, HANDSHAKE_ERROR_ALLOC_FAIL, ctx->quic->metrics.hs_err_alloc_fail_cnt );

  FD_MCNT_ENUM_COPY(   QUIC, STREAM_OPENED, ctx->quic->metrics.stream_opened_cnt );
  FD_MCNT_ENUM_COPY(   QUIC, STREAM_CLOSED, ctx->quic->metrics.stream_closed_cnt );
  FD_MGAUGE_ENUM_COPY( QUIC, STREAM_ACTIVE, ctx->quic->metrics.stream_active_cnt );

  FD_MCNT_SET(  QUIC, STREAM_RECEIVED_EVENTS, ctx->quic->metrics.stream_rx_event_cnt );
  FD_MCNT_SET(  QUIC, STREAM_RECEIVED_BYTES,  ctx->quic->metrics.stream_rx_byte_cnt );
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

  if( FD_UNLIKELY( src_tile!=SRC_TILE_NET ) ) {
    *opt_filter = 1;
    return;
  }

  int handled_port = dst_port == ctx->legacy_transaction_port ||
                     dst_port == ctx->quic->config.net.listen_udp_port;

  /* Ignore traffic e.g. for shred tile */
  if( FD_UNLIKELY( !handled_port ) ) {
    *opt_filter = 1;
    return;
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

  uchar * src = (uchar *)fd_chunk_to_laddr( ctx->in_mem, chunk );
  fd_memcpy( ctx->buffer, src, sz ); /* TODO: Eliminate copy... fd_aio needs refactoring */
}

static void
after_frag( void *             _ctx,
            ulong              in_idx,
            ulong *            opt_sig,
            ulong *            opt_chunk,
            ulong *            opt_sz,
            int *              opt_filter,
            fd_mux_context_t * mux ) {
  (void)in_idx;
  (void)opt_chunk;
  (void)opt_filter;
  (void)mux;

  fd_quic_ctx_t * ctx = (fd_quic_ctx_t *)_ctx;

  ushort dst_port = fd_disco_netmux_sig_port( *opt_sig );

  if( FD_LIKELY( dst_port==ctx->quic->config.net.listen_udp_port ) ) {
    fd_aio_pkt_info_t pkt = { .buf = ctx->buffer, .buf_sz = (ushort)*opt_sz };
    fd_aio_send( ctx->quic_rx_aio, &pkt, 1, NULL, 1 );
  } else if( FD_LIKELY( dst_port==ctx->legacy_transaction_port ) ) {
    ulong network_hdr_sz = fd_disco_netmux_sig_hdr_sz( *opt_sig );
    if( FD_UNLIKELY( *opt_sz<network_hdr_sz ) ) {
      /* Transaction not valid if the packet isn't large enough for the network
         headers. */
      FD_MCNT_INC( QUIC_TILE, NON_QUIC_PACKET_TOO_SMALL, 1UL );
      return;
    }

    if( FD_UNLIKELY( *opt_sz>FD_TPU_MTU ) ) {
      /* Transaction couldn't possibly be valid if it's longer than transaction
         MTU so drop it. This is not required, as the txn will fail to parse,
         but it's a nice short circuit. */
      FD_MCNT_INC( QUIC_TILE, NON_QUIC_PACKET_TOO_LARGE, 1UL );
      return;
    }

    legacy_stream_notify( ctx, ctx->buffer+network_hdr_sz, (uint)(*opt_sz - network_hdr_sz) );
  }
}

/* quic_now is called by the QUIC engine to get the current timestamp in
   UNIX time.  */

static ulong
quic_now( void * ctx ) {
  (void)ctx;
  return (ulong)fd_log_wallclock();
}

/* quic_conn_new is invoked by the QUIC engine whenever a new connection
   is being established. */
static void
quic_conn_new( fd_quic_conn_t * conn,
               void *           _ctx ) {
  fd_quic_ctx_t * ctx = (fd_quic_ctx_t *)_ctx;

  conn->local_conn_id = ++ctx->conn_seq;
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

  /* Acquire reassembly slot */

  uint                  tsorig = (uint)fd_frag_meta_ts_comp( fd_tickcount() );
  fd_tpu_reasm_slot_t * slot   = fd_tpu_reasm_prepare( ctx->reasm, tsorig );

  slot->conn_id   = conn_id;
  slot->stream_id = stream_id;

  /* Wire up with QUIC stream */

  stream->context = slot;

  /* Wind up for next iteration */

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

  /* Load TPU state */

  fd_quic_t *           quic     = stream->conn->quic;
  fd_quic_ctx_t *       quic_ctx = quic->cb.quic_ctx;
  fd_tpu_reasm_t *      reasm    = quic_ctx->reasm;
  fd_tpu_reasm_slot_t * slot     = stream_ctx;
  fd_quic_ctx_t *       ctx    = quic->cb.quic_ctx;

  /* Check if reassembly slot is still valid */

  ulong conn_id   = stream->conn->local_conn_id;
  ulong stream_id = stream->stream_id;

  if( FD_UNLIKELY( ( slot->conn_id   != conn_id   ) |
                   ( slot->stream_id != stream_id ) ) ) {
    return;  /* clobbered */
  }

  /* Append data into chunk, we know this is valid */

  int add_err = fd_tpu_reasm_append( reasm, slot, data, data_sz, offset );
  ctx->metrics.reasm_append[ add_err ]++;
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

  /* Load TPU state */

  fd_quic_t *           quic   = stream->conn->quic;
  fd_quic_ctx_t *       ctx    = quic->cb.quic_ctx;
  fd_tpu_reasm_t *      reasm  = ctx->reasm;
  fd_tpu_reasm_slot_t * slot   = stream_ctx;
  fd_mux_context_t *    mux    = ctx->mux;
  fd_frag_meta_t *      mcache = mux->mcache;
  void *                base   = ctx->verify_out_mem;

  if( FD_UNLIKELY( type!=FD_QUIC_NOTIFY_END ) ) {
    fd_tpu_reasm_cancel( reasm, slot );
    return;  /* not a successful stream close */
  }

  /* Check if reassembly slot is still valid */

  ulong conn_id   = stream->conn->local_conn_id;
  ulong stream_id = stream->stream_id;

  if( FD_UNLIKELY( ( slot->conn_id   != conn_id   ) |
                   ( slot->stream_id != stream_id ) ) ) {
    FD_MCNT_INC( QUIC_TILE, REASSEMBLY_NOTIFY_CLOBBERED, 1UL );
    return;  /* clobbered */
  }

  /* Publish message */

  ulong  seq   = *mux->seq;
  uint   tspub = (uint)fd_frag_meta_ts_comp( fd_tickcount() );
  int pub_err = fd_tpu_reasm_publish( reasm, slot, mcache, base, seq, tspub );
  ctx->metrics.reasm_publish[ pub_err ]++;

  fd_mux_advance( mux );
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
    void * dst = fd_chunk_to_laddr( ctx->net_out_mem, ctx->net_out_chunk );
    fd_memcpy( dst, batch[ i ].buf, batch[ i ].buf_sz );

    uchar const * packet = dst;
    uchar const * packet_end = packet + batch[i].buf_sz;
    uchar const * iphdr = packet + 14U;

    uint test_ethip = ( (uint)packet[12] << 16u ) | ( (uint)packet[13] << 8u ) | (uint)packet[23];
    uint   ip_dstaddr  = 0;
    ushort udp_dstport = 0;
    if( FD_LIKELY( test_ethip==0x080011 ) ) {
      /* IPv4 is variable-length, so lookup IHL to find start of UDP */
      uint iplen = ( ( (uint)iphdr[0] ) & 0x0FU ) * 4U;
      uchar const * udp = iphdr + iplen;

      /* Ignore if UDP header is too short */
      if( FD_UNLIKELY( udp+8U>packet_end ) ) {
        FD_MCNT_INC( QUIC_TILE, QUIC_PACKET_TOO_SMALL, 1UL );
        continue;
      }

      /* Extract IP dest addr and UDP dest port */
      ip_dstaddr  =                  *(uint   *)( iphdr+16UL );
      udp_dstport = fd_ushort_bswap( *(ushort *)( udp+2UL    ) );
    }

    /* send packets are just round-robined by sequence number, so for now
       just indicate where they came from so they don't bounce back */
    ulong sig = fd_disco_netmux_sig( ip_dstaddr, udp_dstport, FD_NETMUX_SIG_MIN_HDR_SZ, SRC_TILE_QUIC, 0 );

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

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile,
                 void *           scratch ) {
  (void)topo;
  (void)tile;

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_quic_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_quic_ctx_t ), sizeof( fd_quic_ctx_t ) );
  ctx->ip = fd_ip_join( fd_ip_new( FD_SCRATCH_ALLOC_APPEND( l, fd_ip_align(), fd_ip_footprint( 256UL, 256UL ) ), 256UL, 256UL ) );
  if( FD_UNLIKELY( !ctx->ip ) ) FD_LOG_ERR(( "fd_ip_join failed" ));

  fd_quic_limits_t limits = quic_limits( tile );
  void * quic_mem  = FD_SCRATCH_ALLOC_APPEND( l, fd_quic_align(), fd_quic_footprint( &limits ) );
  fd_quic_t * quic = fd_quic_join( fd_quic_new( quic_mem, &limits, ctx->ip ) );
  if( FD_UNLIKELY( 32UL!=getrandom( quic->config.identity_key, 32UL, 0 ) ) )
    FD_LOG_ERR(( "failed to generate identity key: getrandom(32,0) failed" ));

  /* call wallclock so glibc loads VDSO, which requires calling mmap while
     privileged */
  fd_log_wallclock();
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile,
                   void *           scratch ) {
  if( FD_UNLIKELY( !tile->in_cnt ) ) FD_LOG_ERR(( "quic tile in cnt is zero" ));

  ulong depth = tile->quic.depth;
  if( topo->links[ tile->out_link_id_primary ].depth != depth )
    FD_LOG_ERR(( "quic tile in depths are not equal" ));

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_quic_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_quic_ctx_t ), sizeof( fd_quic_ctx_t ) );
  FD_SCRATCH_ALLOC_APPEND( l, fd_ip_align(), fd_ip_footprint( 256UL, 256UL ) );

  fd_quic_limits_t limits = quic_limits( tile );
  void * quic_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_quic_align(), fd_quic_footprint( &limits ) );

  /* End privileged allocs */

  fd_aio_t * quic_tx_aio = fd_aio_join( fd_aio_new( FD_SCRATCH_ALLOC_APPEND( l, fd_aio_align(), fd_aio_footprint() ), ctx, quic_tx_aio_send ) );
  if( FD_UNLIKELY( !quic_tx_aio ) ) FD_LOG_ERR(( "fd_aio_join failed" ));

  fd_ip_arp_fetch( ctx->ip );
  fd_ip_route_fetch( ctx->ip );
  fd_quic_t * quic = fd_quic_join( quic_mem );
  if( FD_UNLIKELY( !quic ) ) FD_LOG_ERR(( "fd_quic_join failed" ));

  quic->config.role                       = FD_QUIC_ROLE_SERVER;
  quic->config.net.ip_addr                = tile->quic.ip_addr;
  quic->config.net.listen_udp_port        = tile->quic.quic_transaction_listen_port;
  quic->config.idle_timeout               = tile->quic.idle_timeout_millis * 1000000UL;
  quic->config.initial_rx_max_stream_data = 1<<15;
  fd_memcpy( quic->config.link.src_mac_addr, tile->quic.src_mac_addr, 6 );

  quic->cb.conn_new         = quic_conn_new;
  quic->cb.conn_hs_complete = NULL;
  quic->cb.conn_final       = NULL;
  quic->cb.stream_new       = quic_stream_new;
  quic->cb.stream_receive   = quic_stream_receive;
  quic->cb.stream_notify    = quic_stream_notify;
  quic->cb.now              = quic_now;
  quic->cb.now_ctx          = NULL;
  quic->cb.quic_ctx         = ctx;

  fd_quic_set_aio_net_tx( quic, quic_tx_aio );
  if( FD_UNLIKELY( !fd_quic_init( quic ) ) ) FD_LOG_ERR(( "fd_quic_init failed" ));

  /* Put a bound on chunks we read from the input, to make sure they
      are within in the data region of the workspace. */
  if( FD_UNLIKELY( !tile->in_cnt ) ) FD_LOG_ERR(( "quic tile in link cnt is zero" ));
  fd_topo_link_t * link0 = &topo->links[ tile->in_link_id[ 0 ] ];

  for( ulong i=1; i<tile->in_cnt; i++ ) {
    fd_topo_link_t * link = &topo->links[ tile->in_link_id[ i ] ];

    if( FD_UNLIKELY( link0->wksp_id != link->wksp_id ) ) FD_LOG_ERR(( "quic tile reads input from multiple workspaces" ));
    if( FD_UNLIKELY( link0->mtu != link->mtu         ) ) FD_LOG_ERR(( "quic tile reads input from multiple links with different MTUs" ));
  }

  ctx->in_mem    = topo->workspaces[ link0->wksp_id ].wksp;
  ctx->in_chunk0 = fd_disco_compact_chunk0( ctx->in_mem );
  ctx->in_wmark  = fd_disco_compact_wmark ( ctx->in_mem, link0->mtu );

  if( FD_UNLIKELY( tile->out_cnt != 1 || topo->links[ tile->out_link_id[ 0 ] ].kind != FD_TOPO_LINK_KIND_QUIC_TO_NETMUX ) )
    FD_LOG_ERR(( "quic tile has none or unexpected netmux output link %lu %lu", tile->out_cnt, topo->links[ tile->out_link_id[ 0 ] ].kind ));

  fd_topo_link_t * net_out = &topo->links[ tile->out_link_id[ 0 ] ];

  ctx->net_out_mcache = net_out->mcache;
  ctx->net_out_sync   = fd_mcache_seq_laddr( ctx->net_out_mcache );
  ctx->net_out_depth  = fd_mcache_depth( ctx->net_out_mcache );
  ctx->net_out_seq    = fd_mcache_seq_query( ctx->net_out_sync );
  ctx->net_out_chunk0 = fd_dcache_compact_chunk0( fd_wksp_containing( net_out->dcache ), net_out->dcache );
  ctx->net_out_mem    = topo->workspaces[ net_out->wksp_id ].wksp;
  ctx->net_out_wmark  = fd_dcache_compact_wmark ( ctx->net_out_mem, net_out->dcache, net_out->mtu );
  ctx->net_out_chunk  = ctx->net_out_chunk0;

  if( FD_UNLIKELY( tile->out_link_id_primary == ULONG_MAX ) )
    FD_LOG_ERR(( "quic tile has no primary output link" ));

  fd_topo_link_t * verify_out = &topo->links[ tile->out_link_id_primary ];

  ctx->verify_out_mem    = topo->workspaces[ verify_out->wksp_id ].wksp;

  ctx->reasm = verify_out->dcache;
  if( FD_UNLIKELY( !ctx->reasm ) )
    FD_LOG_ERR(( "invalid tpu_reasm parameters" ));

  ctx->conn_seq    = 0UL;

  ctx->quic        = quic;
  ctx->quic_rx_aio = fd_quic_get_aio_net_rx( quic );

  ctx->round_robin_cnt = fd_topo_tile_kind_cnt( topo, tile->kind );
  ctx->round_robin_id  = tile->kind_id;

  ctx->legacy_transaction_port = tile->quic.legacy_transaction_listen_port;

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));
}

static ulong
populate_allowed_seccomp( void *               scratch,
                          ulong                out_cnt,
                          struct sock_filter * out ) {
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_quic_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_quic_ctx_t ), sizeof( fd_quic_ctx_t ) );

  int netlink_fd = fd_ip_netlink_get( ctx->ip )->fd;
  FD_TEST( netlink_fd >= 0 );
  populate_sock_filter_policy_quic( out_cnt, out, (uint)fd_log_private_logfile_fd(), (uint)netlink_fd );
  return sock_filter_policy_quic_instr_cnt;
}

static ulong
populate_allowed_fds( void * scratch,
                      ulong  out_fds_cnt,
                      int *  out_fds ) {
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_quic_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_quic_ctx_t ), sizeof( fd_quic_ctx_t ) );

  if( FD_UNLIKELY( out_fds_cnt < 3 ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  out_fds[ out_cnt++ ] = fd_ip_netlink_get( ctx->ip )->fd; /* netlink socket */
  return out_cnt;
}

fd_tile_config_t fd_tile_quic = {
  .mux_flags                = FD_MUX_FLAG_MANUAL_PUBLISH | FD_MUX_FLAG_COPY,
  .burst                    = 1UL,
  .mux_ctx                  = mux_ctx,
  .mux_during_housekeeping  = during_housekeeping,
  .mux_before_credit        = before_credit,
  .mux_before_frag          = before_frag,
  .mux_during_frag          = during_frag,
  .mux_after_frag           = after_frag,
  .mux_metrics_write        = metrics_write,
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
};
