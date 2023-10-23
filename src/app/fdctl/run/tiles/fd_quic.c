#include "tiles.h"

#include "../../../../tango/quic/fd_quic.h"
#include "../../../../tango/xdp/fd_xsk_aio.h"
#include "../../../../tango/xdp/fd_xsk.h"
#include "../../../../tango/ip/fd_netlink.h"

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <linux/unistd.h>

/* fd_quic provides a QUIC server tile.

   At present, TPU is the only protocol deployed on QUIC.  It allows
   clients to send transactions to block producers (this tile).  For
   each txn to be transferred, the client opens a unidirectional QUIC
   stream and sends its serialization (see fd_txn_parse).  In QUIC, this
   can occur in as little as a single packet (and an ACK by the server).
   For txn exceeding MTU size, the txn is fragmented over multiple
   packets.  For more information, see the specification:
   https://github.com/solana-foundation/specs/blob/main/p2p/tpu.md

   The fd_quic tile acts as a plain old Tango producer writing to a cnc,
   an mcache, and a dcache.  The tile will defragment multi-packet TPU
   streams coming in from QUIC, such that each mcache/dcache pair forms
   a complete txn.  This requires the dcache mtu to be at least that of
   the largest allowed serialized txn size.

   To facilitate defragmentation, the fd_quic tile stores non-standard
   stream information in the dcache's application region.  (An array of
   fd_quic_tpu_msg_ctx_t)

   QUIC tiles don't service network devices directly, but rely on
   packets being received by net tiles and forwarded on via. a mux
   (multiplexer).  An arbirary number of QUIC tiles can be run, and
   these will round-robin packets from the networking queues based on
   the source IP address.

   An fd_quic_tile will use the cnc application region to accumulate the
   following tile specific counters:

     TPU_CONN_LIVE_CNT  is the number of currently open QUIC conns

     TPU_CONN_SEQ       is the sequence number of the last QUIC conn
                        opened

   As such, the cnc app region must be at least 64B in size.

   Except for IN_BACKP, none of the diagnostics are cleared at tile
   startup (as such that they can be accumulated over multiple runs).
   Clearing is up to monitoring scripts. */

#define FD_QUIC_CNC_DIAG_TPU_CONN_LIVE_CNT (6UL)
#define FD_QUIC_CNC_DIAG_TPU_CONN_SEQ      (7UL)

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
#include "../../../../util/tmpl/fd_queue_dynamic.c"

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
  uchar *     verify_out_dcache_app;
  ulong       verify_out_chunk0;
  ulong       verify_out_wmark;
  ulong       verify_out_chunk;
} fd_quic_ctx_t;

/* fd_quic_dcache_app_footprint returns the required footprint in bytes
   for the QUIC tile's out dcache app region of the given depth. */

FD_FN_CONST ulong
fd_quic_dcache_app_footprint( ulong depth ) {
  return depth * sizeof(fd_quic_msg_ctx_t);
}

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

       Additional connection IDs are simply alises back to the same
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
loose_footprint( fd_topo_tile_t * tile ) {
  (void)tile;

  /* Ensure there is 64 MiB leftover for OpenSSL allocations out of the
     workspace */
  return 1UL << 24UL;
}

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 4096UL;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t * tile ) {
  ulong scratch_top = 0UL;
  SCRATCH_ALLOC( alignof( fd_quic_ctx_t ), sizeof( fd_quic_ctx_t ) );
  SCRATCH_ALLOC( fd_alloc_align(), fd_alloc_footprint() );
  SCRATCH_ALLOC( pubq_align(),   pubq_footprint( tile->quic.depth ) );
  SCRATCH_ALLOC( fd_aio_align(), fd_aio_footprint() );
  fd_quic_limits_t limits = quic_limits( tile );
  SCRATCH_ALLOC( fd_quic_align(), fd_quic_footprint( &limits ) );
  return fd_ulong_align_up( scratch_top, scratch_align() );
}

/* OpenSSL allows us to specify custom memory allocation functions, which we
   want to point to an fd_alloc_t, but it does not let us use a context
   object.  Instead we stash it in this thread local, which is OK because the
   parent workspace exists for the duration of the SSL context, and the
   process only has one thread.

   Currently fd_alloc doesn't support realloc, so it's implemented on top of
   malloc and free, and then also it doesn't support getting the size of an
   allocation from the pointer, which we need for realloc, so we pad each
   alloc by 8 bytes and stuff the size into the first 8 bytes. */
static FD_TL fd_alloc_t * fd_quic_ssl_mem_function_ctx = NULL;

static void *
crypto_malloc( ulong        num,
               char const * file,
               int          line ) {
  (void)file;
  (void)line;
  void * result = fd_alloc_malloc( fd_quic_ssl_mem_function_ctx, 8UL, num + 8UL );
  if( FD_UNLIKELY( !result ) ) return NULL;
  *(ulong*)result = num;
  return (uchar*)result + 8UL;
}

static void
crypto_free( void *       addr,
             char const * file,
             int          line ) {
  (void)file;
  (void)line;

  if( FD_UNLIKELY( !addr ) ) return;
  fd_alloc_free( fd_quic_ssl_mem_function_ctx, (uchar*)addr - 8UL );
}

static void *
crypto_realloc( void *       addr,
                ulong        num,
                char const * file,
                int          line ) {
  (void)file;
  (void)line;

  if( FD_UNLIKELY( !addr ) ) return crypto_malloc( num, file, line );
  if( FD_UNLIKELY( !num ) ) {
    crypto_free( addr, file, line );
    return NULL;
  }

  void * new = fd_alloc_malloc( fd_quic_ssl_mem_function_ctx, 8UL, num + 8UL );
  if( FD_UNLIKELY( !new ) ) return NULL;

  ulong old_num = *(ulong*)( (uchar*)addr - 8UL );
  fd_memcpy( (uchar*)new + 8, (uchar*)addr, fd_ulong_min( old_num, num ) );
  fd_alloc_free( fd_quic_ssl_mem_function_ctx, (uchar*)addr - 8UL );
  *(ulong*)new = num;
  return (uchar*)new + 8UL;
}

FD_FN_CONST static inline void *
mux_ctx( void * scratch ) {
  return (void*)fd_ulong_align_up( (ulong)scratch, alignof( fd_quic_ctx_t ) );
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
  msg_ctx->data      = fd_chunk_to_laddr( ctx->verify_out_mem, chunk );
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

    ulong chunk  = fd_laddr_to_chunk( ctx->verify_out_mem, msg->data );
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

  ushort dst_port    = fd_disco_netmux_sig_port( *opt_sig );

  if( FD_LIKELY( dst_port == ctx->quic->config.net.listen_udp_port ) ) {
    fd_aio_pkt_info_t pkt = { .buf = ctx->buffer, .buf_sz = (ushort)*opt_sz };
    fd_aio_send( ctx->quic_rx_aio, &pkt, 1, NULL, 1 );
  } else if( FD_LIKELY( dst_port == ctx->legacy_transaction_port ) ) {
    ulong network_hdr_sz = fd_disco_netmux_sig_hdr_sz( *opt_sig );
    if( FD_UNLIKELY( *opt_sz < network_hdr_sz ) )
      FD_LOG_ERR(( "corrupt packet received (%lu bytes. header %lu)", *opt_sz, network_hdr_sz ));

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
  msg_ctx->data      = fd_chunk_to_laddr( ctx->verify_out_mem, chunk );
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
    void * dst = fd_chunk_to_laddr( ctx->net_out_mem, ctx->net_out_chunk );
    fd_memcpy( dst, batch[ i ].buf, batch[ i ].buf_sz );

    /* send packets are just round-robined by sequence number, so for now
       just indicate where they came from so they don't bounce back */
    ulong sig = fd_disco_netmux_sig( 0, 0, FD_NETMUX_SIG_MIN_HDR_SZ, SRC_TILE_QUIC, 0 );

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

  /* initialize fd_netlink */
  (void)fd_nl_get();

  /* call wallclock so glibc loads VDSO, which requires calling mmap while
     privileged */
  fd_log_wallclock();

  /* OpenSSL goes and tries to read files and allocate memory and
     other dumb things on a thread local basis, so we need a special
     initializer to do it before seccomp happens in the process. */
  ulong scratch_top = (ulong)scratch;
  SCRATCH_ALLOC( alignof( fd_quic_ctx_t ), sizeof( fd_quic_ctx_t ) );
  fd_quic_ssl_mem_function_ctx = fd_alloc_join( fd_alloc_new( SCRATCH_ALLOC( fd_alloc_align(), fd_alloc_footprint() ), 1UL ), tile->kind_id );
  if( FD_UNLIKELY( !fd_quic_ssl_mem_function_ctx ) )
    FD_LOG_ERR(( "fd_alloc_join failed" ));
  if( FD_UNLIKELY( !CRYPTO_set_mem_functions( crypto_malloc, crypto_realloc, crypto_free ) ) )
    FD_LOG_ERR(( "CRYPTO_set_mem_functions failed" ));

  if( FD_UNLIKELY( !OPENSSL_init_ssl( OPENSSL_INIT_LOAD_SSL_STRINGS , NULL ) ) )
    FD_LOG_ERR(( "OPENSSL_init_ssl failed" ));
  if( FD_UNLIKELY( !OPENSSL_init_crypto( OPENSSL_INIT_LOAD_CRYPTO_STRINGS | OPENSSL_INIT_NO_LOAD_CONFIG , NULL ) ) )
    FD_LOG_ERR(( "OPENSSL_init_crypto failed" ));
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile,
                   void *           scratch ) {
  if( FD_UNLIKELY( !tile->in_cnt ) ) FD_LOG_ERR(( "quic tile in cnt is zero" ));

  ulong depth = tile->quic.depth;
  if( topo->links[ tile->out_link_id_primary ].depth != depth )
    FD_LOG_ERR(( "quic tile in depths are not equal" ));

  void * dcache = topo->links[ tile->out_link_id_primary ].dcache;
  if( FD_UNLIKELY( fd_dcache_app_sz( dcache ) < fd_quic_dcache_app_footprint( depth ) ) )

  FD_LOG_ERR(( "dcache app sz too small (min=%lu have=%lu)",
                fd_quic_dcache_app_footprint( depth ),
                fd_dcache_app_sz( dcache ) ));

  ulong scratch_top = (ulong)scratch;
  fd_quic_ctx_t * ctx = (fd_quic_ctx_t*)SCRATCH_ALLOC( alignof( fd_quic_ctx_t ), sizeof( fd_quic_ctx_t ) );
  SCRATCH_ALLOC( fd_alloc_align(), fd_alloc_footprint() );
  ctx->pubq = pubq_join( pubq_new( SCRATCH_ALLOC( pubq_align(), pubq_footprint( depth ) ), depth ) );
  if( FD_UNLIKELY( !ctx->pubq ) ) FD_LOG_ERR(( "pubq_join failed" ));
  fd_aio_t * quic_tx_aio = fd_aio_join( fd_aio_new( SCRATCH_ALLOC( fd_aio_align(), fd_aio_footprint() ), ctx, quic_tx_aio_send ) );
  if( FD_UNLIKELY( !quic_tx_aio ) ) FD_LOG_ERR(( "fd_aio_join failed" ));

  fd_quic_limits_t limits = quic_limits( tile );
  fd_quic_t * quic = fd_quic_join( fd_quic_new( SCRATCH_ALLOC( fd_quic_align(), fd_quic_footprint( &limits ) ), &limits ) );
  if( FD_UNLIKELY( !quic ) ) FD_LOG_ERR(( "fd_quic_join failed" ));

  quic->config.role                       = FD_QUIC_ROLE_SERVER;
  quic->config.net.ip_addr                = tile->quic.ip_addr;
  quic->config.net.listen_udp_port        = tile->quic.quic_transaction_listen_port;
  quic->config.idle_timeout               = tile->quic.idle_timeout_millis * 1000000UL;
  quic->config.initial_rx_max_stream_data = 1<<15;
  fd_memcpy( quic->config.link.src_mac_addr, tile->quic.src_mac_addr, 6 );

  quic->cb.conn_new         = quic_conn_new;
  quic->cb.conn_hs_complete = NULL;
  quic->cb.conn_final       = quic_conn_final;
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

  ctx->verify_out_mem        = topo->workspaces[ verify_out->wksp_id ].wksp;
  ctx->verify_out_dcache_app = fd_dcache_app_laddr( verify_out->dcache );
  ctx->verify_out_chunk0     = fd_dcache_compact_chunk0( ctx->verify_out_mem, verify_out->dcache );
  ctx->verify_out_wmark      = fd_dcache_compact_wmark ( ctx->verify_out_mem, verify_out->dcache, verify_out->mtu );
  ctx->verify_out_chunk      = ctx->verify_out_chunk0;

  ctx->inflight_streams = 0UL;
  ctx->conn_cnt         = 0UL;
  ctx->conn_seq         = 0UL;

  ctx->quic        = quic;
  ctx->quic_rx_aio = fd_quic_get_aio_net_rx( quic );

  ctx->round_robin_cnt = fd_topo_tile_kind_cnt( topo, tile->kind );
  ctx->round_robin_id  = tile->kind_id;

  ctx->legacy_transaction_port = tile->quic.legacy_transaction_listen_port;

  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));
}

static long allow_syscalls[] = {
  __NR_write,     /* logging */
  __NR_fsync,     /* logging, WARNING and above fsync immediately */
  __NR_getpid,    /* OpenSSL RAND_bytes checks pid, temporarily used as part of quic_init to generate a certificate */
  __NR_getrandom, /* OpenSSL RAND_bytes reads getrandom, temporarily used as part of quic_init to generate a certificate */
  __NR_sendto,    /* allows to make requests on netlink socket */
  __NR_recvfrom,  /* allows to receive responses on netlink socket */
};

static ulong
allow_fds( void * scratch,
           ulong  out_fds_cnt,
           int *  out_fds ) {
  (void)scratch;
  if( FD_UNLIKELY( out_fds_cnt < 3 ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));
  fd_nl_t * nl = fd_nl_get();
  if( nl->init == 0 ) {
    FD_LOG_ERR(( "netlink not initialized" ));
  }
  out_fds[ 0 ] = 2;      /* stderr */
  out_fds[ 1 ] = 3;      /* logfile */
  out_fds[ 2 ] = nl->fd; /* netlink socket */
  return 3;
}

fd_tile_config_t fd_tile_quic = {
  .mux_flags               = FD_MUX_FLAG_MANUAL_PUBLISH | FD_MUX_FLAG_COPY,
  .burst                   = 1UL,
  .mux_ctx                 = mux_ctx,
  .mux_during_housekeeping = during_housekeeping,
  .mux_before_credit       = before_credit,
  .mux_before_frag         = before_frag,
  .mux_during_frag         = during_frag,
  .mux_after_frag          = after_frag,
  .mux_cnc_diag_write      = cnc_diag_write,
  .allow_syscalls_cnt      = sizeof(allow_syscalls)/sizeof(allow_syscalls[ 0 ]),
  .allow_syscalls          = allow_syscalls,
  .allow_fds               = allow_fds,
  .loose_footprint         = loose_footprint,
  .scratch_align           = scratch_align,
  .scratch_footprint       = scratch_footprint,
  .privileged_init         = privileged_init,
  .unprivileged_init       = unprivileged_init,
};
