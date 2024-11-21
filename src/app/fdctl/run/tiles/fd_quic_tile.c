#include "../../../../disco/metrics/fd_metrics.h"
#include "../../../../disco/stem/fd_stem.h"
#include "../../../../disco/topo/fd_topo.h"
#include "../../../../disco/quic/fd_tpu.h"
#include "../../../../waltz/quic/fd_quic_private.h"
#include "generated/quic_seccomp.h"

#include <errno.h>
#include <linux/unistd.h>
#include <sys/random.h>

/* fd_quic provides a TPU server tile.

   This tile handles incoming transactions that clients request to be
   included in blocks.  Supported protocols currently include TPU/UDP
   and TPU/QUIC.

   The fd_quic tile acts as a plain old Tango producer writing to a cnc
   and an mcache.  The tile will defragment multi-packet TPU streams
   coming in from QUIC, such that each mcache/dcache pair forms a
   complete txn.  This requires the dcache mtu to be at least that of
   the largest allowed serialized txn size.

   QUIC tiles don't service network devices directly, but rely on
   packets being received by net tiles and forwarded on via. a mux
   (multiplexer).  An arbitrary number of QUIC tiles can be run.  Each
   UDP flow must stick to one QUIC tile. */

typedef struct {
  fd_tpu_reasm_t * reasm;

  fd_stem_context_t * stem;

  fd_quic_t *      quic;
  const fd_aio_t * quic_rx_aio;
  fd_aio_t         quic_tx_aio[1];

# define ED25519_PRIV_KEY_SZ (32)
# define ED25519_PUB_KEY_SZ  (32)
  uchar            tls_priv_key[ ED25519_PRIV_KEY_SZ ];
  uchar            tls_pub_key [ ED25519_PUB_KEY_SZ  ];
  fd_sha512_t      sha512[1]; /* used for signing */

  uchar buffer[ FD_NET_MTU ];

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
    ulong txns_received_udp;
    ulong txns_received_quic_fast;
    ulong txns_received_quic_frag;
    ulong frag_cnt;
    long  reasm_active;
    ulong reasm_overrun;
    ulong reasm_abandoned;
    ulong reasm_started;
  } metrics;
} fd_quic_ctx_t;

FD_FN_CONST static inline fd_quic_limits_t
quic_limits( fd_topo_tile_t const * tile ) {
  fd_quic_limits_t limits = {
    .conn_cnt      = tile->quic.max_concurrent_connections,
    .handshake_cnt = tile->quic.max_concurrent_handshakes,

    /* fd_quic will not issue nor use any new connection IDs after
       completing a handshake.  Connection migration is not supported
       either. */
    .conn_id_cnt      = FD_QUIC_MIN_CONN_ID_CNT,
    .inflight_pkt_cnt = 16UL,
  };
  if( FD_UNLIKELY( !fd_quic_footprint( &limits ) ) ) {
    FD_LOG_ERR(( "Invalid QUIC limits in config" ));
  }
  return limits;
}

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return fd_ulong_max( alignof(fd_quic_ctx_t), fd_quic_align() );
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  fd_quic_limits_t limits = quic_limits( tile ); /* May FD_LOG_ERR */
  ulong            l      = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof( fd_quic_ctx_t ), sizeof( fd_quic_ctx_t )      );
  l = FD_LAYOUT_APPEND( l, fd_quic_align(),          fd_quic_footprint( &limits ) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

/* legacy_stream_notify is called for transactions sent via TPU/UDP. For
   now both QUIC and non-QUIC transactions are accepted, with traffic
   type determined by port.

   UDP transactions must fit in one packet and cannot be fragmented, and
   notify here means the entire packet was received. */

static void
legacy_stream_notify( fd_quic_ctx_t * ctx,
                      uchar *         packet,
                      ulong           packet_sz ) {

  long                tspub    = fd_tickcount();
  fd_tpu_reasm_t *    reasm    = ctx->reasm;
  fd_stem_context_t * stem     = ctx->stem;
  fd_frag_meta_t *    mcache   = stem->mcaches[0];
  void *              base     = ctx->verify_out_mem;
  ulong               seq      = stem->seqs[0];

  fd_tpu_reasm_publish_fast( reasm, packet, packet_sz, mcache, base, seq, tspub );
  ctx->metrics.txns_received_udp++;

  fd_stem_advance( stem, 0UL );
}

/* Because of the separate mcache for publishing network fragments
   back to networking tiles, which is not managed by the mux, we
   need to periodically update the sync. */
static void
during_housekeeping( fd_quic_ctx_t * ctx ) {
  fd_mcache_seq_update( ctx->net_out_sync, ctx->net_out_seq );
}

/* This tile always publishes messages downstream, even if there are
   no credits available.  It ignores the flow control of the downstream
   verify tile.  This is OK as the verify tile is written to expect
   this behavior, and enables the QUIC tile to publish as fast as it
   can.  It would currently be difficult trying to backpressure further
   up the stack to the network itself. */
static inline void
before_credit( fd_quic_ctx_t *     ctx,
               fd_stem_context_t * stem,
               int *               charge_busy ) {
  ctx->stem = stem;

  /* Publishes to mcache via callbacks */
  *charge_busy = fd_quic_service( ctx->quic );
}

static inline void
metrics_write( fd_quic_ctx_t * ctx ) {
  FD_MCNT_SET  ( QUIC_TILE, TXNS_RECEIVED_UDP,       ctx->metrics.txns_received_udp );
  FD_MCNT_SET  ( QUIC_TILE, TXNS_RECEIVED_QUIC_FAST, ctx->metrics.txns_received_quic_fast );
  FD_MCNT_SET  ( QUIC_TILE, TXNS_RECEIVED_QUIC_FRAG, ctx->metrics.txns_received_quic_frag );
  FD_MCNT_SET  ( QUIC_TILE, TXNS_FRAGS,              ctx->metrics.frag_cnt );
  FD_MCNT_SET  ( QUIC_TILE, TXNS_OVERRUN,            ctx->metrics.reasm_overrun );
  FD_MCNT_SET  ( QUIC_TILE, TXNS_ABANDONED,          ctx->metrics.reasm_abandoned );
  FD_MCNT_SET  ( QUIC_TILE, TXN_REASMS_STARTED,      ctx->metrics.reasm_started );
  FD_MGAUGE_SET( QUIC_TILE, TXN_REASMS_ACTIVE,       (ulong)fd_long_max( ctx->metrics.reasm_active, 0L ) );

  FD_MCNT_SET(   QUIC, RECEIVED_PACKETS, ctx->quic->metrics.net_rx_pkt_cnt );
  FD_MCNT_SET(   QUIC, RECEIVED_BYTES,   ctx->quic->metrics.net_rx_byte_cnt );
  FD_MCNT_SET(   QUIC, SENT_PACKETS,     ctx->quic->metrics.net_tx_pkt_cnt );
  FD_MCNT_SET(   QUIC, SENT_BYTES,       ctx->quic->metrics.net_tx_byte_cnt );

  FD_MGAUGE_SET( QUIC, CONNECTIONS_ACTIVE,  ctx->quic->metrics.conn_active_cnt );
  FD_MCNT_SET(   QUIC, CONNECTIONS_CREATED, ctx->quic->metrics.conn_created_cnt );
  FD_MCNT_SET(   QUIC, CONNECTIONS_CLOSED,  ctx->quic->metrics.conn_closed_cnt );
  FD_MCNT_SET(   QUIC, CONNECTIONS_ABORTED, ctx->quic->metrics.conn_aborted_cnt );
  FD_MCNT_SET(   QUIC, CONNECTIONS_TIMED_OUT, ctx->quic->metrics.conn_timeout_cnt );
  FD_MCNT_SET(   QUIC, CONNECTIONS_RETRIED, ctx->quic->metrics.conn_retry_cnt );

  FD_MCNT_SET(   QUIC, CONNECTION_ERROR_NO_SLOTS,   ctx->quic->metrics.conn_err_no_slots_cnt );
  FD_MCNT_SET(   QUIC, CONNECTION_ERROR_RETRY_FAIL, ctx->quic->metrics.conn_err_retry_fail_cnt );

  FD_MCNT_SET(   QUIC, PKT_CRYPTO_FAILED, ctx->quic->metrics.pkt_decrypt_fail_cnt );
  FD_MCNT_SET(   QUIC, PKT_NO_CONN,       ctx->quic->metrics.pkt_no_conn_cnt );

  FD_MCNT_SET(   QUIC, HANDSHAKES_CREATED,         ctx->quic->metrics.hs_created_cnt );
  FD_MCNT_SET(   QUIC, HANDSHAKE_ERROR_ALLOC_FAIL, ctx->quic->metrics.hs_err_alloc_fail_cnt );

  FD_MCNT_SET(  QUIC, STREAM_RECEIVED_EVENTS, ctx->quic->metrics.stream_rx_event_cnt );
  FD_MCNT_SET(  QUIC, STREAM_RECEIVED_BYTES,  ctx->quic->metrics.stream_rx_byte_cnt );

  FD_MCNT_ENUM_COPY( QUIC, RECEIVED_FRAMES, ctx->quic->metrics.frame_rx_cnt );

  FD_MCNT_ENUM_COPY( QUIC, ACK_TX, ctx->quic->metrics.ack_tx );

  FD_MHIST_COPY( QUIC, SERVICE_DURATION_SECONDS, ctx->quic->metrics.service_duration );
  FD_MHIST_COPY( QUIC, RECEIVE_DURATION_SECONDS, ctx->quic->metrics.receive_duration );
}

static int
before_frag( fd_quic_ctx_t * ctx,
             ulong           in_idx,
             ulong           seq,
             ulong           sig ) {
  (void)in_idx;
  (void)seq;

  ulong proto = fd_disco_netmux_sig_proto( sig );
  if( FD_UNLIKELY( proto!=DST_PROTO_TPU_UDP && proto!=DST_PROTO_TPU_QUIC ) ) return 1;

  ulong hash = fd_disco_netmux_sig_hash( sig );
  if( FD_UNLIKELY( (hash % ctx->round_robin_cnt) != ctx->round_robin_id ) ) return 1;

  return 0;
}

static void
during_frag( fd_quic_ctx_t * ctx,
             ulong           in_idx,
             ulong           seq,
             ulong           sig,
             ulong           chunk,
             ulong           sz ) {
  (void)in_idx;
  (void)seq;
  (void)sig;

  if( FD_UNLIKELY( chunk<ctx->in_chunk0 || chunk>ctx->in_wmark || sz > FD_NET_MTU ) )
    FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->in_chunk0, ctx->in_wmark ));

  uchar * src = (uchar *)fd_chunk_to_laddr( ctx->in_mem, chunk );
  fd_memcpy( ctx->buffer, src, sz ); /* TODO: Eliminate copy... fd_aio needs refactoring */
}

static void
after_frag( fd_quic_ctx_t *     ctx,
            ulong               in_idx,
            ulong               seq,
            ulong               sig,
            ulong               chunk,
            ulong               sz,
            ulong               tsorig,
            fd_stem_context_t * stem ) {
  (void)in_idx;
  (void)seq;
  (void)chunk;
  (void)tsorig;
  (void)stem;

  ulong proto = fd_disco_netmux_sig_proto( sig );

  if( FD_LIKELY( proto==DST_PROTO_TPU_QUIC ) ) {
    fd_aio_pkt_info_t pkt = { .buf = ctx->buffer, .buf_sz = (ushort)sz };
    fd_aio_send( ctx->quic_rx_aio, &pkt, 1, NULL, 1 );
  } else if( FD_LIKELY( proto==DST_PROTO_TPU_UDP ) ) {
    ulong network_hdr_sz = fd_disco_netmux_sig_hdr_sz( sig );
    if( FD_UNLIKELY( sz<=network_hdr_sz ) ) {
      /* Transaction not valid if the packet isn't large enough for the network
         headers. */
      FD_MCNT_INC( QUIC_TILE, NON_QUIC_PACKET_TOO_SMALL, 1UL );
      return;
    }

    ulong data_sz = sz - network_hdr_sz;
    if( FD_UNLIKELY( data_sz<FD_TXN_MIN_SERIALIZED_SZ ) ) {
      /* Smaller than the smallest possible transaction */
      FD_MCNT_INC( QUIC_TILE, NON_QUIC_PACKET_TOO_SMALL, 1UL );
      return;
    }

    if( FD_UNLIKELY( data_sz>FD_TPU_MTU ) ) {
      /* Transaction couldn't possibly be valid if it's longer than transaction
         MTU so drop it. This is not required, as the txn will fail to parse,
         but it's a nice short circuit. */
      FD_MCNT_INC( QUIC_TILE, NON_QUIC_PACKET_TOO_LARGE, 1UL );
      return;
    }

    legacy_stream_notify( ctx, ctx->buffer+network_hdr_sz, data_sz );
  }
}

/* quic_now is called by the QUIC engine to get the current timestamp in
   UNIX time.  */

static ulong
quic_now( void * ctx ) {
  (void)ctx;
  return (ulong)fd_log_wallclock();
}

static void
quic_conn_final( fd_quic_conn_t * conn,
                 void *           quic_ctx ) {
  fd_quic_ctx_t * ctx = quic_ctx;
  long abandon_cnt = fd_long_max( conn->srx->rx_streams_active, 0L );
  ctx->metrics.reasm_active    -= abandon_cnt;
  ctx->metrics.reasm_abandoned += (ulong)abandon_cnt;
}

static int
quic_stream_rx( fd_quic_conn_t * conn,
                ulong            stream_id,
                ulong            offset,
                uchar const *    data,
                ulong            data_sz,
                int              fin ) {

  long                tspub    = fd_tickcount();
  fd_quic_t *         quic     = conn->quic;
  fd_quic_state_t *   state    = fd_quic_get_state( quic );  /* ugly */
  fd_quic_ctx_t *     ctx      = quic->cb.quic_ctx;
  fd_tpu_reasm_t *    reasm    = ctx->reasm;
  ulong               conn_uid = fd_quic_conn_uid( conn );
  fd_stem_context_t * stem     = ctx->stem;
  fd_frag_meta_t *    mcache   = stem->mcaches[0];
  void *              base     = ctx->verify_out_mem;
  ulong               seq      = stem->seqs[0];

  if( offset==0UL && fin ) {
    /* Fast path */
    fd_tpu_reasm_publish_fast( reasm, data, data_sz, mcache, base, seq, tspub );
    fd_stem_advance( stem, 0UL );
    ctx->metrics.txns_received_quic_fast++;
    return FD_QUIC_SUCCESS;
  }

  if( data_sz==0UL && !fin ) return FD_QUIC_SUCCESS; /* noop */

  fd_tpu_reasm_slot_t * slot = fd_tpu_reasm_query( reasm, conn_uid, stream_id );

  if( !slot ) { /* start a new reassembly */
    if( offset>0   ) return FD_QUIC_FAILED;  /* ignore gapped (cancel ACK) */
    if( data_sz==0 ) return FD_QUIC_SUCCESS; /* ignore empty */

    /* Was the reasm buffer we evicted busy? */
    fd_tpu_reasm_slot_t * victim      = fd_tpu_reasm_peek_tail( reasm );
    int                   victim_busy = victim->k.state == FD_TPU_REASM_STATE_BUSY;

    /* If so, does the connection it refers to still exist?
       (Or was the buffer previously abandoned by means of conn close) */
    uint             victim_cidx   = fd_quic_conn_uid_idx( victim->k.conn_uid );
    uint             victim_gen    = fd_quic_conn_uid_gen( victim->k.conn_uid );
    fd_quic_conn_t * victim_conn   = fd_quic_conn_at_idx( state, victim_cidx ); /* possibly oob */
    if( victim_busy ) {
      uint victim_exists = (victim_conn->conn_gen == victim_gen) &
                           (victim_conn->state == FD_QUIC_CONN_STATE_ACTIVE); /* in [0,1] */
      victim_conn->srx->rx_streams_active -= victim_exists;
      ctx->metrics.reasm_overrun          += victim_exists;
      ctx->metrics.reasm_active           -= victim_exists;
    }

    slot = fd_tpu_reasm_prepare( reasm, conn_uid, stream_id, tspub ); /* infallible */
    ctx->metrics.reasm_started++;
    ctx->metrics.reasm_active++;
  }

  conn->srx->rx_streams_active++;

  int reasm_res = fd_tpu_reasm_frag( reasm, slot, data, data_sz, offset );
  if( FD_UNLIKELY( reasm_res != FD_TPU_REASM_SUCCESS ) ) {
    return reasm_res!=FD_TPU_REASM_ERR_SKIP ? FD_QUIC_SUCCESS : FD_QUIC_FAILED;
  }
  ctx->metrics.frag_cnt++;

  if( fin ) {
    int pub_err = fd_tpu_reasm_publish( reasm, slot, mcache, base, seq, tspub );
    if( FD_UNLIKELY( pub_err!=FD_TPU_REASM_SUCCESS ) ) return FD_QUIC_SUCCESS; /* unreachable */
    ctx->metrics.txns_received_quic_frag++;
    ctx->metrics.reasm_active--;
    conn->srx->rx_streams_active--;

    fd_stem_advance( stem, 0UL );
  }

  return FD_QUIC_SUCCESS;
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
    }

    /* send packets are just round-robined by sequence number, so for now
       just indicate where they came from so they don't bounce back */
    ulong sig = fd_disco_netmux_sig( 0U, 0U, ip_dstaddr, DST_PROTO_OUTGOING, FD_NETMUX_SIG_MIN_HDR_SZ );

    long tspub = fd_tickcount();
    fd_mcache_publish( ctx->net_out_mcache,
                       ctx->net_out_depth,
                       ctx->net_out_seq,
                       sig,
                       ctx->net_out_chunk,
                       batch[ i ].buf_sz,
                       fd_frag_meta_ctl( 0UL, 1, 1, 0 ),
                       0,
                       fd_frag_meta_ts_comp( tspub ) );

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
                 fd_topo_tile_t * tile ) {
  (void)topo; (void)tile;

  /* The fd_quic implementation calls fd_log_wallclock() internally
     which itself calls clock_gettime() which on most kernels is not a
     real syscall but a virtual one in the process via. the vDSO.

     The first time this virtual call is made to the vDSO it does an
     mmap(2) of some shared memory into userspace, which cannot
     happen while sandboxed so we need to ensure that initialization
     happens here. */

  fd_log_wallclock();
}

static void
quic_tls_cv_sign( void *      signer_ctx,
                  uchar       signature[ static 64 ],
                  uchar const payload[ static 130 ] ) {
  fd_quic_ctx_t * ctx = signer_ctx;
  fd_sha512_t * sha512 = fd_sha512_join( ctx->sha512 );
  fd_ed25519_sign( signature, payload, 130UL, ctx->tls_pub_key, ctx->tls_priv_key, sha512 );
  fd_sha512_leave( sha512 );
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  if( FD_UNLIKELY( topo->objs[ tile->tile_obj_id ].footprint < scratch_footprint( tile ) ) ) {
    FD_LOG_ERR(( "insufficient tile scratch space" ));
  }

  if( FD_UNLIKELY( tile->in_cnt<1UL ||
                   strcmp( topo->links[ tile->in_link_id[ 0UL ] ].name, "net_quic" ) ) )
    FD_LOG_ERR(( "quic tile has none or unexpected input links %lu %s %s",
                 tile->in_cnt, topo->links[ tile->in_link_id[ 0 ] ].name, topo->links[ tile->in_link_id[ 1 ] ].name ));

  if( FD_UNLIKELY( tile->out_cnt!=2UL ||
                   strcmp( topo->links[ tile->out_link_id[ 0UL ] ].name, "quic_verify" ) ||
                   strcmp( topo->links[ tile->out_link_id[ 1UL ] ].name, "quic_net" ) ) )
    FD_LOG_ERR(( "quic tile has none or unexpected output links %lu %s %s",
                 tile->out_cnt, topo->links[ tile->out_link_id[ 0 ] ].name, topo->links[ tile->out_link_id[ 1 ] ].name ));

  if( FD_UNLIKELY( !tile->in_cnt ) ) FD_LOG_ERR(( "quic tile in cnt is zero" ));

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_quic_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_quic_ctx_t ), sizeof( fd_quic_ctx_t ) );
  fd_memset( ctx, 0, sizeof(fd_quic_ctx_t) );

  if( FD_UNLIKELY( getrandom( ctx->tls_priv_key, ED25519_PRIV_KEY_SZ, 0 )!=ED25519_PRIV_KEY_SZ ) ) {
    FD_LOG_ERR(( "getrandom failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  fd_sha512_t * sha512 = fd_sha512_join( fd_sha512_new( ctx->sha512 ) );
  fd_ed25519_public_from_private( ctx->tls_pub_key, ctx->tls_priv_key, sha512 );
  fd_sha512_leave( sha512 );

  fd_aio_t * quic_tx_aio = fd_aio_join( fd_aio_new( ctx->quic_tx_aio, ctx, quic_tx_aio_send ) );
  if( FD_UNLIKELY( !quic_tx_aio ) ) FD_LOG_ERR(( "fd_aio_join failed" ));

  fd_quic_limits_t limits = quic_limits( tile );
  fd_quic_t * quic = fd_quic_join( fd_quic_new( FD_SCRATCH_ALLOC_APPEND( l, fd_quic_align(), fd_quic_footprint( &limits ) ), &limits ) );
  if( FD_UNLIKELY( !quic ) ) FD_LOG_ERR(( "fd_quic_join failed" ));

  if( FD_UNLIKELY( tile->quic.ack_delay_millis == 0 ) ) {
    FD_LOG_ERR(( "Invalid `ack_delay_millis`: must be greater than zero" ));
  }
  if( FD_UNLIKELY( tile->quic.ack_delay_millis >= tile->quic.idle_timeout_millis ) ) {
    FD_LOG_ERR(( "Invalid `ack_delay_millis`: must be lower than `idle_timeout_millis`" ));
  }
  if( FD_UNLIKELY( !tile->quic.ip_addr ) ) {
    FD_LOG_ERR(( "QUIC IP address not set" ));
  }

  quic->config.role                       = FD_QUIC_ROLE_SERVER;
  quic->config.net.ip_addr                = tile->quic.ip_addr;
  quic->config.net.listen_udp_port        = tile->quic.quic_transaction_listen_port;
  quic->config.idle_timeout               = tile->quic.idle_timeout_millis * 1000000UL;
  quic->config.ack_delay                  = tile->quic.ack_delay_millis * 1000000UL;
  quic->config.initial_rx_max_stream_data = FD_TXN_MTU;
  quic->config.retry                      = tile->quic.retry;
  fd_memcpy( quic->config.link.src_mac_addr, tile->quic.src_mac_addr, 6 );
  fd_memcpy( quic->config.identity_public_key, ctx->tls_pub_key, ED25519_PUB_KEY_SZ );

  quic->config.sign         = quic_tls_cv_sign;
  quic->config.sign_ctx     = ctx;

  quic->cb.conn_final       = quic_conn_final;
  quic->cb.stream_rx        = quic_stream_rx;
  quic->cb.now              = quic_now;
  quic->cb.now_ctx          = NULL;
  quic->cb.quic_ctx         = ctx;

  fd_quic_set_aio_net_tx( quic, quic_tx_aio );
  if( FD_UNLIKELY( !fd_quic_init( quic ) ) ) FD_LOG_ERR(( "fd_quic_init failed" ));

  fd_topo_link_t * net_in = &topo->links[ tile->in_link_id[ 0 ] ];
  ctx->in_mem    = topo->workspaces[ topo->objs[ net_in->dcache_obj_id ].wksp_id ].wksp;
  ctx->in_chunk0 = fd_dcache_compact_chunk0( ctx->in_mem, net_in->dcache );
  ctx->in_wmark  = fd_dcache_compact_wmark ( ctx->in_mem, net_in->dcache, net_in->mtu );

  fd_topo_link_t * net_out = &topo->links[ tile->out_link_id[ 1 ] ];

  ctx->net_out_mcache = net_out->mcache;
  ctx->net_out_sync   = fd_mcache_seq_laddr( ctx->net_out_mcache );
  ctx->net_out_depth  = fd_mcache_depth( ctx->net_out_mcache );
  ctx->net_out_seq    = fd_mcache_seq_query( ctx->net_out_sync );
  ctx->net_out_mem    = topo->workspaces[ topo->objs[ net_out->dcache_obj_id ].wksp_id ].wksp;
  ctx->net_out_chunk0 = fd_dcache_compact_chunk0( ctx->net_out_mem, net_out->dcache );
  ctx->net_out_wmark  = fd_dcache_compact_wmark ( ctx->net_out_mem, net_out->dcache, net_out->mtu );
  ctx->net_out_chunk  = ctx->net_out_chunk0;

  fd_topo_link_t * verify_out = &topo->links[ tile->out_link_id[ 0 ] ];

  ctx->verify_out_mem = topo->workspaces[ topo->objs[ verify_out->reasm_obj_id ].wksp_id ].wksp;

  ctx->reasm = verify_out->reasm;
  if( FD_UNLIKELY( !verify_out->is_reasm || !ctx->reasm ) )
    FD_LOG_ERR(( "invalid tpu_reasm parameters" ));

  ctx->quic        = quic;
  ctx->quic_rx_aio = fd_quic_get_aio_net_rx( quic );

  ctx->round_robin_cnt = fd_topo_tile_name_cnt( topo, tile->name );
  ctx->round_robin_id  = tile->kind_id;
  if( FD_UNLIKELY( ctx->round_robin_id >= ctx->round_robin_cnt ) ) {
    FD_LOG_ERR(( "invalid round robin configuration" ));
  }

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));

  fd_histf_join( fd_histf_new( ctx->quic->metrics.service_duration, FD_MHIST_SECONDS_MIN( QUIC, SERVICE_DURATION_SECONDS ),
                                                                    FD_MHIST_SECONDS_MAX( QUIC, SERVICE_DURATION_SECONDS ) ) );
  fd_histf_join( fd_histf_new( ctx->quic->metrics.receive_duration, FD_MHIST_SECONDS_MIN( QUIC, RECEIVE_DURATION_SECONDS ),
                                                                    FD_MHIST_SECONDS_MAX( QUIC, RECEIVE_DURATION_SECONDS ) ) );
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  (void)topo;
  (void)tile;

  populate_sock_filter_policy_quic( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_quic_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  (void)topo;
  (void)tile;

  if( FD_UNLIKELY( out_fds_cnt<2UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  return out_cnt;
}

#define STEM_BURST (1UL)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_quic_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_quic_ctx_t)

#define STEM_CALLBACK_DURING_HOUSEKEEPING during_housekeeping
#define STEM_CALLBACK_METRICS_WRITE       metrics_write
#define STEM_CALLBACK_BEFORE_CREDIT       before_credit
#define STEM_CALLBACK_BEFORE_FRAG         before_frag
#define STEM_CALLBACK_DURING_FRAG         during_frag
#define STEM_CALLBACK_AFTER_FRAG          after_frag

#include "../../../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_quic = {
  .name                     = "quic",
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
