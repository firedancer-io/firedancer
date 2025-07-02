#include "fd_quic_tile.h"
#include "../metrics/fd_metrics.h"
#include "../stem/fd_stem.h"
#include "../topo/fd_topo.h"
#include "fd_tpu.h"
#include "../../waltz/quic/fd_quic_private.h"
#include "generated/quic_seccomp.h"
#include "../../util/net/fd_eth.h"

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

static inline fd_quic_limits_t
quic_limits( fd_topo_tile_t const * tile ) {
  fd_quic_limits_t limits = {
    .conn_cnt      = tile->quic.max_concurrent_connections,
    .handshake_cnt = tile->quic.max_concurrent_handshakes,

    /* fd_quic will not issue nor use any new connection IDs after
       completing a handshake.  Connection migration is not supported
       either. */
    .conn_id_cnt                 = FD_QUIC_MIN_CONN_ID_CNT,
    .inflight_frame_cnt          = 64UL * tile->quic.max_concurrent_connections,
    .min_inflight_frame_cnt_conn = 32UL
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

static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  ulong out_depth = tile->quic.out_depth;
  ulong reasm_max = tile->quic.reasm_cnt;

  fd_quic_limits_t limits = quic_limits( tile ); /* May FD_LOG_ERR */
  ulong            l      = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof( fd_quic_ctx_t ), sizeof( fd_quic_ctx_t )                        );
  l = FD_LAYOUT_APPEND( l, fd_quic_align(),          fd_quic_footprint( &limits )                   );
  l = FD_LAYOUT_APPEND( l, fd_tpu_reasm_align(),     fd_tpu_reasm_footprint( out_depth, reasm_max ) );
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

  int err = fd_tpu_reasm_publish_fast( reasm, packet, packet_sz, mcache, base, seq, tspub );
  if( FD_LIKELY( err==FD_TPU_REASM_SUCCESS ) ) {
    fd_stem_advance( stem, 0UL );
    ctx->metrics.txns_received_udp++;
  }
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
  FD_MCNT_SET  ( QUIC, TXNS_RECEIVED_UDP,       ctx->metrics.txns_received_udp );
  FD_MCNT_SET  ( QUIC, TXNS_RECEIVED_QUIC_FAST, ctx->metrics.txns_received_quic_fast );
  FD_MCNT_SET  ( QUIC, TXNS_RECEIVED_QUIC_FRAG, ctx->metrics.txns_received_quic_frag );
  FD_MCNT_SET  ( QUIC, FRAGS_OK,                ctx->metrics.frag_ok_cnt );
  FD_MCNT_SET  ( QUIC, FRAGS_GAP,               ctx->metrics.frag_gap_cnt );
  FD_MCNT_SET  ( QUIC, FRAGS_DUP,               ctx->metrics.frag_dup_cnt );
  FD_MCNT_SET  ( QUIC, TXNS_OVERRUN,            ctx->metrics.reasm_overrun );
  FD_MCNT_SET  ( QUIC, TXNS_ABANDONED,          ctx->metrics.reasm_abandoned );
  FD_MCNT_SET  ( QUIC, TXN_REASMS_STARTED,      ctx->metrics.reasm_started );
  FD_MGAUGE_SET( QUIC, TXN_REASMS_ACTIVE,       (ulong)fd_long_max( ctx->metrics.reasm_active, 0L ) );

  FD_MCNT_SET( QUIC, LEGACY_TXN_UNDERSZ, ctx->metrics.udp_pkt_too_small );
  FD_MCNT_SET( QUIC, LEGACY_TXN_OVERSZ,  ctx->metrics.udp_pkt_too_large );
  FD_MCNT_SET( QUIC, TXN_UNDERSZ,        ctx->metrics.quic_txn_too_small );
  FD_MCNT_SET( QUIC, TXN_OVERSZ,         ctx->metrics.quic_txn_too_large );

  FD_MCNT_SET(   QUIC, RECEIVED_PACKETS, ctx->quic->metrics.net_rx_pkt_cnt );
  FD_MCNT_SET(   QUIC, RECEIVED_BYTES,   ctx->quic->metrics.net_rx_byte_cnt );
  FD_MCNT_SET(   QUIC, SENT_PACKETS,     ctx->quic->metrics.net_tx_pkt_cnt );
  FD_MCNT_SET(   QUIC, SENT_BYTES,       ctx->quic->metrics.net_tx_byte_cnt );
  FD_MCNT_SET(   QUIC, RETRY_SENT,       ctx->quic->metrics.retry_tx_cnt );

  FD_MGAUGE_SET( QUIC, CONNECTIONS_ACTIVE,  ctx->quic->metrics.conn_active_cnt );
  FD_MCNT_SET(   QUIC, CONNECTIONS_CREATED, ctx->quic->metrics.conn_created_cnt );
  FD_MCNT_SET(   QUIC, CONNECTIONS_CLOSED,  ctx->quic->metrics.conn_closed_cnt );
  FD_MCNT_SET(   QUIC, CONNECTIONS_ABORTED, ctx->quic->metrics.conn_aborted_cnt );
  FD_MCNT_SET(   QUIC, CONNECTIONS_TIMED_OUT, ctx->quic->metrics.conn_timeout_cnt );
  FD_MCNT_SET(   QUIC, CONNECTIONS_RETRIED, ctx->quic->metrics.conn_retry_cnt );

  FD_MCNT_SET(   QUIC, CONNECTION_ERROR_NO_SLOTS,   ctx->quic->metrics.conn_err_no_slots_cnt );
  FD_MCNT_SET(   QUIC, CONNECTION_ERROR_RETRY_FAIL, ctx->quic->metrics.conn_err_retry_fail_cnt );

  FD_MCNT_ENUM_COPY( QUIC, PKT_CRYPTO_FAILED,   ctx->quic->metrics.pkt_decrypt_fail_cnt );
  FD_MCNT_ENUM_COPY( QUIC, PKT_NO_KEY,          ctx->quic->metrics.pkt_no_key_cnt );
  FD_MCNT_SET(       QUIC, PKT_NO_CONN,         ctx->quic->metrics.pkt_no_conn_cnt );
  FD_MCNT_ENUM_COPY( QUIC, FRAME_TX_ALLOC,        ctx->quic->metrics.frame_tx_alloc_cnt );
  FD_MCNT_SET(       QUIC, PKT_NET_HEADER_INVALID,  ctx->quic->metrics.pkt_net_hdr_err_cnt );
  FD_MCNT_SET(       QUIC, PKT_QUIC_HEADER_INVALID, ctx->quic->metrics.pkt_quic_hdr_err_cnt );
  FD_MCNT_SET(       QUIC, PKT_UNDERSZ,         ctx->quic->metrics.pkt_undersz_cnt );
  FD_MCNT_SET(       QUIC, PKT_OVERSZ,          ctx->quic->metrics.pkt_oversz_cnt );
  FD_MCNT_SET(       QUIC, PKT_VERNEG,          ctx->quic->metrics.pkt_verneg_cnt );
  FD_MCNT_SET(       QUIC, PKT_RETRANSMISSIONS, ctx->quic->metrics.pkt_retransmissions_cnt );

  FD_MCNT_SET(   QUIC, HANDSHAKES_CREATED,         ctx->quic->metrics.hs_created_cnt );
  FD_MCNT_SET(   QUIC, HANDSHAKE_ERROR_ALLOC_FAIL, ctx->quic->metrics.hs_err_alloc_fail_cnt );
  FD_MCNT_SET(   QUIC, HANDSHAKE_EVICTED,          ctx->quic->metrics.hs_evicted_cnt );

  FD_MCNT_SET(  QUIC, STREAM_RECEIVED_EVENTS, ctx->quic->metrics.stream_rx_event_cnt );
  FD_MCNT_SET(  QUIC, STREAM_RECEIVED_BYTES,  ctx->quic->metrics.stream_rx_byte_cnt );

  FD_MCNT_ENUM_COPY( QUIC, RECEIVED_FRAMES,  ctx->quic->metrics.frame_rx_cnt );
  FD_MCNT_SET      ( QUIC, FRAME_FAIL_PARSE, ctx->quic->metrics.frame_rx_err_cnt );

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
             ulong           seq    FD_PARAM_UNUSED,
             ulong           sig    FD_PARAM_UNUSED,
             ulong           chunk,
             ulong           sz,
             ulong           ctl ) {
  void const * src = fd_net_rx_translate_frag( &ctx->net_in_bounds[ in_idx ], chunk, ctl, sz );

  /* FIXME this copy could be eliminated by combining it with the decrypt operation */
  fd_memcpy( ctx->buffer, src, sz );
}

static void
after_frag( fd_quic_ctx_t *     ctx,
            ulong               in_idx,
            ulong               seq,
            ulong               sig,
            ulong               sz,
            ulong               tsorig,
            ulong               tspub,
            fd_stem_context_t * stem ) {
  (void)in_idx;
  (void)seq;
  (void)tsorig;
  (void)tspub;
  (void)stem;

  ulong proto = fd_disco_netmux_sig_proto( sig );

  if( FD_LIKELY( proto==DST_PROTO_TPU_QUIC ) ) {
    if( FD_UNLIKELY( sz<sizeof(fd_eth_hdr_t) ) ) FD_LOG_ERR(( "QUIC packet too small" ));
    uchar * ip_pkt = ctx->buffer + sizeof(fd_eth_hdr_t);
    ulong   ip_sz  = sz - sizeof(fd_eth_hdr_t);

    fd_quic_t * quic = ctx->quic;
    long dt = -fd_tickcount();
    fd_quic_process_packet( quic, ip_pkt, ip_sz );
    dt += fd_tickcount();
    fd_histf_sample( quic->metrics.receive_duration, (ulong)dt );
    quic->metrics.net_rx_byte_cnt += sz;
    quic->metrics.net_rx_pkt_cnt++;
  } else if( FD_LIKELY( proto==DST_PROTO_TPU_UDP ) ) {
    ulong network_hdr_sz = fd_disco_netmux_sig_hdr_sz( sig );
    if( FD_UNLIKELY( sz<=network_hdr_sz ) ) {
      /* Transaction not valid if the packet isn't large enough for the network
         headers. */
      ctx->metrics.udp_pkt_too_small++;
      return;
    }

    ulong data_sz = sz - network_hdr_sz;
    if( FD_UNLIKELY( data_sz<FD_TXN_MIN_SERIALIZED_SZ ) ) {
      /* Smaller than the smallest possible transaction */
      ctx->metrics.udp_pkt_too_small++;
      return;
    }

    if( FD_UNLIKELY( data_sz>FD_TPU_MTU ) ) {
      /* Transaction couldn't possibly be valid if it's longer than transaction
         MTU so drop it. This is not required, as the txn will fail to parse,
         but it's a nice short circuit. */
      ctx->metrics.udp_pkt_too_large++;
      return;
    }

    legacy_stream_notify( ctx, ctx->buffer+network_hdr_sz, data_sz );
  }
}

static ulong
quic_now( void * ctx FD_PARAM_UNUSED ) {
  return (ulong)fd_tickcount();
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

  int oversz = offset+data_sz > FD_TPU_MTU;

  if( offset==0UL && fin ) {
    /* Fast path */
    if( FD_UNLIKELY( data_sz<FD_TXN_MIN_SERIALIZED_SZ ) ) {
      ctx->metrics.quic_txn_too_small++;
      return FD_QUIC_SUCCESS; /* drop */
    }
    if( FD_UNLIKELY( oversz ) ) {
      ctx->metrics.quic_txn_too_large++;
      return FD_QUIC_SUCCESS; /* drop */
    }
    int err = fd_tpu_reasm_publish_fast( reasm, data, data_sz, mcache, base, seq, tspub );
    if( FD_LIKELY( err==FD_TPU_REASM_SUCCESS ) ) {
      fd_stem_advance( stem, 0UL );
      ctx->metrics.txns_received_quic_fast++;
    }
    return FD_QUIC_SUCCESS;
  }

  if( data_sz==0UL && !fin ) return FD_QUIC_SUCCESS; /* noop */

  fd_tpu_reasm_slot_t * slot = fd_tpu_reasm_query( reasm, conn_uid, stream_id );

  if( !slot ) { /* start a new reassembly */
    if( offset>0 ) {
      ctx->metrics.frag_gap_cnt++;
      return FD_QUIC_SUCCESS;
    }
    if( data_sz==0 ) return FD_QUIC_SUCCESS; /* ignore empty */
    if( FD_UNLIKELY( oversz ) ) {
      ctx->metrics.quic_txn_too_large++;
      return FD_QUIC_SUCCESS; /* drop */
    }

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
    conn->srx->rx_streams_active++;
  } else if( slot->k.state != FD_TPU_REASM_STATE_BUSY ) {
    ctx->metrics.frag_dup_cnt++;
    return FD_QUIC_SUCCESS;
  }

  int reasm_res = fd_tpu_reasm_frag( reasm, slot, data, data_sz, offset );
  if( FD_UNLIKELY( reasm_res != FD_TPU_REASM_SUCCESS ) ) {
    int is_gap    = reasm_res==FD_TPU_REASM_ERR_SKIP;
    int is_oversz = reasm_res==FD_TPU_REASM_ERR_SZ;
    ctx->metrics.frag_gap_cnt       += (ulong)is_gap;
    ctx->metrics.quic_txn_too_large += (ulong)is_oversz;
    return is_gap ? FD_QUIC_FAILED : FD_QUIC_SUCCESS;
  }
  ctx->metrics.frag_ok_cnt++;

  if( fin ) {
    if( FD_UNLIKELY( slot->k.sz < FD_TXN_MIN_SERIALIZED_SZ ) ) {
      ctx->metrics.quic_txn_too_small++;
      return FD_QUIC_SUCCESS; /* ignore */
    }
    int pub_err = fd_tpu_reasm_publish( reasm, slot, mcache, base, seq, tspub );
    if( FD_UNLIKELY( pub_err!=FD_TPU_REASM_SUCCESS ) ) return FD_QUIC_SUCCESS; /* unreachable */
    ulong * rcv_cnt = (offset==0UL && fin) ? &ctx->metrics.txns_received_quic_fast : &ctx->metrics.txns_received_quic_frag;
    (*rcv_cnt)++;
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

  fd_quic_ctx_t * ctx = _ctx;

  for( ulong i=0; i<batch_cnt; i++ ) {
    if( FD_UNLIKELY( batch[ i ].buf_sz<FD_NETMUX_SIG_MIN_HDR_SZ ) ) continue;

    uint const ip_dst = FD_LOAD( uint, batch[ i ].buf+offsetof( fd_ip4_hdr_t, daddr_c ) );
    uchar * packet_l2 = fd_chunk_to_laddr( ctx->net_out_mem, ctx->net_out_chunk );
    uchar * packet_l3 = packet_l2 + sizeof(fd_eth_hdr_t);
    memset( packet_l2, 0, 12 );
    FD_STORE( ushort, packet_l2+offsetof( fd_eth_hdr_t, net_type ), fd_ushort_bswap( FD_ETH_HDR_TYPE_IP ) );
    fd_memcpy( packet_l3, batch[ i ].buf, batch[ i ].buf_sz );
    ulong sz_l2 = sizeof(fd_eth_hdr_t) + batch[ i ].buf_sz;

    /* send packets are just round-robined by sequence number, so for now
       just indicate where they came from so they don't bounce back */
    ulong sig = fd_disco_netmux_sig( ip_dst, 0U, ip_dst, DST_PROTO_OUTGOING, FD_NETMUX_SIG_MIN_HDR_SZ );

    long tspub = fd_tickcount();
    fd_mcache_publish( ctx->net_out_mcache,
                       ctx->net_out_depth,
                       ctx->net_out_seq,
                       sig,
                       ctx->net_out_chunk,
                       sz_l2,
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

  if( FD_UNLIKELY( tile->in_cnt==0 ) ) {
    FD_LOG_ERR(( "quic tile has no input links" ));
  }
  if( FD_UNLIKELY( tile->in_cnt > FD_QUIC_TILE_IN_MAX ) ) {
    FD_LOG_ERR(( "quic tile has too many input links (%lu), max %lu",
                 tile->in_cnt, FD_QUIC_TILE_IN_MAX ));
  }

  if( FD_UNLIKELY( tile->out_cnt!=2UL ||
                   strcmp( topo->links[ tile->out_link_id[ 0UL ] ].name, "quic_verify" ) ||
                   strcmp( topo->links[ tile->out_link_id[ 1UL ] ].name, "quic_net" ) ) )
    FD_LOG_ERR(( "quic tile has none or unexpected output links %lu %s %s",
                 tile->out_cnt, topo->links[ tile->out_link_id[ 0 ] ].name, topo->links[ tile->out_link_id[ 1 ] ].name ));

  ulong out_depth = topo->links[ tile->out_link_id[ 0 ] ].depth;
  if( FD_UNLIKELY( tile->quic.out_depth != out_depth ) )
    FD_LOG_ERR(( "tile->quic.out_depth (%u) does not match quic_verify link depth (%lu)",
                 tile->quic.out_depth, out_depth ));

  void * txn_dcache = topo->links[ tile->out_link_id[ 0UL ] ].dcache;
  if( FD_UNLIKELY( !txn_dcache ) ) FD_LOG_ERR(( "Missing output dcache" ));

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_quic_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_quic_ctx_t ), sizeof( fd_quic_ctx_t ) );
  fd_memset( ctx, 0, sizeof(fd_quic_ctx_t) );

  for( ulong i=0; i<tile->in_cnt; i++ ) {
    fd_topo_link_t * link = &topo->links[ tile->in_link_id[ i ] ];
    if( FD_UNLIKELY( 0!=strcmp( link->name, "net_quic" ) ) ) {
      FD_LOG_ERR(( "unexpected input link %s", link->name ));
    }
    fd_net_rx_bounds_init( &ctx->net_in_bounds[ i ], link->dcache );
  }

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
  if( FD_UNLIKELY( !quic ) ) FD_LOG_ERR(( "fd_quic_new failed" ));

  ulong  orig      = 0UL; /* fd_tango origin ID */
  ulong  reasm_max = tile->quic.reasm_cnt;
  void * reasm_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_tpu_reasm_align(), fd_tpu_reasm_footprint( out_depth, reasm_max ) );
  ctx->reasm       = fd_tpu_reasm_join( fd_tpu_reasm_new( reasm_mem, out_depth, reasm_max, orig, txn_dcache ) );
  if( FD_UNLIKELY( !ctx->reasm ) ) FD_LOG_ERR(( "fd_tpu_reasm_new failed" ));

  if( FD_UNLIKELY( tile->quic.ack_delay_millis == 0 ) ) {
    FD_LOG_ERR(( "Invalid `ack_delay_millis`: must be greater than zero" ));
  }
  if( FD_UNLIKELY( tile->quic.ack_delay_millis >= tile->quic.idle_timeout_millis ) ) {
    FD_LOG_ERR(( "Invalid `ack_delay_millis`: must be lower than `idle_timeout_millis`" ));
  }

  quic->config.role                       = FD_QUIC_ROLE_SERVER;
  quic->config.idle_timeout               = tile->quic.idle_timeout_millis * (ulong)1e6;
  quic->config.ack_delay                  = tile->quic.ack_delay_millis * (ulong)1e6;
  quic->config.initial_rx_max_stream_data = FD_TXN_MTU;
  quic->config.retry                      = tile->quic.retry;
  fd_memcpy( quic->config.identity_public_key, ctx->tls_pub_key, ED25519_PUB_KEY_SZ );

  quic->config.sign         = quic_tls_cv_sign;
  quic->config.sign_ctx     = ctx;

  quic->cb.conn_final       = quic_conn_final;
  quic->cb.stream_rx        = quic_stream_rx;
  quic->cb.now              = quic_now;
  quic->cb.now_ctx          = ctx;
  quic->cb.quic_ctx         = ctx;

  fd_quic_set_aio_net_tx( quic, quic_tx_aio );
  fd_quic_set_clock_tickcount( quic );
  if( FD_UNLIKELY( !fd_quic_init( quic ) ) ) FD_LOG_ERR(( "fd_quic_init failed" ));

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

  ctx->verify_out_mem = topo->workspaces[ topo->objs[ verify_out->dcache_obj_id ].wksp_id ].wksp;

  ctx->quic = quic;

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
#define STEM_LAZY  ((long)10e6) /* 10ms */

#define STEM_CALLBACK_CONTEXT_TYPE  fd_quic_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_quic_ctx_t)

#define STEM_CALLBACK_DURING_HOUSEKEEPING during_housekeeping
#define STEM_CALLBACK_METRICS_WRITE       metrics_write
#define STEM_CALLBACK_BEFORE_CREDIT       before_credit
#define STEM_CALLBACK_BEFORE_FRAG         before_frag
#define STEM_CALLBACK_DURING_FRAG         during_frag
#define STEM_CALLBACK_AFTER_FRAG          after_frag

#include "../stem/fd_stem.c"

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
