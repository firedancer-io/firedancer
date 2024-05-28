#include "fd_quic_sandbox.h"
#include "../fd_quic_private.h"

/* fd_quic_sandbox_capture_pkt captures a single outgoing packet sent by
   fd_quic. */

static void
fd_quic_sandbox_capture_pkt( fd_quic_sandbox_t *       sandbox,
                             fd_aio_pkt_info_t const * pkt ) {

  ulong            seq    = sandbox->pkt_seq_w;
  fd_frag_meta_t * mcache = sandbox->pkt_mcache;
  void *           dcache = sandbox->pkt_dcache;
  ulong            mtu    = sandbox->pkt_mtu;
  ulong            chunk  = sandbox->pkt_chunk;
  ulong            chunk0 = fd_dcache_compact_chunk0( sandbox, dcache );
  ulong            wmark  = fd_dcache_compact_wmark ( sandbox, dcache, mtu );
  ulong            depth  = fd_mcache_depth( mcache );
  ulong            sz     = pkt->buf_sz;
  uchar *          data   = fd_chunk_to_laddr( sandbox, chunk );
  ulong            ctl    = fd_frag_meta_ctl( /* orig */ 0, /* som */ 1, /* eom */ 1, /* err */ 0 );
  ulong            ts     = sandbox->wallclock;

  fd_memcpy( data, pkt->buf, sz );
  fd_mcache_publish( mcache, depth, seq, 0UL, chunk, sz, ctl, ts, ts );

  sandbox->pkt_seq_w = fd_seq_inc( seq, 1UL );
  sandbox->pkt_chunk = fd_dcache_compact_next( chunk, pkt->buf_sz, chunk0, wmark );
}

/* fd_quic_sandbox_aio_send implements fd_aio_send_func_t.  Called by
   the sandbox fd_quic to capture response packets into the sandbox
   capture ring. */

static int
fd_quic_sandbox_aio_send( void *                    ctx,
                          fd_aio_pkt_info_t const * batch,
                          ulong                     batch_cnt,
                          ulong *                   opt_batch_idx,
                          int                       flush ) {

  fd_quic_sandbox_t * sandbox = (fd_quic_sandbox_t *)ctx;

  for( ulong j=0UL; j<batch_cnt; j++ ) {
    fd_quic_sandbox_capture_pkt( sandbox, batch + j );
  }

  ulong _batch_idx[1];
  opt_batch_idx = opt_batch_idx ? opt_batch_idx : _batch_idx;
  *opt_batch_idx = batch_cnt;

  (void)flush;
  return FD_AIO_SUCCESS;
}

fd_frag_meta_t const *
fd_quic_sandbox_next_packet( fd_quic_sandbox_t * sandbox ) {
  fd_frag_meta_t * mcache = sandbox->pkt_mcache;

  ulong depth = fd_mcache_depth( mcache );
  ulong seq   = sandbox->pkt_seq_r;
  ulong mline = fd_mcache_line_idx( seq, depth );

  fd_frag_meta_t * frag = mcache + mline;
  if( FD_UNLIKELY( frag->seq < seq ) ) return NULL;
  if( FD_UNLIKELY( frag->seq > seq ) ) {
    /* Occurs if the fd_quic published 'depth' packets in succession
       without any reads via this function. */
    FD_LOG_WARNING(( "overrun detected, some captured packets were lost" ));
    seq = frag->seq;
  }

  sandbox->pkt_seq_r = fd_seq_inc( seq, 1UL );

  return frag;
}

uchar const fd_quic_sandbox_self_ed25519_keypair[64] =
  { /* private key */
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    /* public key */
    0xdb, 0x99, 0x5f, 0xe2, 0x51, 0x69, 0xd1, 0x41,
    0xca, 0xb9, 0xbb, 0xba, 0x92, 0xba, 0xa0, 0x1f,
    0x9f, 0x2e, 0x1e, 0xce, 0x7d, 0xf4, 0xcb, 0x2a,
    0xc0, 0x51, 0x90, 0xf3, 0x7f, 0xcc, 0x1f, 0x9d };


uchar const fd_quic_sandbox_peer_ed25519_keypair[64] =
  { /* private key */
    0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
    0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
    0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
    0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
    /* public key */
    0x21, 0x52, 0xf8, 0xd1, 0x9b, 0x79, 0x1d, 0x24,
    0x45, 0x32, 0x42, 0xe1, 0x5f, 0x2e, 0xab, 0x6c,
    0xb7, 0xcf, 0xfa, 0x7b, 0x6a, 0x5e, 0xd3, 0x00,
    0x97, 0x96, 0x0e, 0x06, 0x98, 0x81, 0xdb, 0x12 };

uchar const fd_quic_sandbox_aes128_key[16] =
  { 0x43, 0x43, 0x43, 0x43, 0x43, 0x43, 0x43, 0x43,
    0x43, 0x43, 0x43, 0x43, 0x43, 0x43, 0x43, 0x43 };

uchar const fd_quic_sandbox_aes128_iv[12] =
  { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00 };

static ulong
fd_quic_sandbox_now_cb( void * context ) {
  fd_quic_sandbox_t * sandbox = context;
  return sandbox->wallclock;
}

ulong
fd_quic_sandbox_align( void ) {
  return fd_ulong_max( fd_ulong_max( fd_ulong_max( fd_ulong_max(
      alignof(fd_quic_sandbox_t),
      fd_quic_align() ),
      fd_mcache_align() ),
      fd_dcache_align() ),
      FD_CHUNK_ALIGN );
}

ulong
fd_quic_sandbox_footprint( fd_quic_limits_t const * quic_limits,
                           ulong                    pkt_cnt,
                           ulong                    mtu ) {

  ulong root_align = fd_quic_sandbox_align();
  ulong quic_fp    = fd_quic_footprint( quic_limits );
  ulong mcache_fp  = fd_mcache_footprint( pkt_cnt, 0UL );
  ulong dcache_fp  = fd_dcache_footprint( fd_dcache_req_data_sz( mtu, pkt_cnt, 1UL, 1 ), 0UL );

  if( FD_UNLIKELY( !quic_fp   ) ) return 0UL;
  if( FD_UNLIKELY( !mcache_fp ) ) return 0UL;
  if( FD_UNLIKELY( !dcache_fp ) ) return 0UL;

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, root_align,        sizeof(fd_quic_sandbox_t) );
  l = FD_LAYOUT_APPEND( l, fd_quic_align(),   quic_fp                   );
  l = FD_LAYOUT_APPEND( l, fd_mcache_align(), mcache_fp                 );
  l = FD_LAYOUT_APPEND( l, fd_dcache_align(), dcache_fp                 );
  return FD_LAYOUT_FINI( l, root_align );
}

void *
fd_quic_sandbox_new( void *                   mem,
                     fd_quic_limits_t const * quic_limits,
                     ulong                    pkt_cnt,
                     ulong                    mtu ) {

  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_quic_sandbox_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  ulong fp = fd_quic_sandbox_footprint( quic_limits, pkt_cnt, mtu );
  if( FD_UNLIKELY( !fp ) ) {
    FD_LOG_WARNING(( "invalid params" ));
    return NULL;
  }

  ulong root_align     = fd_quic_sandbox_align();
  ulong quic_fp        = fd_quic_footprint( quic_limits );
  ulong mcache_fp      = fd_mcache_footprint( pkt_cnt, 0UL );
  ulong dcache_data_sz = fd_dcache_req_data_sz( mtu, pkt_cnt, 1UL, 1 );
  ulong dcache_fp      = fd_dcache_footprint( dcache_data_sz, 0UL );

  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_quic_sandbox_t * sandbox    = FD_SCRATCH_ALLOC_APPEND( l, root_align,        sizeof(fd_quic_sandbox_t) );
  void *              quic_mem   = FD_SCRATCH_ALLOC_APPEND( l, fd_quic_align(),   quic_fp                   );
  void *              mcache_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_mcache_align(), mcache_fp                 );
  void *              dcache_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_dcache_align(), dcache_fp                 );
  FD_SCRATCH_ALLOC_FINI( l, root_align );

  ulong seq0 = 0UL;  /* the first packet in the capture always has sequence number 0 */

  *sandbox = (fd_quic_sandbox_t) {
    .quic       = fd_quic_join  ( fd_quic_new( quic_mem, quic_limits ) ),
    .pkt_mcache = fd_mcache_join( fd_mcache_new( mcache_mem, pkt_cnt, 0UL, seq0 ) ),
    .pkt_dcache = fd_dcache_join( fd_dcache_new( dcache_mem, dcache_data_sz, 0UL ) ),
    .pkt_seq_r  = seq0,
    .pkt_mtu    = mtu
  };

  FD_COMPILER_MFENCE();
  sandbox->magic = FD_QUIC_SANDBOX_MAGIC;
  FD_COMPILER_MFENCE();

  return sandbox;
}

fd_quic_sandbox_t *
fd_quic_sandbox_join( void * mem ) {

  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  fd_quic_sandbox_t * sandbox = (fd_quic_sandbox_t *)mem;
  if( FD_UNLIKELY( sandbox->magic != FD_QUIC_SANDBOX_MAGIC ) ) {
    FD_LOG_WARNING(( "invalid magic" ));
    return NULL;
  }

  return sandbox;
}

fd_quic_sandbox_t *
fd_quic_sandbox_init( fd_quic_sandbox_t * sandbox,
                      int                 role ) {

  fd_quic_t *        quic     = sandbox->quic;
  fd_quic_config_t * quic_cfg = &quic->config;

  quic_cfg->role                  = role;
  quic_cfg->idle_timeout          = FD_QUIC_SANDBOX_IDLE_TIMEOUT;
  quic_cfg->net.ip_addr           = FD_QUIC_SANDBOX_SELF_IP4;
  quic_cfg->net.listen_udp_port   = FD_QUIC_SANDBOX_SELF_PORT;
  quic_cfg->net.ephem_udp_port.lo = FD_QUIC_SANDBOX_SELF_PORT;
  quic_cfg->net.ephem_udp_port.hi = FD_QUIC_SANDBOX_SELF_PORT + 1;
  memcpy( quic_cfg->identity_public_key, fd_quic_sandbox_self_ed25519_keypair + 32, 32 );

  fd_aio_t aio_tx = {
    .send_func = fd_quic_sandbox_aio_send,
    .ctx       = sandbox
  };
  fd_quic_set_aio_net_tx( quic, &aio_tx );

  quic->cb.now_ctx = sandbox;
  quic->cb.now     = fd_quic_sandbox_now_cb;

  if( FD_UNLIKELY( !fd_quic_init( quic ) ) ) {
    FD_LOG_WARNING(( "fd_quic_init failed" ));
    return NULL;
  }

  sandbox->wallclock = 0UL;
  sandbox->pkt_seq_r = 0UL;
  sandbox->pkt_seq_w = 0UL;
  sandbox->pkt_mcache[0].seq = ULONG_MAX;  /* mark first entry as unpublished */
  sandbox->pkt_chunk = fd_dcache_compact_chunk0( sandbox, sandbox->pkt_dcache );

  return sandbox;
}

void *
fd_quic_sandbox_leave( fd_quic_sandbox_t * sandbox ) {
  return (void *)sandbox;
}

void *
fd_quic_sandbox_delete( void * mem ) {

  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  fd_quic_sandbox_t * sandbox = (fd_quic_sandbox_t *)mem;
  if( FD_UNLIKELY( sandbox->magic != FD_QUIC_SANDBOX_MAGIC ) ) {
    FD_LOG_WARNING(( "invalid magic" ));
    return NULL;
  }

  FD_COMPILER_MFENCE();
  sandbox->magic = 0UL;
  FD_COMPILER_MFENCE();

  fd_quic_delete  ( fd_quic_leave  ( sandbox->quic       ) );
  fd_mcache_delete( fd_mcache_leave( sandbox->pkt_mcache ) );
  fd_dcache_delete( fd_dcache_leave( sandbox->pkt_dcache ) );

  return mem;
}

fd_quic_conn_t *
fd_quic_sandbox_new_conn_established( fd_quic_sandbox_t * sandbox,
                                      fd_rng_t *          rng ) {

  fd_quic_t * quic = sandbox->quic;

  /* fd_quic_t conn IDs are always 8 bytes */
  ulong             our_conn_id_u64 = fd_rng_ulong( rng );
  fd_quic_conn_id_t our_conn_id     = fd_quic_conn_id_new( &our_conn_id_u64, 8UL );

  /* the peer may choose a conn ID size 1 to 16 bytes
     For now, pick 8 bytes too */
  ulong             peer_conn_id_u64 = fd_rng_ulong( rng );
  fd_quic_conn_id_t peer_conn_id     = fd_quic_conn_id_new( &peer_conn_id_u64, 8UL );

  fd_quic_conn_t * conn = fd_quic_conn_create(
      /* quic         */ quic,
      /* our_conn_id  */ &our_conn_id,
      /* peer_conn_id */ &peer_conn_id,
      /* dst_ip_addr  */ FD_QUIC_SANDBOX_PEER_IP4,
      /* dst_udp_addr */ FD_QUIC_SANDBOX_PEER_PORT,
      /* server       */ quic->config.role == FD_QUIC_ROLE_SERVER,
      /* version      */ 1 );
  if( FD_UNLIKELY( !conn ) ) {
    FD_LOG_WARNING(( "fd_quic_conn_create failed" ));
    return NULL;
  }

  conn->state       = FD_QUIC_CONN_STATE_ACTIVE;
  conn->established = 1;
  conn->in_service  = 1;

  /* Mock a completed handshake */
  conn->handshake_complete = 1;
  conn->hs_data_empty      = 1;
  conn->peer_enc_level     = fd_quic_enc_level_appdata_id;

  conn->idle_timeout  = FD_QUIC_SANDBOX_IDLE_TIMEOUT;
  conn->last_activity = sandbox->wallclock;

  /* Reset flow control limits */
  conn->tx_max_data      = 0UL;
  conn->tx_tot_data      = 0UL;
  conn->rx_max_data      = 0UL;
  conn->rx_tot_data      = 0UL;
  conn->rx_max_data_ackd = 0UL;
  conn->tx_initial_max_stream_data_uni         = 0UL;
  conn->tx_initial_max_stream_data_bidi_local  = 0UL;
  conn->tx_initial_max_stream_data_bidi_remote = 0UL;
  conn->rx_initial_max_stream_data_uni         = 0UL;
  conn->rx_initial_max_stream_data_bidi_local  = 0UL;
  conn->rx_initial_max_stream_data_bidi_remote = 0UL;

  /* TODO set a realistic packet number */

  return conn;
}

void
fd_quic_sandbox_send_frame( fd_quic_sandbox_t * sandbox,
                            fd_quic_conn_t *    conn,
                            fd_quic_pkt_t *     pkt_meta,
                            uchar const *       frame_ptr,
                            ulong               frame_sz ) {

  /* TODO consider crafting a real app packet instead of bypassing
          packet processing checks */

  fd_quic_t * quic = sandbox->quic;

  /* Scratch space to deserialize frame data into */
  fd_quic_frame_u frame[1];
  ulong rc = fd_quic_handle_v1_frame( quic, conn, pkt_meta, frame_ptr, frame_sz, frame );
  if( FD_UNLIKELY( rc==FD_QUIC_PARSE_FAIL ) ) return;
  if( FD_UNLIKELY( rc==0UL || rc>frame_sz ) ) {
    fd_quic_conn_error( conn, FD_QUIC_CONN_REASON_PROTOCOL_VIOLATION, __LINE__ );
    return;
  }

}

void
fd_quic_sandbox_send_lone_frame( fd_quic_sandbox_t * sandbox,
                                 fd_quic_conn_t *    conn,
                                 uchar const *       frame,
                                 ulong               frame_sz ) {

  FD_TEST( frame_sz <= sandbox->pkt_mtu );

  ulong pkt_num = conn->exp_pkt_number[2]++;

  ulong quic_pkt_sz = frame_sz;  /* TODO mock some QUIC packetization overhead */

  fd_quic_pkt_t pkt_meta = {
    .ip4 = {{
      .verihl       = FD_IP4_VERIHL(4,5),
      .net_tot_len  = (ushort)( 20 + 8 + quic_pkt_sz ),
      .net_frag_off = 0x4000u, /* don't fragment */
      .ttl          = 64,
      .protocol     = FD_IP4_HDR_PROTOCOL_UDP,
    }},
    .udp = {{
      .net_sport = FD_QUIC_SANDBOX_PEER_PORT,
      .net_dport = FD_QUIC_SANDBOX_SELF_PORT,
      .net_len   = (ushort)( 8 + quic_pkt_sz ),
    }},
    .pkt_number = pkt_num,
    .rcv_time   = sandbox->wallclock,
    .enc_level  = fd_quic_enc_level_appdata_id,
  };

  fd_quic_sandbox_send_frame( sandbox, conn, &pkt_meta, frame, frame_sz );
}
