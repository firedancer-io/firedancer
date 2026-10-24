/* fuzz_votor_quic is a stateful fuzz target for the votor tile's QUIC
   receive path.

   The input is one selector byte (which ranked voter the conn belongs
   to) followed by the raw contents of a UDP datagram (in encrypted
   form).  A custom mutator temporarily removes the decryption before
   calling the generic libFuzzer mutator, as in fuzz_quic_wire, so mutated
   inputs reach the frame handlers instead of failing decryption.

   The goal is to cover the whole votor QUIC receive path from raw packets:
   fd_quic_process_packet decrypts and demuxes a packet into DATAGRAM frames,
   each delivered to quic_server_datagram_rx, which decodes the vote or cert,
   checks the sender/rank/ban/shred-version/slot gates, and admits it to the
   consensus pool, emitting cert/event/repair and ban/reconnect follow-ups.
   Because a packet can coalesce many frames, this also drives the
   QUIC_DGRAM_BURST fan-out that sizes the pool's event arrays.  Single
   target, non-differential; the oracle is ASAN/UBSAN plus in-code asserts
   (FD_TEST / FD_LOG_ERR / FD_LOG_CRIT / pool bounds). */

#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#define FD_TILE_TEST 1
#include "fd_votor_tile.c"

#include "../../util/sanitize/fd_fuzz.h"
#include "../../waltz/quic/fd_quic_proto.h"
#include "../../waltz/quic/fd_quic_proto.c"
#include "../../waltz/quic/tests/fd_quic_test_helpers.h"

#include <assert.h>
#include <stdlib.h>

#define FUZZ_VOTER_CNT       (4UL)
#define FUZZ_ROOT_SLOT       (0UL)
#define FUZZ_SLOTS_PER_EPOCH (32UL) /* curr epoch [0,32), next [32,64) */
#define FUZZ_CLIENT_IP4      FD_IP4_ADDR( 127, 0, 0, 2 )
#define FUZZ_SERVER_IP4      FD_IP4_ADDR( 127, 0, 0, 1 )


#define FUZZ_SLOT_MAX  (AG_SLOTS_PER_WINDOW+AG_REWARD_SLOT_DELTA) /* smallest pool ag_pool_footprint accepts */

/* Pool event-queue capacity, for the burst-bound oracle below.  Mirrors
   POOL_EVENT_MAX in ag_pool.c (private there) and must stay in sync.  The
   queue counts past capacity on overflow (only the ring index wraps), so a
   pool_events_cnt above this is a real overflow of the burst sizing. */
#define FUZZ_POOL_EVENT_MAX                                                                    \
  ( FUZZ_SLOT_MAX                                                                              \
  + 3UL*( (FUZZ_SLOT_MAX+AG_SLOTS_PER_WINDOW-1UL)/AG_SLOTS_PER_WINDOW + QUIC_DGRAM_BURST )     \
  +     ( (FUZZ_SLOT_MAX+AG_SLOTS_PER_WINDOW-1UL)/AG_SLOTS_PER_WINDOW + QUIC_DGRAM_BURST )     \
  + 4UL*QUIC_DGRAM_BURST )

/* Reused across inputs; heap-allocated once in LLVMFuzzerInitialize at the
   tile's production footprints so burst admission matches prod. */
static void *              quic_mem;
static void *              pool_mem;
static void *              peers_mem;
static void *              reconn_prq_mem;
static ag_epoch_info_t     epoch_info_mem[2]; /* curr, next */
static fd_votor_tile_t     g_ctx[1];
static fd_quic_t *         g_quic;
static long                g_clock = 1000L;

/* votor_out sink: the cert SLOT_TOO_NEW branch publishes a repair frag. */
static uchar               votor_out_mem   [ 1UL<<16 ] __attribute__((aligned(FD_CHUNK_ALIGN)));
static uchar               votor_mcache_mem[ FD_MCACHE_FOOTPRINT( 128UL, 0UL ) ] __attribute__((aligned(FD_MCACHE_ALIGN)));
static fd_frag_meta_t *    votor_mcache;
static void *              votor_mem;   /* ag_votor_t backing (built once) */

/* Dummy BLS signer for ag_votor_init.  The receive path never signs (it only
   calls ag_votor_set_catchup_vote_slot), so this is only here to satisfy the
   init signature. */
static void
fuzz_sign_vote( void *         ctx,
                fd_bls_sig_t * sig,
                uchar const *  public_key,
                uchar const *  payload,
                ulong          payload_sz ) {
  (void)ctx; (void)public_key; (void)payload; (void)payload_sz;
  memset( sig, 0, sizeof(fd_bls_sig_t) );
}

/* sink- votor's QUIC server will try to send ACKs - drop them. */
static int
fuzz_aio_drop( void *                    ctx,
               fd_aio_pkt_info_t const * batch,
               ulong                     batch_cnt,
               ulong *                   opt_batch_idx,
               int                       flush ) {
  (void)ctx; (void)batch; (void)batch_cnt; (void)opt_batch_idx; (void)flush;
  return FD_AIO_SUCCESS;
}

/* Zero-key crypto glue from fuzz_quic_wire.c.  Lets a seed be written as a
   plaintext packet (marked by an all-zero GCM tag): we re-encrypt it under
   all-zero keys so fd_quic decrypts it instead of dropping it. */

#if !FD_QUIC_DISABLE_CRYPTO

static fd_quic_crypto_keys_t const keys[1] = {{
  .pkt_key    = {0},
  .iv         = {0},
  .hp_key     = {0},
}};

static ulong
guess_packet_size( uchar const * data,
                   ulong         size,
                   ulong *       pn_off ) {
  uchar const * cur_ptr = data;
  ulong         cur_sz  = size;
  ulong pkt_num_pnoff = 0UL;
  ulong total_len     = size;
  if( FD_UNLIKELY( size < 1 ) ) return FD_QUIC_PARSE_FAIL;
  uchar hdr_form = fd_quic_h0_hdr_form( *cur_ptr );
  ulong rc;
  if( hdr_form == 1 ) {  /* long header */
    uchar long_packet_type = fd_quic_h0_long_packet_type( *cur_ptr );
    switch( long_packet_type ) {
    case FD_QUIC_PKT_TYPE_INITIAL: {
      fd_quic_initial_t initial[1];
      rc = fd_quic_decode_initial( initial, data, size );
      if( rc == FD_QUIC_PARSE_FAIL ) return 0UL;
      pkt_num_pnoff = initial->pkt_num_pnoff;
      total_len     = initial->pkt_num_pnoff + initial->len;
      break;
    }
    case FD_QUIC_PKT_TYPE_HANDSHAKE: {
      fd_quic_handshake_t handshake[1];
      rc = fd_quic_decode_handshake( handshake, data, size );
      if( rc == FD_QUIC_PARSE_FAIL ) return 0UL;
      pkt_num_pnoff = handshake->pkt_num_pnoff;
      total_len     = handshake->pkt_num_pnoff + handshake->len;
      break;
    }
    case FD_QUIC_PKT_TYPE_RETRY:    return 0UL;
    case FD_QUIC_PKT_TYPE_ZERO_RTT: return 0UL;
    default:                        __builtin_unreachable();
    }
  } else {  /* short header */
    fd_quic_one_rtt_t one_rtt[1];
    one_rtt->dst_conn_id_len = 8;
    rc = fd_quic_decode_one_rtt( one_rtt, cur_ptr, cur_sz );
    if( rc == FD_QUIC_PARSE_FAIL ) return 0UL;
    cur_ptr += rc; cur_sz -= rc;
    pkt_num_pnoff = one_rtt->pkt_num_pnoff;
  }
  *pn_off = pkt_num_pnoff;
  return total_len;
}

static ulong
decrypt_packet( uchar * const data,
                ulong   const size ) {
  ulong pkt_num_pnoff = 0UL;
  ulong total_len = guess_packet_size( data, size, &pkt_num_pnoff );
  if( !total_len ) return 0UL;
  if( FD_UNLIKELY( total_len > size ) ) return 0UL;
  int decrypt_res = fd_quic_crypto_decrypt_hdr( data, total_len, pkt_num_pnoff, keys );
  if( decrypt_res != FD_QUIC_SUCCESS ) return 0UL;
  uint  pkt_number_sz = fd_quic_h0_pkt_num_len( data[0] ) + 1u;
  ulong pkt_number    = fd_quic_pktnum_decode( data+pkt_num_pnoff, pkt_number_sz );
  decrypt_res = fd_quic_crypto_decrypt( data, total_len, pkt_num_pnoff, pkt_number, keys );
  if( decrypt_res != FD_QUIC_SUCCESS ) return 0UL;
  return total_len;
}

static int
decrypt_payload( uchar * data,
                 ulong   size ) {
  if( size < 16 ) return 0;
  uint mask=0U;
  for( ulong j=0UL; j<15UL; j++ ) mask |= data[size-16+j];
  mask |= data[size-1] & ~7U;
  if( !mask ) return 1;
  uchar * cur_ptr = data;
  ulong   cur_sz  = size;
  do {
    ulong sz = decrypt_packet( cur_ptr, cur_sz );
    if( !sz ) return 0;
    assert( sz <= cur_sz );
    cur_ptr += sz;  cur_sz -= sz;
  } while( cur_sz );
  return 1;
}

static ulong
encrypt_packet( uchar * const data,
                ulong   const size ) {
  uchar out[ FD_QUIC_MTU ];
  ulong pkt_num_pnoff = 0UL;
  ulong total_len = guess_packet_size( data, size, &pkt_num_pnoff );
  if( ( total_len < FD_QUIC_CRYPTO_TAG_SZ ) |
      ( total_len > size                  ) |
      ( total_len > sizeof(out)           ) )
    return size;
  uchar first = data[0];
  ulong pkt_number_sz = ( first & 0x03u ) + 1;
  ulong         out_sz = total_len;
  uchar const * hdr    = data;
  ulong         hdr_sz = pkt_num_pnoff + pkt_number_sz;
  if( ( out_sz          < hdr_sz ) |
      ( out_sz - hdr_sz < FD_QUIC_CRYPTO_TAG_SZ ) |
      ( pkt_num_pnoff + 4UL + FD_QUIC_HP_SAMPLE_SZ > out_sz ) )
    return size;
  ulong pkt_number = 0UL;
  for( ulong j = 0UL; j < pkt_number_sz; ++j )
    pkt_number = ( pkt_number << 8UL ) + (ulong)( hdr[pkt_num_pnoff + j] );
  uchar const * pay    = hdr + hdr_sz;
  ulong         pay_sz = out_sz - hdr_sz - FD_QUIC_CRYPTO_TAG_SZ;
  int encrypt_res = fd_quic_crypto_encrypt( out, &out_sz, hdr, hdr_sz, pay, pay_sz, keys, keys, pkt_number );
  if( encrypt_res != FD_QUIC_SUCCESS ) return size;
  assert( out_sz == total_len );
  fd_memcpy( data, out, out_sz );
  return out_sz;
}

static void
encrypt_payload( uchar * data,
                 ulong   size ) {
  uchar * cur_ptr = data;
  ulong   cur_sz  = size;
  while( cur_sz ) {
    ulong sz = encrypt_packet( cur_ptr, cur_sz );
    assert( sz );
    assert( sz <= cur_sz );
    cur_ptr += sz;  cur_sz -= sz;
  }
}

/* data[0] is the sender selector, the QUIC packet starts at data+1. */
ulong
LLVMFuzzerCustomMutator( uchar * data,
                         ulong   data_sz,
                         ulong   max_sz,
                         uint    seed ) {
  int ok = data_sz>1UL && decrypt_payload( data+1, data_sz-1UL );
  data_sz = LLVMFuzzerMutate( data, data_sz, max_sz );
  if( ok && data_sz>1UL ) encrypt_payload( data+1, data_sz-1UL );
  (void)seed;
  return data_sz;
}

#endif /* !FD_QUIC_DISABLE_CRYPTO */

/* Build FUZZ_VOTER_CNT voters with real BLS keys so rank_voters keeps
   them (it drops voters whose compressed BLS key fails to deserialize). */
static void
fuzz_build_stakes( fd_vote_stake_weight_t * out,
                   ulong                    cnt ) {
  for( ulong i=0UL; i<cnt; i++ ) {
    memset( &out[i], 0, sizeof(fd_vote_stake_weight_t) );
    out[i].stake            = 1000UL + i;
    out[i].id_key.uc  [ 0 ] = (uchar)( i + 1UL );
    out[i].vote_key.uc[ 0 ] = (uchar)( i + 0x80UL );
    fd_bls_sec_t sec; memset( &sec, (int)( i*7UL + 1UL ), FD_BLS_SEC_SZ );
    fd_bls_pub_t pub; fd_bls_sec_to_pub( &sec, &pub );
    blst_p1_affine_compress( out[i].bls_key, &pub );
  }
}

int
LLVMFuzzerInitialize( int *    pargc,
                      char *** pargv ) {
  putenv( "FD_LOG_BACKTRACE=0" );
  setenv( "FD_LOG_PATH", "", 0 );
  fd_boot( pargc, pargv );
  atexit( fd_halt );
# ifndef FD_DEBUG_MODE
  fd_log_level_core_set( 3 ); /* abort on ERR and above (warnings, e.g. ban_peer, are expected) */
# endif
  ulong fp = fd_quic_footprint( &quic_server_limits );
  FD_TEST( fp );
  quic_mem = aligned_alloc( FD_QUIC_ALIGN, fd_ulong_align_up( fp, FD_QUIC_ALIGN ) );
  fp = ag_pool_footprint( FUZZ_SLOT_MAX, QUIC_DGRAM_BURST );
  FD_TEST( fp );
  pool_mem = aligned_alloc( ag_pool_align(), fd_ulong_align_up( fp, ag_pool_align() ) );
  votor_mem = aligned_alloc( ag_votor_align(), fd_ulong_align_up( ag_votor_footprint( FUZZ_SLOT_MAX ), ag_votor_align() ) );
  peers_mem = aligned_alloc( peers_align(), fd_ulong_align_up( peers_footprint( PEERS_LG_SLOT_CNT ), peers_align() ) );
  reconn_prq_mem = aligned_alloc( reconn_prq_align(), fd_ulong_align_up( reconn_prq_footprint( RECONN_MAX ), reconn_prq_align() ) );
  FD_TEST( quic_mem && pool_mem && votor_mem && peers_mem && reconn_prq_mem );
  votor_mcache = fd_mcache_join( fd_mcache_new( votor_mcache_mem, 128UL, 0UL, 0UL ) );
  FD_TEST( votor_mcache );

  /* Build the QUIC server ONCE; rebuilding its large footprint per input
     dominated runtime.  Per input we only reset the pool/peers/ctx and
     create/free one conn on this persistent instance. */
  static fd_aio_t aio;
  g_quic = fd_quic_join( fd_quic_new( quic_mem, &quic_server_limits ) );
  FD_TEST( g_quic );
  fd_quic_set_aio_net_tx( g_quic, fd_aio_join( fd_aio_new( &aio, NULL, fuzz_aio_drop ) ) );

  g_quic->config.role                       = FD_QUIC_ROLE_SERVER;
  g_quic->config.retry                      = 0;
  g_quic->config.idle_timeout               = 5L*1000L*1000L*1000L;
  g_quic->config.ack_delay                  = 2L*1000L*1000L;
  g_quic->config.req_client_cert            = 1;
  g_quic->config.alpn[ 0 ]                  = 0x0c;
  memcpy( g_quic->config.alpn+1, "alpenglow-v1", 12UL );
  g_quic->config.alpn_sz                    = 13UL;
  g_quic->config.initial_rx_max_stream_data = 0UL;
  g_quic->config.max_datagram_frame_size    = 1280UL;

  g_quic->cb.quic_ctx    = g_ctx;
  g_quic->cb.conn_new    = quic_server_conn_new;
  g_quic->cb.conn_final  = quic_server_conn_final;
  g_quic->cb.datagram_rx = quic_server_datagram_rx;

  /* A TLS signer so an Initial with a valid ClientHello can run the server
     handshake to CertificateVerify without a NULL sign_fn call.  This also
     overwrites identity_public_key with a random (non-validator) key. */
  static fd_rng_t                rng[1];
  static fd_tls_test_sign_ctx_t  test_signer[1];
  fd_tls_test_sign_ctx( test_signer, fd_rng_join( fd_rng_new( rng, 0U, 0UL ) ) );
  fd_quic_config_test_signer( g_quic, test_signer );

  FD_TEST( fd_quic_init( g_quic ) );
  return 0;
}

/* Drain pool events as after_credit does, so ParentReady advances the
   vote lookahead bound. */
static void
fuzz_drain( fd_votor_tile_t * ctx ) {
  ag_pool_event_t ev;
  while( ag_pool_poll_pool_event( ctx->pool, &ev ) ) {
    if( ev.kind==AG_POOL_EVENT_PARENT_READY )
      ctx->highest_parent_ready_slot = fd_ulong_max( ctx->highest_parent_ready_slot, ev.parent_ready.slot );
  }
  ag_block_id_t repair;
  while( ag_pool_poll_repair_event( ctx->pool, &repair ) ) {}
}

/* (Re)build the tile ctx and a fresh pool/peers for one input, leaving an
   established server conn whose context is a ranked voter's identity (so
   the receive path's peers_query resolves a sender). */
static void
fuzz_ctx_reset( uint sender_sel ) {
  fd_votor_tile_t * ctx = g_ctx;
  memset( ctx, 0, sizeof(fd_votor_tile_t) );
  fd_clock_tile_init( ctx->clock );

  /* Our identity is not one of the voters, so votes are never self-votes. */
  memset( ctx->id_key.uc, 0xEE, sizeof(fd_pubkey_t) );

  /* Rank the same voters into curr and next epoch.  The tile only sets
     init once the next epoch is known, so both are always present. */
  fd_vote_stake_weight_t stakes[ FUZZ_VOTER_CNT ];
  fuzz_build_stakes( stakes, FUZZ_VOTER_CNT );
  ctx->curr_epoch_info = rank_voters( &epoch_info_mem[0], stakes, FUZZ_VOTER_CNT, NULL, NULL );
  ctx->next_epoch_info = rank_voters( &epoch_info_mem[1], stakes, FUZZ_VOTER_CNT, ctx->curr_epoch_info, NULL );
  ctx->curr_epoch_slot = FUZZ_ROOT_SLOT;
  ctx->next_epoch_slot = FUZZ_ROOT_SLOT+FUZZ_SLOTS_PER_EPOCH;
  ctx->slots_per_epoch = FUZZ_SLOTS_PER_EPOCH;
  FD_TEST( ctx->curr_epoch_info->validator_cnt );

  /* Peers: one per ranked voter, as handle_epoch inserts them. */
  ctx->peers = peers_join( peers_new( peers_mem, PEERS_LG_SLOT_CNT, 42UL ) );
  FD_TEST( ctx->peers );
  for( ulong rank=0UL; rank<ctx->curr_epoch_info->validator_cnt; rank++ ) {
    fd_pubkey_t id; memcpy( id.uc, ctx->curr_epoch_info->validators[ rank ].id_key, sizeof(fd_pubkey_t) );
    peer_t * peer = peers_insert( ctx->peers, id );
    peer->prev_rank      = USHORT_MAX;
    peer->curr_rank      = (ushort)rank;
    peer->next_rank      = (ushort)rank;
    peer->tx_conn        = NULL;
    peer->rx_conn        = NULL;
    peer->ban_ts         = 0L;
    peer->conn_ts        = 0L;
    peer->conn_backoff   = 0L;
    peer->reconn_pending = 0;
  }

  /* Pool rooted at FUZZ_ROOT_SLOT, current epoch advanced. */
  ctx->pool = ag_pool_join( ag_pool_new( pool_mem, FUZZ_SLOT_MAX, QUIC_DGRAM_BURST, 42UL ) );
  FD_TEST( ctx->pool );
  ag_pool_from_genesis( ctx->pool, &(ag_block_id_t){ .slot = FUZZ_ROOT_SLOT } );
  ag_pool_advance_epoch( ctx->pool, ctx->curr_epoch_info, USHORT_MAX, ctx->curr_epoch_slot );
  ag_pool_advance_epoch( ctx->pool, ctx->next_epoch_info, USHORT_MAX, ctx->next_epoch_slot );
  fuzz_drain( ctx ); /* genesis ParentReady sets highest_parent_ready_slot */

  /* reconn_prq: ban_peer -> reconn_prq_insert needs it (a bad-rank vote bans
     the sender and schedules a reconnect). */
  ctx->reconn_prq = reconn_prq_join( reconn_prq_new( reconn_prq_mem, RECONN_MAX ) );
  FD_TEST( ctx->reconn_prq );

  ctx->shred_version = 42;
  ctx->ns_per_slot   = 400L*1000L*1000L;
  ctx->slot_max      = FUZZ_SLOT_MAX; /* cert SLOT_TOO_NEW branch looks back slot_max */
  ctx->init          = 1;
  for( ulong i=0UL; i<AG_SLOTS_PER_WINDOW; i++ ) ctx->reward_certs[ i ].slot = ULONG_MAX; /* as in unprivileged_init */

  /* ag_votor: the cert catchup branch of the receive path calls
     ag_votor_set_catchup_vote_slot on it. */
  ctx->votor = ag_votor_join( ag_votor_new( votor_mem, FUZZ_SLOT_MAX, 42UL ) );
  FD_TEST( ctx->votor );
  ag_votor_init( ctx->votor, &(ag_block_id_t){ .slot = FUZZ_ROOT_SLOT }, g_clock, ctx->ns_per_slot, ctx->shred_version, fuzz_sign_vote, ctx );

  static ulong             seqs[1], depths[1] = { 128UL }, cr_avail[1] = { ULONG_MAX }, min_cr_avail[1] = { ULONG_MAX };
  static int               reliable[1];
  static fd_frag_meta_t *  mcaches[1];
  static fd_stem_context_t stem[1];
  mcaches[0] = votor_mcache;
  *stem = (fd_stem_context_t){ .mcaches = mcaches, .seqs = seqs, .depths = depths, .cr_avail = cr_avail, .min_cr_avail = min_cr_avail, .out_reliable = reliable };
  ctx->stem             = stem;
  ctx->votor_out_mem    = votor_out_mem;
  ctx->votor_out_chunk0 = 0UL;
  ctx->votor_out_chunk  = 0UL;
  /* votor_out_mem is a plain buffer, not a dcache, so compute the watermark
     from its size instead of fd_dcache_compact_wmark, which would read dcache
     metadata before the buffer.  Matches REWARD_OUT_WMARK in test_votor_tile.c. */
  ctx->votor_out_wmark  = ( sizeof(votor_out_mem) - fd_ulong_align_up( sizeof(fd_votor_msg_t), 2UL*FD_CHUNK_SZ ) ) >> FD_CHUNK_LG_SZ;

  /* Reuse the persistent QUIC server (built once in init).  Its callback
     ctx was wired to g_ctx, which is this same ctx. */
  ctx->quic_server = g_quic;
  fd_quic_state_t * state = fd_quic_get_state( g_quic );
  state->now = g_clock;

  /* Creaete an established server conn. */
  fd_quic_conn_id_t peer_conn_id = { .sz=8 };
  fd_quic_conn_t * conn =
    fd_quic_conn_create( ctx->quic_server,
                         ULONG_MAX, &peer_conn_id,
                         FUZZ_CLIENT_IP4, 0U,
                         FUZZ_SERVER_IP4, 0U,
                         1 /* server */ );
  FD_TEST( conn );
  fd_quic_svc_timers_schedule( state->svc_timers, conn, g_clock );
  conn->state              = FD_QUIC_CONN_STATE_ACTIVE;
  conn->handshake_complete = 1;   /* fd_quic_handle_v1_one_rtt rejects 1-RTT without this */
  conn->keys_avail         = 0xff;

  /* Run the tile's real conn_new with voter sender_sel as the authenticated
     client key, so conn context, peer->rx_conn and server_peer_id_keys match
     a real handshake, then release the handshake as fd_quic does. */
  ulong rank = (ulong)sender_sel % ctx->curr_epoch_info->validator_cnt;
  FD_TEST( fd_quic_tls_hs_pool_free( state->hs_pool ) ); /* exhaustion would NULL-deref below */
  fd_quic_tls_hs_t * tls_hs = fd_quic_tls_hs_new(
      fd_quic_tls_hs_pool_ele_acquire( state->hs_pool ),
      state->tls, (void *)conn, 1 /*is_server*/, &state->transport_params, g_clock );
  memcpy( tls_hs->hs.srv.client_pubkey, ctx->curr_epoch_info->validators[ rank ].id_key, sizeof(fd_pubkey_t) );
  conn->tls_hs = tls_hs;
  fd_quic_cb_conn_new( g_quic, conn );
  fd_quic_tls_hs_delete( tls_hs );
  fd_quic_tls_hs_pool_ele_release( state->hs_pool, tls_hs );
  conn->tls_hs = NULL;
  FD_TEST( fd_quic_conn_get_context( conn ) );
}

/* Per-input teardown of the pool/peers.  All conns were already freed by
   the idle-timeout drain in LLVMFuzzerTestOneInput; g_quic survives. */
static void
fuzz_ctx_delete( void ) {
  fd_votor_tile_t * ctx = g_ctx;
  ag_pool_delete( ag_pool_leave( ctx->pool ) );
  peers_delete( peers_leave( ctx->peers ) );
  reconn_prq_delete( reconn_prq_leave( ctx->reconn_prq ) );
}

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         size ) {
  /* data[0] selects the sender identity; the rest is the UDP payload.
     The tile hands fd_quic net_buf[FD_NET_MTU] minus the eth header, so
     that bounds the IP4+UDP packet. */
  ulong hdr_sz = sizeof(fd_ip4_hdr_t)+sizeof(fd_udp_hdr_t);
  if( FD_UNLIKELY( !size || hdr_sz+size-1UL>FD_NET_MTU-sizeof(fd_eth_hdr_t) ) ) return -1;
  uchar const * udp_payload    = data+1;
  ulong         udp_payload_sz = size-1UL;

  fuzz_ctx_reset( data[0] );

  uchar pkt[ FD_NET_MTU ];
  fd_ip4_hdr_t ip4 = {
    .verihl      = FD_IP4_VERIHL(4,5),
    .protocol    = FD_IP4_HDR_PROTOCOL_UDP,
    .net_tot_len = (ushort)( hdr_sz+udp_payload_sz ),
    .saddr       = FUZZ_CLIENT_IP4,
    .daddr       = FUZZ_SERVER_IP4,
  };
  fd_udp_hdr_t udp = { .net_sport=8000, .net_dport=8001, .net_len=(ushort)( sizeof(fd_udp_hdr_t)+udp_payload_sz ) };
  uchar * cur = pkt;
  fd_quic_encode_ip4( cur, hdr_sz, &ip4 ); cur += sizeof(fd_ip4_hdr_t);
  fd_quic_encode_udp( cur, hdr_sz-sizeof(fd_ip4_hdr_t), &udp ); cur += sizeof(fd_udp_hdr_t);
  fd_memcpy( cur, udp_payload, udp_payload_sz );
#if !FD_QUIC_DISABLE_CRYPTO
  /* If the QUIC payload is authored as plaintext (all-zero GCM tag tail),
     re-encrypt it with the zero keys so fd_quic's real crypto decrypts it.
     decrypt_payload unprotects headers in place before authenticating, so
     convert on a scratch copy and only overwrite the packet on success;
     otherwise a normally-encrypted packet (which fails zero-key auth) would
     reach fd_quic half-modified instead of as the original. */
  uchar conv[ FD_NET_MTU ];
  fd_memcpy( conv, cur, udp_payload_sz );
  if( decrypt_payload( conv, udp_payload_sz ) ) {
    encrypt_payload( conv, udp_payload_sz );
    fd_memcpy( cur, conv, udp_payload_sz );
  }
#endif
  fd_quic_process_packet( g_quic, pkt, hdr_sz+udp_payload_sz, g_clock );
  fd_quic_service( g_quic, g_clock ); /* e.g. frees a conn closed by a ban */

  /* Burst-bound oracle: this packet's DATAGRAM frames each drive an ag_pool
     add, and nothing drains the event queue mid-packet, so its depth is the
     whole QUIC_DGRAM_BURST fan-out.  Overflow wraps silently, so assert it. */
  FD_TEST( ag_pool_metrics( g_ctx->pool ).pool_events_cnt<=FUZZ_POOL_EVENT_MAX );

  /* A fuzzed Initial can open conns beyond the fabricated one.  Advance the
     clock past the idle timeout and drain the service queue so fd_quic frees
     EVERY conn (and its handshake); otherwise leaked conns/handshakes would
     accumulate across inputs and exhaust the pools (the clock is otherwise
     fixed, so nothing times out).  This also frees the fabricated conn. */
  g_clock += 2L*g_quic->config.idle_timeout;
  fd_quic_state_t * state = fd_quic_get_state( g_quic );
  while( fd_quic_svc_timers_next( state->svc_timers, g_clock, 0 /* peek */ ).conn ) {
    fd_quic_service( g_quic, g_clock );
  }

  fuzz_ctx_delete();
  return 0;
}
