#define FD_TILE_TEST 1
/* test_votor_tile: the identity keyswitch and the failover links in the
   votor tile.  The tile is included whole so the static handlers can be
   driven directly on a ctx built by hand, the way test_tower_tile does
   it. */

#include "fd_votor_tile.c"
#include "../../choreo/votor/test_ag_cert_builder.h"
#include "../../ballet/ed25519/fd_ed25519.h"

#define TEST_SLOT_MAX      (16UL)
#define TEST_SHRED_VERSION ((ushort)0x5a5a)

/* Long enough for every timeout of a leader window to come due. */
#define TEST_NS_PER_SLOT       (400000000L)
#define TEST_WINDOW_ELAPSED_NS (AG_DELTA_TIMEOUT_NS + (long)(AG_SLOTS_PER_WINDOW+1UL)*TEST_NS_PER_SLOT)

#define TEST_CLIENT_PORT ((ushort)9001)
#define TEST_SERVER_PORT ((ushort)9002)

/* The pool and votor at 2048 live slots take gigabytes, 16 is plenty
   for a switch, and the QUIC objects follow the tile's own limits.
   main checks the footprints before anything is formatted. */

#define POOL_MEM_SZ          (192UL<<20)
#define VOTOR_MEM_SZ         (  1UL<<20)
#define QUIC_CLIENT_MEM_SZ   ( 32UL<<20)
#define QUIC_SERVER_MEM_SZ   ( 64UL<<20)
#define MLEADERS_MEM_SZ      ( 16UL<<20)
#define PEERS_MEM_SZ         (  1UL<<20)
#define CONTACT_INFOS_MEM_SZ (  4UL<<20)

static fd_votor_tile_t ctx_mem[ 1 ];
static fd_keyswitch_t  ks_mem [ 1 ];
static uchar pool_mem         [ POOL_MEM_SZ          ] __attribute__((aligned(128)));
static uchar votor_mem        [ VOTOR_MEM_SZ         ] __attribute__((aligned(128)));
static uchar quic_client_mem  [ QUIC_CLIENT_MEM_SZ   ] __attribute__((aligned(4096)));
static uchar quic_server_mem  [ QUIC_SERVER_MEM_SZ   ] __attribute__((aligned(4096)));
static uchar mleaders_mem     [ MLEADERS_MEM_SZ      ] __attribute__((aligned(128)));
static uchar peers_mem        [ PEERS_MEM_SZ         ] __attribute__((aligned(128)));
static uchar contact_infos_mem[ CONTACT_INFOS_MEM_SZ ] __attribute__((aligned(128)));

/* Outgoing packets and messages land in these instead of a dcache.
   Nothing reads them back, the chunks only have to stay in bounds. */

#define NET_OUT_MEM_SZ   (64UL*FD_NET_MTU)
#define VOTOR_OUT_MEM_SZ (64UL*sizeof(fd_votor_msg_t))

static uchar net_out_mem  [ NET_OUT_MEM_SZ   ] __attribute__((aligned(FD_CHUNK_SZ)));
static uchar votor_out_mem[ VOTOR_OUT_MEM_SZ ] __attribute__((aligned(FD_CHUNK_SZ)));

/* The failover links.  Frames on the hist and failov outs are read back
   through the mcache line stem wrote, and the replay and failov in-links
   hold one frag at chunk 0 that is handed to the frag callbacks by
   hand. */

#define HIST_OUT_MEM_SZ   (16UL*sizeof(fd_votor_hist_msg_t))
#define FAILOV_OUT_MEM_SZ (16UL*FD_CHUNK_SZ)
#define REPLAY_IN_MEM_SZ  ( 2UL*sizeof(fd_replay_message_t))
#define FAILOV_IN_MEM_SZ  ( 2UL*AG_HIST_SER_MAX)

static uchar hist_out_mem  [ HIST_OUT_MEM_SZ   ] __attribute__((aligned(FD_CHUNK_SZ)));
static uchar failov_out_mem[ FAILOV_OUT_MEM_SZ ] __attribute__((aligned(FD_CHUNK_SZ)));
static uchar replay_in_mem [ REPLAY_IN_MEM_SZ  ] __attribute__((aligned(FD_CHUNK_SZ)));
static uchar failov_in_mem [ FAILOV_IN_MEM_SZ  ] __attribute__((aligned(FD_CHUNK_SZ)));

#define IN_IDX_REPLAY (0UL)
#define IN_IDX_FAILOV (1UL)

static ulong
out_wmark( ulong mem_sz,
           ulong mtu ) {
  ulong chunk_mtu = ((mtu + 2UL*FD_CHUNK_SZ-1UL) >> (1+FD_CHUNK_LG_SZ)) << 1;
  return (mem_sz>>FD_CHUNK_LG_SZ) - chunk_mtu;
}

/* A fake stem with the tile's two outs and the two failover outs.
   Publishing writes a real mcache line and nothing consumes it. */

#define OUT_IDX_HIST   (2UL)
#define OUT_IDX_FAILOV (3UL)
#define OUT_CNT        (4UL)
#define OUT_DEPTH      (128UL)

static fd_frag_meta_t    out_mcache[ OUT_CNT ][ OUT_DEPTH ];
static fd_frag_meta_t *  out_mcaches[ OUT_CNT ];
static ulong             out_seqs[ OUT_CNT ];
static ulong             out_depths[ OUT_CNT ];
static ulong             out_cr_avail[ OUT_CNT ];
static ulong             out_min_cr_avail;
static int               out_reliable[ OUT_CNT ];
static fd_stem_context_t stem[ 1 ];

static void
stem_init( void ) {
  for( ulong i=0UL; i<OUT_CNT; i++ ) {
    out_mcaches [ i ] = out_mcache[ i ];
    out_seqs    [ i ] = 0UL;
    out_depths  [ i ] = OUT_DEPTH;
    out_cr_avail[ i ] = OUT_DEPTH;
    out_reliable[ i ] = 0;
  }
  out_min_cr_avail = OUT_DEPTH;
  *stem = (fd_stem_context_t){
    .mcaches = out_mcaches, .seqs = out_seqs, .depths = out_depths,
    .cr_avail = out_cr_avail, .min_cr_avail = &out_min_cr_avail,
    .cr_decrement_amount = 1UL, .out_reliable = out_reliable,
  };
}

/* The tile signs TLS handshakes through the keyguard, which is not
   here.  No handshake progresses in these tests since no packet ever
   arrives, so this signer only has to be a valid callback. */

static uchar test_keypair[ 64 ];

static void
test_sign_ed25519( void *      signer_ctx,
                   uchar       sig[ static FD_ED25519_SIG_SZ ],
                   uchar const msg[ static FD_TLS_CV_SIGN_SZ ] ) {
  (void)signer_ctx;
  fd_sha512_t sha[ 1 ];
  fd_ed25519_sign( sig, msg, FD_TLS_CV_SIGN_SZ, test_keypair+32UL, test_keypair, sha );
}

static fd_pubkey_t
pubkey( int fill ) {
  fd_pubkey_t key;
  fd_memset( key.uc, fill, sizeof(key) );
  return key;
}

/* One ctx per test, formatted the way unprivileged_init does it minus
   the topology.  The QUIC config lines are the tile's own. */

static fd_votor_tile_t *
fixture_new( fd_pubkey_t const * id_key ) {
  fd_votor_tile_t * ctx = ctx_mem;
  fd_memset( ctx, 0, sizeof(*ctx) );
  ctx->id_key = *id_key;

  ctx->pool = ag_pool_join( ag_pool_new( pool_mem, TEST_SLOT_MAX, 42UL ) );
  FD_TEST( ctx->pool );
  ctx->votor = ag_votor_join( ag_votor_new( votor_mem, TEST_SLOT_MAX, 42UL ) );
  FD_TEST( ctx->votor );
  ctx->peers = peers_join( peers_new( peers_mem ) );
  FD_TEST( ctx->peers );
  ctx->contact_infos = contact_infos_join( contact_infos_new( contact_infos_mem ) );
  FD_TEST( ctx->contact_infos );
  ctx->mleaders = fd_multi_epoch_leaders_join( fd_multi_epoch_leaders_new( mleaders_mem ) );
  FD_TEST( ctx->mleaders );

  ctx->prev_epoch_slot        = ULONG_MAX;
  ctx->curr_epoch_slot        = ULONG_MAX;
  ctx->next_epoch_slot        = ULONG_MAX;
  ctx->next_leader_slot       = ULONG_MAX;
  ctx->curr_leader_slot       = ULONG_MAX;
  ctx->ns_per_slot            = TEST_NS_PER_SLOT;
  ctx->highest_unotar_final_slot = ULONG_MAX;
  fd_clock_tile_init( ctx->clock );
  ctx->last_leader_slot       = ULONG_MAX;
  ctx->highest_completed_slot = 0UL;
  /* No failover links in this fixture, the tile behaves like a plain
     staked node. */
  ctx->vote_authority           = 1;
  ctx->hist_out_idx             = ULONG_MAX;
  ctx->failov_out_idx           = ULONG_MAX;
  ctx->adopted_last_leader_slot = ULONG_MAX;
  ctx->last_vote_slot           = ULONG_MAX;
  ctx->root_slot                = ULONG_MAX;
  ctx->own_rank[ 0 ]            = USHORT_MAX;
  ctx->own_rank[ 1 ]            = USHORT_MAX;
  ctx->own_rank[ 2 ]            = USHORT_MAX;

  ctx->quic_client_listen_port = TEST_CLIENT_PORT;
  ctx->quic_server_listen_port = TEST_SERVER_PORT;
  ctx->src_ip_addr             = FD_IP4_ADDR( 127, 0, 0, 1 );
  fd_ip4_udp_hdr_init( ctx->hdr, FD_NET_MTU, ctx->src_ip_addr, ctx->quic_client_listen_port );

  ctx->net_out_mem      = net_out_mem;
  ctx->net_out_chunk0   = 0UL;
  ctx->net_out_wmark    = out_wmark( NET_OUT_MEM_SZ, FD_NET_MTU );
  ctx->net_out_chunk    = 0UL;
  ctx->votor_out_mem    = votor_out_mem;
  ctx->votor_out_chunk0 = 0UL;
  ctx->votor_out_wmark  = out_wmark( VOTOR_OUT_MEM_SZ, sizeof(fd_votor_msg_t) );
  ctx->votor_out_chunk  = 0UL;

  ctx->identity_keyswitch = fd_keyswitch_join( fd_keyswitch_new( ks_mem, FD_KEYSWITCH_STATE_UNLOCKED ) );
  FD_TEST( ctx->identity_keyswitch );

  fd_aio_t * quic_tx_aio = fd_aio_join( fd_aio_new( ctx->quic_tx_aio, ctx, quic_aio_tx ) );
  FD_TEST( quic_tx_aio );

  ctx->quic_client = fd_quic_join( fd_quic_new( quic_client_mem, &quic_client_limits ) );
  FD_TEST( ctx->quic_client );
  fd_quic_set_aio_net_tx( ctx->quic_client, quic_tx_aio );

  ctx->quic_client->config.role                       = FD_QUIC_ROLE_CLIENT;
  ctx->quic_client->config.retry                      = 0;
  ctx->quic_client->config.keep_alive                 = 1;
  ctx->quic_client->config.idle_timeout               = 5L*1000L*1000L*1000L;
  ctx->quic_client->config.ack_delay                  = 2L*1000L*1000L;
  fd_memcpy( ctx->quic_client->config.identity_public_key, ctx->id_key.uc, 32UL );
  ctx->quic_client->config.sign                       = test_sign_ed25519;
  ctx->quic_client->config.sign_ctx                   = ctx;
  ctx->quic_client->config.alpn[ 0 ]                  = 0x0c;
  fd_memcpy( ctx->quic_client->config.alpn+1, "alpenglow-v1", 12UL );
  ctx->quic_client->config.alpn_sz                    = 13UL;
  ctx->quic_client->config.initial_rx_max_stream_data = 0UL;

  ctx->quic_client->cb.quic_ctx         = ctx;
  ctx->quic_client->cb.conn_hs_complete = quic_client_conn_hs_complete;
  ctx->quic_client->cb.conn_final       = quic_client_conn_final;

  FD_TEST( fd_quic_init( ctx->quic_client ) );

  ctx->quic_server = fd_quic_join( fd_quic_new( quic_server_mem, &quic_server_limits ) );
  FD_TEST( ctx->quic_server );
  fd_quic_set_aio_net_tx( ctx->quic_server, quic_tx_aio );

  ctx->quic_server->config.role                       = FD_QUIC_ROLE_SERVER;
  ctx->quic_server->config.retry                      = 0;
  ctx->quic_server->config.idle_timeout               = 5L*1000L*1000L*1000L;
  ctx->quic_server->config.ack_delay                  = 2L*1000L*1000L;
  fd_memcpy( ctx->quic_server->config.identity_public_key, ctx->id_key.uc, 32UL );
  ctx->quic_server->config.sign                       = test_sign_ed25519;
  ctx->quic_server->config.sign_ctx                   = ctx;
  ctx->quic_server->config.alpn[ 0 ]                  = 0x0c;
  fd_memcpy( ctx->quic_server->config.alpn+1, "alpenglow-v1", 12UL );
  ctx->quic_server->config.alpn_sz                    = 13UL;
  ctx->quic_server->config.initial_rx_max_stream_data = 0UL;
  ctx->quic_server->config.max_datagram_frame_size    = 1280UL;

  ctx->quic_server->cb.quic_ctx    = ctx;
  ctx->quic_server->cb.conn_new    = quic_server_conn_new;
  ctx->quic_server->cb.conn_final  = quic_server_conn_final;
  ctx->quic_server->cb.datagram_rx = quic_server_datagram_rx;

  FD_TEST( fd_quic_init( ctx->quic_server ) );

  stem_init();
  return ctx;
}

static void
fixture_delete( fd_votor_tile_t * ctx ) {
  fd_quic_delete( fd_quic_leave( fd_quic_fini( ctx->quic_client ) ) );
  fd_quic_delete( fd_quic_leave( fd_quic_fini( ctx->quic_server ) ) );
  ag_votor_delete( ag_votor_leave( ctx->votor ) );
  ag_pool_delete( ag_pool_leave( ctx->pool ) );
}

/* Two validators with BLS keys, A ranked 0 and B ranked 1, the way
   test_ag_votor builds its epoch.  The identity keys are the point
   here since own_rank_in matches on them. */

static fd_bls_sec_t        sk[ 2 ];
static ag_validator_info_t infos[ 2 ];
static ag_epoch_info_t     epoch_info_mem;

static void
build_epoch_info( fd_pubkey_t const * a,
                  fd_pubkey_t const * b ) {
  fd_pubkey_t const * keys[ 2 ] = { a, b };
  for( ulong i=0UL; i<2UL; i++ ) {
    fd_memset( &sk[i], (int)(i*7UL+1UL), FD_BLS_SEC_SZ );
    fd_memset( &infos[i], 0, sizeof(ag_validator_info_t) );
    infos[i].id    = i;
    infos[i].stake = 1UL;
    fd_bls_sec_to_pub( &sk[i], &infos[i].bls_key );
    fd_memcpy( infos[i].id_key, keys[i]->uc, sizeof(ag_id_key_t) );
  }
  epoch_info_build( &epoch_info_mem, infos, 2UL );
}

/* Bring consensus up at slot 0 as rank own_rank of the built epoch.
   The votor's clock starts at now, so a case that runs after_credit on
   the wallclock passes it the wallclock to keep the skip timeouts from
   coming due underneath it. */

static void
start_consensus_at( fd_votor_tile_t * ctx,
                    ulong             own_rank,
                    long              now ) {
  ctx->curr_epoch_info = &epoch_info_mem;
  ctx->curr_epoch_slot = 0UL;
  ag_pool_advance_epoch ( ctx->pool, &epoch_info_mem, own_rank, 0UL );
  ag_votor_advance_epoch( ctx->votor, TEST_NS_PER_SLOT, own_rank, 0UL );
  ag_pool_init ( ctx->pool, 0UL );
  ag_votor_init( ctx->votor, 0UL, now, TEST_NS_PER_SLOT, TEST_SHRED_VERSION, sec_sign_fn, &sk[ own_rank ] );
  ctx->shred_version = TEST_SHRED_VERSION;
  ctx->init          = 1;
}

static void
start_consensus( fd_votor_tile_t * ctx,
                 ulong             own_rank ) {
  start_consensus_at( ctx, own_rank, 0L );
}

static peer_t *
add_ranked_peer( fd_votor_tile_t *   ctx,
                 fd_pubkey_t const * id_key,
                 ushort              rank,
                 uint                ip4,
                 ushort              port ) {
  peer_t * peer   = peers_insert( ctx->peers, *id_key );
  peer->prev_rank = USHORT_MAX;
  peer->curr_rank = rank;
  peer->next_rank = USHORT_MAX;
  peer->tx_conn   = NULL;
  peer->rx_conn   = NULL;
  peer->ban_ts    = 0L;
  if( FD_LIKELY( port ) ) {
    contact_info_t * ci = contact_infos_insert( ctx->contact_infos, *id_key );
    ci->ip4  = ip4;
    ci->port = port;
  }
  return peer;
}

static void
request_switch( fd_votor_tile_t *   ctx,
                fd_pubkey_t const * to ) {
  fd_memcpy( ctx->identity_keyswitch->bytes, to->uc, 32UL );
  fd_keyswitch_state( ctx->identity_keyswitch, FD_KEYSWITCH_STATE_SWITCH_PENDING );
}

static void
run_after_credit( fd_votor_tile_t * ctx ) {
  int poll_in     = 1;
  int charge_busy = 0;
  after_credit( ctx, stem, &poll_in, &charge_busy );
}

static void
unhalt( fd_votor_tile_t * ctx ) {
  fd_keyswitch_state( ctx->identity_keyswitch, FD_KEYSWITCH_STATE_UNHALT_PENDING );
  during_housekeeping( ctx );
  FD_TEST( !ctx->halt_signing );
  FD_TEST( fd_keyswitch_state_query( ctx->identity_keyswitch )==FD_KEYSWITCH_STATE_COMPLETED );
}

/* Make the fixture a failover member with the given staked identity,
   with the hist and failov outs and the replay and failov in-links wired
   the way unprivileged_init does it.  Nothing else changes, so the plain
   cases never see these links. */

static void
enable_failover( fd_votor_tile_t *   ctx,
                 fd_pubkey_t const * staked ) {
  ctx->failover_enabled         = 1;
  ctx->failover_staked_identity = *staked;
  ctx->failover_standby         = !fd_pubkey_eq( &ctx->id_key, staked );

  ctx->hist_out_idx      = OUT_IDX_HIST;
  ctx->hist_out_mem      = hist_out_mem;
  ctx->hist_out_chunk0   = 0UL;
  ctx->hist_out_wmark    = out_wmark( HIST_OUT_MEM_SZ, sizeof(fd_votor_hist_msg_t) );
  ctx->hist_out_chunk    = 0UL;
  ctx->failov_out_idx    = OUT_IDX_FAILOV;
  ctx->failov_out_mem    = failov_out_mem;
  ctx->failov_out_chunk0 = 0UL;
  ctx->failov_out_wmark  = out_wmark( FAILOV_OUT_MEM_SZ, sizeof(fd_votor_adopt_result_t) );
  ctx->failov_out_chunk  = 0UL;

  ctx->in_kind[ IN_IDX_REPLAY ]   = IN_KIND_REPLAY;
  ctx->in[ IN_IDX_REPLAY ].mem    = (fd_wksp_t *)fd_type_pun( replay_in_mem );
  ctx->in[ IN_IDX_REPLAY ].chunk0 = 0UL;
  ctx->in[ IN_IDX_REPLAY ].wmark  = out_wmark( REPLAY_IN_MEM_SZ, sizeof(fd_replay_message_t) );
  ctx->in[ IN_IDX_REPLAY ].mtu    = sizeof(fd_replay_message_t);
  ctx->in_kind[ IN_IDX_FAILOV ]   = IN_KIND_FAILOV;
  ctx->in[ IN_IDX_FAILOV ].mem    = (fd_wksp_t *)fd_type_pun( failov_in_mem );
  ctx->in[ IN_IDX_FAILOV ].chunk0 = 0UL;
  ctx->in[ IN_IDX_FAILOV ].wmark  = out_wmark( FAILOV_IN_MEM_SZ, AG_HIST_SER_MAX );
  ctx->in[ IN_IDX_FAILOV ].mtu    = AG_HIST_SER_MAX;
}

/* One frag on in-link in_idx the way stem hands it over, the payload
   sits at chunk 0 of that link's buffer.  Returns before_frag's verdict,
   nonzero means the tile filtered it and nothing else ran. */

static int
deliver_frag( fd_votor_tile_t * ctx,
              ulong             in_idx,
              ulong             sig,
              ulong             sz ) {
  static ulong seq = 0UL;
  if( FD_UNLIKELY( before_frag( ctx, in_idx, seq, sig ) ) ) return 1;
  during_frag( ctx, in_idx, seq, sig, 0UL, sz, 0UL );
  after_frag ( ctx, in_idx, seq, sig, sz, 0UL, 0UL, stem );
  seq++;
  return 0;
}

static fd_replay_message_t *
replay_in_msg( void ) {
  fd_memset( replay_in_mem, 0, sizeof(fd_replay_message_t) );
  return (fd_replay_message_t *)fd_type_pun( replay_in_mem );
}

/* The frame stem wrote at seq on one of the outs, checked against the
   sig and size the tile publishes with. */

static void const *
out_frame( ulong        out_idx,
           void const * mem,
           ulong        seq,
           ulong        sig,
           ulong        sz ) {
  fd_frag_meta_t const * meta = &out_mcache[ out_idx ][ seq & (OUT_DEPTH-1UL) ];
  FD_TEST( meta->seq==seq && meta->sig==sig && (ulong)meta->sz==sz );
  return fd_chunk_to_laddr_const( mem, meta->chunk );
}

static fd_votor_hist_msg_t const *
hist_frame( ulong seq ) {
  return out_frame( OUT_IDX_HIST, hist_out_mem, seq, FD_VOTOR_HIST_SIG, sizeof(fd_votor_hist_msg_t) );
}

static fd_votor_adopt_result_t const *
adopt_reply( ulong seq,
             ulong sig ) {
  return out_frame( OUT_IDX_FAILOV, failov_out_mem, seq, sig, sizeof(fd_votor_adopt_result_t) );
}

static ag_hist_rec_t const *
hist_rec( ag_hist_t const * hist,
          ulong             slot ) {
  for( ulong i=0UL; i<hist->rec_cnt; i++ ) if( FD_UNLIKELY( hist->rec[ i ].slot==slot ) ) return &hist->rec[ i ];
  return NULL;
}

/* A history on anchor 0 with one voted slot, a notar vote on notar_hash
   when one is given. */

static void
one_slot_hist( ag_hist_t *   hist,
               ulong         slot,
               uchar const * notar_hash ) {
  fd_memset( hist, 0, sizeof(*hist) );
  hist->anchor           = 0UL;
  hist->last_leader_slot = ULONG_MAX;
  hist->rec_cnt          = 1UL;
  hist->rec[ 0 ].slot    = slot;
  hist->rec[ 0 ].flags   = (uchar)( AG_HIST_FLAG_VOTED | fd_uint_if( !!notar_hash, AG_HIST_FLAG_VOTED_NOTAR, 0U ) );
  if( FD_LIKELY( notar_hash ) ) fd_memcpy( hist->rec[ 0 ].notar_hash, notar_hash, sizeof(ag_block_hash_t) );
}

/* test_switch_completes_uninitialised: a switch before any epoch or
   replay arrived still halts, installs the key and completes, the
   admin tile waits on it. */

static void
test_switch_completes_uninitialised( void ) {
  fd_pubkey_t old_key = pubkey( 0x11 );
  fd_pubkey_t new_key = pubkey( 0x22 );
  fd_votor_tile_t * ctx = fixture_new( &old_key );
  FD_TEST( !ctx->init && !ctx->curr_epoch_info );
  FD_TEST( ag_pool_finalized_slot( ctx->pool )==ULONG_MAX );

  request_switch( ctx, &new_key );
  during_housekeeping( ctx );
  FD_TEST( ctx->halt_signing==1 );
  FD_TEST( fd_keyswitch_state_query( ctx->identity_keyswitch )==FD_KEYSWITCH_STATE_SWITCH_PENDING );
  FD_TEST( fd_pubkey_eq( &ctx->id_key, &old_key ) ); /* housekeeping only halts */

  run_after_credit( ctx );
  FD_TEST( fd_keyswitch_state_query( ctx->identity_keyswitch )==FD_KEYSWITCH_STATE_COMPLETED );
  FD_TEST( ctx->identity_keyswitch->result==0UL );
  FD_TEST( fd_pubkey_eq( &ctx->id_key, &new_key ) );
  FD_TEST( fd_memeq( ctx->quic_client->config.identity_public_key, new_key.uc, 32UL ) );
  FD_TEST( fd_memeq( ctx->quic_server->config.identity_public_key, new_key.uc, 32UL ) );
  FD_TEST( ctx->next_leader_slot==ULONG_MAX );
  FD_TEST( ctx->halt_signing==1 ); /* completion does not unhalt, the admin tile does */

  /* A second after_credit does not redo the switch. */
  ctx->identity_keyswitch->result = 7UL;
  run_after_credit( ctx );
  FD_TEST( ctx->identity_keyswitch->result==7UL );

  unhalt( ctx );
  FD_TEST( fd_pubkey_eq( &ctx->id_key, &new_key ) );

  fixture_delete( ctx );
  FD_LOG_NOTICE(( "pass: an uninitialised tile completes a switch and installs the key" ));
}

/* test_switch_closes_and_reconnects: halting drops every peer conn so
   nobody keeps reading datagrams as the old identity, and unhalt dials
   every ranked peer with a contact info again. */

static void
test_switch_closes_and_reconnects( void ) {
  fd_pubkey_t old_key = pubkey( 0x11 );
  fd_pubkey_t new_key = pubkey( 0x22 );
  fd_pubkey_t p1      = pubkey( 0x31 );
  fd_pubkey_t p2      = pubkey( 0x32 );
  fd_pubkey_t p3      = pubkey( 0x33 );
  fd_votor_tile_t * ctx = fixture_new( &old_key );

  peer_t * peer1 = add_ranked_peer( ctx, &p1, (ushort)0, FD_IP4_ADDR( 10, 0, 0, 1 ), (ushort)8001 );
  peer_t * peer2 = add_ranked_peer( ctx, &p2, (ushort)1, FD_IP4_ADDR( 10, 0, 0, 2 ), (ushort)8002 );
  peer_t * peer3 = add_ranked_peer( ctx, &p3, (ushort)2, 0U, (ushort)0 ); /* ranked, no address yet */

  connect_peers( ctx );
  FD_TEST( peer1->tx_conn && peer2->tx_conn && !peer3->tx_conn );
  FD_TEST( peer1->tx_conn->state==FD_QUIC_CONN_STATE_HANDSHAKE );
  FD_TEST( fd_pubkey_eq( fd_quic_conn_get_context( peer1->tx_conn ), &p1 ) );

  /* No server handshake completes in this fixture, so a second client
     conn stands in for the accepted rx side.  close_conns treats both
     the same way. */
  long now = fd_log_wallclock();
  peer1->rx_conn = fd_quic_connect( ctx->quic_client, FD_IP4_ADDR( 10, 0, 0, 1 ), (ushort)8001, ctx->src_ip_addr, ctx->quic_client_listen_port, now );
  FD_TEST( peer1->rx_conn );
  fd_quic_conn_t * tx1 = peer1->tx_conn;
  fd_quic_conn_t * rx1 = peer1->rx_conn;
  fd_quic_conn_t * tx2 = peer2->tx_conn;

  request_switch( ctx, &new_key );
  during_housekeeping( ctx );
  FD_TEST( ctx->halt_signing );
  for( ulong slot=0UL; slot<peers_slot_cnt(); slot++ ) {
    peer_t const * peer = &ctx->peers[ slot ];
    if( FD_LIKELY( peers_key_inval( peer->id_key ) ) ) continue;
    FD_TEST( !peer->tx_conn && !peer->rx_conn );
  }
  FD_TEST( tx1->state==FD_QUIC_CONN_STATE_CLOSE_PENDING );
  FD_TEST( rx1->state==FD_QUIC_CONN_STATE_CLOSE_PENDING );
  FD_TEST( tx2->state==FD_QUIC_CONN_STATE_CLOSE_PENDING );
  FD_TEST( !fd_quic_conn_get_context( tx1 ) ); /* conn_final must not touch the peer again */

  /* Nothing dials while halted, the handshake would sign as the old key. */
  connect_peers( ctx );
  FD_TEST( !peer1->tx_conn && !peer2->tx_conn );

  run_after_credit( ctx );
  FD_TEST( fd_keyswitch_state_query( ctx->identity_keyswitch )==FD_KEYSWITCH_STATE_COMPLETED );
  FD_TEST( fd_pubkey_eq( &ctx->id_key, &new_key ) );
  FD_TEST( !peer1->tx_conn && !peer2->tx_conn );

  unhalt( ctx );
  FD_TEST( peer1->tx_conn && peer2->tx_conn && !peer3->tx_conn );
  FD_TEST( !peer1->rx_conn && !peer2->rx_conn );
  /* A freed conn slot may be handed out again, so a fresh handshake is
     the sign of a redial, not a new address. */
  FD_TEST( peer1->tx_conn->state==FD_QUIC_CONN_STATE_HANDSHAKE );
  FD_TEST( peer2->tx_conn->state==FD_QUIC_CONN_STATE_HANDSHAKE );
  FD_TEST( fd_pubkey_eq( fd_quic_conn_get_context( peer1->tx_conn ), &p1 ) );
  FD_TEST( fd_pubkey_eq( fd_quic_conn_get_context( peer2->tx_conn ), &p2 ) );

  fixture_delete( ctx );
  FD_LOG_NOTICE(( "pass: the halt closes every conn and unhalt dials the ranked peers again" ));
}

/* test_switch_ranks_and_leader: start as A, switch to B, the slot state
   created before the switch gets B's rank and one created after is
   born with it.  A key in no epoch is unranked, and the old identity's
   leader slot is dropped. */

static void
test_switch_ranks_and_leader( void ) {
  fd_pubkey_t a = pubkey( 0x41 );
  fd_pubkey_t b = pubkey( 0x42 );
  fd_pubkey_t c = pubkey( 0x43 );
  fd_votor_tile_t * ctx = fixture_new( &a );
  build_epoch_info( &a, &b );
  start_consensus( ctx, 0UL );

  FD_TEST( own_rank_in( &epoch_info_mem, &a )==(ushort)0 );
  FD_TEST( own_rank_in( &epoch_info_mem, &b )==(ushort)1 );
  FD_TEST( own_rank_in( &epoch_info_mem, &c )==USHORT_MAX );
  FD_TEST( own_rank_in( NULL,            &a )==USHORT_MAX );

  /* A slot state made under A. */
  ag_block_id_t parent = { .slot = 0UL };
  ag_block_id_t block1 = { .slot = 1UL };
  fd_memset( block1.hash, 0xa1, sizeof(ag_block_hash_t) );
  FD_TEST( ag_pool_add_block( ctx->pool, &block1, &parent, ctx->scratch.bad )==AG_POOL_SUCCESS );
  ag_slot_state_t const * state1 = ag_pool_slot_state( ctx->pool, 1UL );
  FD_TEST( state1 && state1->own_rank==0UL );

  /* A leader slot A had, and a completed slot past the finalized one so
     the schedule lookup runs (nothing is loaded, so it finds none). */
  ctx->curr_leader_slot       = 0UL;
  ctx->next_leader_slot       = 8UL;
  ctx->highest_completed_slot = 1UL;

  request_switch( ctx, &b );
  during_housekeeping( ctx );
  run_after_credit( ctx );
  FD_TEST( fd_keyswitch_state_query( ctx->identity_keyswitch )==FD_KEYSWITCH_STATE_COMPLETED );
  FD_TEST( fd_pubkey_eq( &ctx->id_key, &b ) );
  FD_TEST( state1->own_rank==1UL );
  FD_TEST( ctx->curr_leader_slot==ULONG_MAX );
  FD_TEST( ctx->next_leader_slot==ULONG_MAX );
  FD_TEST( ctx->init ); /* consensus state survives the switch */

  /* A slot state made under B. */
  ag_block_id_t block2 = { .slot = 2UL };
  fd_memset( block2.hash, 0xa2, sizeof(ag_block_hash_t) );
  FD_TEST( ag_pool_add_block( ctx->pool, &block2, &block1, ctx->scratch.bad )==AG_POOL_SUCCESS );
  ag_slot_state_t const * state2 = ag_pool_slot_state( ctx->pool, 2UL );
  FD_TEST( state2 && state2->own_rank==1UL );

  /* C is in no epoch, so both live slot states go unranked. */
  unhalt( ctx );
  request_switch( ctx, &c );
  during_housekeeping( ctx );
  run_after_credit( ctx );
  FD_TEST( fd_keyswitch_state_query( ctx->identity_keyswitch )==FD_KEYSWITCH_STATE_COMPLETED );
  FD_TEST( fd_pubkey_eq( &ctx->id_key, &c ) );
  FD_TEST( state1->own_rank==(ulong)USHORT_MAX );
  FD_TEST( state2->own_rank==(ulong)USHORT_MAX );

  /* And back to A restores rank 0 everywhere. */
  unhalt( ctx );
  request_switch( ctx, &a );
  during_housekeeping( ctx );
  run_after_credit( ctx );
  FD_TEST( state1->own_rank==0UL && state2->own_rank==0UL );

  unhalt( ctx );
  fixture_delete( ctx );
  FD_LOG_NOTICE(( "pass: the switch rewrites our rank in the pool and drops the old leader slot" ));
}

/* test_gossip_dial_gated: a contact info arriving mid switch is kept
   but not dialed, the handshake would sign as the old key.  Once
   unhalted the same update dials. */

static void
test_gossip_dial_gated( void ) {
  fd_pubkey_t a = pubkey( 0x41 );
  fd_pubkey_t p = pubkey( 0x51 );
  fd_votor_tile_t * ctx  = fixture_new( &a );
  peer_t *          peer = add_ranked_peer( ctx, &p, (ushort)0, 0U, (ushort)0 );

  static fd_gossip_update_message_t msg;
  fd_memset( &msg, 0, sizeof(msg) );
  msg.tag = FD_GOSSIP_UPDATE_TAG_CONTACT_INFO;
  fd_memcpy( msg.origin, p.uc, sizeof(fd_pubkey_t) );
  fd_gossip_socket_t * socket = &msg.contact_info->value->sockets[ FD_GOSSIP_CONTACT_INFO_SOCKET_ALPENGLOW ];
  socket->is_ipv6 = 0U;
  socket->ip4     = FD_IP4_ADDR( 10, 0, 0, 9 );
  socket->port    = fd_ushort_bswap( (ushort)8009 );

  ctx->halt_signing = 1;
  handle_gossip( ctx, FD_GOSSIP_UPDATE_TAG_CONTACT_INFO, &msg );
  contact_info_t const * ci = contact_infos_query( ctx->contact_infos, p, NULL );
  FD_TEST( ci && ci->ip4==FD_IP4_ADDR( 10, 0, 0, 9 ) && ci->port==(ushort)8009 );
  FD_TEST( !peer->tx_conn );

  ctx->halt_signing = 0;
  handle_gossip( ctx, FD_GOSSIP_UPDATE_TAG_CONTACT_INFO, &msg );
  FD_TEST( peer->tx_conn );
  FD_TEST( fd_pubkey_eq( fd_quic_conn_get_context( peer->tx_conn ), &p ) );

  fixture_delete( ctx );
  FD_LOG_NOTICE(( "pass: gossip keeps the address but only dials once unhalted" ));
}

/* test_drops_queued_votes: votes the votor queued before the halt are
   dropped by the completion, they would go out signed by whichever key
   the sign tile holds by then. */

static void
test_drops_queued_votes( void ) {
  fd_pubkey_t a = pubkey( 0x41 );
  fd_pubkey_t b = pubkey( 0x42 );
  fd_votor_tile_t * ctx = fixture_new( &a );
  build_epoch_info( &a, &b );
  start_consensus( ctx, 0UL );

  /* Every timeout of the first window fires, so skip votes for slots
     1..3 queue up.  Popping one proves the queue is live, two remain. */
  ag_event_timeout_t timeout;
  while( ag_votor_poll_timeout_event( ctx->votor, TEST_WINDOW_ELAPSED_NS, &timeout ) ) ag_votor_handle_timeout_event( ctx->votor, &timeout );
  ag_event_vote_t vote_event;
  FD_TEST( ag_votor_poll_vote_event( ctx->votor, &vote_event ) );
  FD_TEST( vote_event.vote.kind==AG_VOTE_KIND_SKIP && ag_vote_slot( &vote_event.vote )==1UL );

  request_switch( ctx, &b );
  during_housekeeping( ctx );
  run_after_credit( ctx );
  FD_TEST( fd_keyswitch_state_query( ctx->identity_keyswitch )==FD_KEYSWITCH_STATE_COMPLETED );
  FD_TEST( !ag_votor_poll_vote_event( ctx->votor, &vote_event ) );

  unhalt( ctx );
  FD_TEST( !ag_votor_poll_vote_event( ctx->votor, &vote_event ) );

  fixture_delete( ctx );
  FD_LOG_NOTICE(( "pass: the completion drops every vote queued before the halt" ));
}

#define TEST_VOTER_MAX (4UL)

/* An ag_epoch_info_t is nearly 300 KiB, too big for the stack. */

static ag_epoch_info_t rank_epoch_info_mem;

/* Builds cnt voters with distinct identities and valid BLS keys, staked
   base, base+1, ... rank_voters drops any voter whose BLS key fails to
   deserialize, so the keys have to be real points. */

static void
build_stakes( fd_vote_stake_weight_t * out,
              ulong                    cnt,
              ulong                    base ) {
  for( ulong i=0UL; i<cnt; i++ ) {
    memset( &out[i], 0, sizeof(fd_vote_stake_weight_t) );
    out[i].stake           = base + i;
    out[i].id_key.uc  [ 0 ] = (uchar)( i + 1UL );
    out[i].vote_key.uc[ 0 ] = (uchar)( i + 0x80UL );

    fd_bls_sec_t sec; memset( &sec, (int)( i*7UL + 1UL ), FD_BLS_SEC_SZ );
    fd_bls_pub_t pub; fd_bls_sec_to_pub( &sec, &pub );
    blst_p1_compress( out[i].bls_key, &pub );
  }
}

static void
test_rank_voters_resets_total_stake( void ) {
  fd_vote_stake_weight_t stakes[ TEST_VOTER_MAX ];
  ag_epoch_info_t *      epoch_info = &rank_epoch_info_mem;

  build_stakes( stakes, 3UL, 10UL );
  FD_TEST( rank_voters( epoch_info, stakes, 3UL )==epoch_info );
  FD_TEST( epoch_info->validator_cnt==3UL  );
  FD_TEST( epoch_info->total_stake  ==33UL ); /* 10+11+12 */

  /* Same buffer, next epoch. */

  build_stakes( stakes, 2UL, 5UL );
  FD_TEST( rank_voters( epoch_info, stakes, 2UL )==epoch_info );
  FD_TEST( epoch_info->validator_cnt==2UL  );
  FD_TEST( epoch_info->total_stake  ==11UL ); /* 5+6, not 33+11 */
}

/* test_hist_frames: a frame follows our own vote with has_vote set and
   the voted slot in the history, a completed slot answers with has_vote
   clear and the replay slot moved, and a LEADER publishes one more that
   gives the window we lead. */

static void
test_hist_frames( void ) {
  fd_pubkey_t a = pubkey( 0x41 );
  fd_pubkey_t b = pubkey( 0x42 );
  fd_votor_tile_t * ctx = fixture_new( &a );
  enable_failover( ctx, &a );
  build_epoch_info( &a, &b );
  start_consensus_at( ctx, 0UL, fd_log_wallclock() );
  ctx->highest_completed_slot = 1UL;
  ctx->root_slot              = 0UL;

  /* Init voted notar on slot 0 with a zero hash, so block 1 on that
     parent gets our notar vote. */
  ag_block_id_t block0 = { .slot = 0UL };
  ag_block_id_t block1 = { .slot = 1UL };
  fd_memset( block1.hash, 0xb1, sizeof(ag_block_hash_t) );
  FD_TEST( ag_pool_add_block( ctx->pool, &block1, &block0, ctx->scratch.bad )==AG_POOL_SUCCESS );
  ag_event_replay_t completed = { .kind = AG_EVENT_REPLAY_COMPLETED, .slot = 1UL, .block_info = { .parent = block0 } };
  fd_memcpy( completed.block_info.hash, block1.hash, sizeof(ag_block_hash_t) );
  ag_votor_handle_replay_event( ctx->votor, &completed );
  FD_TEST( ag_votor_has_voted( ctx->votor, 1UL ) );

  FD_TEST( out_seqs[ OUT_IDX_HIST ]==0UL );
  run_after_credit( ctx );
  FD_TEST( out_seqs[ OUT_IDX_HIST ]==1UL );
  FD_TEST( ctx->last_vote_slot==1UL );
  fd_votor_hist_msg_t const * frame = hist_frame( 0UL );
  FD_TEST( frame->has_vote==1 && !frame->truncated );
  FD_TEST( frame->vote_slot==1UL && frame->vote_slot==ag_hist_tip( &frame->hist ) );
  FD_TEST( frame->replay_slot==1UL && frame->root_slot==0UL );
  FD_TEST( frame->hist.anchor==0UL && frame->hist.last_leader_slot==ULONG_MAX );
  FD_TEST( frame->hist.rec_cnt>=1UL );
  ag_hist_rec_t const * rec = hist_rec( &frame->hist, 1UL );
  FD_TEST( rec && rec->flags==(AG_HIST_FLAG_VOTED|AG_HIST_FLAG_VOTED_NOTAR) );
  FD_TEST( fd_memeq( rec->notar_hash, block1.hash, sizeof(ag_block_hash_t) ) );

  /* Replay completes slot 2 on block 1.  The frame follows from
     after_frag with no vote behind it and the replay slot moved. */
  ag_block_id_t block2 = { .slot = 2UL };
  fd_memset( block2.hash, 0xb2, sizeof(ag_block_hash_t) );
  fd_replay_message_t * replay = replay_in_msg();
  replay->slot_completed.slot        = 2UL;
  replay->slot_completed.parent_slot = 1UL;
  replay->slot_completed.root_slot   = 0UL;
  fd_memcpy( replay->slot_completed.block_id.uc,        block2.hash, sizeof(fd_hash_t) );
  fd_memcpy( replay->slot_completed.parent_block_id.uc, block1.hash, sizeof(fd_hash_t) );
  FD_TEST( !deliver_frag( ctx, IN_IDX_REPLAY, REPLAY_SIG_SLOT_COMPLETED, sizeof(fd_replay_message_t) ) );
  FD_TEST( out_seqs[ OUT_IDX_HIST ]==2UL );
  FD_TEST( ctx->highest_completed_slot==2UL );
  frame = hist_frame( 1UL );
  FD_TEST( frame->has_vote==0 );
  FD_TEST( frame->replay_slot==2UL && frame->root_slot==0UL );
  FD_TEST( frame->vote_slot==ag_hist_tip( &frame->hist ) );

  /* Replay roots block 3, which grants parent ready for window 4.  With
     4 as our next leader slot, after_credit publishes LEADER and one
     more frame that holds the window.  The notar vote queued for slot 2
     pops first, so the frame we want is the last one. */
  ag_block_id_t block3 = { .slot = 3UL };
  fd_memset( block3.hash, 0xb3, sizeof(ag_block_hash_t) );
  FD_TEST( ag_pool_add_block( ctx->pool, &block3, &block2, ctx->scratch.bad )==AG_POOL_SUCCESS );
  replay = replay_in_msg();
  replay->root_advanced.slot = 3UL;
  fd_memcpy( replay->root_advanced.block_id.uc, block3.hash, sizeof(fd_hash_t) );
  FD_TEST( !deliver_frag( ctx, IN_IDX_REPLAY, REPLAY_SIG_ROOT_ADVANCED, sizeof(fd_replay_message_t) ) );
  FD_TEST( ag_pool_finalized_slot( ctx->pool )==3UL );
  FD_TEST( ag_pool_wait_for_parent_ready( ctx->pool, 4UL ).slot==3UL );
  FD_TEST( out_seqs[ OUT_IDX_HIST ]==2UL ); /* a root alone publishes nothing */

  ctx->next_leader_slot = 4UL;
  ulong votor_seq = out_seqs[ OUT_IDX_VOTOR ];
  run_after_credit( ctx );
  FD_TEST( ctx->last_leader_slot==4UL );
  FD_TEST( ctx->next_leader_slot==ULONG_MAX ); /* no schedule loaded */
  FD_TEST( out_seqs[ OUT_IDX_VOTOR ]>votor_seq );
  FD_TEST( out_mcache[ OUT_IDX_VOTOR ][ (out_seqs[ OUT_IDX_VOTOR ]-1UL) & (OUT_DEPTH-1UL) ].sig==FD_VOTOR_SIG_LEADER );
  FD_TEST( out_seqs[ OUT_IDX_HIST ]==4UL );
  FD_TEST( hist_frame( 2UL )->has_vote==1 && ctx->last_vote_slot==2UL );
  frame = hist_frame( 3UL );
  FD_TEST( frame->has_vote==0 );
  FD_TEST( frame->hist.last_leader_slot==4UL && frame->hist.anchor==3UL );
  FD_TEST( frame->replay_slot==2UL && frame->root_slot==0UL );

  fixture_delete( ctx );
  FD_LOG_NOTICE(( "pass: a frame follows every own vote, completed slot and LEADER" ));
}

/* test_switch_watermark: the completion publishes one last frame and
   hands the failover tile the sequence after it as the watermark. */

static void
test_switch_watermark( void ) {
  fd_pubkey_t a = pubkey( 0x41 );
  fd_pubkey_t b = pubkey( 0x42 );
  fd_votor_tile_t * ctx = fixture_new( &a );
  enable_failover( ctx, &b );
  build_epoch_info( &a, &b );
  start_consensus( ctx, 0UL );
  ctx->failover_hist_adopted = 1;

  FD_TEST( out_seqs[ OUT_IDX_HIST ]==0UL );
  request_switch( ctx, &b );
  during_housekeeping( ctx );
  run_after_credit( ctx );
  FD_TEST( fd_keyswitch_state_query( ctx->identity_keyswitch )==FD_KEYSWITCH_STATE_COMPLETED );
  FD_TEST( out_seqs[ OUT_IDX_HIST ]==1UL );
  FD_TEST( ctx->identity_keyswitch->result==out_seqs[ OUT_IDX_HIST ] );
  fd_votor_hist_msg_t const * frame = hist_frame( 0UL );
  FD_TEST( frame->has_vote==0 && frame->hist.anchor==0UL );

  /* Nothing more goes out while halted, the watermark stays put. */
  run_after_credit( ctx );
  FD_TEST( out_seqs[ OUT_IDX_HIST ]==1UL && ctx->identity_keyswitch->result==1UL );

  unhalt( ctx );
  fixture_delete( ctx );
  FD_LOG_NOTICE(( "pass: the switch publishes a last frame and reports the sequence after it" ));
}

/* test_adopt_reply: an adoption request on failov_votor is answered on
   votor_failov under the request's sequence number.  A good history is
   taken, one older than the votes we sent is stale, garbage fails to
   decode and an empty history is invalid. */

static void
test_adopt_reply( void ) {
  fd_pubkey_t a = pubkey( 0x41 );
  fd_pubkey_t b = pubkey( 0x42 );
  fd_votor_tile_t * ctx = fixture_new( &a );
  enable_failover( ctx, &b );
  build_epoch_info( &a, &b );
  start_consensus( ctx, 0UL );

  uchar hash[ 32 ];
  fd_memset( hash, 0xc1, sizeof(hash) );
  ag_hist_t hist[ 1 ];
  one_slot_hist( hist, 1UL, hash );
  ulong sz;
  FD_TEST( !ag_hist_ser( hist, failov_in_mem, FAILOV_IN_MEM_SZ, &sz ) );

  FD_TEST( !ag_votor_has_voted( ctx->votor, 1UL ) );
  FD_TEST( !deliver_frag( ctx, IN_IDX_FAILOV, 77UL, sz ) );
  FD_TEST( out_seqs[ OUT_IDX_FAILOV ]==1UL );
  fd_votor_adopt_result_t const * reply = adopt_reply( 0UL, 77UL );
  FD_TEST( reply->result==FD_VOTOR_ADOPT_SUCCESS );
  FD_TEST( reply->vote_slot==1UL );
  FD_TEST( reply->root==ag_votor_highest_final_cert_slot( ctx->votor ) && reply->root==0UL );
  FD_TEST( ctx->failover_hist_adopted==1 );
  FD_TEST( ctx->adopted_last_leader_slot==ULONG_MAX );
  FD_TEST( ag_votor_has_voted( ctx->votor, 1UL ) );

  /* A tip below the last vote this identity sent from here. */
  ctx->last_vote_slot = 5UL;
  FD_TEST( !deliver_frag( ctx, IN_IDX_FAILOV, 78UL, sz ) );
  reply = adopt_reply( 1UL, 78UL );
  FD_TEST( reply->result==FD_VOTOR_ADOPT_ERR_STALE );
  FD_TEST( reply->root==ULONG_MAX && reply->vote_slot==ULONG_MAX );

  /* Bytes that are no history. */
  fd_memset( failov_in_mem, 0xff, 32UL );
  FD_TEST( !deliver_frag( ctx, IN_IDX_FAILOV, 79UL, 32UL ) );
  reply = adopt_reply( 2UL, 79UL );
  FD_TEST( reply->result==FD_VOTOR_ADOPT_ERR_DECODE );

  /* A history with nothing in it. */
  hist->rec_cnt = 0UL;
  FD_TEST( !ag_hist_ser( hist, failov_in_mem, FAILOV_IN_MEM_SZ, &sz ) );
  FD_TEST( !deliver_frag( ctx, IN_IDX_FAILOV, 80UL, sz ) );
  reply = adopt_reply( 3UL, 80UL );
  FD_TEST( reply->result==FD_VOTOR_ADOPT_ERR_INVALID );
  FD_TEST( out_seqs[ OUT_IDX_FAILOV ]==4UL );

  fixture_delete( ctx );
  FD_LOG_NOTICE(( "pass: adoption answers echo the request and reject stale, garbage and empty histories" ));
}

/* test_switch_gating: the staked key installed without an adopted
   history or first use may not vote and goes unranked, with a history
   adopted it votes at its rank and the adoption is spent, first use is
   spent the same way, and the junk key never votes. */

static void
test_switch_gating( void ) {
  fd_pubkey_t a = pubkey( 0x41 );
  fd_pubkey_t b = pubkey( 0x42 );
  fd_pubkey_t c = pubkey( 0x43 );
  fd_votor_tile_t * ctx = fixture_new( &a );
  enable_failover( ctx, &b );
  build_epoch_info( &a, &b );
  start_consensus( ctx, 0UL );

  /* A spare boots unranked, and a slot state made then is unranked. */
  ctx->vote_authority = 0;
  install_ranks( ctx );
  ag_block_id_t block0 = { .slot = 0UL };
  ag_block_id_t block1 = { .slot = 1UL };
  fd_memset( block1.hash, 0xa1, sizeof(ag_block_hash_t) );
  FD_TEST( ag_pool_add_block( ctx->pool, &block1, &block0, ctx->scratch.bad )==AG_POOL_SUCCESS );
  ag_slot_state_t const * state1 = ag_pool_slot_state( ctx->pool, 1UL );
  FD_TEST( state1 && state1->own_rank==(ulong)USHORT_MAX );

  /* The staked key with nothing adopted and no first use. */
  FD_TEST( !ctx->failover_hist_adopted && !ctx->first_use_authorized );
  request_switch( ctx, &b );
  during_housekeeping( ctx );
  run_after_credit( ctx );
  FD_TEST( fd_keyswitch_state_query( ctx->identity_keyswitch )==FD_KEYSWITCH_STATE_COMPLETED );
  FD_TEST( fd_pubkey_eq( &ctx->id_key, &b ) && !ctx->failover_standby );
  FD_TEST( ctx->vote_authority==0 );
  FD_TEST( ctx->own_rank[ 1 ]==USHORT_MAX && state1->own_rank==(ulong)USHORT_MAX );

  /* The same key with a history adopted. */
  unhalt( ctx );
  ctx->failover_hist_adopted = 1;
  request_switch( ctx, &b );
  during_housekeeping( ctx );
  run_after_credit( ctx );
  FD_TEST( fd_keyswitch_state_query( ctx->identity_keyswitch )==FD_KEYSWITCH_STATE_COMPLETED );
  FD_TEST( ctx->vote_authority==1 );
  FD_TEST( ctx->own_rank[ 1 ]==(ushort)1 && state1->own_rank==1UL );
  FD_TEST( ctx->failover_hist_adopted==0 );

  /* First use unlocks it once. */
  unhalt( ctx );
  ctx->first_use_authorized = 1;
  request_switch( ctx, &b );
  during_housekeeping( ctx );
  run_after_credit( ctx );
  FD_TEST( ctx->vote_authority==1 && ctx->first_use_authorized==0 );
  FD_TEST( state1->own_rank==1UL );

  /* The junk key. */
  unhalt( ctx );
  request_switch( ctx, &c );
  during_housekeeping( ctx );
  run_after_credit( ctx );
  FD_TEST( fd_keyswitch_state_query( ctx->identity_keyswitch )==FD_KEYSWITCH_STATE_COMPLETED );
  FD_TEST( fd_pubkey_eq( &ctx->id_key, &c ) && ctx->failover_standby );
  FD_TEST( ctx->vote_authority==0 );
  FD_TEST( ctx->own_rank[ 1 ]==USHORT_MAX && state1->own_rank==(ulong)USHORT_MAX );

  unhalt( ctx );
  fixture_delete( ctx );
  FD_LOG_NOTICE(( "pass: the staked key votes only after an adoption or first use, the junk key never" ));
}

/* test_leader_floor: after a switch the next leader slot starts past the
   window the peer already led as this identity, without that floor it
   starts right after what we have seen, and with nothing seen there is
   none.  The schedule has B leading every slot of epoch 0. */

static void
test_leader_floor( void ) {
  fd_pubkey_t a = pubkey( 0x41 );
  fd_pubkey_t b = pubkey( 0x42 );
  fd_votor_tile_t * ctx = fixture_new( &a );
  enable_failover( ctx, &b );
  build_epoch_info( &a, &b );
  start_consensus( ctx, 0UL );

  static uchar msg_mem[ FD_EPOCH_INFO_MSG_HEADER_SZ+sizeof(fd_vote_stake_weight_t) ] __attribute__((aligned(64)));
  fd_memset( msg_mem, 0, sizeof(msg_mem) );
  fd_epoch_info_msg_t * msg = (fd_epoch_info_msg_t *)fd_type_pun( msg_mem );
  msg->epoch           = 0UL;
  msg->start_slot      = 0UL;
  msg->slot_cnt        = 64UL;
  msg->staked_vote_cnt = 1UL;
  msg->staked_id_cnt   = 1UL;
  fd_vote_stake_weight_t * weight = fd_epoch_info_msg_stake_weights( msg );
  weight->vote_key = b;
  weight->id_key   = b;
  weight->stake    = 1000UL;
  fd_multi_epoch_leaders_epoch_msg_init( ctx->mleaders, msg );
  fd_multi_epoch_leaders_epoch_msg_fini( ctx->mleaders );
  FD_TEST( fd_multi_epoch_leaders_get_next_slot( ctx->mleaders, 1UL, &b )==1UL );
  FD_TEST( fd_multi_epoch_leaders_get_next_slot( ctx->mleaders, 1UL, &a )==ULONG_MAX );

  /* The adopted history says the peer led window 8, so the search
     starts at 12 even though we have seen nothing past slot 2. */
  ctx->highest_completed_slot   = 2UL;
  ctx->adopted_last_leader_slot = 8UL;
  ctx->failover_hist_adopted    = 1;
  request_switch( ctx, &b );
  during_housekeeping( ctx );
  run_after_credit( ctx );
  FD_TEST( fd_keyswitch_state_query( ctx->identity_keyswitch )==FD_KEYSWITCH_STATE_COMPLETED );
  FD_TEST( ctx->next_leader_slot==12UL );

  /* Without the floor it starts at the window after the highest completed
     slot. */
  unhalt( ctx );
  ctx->adopted_last_leader_slot = ULONG_MAX;
  ctx->failover_hist_adopted    = 1;
  request_switch( ctx, &b );
  during_housekeeping( ctx );
  run_after_credit( ctx );
  FD_TEST( ctx->next_leader_slot==4UL );

  /* Nothing seen leaves no leader slot, handle_epoch seeds it later. */
  unhalt( ctx );
  ctx->highest_completed_slot = 0UL;
  ctx->failover_hist_adopted  = 1;
  request_switch( ctx, &b );
  during_housekeeping( ctx );
  run_after_credit( ctx );
  FD_TEST( ctx->next_leader_slot==ULONG_MAX );

  unhalt( ctx );
  fixture_delete( ctx );
  FD_LOG_NOTICE(( "pass: the switch starts the leader search past the window the peer led" ));
}

/* test_doppelganger: our rank on a slot this machine never voted stops
   us voting and drops our rank, a slot we did vote changes nothing, and
   cert_has_signer finds our rank in a cert's signer set. */

static void
test_doppelganger( void ) {
  fd_pubkey_t a = pubkey( 0x41 );
  fd_pubkey_t b = pubkey( 0x42 );
  fd_votor_tile_t * ctx = fixture_new( &b );
  enable_failover( ctx, &b );
  build_epoch_info( &a, &b );
  start_consensus( ctx, 1UL );
  ctx->vote_authority = 1;
  install_ranks( ctx );
  FD_TEST( ctx->own_rank[ 1 ]==(ushort)1 && own_rank_for( ctx, 5UL )==(ushort)1 );

  /* Not our signature. */
  doppelganger_check( ctx, 5UL, 0 );
  FD_TEST( !ctx->doppelganger && ctx->vote_authority );

  /* Our rank on slot 5, which this machine never voted. */
  doppelganger_check( ctx, 5UL, 1 );
  FD_TEST( ctx->doppelganger==1 && ctx->vote_authority==0 );
  FD_TEST( ctx->own_rank[ 1 ]==USHORT_MAX && own_rank_for( ctx, 5UL )==USHORT_MAX );

  /* Slot 5 voted through an adopted history changes nothing. */
  ctx->doppelganger   = 0;
  ctx->vote_authority = 1;
  install_ranks( ctx );
  ag_hist_t hist[ 1 ];
  one_slot_hist( hist, 5UL, NULL );
  FD_TEST( !ag_votor_hist_adopt( ctx->votor, hist ) );
  FD_TEST( ag_votor_has_voted( ctx->votor, 5UL ) );
  doppelganger_check( ctx, 5UL, 1 );
  FD_TEST( !ctx->doppelganger && ctx->vote_authority );
  FD_TEST( ctx->own_rank[ 1 ]==(ushort)1 );

  /* A notar cert with rank 1 in its signer set. */
  ag_cert_t cert[ 1 ];
  fd_memset( cert, 0, sizeof(*cert) );
  cert->kind       = AG_CERT_KIND_NOTAR;
  cert->notar.slot = 5UL;
  fd_bls_set_insert( fd_bls_set_null( cert->notar.agg.set ), 1UL );
  FD_TEST(  cert_has_signer( cert, (ushort)1 ) );
  FD_TEST( !cert_has_signer( cert, (ushort)0 ) );
  FD_TEST( !cert_has_signer( cert, USHORT_MAX ) );

  fixture_delete( ctx );
  FD_LOG_NOTICE(( "pass: a vote from our identity we never cast stops us, a voted slot does not" ));
}

/* test_root_follow: a failover member follows replay's root, the pool
   finalizes the rooted block and the votor prunes below it, and without
   failover the sig is filtered before it is read. */

static void
test_root_follow( void ) {
  fd_pubkey_t a = pubkey( 0x41 );
  fd_pubkey_t b = pubkey( 0x42 );
  fd_votor_tile_t * ctx = fixture_new( &a );
  enable_failover( ctx, &a );
  build_epoch_info( &a, &b );
  start_consensus( ctx, 0UL );

  /* Chain 1..7 on the init slot, 16 live slots reach no further. */
  ag_block_id_t blocks[ 9 ];
  fd_memset( blocks, 0, sizeof(blocks) );
  for( ulong i=1UL; i<9UL; i++ ) {
    blocks[ i ].slot = i;
    fd_memset( blocks[ i ].hash, (int)(0xd0UL+i), sizeof(ag_block_hash_t) );
  }
  for( ulong i=1UL; i<8UL; i++ ) FD_TEST( ag_pool_add_block( ctx->pool, &blocks[ i ], &blocks[ i-1UL ], ctx->scratch.bad )==AG_POOL_SUCCESS );
  FD_TEST( ag_pool_add_block( ctx->pool, &blocks[ 8 ], &blocks[ 7 ], ctx->scratch.bad )==AG_POOL_ERR_SLOT_OUT_OF_BOUNDS );
  FD_TEST( ag_pool_finalized_slot( ctx->pool )==0UL );
  FD_TEST( ag_votor_first_unpruned_slot( ctx->votor )==0UL );

  fd_replay_message_t * replay = replay_in_msg();
  replay->root_advanced.slot = 4UL;
  fd_memcpy( replay->root_advanced.block_id.uc, blocks[ 4 ].hash, sizeof(fd_hash_t) );
  FD_TEST( !deliver_frag( ctx, IN_IDX_REPLAY, REPLAY_SIG_ROOT_ADVANCED, sizeof(fd_replay_message_t) ) );
  FD_TEST( ag_pool_finalized_slot( ctx->pool )==4UL );
  FD_TEST( fd_memeq( ag_pool_finalized_block_hash( ctx->pool ), blocks[ 4 ].hash, sizeof(ag_block_hash_t) ) );
  FD_TEST( ag_votor_highest_final_cert_slot( ctx->votor )==4UL );
  FD_TEST( ag_votor_first_unpruned_slot( ctx->votor )==0UL ); /* the window 8 below 4 is still 0 */

  /* Root 12, a block the pool never saw, the way a spare outside the
     mesh learns finality from replay alone. */
  replay = replay_in_msg();
  replay->root_advanced.slot = 12UL;
  fd_memset( replay->root_advanced.block_id.uc, 0xdc, sizeof(fd_hash_t) );
  FD_TEST( !deliver_frag( ctx, IN_IDX_REPLAY, REPLAY_SIG_ROOT_ADVANCED, sizeof(fd_replay_message_t) ) );
  FD_TEST( ag_pool_finalized_slot( ctx->pool )==12UL );
  FD_TEST( ag_votor_highest_final_cert_slot( ctx->votor )==12UL );
  FD_TEST( ag_votor_first_unpruned_slot( ctx->votor )==4UL );
  FD_TEST( out_seqs[ OUT_IDX_HIST ]==0UL ); /* roots publish no frame */

  /* Only a failover member reads the sig. */
  ctx->failover_enabled = 0;
  FD_TEST(  before_frag( ctx, IN_IDX_REPLAY, 0UL, REPLAY_SIG_ROOT_ADVANCED ) );
  ctx->failover_enabled = 1;
  FD_TEST( !before_frag( ctx, IN_IDX_REPLAY, 0UL, REPLAY_SIG_ROOT_ADVANCED ) );

  fixture_delete( ctx );
  FD_LOG_NOTICE(( "pass: the pool and the votor follow replay's root" ));
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  FD_LOG_NOTICE(( "footprints: pool %lu votor %lu quic client %lu quic server %lu mleaders %lu peers %lu contact_infos %lu",
                  ag_pool_footprint( TEST_SLOT_MAX ), ag_votor_footprint( TEST_SLOT_MAX ),
                  fd_quic_footprint( &quic_client_limits ), fd_quic_footprint( &quic_server_limits ),
                  fd_multi_epoch_leaders_footprint(), peers_footprint(), contact_infos_footprint() ));
  FD_TEST( ag_pool_footprint ( TEST_SLOT_MAX )         <=POOL_MEM_SZ          );
  FD_TEST( ag_votor_footprint( TEST_SLOT_MAX )         <=VOTOR_MEM_SZ         );
  FD_TEST( fd_quic_footprint( &quic_client_limits )    <=QUIC_CLIENT_MEM_SZ   );
  FD_TEST( fd_quic_footprint( &quic_server_limits )    <=QUIC_SERVER_MEM_SZ   );
  FD_TEST( fd_multi_epoch_leaders_footprint()          <=MLEADERS_MEM_SZ      );
  FD_TEST( peers_footprint()                           <=PEERS_MEM_SZ         );
  FD_TEST( contact_infos_footprint()                   <=CONTACT_INFOS_MEM_SZ );
  FD_TEST( fd_quic_align()<=4096UL );

  fd_memset( test_keypair, 0x42, 32UL );
  fd_sha512_t sha[ 1 ];
  fd_ed25519_public_from_private( test_keypair+32UL, test_keypair, sha );

  test_rank_voters_resets_total_stake();
  test_switch_completes_uninitialised();
  test_switch_closes_and_reconnects();
  test_switch_ranks_and_leader();
  test_gossip_dial_gated();
  test_drops_queued_votes();
  test_hist_frames();
  test_switch_watermark();
  test_adopt_reply();
  test_switch_gating();
  test_leader_floor();
  test_doppelganger();
  test_root_follow();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
