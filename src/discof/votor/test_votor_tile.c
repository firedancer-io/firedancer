#define FD_TILE_TEST 1
#include "fd_votor_tile.c"
#include "../../choreo/votor/test_ag_cert_builder.h"
#include "../../ballet/ed25519/fd_ed25519.h"

#define TEST_VOTER_MAX (4UL)

/* An ag_epoch_info_t is nearly 300 KiB, too big for the stack. */

static ag_epoch_info_t epoch_info_mem;

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
  ag_epoch_info_t *      epoch_info = &epoch_info_mem;

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

static fd_votor_tile_t ack_ctx;
static fd_quic_conn_t  ack_conn[ 2 ];

static void
test_quic_client_ack_range( void ) {
  fd_votor_tile_t * ctx = &ack_ctx;
  for( ulong i=0UL; i<REWARD_VOTE_MAX; i++ ) ctx->reward_votes[ i ].slot = ULONG_MAX;

  /* ACKs count only on the conn the vote was sent on. */

  reward_vote_t * rv = &ctx->reward_votes[ 100UL%REWARD_VOTE_MAX ];
  rv->slot         = 100UL;
  rv->tx_cnt       = 2UL;
  rv->conn         = &ack_conn[ 0 ];
  rv->pkt_num[ 0 ] = 7UL;
  rv->pkt_num[ 1 ] = 12UL;
  rv->pkt_num[ 2 ] = ULONG_MAX;
  rv->pkt_num[ 3 ] = ULONG_MAX;

  quic_client_ack_range( &ack_conn[ 1 ], 0UL, 20UL, ctx );
  FD_TEST( rv->slot==100UL );

  quic_client_ack_range( &ack_conn[ 0 ], 8UL, 11UL, ctx );
  FD_TEST( rv->slot==100UL );

  quic_client_ack_range( &ack_conn[ 0 ], 7UL, 7UL, ctx );
  FD_TEST( rv->slot==ULONG_MAX );

  quic_client_ack_range( &ack_conn[ 0 ], 0UL, 20UL, ctx );
  FD_TEST( rv->slot==ULONG_MAX );

  /* A new vote in the same entry does not inherit the stale sends. */

  rv->slot   = 100UL+REWARD_VOTE_MAX;
  rv->tx_cnt = 0UL;
  quic_client_ack_range( &ack_conn[ 0 ], 0UL, 20UL, ctx );
  FD_TEST( rv->slot==100UL+REWARD_VOTE_MAX );

  /* An entry whose conn was cleared on reconnect is ignored. */

  rv->tx_cnt = 1UL;
  rv->conn   = NULL;
  quic_client_ack_range( &ack_conn[ 0 ], 0UL, 20UL, ctx );
  FD_TEST( rv->slot==100UL+REWARD_VOTE_MAX );
}

static void
test_rank_voters_bls_keys( void ) {
  fd_vote_stake_weight_t stakes[ TEST_VOTER_MAX ];
  ag_epoch_info_t *      epoch_info = &epoch_info_mem;

  /* Ranked by descending stake: rank r is stakes[2-r]. */

  build_stakes( stakes, 3UL, 10UL );
  rank_voters( epoch_info, stakes, 3UL );
  for( ulong rank=0UL; rank<3UL; rank++ ) {
    uchar const * bls_key = stakes[ 2UL-rank ].bls_key;
    FD_TEST( !memcmp( epoch_info->validators[ rank ].bls_key, bls_key, sizeof(ag_bls_key_t) ) );
    fd_bls_pub_t pub; FD_TEST( !fd_bls_pub_de( &pub, bls_key, FD_BLS_PUB_COMPRESSED_SZ ) );
    FD_TEST( blst_p1_is_equal( ag_epoch_info_pubkey( epoch_info, rank ), &pub ) );
  }
}

/* Fills bls_keys[0,cnt) from secret keys memset to 7, 8, ... */

static void
build_bls_keys( ag_bls_key_t * bls_keys,
                fd_bls_sec_t * secs,
                fd_bls_pub_t * pubs,
                ulong          cnt ) {
  for( ulong i=0UL; i<cnt; i++ ) {
    memset( &secs[i], (int)( i + 7UL ), sizeof(fd_bls_sec_t) );
    fd_bls_sec_to_pub( &secs[i], &pubs[i] );
    blst_p1_compress( bls_keys[i], &pubs[i] );
  }
}

/* Maps bls_keys[0] to our identity and bls_keys[i] to authorized voter
   i-1, as load_keys does. */

static void
init_keys( fd_votor_tile_t * ctx,
           auth_vtr_t *      auth_vtr_mem,
           ag_bls_key_t *    bls_keys,
           ulong             cnt ) {
  ctx->auth_vtr = auth_vtr_join( auth_vtr_new( auth_vtr_mem ) );
  for( ulong i=0UL; i<cnt; i++ ) {
    auth_vtr_key_t bls_key; memcpy( bls_key.uc, bls_keys[i], sizeof(ag_bls_key_t) );
    auth_vtr_t * auth_vtr = auth_vtr_insert( ctx->auth_vtr, bls_key );
    auth_vtr->paths_idx = i-1UL; /* ULONG_MAX for the identity */
  }
}

/* Returns the paths_idx mapped to bls_key, or LONG_MAX if none. */

static ulong
paths_idx_of( fd_votor_tile_t const * ctx,
              ag_bls_key_t            bls_key ) {
  auth_vtr_key_t key; memcpy( key.uc, bls_key, sizeof(ag_bls_key_t) );
  auth_vtr_t const * auth_vtr = auth_vtr_query_const( ctx->auth_vtr, key, NULL );
  return auth_vtr ? auth_vtr->paths_idx : LONG_MAX;
}

static void
test_load_keys( int identity_is_voter ) {
  static fd_votor_tile_t ctx;
  static fd_topo_tile_t  tile;
  static auth_vtr_t      auth_vtr_mem[ 1UL<<AUTH_VTR_LG_SLOT_CNT ];
  static uchar request_mcache_mem [ FD_MCACHE_FOOTPRINT( 128UL, 0UL ) ] __attribute__((aligned(FD_MCACHE_ALIGN)));
  static uchar response_mcache_mem[ FD_MCACHE_FOOTPRINT( 128UL, 0UL ) ] __attribute__((aligned(FD_MCACHE_ALIGN)));
  static uchar request_data[ sizeof(ulong) ] __attribute__((aligned(FD_CHUNK_ALIGN)));
  static uchar response_data[ 17UL*FD_CHUNK_SZ ] __attribute__((aligned(FD_CHUNK_ALIGN)));

  ag_bls_key_t bls_keys[17];
  fd_bls_sec_t secs[17];
  fd_bls_pub_t pubs[17];
  build_bls_keys( bls_keys, secs, pubs, 17UL );
  if( identity_is_voter ) memcpy( bls_keys[4], bls_keys[0], sizeof(ag_bls_key_t) ); /* authorized voter 3 */
  ctx.auth_vtr = auth_vtr_join( auth_vtr_new( auth_vtr_mem ) );
  tile.votor.authorized_voter_paths_cnt = 16UL;

  fd_keyguard_client_t * client = ctx.keyguard_client;
  memset( client, 0, sizeof(fd_keyguard_client_t) );
  client->request        = fd_mcache_join( fd_mcache_new( request_mcache_mem, 128UL, 0UL, 0UL ) );
  client->response       = fd_mcache_join( fd_mcache_new( response_mcache_mem, 128UL, 0UL, 0UL ) );
  FD_TEST( client->request && client->response );
  client->request_depth  = 128UL;
  client->response_depth = 128UL;
  client->request_mem    = (fd_wksp_t *)request_data;
  client->response_mem   = (fd_wksp_t *)response_data;
  client->request_mtu    = sizeof(request_data);
  client->response_mtu   = FD_KEYGUARD_BLS_PUBKEY_SZ;
  client->response_wmark = 16UL;

  /* Prepublish public-key responses.  The configured key paths are
     empty: load_keys must query the signer without opening keyfiles. */
  for( ulong i=0UL; i<17UL; i++ ) {
    memcpy( response_data+i*FD_CHUNK_SZ, bls_keys[i], sizeof(ag_bls_key_t) );
    fd_mcache_publish( client->response, 128UL, i, FD_KEYGUARD_SIGN_TYPE_BLS_PUBKEY, i, sizeof(ag_bls_key_t), 0UL, 0UL, 0UL );
  }
  load_keys( &ctx, tile.votor.authorized_voter_paths_cnt );
  FD_TEST( client->request_seq==17UL && client->response_seq==17UL );
  FD_TEST( paths_idx_of( &ctx, bls_keys[0] )==ULONG_MAX );
  for( ulong i=1UL; i<17UL; i++ ) {
    if( identity_is_voter && i==4UL ) continue;
    FD_TEST( paths_idx_of( &ctx, bls_keys[i] )==i-1UL );
  }
  for( ulong i=0UL; i<17UL; i++ ) {
    fd_frag_meta_t const * request = client->request+fd_mcache_line_idx( i, 128UL );
    FD_TEST( request->sig==FD_KEYGUARD_SIGN_TYPE_BLS_PUBKEY );
    FD_TEST( request->sz==sizeof(ulong) );
  }
  FD_TEST( FD_LOAD( ulong, request_data )==15UL );
}

static void
test_own_bls_key( void ) {
  static fd_votor_tile_t ctx;
  static auth_vtr_t      auth_vtr_mem[ 1UL<<AUTH_VTR_LG_SLOT_CNT ];
  fd_vote_stake_weight_t stakes[ TEST_VOTER_MAX ];
  ag_epoch_info_t *      epoch_info = &epoch_info_mem;

  build_stakes( stakes, 3UL, 10UL );
  rank_voters( epoch_info, stakes, 3UL );
  ag_bls_key_t bls_keys[2];
  memcpy( bls_keys[0], epoch_info->validators[0].bls_key, sizeof(ag_bls_key_t) );
  memcpy( bls_keys[1], epoch_info->validators[1].bls_key, sizeof(ag_bls_key_t) );
  init_keys( &ctx, auth_vtr_mem, bls_keys, 2UL );

  FD_TEST( own_bls_key( &ctx, epoch_info, USHORT_MAX )==NULL                              );
  FD_TEST( own_bls_key( &ctx, epoch_info, 0          )==epoch_info->validators[0].bls_key );
  FD_TEST( own_bls_key( &ctx, epoch_info, 1          )==epoch_info->validators[1].bls_key );
  FD_TEST( own_bls_key( &ctx, epoch_info, 2          )==NULL                              );
}

static void
test_sign_bls_request( void ) {
  static fd_votor_tile_t ctx;
  static auth_vtr_t      auth_vtr_mem[ 1UL<<AUTH_VTR_LG_SLOT_CNT ];
  static uchar request_mcache_mem [ FD_MCACHE_FOOTPRINT( 128UL, 0UL ) ] __attribute__((aligned(FD_MCACHE_ALIGN)));
  static uchar response_mcache_mem[ FD_MCACHE_FOOTPRINT( 128UL, 0UL ) ] __attribute__((aligned(FD_MCACHE_ALIGN)));
  static uchar request_data [ AG_VOTE_SIGNING_SER_MAX ] __attribute__((aligned(FD_CHUNK_ALIGN)));
  static uchar response_data[ FD_BLS_SIG_SZ ] __attribute__((aligned(FD_CHUNK_ALIGN)));

  fd_keyguard_client_t * client = ctx.keyguard_client;
  client->request        = fd_mcache_join( fd_mcache_new( request_mcache_mem, 128UL, 0UL, 0UL ) );
  client->response       = fd_mcache_join( fd_mcache_new( response_mcache_mem, 128UL, 0UL, 0UL ) );
  FD_TEST( client->request && client->response );
  client->request_depth  = 128UL;
  client->response_depth = 128UL;
  client->request_mem    = (fd_wksp_t *)request_data;
  client->response_mem   = (fd_wksp_t *)response_data;
  client->request_mtu    = sizeof(request_data);
  client->response_mtu   = sizeof(response_data);

  /* The identity's key, then authorized voters 0, 1 and 2. */

  ag_bls_key_t bls_keys[4];
  fd_bls_sec_t secs[4];
  fd_bls_pub_t pubs[4];
  build_bls_keys( bls_keys, secs, pubs, 4UL );
  init_keys( &ctx, auth_vtr_mem, bls_keys, 4UL );

  for( ulong i=0UL; i<4UL; i++ ) {
    ulong request_sig = FD_KEYGUARD_SIGN_TYPE_BLS;
    if( i ) request_sig |= (1UL<<32) | ((i-1UL)<<33);

    for( uchar tag=1U; tag<=5U; tag++ ) {
      uchar payload[43];
      memset( payload, 0x42, sizeof(payload) );
      payload[0] = tag;
      ulong payload_sz = ( tag==1U || tag==4U ) ? 43UL : 11UL;
      ulong seq        = client->request_seq;

      /* Prepublish the signer's response so the blocking callback can
         run here.  Inspect the request it publishes below. */
      fd_bls_sig_t expected_sig;
      fd_bls_sec_sign( &secs[i], payload, payload_sz, &expected_sig );
      fd_bls_sig_ser( &expected_sig, response_data );
      fd_mcache_publish( client->response, 128UL, seq, request_sig, 0UL, FD_BLS_SIG_SZ, 0UL, 0UL, 0UL );

      fd_bls_sig_t sig;
      sign_bls( &ctx, &sig, bls_keys[i], payload, payload_sz );
      fd_frag_meta_t const * request = client->request+fd_mcache_line_idx( seq, 128UL );
      FD_TEST( fd_frag_meta_seq_query( request )==seq );
      FD_TEST( request->sig==request_sig );
      FD_TEST( request->sz==payload_sz );
      FD_TEST( !memcmp( request_data, payload, payload_sz ) );
      FD_TEST( fd_bls_agg_verify( payload, payload_sz, &pubs[i], &sig ) );
    }
  }
}

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
static auth_vtr_t      auth_vtr_mem[ 1UL<<AUTH_VTR_LG_SLOT_CNT ];
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

/* The sign tile answers the BLS public key query an unhalt makes over
   these channels.  The fixture loads no authorized voters, so each
   unhalt asks for the identity's key alone. */

static uchar kg_request_mcache [ FD_MCACHE_FOOTPRINT( 128UL, 0UL ) ] __attribute__((aligned(FD_MCACHE_ALIGN)));
static uchar kg_response_mcache[ FD_MCACHE_FOOTPRINT( 128UL, 0UL ) ] __attribute__((aligned(FD_MCACHE_ALIGN)));
static uchar kg_request_data [ sizeof(ulong)             ] __attribute__((aligned(FD_CHUNK_ALIGN)));
static uchar kg_response_data[ FD_KEYGUARD_BLS_PUBKEY_SZ ] __attribute__((aligned(FD_CHUNK_ALIGN)));

/* The sign tile's BLS key for an identity in no epoch, the junk
   identity of a failover standby for instance. */

static ag_bls_key_t junk_bls_key;

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
   the topology.  The QUIC config lines are copied from the tile. */

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
  ctx->ns_per_slot            = TEST_NS_PER_SLOT;
  ctx->highest_unotar_final_slot = ULONG_MAX;
  fd_clock_tile_init( ctx->clock );
  ctx->highest_completed_slot = 0UL;

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
  /* No failover links, as unprivileged_init sets it up. */
  ctx->vote_authority           = 1;
  ctx->hist_out_idx             = ULONG_MAX;
  ctx->failov_out_idx           = ULONG_MAX;
  ctx->last_leader_slot         = ULONG_MAX;
  ctx->adopted_last_leader_slot = ULONG_MAX;
  ctx->last_vote_slot           = ULONG_MAX;
  ctx->root_slot                = ULONG_MAX;
  ctx->own_rank[ 0 ]            = USHORT_MAX;
  ctx->own_rank[ 1 ]            = USHORT_MAX;
  ctx->own_rank[ 2 ]            = USHORT_MAX;

  ctx->auth_vtr = auth_vtr_join( auth_vtr_new( auth_vtr_mem ) );
  FD_TEST( ctx->auth_vtr );
  fd_keyguard_client_t * client = ctx->keyguard_client;
  client->request        = fd_mcache_join( fd_mcache_new( kg_request_mcache,  128UL, 0UL, 0UL ) );
  client->response       = fd_mcache_join( fd_mcache_new( kg_response_mcache, 128UL, 0UL, 0UL ) );
  FD_TEST( client->request && client->response );
  client->request_depth  = 128UL;
  client->response_depth = 128UL;
  client->request_mem    = (fd_wksp_t *)kg_request_data;
  client->response_mem   = (fd_wksp_t *)kg_response_data;
  client->request_mtu    = sizeof(kg_request_data);
  client->response_mtu   = FD_KEYGUARD_BLS_PUBKEY_SZ;

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
   test_ag_votor builds its epoch.  own_rank_in matches on the identity
   keys. */

static fd_bls_sec_t        sk[ 2 ];
static ag_validator_info_t infos[ 2 ];

static void
build_epoch_info( fd_pubkey_t const * a,
                  fd_pubkey_t const * b ) {
  fd_pubkey_t const * keys[ 2 ] = { a, b };
  for( ulong i=0UL; i<2UL; i++ ) {
    fd_memset( &sk[i], (int)(i*7UL+1UL), FD_BLS_SEC_SZ );
    fd_memset( &infos[i], 0, sizeof(ag_validator_info_t) );
    infos[i].id    = i;
    infos[i].stake = 1UL;
    bls_key_from_sec( infos[i].bls_key, &sk[i] );
    fd_memcpy( infos[i].id_key, keys[i]->uc, sizeof(ag_id_key_t) );
  }
  epoch_info_build( &epoch_info_mem, infos, 2UL );
}

/* The BLS public key of the last vote signed, checked against the key
   the votor should hold. */

static ag_bls_key_t signed_with;

static void
recording_sign_fn( void *         ctx,
                   fd_bls_sig_t * sig,
                   uchar const *  public_key,
                   uchar const *  msg,
                   ulong          msg_sz ) {
  fd_memcpy( signed_with, public_key, sizeof(ag_bls_key_t) );
  sec_sign_fn( ctx, sig, public_key, msg, msg_sz );
}

/* Bring consensus up at slot 0 as rank own_rank of the built epoch,
   with that rank's BLS key as the identity's, as load_keys enters it.
   The votor's clock starts at now, so a case that runs after_credit on
   the wallclock passes it the wallclock to keep the skip timeouts from
   coming due underneath it. */

static void
start_consensus_at( fd_votor_tile_t * ctx,
                    ulong             own_rank,
                    long              now ) {
  auth_vtr_key_t bls_key; fd_memcpy( bls_key.uc, infos[ own_rank ].bls_key, sizeof(ag_bls_key_t) );
  auth_vtr_insert( ctx->auth_vtr, bls_key )->paths_idx = ULONG_MAX;
  ctx->curr_epoch_info = &epoch_info_mem;
  ctx->curr_epoch_slot = 0UL;
  ag_pool_advance_epoch ( ctx->pool, &epoch_info_mem, own_rank, 0UL );
  ag_votor_advance_epoch( ctx->votor, TEST_NS_PER_SLOT, own_rank, 0UL, own_bls_key( ctx, &epoch_info_mem, (ushort)own_rank ) );
  ag_pool_init ( ctx->pool, 0UL );
  ag_votor_init( ctx->votor, 0UL, now, TEST_NS_PER_SLOT, TEST_SHRED_VERSION, recording_sign_fn, &sk[ own_rank ] );
  ctx->shred_version = TEST_SHRED_VERSION;
  ctx->init          = 1;
}

static void
start_consensus( fd_votor_tile_t * ctx,
                 ulong             own_rank ) {
  start_consensus_at( ctx, own_rank, 0L );
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

/* Unhalt with the sign tile holding the identity whose BLS key is
   bls_key.  The tile asks for it and enters it as the identity's. */

static void
unhalt( fd_votor_tile_t * ctx,
        ag_bls_key_t      bls_key ) {
  fd_keyguard_client_t * client      = ctx->keyguard_client;
  ulong                  request_seq = client->request_seq;
  fd_memcpy( kg_response_data, bls_key, sizeof(ag_bls_key_t) );
  fd_mcache_publish( client->response, 128UL, client->response_seq, FD_KEYGUARD_SIGN_TYPE_BLS_PUBKEY, 0UL, sizeof(ag_bls_key_t), 0UL, 0UL, 0UL );

  fd_keyswitch_state( ctx->identity_keyswitch, FD_KEYSWITCH_STATE_UNHALT_PENDING );
  during_housekeeping( ctx );
  FD_TEST( !ctx->halt_signing );
  FD_TEST( fd_keyswitch_state_query( ctx->identity_keyswitch )==FD_KEYSWITCH_STATE_COMPLETED );
  FD_TEST( client->request_seq==request_seq+1UL );
  FD_TEST( FD_LOAD( ulong, kg_request_data )==ULONG_MAX );
  FD_TEST( paths_idx_of( ctx, bls_key )==ULONG_MAX );
}

/* Unhalt with the sign tile holding the BLS key of the identity we
   switched to, its key in the built epoch when it has a rank there, else
   the junk key. */

static void
unhalt_id( fd_votor_tile_t * ctx ) {
  uchar * bls_key = junk_bls_key;
  if( FD_LIKELY( ctx->curr_epoch_info ) ) {
    for( ulong i=0UL; i<2UL; i++ ) if( fd_memeq( infos[ i ].id_key, ctx->id_key.uc, 32UL ) ) bls_key = infos[ i ].bls_key;
  }
  unhalt( ctx, bls_key );
}

/* Fire every timeout of the first window, which builds a skip vote for
   slots 1..3 wherever we hold a rank and a BLS key. */

static void
fire_first_window( fd_votor_tile_t * ctx ) {
  ag_event_timeout_t timeout;
  while( ag_votor_poll_timeout_event( ctx->votor, TEST_WINDOW_ELAPSED_NS, &timeout ) ) ag_votor_handle_timeout_event( ctx->votor, &timeout );
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

/* Make the fixture a failover member that booted under its current
   key, with the hist and failov outs and the replay and failov in-links
   wired the way unprivileged_init does it.  Nothing else changes, so
   the plain cases never see these links. */

static void
enable_failover( fd_votor_tile_t * ctx ) {
  ctx->failover_enabled = 1;
  ctx->boot_id_key      = ctx->id_key;

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
   sits at chunk 0 of that link's buffer.  Returns before_frag's result,
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
   when one is given, and no vote bound. */

static void
one_slot_hist( ag_hist_t *   hist,
               ulong         slot,
               uchar const * notar_hash ) {
  fd_memset( hist, 0, sizeof(*hist) );
  hist->anchor           = 0UL;
  hist->last_leader_slot = ULONG_MAX;
  hist->vote_bound       = ULONG_MAX;
  hist->rec_cnt          = 1UL;
  hist->rec[ 0 ].slot    = slot;
  hist->rec[ 0 ].flags   = (uchar)( AG_HIST_FLAG_VOTED | fd_uint_if( !!notar_hash, AG_HIST_FLAG_VOTED_NOTAR, 0U ) );
  if( FD_LIKELY( notar_hash ) ) fd_memcpy( hist->rec[ 0 ].notar_hash, notar_hash, sizeof(ag_block_hash_t) );
}

/* Certs signed by both validators of the built epoch, which is all the
   stake.  The footer helpers write them the way a leader puts them in
   its block footer. */

static ag_cert_t
signed_notar_cert( ulong         slot,
                   uchar const * hash,
                   int           fast ) {
  ag_vote_notar_t votes[ 2 ];
  for( ulong i=0UL; i<2UL; i++ ) votes[ i ] = ag_vote_construct_notar( sec_sign_fn, &sk[ i ], infos[ i ].bls_key, slot, hash, (ushort)i, TEST_SHRED_VERSION ).notar;
  return fast ? cert_build_fast_final( votes, 2UL, &epoch_info_mem ) : cert_build_notar( votes, 2UL, &epoch_info_mem );
}

static void
footer_cert( fd_block_footer_cert_t * out,
             ulong                    slot,
             uchar const *            hash,
             fd_bls_agg_t const *     agg ) {
  out->slot = slot;
  if( FD_LIKELY( hash ) ) fd_memcpy( out->block_id.uc, hash, sizeof(fd_hash_t) );
  fd_bls_set_copy( out->signer_set, agg->set );
  blst_p2_compress( out->sig, &agg->sig );
}

static void
footer_fast_final( fd_block_footer_t * footer,
                   ulong               slot,
                   uchar const *       hash ) {
  ag_cert_t cert = signed_notar_cert( slot, hash, 1 );
  footer->has_fast_final_cert = 1;
  footer_cert( &footer->fast_final_cert, slot, hash, &cert.fast_final.agg );
}

static void
footer_final( fd_block_footer_t * footer,
              ulong               slot,
              uchar const *       hash ) {
  ag_vote_final_t votes[ 2 ];
  for( ulong i=0UL; i<2UL; i++ ) votes[ i ] = ag_vote_construct_final( sec_sign_fn, &sk[ i ], infos[ i ].bls_key, slot, (ushort)i, TEST_SHRED_VERSION ).final;
  ag_cert_t final = cert_build_final( votes, 2UL, &epoch_info_mem );
  ag_cert_t notar = signed_notar_cert( slot, hash, 0 );
  footer->has_final_cert = 1;
  footer_cert( &footer->final_cert, slot, NULL, &final.final.agg );
  footer_cert( &footer->notar_cert, slot, hash, &notar.notar.agg );
}

/* Replay completes slot on its parent, the block hash of each is its
   slot number repeated.  The footer is empty unless the caller fills it
   before delivering. */

static void
fill_block_hash( uchar * hash,
                 ulong   slot ) {
  fd_memset( hash, slot ? (int)(0xd0UL+slot) : 0, sizeof(ag_block_hash_t) );
}

static fd_replay_slot_completed_t *
completed_msg( ulong slot ) {
  fd_replay_slot_completed_t * completed = &replay_in_msg()->slot_completed;
  completed->slot        = slot;
  completed->parent_slot = slot-1UL;
  completed->root_slot   = ULONG_MAX;
  fill_block_hash( completed->block_id.uc,        slot     );
  fill_block_hash( completed->parent_block_id.uc, slot-1UL );
  return completed;
}

/* Runs after_credit enough times to take every pool event and vote the
   cases below queue up, one of each goes per call. */

static void
drain( fd_votor_tile_t * ctx ) {
  for( ulong i=0UL; i<32UL; i++ ) run_after_credit( ctx );
}

/* test_switch_no_bls_key_until_unhalt: the sign tile switches after
   votor, so from the switch to unhalt votor holds no BLS key and builds
   no vote.  Unhalt enters the new identity's key and drops the old. */

static void
test_switch_no_bls_key_until_unhalt( void ) {
  fd_pubkey_t a = pubkey( 0x41 );
  fd_pubkey_t b = pubkey( 0x42 );
  fd_votor_tile_t * ctx = fixture_new( &a );
  build_epoch_info( &a, &b );
  start_consensus( ctx, 0UL );
  FD_TEST( paths_idx_of( ctx, infos[ 0 ].bls_key )==ULONG_MAX );

  request_switch( ctx, &b );
  during_housekeeping( ctx );
  run_after_credit( ctx );
  FD_TEST( fd_keyswitch_state_query( ctx->identity_keyswitch )==FD_KEYSWITCH_STATE_COMPLETED );

  fire_first_window( ctx );
  ag_event_vote_t vote_event;
  FD_TEST( !ag_votor_poll_vote_event( ctx->votor, &vote_event ) );

  unhalt( ctx, infos[ 1 ].bls_key );
  FD_TEST( paths_idx_of( ctx, infos[ 0 ].bls_key )==LONG_MAX );

  fixture_delete( ctx );
  FD_LOG_NOTICE(( "pass: votor holds no BLS key between the switch and unhalt" ));
}

/* test_switch_votes_with_new_key: after unhalt votes have the new
   identity's rank and are signed with the BLS key the sign tile holds
   for it. */

static void
test_switch_votes_with_new_key( void ) {
  fd_pubkey_t a = pubkey( 0x41 );
  fd_pubkey_t b = pubkey( 0x42 );
  fd_votor_tile_t * ctx = fixture_new( &a );
  build_epoch_info( &a, &b );
  start_consensus( ctx, 0UL );

  request_switch( ctx, &b );
  during_housekeeping( ctx );
  run_after_credit( ctx );
  unhalt( ctx, infos[ 1 ].bls_key );

  fire_first_window( ctx );
  for( ulong slot=1UL; slot<AG_SLOTS_PER_WINDOW; slot++ ) {
    ag_event_vote_t vote_event;
    FD_TEST( ag_votor_poll_vote_event( ctx->votor, &vote_event ) );
    FD_TEST( vote_event.vote.kind==AG_VOTE_KIND_SKIP && ag_vote_slot( &vote_event.vote )==slot );
    FD_TEST( ag_vote_rank( &vote_event.vote )==(ushort)1 );
  }
  FD_TEST( fd_memeq( signed_with, infos[ 1 ].bls_key, sizeof(ag_bls_key_t) ) );

  fixture_delete( ctx );
  FD_LOG_NOTICE(( "pass: after unhalt votes have the new rank and BLS key" ));
}

/* test_demote_builds_no_vote: a switch to an identity in no epoch, the
   junk identity under failover, votes nothing from the switch on. */

static void
test_demote_builds_no_vote( void ) {
  fd_pubkey_t a    = pubkey( 0x41 );
  fd_pubkey_t b    = pubkey( 0x42 );
  fd_pubkey_t junk = pubkey( 0x4a );
  fd_votor_tile_t * ctx = fixture_new( &a );
  build_epoch_info( &a, &b );
  start_consensus( ctx, 0UL );

  request_switch( ctx, &junk );
  during_housekeeping( ctx );
  run_after_credit( ctx );
  unhalt( ctx, junk_bls_key );
  FD_TEST( paths_idx_of( ctx, infos[ 0 ].bls_key )==LONG_MAX );

  fire_first_window( ctx );
  ag_event_vote_t vote_event;
  FD_TEST( !ag_votor_poll_vote_event( ctx->votor, &vote_event ) );

  fixture_delete( ctx );
  FD_LOG_NOTICE(( "pass: a switch to the junk identity votes nothing" ));
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

  unhalt_id( ctx );
  FD_TEST( fd_pubkey_eq( &ctx->id_key, &new_key ) );

  fixture_delete( ctx );
  FD_LOG_NOTICE(( "pass: an uninitialised tile completes a switch and installs the key" ));
}

/* test_switch_closes_and_reconnects: the halt closes every peer conn
   and unhalt dials every ranked peer with a contact info again. */

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

  unhalt_id( ctx );
  FD_TEST( peer1->tx_conn && peer2->tx_conn && !peer3->tx_conn );
  FD_TEST( !peer1->rx_conn && !peer2->rx_conn );
  /* A freed conn slot can be reused, so we check for a fresh handshake
     rather than a new pointer. */
  FD_TEST( peer1->tx_conn->state==FD_QUIC_CONN_STATE_HANDSHAKE );
  FD_TEST( peer2->tx_conn->state==FD_QUIC_CONN_STATE_HANDSHAKE );
  FD_TEST( fd_pubkey_eq( fd_quic_conn_get_context( peer1->tx_conn ), &p1 ) );
  FD_TEST( fd_pubkey_eq( fd_quic_conn_get_context( peer2->tx_conn ), &p2 ) );

  fixture_delete( ctx );
  FD_LOG_NOTICE(( "pass: the halt closes every conn and unhalt dials the ranked peers again" ));
}

/* test_switch_ranks_and_leader: start as A, switch to B, the slot state
   created before the switch gets B's rank and one created after starts
   with it.  A key in no epoch is unranked, and the old identity's leader
   slot is dropped. */

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
  ctx->next_leader_slot       = 8UL;
  ctx->highest_completed_slot = 1UL;

  request_switch( ctx, &b );
  during_housekeeping( ctx );
  run_after_credit( ctx );
  FD_TEST( fd_keyswitch_state_query( ctx->identity_keyswitch )==FD_KEYSWITCH_STATE_COMPLETED );
  FD_TEST( fd_pubkey_eq( &ctx->id_key, &b ) );
  FD_TEST( state1->own_rank==1UL );
  FD_TEST( ctx->next_leader_slot==ULONG_MAX );
  FD_TEST( ctx->init ); /* consensus state survives the switch */

  /* A slot state made under B. */
  ag_block_id_t block2 = { .slot = 2UL };
  fd_memset( block2.hash, 0xa2, sizeof(ag_block_hash_t) );
  FD_TEST( ag_pool_add_block( ctx->pool, &block2, &block1, ctx->scratch.bad )==AG_POOL_SUCCESS );
  ag_slot_state_t const * state2 = ag_pool_slot_state( ctx->pool, 2UL );
  FD_TEST( state2 && state2->own_rank==1UL );

  /* C is in no epoch, so both live slot states go unranked. */
  unhalt_id( ctx );
  request_switch( ctx, &c );
  during_housekeeping( ctx );
  run_after_credit( ctx );
  FD_TEST( fd_keyswitch_state_query( ctx->identity_keyswitch )==FD_KEYSWITCH_STATE_COMPLETED );
  FD_TEST( fd_pubkey_eq( &ctx->id_key, &c ) );
  FD_TEST( state1->own_rank==(ulong)USHORT_MAX );
  FD_TEST( state2->own_rank==(ulong)USHORT_MAX );

  /* Switching back to A restores rank 0. */
  unhalt_id( ctx );
  request_switch( ctx, &a );
  during_housekeeping( ctx );
  run_after_credit( ctx );
  FD_TEST( state1->own_rank==0UL && state2->own_rank==0UL );

  unhalt_id( ctx );
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

  unhalt_id( ctx );
  FD_TEST( !ag_votor_poll_vote_event( ctx->votor, &vote_event ) );

  fixture_delete( ctx );
  FD_LOG_NOTICE(( "pass: the completion drops every vote queued before the halt" ));
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
  enable_failover( ctx );
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
  ag_event_replay_t completed = { .slot = 1UL, .block_info = { .parent = block0 } };
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

  /* A fast final cert on block 3 grants parent ready for window 4.  A
     cert alone publishes nothing.  The pool events and the notar vote
     queued for slot 2 go first, with no leader slot yet. */
  ag_block_id_t block3 = { .slot = 3UL };
  fd_memset( block3.hash, 0xb3, sizeof(ag_block_hash_t) );
  FD_TEST( ag_pool_add_block( ctx->pool, &block3, &block2, ctx->scratch.bad )==AG_POOL_SUCCESS );
  ag_cert_t cert = signed_notar_cert( 3UL, block3.hash, 1 );
  FD_TEST( ag_pool_add_cert( ctx->pool, &cert, ctx->scratch.bad )==AG_POOL_SUCCESS );
  FD_TEST( ag_pool_finalized_slot( ctx->pool )==3UL );
  FD_TEST( ag_pool_wait_for_parent_ready( ctx->pool, 4UL ).slot==3UL );
  FD_TEST( out_seqs[ OUT_IDX_HIST ]==2UL );
  drain( ctx );
  FD_TEST( out_seqs[ OUT_IDX_HIST ]==3UL );
  FD_TEST( hist_frame( 2UL )->has_vote==1 && ctx->last_vote_slot==2UL );
  FD_TEST( ag_votor_highest_final_cert_slot( ctx->votor )==3UL );

  /* With 4 as our next leader slot, after_credit publishes LEADER and
     one more frame that holds the window. */
  ctx->next_leader_slot = 4UL;
  ulong votor_seq = out_seqs[ OUT_IDX_VOTOR ];
  run_after_credit( ctx );
  FD_TEST( ctx->last_leader_slot==4UL );
  FD_TEST( ctx->next_leader_slot==ULONG_MAX ); /* no schedule loaded */
  FD_TEST( out_seqs[ OUT_IDX_VOTOR ]>votor_seq );
  FD_TEST( out_mcache[ OUT_IDX_VOTOR ][ (out_seqs[ OUT_IDX_VOTOR ]-1UL) & (OUT_DEPTH-1UL) ].sig==FD_VOTOR_SIG_LEADER );
  FD_TEST( out_seqs[ OUT_IDX_HIST ]==4UL );
  frame = hist_frame( 3UL );
  FD_TEST( frame->has_vote==0 );
  FD_TEST( frame->hist.last_leader_slot==4UL && frame->hist.anchor==3UL );
  FD_TEST( frame->replay_slot==2UL && frame->root_slot==0UL );

  fixture_delete( ctx );
  FD_LOG_NOTICE(( "pass: a frame follows every own vote, completed slot and LEADER" ));
}

/* test_switch_watermark: the completion publishes one last frame, with
   a notar queued before the halt marked as never sent, and hands the
   failover tile the sequence after it as the watermark. */

static void
test_switch_watermark( void ) {
  fd_pubkey_t a = pubkey( 0x41 );
  fd_pubkey_t b = pubkey( 0x42 );
  fd_votor_tile_t * ctx = fixture_new( &a );
  enable_failover( ctx );
  build_epoch_info( &a, &b );
  start_consensus( ctx, 0UL );
  ctx->failover_hist_adopted = 1;

  ag_block_id_t block0 = { .slot = 0UL };
  ag_event_replay_t completed = { .slot = 1UL, .block_info = { .parent = block0 } };
  fd_memset( completed.block_info.hash, 0xb1, sizeof(ag_block_hash_t) );
  ag_votor_handle_replay_event( ctx->votor, &completed );

  FD_TEST( out_seqs[ OUT_IDX_HIST ]==0UL );
  request_switch( ctx, &b );
  during_housekeeping( ctx );
  run_after_credit( ctx );
  FD_TEST( fd_keyswitch_state_query( ctx->identity_keyswitch )==FD_KEYSWITCH_STATE_COMPLETED );
  FD_TEST( out_seqs[ OUT_IDX_HIST ]==1UL );
  FD_TEST( ctx->identity_keyswitch->result==out_seqs[ OUT_IDX_HIST ] );
  fd_votor_hist_msg_t const * frame = hist_frame( 0UL );
  FD_TEST( frame->has_vote==0 && frame->hist.anchor==0UL );
  ag_hist_rec_t const * rec = hist_rec( &frame->hist, 1UL );
  FD_TEST( rec && rec->flags==(AG_HIST_FLAG_VOTED|AG_HIST_FLAG_BAD_WINDOW) );
  FD_TEST( ctx->last_vote_slot==ULONG_MAX );

  /* Nothing more goes out while halted, the watermark stays put. */
  run_after_credit( ctx );
  FD_TEST( out_seqs[ OUT_IDX_HIST ]==1UL && ctx->identity_keyswitch->result==1UL );

  unhalt_id( ctx );
  fixture_delete( ctx );
  FD_LOG_NOTICE(( "pass: the switch publishes a last frame and reports the sequence after it" ));
}

/* test_adopt_reply: an adoption request on failov_votor is answered on
   votor_failov under the request's sequence number.  A good history is
   taken, one older than the votes we sent is stale, garbage fails to
   decode, a serialized history with no records is invalid, and an empty
   request with its bound starts from an empty history once consensus
   is up.  A history anchored past our replayed slots is refused until
   replay reaches the anchor. */

static void
test_adopt_reply( void ) {
  fd_pubkey_t a = pubkey( 0x41 );
  fd_pubkey_t b = pubkey( 0x42 );
  fd_votor_tile_t * ctx = fixture_new( &a );
  enable_failover( ctx );
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
  FD_TEST( reply->vote_slot==1UL && reply->vote_bound==ULONG_MAX );
  FD_TEST( reply->root==ag_votor_highest_final_cert_slot( ctx->votor ) && reply->root==0UL );
  FD_TEST( ctx->failover_hist_adopted==1 );
  FD_TEST( ctx->adopted_last_leader_slot==ULONG_MAX );
  FD_TEST( ag_votor_has_voted( ctx->votor, 1UL ) );

  /* A tip below the last vote this identity sent from here. */
  ctx->last_vote_slot = 5UL;
  FD_TEST( !deliver_frag( ctx, IN_IDX_FAILOV, 78UL, sz ) );
  reply = adopt_reply( 1UL, 78UL );
  FD_TEST( reply->result==FD_VOTOR_ADOPT_ERR_STALE );
  FD_TEST( reply->root==ULONG_MAX && reply->vote_slot==ULONG_MAX && reply->vote_bound==ULONG_MAX );

  /* Bytes that are no history. */
  fd_memset( failov_in_mem, 0xff, 32UL );
  FD_TEST( !deliver_frag( ctx, IN_IDX_FAILOV, 79UL, 32UL ) );
  reply = adopt_reply( 2UL, 79UL );
  FD_TEST( reply->result==FD_VOTOR_ADOPT_ERR_DECODE );

  /* A serialized history with nothing in it. */
  hist->rec_cnt = 0UL;
  FD_TEST( !ag_hist_ser( hist, failov_in_mem, FAILOV_IN_MEM_SZ, &sz ) );
  FD_TEST( !deliver_frag( ctx, IN_IDX_FAILOV, 80UL, sz ) );
  reply = adopt_reply( 3UL, 80UL );
  FD_TEST( reply->result==FD_VOTOR_ADOPT_ERR_INVALID );

  /* An empty request before consensus is up is asked again. */
  ctx->failover_hist_adopted = 0;
  ctx->init                  = 0;
  FD_STORE( ulong, failov_in_mem, 9UL );
  FD_TEST( !deliver_frag( ctx, IN_IDX_FAILOV, 81UL, FD_VOTOR_ADOPT_EMPTY_SZ ) );
  reply = adopt_reply( 4UL, 81UL );
  FD_TEST( reply->result==FD_VOTOR_ADOPT_ERR_UNREPLAYED );
  FD_TEST( !ctx->failover_hist_adopted );

  /* The same once it is up, our own marks stay. */
  ctx->init = 1;
  FD_TEST( !deliver_frag( ctx, IN_IDX_FAILOV, 82UL, FD_VOTOR_ADOPT_EMPTY_SZ ) );
  reply = adopt_reply( 5UL, 82UL );
  FD_TEST( reply->result==FD_VOTOR_ADOPT_SUCCESS );
  FD_TEST( reply->root==0UL && reply->vote_slot==ULONG_MAX && reply->vote_bound==9UL );
  FD_TEST( ctx->failover_hist_adopted==1 );
  FD_TEST( ag_votor_has_voted( ctx->votor, 1UL ) );

  /* A request with no bound, or ULONG_MAX for one, is refused. */
  FD_TEST( !deliver_frag( ctx, IN_IDX_FAILOV, 83UL, 0UL ) );
  FD_TEST( adopt_reply( 6UL, 83UL )->result==FD_VOTOR_ADOPT_ERR_DECODE );
  FD_STORE( ulong, failov_in_mem, ULONG_MAX );
  FD_TEST( !deliver_frag( ctx, IN_IDX_FAILOV, 84UL, FD_VOTOR_ADOPT_EMPTY_SZ ) );
  FD_TEST( adopt_reply( 7UL, 84UL )->result==FD_VOTOR_ADOPT_ERR_INVALID );
  FD_TEST( ag_votor_vote_bound( ctx->votor )==9UL );
  FD_TEST( out_seqs[ OUT_IDX_FAILOV ]==8UL );

  /* A history anchored at 12 with replay at slot 11 is refused and
     changes nothing. */
  ag_hist_t far[ 1 ];
  one_slot_hist( far, 14UL, hash );
  far->anchor = 12UL;
  FD_TEST( !ag_hist_ser( far, failov_in_mem, FAILOV_IN_MEM_SZ, &sz ) );
  ctx->failover_hist_adopted  = 0;
  ctx->highest_completed_slot = 11UL;
  FD_TEST( !deliver_frag( ctx, IN_IDX_FAILOV, 85UL, sz ) );
  reply = adopt_reply( 8UL, 85UL );
  FD_TEST( reply->result==FD_VOTOR_ADOPT_ERR_UNREPLAYED_ROOT );
  FD_TEST( reply->root==ULONG_MAX && reply->vote_slot==ULONG_MAX && reply->vote_bound==ULONG_MAX );
  FD_TEST( ag_votor_highest_final_cert_slot( ctx->votor )==0UL );
  FD_TEST( !ag_votor_has_voted( ctx->votor, 14UL ) );
  FD_TEST( !ctx->failover_hist_adopted );

  /* Once replay reaches the anchor it is taken. */
  ctx->highest_completed_slot = 12UL;
  FD_TEST( !deliver_frag( ctx, IN_IDX_FAILOV, 86UL, sz ) );
  reply = adopt_reply( 9UL, 86UL );
  FD_TEST( reply->result==FD_VOTOR_ADOPT_SUCCESS );
  FD_TEST( reply->root==12UL && reply->vote_slot==14UL && reply->vote_bound==9UL );
  FD_TEST( ag_votor_has_voted( ctx->votor, 14UL ) );
  FD_TEST( ctx->failover_hist_adopted==1 );

  fixture_delete( ctx );
  FD_LOG_NOTICE(( "pass: adoption answers echo the request, an empty request starts an empty history" ));
}

/* test_empty_adopt_bound: after an empty adoption with bound 5 we build
   and send no notar, final, fallback or skip vote on a slot up to 5,
   while the skips on 6 and 7 go out. */

static void
test_empty_adopt_bound( void ) {
  fd_pubkey_t a = pubkey( 0x41 );
  fd_pubkey_t b = pubkey( 0x42 );
  fd_votor_tile_t * ctx = fixture_new( &a );
  enable_failover( ctx );
  build_epoch_info( &a, &b );
  long now = fd_log_wallclock();
  start_consensus_at( ctx, 0UL, now );

  /* Our notar on block 1 goes out before the adoption. */
  ag_block_id_t block0 = { .slot = 0UL };
  ag_block_id_t block1 = { .slot = 1UL };
  fd_memset( block1.hash, 0xb1, sizeof(ag_block_hash_t) );
  ag_event_replay_t completed = { .slot = 1UL, .block_info = { .parent = block0 } };
  fd_memcpy( completed.block_info.hash, block1.hash, sizeof(ag_block_hash_t) );
  ag_votor_handle_replay_event( ctx->votor, &completed );
  run_after_credit( ctx );
  FD_TEST( ctx->last_vote_slot==1UL );

  FD_STORE( ulong, failov_in_mem, 5UL );
  FD_TEST( !deliver_frag( ctx, IN_IDX_FAILOV, 90UL, FD_VOTOR_ADOPT_EMPTY_SZ ) );
  fd_votor_adopt_result_t const * reply = adopt_reply( 0UL, 90UL );
  FD_TEST( reply->result==FD_VOTOR_ADOPT_SUCCESS && reply->vote_bound==5UL && reply->vote_slot==ULONG_MAX );

  /* Block 2 on block 1 would draw a notar, a notar cert on block 1 a
     final, the safe to notar and skip events fallbacks and the first
     window's timeouts skips. */
  completed = (ag_event_replay_t){ .slot = 2UL, .block_info = { .parent = block1 } };
  fd_memset( completed.block_info.hash, 0xb2, sizeof(ag_block_hash_t) );
  ag_votor_handle_replay_event( ctx->votor, &completed );
  ag_event_pool_t event = { .kind = AG_EVENT_POOL_CERT_CREATED, .cert_created = signed_notar_cert( 1UL, block1.hash, 0 ) };
  ag_votor_handle_pool_event( ctx->votor, &event, now );
  event = (ag_event_pool_t){ .kind = AG_EVENT_POOL_SAFE_TO_NOTAR, .safe_to_notar = { .slot = 3UL } };
  fd_memset( event.safe_to_notar.hash, 0xb3, sizeof(ag_block_hash_t) );
  ag_votor_handle_pool_event( ctx->votor, &event, now );
  event = (ag_event_pool_t){ .kind = AG_EVENT_POOL_SAFE_TO_SKIP, .safe_to_skip = 2UL };
  ag_votor_handle_pool_event( ctx->votor, &event, now );
  ag_event_timeout_t timeout;
  now += TEST_WINDOW_ELAPSED_NS;
  while( ag_votor_poll_timeout_event( ctx->votor, now, &timeout ) ) ag_votor_handle_timeout_event( ctx->votor, &timeout );

  ag_event_vote_t vote_event;
  FD_TEST( !ag_votor_poll_vote_event( ctx->votor, &vote_event ) );
  FD_TEST( !ag_votor_has_voted( ctx->votor, 2UL ) && !ag_votor_has_voted( ctx->votor, 3UL ) );
  drain( ctx );
  FD_TEST( ctx->last_vote_slot==1UL );

  /* Window 4 opens and times out.  4 and 5 stay silent, the skips on 6
     and 7 are built and sent. */
  ulong hist_seq = out_seqs[ OUT_IDX_HIST ];
  event = (ag_event_pool_t){ .kind = AG_EVENT_POOL_PARENT_READY, .parent_ready = { .slot = 4UL, .parent = { .slot = 3UL } } };
  ag_votor_handle_pool_event( ctx->votor, &event, now );
  now += TEST_WINDOW_ELAPSED_NS;
  while( ag_votor_poll_timeout_event( ctx->votor, now, &timeout ) ) ag_votor_handle_timeout_event( ctx->votor, &timeout );
  FD_TEST( !ag_votor_has_voted( ctx->votor, 4UL ) && !ag_votor_has_voted( ctx->votor, 5UL ) );
  FD_TEST(  ag_votor_has_voted( ctx->votor, 6UL ) &&  ag_votor_has_voted( ctx->votor, 7UL ) );
  drain( ctx );
  FD_TEST( ctx->last_vote_slot==7UL );
  FD_TEST( out_seqs[ OUT_IDX_HIST ]==hist_seq+2UL );
  FD_TEST( hist_frame( hist_seq )->has_vote==1 && hist_frame( hist_seq+1UL )->has_vote==1 );

  fixture_delete( ctx );
  FD_LOG_NOTICE(( "pass: an empty adoption casts nothing at or below its bound" ));
}

/* test_switch_gating: we boot under the junk key.  The staked key
   installed without an adopted history may not vote and goes unranked,
   with a history adopted it votes at its rank and the adoption is
   spent, and the junk key never votes even after an adoption. */

static void
test_switch_gating( void ) {
  fd_pubkey_t a = pubkey( 0x41 );
  fd_pubkey_t b = pubkey( 0x42 );
  fd_pubkey_t c = pubkey( 0x43 );
  fd_votor_tile_t * ctx = fixture_new( &c );
  enable_failover( ctx );
  build_epoch_info( &a, &b );
  start_consensus( ctx, 0UL );

  /* A standby boots unranked, and a slot state made then is unranked. */
  ctx->vote_authority = 0;
  install_ranks( ctx );
  ag_block_id_t block0 = { .slot = 0UL };
  ag_block_id_t block1 = { .slot = 1UL };
  fd_memset( block1.hash, 0xa1, sizeof(ag_block_hash_t) );
  FD_TEST( ag_pool_add_block( ctx->pool, &block1, &block0, ctx->scratch.bad )==AG_POOL_SUCCESS );
  ag_slot_state_t const * state1 = ag_pool_slot_state( ctx->pool, 1UL );
  FD_TEST( state1 && state1->own_rank==(ulong)USHORT_MAX );

  /* The staked key with nothing adopted. */
  FD_TEST( !ctx->failover_hist_adopted );
  request_switch( ctx, &b );
  during_housekeeping( ctx );
  run_after_credit( ctx );
  FD_TEST( fd_keyswitch_state_query( ctx->identity_keyswitch )==FD_KEYSWITCH_STATE_COMPLETED );
  FD_TEST( fd_pubkey_eq( &ctx->id_key, &b ) );
  FD_TEST( ctx->vote_authority==0 );
  FD_TEST( ctx->own_rank[ 1 ]==USHORT_MAX && state1->own_rank==(ulong)USHORT_MAX );

  /* The same key with a history adopted. */
  unhalt_id( ctx );
  ctx->failover_hist_adopted = 1;
  request_switch( ctx, &b );
  during_housekeeping( ctx );
  run_after_credit( ctx );
  FD_TEST( fd_keyswitch_state_query( ctx->identity_keyswitch )==FD_KEYSWITCH_STATE_COMPLETED );
  FD_TEST( ctx->vote_authority==1 );
  FD_TEST( ctx->own_rank[ 1 ]==(ushort)1 && state1->own_rank==1UL );
  FD_TEST( ctx->failover_hist_adopted==0 );

  /* Back to the junk key, an adoption does not matter there. */
  unhalt_id( ctx );
  ctx->failover_hist_adopted = 1;
  request_switch( ctx, &c );
  during_housekeeping( ctx );
  run_after_credit( ctx );
  FD_TEST( fd_keyswitch_state_query( ctx->identity_keyswitch )==FD_KEYSWITCH_STATE_COMPLETED );
  FD_TEST( fd_pubkey_eq( &ctx->id_key, &c ) );
  FD_TEST( ctx->vote_authority==0 && ctx->failover_hist_adopted==0 );
  FD_TEST( ctx->own_rank[ 1 ]==USHORT_MAX && state1->own_rank==(ulong)USHORT_MAX );

  unhalt_id( ctx );
  fixture_delete( ctx );
  FD_LOG_NOTICE(( "pass: the staked key votes only after an adoption, the junk key never" ));
}

/* test_epoch_keeps_unranked: a new epoch that ranks the staked key
   leaves it unranked while it may not vote, and the next switch after
   an adoption ranks it. */

static void
test_epoch_keeps_unranked( void ) {
  fd_vote_stake_weight_t stakes[ 2 ];
  build_stakes( stakes, 2UL, 10UL );
  fd_pubkey_t junk   = pubkey( 0x43 );
  fd_pubkey_t staked = stakes[ 1 ].id_key;
  fd_votor_tile_t * ctx = fixture_new( &junk );
  enable_failover( ctx );
  ctx->vote_authority = 0;

  request_switch( ctx, &staked );
  during_housekeeping( ctx );
  run_after_credit( ctx );
  FD_TEST( fd_keyswitch_state_query( ctx->identity_keyswitch )==FD_KEYSWITCH_STATE_COMPLETED );
  FD_TEST( ctx->vote_authority==0 );
  unhalt_id( ctx );

  static uchar msg_mem[ FD_EPOCH_INFO_MSG_HEADER_SZ+2UL*sizeof(fd_vote_stake_weight_t) ] __attribute__((aligned(64)));
  fd_memset( msg_mem, 0, sizeof(msg_mem) );
  fd_epoch_info_msg_t * msg = (fd_epoch_info_msg_t *)fd_type_pun( msg_mem );
  msg->epoch           = 0UL;
  msg->start_slot      = 0UL;
  msg->slot_cnt        = 64UL;
  msg->ns_per_slot     = (ulong)TEST_NS_PER_SLOT;
  msg->staked_vote_cnt = 2UL;
  msg->staked_id_cnt   = 0UL;
  fd_memcpy( fd_epoch_info_msg_stake_weights( msg ), stakes, sizeof(stakes) );
  ag_pool_init( ctx->pool, 0UL );
  handle_epoch( ctx, msg );
  ushort rank = own_rank_in( ctx->curr_epoch_info, &staked );
  FD_TEST( rank!=USHORT_MAX );
  FD_TEST( ctx->own_rank[ 0 ]==USHORT_MAX && ctx->own_rank[ 1 ]==USHORT_MAX && ctx->own_rank[ 2 ]==USHORT_MAX );

  /* A slot state made in the new epoch is unranked too. */
  ag_block_id_t block0 = { .slot = 0UL };
  ag_block_id_t block1 = { .slot = 1UL };
  fd_memset( block1.hash, 0xa1, sizeof(ag_block_hash_t) );
  FD_TEST( ag_pool_add_block( ctx->pool, &block1, &block0, ctx->scratch.bad )==AG_POOL_SUCCESS );
  ag_slot_state_t const * state1 = ag_pool_slot_state( ctx->pool, 1UL );
  FD_TEST( state1 && state1->own_rank==(ulong)USHORT_MAX );

  ctx->failover_hist_adopted = 1;
  request_switch( ctx, &staked );
  during_housekeeping( ctx );
  run_after_credit( ctx );
  FD_TEST( ctx->vote_authority==1 );
  FD_TEST( ctx->own_rank[ 1 ]==rank && state1->own_rank==(ulong)rank );

  unhalt_id( ctx );
  fixture_delete( ctx );
  FD_LOG_NOTICE(( "pass: a new epoch keeps the staked key unranked until it may vote" ));
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
  enable_failover( ctx );
  build_epoch_info( &a, &b );
  start_consensus( ctx, 0UL );

  static uchar msg_mem[ FD_EPOCH_INFO_MSG_HEADER_SZ+sizeof(fd_vote_stake_weight_t) ] __attribute__((aligned(64)));
  fd_memset( msg_mem, 0, sizeof(msg_mem) );
  fd_epoch_info_msg_t * msg = (fd_epoch_info_msg_t *)fd_type_pun( msg_mem );
  msg->epoch           = 0UL;
  msg->start_slot      = 0UL;
  msg->slot_cnt        = 64UL;
  msg->staked_vote_cnt = 1UL;
  msg->staked_id_cnt   = 0UL;
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
  unhalt_id( ctx );
  ctx->adopted_last_leader_slot = ULONG_MAX;
  ctx->failover_hist_adopted    = 1;
  request_switch( ctx, &b );
  during_housekeeping( ctx );
  run_after_credit( ctx );
  FD_TEST( ctx->next_leader_slot==4UL );

  /* Nothing seen leaves no leader slot, handle_epoch seeds it later. */
  unhalt_id( ctx );
  ctx->highest_completed_slot = 0UL;
  ctx->failover_hist_adopted  = 1;
  request_switch( ctx, &b );
  during_housekeeping( ctx );
  run_after_credit( ctx );
  FD_TEST( ctx->next_leader_slot==ULONG_MAX );

  unhalt_id( ctx );
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
  enable_failover( ctx );
  build_epoch_info( &a, &b );
  start_consensus( ctx, 1UL );
  ctx->vote_authority = 1;
  install_ranks( ctx );
  FD_TEST( ctx->own_rank[ 1 ]==(ushort)1 && own_rank_for( ctx, 5UL )==(ushort)1 );

  /* Not our signature. */
  doppelganger_check( ctx, 5UL, 0, 0 );
  FD_TEST( !ctx->doppelganger && ctx->vote_authority );

  /* Our rank on slot 5, which this machine never voted. */
  doppelganger_check( ctx, 5UL, 1, 0 );
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
  doppelganger_check( ctx, 5UL, 1, 0 );
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

/* test_doppelganger_stop: a doppelganger stop drops the vote already
   queued so it never goes out, every frame says we stopped, and we lead
   no window until a switch after an adopt gives the vote back. */

static void
test_doppelganger_stop( void ) {
  fd_pubkey_t a    = pubkey( 0x41 );
  fd_pubkey_t b    = pubkey( 0x42 );
  fd_pubkey_t junk = pubkey( 0x43 );
  fd_votor_tile_t * ctx = fixture_new( &b );
  enable_failover( ctx );
  ctx->boot_id_key = junk;
  build_epoch_info( &a, &b );
  start_consensus_at( ctx, 1UL, fd_log_wallclock() );
  ctx->vote_authority = 1;
  install_ranks( ctx );

  /* Block 1 on slot 0 queues our notar at rank 1, then our rank shows
     up on slot 5, which this machine never voted. */
  ag_block_id_t block0 = { .slot = 0UL };
  ag_block_id_t block1 = { .slot = 1UL };
  fill_block_hash( block1.hash, 1UL );
  FD_TEST( ag_pool_add_block( ctx->pool, &block1, &block0, ctx->scratch.bad )==AG_POOL_SUCCESS );
  ag_event_replay_t completed = { .slot = 1UL, .block_info = { .parent = block0 } };
  fd_memcpy( completed.block_info.hash, block1.hash, sizeof(ag_block_hash_t) );
  ag_votor_handle_replay_event( ctx->votor, &completed );
  doppelganger_check( ctx, 5UL, 1, 0 );
  FD_TEST( ctx->doppelganger==1 && ctx->vote_authority==0 );

  /* The notar never goes out and the history says so, and every frame
     tells the failover tile we stopped. */
  drain( ctx );
  publish_hist( ctx, stem, 0 );
  FD_TEST( ctx->last_vote_slot==ULONG_MAX );
  for( ulong seq=0UL; seq<out_seqs[ OUT_IDX_HIST ]; seq++ ) FD_TEST( !hist_frame( seq )->has_vote && hist_frame( seq )->stopped==1 );
  ag_hist_t hist[ 1 ];
  ag_votor_hist_export( ctx->votor, ULONG_MAX, hist );
  ag_hist_rec_t const * rec = hist_rec( hist, 1UL );
  FD_TEST( rec && rec->flags==(AG_HIST_FLAG_VOTED|AG_HIST_FLAG_BAD_WINDOW) );

  /* A fast final cert on block 3 grants parent ready for window 4, our
     next leader slot.  We do not lead it. */
  ag_block_id_t block2 = { .slot = 2UL };
  ag_block_id_t block3 = { .slot = 3UL };
  fill_block_hash( block2.hash, 2UL );
  fill_block_hash( block3.hash, 3UL );
  FD_TEST( ag_pool_add_block( ctx->pool, &block2, &block1, ctx->scratch.bad )==AG_POOL_SUCCESS );
  FD_TEST( ag_pool_add_block( ctx->pool, &block3, &block2, ctx->scratch.bad )==AG_POOL_SUCCESS );
  ag_cert_t cert = signed_notar_cert( 3UL, block3.hash, 1 );
  FD_TEST( ag_pool_add_cert( ctx->pool, &cert, ctx->scratch.bad )==AG_POOL_SUCCESS );
  FD_TEST( ag_pool_wait_for_parent_ready( ctx->pool, 4UL ).slot==3UL );
  ctx->next_leader_slot = 4UL;
  drain( ctx );
  FD_TEST( ctx->next_leader_slot==4UL && ctx->last_leader_slot==ULONG_MAX );
  for( ulong seq=0UL; seq<out_seqs[ OUT_IDX_VOTOR ]; seq++ ) FD_TEST( out_mcache[ OUT_IDX_VOTOR ][ seq & (OUT_DEPTH-1UL) ].sig!=FD_VOTOR_SIG_LEADER );

  /* A switch after an adopt gives the vote back and we lead window 4.
     No schedule is loaded, so the switch found no leader slot. */
  ctx->failover_hist_adopted = 1;
  request_switch( ctx, &b );
  during_housekeeping( ctx );
  run_after_credit( ctx );
  FD_TEST( fd_keyswitch_state_query( ctx->identity_keyswitch )==FD_KEYSWITCH_STATE_COMPLETED );
  FD_TEST( ctx->vote_authority==1 && !ctx->doppelganger );
  FD_TEST( hist_frame( out_seqs[ OUT_IDX_HIST ]-1UL )->stopped==1 ); /* the halt frame, taken before the switch */
  unhalt_id( ctx );
  ctx->next_leader_slot = 4UL;
  run_after_credit( ctx );
  FD_TEST( ctx->last_leader_slot==4UL );
  FD_TEST( !hist_frame( out_seqs[ OUT_IDX_HIST ]-1UL )->stopped ); /* the LEADER frame */
  FD_TEST( out_mcache[ OUT_IDX_VOTOR ][ (out_seqs[ OUT_IDX_VOTOR ]-1UL) & (OUT_DEPTH-1UL) ].sig==FD_VOTOR_SIG_LEADER );

  fixture_delete( ctx );
  FD_LOG_NOTICE(( "pass: a doppelganger stop drops the queued vote and leads nothing until an adopt" ));
}

/* test_root_follow: a standby outside the vote mesh finalizes from the
   certs in replay's block footers alone, a fast final cert, the final
   and notar pair and a dead block's footer.  The pool and the votor
   move up and the exported anchor follows, so replay's root advance
   stays filtered as it is without failover. */

static void
test_root_follow( void ) {
  fd_pubkey_t a = pubkey( 0x41 );
  fd_pubkey_t b = pubkey( 0x42 );
  fd_pubkey_t c = pubkey( 0x43 );
  fd_votor_tile_t * ctx = fixture_new( &c );
  enable_failover( ctx );
  build_epoch_info( &a, &b );
  start_consensus_at( ctx, 0UL, fd_log_wallclock() );
  ctx->vote_authority = 0;
  install_ranks( ctx );

  /* Replay completes 1 to 4 with empty footers, then 5 whose footer has
     a fast final cert on block 4. */
  for( ulong slot=1UL; slot<=4UL; slot++ ) {
    completed_msg( slot );
    FD_TEST( !deliver_frag( ctx, IN_IDX_REPLAY, REPLAY_SIG_SLOT_COMPLETED, sizeof(fd_replay_message_t) ) );
    drain( ctx );
  }
  FD_TEST( ag_pool_finalized_slot( ctx->pool )==0UL );
  uchar hash[ 32 ];
  fill_block_hash( hash, 4UL );
  footer_fast_final( &completed_msg( 5UL )->footer, 4UL, hash );
  FD_TEST( !deliver_frag( ctx, IN_IDX_REPLAY, REPLAY_SIG_SLOT_COMPLETED, sizeof(fd_replay_message_t) ) );
  FD_TEST( ag_pool_finalized_slot( ctx->pool )==4UL );
  drain( ctx );
  FD_TEST( ag_votor_highest_final_cert_slot( ctx->votor )==4UL );

  /* 6 to 8 empty, then 9 whose footer has the final and notar pair on
     block 8. */
  for( ulong slot=6UL; slot<=8UL; slot++ ) {
    completed_msg( slot );
    FD_TEST( !deliver_frag( ctx, IN_IDX_REPLAY, REPLAY_SIG_SLOT_COMPLETED, sizeof(fd_replay_message_t) ) );
    drain( ctx );
  }
  fill_block_hash( hash, 8UL );
  footer_final( &completed_msg( 9UL )->footer, 8UL, hash );
  FD_TEST( !deliver_frag( ctx, IN_IDX_REPLAY, REPLAY_SIG_SLOT_COMPLETED, sizeof(fd_replay_message_t) ) );
  FD_TEST( ag_pool_finalized_slot( ctx->pool )==8UL );
  drain( ctx );
  FD_TEST( ag_votor_highest_final_cert_slot( ctx->votor )==8UL );

  /* 10 to 12 empty, then a dead block 13 whose footer has a fast final
     cert on block 12.  The votor prunes below the window of 12-8. */
  for( ulong slot=10UL; slot<=12UL; slot++ ) {
    completed_msg( slot );
    FD_TEST( !deliver_frag( ctx, IN_IDX_REPLAY, REPLAY_SIG_SLOT_COMPLETED, sizeof(fd_replay_message_t) ) );
    drain( ctx );
  }
  fd_replay_slot_dead_t * dead = &replay_in_msg()->slot_dead;
  dead->slot = 13UL;
  fill_block_hash( dead->block_id.uc, 13UL );
  fill_block_hash( hash, 12UL );
  footer_fast_final( &dead->footer, 12UL, hash );
  FD_TEST( !deliver_frag( ctx, IN_IDX_REPLAY, REPLAY_SIG_SLOT_DEAD, sizeof(fd_replay_message_t) ) );
  FD_TEST( ag_pool_finalized_slot( ctx->pool )==12UL );
  FD_TEST( fd_memeq( ag_pool_finalized_block_hash( ctx->pool ), hash, sizeof(ag_block_hash_t) ) );
  drain( ctx );
  FD_TEST( ag_votor_highest_final_cert_slot( ctx->votor )==12UL );
  FD_TEST( ag_votor_first_unpruned_slot( ctx->votor )==4UL );

  ag_hist_t hist[ 1 ];
  ag_votor_hist_export( ctx->votor, ULONG_MAX, hist );
  FD_TEST( hist->anchor==12UL );
  FD_TEST( !hist->rec_cnt || hist->rec[ 0 ].slot>=4UL );

  /* Replay's root advance is filtered with or without failover. */
  FD_TEST( before_frag( ctx, IN_IDX_REPLAY, 0UL, REPLAY_SIG_ROOT_ADVANCED ) );

  fixture_delete( ctx );
  FD_LOG_NOTICE(( "pass: a standby finalizes from block footer certs alone" ));
}

/* Use production input initialization with the unpolled keyguard response
   before adoption, as in topology.c.  Hand-built callback indices hid this
   routing failure in the other adoption fixtures. */
static void
unexpected_sign( void *         ctx,
                 fd_bls_sig_t * sig,
                 uchar const *  public_key,
                 uchar const *  payload,
                 ulong          payload_sz ) {
  (void)ctx; (void)sig; (void)public_key; (void)payload; (void)payload_sz;
  FD_LOG_ERR(( "adopting an empty history must not sign a vote" ));
}

/* Use production input initialization with the unpolled keyguard response
   before adoption, as in topology.c.  Hand-built callback indices hid this
   routing failure in the other adoption fixtures. */
static void
test_input_link_indices( void ) {
  static fd_topo_t topo;
  fd_topo_tile_t * tile = &topo.tiles[ 0 ];
  fd_wksp_t * wksp = fd_wksp_new_anonymous( FD_SHMEM_NORMAL_PAGE_SZ, 4096UL, 0UL, "votor_inputs", 0UL );
  FD_TEST( wksp );
  topo.workspaces[ 0 ].wksp = wksp;
  topo.objs[ 0 ].wksp_id    = 0UL;
  char const * names[] = { "replay_out", "replay_epoch", "gossip_out", "ipecho_out", "net_votor", "sign_votor", "failov_votor" };
  tile->in_cnt = sizeof(names)/sizeof(names[0]);
  for( ulong i=0UL; i<tile->in_cnt; i++ ) {
    fd_topo_link_t * link = &topo.links[ i ];
    fd_cstr_ncpy( link->name, names[ i ], sizeof(link->name) );
    link->mtu = AG_HIST_SER_MAX;
    ulong data_sz = fd_dcache_req_data_sz( link->mtu, 4UL, 1UL, 1 );
    void * mem = fd_wksp_alloc_laddr( wksp, fd_dcache_align(), fd_dcache_footprint( data_sz, 0UL ), 1UL );
    FD_TEST( mem );
    link->dcache = fd_dcache_join( fd_dcache_new( mem, data_sz, 0UL ) );
    FD_TEST( link->dcache );
    tile->in_link_id[ i ]   = i;
    tile->in_link_poll[ i ] = strcmp( names[ i ], "sign_votor" )!=0;
  }

  static fd_votor_tile_t ctx_mem[ 1 ];
  static uchar votor_mem[ 1UL<<20 ] __attribute__((aligned(128)));
  fd_votor_tile_t * ctx = ctx_mem;
  FD_TEST( ag_votor_footprint( 16UL )<=sizeof(votor_mem) );
  ctx->votor = ag_votor_join( ag_votor_new( votor_mem, 16UL, 42UL ) );
  FD_TEST( ctx->votor );
  /* Empty-history adoption does not sign, but requires initialized consensus. */
  ag_votor_init( ctx->votor, 0UL, 0L, 400000000L, 1U, unexpected_sign, NULL );
  ctx->init = 1;
  ctx->failover_enabled = 1;
  ctx->adopted_last_leader_slot = ULONG_MAX;
  ctx->last_leader_slot         = ULONG_MAX;
  ctx->last_vote_slot           = ULONG_MAX;

  static uchar reply_mem[ 512 ] __attribute__((aligned(FD_CHUNK_SZ)));
  static fd_frag_meta_t mcache[ 8 ];
  fd_frag_meta_t * mcaches[] = { mcache };
  ulong seqs[] = { 0UL }, depths[] = { 8UL };
  ulong cr_avail = 64UL, min_cr_avail = 64UL;
  int reliable = 0;
  fd_stem_context_t stem[ 1 ] = {{
    .mcaches=mcaches, .seqs=seqs, .depths=depths,
    .cr_avail=&cr_avail, .min_cr_avail=&min_cr_avail,
    .cr_decrement_amount=1UL, .out_reliable=&reliable
  }};
  ctx->failov_out_idx = 0UL;
  ctx->failov_out_mem = reply_mem;
  ctx->failov_out_wmark = 4UL;
  init_input_links( ctx, &topo, tile );

  /* Stem skips the synchronous sign response link when numbering callbacks. */
  ulong callback_idx = 0UL;
  for( ulong i=0UL; i<6UL; i++ ) callback_idx += !!tile->in_link_poll[ i ];
  FD_TEST( callback_idx==5UL );
  fd_topo_link_t const * link = &topo.links[ 6 ];
  FD_STORE( ulong, link->dcache, 9UL );
  ulong chunk = fd_dcache_compact_chunk0( wksp, link->dcache );
  FD_TEST( !before_frag( ctx, callback_idx, 0UL, 901UL ) );
  during_frag( ctx, callback_idx, 0UL, 901UL, chunk, FD_VOTOR_ADOPT_EMPTY_SZ, 0UL );
  after_frag( ctx, callback_idx, 0UL, 901UL, FD_VOTOR_ADOPT_EMPTY_SZ, 0UL, 0UL, stem );
  FD_TEST( seqs[0]==1UL && mcache[0].sig==901UL && mcache[0].sz==sizeof(fd_votor_adopt_result_t) );
  fd_votor_adopt_result_t const * reply = fd_chunk_to_laddr_const( reply_mem, mcache[0].chunk );
  FD_TEST( reply->result==FD_VOTOR_ADOPT_SUCCESS && reply->vote_bound==9UL );
  FD_TEST( ctx->failover_hist_adopted );
  FD_TEST( ctx->adopted_last_leader_slot==ag_first_slot_in_window( 9UL ) );
  FD_TEST( ctx->in_kind[ callback_idx ]==IN_KIND_FAILOV );
  FD_TEST( ctx->in[ callback_idx ].chunk0==chunk && ctx->in[ callback_idx ].mtu==link->mtu );

  /* A request without a bound is refused and preserves the earlier bound. */
  ctx->failover_hist_adopted = 0;
  FD_STORE( ulong, link->dcache, ULONG_MAX );
  during_frag( ctx, callback_idx, 1UL, 902UL, chunk, FD_VOTOR_ADOPT_EMPTY_SZ, 0UL );
  after_frag( ctx, callback_idx, 1UL, 902UL, FD_VOTOR_ADOPT_EMPTY_SZ, 0UL, 0UL, stem );
  FD_TEST( seqs[0]==2UL && mcache[1].sig==902UL && mcache[1].sz==sizeof(fd_votor_adopt_result_t) );
  reply = fd_chunk_to_laddr_const( reply_mem, mcache[1].chunk );
  FD_TEST( reply->result==FD_VOTOR_ADOPT_ERR_INVALID && !ctx->failover_hist_adopted );
  FD_TEST( ag_votor_vote_bound( ctx->votor )==9UL );
  FD_TEST( ctx->adopted_last_leader_slot==ag_first_slot_in_window( 9UL ) );

  /* Before consensus is up the answer says to ask again, and nothing
     moves. */
  ctx->init = 0;
  FD_STORE( ulong, link->dcache, 21UL );
  during_frag( ctx, callback_idx, 2UL, 903UL, chunk, FD_VOTOR_ADOPT_EMPTY_SZ, 0UL );
  after_frag( ctx, callback_idx, 2UL, 903UL, FD_VOTOR_ADOPT_EMPTY_SZ, 0UL, 0UL, stem );
  FD_TEST( seqs[0]==3UL && mcache[2].sig==903UL );
  reply = fd_chunk_to_laddr_const( reply_mem, mcache[2].chunk );
  FD_TEST( reply->result==FD_VOTOR_ADOPT_ERR_UNREPLAYED && !ctx->failover_hist_adopted );
  FD_TEST( ag_votor_vote_bound( ctx->votor )==9UL );
  ctx->init = 1;

  /* After set-identity turned failover off nothing waits for an answer,
     the request is dropped and moves neither bound. */
  ctx->failover_enabled = 0;
  during_frag( ctx, callback_idx, 3UL, 904UL, chunk, FD_VOTOR_ADOPT_EMPTY_SZ, 0UL );
  after_frag( ctx, callback_idx, 3UL, 904UL, FD_VOTOR_ADOPT_EMPTY_SZ, 0UL, 0UL, stem );
  FD_TEST( seqs[0]==3UL && !ctx->failover_hist_adopted );
  FD_TEST( ag_votor_vote_bound( ctx->votor )==9UL );
  FD_TEST( ctx->adopted_last_leader_slot==ag_first_slot_in_window( 9UL ) );

  ag_votor_delete( ag_votor_leave( ctx->votor ) );
  fd_wksp_delete_anonymous( wksp );
  FD_LOG_NOTICE(( "pass: production input initialization routes adoption past the unpolled signer link" ));
}

/* test_history_raises_the_leader_floor: an adopted history fences the
   window of the last LEADER it reports and the window of its vote
   bound, and a lower bound or leader slot never lowers the fence. */

static void
test_history_raises_the_leader_floor( void ) {
  fd_pubkey_t a = pubkey( 0x41 );
  fd_pubkey_t b = pubkey( 0x42 );
  fd_votor_tile_t * ctx = fixture_new( &a );
  build_epoch_info( &a, &b );
  start_consensus( ctx, 0UL );
  ctx->failover_enabled = 1;

  ag_hist_t hist = { .anchor = 0UL, .last_leader_slot = 12UL, .vote_bound = 17UL, .rec_cnt = 1UL };
  hist.rec[ 0 ].slot  = 1UL;
  hist.rec[ 0 ].flags = AG_HIST_FLAG_VOTED;
  uchar req[ AG_HIST_SER_MAX ];
  ulong req_sz;
  FD_TEST( !ag_hist_ser( &hist, req, sizeof(req), &req_sz ) );
  fd_votor_adopt_result_t result = failover_adopt_hist( ctx, req, req_sz );
  FD_TEST( result.result==FD_VOTOR_ADOPT_SUCCESS && result.vote_slot==1UL && result.vote_bound==17UL );
  FD_TEST( ag_votor_vote_bound( ctx->votor )==17UL );
  FD_TEST( ctx->adopted_last_leader_slot==ag_first_slot_in_window( 17UL ) );
  FD_TEST( leader_floor( ctx )==ag_first_slot_in_window( 17UL ) );

  hist.last_leader_slot = 4UL;
  hist.vote_bound       = 6UL;
  FD_TEST( !ag_hist_ser( &hist, req, sizeof(req), &req_sz ) );
  result = failover_adopt_hist( ctx, req, req_sz );
  FD_TEST( result.result==FD_VOTOR_ADOPT_SUCCESS && result.vote_bound==17UL );
  FD_TEST( ctx->adopted_last_leader_slot==ag_first_slot_in_window( 17UL ) );

  uchar empty[ FD_VOTOR_ADOPT_EMPTY_SZ ];
  FD_STORE( ulong, empty, 2UL );
  result = failover_adopt_hist( ctx, empty, sizeof(empty) );
  FD_TEST( result.result==FD_VOTOR_ADOPT_SUCCESS && result.vote_bound==17UL );
  FD_TEST( ctx->adopted_last_leader_slot==ag_first_slot_in_window( 17UL ) );

  /* A history older than the votes this machine sent is refused. */
  ctx->last_vote_slot = 3UL;
  result = failover_adopt_hist( ctx, req, req_sz );
  FD_TEST( result.result==FD_VOTOR_ADOPT_ERR_STALE );

  fixture_delete( ctx );
  FD_LOG_NOTICE(( "pass: an adopted history raises the leader floor" ));
}

/* test_doppelganger_cert_below_bound: a cert with our rank at or below
   the vote bound can hold the previous holder's votes and does not stop
   us.  A vote datagram there does, and so does a cert above the bound. */

static void
test_doppelganger_cert_below_bound( void ) {
  fd_pubkey_t a = pubkey( 0x41 );
  fd_pubkey_t b = pubkey( 0x42 );
  fd_votor_tile_t * ctx = fixture_new( &a );
  build_epoch_info( &a, &b );
  start_consensus( ctx, 0UL );
  ctx->failover_enabled = 1;
  ag_votor_set_vote_bound( ctx->votor, 5UL );

  doppelganger_check( ctx, 3UL, 1, 1 );
  FD_TEST( !ctx->doppelganger && ctx->vote_authority );
  doppelganger_check( ctx, 5UL, 1, 1 );
  FD_TEST( !ctx->doppelganger && ctx->vote_authority );
  doppelganger_check( ctx, 6UL, 0, 1 );
  FD_TEST( !ctx->doppelganger && ctx->vote_authority );

  doppelganger_check( ctx, 3UL, 1, 0 );
  FD_TEST( ctx->doppelganger && !ctx->vote_authority );

  ctx->doppelganger   = 0;
  ctx->vote_authority = 1;
  doppelganger_check( ctx, 6UL, 1, 1 );
  FD_TEST( ctx->doppelganger && !ctx->vote_authority );

  fixture_delete( ctx );
  FD_LOG_NOTICE(( "pass: a cert at or below the vote bound does not stop us" ));
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
  fd_bls_sec_t junk_sec; fd_memset( &junk_sec, 0x55, FD_BLS_SEC_SZ );
  bls_key_from_sec( junk_bls_key, &junk_sec );

  test_input_link_indices();
  test_rank_voters_resets_total_stake();
  test_quic_client_ack_range();
  test_rank_voters_bls_keys();
  test_load_keys( 0 );
  test_load_keys( 1 );
  test_own_bls_key();
  test_sign_bls_request();
  test_switch_no_bls_key_until_unhalt();
  test_switch_votes_with_new_key();
  test_demote_builds_no_vote();
  test_switch_completes_uninitialised();
  test_switch_closes_and_reconnects();
  test_switch_ranks_and_leader();
  test_gossip_dial_gated();
  test_drops_queued_votes();
  test_hist_frames();
  test_switch_watermark();
  test_adopt_reply();
  test_empty_adopt_bound();
  test_switch_gating();
  test_epoch_keeps_unranked();
  test_leader_floor();
  test_doppelganger();
  test_doppelganger_stop();
  test_root_follow();
  test_history_raises_the_leader_floor();
  test_doppelganger_cert_below_bound();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
