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

static ulong
out_wmark( ulong mem_sz,
           ulong mtu ) {
  ulong chunk_mtu = ((mtu + 2UL*FD_CHUNK_SZ-1UL) >> (1+FD_CHUNK_LG_SZ)) << 1;
  return (mem_sz>>FD_CHUNK_LG_SZ) - chunk_mtu;
}

/* A fake stem with the tile's two outs.  Publishing writes a real
   mcache line and nothing consumes it. */

#define OUT_CNT   (2UL)
#define OUT_DEPTH (128UL)

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
   with that rank's BLS key as the identity's, as load_keys enters it. */

static void
start_consensus( fd_votor_tile_t * ctx,
                 ulong             own_rank ) {
  auth_vtr_key_t bls_key; fd_memcpy( bls_key.uc, infos[ own_rank ].bls_key, sizeof(ag_bls_key_t) );
  auth_vtr_insert( ctx->auth_vtr, bls_key )->paths_idx = ULONG_MAX;
  ctx->curr_epoch_info = &epoch_info_mem;
  ctx->curr_epoch_slot = 0UL;
  ag_pool_advance_epoch ( ctx->pool, &epoch_info_mem, own_rank, 0UL );
  ag_votor_advance_epoch( ctx->votor, TEST_NS_PER_SLOT, own_rank, 0UL, own_bls_key( ctx, &epoch_info_mem, (ushort)own_rank ) );
  ag_pool_init ( ctx->pool, 0UL );
  ag_votor_init( ctx->votor, 0UL, 0L, TEST_NS_PER_SLOT, TEST_SHRED_VERSION, recording_sign_fn, &sk[ own_rank ] );
  ctx->shred_version = TEST_SHRED_VERSION;
  ctx->init          = 1;
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

/* Fire every timeout of the first window, which builds a skip vote for
   slots 1..3 wherever we hold a rank and a BLS key. */

static void
fire_first_window( fd_votor_tile_t * ctx ) {
  ag_event_timeout_t timeout;
  while( ag_votor_poll_timeout_event( ctx->votor, TEST_WINDOW_ELAPSED_NS, &timeout ) ) ag_votor_handle_timeout_event( ctx->votor, &timeout );
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
  test_history_raises_the_leader_floor();
  test_doppelganger_cert_below_bound();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
