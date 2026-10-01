#define FD_TILE_TEST 1
#include "fd_votor_tile.c"

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

static uchar bls_pubkey_request_mcache [ FD_MCACHE_FOOTPRINT( 128UL, 0UL ) ] __attribute__((aligned(FD_MCACHE_ALIGN)));
static uchar bls_pubkey_response_mcache[ FD_MCACHE_FOOTPRINT( 128UL, 0UL ) ] __attribute__((aligned(FD_MCACHE_ALIGN)));
static uchar bls_pubkey_request [ sizeof(ulong) ] __attribute__((aligned(FD_CHUNK_ALIGN)));
static uchar bls_pubkey_response[ 17UL*FD_CHUNK_SZ ] __attribute__((aligned(FD_CHUNK_ALIGN)));

/* Joins client to a signer that has prepublished bls_keys[0,cnt) as its
   next public-key responses.  bls_pubkey_request holds the most recent
   request. */

static void
bls_pubkey_client_init( fd_keyguard_client_t * client,
                        ag_bls_key_t *         bls_keys,
                        ulong                  cnt ) {
  memset( client, 0, sizeof(fd_keyguard_client_t) );
  client->request        = fd_mcache_join( fd_mcache_new( bls_pubkey_request_mcache,  128UL, 0UL, 0UL ) );
  client->response       = fd_mcache_join( fd_mcache_new( bls_pubkey_response_mcache, 128UL, 0UL, 0UL ) );
  FD_TEST( client->request && client->response );
  client->request_depth  = 128UL;
  client->response_depth = 128UL;
  client->request_mem    = (fd_wksp_t *)bls_pubkey_request;
  client->response_mem   = (fd_wksp_t *)bls_pubkey_response;
  client->request_mtu    = sizeof(bls_pubkey_request);
  client->response_mtu   = FD_KEYGUARD_BLS_PUBKEY_SZ;
  client->response_wmark = 16UL;
  for( ulong i=0UL; i<cnt; i++ ) {
    memcpy( bls_pubkey_response+i*FD_CHUNK_SZ, bls_keys[i], sizeof(ag_bls_key_t) );
    fd_mcache_publish( client->response, 128UL, i, FD_KEYGUARD_SIGN_TYPE_BLS_PUBKEY, i, sizeof(ag_bls_key_t), 0UL, 0UL, 0UL );
  }
}

static void
test_load_keys( int identity_is_voter ) {
  static fd_votor_tile_t ctx;
  static fd_topo_tile_t  tile;
  static auth_vtr_t      auth_vtr_mem[ 1UL<<AUTH_VTR_LG_SLOT_CNT ];

  ag_bls_key_t bls_keys[17];
  fd_bls_sec_t secs[17];
  fd_bls_pub_t pubs[17];
  build_bls_keys( bls_keys, secs, pubs, 17UL );
  if( identity_is_voter ) memcpy( bls_keys[4], bls_keys[0], sizeof(ag_bls_key_t) ); /* authorized voter 3 */
  ctx.auth_vtr = auth_vtr_join( auth_vtr_new( auth_vtr_mem ) );
  tile.votor.authorized_voter_paths_cnt = 16UL;

  /* The configured key paths are empty: load_keys must query the signer
     without opening keyfiles. */
  fd_keyguard_client_t * client = ctx.keyguard_client;
  bls_pubkey_client_init( client, bls_keys, 17UL );
  load_keys( &ctx, &tile );
  FD_TEST( client->request_seq==17UL && client->response_seq==17UL );
  FD_TEST( ctx.auth_vtr_path_cnt==16UL );
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
  FD_TEST( FD_LOAD( ulong, bls_pubkey_request )==15UL );
}

/* Once the admin tile has added an authorized voter to the sign tiles,
   the votor indexes the voter's BLS key under the next authorized voter
   index.  A voter whose key is the identity's still uses up an index. */

static void
test_auth_vtr_keyswitch_add( int identity_is_voter ) {
  static fd_votor_tile_t ctx;
  static auth_vtr_t      auth_vtr_mem[ 1UL<<AUTH_VTR_LG_SLOT_CNT ];
  static fd_keyswitch_t  keyswitch[1];

  /* The identity's key, authorized voters 0 and 1, and the voter added. */

  ag_bls_key_t bls_keys[4];
  fd_bls_sec_t secs[4];
  fd_bls_pub_t pubs[4];
  build_bls_keys( bls_keys, secs, pubs, 4UL );
  if( identity_is_voter ) memcpy( bls_keys[3], bls_keys[0], sizeof(ag_bls_key_t) );
  init_keys( &ctx, auth_vtr_mem, bls_keys, 3UL );
  ctx.auth_vtr_path_cnt  = 2UL;
  ctx.auth_vtr_keyswitch = fd_keyswitch_join( fd_keyswitch_new( keyswitch, FD_KEYSWITCH_STATE_LOCKED ) );
  FD_TEST( ctx.auth_vtr_keyswitch );
  fd_clock_tile_init( ctx.clock );
  fd_keyguard_client_t * client = ctx.keyguard_client;
  bls_pubkey_client_init( client, &bls_keys[3], 1UL );

  /* Nothing to do while the admin tile updates the sign tiles. */

  during_housekeeping( &ctx );
  FD_TEST( keyswitch->state==FD_KEYSWITCH_STATE_LOCKED && !client->request_seq );

  keyswitch->param = FD_KEYSWITCH_PARAM_AV_ADD;
  fd_keyswitch_state( keyswitch, FD_KEYSWITCH_STATE_SWITCH_PENDING );
  during_housekeeping( &ctx );
  FD_TEST( keyswitch->state==FD_KEYSWITCH_STATE_COMPLETED );
  FD_TEST( client->request_seq==1UL && FD_LOAD( ulong, bls_pubkey_request )==2UL );
  FD_TEST( ctx.auth_vtr_path_cnt==3UL );
  FD_TEST( paths_idx_of( &ctx, bls_keys[0] )==ULONG_MAX );
  FD_TEST( paths_idx_of( &ctx, bls_keys[1] )==0UL );
  FD_TEST( paths_idx_of( &ctx, bls_keys[2] )==1UL );
  if( !identity_is_voter ) FD_TEST( paths_idx_of( &ctx, bls_keys[3] )==2UL );

  fd_keyswitch_state( keyswitch, FD_KEYSWITCH_STATE_UNHALT_PENDING );
  during_housekeeping( &ctx );
  FD_TEST( keyswitch->state==FD_KEYSWITCH_STATE_UNLOCKED );
}

/* When a sign tile rejects the voter, the admin tile unlocks the votor
   without asking it to add anything. */

static void
test_auth_vtr_keyswitch_rejected( void ) {
  static fd_votor_tile_t ctx;
  static fd_keyswitch_t  keyswitch[1];

  ctx.auth_vtr_path_cnt  = 2UL;
  ctx.auth_vtr_keyswitch = fd_keyswitch_join( fd_keyswitch_new( keyswitch, FD_KEYSWITCH_STATE_UNHALT_PENDING ) );
  FD_TEST( ctx.auth_vtr_keyswitch );
  fd_clock_tile_init( ctx.clock );
  during_housekeeping( &ctx );
  FD_TEST( keyswitch->state==FD_KEYSWITCH_STATE_UNLOCKED && ctx.auth_vtr_path_cnt==2UL );
}

static uchar votor_scratch[ 1UL<<21 ] __attribute__((aligned(128)));
static uchar last_bls_signer[ FD_BLS_PUB_COMPRESSED_SZ ];

static void
capture_sign_bls( void *         signer_ctx,
                  fd_bls_sig_t * sig,
                  uchar const *  public_key,
                  uchar const *  payload,
                  ulong          payload_sz ) {
  (void)signer_ctx;
  memcpy( last_bls_signer, public_key, FD_BLS_PUB_COMPRESSED_SZ );
  fd_bls_sec_t sec; memset( &sec, 1, sizeof(fd_bls_sec_t) );
  fd_bls_sec_sign( &sec, payload, payload_sz, sig );
}

/* Votor already holds the epoch when the voter is added, so the add has
   to re-check the epoch for votes to use the new voter's key. */

static void
test_auth_vtr_keyswitch_refreshes_epochs( void ) {
  static fd_votor_tile_t ctx;
  static auth_vtr_t      auth_vtr_mem[ 1UL<<AUTH_VTR_LG_SLOT_CNT ];
  static fd_keyswitch_t  keyswitch[1];

  /* We are rank 1, and our vote account's key belongs to the voter
     being added. */

  fd_vote_stake_weight_t stakes[ TEST_VOTER_MAX ];
  build_stakes( stakes, 3UL, 10UL );
  ag_epoch_info_t * epoch_info = rank_voters( &epoch_info_mem, stakes, 3UL );
  memcpy( ctx.id_key.uc, epoch_info->validators[1].id_key, sizeof(fd_pubkey_t) );
  ctx.curr_epoch_info = epoch_info;
  ctx.curr_epoch_slot = 0UL;

  ag_bls_key_t bls_keys[2];
  fd_bls_sec_t secs[2];
  fd_bls_pub_t pubs[2];
  build_bls_keys( bls_keys, secs, pubs, 1UL );
  memcpy( bls_keys[1], epoch_info->validators[1].bls_key, sizeof(ag_bls_key_t) );
  init_keys( &ctx, auth_vtr_mem, bls_keys, 1UL ); /* only the identity */
  ctx.auth_vtr_path_cnt  = 0UL;
  ctx.auth_vtr_keyswitch = fd_keyswitch_join( fd_keyswitch_new( keyswitch, FD_KEYSWITCH_STATE_LOCKED ) );
  FD_TEST( ctx.auth_vtr_keyswitch );
  fd_clock_tile_init( ctx.clock );
  bls_pubkey_client_init( ctx.keyguard_client, &bls_keys[1], 1UL );

  /* The epoch advanced before the add, so it has no key to vote with. */

  FD_TEST( ag_votor_footprint( 64UL )<=sizeof(votor_scratch) );
  ctx.votor = ag_votor_join( ag_votor_new( votor_scratch, 64UL, 42UL ) );
  FD_TEST( ctx.votor );
  ag_votor_init         ( ctx.votor, 0UL, 0L, 400000000L, (ushort)1, capture_sign_bls, NULL );
  ag_votor_advance_epoch( ctx.votor, 400000000L, 1UL, 0UL, NULL );

  keyswitch->param = FD_KEYSWITCH_PARAM_AV_ADD;
  fd_keyswitch_state( keyswitch, FD_KEYSWITCH_STATE_SWITCH_PENDING );
  during_housekeeping( &ctx );

  /* Block 1 builds on the root, slot 0 with a zero hash. */

  ag_event_replay_t block = { .slot = 1UL };
  memset( block.block_info.hash, 1, sizeof(ag_block_hash_t) );
  ag_votor_handle_replay_event( ctx.votor, &block );

  ag_event_vote_t vote;
  FD_TEST( ag_votor_poll_vote_event( ctx.votor, &vote ) );
  FD_TEST( vote.vote.kind==AG_VOTE_KIND_NOTAR );
  FD_TEST( !memcmp( last_bls_signer, bls_keys[1], sizeof(ag_bls_key_t) ) );

  ag_votor_delete( ag_votor_leave( ctx.votor ) );
}

/* Clearing drops every authorized voter but keeps the identity, and an
   epoch that votes with a removed voter's key stops voting instead of
   asking the sign tile for a key it is about to drop. */

static void
test_auth_vtr_keyswitch_clear( void ) {
  static fd_votor_tile_t ctx;
  static auth_vtr_t      auth_vtr_mem[ 1UL<<AUTH_VTR_LG_SLOT_CNT ];
  static fd_keyswitch_t  keyswitch[1];

  /* We are rank 0, and vote with authorized voter 1's key. */

  fd_vote_stake_weight_t stakes[ TEST_VOTER_MAX ];
  build_stakes( stakes, 3UL, 10UL );
  ag_epoch_info_t * epoch_info = rank_voters( &epoch_info_mem, stakes, 3UL );
  memcpy( ctx.id_key.uc, epoch_info->validators[0].id_key, sizeof(fd_pubkey_t) );
  ctx.curr_epoch_info = epoch_info;
  ctx.curr_epoch_slot = 0UL;

  ag_bls_key_t bls_keys[3];
  fd_bls_sec_t secs[3];
  fd_bls_pub_t pubs[3];
  build_bls_keys( bls_keys, secs, pubs, 2UL );
  memcpy( bls_keys[2], epoch_info->validators[0].bls_key, sizeof(ag_bls_key_t) );
  init_keys( &ctx, auth_vtr_mem, bls_keys, 3UL ); /* the identity, authorized voters 0 and 1 */
  ctx.auth_vtr_path_cnt  = 2UL;
  ctx.auth_vtr_keyswitch = fd_keyswitch_join( fd_keyswitch_new( keyswitch, FD_KEYSWITCH_STATE_LOCKED ) );
  FD_TEST( ctx.auth_vtr_keyswitch );
  fd_clock_tile_init( ctx.clock );
  bls_pubkey_client_init( ctx.keyguard_client, bls_keys, 1UL ); /* the identity's key, if asked */

  ctx.votor = ag_votor_join( ag_votor_new( votor_scratch, 64UL, 42UL ) );
  FD_TEST( ctx.votor );
  ag_votor_init         ( ctx.votor, 0UL, 0L, 400000000L, (ushort)1, capture_sign_bls, NULL );
  ag_votor_advance_epoch( ctx.votor, 400000000L, 0UL, 0UL, bls_keys[2] );

  keyswitch->param = FD_KEYSWITCH_PARAM_AV_CLEAR;
  fd_keyswitch_state( keyswitch, FD_KEYSWITCH_STATE_SWITCH_PENDING );
  during_housekeeping( &ctx );
  FD_TEST( keyswitch->state==FD_KEYSWITCH_STATE_COMPLETED );
  FD_TEST( ctx.auth_vtr_path_cnt==0UL );
  FD_TEST( paths_idx_of( &ctx, bls_keys[0] )==ULONG_MAX );
  FD_TEST( paths_idx_of( &ctx, bls_keys[1] )==(ulong)LONG_MAX );
  FD_TEST( paths_idx_of( &ctx, bls_keys[2] )==(ulong)LONG_MAX );

  /* Block 1 builds on the root, slot 0 with a zero hash. */

  ag_event_replay_t block = { .slot = 1UL };
  memset( block.block_info.hash, 1, sizeof(ag_block_hash_t) );
  ag_votor_handle_replay_event( ctx.votor, &block );

  ag_event_vote_t vote;
  FD_TEST( !ag_votor_poll_vote_event( ctx.votor, &vote ) );

  fd_keyswitch_state( keyswitch, FD_KEYSWITCH_STATE_UNHALT_PENDING );
  during_housekeeping( &ctx );
  FD_TEST( keyswitch->state==FD_KEYSWITCH_STATE_UNLOCKED );

  ag_votor_delete( ag_votor_leave( ctx.votor ) );
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

static peer_t peers_mem[ 1UL<<PEERS_LG_SLOT_CNT ];

static peer_t *
test_peer( fd_votor_tile_t * ctx,
           uchar             id,
           ushort            curr_rank ) {
  fd_pubkey_t id_key = {0}; id_key.uc[ 0 ] = id;
  peer_t * peer = peers_insert( ctx->peers, id_key );
  peer->prev_rank = USHORT_MAX;
  peer->curr_rank = curr_rank;
  peer->next_rank = USHORT_MAX;
  peer->tx_conn   = NULL;
  peer->rx_conn   = NULL;
  peer->ban_ts    = 0L;
  return peer;
}

static void
test_can_dial( void ) {
  static fd_votor_tile_t ctx;
  ctx.peers = peers_join( peers_new( peers_mem ) );
  FD_TEST( ctx.peers );
  memset( &ctx.id_key, 0, sizeof(fd_pubkey_t) ); ctx.id_key.uc[ 0 ] = 1;

  long     now   = 100L*1000L*1000L*1000L;
  peer_t * other = test_peer( &ctx, 2, 0 );

  /* Not in the peer set (unstaked): never dial, since peers would
     refuse us with NOT_ADMITTED. */
  FD_TEST( !can_dial( &ctx, other, now ) );

  /* Ranked only in the previous epoch: until AG_REWARD_SLOT_DELTA slots
     past the boundary.  Only in the next: within
     QUIC_DIAL_NEXT_EPOCH_SLOTS of it.  Neither before anything is
     finalized. */
  ctx.curr_epoch_slot = 100000UL;
  ctx.next_epoch_slot = 200000UL;
  peer_t * self = test_peer( &ctx, 1, USHORT_MAX );
  self->prev_rank = 0;
  FD_TEST( !in_boundary_window( &ctx, self, ULONG_MAX                              ) );
  FD_TEST(  in_boundary_window( &ctx, self, 100000UL+AG_REWARD_SLOT_DELTA-1UL      ) );
  FD_TEST( !in_boundary_window( &ctx, self, 100000UL+AG_REWARD_SLOT_DELTA          ) );
  self->prev_rank = USHORT_MAX; self->next_rank = 0;
  FD_TEST( !in_boundary_window( &ctx, self, ULONG_MAX                              ) );
  FD_TEST( !in_boundary_window( &ctx, self, 200000UL-QUIC_DIAL_NEXT_EPOCH_SLOTS-1UL ) );
  FD_TEST(  in_boundary_window( &ctx, self, 200000UL-QUIC_DIAL_NEXT_EPOCH_SLOTS     ) );
  self->next_rank = USHORT_MAX;
  FD_TEST( !in_boundary_window( &ctx, self, 200000UL-QUIC_DIAL_NEXT_EPOCH_SLOTS     ) );

  /* Ranked in the current epoch: dial everyone but ourselves. */
  self->curr_rank = 1;
  FD_TEST(  can_dial( &ctx, other, now ) );
  FD_TEST( !can_dial( &ctx, self,  now ) );

  /* A peer marked for eviction is not dialed. */
  other->curr_rank = USHORT_MAX;
  FD_TEST( !can_dial( &ctx, other, now ) );
  other->curr_rank = 0;

  /* An existing conn or a ban holds off the dial. */
  fd_quic_conn_t conn[1];
  other->tx_conn = conn;                                FD_TEST( !can_dial( &ctx, other, now ) );
  other->tx_conn = NULL;
  other->ban_ts  = now-QUIC_BAN_TIMEOUT_NS+1L;          FD_TEST( !can_dial( &ctx, other, now ) );
  other->ban_ts  = now-QUIC_BAN_TIMEOUT_NS;             FD_TEST(  can_dial( &ctx, other, now ) );

  /* A closed conn, whether or not it ever handshaked, frees the peer
     for an immediate redial. */
  memset( conn, 0, sizeof(conn) );
  fd_quic_conn_set_context( conn, &other->id_key );
  other->tx_conn = conn;
  quic_client_conn_final( conn, &ctx );
  FD_TEST( !other->tx_conn && can_dial( &ctx, other, now ) );

  peers_delete( peers_leave( ctx.peers ) );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_rank_voters_resets_total_stake();
  test_quic_client_ack_range();
  test_rank_voters_bls_keys();
  test_load_keys( 0 );
  test_load_keys( 1 );
  test_auth_vtr_keyswitch_add( 0 );
  test_auth_vtr_keyswitch_add( 1 );
  test_auth_vtr_keyswitch_rejected();
  test_auth_vtr_keyswitch_refreshes_epochs();
  test_auth_vtr_keyswitch_clear();
  test_own_bls_key();
  test_sign_bls_request();
  test_can_dial();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
