#define FD_TILE_TEST 1
#include "fd_votor_tile.c"

#include <stdlib.h>

#define TEST_VOTER_MAX (4UL)

/* An ag_epoch_info_t is nearly 300 KiB, too big for the stack. */

static ag_epoch_info_t epoch_info_mem;

/* The secret BLS key of voter i in build_stakes. */

static void
voter_sec( fd_bls_sec_t * sec,
           ulong          i ) {
  memset( sec, (int)( i*7UL + 1UL ), FD_BLS_SEC_SZ );
}

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

    fd_bls_sec_t sec; voter_sec( &sec, i );
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
static uchar bls_pubkey_request [ FD_KEYGUARD_SIGN_REQ_MTU ] __attribute__((aligned(FD_CHUNK_ALIGN)));
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
  load_keys( &ctx, tile.votor.authorized_voter_paths_cnt );
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

static fd_keyswitch_t id_keyswitch_mem[1];

#define TEST_POOL_SLOT_MAX (AG_SLOTS_PER_WINDOW+AG_REWARD_SLOT_DELTA)

static uchar pool_scratch[ 160UL<<20 ] __attribute__((aligned(128))); /* ag_pool_footprint( TEST_POOL_SLOT_MAX ) is ~134 MiB, mostly untouched */

/* Returns a pool holding epoch_info from slot 0, in which we are rank. */

static ag_pool_t *
test_pool( ag_epoch_info_t const * epoch_info,
           ulong                   rank ) {
  FD_TEST( ag_pool_footprint( TEST_POOL_SLOT_MAX )<=sizeof(pool_scratch) );
  FD_TEST( fd_ulong_is_aligned( (ulong)pool_scratch, ag_pool_align() ) );
  ag_pool_t * pool = ag_pool_join( ag_pool_new( pool_scratch, TEST_POOL_SLOT_MAX, 42UL ) );
  FD_TEST( pool );
  ag_pool_init( pool, &(ag_block_id_t){ .slot = 0UL } );
  ag_pool_advance_epoch( pool, epoch_info, rank, 0UL );
  return pool;
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
  ctx.auth_vtr_keyswitch = fd_keyswitch_join( fd_keyswitch_new( keyswitch,        FD_KEYSWITCH_STATE_LOCKED   ) );
  ctx.id_keyswitch       = fd_keyswitch_join( fd_keyswitch_new( id_keyswitch_mem, FD_KEYSWITCH_STATE_UNLOCKED ) );
  FD_TEST( ctx.auth_vtr_keyswitch && ctx.id_keyswitch );
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
  ctx.auth_vtr_keyswitch = fd_keyswitch_join( fd_keyswitch_new( keyswitch,        FD_KEYSWITCH_STATE_UNHALT_PENDING ) );
  ctx.id_keyswitch       = fd_keyswitch_join( fd_keyswitch_new( id_keyswitch_mem, FD_KEYSWITCH_STATE_UNLOCKED       ) );
  FD_TEST( ctx.auth_vtr_keyswitch && ctx.id_keyswitch );
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

/* Signs with the fd_bls_sec_t at signer_ctx. */

static void
sec_sign_bls( void *         signer_ctx,
              fd_bls_sig_t * sig,
              uchar const *  public_key,
              uchar const *  payload,
              ulong          payload_sz ) {
  (void)public_key;
  fd_bls_sec_sign( (fd_bls_sec_t const *)signer_ctx, payload, payload_sz, sig );
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
  ctx.auth_vtr_keyswitch = fd_keyswitch_join( fd_keyswitch_new( keyswitch,        FD_KEYSWITCH_STATE_LOCKED   ) );
  ctx.id_keyswitch       = fd_keyswitch_join( fd_keyswitch_new( id_keyswitch_mem, FD_KEYSWITCH_STATE_UNLOCKED ) );
  FD_TEST( ctx.auth_vtr_keyswitch && ctx.id_keyswitch );
  fd_clock_tile_init( ctx.clock );
  bls_pubkey_client_init( ctx.keyguard_client, &bls_keys[1], 1UL );

  /* The epoch advanced before the add, so it has no key to vote with. */

  FD_TEST( ag_votor_footprint( 64UL )<=sizeof(votor_scratch) );
  ctx.votor = ag_votor_join( ag_votor_new( votor_scratch, 64UL, 42UL ) );
  FD_TEST( ctx.votor );
  ag_votor_init         ( ctx.votor, &(ag_block_id_t){ .slot = 0UL }, 0L, 400000000L, (ushort)1, capture_sign_bls, NULL );
  ag_votor_advance_epoch( ctx.votor, 400000000L, 1UL, 0UL, NULL );
  ctx.pool = test_pool( epoch_info, 1UL );

  keyswitch->param = FD_KEYSWITCH_PARAM_AV_ADD;
  fd_keyswitch_state( keyswitch, FD_KEYSWITCH_STATE_SWITCH_PENDING );
  during_housekeeping( &ctx );

  /* Block 1 builds on the root, slot 0 with a zero hash. */

  ag_block_info_t block = {0};
  memset( block.hash, 1, sizeof(ag_block_hash_t) );
  ag_votor_process_replay( ctx.votor, 1UL, &block );

  ag_vote_t vote;
  uchar     reason;
  FD_TEST( ag_votor_poll_vote( ctx.votor, &vote, &reason ) );
  FD_TEST( vote.kind==AG_VOTE_KIND_NOTAR );
  FD_TEST( !memcmp( last_bls_signer, bls_keys[1], sizeof(ag_bls_key_t) ) );

  ag_pool_delete( ag_pool_leave( ctx.pool ) );
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
  ctx.auth_vtr_keyswitch = fd_keyswitch_join( fd_keyswitch_new( keyswitch,        FD_KEYSWITCH_STATE_LOCKED   ) );
  ctx.id_keyswitch       = fd_keyswitch_join( fd_keyswitch_new( id_keyswitch_mem, FD_KEYSWITCH_STATE_UNLOCKED ) );
  FD_TEST( ctx.auth_vtr_keyswitch && ctx.id_keyswitch );
  fd_clock_tile_init( ctx.clock );
  bls_pubkey_client_init( ctx.keyguard_client, bls_keys, 1UL ); /* the identity's key, if asked */

  ctx.votor = ag_votor_join( ag_votor_new( votor_scratch, 64UL, 42UL ) );
  FD_TEST( ctx.votor );
  ag_votor_init         ( ctx.votor, &(ag_block_id_t){ .slot = 0UL }, 0L, 400000000L, (ushort)1, capture_sign_bls, NULL );
  ag_votor_advance_epoch( ctx.votor, 400000000L, 0UL, 0UL, bls_keys[2] );
  ctx.pool = test_pool( epoch_info, 0UL );

  keyswitch->param = FD_KEYSWITCH_PARAM_AV_CLEAR;
  fd_keyswitch_state( keyswitch, FD_KEYSWITCH_STATE_SWITCH_PENDING );
  during_housekeeping( &ctx );
  FD_TEST( keyswitch->state==FD_KEYSWITCH_STATE_COMPLETED );
  FD_TEST( ctx.auth_vtr_path_cnt==0UL );
  FD_TEST( paths_idx_of( &ctx, bls_keys[0] )==ULONG_MAX );
  FD_TEST( paths_idx_of( &ctx, bls_keys[1] )==(ulong)LONG_MAX );
  FD_TEST( paths_idx_of( &ctx, bls_keys[2] )==(ulong)LONG_MAX );

  /* Block 1 builds on the root, slot 0 with a zero hash. */

  ag_block_info_t block = {0};
  memset( block.hash, 1, sizeof(ag_block_hash_t) );
  ag_votor_process_replay( ctx.votor, 1UL, &block );

  ag_vote_t vote;
  uchar     reason;
  FD_TEST( !ag_votor_poll_vote( ctx.votor, &vote, &reason ) );

  fd_keyswitch_state( keyswitch, FD_KEYSWITCH_STATE_UNHALT_PENDING );
  during_housekeeping( &ctx );
  FD_TEST( keyswitch->state==FD_KEYSWITCH_STATE_UNLOCKED );

  ag_pool_delete( ag_pool_leave( ctx.pool ) );
  ag_votor_delete( ag_votor_leave( ctx.votor ) );
}

static fd_quic_limits_t const test_quic_limits = {
  .conn_cnt                    = 3UL,
  .handshake_cnt               = 3UL,
  .conn_id_cnt                 = FD_QUIC_MIN_CONN_ID_CNT,
  .inflight_frame_cnt          = 16UL,
  .min_inflight_frame_cnt_conn = 4UL,
};

static uchar quic_client_scratch[ 8UL<<20 ] __attribute__((aligned(FD_QUIC_ALIGN)));
static uchar quic_server_scratch[ 8UL<<20 ] __attribute__((aligned(FD_QUIC_ALIGN)));

static int
drop_aio_send( void *                    ctx,
               fd_aio_pkt_info_t const * batch,
               ulong                     batch_cnt,
               ulong *                   opt_batch_idx,
               int                       flush ) {
  (void)ctx; (void)batch; (void)batch_cnt; (void)opt_batch_idx; (void)flush;
  return FD_AIO_SUCCESS;
}

static fd_quic_t *
test_quic( uchar *           mem,
           ulong             mem_sz,
           int               role,
           fd_votor_tile_t * ctx,
           fd_aio_t const *  aio ) {
  FD_TEST( fd_quic_footprint( &test_quic_limits )<=mem_sz );
  fd_quic_t * quic = fd_quic_join( fd_quic_new( mem, &test_quic_limits ) );
  FD_TEST( quic );
  fd_quic_set_aio_net_tx( quic, aio );
  quic->config.role         = role;
  quic->config.idle_timeout = 5L*1000L*1000L*1000L;
  quic->config.ack_delay    = 2L*1000L*1000L;
  quic->config.sign         = sign_ed25519;
  quic->config.sign_ctx     = ctx;
  memcpy( quic->config.identity_public_key, ctx->id_key.uc, sizeof(fd_pubkey_t) );
  FD_TEST( fd_quic_init( quic ) );
  return quic;
}

/* Before epoch info, votor holds the replay completions it needs (the
   snapshot root's SLOT_COMPLETED initializes the pool) so stem polls
   them again, and still drops other replay sigs. */

static void
test_replay_before_epoch( void ) {
  static fd_votor_tile_t ctx;
  static ag_epoch_info_t epoch_info;
  ctx.in_kind[ 0 ]    = IN_KIND_REPLAY;
  ctx.curr_epoch_info = NULL;
  ctx.replay_in_seq   = 0UL;

  FD_TEST( before_frag( &ctx, 0UL, 5UL, REPLAY_SIG_SLOT_COMPLETED )==-1 );
  FD_TEST( before_frag( &ctx, 0UL, 5UL, REPLAY_SIG_SLOT_DEAD      )==-1 );
  FD_TEST( ctx.replay_in_seq==0UL );
  FD_TEST( before_frag( &ctx, 0UL, 4UL, REPLAY_SIG_ROOT_ADVANCED  )==1  );
  FD_TEST( ctx.replay_in_seq==5UL );

  ctx.curr_epoch_info = &epoch_info;
  FD_TEST( before_frag( &ctx, 0UL, 5UL, REPLAY_SIG_SLOT_COMPLETED )==0  );
  FD_TEST( ctx.replay_in_seq==6UL );
}

/* During set-identity votor halts right after replay.  It keeps voting
   until it has consumed replay_slot through the seq replay switched at,
   then stops voting, lets the votes it already signed go out under the
   old identity, takes the new identity and drops the old identity's
   connections.  On resume it votes as the new identity's rank and
   redials its peers. */

static void
test_id_keyswitch( void ) {
  static fd_votor_tile_t ctx;
  static auth_vtr_t      auth_vtr_mem     [ 1UL<<AUTH_VTR_LG_SLOT_CNT      ];
  static peer_t          peers_mem        [ 1UL<<PEERS_LG_SLOT_CNT         ];
  static contact_info_t  contact_infos_mem[ 1UL<<CONTACT_INFOS_LG_SLOT_CNT ];
  static uchar           mleaders_mem[ FD_MULTI_EPOCH_LEADERS_FOOTPRINT ] __attribute__((aligned(FD_MULTI_EPOCH_LEADERS_ALIGN)));
  static fd_keyswitch_t  av_keyswitch_mem[1];
  static fd_aio_t        aio_mem[1];

  /* We switch from rank 0 to rank 1, and peer with rank 2. */

  fd_vote_stake_weight_t stakes[ TEST_VOTER_MAX ];
  build_stakes( stakes, 3UL, 10UL );
  ag_epoch_info_t * epoch_info = rank_voters( &epoch_info_mem, stakes, 3UL );
  fd_pubkey_t old_id;  memcpy( old_id.uc,  epoch_info->validators[0].id_key, sizeof(fd_pubkey_t) );
  fd_pubkey_t new_id;  memcpy( new_id.uc,  epoch_info->validators[1].id_key, sizeof(fd_pubkey_t) );
  fd_pubkey_t peer_id; memcpy( peer_id.uc, epoch_info->validators[2].id_key, sizeof(fd_pubkey_t) );
  ctx.id_key          = old_id;
  ctx.curr_epoch_info = epoch_info;
  ctx.curr_epoch_slot = 0UL;

  ag_bls_key_t bls_keys[2];
  memcpy( bls_keys[0], epoch_info->validators[0].bls_key, sizeof(ag_bls_key_t) );
  memcpy( bls_keys[1], epoch_info->validators[1].bls_key, sizeof(ag_bls_key_t) );
  init_keys( &ctx, auth_vtr_mem, bls_keys, 1UL ); /* the old identity's key */
  ctx.auth_vtr_path_cnt = 0UL;
  bls_pubkey_client_init( ctx.keyguard_client, bls_keys, 2UL ); /* any bytes sign the old identity's vote history, then the new identity's key, asked on resume */
  ctx.keyguard_client->response_mtu = FD_CHUNK_SZ;              /* the 64 byte signature */
  ctx.auth_vtr_keyswitch = fd_keyswitch_join( fd_keyswitch_new( av_keyswitch_mem, FD_KEYSWITCH_STATE_UNLOCKED ) );
  ctx.id_keyswitch       = fd_keyswitch_join( fd_keyswitch_new( id_keyswitch_mem, FD_KEYSWITCH_STATE_LOCKED   ) );
  FD_TEST( ctx.auth_vtr_keyswitch && ctx.id_keyswitch );
  fd_clock_tile_init( ctx.clock );

  ctx.votor = ag_votor_join( ag_votor_new( votor_scratch, 64UL, 42UL ) );
  FD_TEST( ctx.votor );
  ag_votor_init         ( ctx.votor, &(ag_block_id_t){ .slot = 0UL }, 0L, 400000000L, (ushort)1, capture_sign_bls, NULL );
  ag_votor_advance_epoch( ctx.votor, 400000000L, 0UL, 0UL, bls_keys[0] );
  ctx.pool = test_pool( epoch_info, 0UL );
  ag_block_id_t root = { .slot = 0UL };
  ag_block_id_t b1   = { .slot = 1UL }; memset( b1.hash, 1, sizeof(ag_block_hash_t) );
  FD_TEST( ag_pool_add_block( ctx.pool, &b1, &root, ctx.scratch.bad )==AG_POOL_SUCCESS );

  ctx.mleaders      = fd_multi_epoch_leaders_join( fd_multi_epoch_leaders_new( mleaders_mem ) );
  ctx.peers         = peers_join        ( peers_new        ( peers_mem         ) );
  ctx.contact_infos = contact_infos_join( contact_infos_new( contact_infos_mem ) );
  FD_TEST( ctx.mleaders && ctx.peers && ctx.contact_infos );

  /* The new identity leads every slot, and the window at slot 4 is
     already in progress. */

  static uchar stake_msg_mem[ FD_STAKE_CI_STAKE_MSG_HEADER_SZ+FD_STAKE_CI_STAKE_MSG_RECORD_SZ ] __attribute__((aligned(8)));
  fd_stake_weight_msg_t * stake_msg = fd_type_pun( stake_msg_mem );
  *stake_msg = (fd_stake_weight_msg_t){ .epoch = 0UL, .staked_vote_cnt = 1UL, .start_slot = 0UL, .slot_cnt = 64UL };
  *(fd_vote_stake_weight_t *)fd_type_pun( stake_msg+1 ) = (fd_vote_stake_weight_t){ .vote_key = new_id, .id_key = new_id, .stake = 10UL };
  fd_multi_epoch_leaders_stake_msg_init( ctx.mleaders, stake_msg );
  fd_multi_epoch_leaders_stake_msg_fini( ctx.mleaders );
  ctx.highest_parent_ready_slot = 4UL;
  fd_aio_t * aio = fd_aio_join( fd_aio_new( aio_mem, NULL, drop_aio_send ) );
  FD_TEST( aio );
  ctx.quic_client = test_quic( quic_client_scratch, sizeof(quic_client_scratch), FD_QUIC_ROLE_CLIENT, &ctx, aio );
  ctx.quic_server = test_quic( quic_server_scratch, sizeof(quic_server_scratch), FD_QUIC_ROLE_SERVER, &ctx, aio );
  ctx.src_ip_addr             = FD_IP4_ADDR( 127, 0, 0, 1 );
  ctx.quic_client_listen_port = (ushort)9000;

  /* Votor dials only while its identity is ranked, so both identities
     are peers at their ranks. */

  fd_pubkey_t const ids[3] = { old_id, new_id, peer_id };
  peer_t *          peer   = NULL;
  for( ulong i=0UL; i<3UL; i++ ) {
    peer = peers_insert( ctx.peers, ids[ i ] );
    peer->prev_rank = USHORT_MAX;
    peer->curr_rank = (ushort)i;
    peer->next_rank = USHORT_MAX;
    peer->tx_conn   = NULL;
    peer->rx_conn   = NULL;
    peer->ban_ts    = 0L;
  }
  contact_info_t * ci = contact_infos_insert( ctx.contact_infos, peer_id );
  ci->ip4  = FD_IP4_ADDR( 127, 0, 0, 2 );
  ci->port = (ushort)9001;
  for( ulong i=0UL; i<REWARD_VOTE_MAX; i++ ) ctx.reward_votes[ i ].slot = ULONG_MAX;
  connect_peers( &ctx, fd_clock_tile_now( ctx.clock ) );
  fd_quic_conn_t * old_conn = peer->tx_conn;
  FD_TEST( old_conn );
  ctx.reward_votes[ 1UL ].slot = 1UL;

  /* The peer's established inbound conn survives the switch, since it
     identifies the peer, not us.  Inbound conns still in a handshake
     state are not rx_conns until they go active, and would complete as
     the old identity. */

  fd_quic_get_state( ctx.quic_server )->now = fd_clock_tile_now( ctx.clock );
  ulong             rx_conn_id  = 1UL;
  ulong             hs_conn_id  = 2UL;
  ulong             hc_conn_id  = 3UL;
  fd_quic_conn_id_t rx_peer_cid = fd_quic_conn_id_new( &rx_conn_id, 8UL );
  fd_quic_conn_id_t hs_peer_cid = fd_quic_conn_id_new( &hs_conn_id, 8UL );
  fd_quic_conn_id_t hc_peer_cid = fd_quic_conn_id_new( &hc_conn_id, 8UL );
  fd_quic_conn_t *  rx_conn     = fd_quic_conn_create( ctx.quic_server, rx_conn_id, &rx_peer_cid, ci->ip4, (ushort)9002, ctx.src_ip_addr, ctx.quic_server_listen_port, 1 );
  fd_quic_conn_t *  hs_conn     = fd_quic_conn_create( ctx.quic_server, hs_conn_id, &hs_peer_cid, ci->ip4, (ushort)9003, ctx.src_ip_addr, ctx.quic_server_listen_port, 1 );
  fd_quic_conn_t *  hc_conn     = fd_quic_conn_create( ctx.quic_server, hc_conn_id, &hc_peer_cid, ci->ip4, (ushort)9004, ctx.src_ip_addr, ctx.quic_server_listen_port, 1 );
  FD_TEST( rx_conn && hs_conn && hc_conn );
  rx_conn->state = FD_QUIC_CONN_STATE_ACTIVE;
  hc_conn->state = FD_QUIC_CONN_STATE_HANDSHAKE_COMPLETE;
  peer->rx_conn  = rx_conn;

  ctx.in_kind[ 0 ] = IN_KIND_NET;
  ulong net_sig = fd_disco_netmux_sig( 0U, (ushort)0, 0U, DST_PROTO_VOTOR, FD_NETMUX_SIG_MIN_HDR_SZ );
  FD_TEST( !before_frag( &ctx, 0UL, 0UL, net_sig ) );

  /* The old identity's vote history file */

  char dir[] = "/tmp/test_id_keyswitch_XXXXXX";
  FD_TEST( mkdtemp( dir ) );
  ctx.vote_history_dir_fd = open( dir, O_RDONLY|O_DIRECTORY );
  FD_TEST( -1!=ctx.vote_history_dir_fd );
  FD_BASE58_ENCODE_32_BYTES( old_id.uc, old_b58 );
  FD_TEST( fd_cstr_printf_check( ctx.vote_history_name[ 1 ], PATH_MAX, NULL, "vote_history-%s.bin", old_b58 ) );
  FD_TEST( fd_cstr_printf_check( ctx.vote_history_name[ 0 ], PATH_MAX, NULL, "%s.new", ctx.vote_history_name[ 1 ] ) );
  for( ulong i=0UL; i<2UL; i++ ) {
    ctx.vote_history_fd[ i ] = openat( ctx.vote_history_dir_fd, ctx.vote_history_name[ i ], O_WRONLY|O_CREAT, 0644 );
    FD_TEST( -1!=ctx.vote_history_fd[ i ] );
  }

  /* A vote signed as the old identity is waiting to go out, and the
     vote history does not know of it yet. */

  ag_block_info_t block = {0};
  memcpy( block.hash, b1.hash, sizeof(ag_block_hash_t) );
  ag_votor_process_replay( ctx.votor, 1UL, &block );
  FD_TEST( ag_votor_metrics( ctx.votor ).vote_events_cnt==1UL && !ctx.vote_history_pending );

  memcpy( ctx.id_keyswitch->bytes, new_id.uc, sizeof(fd_pubkey_t) );
  FD_STORE( ulong, ctx.id_keyswitch->bytes+32UL, sizeof(ulong) ); /* the vote history file's wait_to_vote_slot */
  FD_STORE( ulong, ctx.id_keyswitch->bytes+40UL, 4UL );
  ctx.id_keyswitch->param = 8UL;
  fd_keyswitch_state( ctx.id_keyswitch, FD_KEYSWITCH_STATE_SWITCH_PENDING );

  /* Replay switched at seq 8, so votor keeps voting as the old identity
     until it has consumed replay_slot through seq 7. */

  ctx.in_kind[ 1 ] = IN_KIND_REPLAY;
  FD_TEST( !before_frag( &ctx, 1UL, 6UL, REPLAY_SIG_SLOT_COMPLETED ) );
  during_housekeeping( &ctx );
  FD_TEST( ctx.id_keyswitch->state==FD_KEYSWITCH_STATE_SWITCH_PENDING && !ctx.halt_signing );
  FD_TEST( !before_frag( &ctx, 0UL, 0UL, net_sig ) );
  FD_TEST( before_frag( &ctx, 1UL, 7UL, REPLAY_SIG_ROOT_ADVANCED ) );

  during_housekeeping( &ctx );
  FD_TEST( ctx.id_keyswitch->state==FD_KEYSWITCH_STATE_SWITCH_PENDING );
  FD_TEST( fd_pubkey_eq( &ctx.id_key, &old_id ) && peer->tx_conn==old_conn );
  FD_TEST( before_frag( &ctx, 0UL, 0UL, net_sig ) );

  /* Halted, votor signs nothing more, and the queued vote goes out. */

  block = (ag_block_info_t){0};
  block.parent = b1;
  memset( block.hash, 2, sizeof(ag_block_hash_t) );
  ag_votor_process_replay( ctx.votor, 2UL, &block );
  ag_vote_t vote;
  uchar     reason;
  FD_TEST( ag_votor_poll_vote( ctx.votor, &vote, &reason ) );
  FD_TEST( ag_vote_slot( &vote )==1UL && ag_vote_rank( &vote )==0UL );
  FD_TEST( !ag_votor_metrics( ctx.votor ).vote_events_cnt );
  ctx.vote_history_pending = ag_vote_slot( &vote ); /* as after_credit does for the vote it sends */

  /* The other voters skip slot 1, which the old identity notarized, so
     the pool queues a safe-to-skip decided with the old rank.  Votor
     must handle it while it has no key, or the new identity would skip
     the rest of the window on the old identity's behalf. */

  fd_bls_sec_t secs[3];
  for( ulong rank=0UL; rank<3UL; rank++ ) voter_sec( &secs[ rank ], 2UL-rank ); /* ranked by descending stake */
  ag_vote_t pool_votes[3] = {
    ag_vote_construct_notar( sec_sign_bls, &secs[0], epoch_info->validators[0].bls_key, 1UL, b1.hash, (ushort)0, (ushort)1 ),
    ag_vote_construct_skip ( sec_sign_bls, &secs[1], epoch_info->validators[1].bls_key, 1UL,          (ushort)1, (ushort)1 ),
    ag_vote_construct_skip ( sec_sign_bls, &secs[2], epoch_info->validators[2].bls_key, 1UL,          (ushort)2, (ushort)1 )
  };
  uchar quorum_reached;
  for( ulong i=0UL; i<3UL; i++ ) {
    FD_TEST( ag_pool_add_vote( ctx.pool, &pool_votes[ i ], ctx.scratch.bad, &quorum_reached )==AG_POOL_SUCCESS );
    FD_TEST( fd_bls_set_is_null( ctx.scratch.bad ) );
  }

  during_housekeeping( &ctx );
  FD_TEST( ctx.id_keyswitch->state==FD_KEYSWITCH_STATE_SWITCH_PENDING );
  FD_TEST( fd_pubkey_eq( &ctx.id_key, &old_id ) );

  ag_pool_event_t pool_event;
  int             safe_to_skip = 0;
  while( ag_pool_poll_pool_event( ctx.pool, &pool_event ) ) {
    safe_to_skip |= pool_event.kind==AG_POOL_EVENT_SAFE_TO_SKIP && pool_event.safe_to_skip==1UL;
    ag_votor_handle_pool_event( ctx.votor, &pool_event, 0L );
  }
  FD_TEST( safe_to_skip );
  FD_TEST( !ag_votor_metrics( ctx.votor ).vote_events_cnt );

  during_housekeeping( &ctx );
  FD_TEST( ctx.id_keyswitch->state==FD_KEYSWITCH_STATE_COMPLETED );
  FD_TEST( fd_pubkey_eq( &ctx.id_key, &new_id ) );
  FD_TEST( ctx.wait_to_vote_slot==4UL );
  FD_TEST( ctx.next_leader_slot==8UL );
  FD_TEST( !memcmp( ctx.quic_client->config.identity_public_key, new_id.uc, sizeof(fd_pubkey_t) ) );
  FD_TEST( !memcmp( ctx.quic_server->config.identity_public_key, new_id.uc, sizeof(fd_pubkey_t) ) );
  FD_TEST( !peer->tx_conn && peer->rx_conn==rx_conn && ctx.reward_votes[ 1UL ].slot==ULONG_MAX );
  FD_TEST( rx_conn->state==FD_QUIC_CONN_STATE_ACTIVE );
  FD_TEST( hs_conn->state==FD_QUIC_CONN_STATE_CLOSE_PENDING && hc_conn->state==FD_QUIC_CONN_STATE_CLOSE_PENDING );
  FD_TEST( before_frag( &ctx, 0UL, 0UL, net_sig ) );

  /* The vote sent after the halt was saved in the old identity's file
     before the switch. */

  FD_TEST( !ctx.vote_history_pending && ctx.metrics.vote_history_write==1UL && ctx.metrics.vote_history_slot==1UL );
  uchar head[ AG_VOTE_HISTORY_FILE_DATA_OFF+32UL ];
  int   head_fd = openat( ctx.vote_history_dir_fd, ctx.vote_history_name[ 1 ], O_RDONLY );
  FD_TEST( -1!=head_fd && read( head_fd, head, sizeof(head) )==(long)sizeof(head) && !close( head_fd ) );
  FD_TEST( strstr( ctx.vote_history_name[ 1 ], old_b58 ) && fd_memeq( head+AG_VOTE_HISTORY_FILE_DATA_OFF, old_id.uc, 32UL ) );
  for( ulong i=0UL; i<2UL; i++ ) {
    FD_TEST( !unlinkat( ctx.vote_history_dir_fd, ctx.vote_history_name[ i ], 0 ) );
    FD_TEST( !close( ctx.vote_history_fd[ i ] ) );
  }
  FD_TEST( !close( ctx.vote_history_dir_fd ) && !rmdir( dir ) );
  ctx.vote_history_dir_fd = -1;

  /* Epoch and gossip updates still arrive while halted, but must not
     dial before the sign tile has the new key. */

  connect_peers( &ctx, fd_clock_tile_now( ctx.clock ) );
  FD_TEST( !peer->tx_conn );

  /* The admin tile switches the sign tile's keys, then resumes votor,
     which drops the old identity's votes from the vote history. */

  fd_keyswitch_state( ctx.id_keyswitch, FD_KEYSWITCH_STATE_UNHALT_PENDING );
  during_housekeeping( &ctx );
  FD_TEST( ctx.id_keyswitch->state==FD_KEYSWITCH_STATE_COMPLETED );
  FD_TEST( !ag_votor_vote_history( ctx.votor, ctx.vote_history ) && !ctx.vote_history->votes_cast_cnt );
  FD_TEST( !before_frag( &ctx, 0UL, 0UL, net_sig ) );
  FD_TEST( paths_idx_of( &ctx, bls_keys[1] )==ULONG_MAX && paths_idx_of( &ctx, bls_keys[0] )==(ulong)LONG_MAX );
  FD_TEST( ag_pool_slot_state( ctx.pool, 1UL )->own_rank==1UL );
  FD_TEST( peer->tx_conn && peer->tx_conn!=old_conn );
  FD_TEST( fd_pubkey_eq( fd_quic_conn_get_context( peer->tx_conn ), &peer_id ) );

  /* Votes now carry the new identity's rank and key.  Block 2 arrived
     while votor was halted, so its vote is never sent. */

  ag_block_id_t b2 = { .slot = 2UL }; memset( b2.hash, 2, sizeof(ag_block_hash_t) );
  ag_pool_event_t parent_ready = { .kind = AG_POOL_EVENT_PARENT_READY };
  parent_ready.parent_ready.slot   = 4UL;
  parent_ready.parent_ready.parent = b2;
  ag_votor_handle_pool_event( ctx.votor, &parent_ready, 0L );
  ag_pool_event_t b2_cert = { .kind = AG_POOL_EVENT_CERT_CREATED, .cert_created = { .kind = AG_CERT_KIND_NOTAR_FALLBACK, .notar_fallback = { .slot = 2UL } } };
  memcpy( b2_cert.cert_created.notar_fallback.block_hash, b2.hash, sizeof(ag_block_hash_t) );
  ag_votor_handle_pool_event( ctx.votor, &b2_cert, 0L );
  ag_pool_event_t skip3 = { .kind = AG_POOL_EVENT_CERT_CREATED, .cert_created = { .kind = AG_CERT_KIND_SKIP, .skip = { .slot = 3UL } } };
  ag_votor_handle_pool_event( ctx.votor, &skip3, 0L );
  block = (ag_block_info_t){0};
  block.parent = b2;
  memset( block.hash, 4, sizeof(ag_block_hash_t) );
  ag_votor_process_replay( ctx.votor, 4UL, &block );
  FD_TEST( ag_votor_poll_vote( ctx.votor, &vote, &reason ) );
  FD_TEST( ag_vote_slot( &vote )==4UL && ag_vote_rank( &vote )==1UL );
  FD_TEST( !memcmp( last_bls_signer, bls_keys[1], sizeof(ag_bls_key_t) ) );
  FD_TEST( !ag_votor_metrics( ctx.votor ).vote_events_cnt );

  /* A switch whose vote history file floor is past the next window
     leads from the floor. */

  FD_STORE( ulong, ctx.id_keyswitch->bytes+40UL, 16UL );
  fd_keyswitch_state( ctx.id_keyswitch, FD_KEYSWITCH_STATE_SWITCH_PENDING );
  during_housekeeping( &ctx );
  FD_TEST( ctx.id_keyswitch->state==FD_KEYSWITCH_STATE_COMPLETED && ctx.next_leader_slot==16UL );

  /* A floor in an epoch whose leader schedule is not known yet leaves
     no leader slot, and the epoch update that brings the schedule
     leads from the floor. */

  FD_STORE( ulong, ctx.id_keyswitch->bytes+40UL, 72UL ); /* epoch 1 starts at slot 64, not yet tracked */
  fd_keyswitch_state( ctx.id_keyswitch, FD_KEYSWITCH_STATE_SWITCH_PENDING );
  during_housekeeping( &ctx );
  FD_TEST( ctx.id_keyswitch->state==FD_KEYSWITCH_STATE_COMPLETED && ctx.wait_to_vote_slot==72UL && ctx.next_leader_slot==ULONG_MAX );

  static uchar epoch_msg_mem[ FD_EPOCH_INFO_MSG_HEADER_SZ+sizeof(fd_vote_stake_weight_t) ] __attribute__((aligned(8)));
  fd_epoch_info_msg_t * epoch_msg = fd_type_pun( epoch_msg_mem );
  *epoch_msg = (fd_epoch_info_msg_t){ .epoch = 1UL, .staked_vote_cnt = 1UL, .start_slot = 64UL, .slot_cnt = 64UL, .ns_per_slot = 400000000UL };
  fd_vote_stake_weight_t * epoch_weight = fd_epoch_info_msg_stake_weights( epoch_msg );
  *epoch_weight = (fd_vote_stake_weight_t){ .vote_key = new_id, .id_key = new_id, .stake = 10UL }; /* the new identity still leads every slot */
  memcpy( epoch_weight->bls_key, epoch_info->validators[1].bls_key, sizeof(ag_bls_key_t) );
  handle_epoch( &ctx, epoch_msg );
  FD_TEST( ctx.next_epoch_slot==64UL && fd_multi_epoch_leaders_get_next_slot( ctx.mleaders, 64UL, &new_id )==64UL );
  FD_TEST( ctx.next_leader_slot==72UL );

  ag_pool_delete( ag_pool_leave( ctx.pool ) );
  ag_votor_delete( ag_votor_leave( ctx.votor ) );
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

static peer_t         peers_mem        [ 1UL<<PEERS_LG_SLOT_CNT         ];
static contact_info_t contact_infos_mem[ 1UL<<CONTACT_INFOS_LG_SLOT_CNT ];
static uchar          reconn_prq_mem   [ 1UL<<19 ] __attribute__((aligned(128)));
static uchar          quic_mem         [ 1UL<<24 ] __attribute__((aligned(FD_QUIC_ALIGN)));
static uchar          pool_mem         [ (AG_SLOTS_PER_WINDOW+AG_REWARD_SLOT_DELTA)*sizeof(ag_slot_state_t)+(4UL<<20) ] __attribute__((aligned(128)));

static peer_t *
test_peer( fd_votor_tile_t * ctx,
           uchar             id,
           ushort            curr_rank ) {
  fd_pubkey_t id_key = {0}; id_key.uc[ 0 ] = id;
  peer_t * peer = peers_insert( ctx->peers, id_key );
  peer->prev_rank      = USHORT_MAX;
  peer->curr_rank      = curr_rank;
  peer->next_rank      = USHORT_MAX;
  peer->tx_conn        = NULL;
  peer->rx_conn        = NULL;
  peer->ban_ts         = 0L;
  peer->conn_ts        = 0L;
  peer->conn_backoff   = 0L;
  peer->reconn_pending = 0;
  return peer;
}

static contact_info_t *
test_ci( fd_votor_tile_t * ctx,
         peer_t const *    peer,
         ushort            port ) {
  contact_info_t * ci = contact_infos_insert( ctx->contact_infos, peer->id_key );
  ci->ip4  = FD_IP4_ADDR( 10, 0, 0, 1 );
  ci->port = port;
  return ci;
}

static int
test_aio_drop( void *                    ctx,
               fd_aio_pkt_info_t const * batch,
               ulong                     batch_cnt,
               ulong *                   opt_batch_idx,
               int                       flush ) {
  (void)ctx; (void)batch; (void)batch_cnt; (void)opt_batch_idx; (void)flush;
  return FD_AIO_SUCCESS;
}

/* test_ctx_new sets up the peer, contact info and reconnect state of ctx,
   with us (id 1) ranked, and a client quic with conn_cnt conns. */

static void
test_ctx_new( fd_votor_tile_t * ctx,
              ulong             conn_cnt ) {
  static fd_aio_t aio;
  ctx->peers         = peers_join( peers_new( peers_mem ) );
  ctx->contact_infos = contact_infos_join( contact_infos_new( contact_infos_mem ) );
  FD_TEST( reconn_prq_footprint( RECONN_MAX )<=sizeof(reconn_prq_mem) );
  ctx->reconn_prq    = reconn_prq_join( reconn_prq_new( reconn_prq_mem, RECONN_MAX ) );
  FD_TEST( ag_pool_footprint( AG_SLOTS_PER_WINDOW+AG_REWARD_SLOT_DELTA )<=sizeof(pool_mem) );
  ctx->pool          = ag_pool_join( ag_pool_new( pool_mem, AG_SLOTS_PER_WINDOW+AG_REWARD_SLOT_DELTA, 42UL ) );
  FD_TEST( ctx->peers && ctx->contact_infos && ctx->reconn_prq && ctx->pool );
  ag_pool_init( ctx->pool, &(ag_block_id_t){ .slot = 0UL } );
  fd_clock_tile_init( ctx->clock );
  memset( &ctx->id_key, 0, sizeof(fd_pubkey_t) ); ctx->id_key.uc[ 0 ] = 1;
  test_peer( ctx, 1, 0 );

  fd_quic_limits_t limits = { .conn_cnt=conn_cnt, .handshake_cnt=conn_cnt, .conn_id_cnt=FD_QUIC_MIN_CONN_ID_CNT, .inflight_frame_cnt=16UL, .min_inflight_frame_cnt_conn=4UL };
  FD_TEST( fd_quic_footprint( &limits )<=sizeof(quic_mem) );
  ctx->quic_client = fd_quic_join( fd_quic_new( quic_mem, &limits ) );
  FD_TEST( ctx->quic_client );
  ctx->quic_client->config.role         = FD_QUIC_ROLE_CLIENT;
  ctx->quic_client->config.idle_timeout = 5L*1000L*1000L*1000L;
  ctx->quic_client->config.ack_delay    = 2L*1000L*1000L;
  memcpy( ctx->quic_client->config.identity_public_key, ctx->id_key.uc, 32UL );
  fd_quic_set_aio_net_tx( ctx->quic_client, fd_aio_join( fd_aio_new( &aio, NULL, test_aio_drop ) ) );
  FD_TEST( fd_quic_init( ctx->quic_client ) );
}

static void
test_ctx_delete( fd_votor_tile_t * ctx ) {
  fd_quic_delete( fd_quic_leave( fd_quic_fini( ctx->quic_client ) ) );
  ag_pool_delete( ag_pool_leave( ctx->pool ) );
  reconn_prq_delete( reconn_prq_leave( ctx->reconn_prq ) );
  contact_infos_delete( contact_infos_leave( ctx->contact_infos ) );
  peers_delete( peers_leave( ctx->peers ) );
}

/* test_drop_conn forgets peer's tx conn as if we closed it ourselves. */

static void
test_drop_conn( peer_t * peer ) {
  fd_quic_conn_set_context( peer->tx_conn, NULL );
  peer->tx_conn = NULL;
}

static void
test_connect_peer( void ) {
  static fd_votor_tile_t ctx;
  test_ctx_new( &ctx, 4UL );
  long             now   = 100L*1000L*1000L*1000L;
  peer_t *         self  = peers_query( ctx.peers, ctx.id_key, NULL );
  peer_t *         other = test_peer( &ctx, 2, 0 );
  contact_info_t * ci    = test_ci( &ctx, other, 8000 );

  /* Unstaked in the current epoch: connect only ahead of the next
     epoch, within QUIC_CONN_AHEAD_NS of it (50 slots at 200 ms), and never
     before anything is finalized; otherwise peers would refuse us with
     NOT_ADMITTED. */
  ctx.next_epoch_slot = 200000UL;
  ctx.ns_per_slot     = 200000000L;
  self->curr_rank = USHORT_MAX;
  struct { ushort prev; ushort next; ulong root; int ok; } win[] = {
    { USHORT_MAX, 0,          ULONG_MAX,   0 },
    { USHORT_MAX, 0,          200000UL-51, 0 },
    { USHORT_MAX, 0,          200000UL-50, 1 },
    { USHORT_MAX, 0,          200000UL,    1 },
    { USHORT_MAX, USHORT_MAX, 200000UL-50, 0 },
    { 0,          USHORT_MAX, 200000UL-50, 0 },
  };
  for( ulong i=0UL; i<sizeof(win)/sizeof(win[0]); i++ ) {
    self->prev_rank = win[i].prev; self->next_rank = win[i].next;
    if( win[i].root==ULONG_MAX ) ag_pool_fini( ctx.pool );
    else                         ag_pool_init( ctx.pool, &(ag_block_id_t){ .slot = win[i].root } );
    quic_client_connect( &ctx, other, ci, now );
    FD_TEST( !!other->tx_conn==win[i].ok );
    if( other->tx_conn ) test_drop_conn( other );
  }
  self->prev_rank = USHORT_MAX; self->next_rank = USHORT_MAX;
  self->curr_rank = 1;

  /* Never ourselves, nor a peer marked for eviction. */
  quic_client_connect( &ctx, self, ci, now ); FD_TEST( !self->tx_conn );
  other->curr_rank = USHORT_MAX;
  quic_client_connect( &ctx, other, ci, now ); FD_TEST( !other->tx_conn );
  other->curr_rank = 0;

  /* A ban holds off the connect; a pending backoff does not. */
  other->ban_ts = now-QUIC_BAN_TIMEOUT_NS+1L;
  quic_client_connect( &ctx, other, ci, now ); FD_TEST( !other->tx_conn );
  other->ban_ts = now-QUIC_BAN_TIMEOUT_NS;
  other->conn_ts = now-1L; other->conn_backoff = QUIC_CONN_BACKOFF_MAX_NS;
  quic_client_connect( &ctx, other, ci, now );
  FD_TEST( other->tx_conn && other->conn_ts==now );

  /* An existing conn holds off a second connect. */
  fd_quic_conn_t * conn = other->tx_conn;
  quic_client_connect( &ctx, other, ci, now+1L ); FD_TEST( other->tx_conn==conn && other->conn_ts==now );

  test_ctx_delete( &ctx );
}

/* A conn that closes on its own sets the backoff and queues one reconnect
   for when it expires: one PTO of the conn's RTT estimate, doubled on
   every close, capped at max, cleared by a completed handshake. */

static void
test_conn_final_backoff( void ) {
  static fd_votor_tile_t ctx;
  test_ctx_new( &ctx, 1UL );
  peer_t *       other = test_peer( &ctx, 2, 0 );
  fd_quic_conn_t conn[1];
  memset( conn, 0, sizeof(conn) );
  fd_quic_conn_set_context( conn, &other->id_key );
  conn->rtt->smoothed_rtt     = 50e6f;
  conn->rtt->var_rtt          = 5e6f;
  conn->peer_max_ack_delay_ns = 25e6f;
  long pto = 95000000L; /* 50 ms + 4*5 ms + 25 ms */

  long t      = fd_clock_tile_now( ctx.clock );
  long expect = pto;
  for( ulong i=0UL; i<16UL; i++ ) {
    other->tx_conn = conn; other->conn_ts = t;
    quic_client_conn_final( conn, &ctx );
    FD_TEST( !other->tx_conn && other->conn_backoff==expect );
    FD_TEST( other->reconn_pending && reconn_prq_cnt( ctx.reconn_prq )==1UL );
    FD_TEST( ctx.reconn_prq[ 0 ].timeout==other->conn_ts+expect );
    reconn_prq_remove_min( ctx.reconn_prq ); other->reconn_pending = 0;
    expect = fd_long_min( 2L*expect, QUIC_CONN_BACKOFF_MAX_NS );
  }
  FD_TEST( other->conn_backoff==QUIC_CONN_BACKOFF_MAX_NS );

  /* However long it lived, a conn that never completed its handshake
     keeps the (capped) backoff; a completed handshake clears it, so the
     next close backs off from one PTO again. */
  other->tx_conn = conn; other->conn_ts = fd_clock_tile_now( ctx.clock )-QUIC_CONN_BACKOFF_MAX_NS;
  quic_client_conn_final( conn, &ctx );
  FD_TEST( other->conn_backoff==QUIC_CONN_BACKOFF_MAX_NS );
  reconn_prq_remove_min( ctx.reconn_prq ); other->reconn_pending = 0;
  static fd_quic_tls_hs_t hs;
  memcpy( hs.hs.cli.server_pubkey, other->id_key.uc, sizeof(fd_pubkey_t) );
  conn->tls_hs = &hs;
  other->tx_conn = conn;
  quic_client_conn_hs_complete( conn, &ctx );
  FD_TEST( other->tx_conn==conn && other->conn_backoff==0L );
  conn->tls_hs = NULL;
  quic_client_conn_final( conn, &ctx );
  FD_TEST( other->conn_backoff==pto && ctx.reconn_prq[ 0 ].timeout==other->conn_ts+pto );

  /* A second close while a reconnect is queued does not queue another. */
  other->tx_conn = conn;
  quic_client_conn_final( conn, &ctx );
  FD_TEST( reconn_prq_cnt( ctx.reconn_prq )==1UL );

  /* A conn we closed ourselves (context cleared) queues nothing. */
  reconn_prq_remove_all( ctx.reconn_prq ); other->reconn_pending = 0;
  fd_quic_conn_set_context( conn, NULL );
  quic_client_conn_final( conn, &ctx );
  FD_TEST( !reconn_prq_cnt( ctx.reconn_prq ) );

  test_ctx_delete( &ctx );
}

/* A connect that fails for lack of conns is not a connect, so it must not
   restart the peer's backoff, but it is retried. */

static void
test_connect_fail_keeps_backoff( void ) {
  static fd_votor_tile_t ctx;
  test_ctx_new( &ctx, 1UL );
  long             now = 100L*1000L*1000L*1000L;
  peer_t *         a   = test_peer( &ctx, 2, 0 );
  peer_t *         b   = test_peer( &ctx, 3, 0 );
  contact_info_t * ci  = test_ci( &ctx, a, 8000 );

  quic_client_connect( &ctx, a, ci, now ); /* takes the only conn */
  FD_TEST( a->tx_conn && a->conn_ts==now );

  b->conn_ts = now-QUIC_CONN_BACKOFF_MAX_NS; b->conn_backoff = QUIC_CONN_BACKOFF_MAX_NS;
  quic_client_connect( &ctx, b, ci, now );
  FD_TEST( !b->tx_conn && b->conn_ts==now-QUIC_CONN_BACKOFF_MAX_NS && b->conn_backoff==QUIC_CONN_BACKOFF_MAX_NS );
  FD_TEST( b->reconn_pending && reconn_prq_cnt( ctx.reconn_prq )==1UL && ctx.reconn_prq[ 0 ].timeout==now+QUIC_CONN_BACKOFF_MIN_NS );

  test_ctx_delete( &ctx );
}

static void
test_gossip_connects_new_address( void ) {
  static fd_votor_tile_t            ctx;
  static fd_gossip_update_message_t msg;
  test_ctx_new( &ctx, 4UL );
  peer_t * other = test_peer( &ctx, 2, 0 );
  memcpy( msg.origin, other->id_key.uc, sizeof(fd_pubkey_t) );
  fd_gossip_socket_t * sock = &msg.contact_info->value->sockets[ FD_GOSSIP_CONTACT_INFO_SOCKET_ALPENGLOW ];
  sock->ip4  = FD_IP4_ADDR( 10, 0, 0, 1 );
  sock->port = fd_ushort_bswap( 8000 );

  /* A new address connects at once with a fresh backoff. */
  other->conn_backoff = QUIC_CONN_BACKOFF_MAX_NS;
  handle_gossip( &ctx, FD_GOSSIP_UPDATE_TAG_CONTACT_INFO, &msg );
  FD_TEST( contact_infos_query( ctx.contact_infos, other->id_key, NULL ) );
  FD_TEST( other->tx_conn && other->conn_backoff==0L );

  /* A refresh of the same address connects nothing, even without a conn,
     and keeps the backoff. */
  test_drop_conn( other );
  other->conn_backoff = QUIC_CONN_BACKOFF_MAX_NS;
  handle_gossip( &ctx, FD_GOSSIP_UPDATE_TAG_CONTACT_INFO, &msg );
  FD_TEST( !other->tx_conn && other->conn_backoff==QUIC_CONN_BACKOFF_MAX_NS );

  /* A changed address, in place or after a removal, connects at once with
     a fresh backoff. */
  sock->port = fd_ushort_bswap( 8001 );
  handle_gossip( &ctx, FD_GOSSIP_UPDATE_TAG_CONTACT_INFO, &msg );
  FD_TEST( other->tx_conn && other->conn_backoff==0L );

  /* A removal forgets the address but leaves the conn up. */
  handle_gossip( &ctx, FD_GOSSIP_UPDATE_TAG_CONTACT_INFO_REMOVE, &msg );
  FD_TEST( !contact_infos_query( ctx.contact_infos, other->id_key, NULL ) && other->tx_conn );
  other->conn_backoff = QUIC_CONN_BACKOFF_MAX_NS;
  sock->ip4 = FD_IP4_ADDR( 10, 0, 0, 2 );
  handle_gossip( &ctx, FD_GOSSIP_UPDATE_TAG_CONTACT_INFO, &msg );
  FD_TEST( other->tx_conn && other->conn_backoff==0L );

  /* 0.0.0.0 is unreachable, like port 0, so it is a removal. */
  sock->ip4 = 0U;
  handle_gossip( &ctx, FD_GOSSIP_UPDATE_TAG_CONTACT_INFO, &msg );
  FD_TEST( other->tx_conn && !contact_infos_query( ctx.contact_infos, other->id_key, NULL ) );

  test_ctx_delete( &ctx );
}

/* gossip only sends a contact info again when it changes, so one that
   arrives before the peer is staked is kept, and the peer is connected
   once it is. */

static void
test_gossip_before_stake( void ) {
  static fd_votor_tile_t            ctx;
  static fd_gossip_update_message_t msg;
  test_ctx_new( &ctx, 4UL );
  fd_pubkey_t id_key = {0}; id_key.uc[ 0 ] = 2;
  memcpy( msg.origin, id_key.uc, sizeof(fd_pubkey_t) );
  fd_gossip_socket_t * sock = &msg.contact_info->value->sockets[ FD_GOSSIP_CONTACT_INFO_SOCKET_ALPENGLOW ];
  sock->ip4  = FD_IP4_ADDR( 10, 0, 0, 1 );
  sock->port = fd_ushort_bswap( 8000 );

  handle_gossip( &ctx, FD_GOSSIP_UPDATE_TAG_CONTACT_INFO, &msg );
  FD_TEST( contact_infos_query( ctx.contact_infos, id_key, NULL ) );

  peer_t * other = test_peer( &ctx, 2, 0 );
  connect_peers( &ctx, fd_clock_tile_now( ctx.clock ) );
  FD_TEST( other->tx_conn );

  test_ctx_delete( &ctx );
}

/* A tile ranked 0 in a three-voter epoch with consensus up at slot 0,
   failover on, booted under its own key, for the history tests. */

static ag_epoch_info_t *
hist_setup( fd_votor_tile_t * ctx ) {
  memset( ctx, 0, sizeof(fd_votor_tile_t) );
  fd_vote_stake_weight_t stakes[ TEST_VOTER_MAX ];
  build_stakes( stakes, 3UL, 10UL );
  ag_epoch_info_t * epoch_info = rank_voters( &epoch_info_mem, stakes, 3UL );
  memcpy( ctx->id_key.uc, epoch_info->validators[0].id_key, sizeof(fd_pubkey_t) );
  ctx->boot_id_key              = ctx->id_key;
  ctx->curr_epoch_info          = epoch_info;
  ctx->failover_enabled         = 1;
  ctx->hist_out_idx             = ULONG_MAX;
  ctx->failov_out_idx           = ULONG_MAX;
  ctx->last_leader_slot         = ULONG_MAX;
  ctx->adopted_last_leader_slot = ULONG_MAX;
  ctx->last_vote_slot           = ULONG_MAX;
  ctx->root_slot                = ULONG_MAX;

  ctx->pool  = test_pool( epoch_info, 0UL );
  ctx->votor = ag_votor_join( ag_votor_new( votor_scratch, 64UL, 42UL ) );
  FD_TEST( ctx->votor );
  ag_votor_init         ( ctx->votor, &(ag_block_id_t){ .slot = 0UL }, 0L, 400000000L, (ushort)1, capture_sign_bls, NULL );
  ag_votor_advance_epoch( ctx->votor, 400000000L, 0UL, 0UL, epoch_info->validators[0].bls_key );
  ctx->init = 1;
  return epoch_info;
}

static void
hist_teardown( fd_votor_tile_t * ctx ) {
  ag_votor_delete( ag_votor_leave( ctx->votor ) );
  ag_pool_delete( ag_pool_leave( ctx->pool ) );
}

/* after_credit connects queued peers once due and leaves the rest,
   requeues one whose backoff grew, and drops entries for peers that
   can no longer be connected. */

static void
test_reconnect( void ) {
  static fd_votor_tile_t ctx;
  test_ctx_new( &ctx, 4UL );
  ctx.quic_server = ctx.quic_client; /* after_credit services both */
  ctx.net_tx_cnt  = 0UL;
  ctx.init        = 0;               /* stop after the reconnects */
  peer_t * a     = test_peer( &ctx, 2, 0 );
  peer_t * b     = test_peer( &ctx, 3, 0 );
  peer_t * later = test_peer( &ctx, 4, 0 );
  peer_t * noci  = test_peer( &ctx, 5, 0 );
  test_ci( &ctx, a,     8000 );
  test_ci( &ctx, b,     8001 );
  test_ci( &ctx, later, 8002 );

  long     t    = fd_clock_tile_now( ctx.clock );
  long     wait = 60L*1000L*1000L*1000L;
  reconn_t e;
  a->conn_ts = t-QUIC_CONN_BACKOFF_MIN_NS; a->conn_backoff = QUIC_CONN_BACKOFF_MIN_NS;
  e = (reconn_t){ .timeout = t,      .id_key = a->id_key     }; reconn_prq_insert( ctx.reconn_prq, &e ); a->reconn_pending     = 1;
  e = (reconn_t){ .timeout = t,      .id_key = noci->id_key  }; reconn_prq_insert( ctx.reconn_prq, &e ); noci->reconn_pending  = 1;
  e = (reconn_t){ .timeout = t+wait, .id_key = later->id_key }; reconn_prq_insert( ctx.reconn_prq, &e ); later->reconn_pending = 1;

  /* b's entry predates a larger backoff: it goes back in. */
  b->conn_ts = t; b->conn_backoff = QUIC_CONN_BACKOFF_MAX_NS;
  e = (reconn_t){ .timeout = t,      .id_key = b->id_key     }; reconn_prq_insert( ctx.reconn_prq, &e ); b->reconn_pending     = 1;

  int busy = 0;
  after_credit( &ctx, NULL, NULL, &busy );
  FD_TEST( a->tx_conn && !a->reconn_pending );
  FD_TEST( !noci->tx_conn && !noci->reconn_pending );
  FD_TEST( !later->tx_conn && later->reconn_pending );
  FD_TEST( !b->tx_conn && b->reconn_pending && reconn_prq_cnt( ctx.reconn_prq )==2UL );
  FD_TEST( ctx.reconn_prq[ 0 ].timeout==t+wait || ctx.reconn_prq[ 0 ].timeout==t+QUIC_CONN_BACKOFF_MAX_NS );

  /* Unstaked, a due entry is dropped without a connect. */
  peers_query( ctx.peers, ctx.id_key, NULL )->curr_rank = USHORT_MAX;
  test_drop_conn( a ); a->conn_backoff = 0L;
  e = (reconn_t){ .timeout = t, .id_key = a->id_key }; reconn_prq_insert( ctx.reconn_prq, &e ); a->reconn_pending = 1;
  after_credit( &ctx, NULL, NULL, &busy );
  FD_TEST( !a->tx_conn && !a->reconn_pending && reconn_prq_cnt( ctx.reconn_prq )==2UL );

  test_ctx_delete( &ctx );
}

/* Ranked only in the next epoch, housekeeping queues one connect per
   peer once the epoch is within QUIC_CONN_AHEAD_NS, spread over the first
   half of it, and only once per epoch. */

static void
test_conn_ahead( void ) {
  static fd_votor_tile_t ctx;
  static fd_keyswitch_t  keyswitch[1];
  test_ctx_new( &ctx, 4UL );
  ctx.auth_vtr_keyswitch = fd_keyswitch_join( fd_keyswitch_new( keyswitch,        FD_KEYSWITCH_STATE_LOCKED   ) );
  ctx.id_keyswitch       = fd_keyswitch_join( fd_keyswitch_new( id_keyswitch_mem, FD_KEYSWITCH_STATE_UNLOCKED ) );
  ctx.next_epoch_slot    = 200000UL;
  ctx.ns_per_slot        = 200000000L;
  ctx.quic_server        = ctx.quic_client; /* after_credit services both */
  ctx.init               = 0;               /* stop after the reconnects */
  peer_t * self = peers_query( ctx.peers, ctx.id_key, NULL );
  self->curr_rank = USHORT_MAX; self->next_rank = 0;
  peer_t * a = test_peer( &ctx, 2, 0 ); test_ci( &ctx, a, 8000 );
  peer_t * b = test_peer( &ctx, 3, 0 ); test_ci( &ctx, b, 8001 );
  test_peer( &ctx, 4, 0 ); /* no contact info: nothing to connect to */

  ag_pool_init( ctx.pool, &(ag_block_id_t){ .slot = 200000UL-51UL } );
  during_housekeeping( &ctx );
  FD_TEST( !reconn_prq_cnt( ctx.reconn_prq ) && ctx.conn_ahead_slot!=ctx.next_epoch_slot );

  ag_pool_init( ctx.pool, &(ag_block_id_t){ .slot = 200000UL-50UL } );
  long t = fd_clock_tile_now( ctx.clock );
  during_housekeeping( &ctx );
  FD_TEST( reconn_prq_cnt( ctx.reconn_prq )==2UL && a->reconn_pending && b->reconn_pending );
  FD_TEST( ctx.conn_ahead_slot==ctx.next_epoch_slot );
  long lo = fd_long_min( ctx.reconn_prq[ 0 ].timeout, ctx.reconn_prq[ 1 ].timeout );
  long hi = fd_long_max( ctx.reconn_prq[ 0 ].timeout, ctx.reconn_prq[ 1 ].timeout );
  FD_TEST( lo>=t && hi-lo>=QUIC_CONN_AHEAD_NS/4L-1000000L && hi<=t+QUIC_CONN_AHEAD_NS/2L );

  /* Not again for the same epoch. */
  reconn_prq_remove_all( ctx.reconn_prq ); a->reconn_pending = 0; b->reconn_pending = 0;
  during_housekeeping( &ctx );
  FD_TEST( !reconn_prq_cnt( ctx.reconn_prq ) );

  test_ctx_delete( &ctx );
}

/* Park scheduling: next_deadline is the earliest QUIC, skip timeout or
   reward retry obligation.  Nothing pending parks untimed, a pending
   skip timer parks until it and fires on the pass that wakes, a reward
   retry that cannot go out makes no past deadline (no busy spin), and
   every pass that pops a vote charges busy, so the stem never parks
   with votes queued. */

#define PARK_SLOT_MAX (AG_SLOTS_PER_WINDOW+AG_REWARD_SLOT_DELTA)

static uchar park_quic_mem [ 2 ][ 1UL<<20 ] __attribute__((aligned(FD_QUIC_ALIGN)));
static uchar park_votor_mem[ 1UL<<20 ] __attribute__((aligned(128)));
static uchar park_peers_mem[ 1UL<<20 ] __attribute__((aligned(128)));

static void
park_sign( void *         ctx,
           fd_bls_sig_t * sig,
           uchar const *  public_key,
           uchar const *  payload,
           ulong          payload_sz ) {
  (void)ctx; (void)public_key; (void)payload; (void)payload_sz;
  memset( sig, 0, sizeof(fd_bls_sig_t) );
}

static int
park_aio_tx( void *                    ctx,
             fd_aio_pkt_info_t const * batch,
             ulong                     batch_cnt,
             ulong *                   opt_batch_idx,
             int                       flush ) {
  (void)ctx; (void)batch; (void)flush;
  if( opt_batch_idx ) *opt_batch_idx = batch_cnt;
  return FD_AIO_SUCCESS;
}

static fd_quic_t *
park_quic( void * mem,
           int    role ) {
  fd_quic_limits_t limits = { .conn_cnt = 4UL, .handshake_cnt = 4UL, .conn_id_cnt = FD_QUIC_MIN_CONN_ID_CNT,
                              .inflight_frame_cnt = 64UL, .min_inflight_frame_cnt_conn = 8UL };
  FD_TEST( fd_quic_footprint( &limits )<=sizeof(park_quic_mem[0]) );
  fd_quic_t * quic = fd_quic_join( fd_quic_new( mem, &limits ) );
  FD_TEST( quic );
  static fd_aio_t aio[ 2 ];
  fd_quic_set_aio_net_tx( quic, fd_aio_join( fd_aio_new( &aio[ role==FD_QUIC_ROLE_SERVER ], NULL, park_aio_tx ) ) );
  quic->config.role         = role;
  quic->config.idle_timeout = (long)5e9;
  quic->config.ack_delay    = (long)2e6;
  memset( quic->config.identity_public_key, 1, 32UL );
  FD_TEST( fd_quic_init( quic ) );
  return quic;
}

static void
test_park( void ) {
  static fd_votor_tile_t ctx[1];
  memset( ctx, 0, sizeof(fd_votor_tile_t) );
  fd_clock_tile_init( ctx->clock );

  void * park_pool_mem = aligned_alloc( ag_pool_align(), fd_ulong_align_up( ag_pool_footprint( PARK_SLOT_MAX ), ag_pool_align() ) );
  FD_TEST( park_pool_mem );
  FD_TEST( ag_votor_footprint( PARK_SLOT_MAX )<=sizeof(park_votor_mem) );
  FD_TEST( peers_footprint()<=sizeof(park_peers_mem) );
  ctx->pool        = ag_pool_join ( ag_pool_new ( park_pool_mem,  PARK_SLOT_MAX, 42UL ) );
  ctx->votor       = ag_votor_join( ag_votor_new( park_votor_mem, PARK_SLOT_MAX, 42UL ) );
  ctx->peers       = peers_join( peers_new( park_peers_mem ) );
  ctx->reconn_prq  = reconn_prq_join( reconn_prq_new( reconn_prq_mem, RECONN_MAX ) );
  ctx->quic_client = park_quic( park_quic_mem[ 0 ], FD_QUIC_ROLE_CLIENT );
  ctx->quic_server = park_quic( park_quic_mem[ 1 ], FD_QUIC_ROLE_SERVER );
  static uchar mleaders_mem[ FD_MULTI_EPOCH_LEADERS_FOOTPRINT ] __attribute__((aligned(FD_MULTI_EPOCH_LEADERS_ALIGN)));
  ctx->mleaders    = fd_multi_epoch_leaders_join( fd_multi_epoch_leaders_new( mleaders_mem ) );
  FD_TEST( ctx->pool && ctx->votor && ctx->peers && ctx->reconn_prq && ctx->mleaders );
  for( ulong i=0UL; i<REWARD_VOTE_MAX; i++ ) ctx->reward_votes[ i ].slot = ULONG_MAX;
  ctx->next_leader_slot = ULONG_MAX;
  ctx->ns_per_slot      = 400000000L;
  int charge_busy;

  /* Not yet init: no QUIC conns and nothing else counts. */
  FD_TEST( next_deadline( ctx )==LONG_MAX );

  /* Init sets the skip timers of the root's window: the park is timed
     on the earliest one (the window's first slot), in the tickcount
     domain. */
  long now = fd_clock_tile_now( ctx->clock );
  uchar bls_pubkey[ FD_BLS_PUB_COMPRESSED_SZ ] = { 1 };
  ag_pool_init ( ctx->pool, &(ag_block_id_t){ .slot = 0UL } );
  ag_votor_init( ctx->votor, &(ag_block_id_t){ .slot = 0UL }, now, ctx->ns_per_slot, 1, park_sign, ctx );
  ag_votor_advance_epoch( ctx->votor, ctx->ns_per_slot, 0UL, 0UL, bls_pubkey );
  ctx->shred_version = 1;

  /* Timers are set but after_credit only polls them once init (epoch
     info missing): counting them would be a past deadline, a spin. */
  FD_TEST( ag_votor_next_skip_timeout( ctx->votor )!=LONG_MAX );
  FD_TEST( next_deadline( ctx )==LONG_MAX );

  ctx->init = 1;
  long timeout = ag_votor_next_skip_timeout( ctx->votor );
  FD_TEST( timeout==now+AG_DELTA_TIMEOUT_NS+ctx->ns_per_slot );
  long due = next_deadline( ctx );
  FD_TEST( due==fd_clock_tile_wallclock_to_tickcount( ctx->clock, timeout ) );
  FD_TEST( due>fd_tickcount() );

  /* A reconnect due before the timer moves the park up. */
  reconn_t reconn = { .timeout = timeout-1000L, .id_key = ctx->id_key };
  reconn_prq_insert( ctx->reconn_prq, &reconn );
  FD_TEST( next_deadline( ctx )==fd_clock_tile_wallclock_to_tickcount( ctx->clock, timeout-1000L ) );
  reconn_prq_remove_min( ctx->reconn_prq );

  /* A fruitless pass before the timer does not charge busy (the stem
     parks) and leaves the deadline where it was. */
  charge_busy = 0;
  after_credit( ctx, NULL, NULL, &charge_busy );
  FD_TEST( !charge_busy );
  FD_TEST( ag_votor_next_skip_timeout( ctx->votor )==timeout );

  /* The clock reaches the timer: the deadline is due (never park past
     it) and the pass that wakes pops it.  It is the root's, so no vote,
     and the park moves on to slot 1's timer, one slot later. */
  fd_clock_tile_set( ctx->clock, timeout );
  FD_TEST( next_deadline( ctx )<=fd_tickcount() );
  charge_busy = 0;
  after_credit( ctx, NULL, NULL, &charge_busy );
  FD_TEST( charge_busy );
  uchar reason;
  FD_TEST( !ag_votor_poll_vote( ctx->votor, &ctx->scratch.vote, &reason ) );
  long timeout1 = ag_votor_next_skip_timeout( ctx->votor );
  FD_TEST( timeout1==timeout+ctx->ns_per_slot );
  FD_TEST( next_deadline( ctx )>fd_tickcount() );
  charge_busy = 0;
  after_credit( ctx, NULL, NULL, &charge_busy );
  FD_TEST( !charge_busy );

  /* Slot 1's timer skips the rest of the window: three skip votes, one
     per pass, each charging busy though there is no epoch info to
     broadcast them against, so the stem never parks with votes queued.
     Then the passes go quiet. */
  fd_clock_tile_set( ctx->clock, timeout1 );
  ulong busy_cnt = 0UL;
  for( ulong i=0UL; i<16UL; i++ ) {
    charge_busy = 0;
    after_credit( ctx, NULL, NULL, &charge_busy );
    if( !charge_busy ) break;
    busy_cnt++;
  }
  FD_TEST( busy_cnt==3UL ); /* the pop sends the first vote in the same pass */
  FD_TEST( !ag_votor_poll_vote( ctx->votor, &ctx->scratch.vote, &reason ) );
  long next = ag_votor_next_skip_timeout( ctx->votor );
  FD_TEST( next==timeout1+ctx->ns_per_slot ); /* slot 2: still set, a no-op when it fires */

  /* A reward retry whose leader has no active conn waits for the frag
     that brings one up: it adds no deadline, due or not. */
  fd_clock_tile_set( ctx->clock, timeout+(long)10e9 );
  ulong timeout_slot;
  while( ag_votor_poll_skip_timeout( ctx->votor, LONG_MAX-1L, &timeout_slot ) ) ag_votor_handle_skip_timeout( ctx->votor, timeout_slot );
  while( ag_votor_poll_vote( ctx->votor, &ctx->scratch.vote, &reason ) );
  FD_TEST( ag_votor_next_skip_timeout( ctx->votor )==LONG_MAX );
  FD_TEST( next_deadline( ctx )==LONG_MAX );
  reward_vote_t * rv = &ctx->reward_votes[ 5UL%REWARD_VOTE_MAX ];
  rv->slot     = 5UL;
  rv->retry_ts = timeout;
  FD_TEST( next_deadline( ctx )==LONG_MAX );
  charge_busy = 0;
  after_credit( ctx, NULL, NULL, &charge_busy );
  FD_TEST( !charge_busy );
  FD_TEST( next_deadline( ctx )==LONG_MAX );
  FD_TEST( rv->slot==5UL );

  reconn_prq_delete( reconn_prq_leave( ctx->reconn_prq ) );
  free( park_pool_mem );
  FD_LOG_NOTICE(( "pass: test_park" ));
}

static uchar vote_history_request [ FD_KEYGUARD_SIGN_REQ_MTU ] __attribute__((aligned(FD_CHUNK_ALIGN)));
static uchar vote_history_response[ FD_CHUNK_SZ ]              __attribute__((aligned(FD_CHUNK_ALIGN)));

/* Joins client to a signer that has prepublished cnt zero signatures as
   its next responses. */

static void
sign_client_init( fd_keyguard_client_t * client,
                  ulong                  cnt ) {
  memset( client, 0, sizeof(fd_keyguard_client_t) );
  client->request        = fd_mcache_join( fd_mcache_new( bls_pubkey_request_mcache,  128UL, 0UL, 0UL ) );
  client->response       = fd_mcache_join( fd_mcache_new( bls_pubkey_response_mcache, 128UL, 0UL, 0UL ) );
  FD_TEST( client->request && client->response );
  client->request_depth  = 128UL;
  client->response_depth = 128UL;
  client->request_mem    = (fd_wksp_t *)vote_history_request;
  client->response_mem   = (fd_wksp_t *)vote_history_response;
  client->request_mtu    = sizeof(vote_history_request);
  client->response_mtu   = 64UL;
  for( ulong i=0UL; i<cnt; i++ ) fd_mcache_publish( client->response, 128UL, i, FD_KEYGUARD_SIGN_TYPE_ED25519, 0UL, 64UL, 0UL, 0UL, 0UL );
}

static void
file_make( int          dir_fd,
           char const * name,
           char const * text ) {
  int fd = openat( dir_fd, name, O_WRONLY|O_CREAT|O_TRUNC, 0644 );
  FD_TEST( -1!=fd );
  FD_TEST( (long)strlen( text )==write( fd, text, strlen( text ) ) );
  FD_TEST( !close( fd ) );
}

/* file_is returns whether name holds text, or if text is NULL, a vote
   history file for identity. */

static int
file_is( int                 dir_fd,
         char const *        name,
         char const *        text,
         fd_pubkey_t const * identity ) {
  uchar buf[ AG_VOTE_HISTORY_FILE_DATA_OFF+32UL ] = {0};
  int   fd = openat( dir_fd, name, O_RDONLY );
  if( -1==fd ) return 0;
  long n = read( fd, buf, sizeof(buf) );
  FD_TEST( !close( fd ) );
  if( text ) return n==(long)strlen( text ) && !memcmp( buf, text, strlen( text ) );
  return n==(long)sizeof(buf) && FD_LOAD( uint, buf )==AG_VOTE_HISTORY_FILE_KIND && fd_memeq( buf+AG_VOTE_HISTORY_FILE_DATA_OFF, identity->uc, 32UL );
}

/* vote_history_write writes the votes votor cast, renames the files to
   a new identity on the first write after a switch, keeps a file that
   already has the new name under .old, and empties the live file while
   the history does not fit. */

static void
test_vote_history_write( void ) {
  static fd_votor_tile_t ctx;
  sign_client_init( ctx.keyguard_client, 8UL );

  ag_bls_key_t bls_key[1];
  fd_bls_sec_t sec[1];
  fd_bls_pub_t pub[1];
  build_bls_keys( bls_key, sec, pub, 1UL );
  ctx.votor = ag_votor_join( ag_votor_new( votor_scratch, 64UL, 42UL ) );
  ag_votor_init         ( ctx.votor, &(ag_block_id_t){ .slot = 0UL }, 0L, 400000000L, (ushort)1, capture_sign_bls, NULL );
  ag_votor_advance_epoch( ctx.votor, 400000000L, 0UL, 0UL, bls_key[0] );

  ag_block_info_t block = {0};
  memset( block.hash, 1, sizeof(ag_block_hash_t) );
  ag_votor_process_replay( ctx.votor, 1UL, &block );
  ag_vote_t vote;
  uchar     reason;
  FD_TEST( ag_votor_poll_vote( ctx.votor, &vote, &reason ) && vote.kind==AG_VOTE_KIND_NOTAR );

  char dir[] = "/tmp/test_vote_history_write_XXXXXX";
  FD_TEST( mkdtemp( dir ) );
  int dir_fd = open( dir, O_RDONLY|O_DIRECTORY );
  FD_TEST( -1!=dir_fd );
  ctx.vote_history_dir_fd = dir_fd;

  /* identities U and A */

  fd_pubkey_t id[ 2 ];
  char        name[ 2 ][ 2 ][ PATH_MAX ];
  char        old[ PATH_MAX ];
  for( ulong i=0UL; i<2UL; i++ ) {
    memset( id[ i ].uc, (int)(0x11UL*(i+1UL)), 32UL );
    FD_BASE58_ENCODE_32_BYTES( id[ i ].uc, b58 );
    FD_TEST( fd_cstr_printf_check( name[ i ][ 1 ], PATH_MAX, NULL, "vote_history-%s.bin", b58 ) );
    FD_TEST( fd_cstr_printf_check( name[ i ][ 0 ], PATH_MAX, NULL, "%s.new", name[ i ][ 1 ] ) );
  }
  FD_TEST( fd_cstr_printf_check( old, PATH_MAX, NULL, "%s.old", name[ 1 ][ 1 ] ) );

  ctx.id_key = id[ 0 ];
  memcpy( ctx.vote_history_name, name[ 0 ], sizeof(name[ 0 ]) );
  for( ulong i=0UL; i<2UL; i++ ) {
    ctx.vote_history_fd[ i ] = openat( dir_fd, ctx.vote_history_name[ i ], O_WRONLY|O_CREAT, 0644 );
    FD_TEST( -1!=ctx.vote_history_fd[ i ] );
  }

  /* the first write as U, whose first bytes look like a txn message
     header */

  ctx.vote_history_pending = 1UL;
  vote_history_write( &ctx );
  FD_TEST( file_is( dir_fd, name[ 0 ][ 1 ], NULL, &id[ 0 ] ) );
  FD_TEST( !ctx.vote_history_pending && ctx.metrics.vote_history_write==1UL && ctx.metrics.vote_history_slot==1UL );

  /* switching to A, whose name has the vote history file passed to
     set-identity, keeps that file under an .old name */

  file_make( dir_fd, name[ 1 ][ 1 ], "copy" );
  ctx.id_key               = id[ 1 ];
  ctx.vote_history_pending = 1UL;
  vote_history_write( &ctx );
  FD_TEST( file_is( dir_fd, name[ 1 ][ 1 ], NULL,   &id[ 1 ] ) );
  FD_TEST( file_is( dir_fd, name[ 1 ][ 0 ], NULL,   &id[ 0 ] ) );
  FD_TEST( file_is( dir_fd, old,            "copy", NULL     ) );
  FD_TEST( -1==faccessat( dir_fd, name[ 0 ][ 0 ], F_OK, 0 ) && -1==faccessat( dir_fd, name[ 0 ][ 1 ], F_OK, 0 ) );

  /* a skip or notar and 7 notar fallbacks in each slot do not fit, so
     the live file is emptied, once */

  for( ulong slot=1UL; slot<64UL; slot++ ) {
    for( ulong i=0UL; i<AG_EQVOC_BLOCK_HASH_MAX; i++ ) {
      ag_pool_event_t event = { .kind = AG_POOL_EVENT_SAFE_TO_NOTAR, .safe_to_notar = { .slot = slot } };
      memset( event.safe_to_notar.hash, (int)( i+2UL ), sizeof(ag_block_hash_t) );
      ag_votor_handle_pool_event( ctx.votor, &event, 0L );
      while( ag_votor_poll_vote( ctx.votor, &vote, &reason ) );
    }
  }
  for( ulong i=0UL; i<2UL; i++ ) {
    ctx.vote_history_pending = 2UL;
    vote_history_write( &ctx );
    FD_TEST( file_is( dir_fd, name[ 1 ][ 1 ], "", NULL ) );
    FD_TEST( ctx.vote_history_empty && ctx.metrics.vote_history_too_large==i+1UL && ctx.metrics.vote_history_write==2UL );
    FD_TEST( ctx.metrics.vote_history_slot==ULONG_MAX && !ctx.metrics.vote_history_sz );
  }

  /* and written again once the history fits.  After skips through slot
     3, a late fallback for slot 2 leaves the gauge at slot 3. */

  ctx.votor = ag_votor_join( ag_votor_new( votor_scratch, 64UL, 42UL ) );
  ag_votor_init( ctx.votor, &(ag_block_id_t){ .slot = 0UL }, 0L, 400000000L, (ushort)1, capture_sign_bls, NULL );
  ag_votor_advance_epoch( ctx.votor, 400000000L, 0UL, 0UL, bls_key[0] );
  ag_votor_handle_skip_timeout( ctx.votor, 3UL );
  ag_pool_event_t late = { .kind = AG_POOL_EVENT_SAFE_TO_NOTAR, .safe_to_notar = { .slot = 2UL } };
  ag_votor_handle_pool_event( ctx.votor, &late, 0L );
  ctx.vote_history_pending = 2UL;
  vote_history_write( &ctx );
  FD_TEST( file_is( dir_fd, name[ 1 ][ 1 ], NULL, &id[ 1 ] ) );
  FD_TEST( !ctx.vote_history_empty && ctx.metrics.vote_history_write==3UL && ctx.metrics.vote_history_slot==3UL );

  char const * files[] = { name[ 1 ][ 0 ], name[ 1 ][ 1 ], old };
  for( ulong i=0UL; i<3UL; i++ ) FD_TEST( !unlinkat( dir_fd, files[ i ], 0 ) );
  for( ulong i=0UL; i<2UL; i++ ) FD_TEST( !close( ctx.vote_history_fd[ i ] ) );
  FD_TEST( !close( dir_fd ) );
  FD_TEST( !rmdir( dir ) );
  ag_votor_delete( ag_votor_leave( ctx.votor ) );

  FD_LOG_NOTICE(( "pass: test_vote_history_write" ));
}

/* An adopted history fences the window of the last LEADER it reports
   and the window of its vote bound, and a lower bound or leader slot
   never lowers the fence. */

static void
test_history_raises_the_leader_floor( void ) {
  static fd_votor_tile_t ctx;
  hist_setup( &ctx );

  ag_hist_t hist = { .anchor = 0UL, .last_leader_slot = 12UL, .vote_bound = 17UL, .rec_cnt = 1UL };
  hist.rec[ 0 ].slot  = 1UL;
  hist.rec[ 0 ].flags = AG_HIST_FLAG_VOTED;
  uchar req[ AG_HIST_SER_MAX ];
  ulong req_sz;
  FD_TEST( !ag_hist_ser( &hist, req, sizeof(req), &req_sz ) );
  fd_votor_adopt_result_t result = failover_adopt_hist( &ctx, req, req_sz );
  FD_TEST( result.result==FD_VOTOR_ADOPT_SUCCESS && result.vote_slot==1UL && result.vote_bound==17UL );
  FD_TEST( ag_votor_vote_bound( ctx.votor )==17UL );
  FD_TEST( ctx.adopted_last_leader_slot==ag_first_slot_in_window( 17UL ) );
  FD_TEST( leader_floor( &ctx )==ag_first_slot_in_window( 17UL ) );

  hist.last_leader_slot = 4UL;
  hist.vote_bound       = 6UL;
  FD_TEST( !ag_hist_ser( &hist, req, sizeof(req), &req_sz ) );
  result = failover_adopt_hist( &ctx, req, req_sz );
  FD_TEST( result.result==FD_VOTOR_ADOPT_SUCCESS && result.vote_bound==17UL );
  FD_TEST( ctx.adopted_last_leader_slot==ag_first_slot_in_window( 17UL ) );

  uchar empty[ FD_VOTOR_ADOPT_EMPTY_SZ ];
  FD_STORE( ulong, empty, 2UL );
  result = failover_adopt_hist( &ctx, empty, sizeof(empty) );
  FD_TEST( result.result==FD_VOTOR_ADOPT_SUCCESS && result.vote_bound==17UL );
  FD_TEST( ctx.adopted_last_leader_slot==ag_first_slot_in_window( 17UL ) );

  /* A history older than the votes this machine sent is refused. */
  ctx.last_vote_slot = 3UL;
  result = failover_adopt_hist( &ctx, req, req_sz );
  FD_TEST( result.result==FD_VOTOR_ADOPT_ERR_STALE );

  hist_teardown( &ctx );
}

/* Without the failover links failover_init leaves failover off.  The
   identity votes as soon as it is ranked, replay completions and votes
   leave the failover state alone, a vote that never left the machine
   keeps its notar mark as upstream does, and an identity switch leads
   from upstream's next window with no leader floor and no vote
   authority change. */

static void
test_failover_off( void ) {
  static fd_votor_tile_t ctx;
  static fd_topo_t       topo[1];
  static fd_topo_tile_t  tile[1];
  static auth_vtr_t      auth_vtr_mem[ 1UL<<AUTH_VTR_LG_SLOT_CNT ];
  static peer_t          peers_mem[ 1UL<<PEERS_LG_SLOT_CNT ];
  static uchar           mleaders_mem[ FD_MULTI_EPOCH_LEADERS_FOOTPRINT ] __attribute__((aligned(FD_MULTI_EPOCH_LEADERS_ALIGN)));
  static fd_keyswitch_t  av_keyswitch_mem[1];
  static fd_aio_t        aio_mem[1];
  memset( &ctx, 0, sizeof(fd_votor_tile_t) );
  memset( topo, 0, sizeof(fd_topo_t)       );
  memset( tile, 0, sizeof(fd_topo_tile_t)  );

  fd_vote_stake_weight_t stakes[ TEST_VOTER_MAX ];
  build_stakes( stakes, 3UL, 10UL );
  ag_epoch_info_t * epoch_info = rank_voters( &epoch_info_mem, stakes, 3UL );
  memcpy( ctx.id_key.uc, epoch_info->validators[0].id_key, sizeof(fd_pubkey_t) );
  failover_init( &ctx, topo, tile );
  FD_TEST( !ctx.failover_enabled && ctx.vote_authority );
  FD_TEST( ctx.hist_out_idx==ULONG_MAX && ctx.failov_out_idx==ULONG_MAX );

  ag_bls_key_t bls_key; memcpy( bls_key, epoch_info->validators[0].bls_key, sizeof(ag_bls_key_t) );
  init_keys( &ctx, auth_vtr_mem, &bls_key, 1UL );
  ctx.curr_epoch_info  = epoch_info;
  ctx.next_epoch_slot  = ULONG_MAX;
  ctx.next_leader_slot = ULONG_MAX;
  ctx.pool  = test_pool( epoch_info, 0UL );
  ctx.votor = ag_votor_join( ag_votor_new( votor_scratch, 64UL, 42UL ) );
  FD_TEST( ctx.votor );
  ag_votor_init         ( ctx.votor, &(ag_block_id_t){ .slot = 0UL }, 0L, 400000000L, (ushort)1, capture_sign_bls, NULL );
  ag_votor_advance_epoch( ctx.votor, 400000000L, 0UL, 0UL, NULL ); /* no key until set_rank_and_bls_key picks ours */
  set_rank_and_bls_key( &ctx );
  ctx.init = 1;

  /* We lead every slot of epoch 0. */

  ctx.mleaders   = fd_multi_epoch_leaders_join( fd_multi_epoch_leaders_new( mleaders_mem ) );
  ctx.peers      = peers_join( peers_new( peers_mem ) );
  ctx.reconn_prq = reconn_prq_join( reconn_prq_new( reconn_prq_mem, RECONN_MAX ) );
  FD_TEST( ctx.mleaders && ctx.peers && ctx.reconn_prq );
  static uchar stake_msg_mem[ FD_STAKE_CI_STAKE_MSG_HEADER_SZ+FD_STAKE_CI_STAKE_MSG_RECORD_SZ ] __attribute__((aligned(8)));
  fd_stake_weight_msg_t * stake_msg = fd_type_pun( stake_msg_mem );
  *stake_msg = (fd_stake_weight_msg_t){ .epoch = 0UL, .staked_vote_cnt = 1UL, .start_slot = 0UL, .slot_cnt = 64UL };
  *(fd_vote_stake_weight_t *)fd_type_pun( stake_msg+1 ) = (fd_vote_stake_weight_t){ .vote_key = ctx.id_key, .id_key = ctx.id_key, .stake = 10UL };
  fd_multi_epoch_leaders_stake_msg_init( ctx.mleaders, stake_msg );
  fd_multi_epoch_leaders_stake_msg_fini( ctx.mleaders );
  fd_aio_t * aio = fd_aio_join( fd_aio_new( aio_mem, NULL, drop_aio_send ) );
  ctx.quic_client = test_quic( quic_client_scratch, sizeof(quic_client_scratch), FD_QUIC_ROLE_CLIENT, &ctx, aio );
  ctx.quic_server = test_quic( quic_server_scratch, sizeof(quic_server_scratch), FD_QUIC_ROLE_SERVER, &ctx, aio );
  ctx.auth_vtr_keyswitch = fd_keyswitch_join( fd_keyswitch_new( av_keyswitch_mem, FD_KEYSWITCH_STATE_UNLOCKED ) );
  ctx.id_keyswitch       = fd_keyswitch_join( fd_keyswitch_new( id_keyswitch_mem, FD_KEYSWITCH_STATE_UNLOCKED ) );
  FD_TEST( ctx.auth_vtr_keyswitch && ctx.id_keyswitch );
  fd_clock_tile_init( ctx.clock );
  ctx.vote_history_dir_fd = -1;
  for( ulong i=0UL; i<REWARD_VOTE_MAX; i++ ) ctx.reward_votes[ i ].slot = ULONG_MAX;

  /* A completed slot gets our notar, and the failover state stays where
     failover_init put it. */

  static fd_replay_message_t replay;
  memset( &replay, 0, sizeof(replay) );
  replay.slot_completed.slot        = 1UL;
  replay.slot_completed.root_slot   = 0UL;
  replay.slot_completed.parent_slot = 0UL;
  memset( replay.slot_completed.block_id.uc, 1, sizeof(fd_hash_t) );
  handle_replay( &ctx, REPLAY_SIG_SLOT_COMPLETED, &replay );
  FD_TEST( !ctx.highest_completed_slot && ctx.root_slot==ULONG_MAX );
  FD_TEST( ag_votor_metrics( ctx.votor ).vote_events_cnt==1UL );

  /* The notar goes out against an epoch we do not know, so it never
     leaves the machine.  Upstream drops it and the slot keeps its notar
     mark. */

  ctx.curr_epoch_info = NULL;
  int charge_busy = 0;
  after_credit( &ctx, NULL, NULL, &charge_busy );
  ctx.curr_epoch_info = epoch_info;
  FD_TEST( !ag_votor_metrics( ctx.votor ).vote_events_cnt );
  static ag_hist_t hist;
  ag_votor_hist_export( ctx.votor, ULONG_MAX, &hist );
  ulong rec_idx = ULONG_MAX;
  for( ulong i=0UL; i<hist.rec_cnt; i++ ) if( hist.rec[ i ].slot==1UL ) rec_idx = i;
  FD_TEST( rec_idx!=ULONG_MAX );
  FD_TEST( ( hist.rec[ rec_idx ].flags & AG_HIST_FLAG_VOTED_NOTAR ) && !( hist.rec[ rec_idx ].flags & AG_HIST_FLAG_BAD_WINDOW ) );
  FD_TEST( ag_votor_vote_bound( ctx.votor )==ULONG_MAX );

  /* A switch leads from the next window, the leader floor is not
     consulted and the vote authority stays. */

  ctx.last_leader_slot          = 40UL; /* a floor would move the leader slot past 40 */
  ctx.highest_parent_ready_slot = 4UL;
  memcpy( ctx.id_keyswitch->bytes, ctx.id_key.uc, sizeof(fd_pubkey_t) );
  ctx.id_keyswitch->result = 77UL;
  fd_keyswitch_state( ctx.id_keyswitch, FD_KEYSWITCH_STATE_SWITCH_PENDING );
  during_housekeeping( &ctx );
  FD_TEST( ctx.id_keyswitch->state==FD_KEYSWITCH_STATE_COMPLETED );
  FD_TEST( ctx.next_leader_slot==8UL && ctx.vote_authority );
  FD_TEST( ctx.id_keyswitch->result==77UL );

  fd_quic_delete( fd_quic_leave( fd_quic_fini( ctx.quic_client ) ) );
  fd_quic_delete( fd_quic_leave( fd_quic_fini( ctx.quic_server ) ) );
  reconn_prq_delete( reconn_prq_leave( ctx.reconn_prq ) );
  hist_teardown( &ctx );
}

/* Under failover, booted under the junk key (rank 0), the staked key
   (rank 1) votes only after an adoption unless set-identity installed
   it, and the junk key never votes, also when set-identity installs it.
   The switch itself is upstream's, this checks the failover rule at its
   end and the rank it leaves for the resume. */

static void
operator_switch( int    operator,
                 ulong  new_rank,
                 int    expect_votes ) {
  static fd_votor_tile_t ctx;
  static auth_vtr_t      auth_vtr_mem[ 1UL<<AUTH_VTR_LG_SLOT_CNT ];
  ag_epoch_info_t * epoch_info = hist_setup( &ctx );
  ag_bls_key_t bls_key; memcpy( bls_key, epoch_info->validators[ new_rank ].bls_key, sizeof(ag_bls_key_t) );
  init_keys( &ctx, auth_vtr_mem, &bls_key, 1UL ); /* the new identity's key, as the resume loads it */
  ctx.id_keyswitch = fd_keyswitch_join( fd_keyswitch_new( id_keyswitch_mem, FD_KEYSWITCH_STATE_SWITCH_PENDING ) );
  FD_TEST( ctx.id_keyswitch );
  ctx.id_keyswitch->operator = (ulong)operator;
  ctx.hist_seq               = 77UL;

  memcpy( ctx.id_key.uc, epoch_info->validators[ new_rank ].id_key, sizeof(fd_pubkey_t) );
  failover_switched( &ctx );
  FD_TEST( ctx.vote_authority==expect_votes && !ctx.failover_hist_adopted );
  FD_TEST( ctx.id_keyswitch->result==77UL );
  set_rank_and_bls_key( &ctx );

  ag_block_info_t block = {0};
  memset( block.hash, 1, sizeof(ag_block_hash_t) );
  ag_votor_process_replay( ctx.votor, 1UL, &block );
  ag_vote_t vote;
  uchar     reason;
  FD_TEST( ag_votor_poll_vote( ctx.votor, &vote, &reason )==expect_votes );
  if( expect_votes ) FD_TEST( ag_vote_rank( &vote )==new_rank );

  hist_teardown( &ctx );
}

/* With failover on, the end of upstream's switch applies the failover
   rule and leaves the history watermark for the admin tile. */

static void
test_switch_runs_the_failover_rule( void ) {
  static fd_votor_tile_t ctx;
  static auth_vtr_t      auth_vtr_mem[ 1UL<<AUTH_VTR_LG_SLOT_CNT ];
  static peer_t          peers_mem[ 1UL<<PEERS_LG_SLOT_CNT ];
  static uchar           mleaders_mem[ FD_MULTI_EPOCH_LEADERS_FOOTPRINT ] __attribute__((aligned(FD_MULTI_EPOCH_LEADERS_ALIGN)));
  static fd_keyswitch_t  av_keyswitch_mem[1];
  static fd_aio_t        aio_mem[1];
  ag_epoch_info_t * epoch_info = hist_setup( &ctx );
  ag_bls_key_t bls_key; memcpy( bls_key, epoch_info->validators[0].bls_key, sizeof(ag_bls_key_t) );
  init_keys( &ctx, auth_vtr_mem, &bls_key, 1UL );
  ctx.vote_authority = 1;
  ctx.hist_seq       = 77UL;
  ctx.mleaders = fd_multi_epoch_leaders_join( fd_multi_epoch_leaders_new( mleaders_mem ) );
  ctx.peers    = peers_join( peers_new( peers_mem ) );
  FD_TEST( ctx.mleaders && ctx.peers );
  fd_aio_t * aio = fd_aio_join( fd_aio_new( aio_mem, NULL, drop_aio_send ) );
  ctx.quic_client = test_quic( quic_client_scratch, sizeof(quic_client_scratch), FD_QUIC_ROLE_CLIENT, &ctx, aio );
  ctx.quic_server = test_quic( quic_server_scratch, sizeof(quic_server_scratch), FD_QUIC_ROLE_SERVER, &ctx, aio );
  ctx.auth_vtr_keyswitch = fd_keyswitch_join( fd_keyswitch_new( av_keyswitch_mem, FD_KEYSWITCH_STATE_UNLOCKED ) );
  ctx.id_keyswitch       = fd_keyswitch_join( fd_keyswitch_new( id_keyswitch_mem, FD_KEYSWITCH_STATE_UNLOCKED ) );
  FD_TEST( ctx.auth_vtr_keyswitch && ctx.id_keyswitch );
  fd_clock_tile_init( ctx.clock );

  /* A failover switch to the junk key we booted under, no adoption. */
  memcpy( ctx.id_keyswitch->bytes, ctx.boot_id_key.uc, sizeof(fd_pubkey_t) );
  fd_keyswitch_state( ctx.id_keyswitch, FD_KEYSWITCH_STATE_SWITCH_PENDING );
  during_housekeeping( &ctx );
  FD_TEST( ctx.id_keyswitch->state==FD_KEYSWITCH_STATE_COMPLETED );
  FD_TEST( !ctx.vote_authority && ctx.id_keyswitch->result==77UL );

  hist_teardown( &ctx );
}

static void
test_operator_switch_votes( void ) {
  operator_switch( 0, 1UL, 0 ); /* staked, no adoption */
  operator_switch( 1, 1UL, 1 ); /* staked, by set-identity */
  operator_switch( 1, 0UL, 0 ); /* back to the junk key, by set-identity */
}

/* While this machine votes, an adoption, which can only be one that
   crossed set-identity, is refused and moves nothing.  Once it stands
   by again the same request is taken. */

static void
test_adopt_refused_while_voting( void ) {
  static fd_votor_tile_t ctx;
  hist_setup( &ctx );
  ctx.vote_authority = 1;

  static uchar          reply_mem[ 512 ] __attribute__((aligned(FD_CHUNK_SZ)));
  static fd_frag_meta_t mcache[ 8 ];
  fd_frag_meta_t * mcaches[] = { mcache };
  ulong seqs[] = { 0UL }, depths[] = { 8UL };
  ulong cr_avail = 64UL, min_cr_avail = 64UL;
  int   reliable = 0;
  fd_stem_context_t stem[ 1 ] = {{
    .mcaches=mcaches, .seqs=seqs, .depths=depths,
    .cr_avail=&cr_avail, .min_cr_avail=&min_cr_avail,
    .cr_decrement_amount=1UL, .out_reliable=&reliable
  }};
  ctx.failov_out_idx    = 0UL;
  ctx.failov_out_mem    = reply_mem;
  ctx.failov_out_chunk0 = 0UL;
  ctx.failov_out_wmark  = 4UL;
  ctx.failov_out_chunk  = 0UL;
  ctx.in_kind[ 0 ]      = IN_KIND_FAILOV;
  FD_STORE( ulong, ctx.adopt_req, 9UL ); /* empty history, no vote at or below slot 9 */
  ctx.adopt_req_sz = FD_VOTOR_ADOPT_EMPTY_SZ;

  after_frag( &ctx, 0UL, 0UL, 901UL, FD_VOTOR_ADOPT_EMPTY_SZ, 0UL, 0UL, stem );
  fd_votor_adopt_result_t const * reply = fd_chunk_to_laddr_const( reply_mem, mcache[0].chunk );
  FD_TEST( seqs[0]==1UL && mcache[0].sig==901UL );
  FD_TEST( reply->result==FD_VOTOR_ADOPT_ERR_INVALID && !ctx.failover_hist_adopted );
  FD_TEST( ag_votor_vote_bound( ctx.votor )==ULONG_MAX );

  ctx.vote_authority = 0;
  after_frag( &ctx, 0UL, 1UL, 902UL, FD_VOTOR_ADOPT_EMPTY_SZ, 0UL, 0UL, stem );
  reply = fd_chunk_to_laddr_const( reply_mem, mcache[1].chunk );
  FD_TEST( seqs[0]==2UL && mcache[1].sig==902UL );
  FD_TEST( reply->result==FD_VOTOR_ADOPT_SUCCESS && ctx.failover_hist_adopted );
  FD_TEST( ag_votor_vote_bound( ctx.votor )==9UL );

  hist_teardown( &ctx );
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
  test_id_keyswitch();
  test_replay_before_epoch();
  test_sign_bls_request();
  test_connect_peer();
  test_conn_final_backoff();
  test_connect_fail_keeps_backoff();
  test_gossip_connects_new_address();
  test_gossip_before_stake();
  test_reconnect();
  test_conn_ahead();
  test_park();
  test_vote_history_write();
  test_history_raises_the_leader_floor();
  test_failover_off();
  test_switch_runs_the_failover_rule();
  test_operator_switch_votes();
  test_adopt_refused_while_voting();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
