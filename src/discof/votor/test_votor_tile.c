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
  load_keys( &ctx, &tile );
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

static void
test_dial_backoff_next( void ) {
  long b = 0L;
  b = dial_backoff_next( b, 30000000L );             FD_TEST( b==QUIC_DIAL_BACKOFF_MIN_NS    ); /* refused 30ms after dial */
  b = dial_backoff_next( b, 30000000L );             FD_TEST( b==2L*QUIC_DIAL_BACKOFF_MIN_NS );
  for( ulong i=0UL; i<16UL; i++ ) b = dial_backoff_next( b, 0L );
  FD_TEST( b==QUIC_DIAL_BACKOFF_MAX_NS );
  b = dial_backoff_next( b, QUIC_DIAL_STABLE_NS-1L ); FD_TEST( b==QUIC_DIAL_BACKOFF_MAX_NS    );
  b = dial_backoff_next( b, QUIC_DIAL_STABLE_NS    ); FD_TEST( b==0L                          ); /* a conn that lived resets */
}

static peer_t peers_mem[ 1UL<<PEERS_LG_SLOT_CNT ];

static peer_t *
test_peer( fd_votor_tile_t * ctx,
           uchar             id,
           ushort            curr_rank ) {
  fd_pubkey_t id_key = {0}; id_key.uc[ 0 ] = id;
  peer_t * peer = peers_insert( ctx->peers, id_key );
  peer->prev_rank    = USHORT_MAX;
  peer->curr_rank    = curr_rank;
  peer->next_rank    = USHORT_MAX;
  peer->tx_conn      = NULL;
  peer->rx_conn      = NULL;
  peer->ban_ts       = 0L;
  peer->dial_ts      = 0L;
  peer->dial_backoff = 0L;
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

  /* Ranked only in the next or the previous epoch: no. */
  peer_t * self = test_peer( &ctx, 1, USHORT_MAX );
  self->next_rank = 0;
  FD_TEST( !can_dial( &ctx, other, now ) );
  self->next_rank = USHORT_MAX; self->prev_rank = 0;
  FD_TEST( !can_dial( &ctx, other, now ) );

  /* Ranked in the current epoch: dial everyone but ourselves. */
  self->curr_rank = 1;
  FD_TEST(  can_dial( &ctx, other, now ) );
  FD_TEST( !can_dial( &ctx, self,  now ) );

  /* A peer marked for eviction is not dialed. */
  other->curr_rank = USHORT_MAX;
  FD_TEST( !can_dial( &ctx, other, now ) );
  other->curr_rank = 0;

  /* Existing conn, ban and backoff all hold off the dial. */
  fd_quic_conn_t conn[1];
  other->tx_conn = conn;                                FD_TEST( !can_dial( &ctx, other, now ) );
  other->tx_conn = NULL;
  other->ban_ts  = now-QUIC_BAN_TIMEOUT_NS+1L;          FD_TEST( !can_dial( &ctx, other, now ) );
  other->ban_ts  = now-QUIC_BAN_TIMEOUT_NS;             FD_TEST(  can_dial( &ctx, other, now ) );
  other->dial_ts = now-1L; other->dial_backoff = 2L;    FD_TEST( !can_dial( &ctx, other, now ) );
  other->dial_backoff = 1L;                             FD_TEST(  can_dial( &ctx, other, now ) );

  /* A conn that closes right after the dial backs off the next one; a
     conn that lived resets it. */
  fd_clock_tile_init( ctx.clock );
  long t = fd_clock_tile_now( ctx.clock );
  memset( conn, 0, sizeof(conn) );
  fd_quic_conn_set_context( conn, &other->id_key );
  other->tx_conn = conn; other->dial_ts = t; other->dial_backoff = 0L;
  quic_client_conn_final( conn, &ctx );
  FD_TEST( !other->tx_conn && other->dial_backoff==QUIC_DIAL_BACKOFF_MIN_NS );
  FD_TEST( !can_dial( &ctx, other, t+1L ) );
  other->tx_conn = conn; other->dial_ts = t-QUIC_DIAL_STABLE_NS;
  quic_client_conn_final( conn, &ctx );
  FD_TEST( !other->tx_conn && other->dial_backoff==0L );

  /* A conn that closes short of stable (after ~9 s) backs off from the
     close, not from the dial. */
  other->tx_conn = conn; other->dial_ts = t-QUIC_DIAL_STABLE_NS+QUIC_DIAL_BACKOFF_MIN_NS;
  quic_client_conn_final( conn, &ctx );
  FD_TEST( other->dial_backoff==QUIC_DIAL_BACKOFF_MIN_NS );
  long closed = other->dial_ts;
  FD_TEST( closed>=t );
  FD_TEST( !can_dial( &ctx, other, closed+QUIC_DIAL_BACKOFF_MIN_NS-1L ) );
  FD_TEST(  can_dial( &ctx, other, closed+QUIC_DIAL_BACKOFF_MIN_NS    ) );

  peers_delete( peers_leave( ctx.peers ) );
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

static uchar quic_mem[ 1UL<<24 ] __attribute__((aligned(FD_QUIC_ALIGN)));

/* A connect that fails for lack of conns is not a dial, so it must not
   restart the peer's backoff. */

static void
test_connect_fail_keeps_backoff( void ) {
  static fd_votor_tile_t ctx;
  static fd_aio_t        aio;
  ctx.peers = peers_join( peers_new( peers_mem ) );
  FD_TEST( ctx.peers );
  memset( &ctx.id_key, 0, sizeof(fd_pubkey_t) ); ctx.id_key.uc[ 0 ] = 1;
  test_peer( &ctx, 1, 0 );

  fd_quic_limits_t limits = { .conn_cnt=1UL, .handshake_cnt=1UL, .conn_id_cnt=FD_QUIC_MIN_CONN_ID_CNT, .inflight_frame_cnt=16UL, .min_inflight_frame_cnt_conn=8UL };
  FD_TEST( fd_quic_footprint( &limits )<=sizeof(quic_mem) );
  ctx.quic_client = fd_quic_join( fd_quic_new( quic_mem, &limits ) );
  FD_TEST( ctx.quic_client );
  ctx.quic_client->config.role         = FD_QUIC_ROLE_CLIENT;
  ctx.quic_client->config.idle_timeout = 5L*1000L*1000L*1000L;
  ctx.quic_client->config.ack_delay    = 2L*1000L*1000L;
  memcpy( ctx.quic_client->config.identity_public_key, ctx.id_key.uc, 32UL );
  fd_quic_set_aio_net_tx( ctx.quic_client, fd_aio_join( fd_aio_new( &aio, NULL, test_aio_drop ) ) );
  FD_TEST( fd_quic_init( ctx.quic_client ) );

  contact_info_t ci = { .ip4=FD_IP4_ADDR( 10, 0, 0, 1 ), .port=8000 };
  long     now = 100L*1000L*1000L*1000L;
  peer_t * a   = test_peer( &ctx, 2, 0 );
  peer_t * b   = test_peer( &ctx, 3, 0 );

  peer_connect( &ctx, a, &ci, now ); /* takes the only conn */
  FD_TEST( a->tx_conn && a->dial_ts==now );

  b->dial_ts = now-QUIC_DIAL_BACKOFF_MAX_NS; b->dial_backoff = QUIC_DIAL_BACKOFF_MAX_NS;
  peer_connect( &ctx, b, &ci, now );
  FD_TEST( !b->tx_conn && b->dial_ts==now-QUIC_DIAL_BACKOFF_MAX_NS );
  FD_TEST( can_dial( &ctx, b, now+1L ) );

  fd_quic_delete( fd_quic_leave( fd_quic_fini( ctx.quic_client ) ) );
  peers_delete( peers_leave( ctx.peers ) );
}

static contact_info_t contact_infos_mem[ 1UL<<CONTACT_INFOS_LG_SLOT_CNT ];

static void
test_gossip_address_resets_backoff( void ) {
  static fd_votor_tile_t            ctx;
  static fd_gossip_update_message_t msg;
  ctx.peers         = peers_join( peers_new( peers_mem ) );
  ctx.contact_infos = contact_infos_join( contact_infos_new( contact_infos_mem ) );
  FD_TEST( ctx.peers && ctx.contact_infos );
  fd_clock_tile_init( ctx.clock );
  memset( &ctx.id_key, 0, sizeof(fd_pubkey_t) ); ctx.id_key.uc[ 0 ] = 1; /* unranked, so nothing is dialed */

  peer_t * other = test_peer( &ctx, 2, 0 );
  memcpy( msg.origin, other->id_key.uc, sizeof(fd_pubkey_t) );
  fd_gossip_socket_t * sock = &msg.contact_info->value->sockets[ FD_GOSSIP_CONTACT_INFO_SOCKET_ALPENGLOW ];
  sock->ip4  = FD_IP4_ADDR( 10, 0, 0, 1 );
  sock->port = fd_ushort_bswap( 8000 );
  handle_gossip( &ctx, FD_GOSSIP_UPDATE_TAG_CONTACT_INFO, &msg );
  FD_TEST( contact_infos_query( ctx.contact_infos, other->id_key, NULL ) );

  /* A refresh of the same address keeps the backoff. */
  other->dial_backoff = QUIC_DIAL_BACKOFF_MAX_NS;
  handle_gossip( &ctx, FD_GOSSIP_UPDATE_TAG_CONTACT_INFO, &msg );
  FD_TEST( other->dial_backoff==QUIC_DIAL_BACKOFF_MAX_NS );

  /* A changed address, in place or after a removal, resets it. */
  sock->port = fd_ushort_bswap( 8001 );
  handle_gossip( &ctx, FD_GOSSIP_UPDATE_TAG_CONTACT_INFO, &msg );
  FD_TEST( other->dial_backoff==0L );

  other->dial_backoff = QUIC_DIAL_BACKOFF_MAX_NS;
  handle_gossip( &ctx, FD_GOSSIP_UPDATE_TAG_CONTACT_INFO_REMOVE, &msg );
  FD_TEST( !contact_infos_query( ctx.contact_infos, other->id_key, NULL ) );
  sock->ip4 = FD_IP4_ADDR( 10, 0, 0, 2 );
  handle_gossip( &ctx, FD_GOSSIP_UPDATE_TAG_CONTACT_INFO, &msg );
  FD_TEST( other->dial_backoff==0L );

  contact_infos_delete( contact_infos_leave( ctx.contact_infos ) );
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
  test_own_bls_key();
  test_sign_bls_request();
  test_dial_backoff_next();
  test_can_dial();
  test_gossip_address_resets_backoff();
  test_connect_fail_keeps_backoff();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
