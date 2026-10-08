#include "fd_admin_tile.c"
#include "../../disco/topo/fd_topob.h"

#define TEST_SIGN_CNT (2UL)

static fd_admin_tile_ctx_t ctx;
static fd_keyswitch_t      voter [1];
static fd_keyswitch_t      txsend[1];
static fd_keyswitch_t      sign  [ TEST_SIGN_CNT ];

static void
setup( int alpenglow ) {
  memset( &ctx, 0, sizeof(ctx) );
  ctx.alpenglow           = alpenglow;
  ctx.voter_name          = alpenglow ? "votor" : "tower";
  ctx.voter_av_keyswitch  = fd_keyswitch_join( fd_keyswitch_new( voter,  FD_KEYSWITCH_STATE_UNLOCKED ) );
  ctx.txsend_av_keyswitch = fd_keyswitch_join( fd_keyswitch_new( txsend, FD_KEYSWITCH_STATE_UNLOCKED ) );
  FD_TEST( ctx.voter_av_keyswitch && ctx.txsend_av_keyswitch );
  for( ulong i=0UL; i<TEST_SIGN_CNT; i++ ) {
    ctx.sign_av_keyswitch[ i ] = fd_keyswitch_join( fd_keyswitch_new( &sign[ i ], FD_KEYSWITCH_STATE_UNLOCKED ) );
    FD_TEST( ctx.sign_av_keyswitch[ i ] );
  }
  ctx.sign_av_keyswitch_cnt = TEST_SIGN_CNT;
}

static void
sign_expect( ulong state,
             ulong param ) {
  for( ulong i=0UL; i<TEST_SIGN_CNT; i++ ) {
    FD_TEST( sign[ i ].state==state );
    if( state==FD_KEYSWITCH_STATE_SWITCH_PENDING ) FD_TEST( sign[ i ].param==param );
  }
}

static void
sign_complete( void ) {
  for( ulong i=0UL; i<TEST_SIGN_CNT; i++ ) fd_keyswitch_state( &sign[ i ], FD_KEYSWITCH_STATE_COMPLETED );
}

/* The sign tiles learn a new authorized voter before the vote producing
   tile (tower, or votor under Alpenglow) does. */

static void
test_add_authorized_voter( int alpenglow ) {
  setup( alpenglow );
  uchar keypair[ 64 ]; memset( keypair, 0x33, sizeof(keypair) );
  ulong result = 0UL;
  ulong state  = FD_ADD_AUTH_VOTER_STATE_UNLOCKED;

  poll_add_authorized_voter( &ctx, &state, keypair, &result );
  FD_TEST( state==FD_ADD_AUTH_VOTER_STATE_LOCKED && voter->state==FD_KEYSWITCH_STATE_LOCKED );

  poll_add_authorized_voter( &ctx, &state, keypair, &result );
  FD_TEST( state==FD_ADD_AUTH_VOTER_STATE_SIGN_TILE_REQUESTED );
  sign_expect( FD_KEYSWITCH_STATE_SWITCH_PENDING, FD_KEYSWITCH_PARAM_AV_ADD );
  FD_TEST( voter->state==FD_KEYSWITCH_STATE_LOCKED );

  poll_add_authorized_voter( &ctx, &state, keypair, &result );
  FD_TEST( state==FD_ADD_AUTH_VOTER_STATE_SIGN_TILE_REQUESTED );
  sign_complete();
  poll_add_authorized_voter( &ctx, &state, keypair, &result );
  FD_TEST( state==FD_ADD_AUTH_VOTER_STATE_SIGN_TILE_UPDATED );

  poll_add_authorized_voter( &ctx, &state, keypair, &result );
  FD_TEST( state==FD_ADD_AUTH_VOTER_STATE_VOTER_TILE_REQUESTED );
  FD_TEST( voter->state==FD_KEYSWITCH_STATE_SWITCH_PENDING && voter->param==FD_KEYSWITCH_PARAM_AV_ADD );
  fd_keyswitch_state( voter, FD_KEYSWITCH_STATE_COMPLETED );
  poll_add_authorized_voter( &ctx, &state, keypair, &result );
  FD_TEST( state==FD_ADD_AUTH_VOTER_STATE_VOTER_TILE_UPDATED );

  poll_add_authorized_voter( &ctx, &state, keypair, &result );
  FD_TEST( state==FD_ADD_AUTH_VOTER_STATE_UNLOCK_REQUESTED && voter->state==FD_KEYSWITCH_STATE_UNHALT_PENDING );
  fd_keyswitch_state( voter, FD_KEYSWITCH_STATE_UNLOCKED );
  poll_add_authorized_voter( &ctx, &state, keypair, &result );
  FD_TEST( state==FD_ADD_AUTH_VOTER_STATE_UNLOCKED && !result );
  FD_TEST( txsend->state==FD_KEYSWITCH_STATE_UNLOCKED );
}

/* The vote producing tile drops its authorized voters before the sign
   tiles do.  Only the tower's votes pass through TxSend, so only the
   tower path drains it. */

static void
test_remove_all_authorized_voters( int alpenglow ) {
  setup( alpenglow );
  ulong state = FD_REMOVE_ALL_AUTH_VOTERS_STATE_UNLOCKED;

  poll_remove_all_authorized_voters( &ctx, &state );
  FD_TEST( state==FD_REMOVE_ALL_AUTH_VOTERS_STATE_LOCKED && voter->state==FD_KEYSWITCH_STATE_LOCKED );

  poll_remove_all_authorized_voters( &ctx, &state );
  FD_TEST( state==FD_REMOVE_ALL_AUTH_VOTERS_STATE_VOTER_TILE_REQUESTED );
  FD_TEST( voter->state==FD_KEYSWITCH_STATE_SWITCH_PENDING && voter->param==FD_KEYSWITCH_PARAM_AV_CLEAR );
  sign_expect( FD_KEYSWITCH_STATE_UNLOCKED, 0UL );

  voter->result = 42UL;
  fd_keyswitch_state( voter, FD_KEYSWITCH_STATE_COMPLETED );
  poll_remove_all_authorized_voters( &ctx, &state );
  FD_TEST( state==FD_REMOVE_ALL_AUTH_VOTERS_STATE_VOTER_TILE_CLEARED );

  poll_remove_all_authorized_voters( &ctx, &state );
  if( alpenglow ) {
    FD_TEST( state==FD_REMOVE_ALL_AUTH_VOTERS_STATE_TXSEND_FLUSHED );
    FD_TEST( txsend->state==FD_KEYSWITCH_STATE_UNLOCKED );
  } else {
    FD_TEST( state==FD_REMOVE_ALL_AUTH_VOTERS_STATE_TXSEND_FLUSH_REQUESTED );
    FD_TEST( txsend->state==FD_KEYSWITCH_STATE_SWITCH_PENDING && txsend->param==42UL );
    fd_keyswitch_state( txsend, FD_KEYSWITCH_STATE_COMPLETED );
    poll_remove_all_authorized_voters( &ctx, &state );
    FD_TEST( state==FD_REMOVE_ALL_AUTH_VOTERS_STATE_TXSEND_FLUSHED );
  }
  sign_expect( FD_KEYSWITCH_STATE_UNLOCKED, 0UL );

  poll_remove_all_authorized_voters( &ctx, &state );
  FD_TEST( state==FD_REMOVE_ALL_AUTH_VOTERS_STATE_SIGN_TILE_REQUESTED );
  sign_expect( FD_KEYSWITCH_STATE_SWITCH_PENDING, FD_KEYSWITCH_PARAM_AV_CLEAR );
  sign_complete();
  poll_remove_all_authorized_voters( &ctx, &state );
  FD_TEST( state==FD_REMOVE_ALL_AUTH_VOTERS_STATE_SIGN_TILE_CLEARED );

  poll_remove_all_authorized_voters( &ctx, &state );
  FD_TEST( state==FD_REMOVE_ALL_AUTH_VOTERS_STATE_UNLOCK_REQUESTED && voter->state==FD_KEYSWITCH_STATE_UNHALT_PENDING );
  fd_keyswitch_state( voter, FD_KEYSWITCH_STATE_UNLOCKED );
  poll_remove_all_authorized_voters( &ctx, &state );
  FD_TEST( state==FD_REMOVE_ALL_AUTH_VOTERS_STATE_UNLOCKED );
}

static fd_topo_t      test_topo[1];
static fd_keyswitch_t id_keyswitch[ 8 ];

static fd_keyswitch_t *
mock_tile( char const * name ) {
  fd_topo_tile_t * tile = fd_topob_tile( test_topo, name, "wksp", "wksp", 0UL, 0, 1, 0, 0 );
  fd_keyswitch_t * ks   = fd_keyswitch_join( fd_keyswitch_new( &id_keyswitch[ tile->id ], FD_KEYSWITCH_STATE_UNLOCKED ) );
  FD_TEST( ks );
  test_topo->objs[ tile->id_keyswitch_obj_id ].offset = (ulong)ks;
  return ks;
}

/* Votor and rotor stand in for tower and repair under Alpenglow: they
   stop signing before the sign tiles switch keys, and resume after.
   Alpenglow has no TxSend tile to drain. */

static void
test_set_identity( int alpenglow ) {
  setup( alpenglow );
  FD_TEST( fd_topob_new( test_topo, "admin-test" ) );
  fd_topob_wksp( test_topo, "wksp" )->wksp = NULL;
  fd_keyswitch_t * replay_ks = mock_tile( "replay" );
  fd_keyswitch_t * repair_ks = mock_tile( alpenglow ? "rotor" : "repair" );
  fd_keyswitch_t * voter_ks  = mock_tile( ctx.voter_name );
  fd_keyswitch_t * txsend_ks = alpenglow ? NULL : mock_tile( "txsend" );
  fd_keyswitch_t * gossip_ks = mock_tile( "gossip" );
  fd_keyswitch_t * sign_ks   = mock_tile( "sign" );
  fd_keyswitch_t * gui_ks    = mock_tile( "gui" );
  ctx.topo = test_topo;

  uchar keypair[ 64 ]; memset( keypair, 0x44, sizeof(keypair) );
  uchar vote_history[ 3 ] = { 1, 2, 3 };
  ulong state = FD_SET_IDENTITY_STATE_UNLOCKED;

  poll_set_identity( &ctx, &state, 0UL, keypair, vote_history, sizeof(vote_history) );
  FD_TEST( state==FD_SET_IDENTITY_STATE_LOCKED && replay_ks->state==FD_KEYSWITCH_STATE_LOCKED );

  poll_set_identity( &ctx, &state, 0UL, keypair, vote_history, sizeof(vote_history) );
  FD_TEST( state==FD_SET_IDENTITY_STATE_REPLAY_HALT_REQUESTED && replay_ks->state==FD_KEYSWITCH_STATE_SWITCH_PENDING );
  replay_ks->result = 40UL;
  fd_keyswitch_state( replay_ks, FD_KEYSWITCH_STATE_COMPLETED );
  poll_set_identity( &ctx, &state, 0UL, keypair, vote_history, sizeof(vote_history) );
  FD_TEST( state==FD_SET_IDENTITY_STATE_REPLAY_HALTED );

  poll_set_identity( &ctx, &state, 0UL, keypair, vote_history, sizeof(vote_history) );
  FD_TEST( state==FD_SET_IDENTITY_STATE_VOTER_HALT_REQUESTED );
  FD_TEST( voter_ks->state==FD_KEYSWITCH_STATE_SWITCH_PENDING && voter_ks->param==40UL );
  FD_TEST( FD_LOAD( ulong, voter_ks->bytes+32UL )==sizeof(vote_history) && !memcmp( voter_ks->bytes+40UL, vote_history, sizeof(vote_history) ) );
  voter_ks->result = 42UL;
  fd_keyswitch_state( voter_ks, FD_KEYSWITCH_STATE_COMPLETED );
  poll_set_identity( &ctx, &state, 0UL, keypair, vote_history, sizeof(vote_history) );
  FD_TEST( state==FD_SET_IDENTITY_STATE_VOTER_HALTED );

  poll_set_identity( &ctx, &state, 0UL, keypair, vote_history, sizeof(vote_history) );
  if( !alpenglow ) {
    FD_TEST( state==FD_SET_IDENTITY_STATE_TXSEND_FLUSH_REQUESTED );
    FD_TEST( txsend_ks->state==FD_KEYSWITCH_STATE_SWITCH_PENDING && txsend_ks->param==42UL );
    txsend_ks->result = 7UL;
    fd_keyswitch_state( txsend_ks, FD_KEYSWITCH_STATE_COMPLETED );
    poll_set_identity( &ctx, &state, 0UL, keypair, vote_history, sizeof(vote_history) );
  }
  FD_TEST( state==FD_SET_IDENTITY_STATE_TXSEND_FLUSHED );

  /* Gossip must push the old identity votes TxSend published before it
     halts. */
  poll_set_identity( &ctx, &state, 0UL, keypair, vote_history, sizeof(vote_history) );
  FD_TEST( state==FD_SET_IDENTITY_STATE_SIGNERS_HALT_REQUESTED );
  FD_TEST( repair_ks->state==FD_KEYSWITCH_STATE_SWITCH_PENDING && voter_ks->state==FD_KEYSWITCH_STATE_COMPLETED );
  FD_TEST( gossip_ks->state==FD_KEYSWITCH_STATE_SWITCH_PENDING && gossip_ks->param==( alpenglow ? 0UL : 7UL ) );
  FD_TEST( sign_ks->state==FD_KEYSWITCH_STATE_UNLOCKED && gui_ks->state==FD_KEYSWITCH_STATE_UNLOCKED );
  fd_keyswitch_state( repair_ks, FD_KEYSWITCH_STATE_COMPLETED );
  fd_keyswitch_state( gossip_ks, FD_KEYSWITCH_STATE_COMPLETED );
  poll_set_identity( &ctx, &state, 0UL, keypair, vote_history, sizeof(vote_history) );
  FD_TEST( state==FD_SET_IDENTITY_STATE_SIGNERS_HALTED );

  poll_set_identity( &ctx, &state, 0UL, keypair, vote_history, sizeof(vote_history) );
  FD_TEST( state==FD_SET_IDENTITY_STATE_ALL_SWITCH_REQUESTED );
  FD_TEST( sign_ks->state==FD_KEYSWITCH_STATE_SWITCH_PENDING && gui_ks->state==FD_KEYSWITCH_STATE_SWITCH_PENDING );
  FD_TEST( repair_ks->state==FD_KEYSWITCH_STATE_COMPLETED && voter_ks->state==FD_KEYSWITCH_STATE_COMPLETED );
  fd_keyswitch_state( sign_ks, FD_KEYSWITCH_STATE_COMPLETED );
  fd_keyswitch_state( gui_ks,  FD_KEYSWITCH_STATE_COMPLETED );
  poll_set_identity( &ctx, &state, 0UL, keypair, vote_history, sizeof(vote_history) );
  FD_TEST( state==FD_SET_IDENTITY_STATE_ALL_SWITCHED );

  poll_set_identity( &ctx, &state, 0UL, keypair, vote_history, sizeof(vote_history) );
  FD_TEST( state==FD_SET_IDENTITY_STATE_SIGNERS_UNHALT_REQUESTED );
  FD_TEST( repair_ks->state==FD_KEYSWITCH_STATE_UNHALT_PENDING && voter_ks->state==FD_KEYSWITCH_STATE_UNHALT_PENDING );
  FD_TEST( gossip_ks->state==FD_KEYSWITCH_STATE_UNHALT_PENDING && gossip_ks->param==0UL /* identity_outset */ );
  FD_TEST( gui_ks->state==FD_KEYSWITCH_STATE_COMPLETED );
  if( !alpenglow ) FD_TEST( txsend_ks->state==FD_KEYSWITCH_STATE_UNHALT_PENDING );
  fd_keyswitch_state( repair_ks, FD_KEYSWITCH_STATE_COMPLETED );
  fd_keyswitch_state( voter_ks,  FD_KEYSWITCH_STATE_COMPLETED );
  fd_keyswitch_state( gossip_ks, FD_KEYSWITCH_STATE_COMPLETED );
  if( !alpenglow ) fd_keyswitch_state( txsend_ks, FD_KEYSWITCH_STATE_COMPLETED );
  poll_set_identity( &ctx, &state, 0UL, keypair, vote_history, sizeof(vote_history) );
  FD_TEST( state==FD_SET_IDENTITY_STATE_SIGNERS_UNHALTED );

  poll_set_identity( &ctx, &state, 0UL, keypair, vote_history, sizeof(vote_history) );
  FD_TEST( state==FD_SET_IDENTITY_STATE_REPLAY_UNHALT_REQUESTED && replay_ks->state==FD_KEYSWITCH_STATE_UNHALT_PENDING );
  fd_keyswitch_state( replay_ks, FD_KEYSWITCH_STATE_COMPLETED );
  FD_TEST( poll_set_identity( &ctx, &state, 0UL, keypair, vote_history, sizeof(vote_history) ) );
  FD_TEST( state==FD_SET_IDENTITY_STATE_UNLOCKED && replay_ks->state==FD_KEYSWITCH_STATE_UNLOCKED );
}

/* The admin tile decodes the tower or Alpenglow vote history file, and
   rejects an invalid one before switching. */

static uchar adminctl_mem[ 1UL<<18 ] __attribute__((aligned(FD_ADMINCTL_ALIGN)));

static void
test_set_identity_invalid_vote_history( int alpenglow ) {
  setup( alpenglow );
  FD_TEST( fd_sha512_join( fd_sha512_new( ctx.sha512 ) ) );
  FD_TEST( fd_adminctl_footprint()<=sizeof(adminctl_mem) );
  ctx.adminctl = fd_adminctl_join( fd_adminctl_new( adminctl_mem ) );
  FD_TEST( ctx.adminctl );

  void * payload;
  ulong  payload_max;
  ulong  slot_idx = fd_adminctl_reserve( ctx.adminctl, &payload, &payload_max );
  FD_TEST( slot_idx!=ULONG_MAX && payload_max>=sizeof(fd_adminctl_set_identity_t) );
  fd_adminctl_set_identity_t * req = payload;
  req->version         = FD_ADMINCTL_SET_IDENTITY_PAYLOAD_VERSION;
  req->vote_history_sz = 1UL;
  memset( req->keypair, 0x44, 32UL );
  fd_ed25519_public_from_private( req->keypair+32UL, req->keypair, ctx.sha512 );
  fd_adminctl_publish( ctx.adminctl, slot_idx, FD_ADMINCTL_CMD_SET_IDENTITY, sizeof(fd_adminctl_set_identity_t) );

  ulong  poll_idx;
  void * data;
  ulong  data_sz;
  FD_TEST( fd_adminctl_poll( ctx.adminctl, &poll_idx, &data, &data_sz )==FD_ADMINCTL_CMD_SET_IDENTITY );
  set_identity( &ctx, NULL, poll_idx, data, data_sz );
  FD_TEST( fd_adminctl_wait( ctx.adminctl, slot_idx )==FD_SET_IDENTITY_RESULT_INVALID_VOTE_HISTORY );
}

/* Under failover, set-identity moves the failover identity unless the
   key is our junk key.  OPERATOR is owed while the link has no room and
   failover commands are busy until it goes out.  A switch request from
   before set-identity gets STALE with the failover identity. */

static fd_frag_meta_t    bus_mcache[ 8 ];
static ulong             bus_seq;
static ulong             bus_depth = 8UL;
static ulong             bus_cr_avail;
static ulong             bus_min_cr_avail;
static int               bus_reliable = 1;
static fd_frag_meta_t *  bus_mcaches[ 1 ] = { bus_mcache };
static fd_stem_context_t bus_stem[ 1 ];
static uchar             bus_out[ 1024 ] __attribute__((aligned(128)));

static void
bus_setup( ulong credits ) {
  fd_memset( bus_mcache, 0, sizeof(bus_mcache) );
  bus_seq          = 0UL;
  bus_cr_avail     = credits;
  bus_min_cr_avail = credits;
  *bus_stem = (fd_stem_context_t){ .mcaches=bus_mcaches, .seqs=&bus_seq, .depths=&bus_depth,
                                   .cr_avail=&bus_cr_avail, .min_cr_avail=&bus_min_cr_avail,
                                   .cr_decrement_amount=1UL, .out_reliable=&bus_reliable };
  ctx.failov_out_idx    = 0UL;
  ctx.failov_out_mem    = (fd_wksp_t *)bus_out;
  ctx.failov_out_chunk0 = ctx.failov_out_wmark = ctx.failov_out_chunk = 0UL;
}

static fd_failover_operator_t
bus_operator( void ) {
  FD_TEST( bus_seq && bus_mcache[ bus_seq-1UL ].sig==FD_FAILOVER_BUS_OPERATOR );
  fd_failover_operator_t operator;
  fd_memcpy( &operator, ((fd_failover_bus_msg_t const *)bus_out)->payload, sizeof(operator) );
  return operator;
}

static void
test_failover_identity( void ) {
  setup( 0 );
  FD_TEST( fd_topob_new( test_topo, "admin-test" ) );
  fd_topob_wksp( test_topo, "wksp" )->wksp = NULL;
  fd_keyswitch_t * tower_ks = mock_tile( "tower" );
  fd_keyswitch_t * sign_ks  = mock_tile( "sign" );
  ctx.topo             = test_topo;
  ctx.failover_enabled = 1;
  fd_memset( ctx.junk_pubkey,     0x11, 32UL );
  fd_memset( ctx.failover_pubkey, 0x5A, 32UL );
  fd_memcpy( ctx.identity_pubkey, ctx.junk_pubkey, 32UL );
  uchar third[ 32 ]; fd_memset( third, 0x66, 32UL );
  bus_setup( 8UL );

  /* A third key becomes the failover identity, and nothing goes to the
     failover tile until every tile switched. */
  failover_operator_begin( &ctx, third );
  FD_TEST( ctx.operator_epoch==1UL && fd_memeq( ctx.failover_pubkey, third, 32UL ) && ctx.operator_owed && !bus_seq );
  FD_TEST( sign_ks->param==FD_KEYSWITCH_PARAM_IDENTITY_KEYPAIR && tower_ks->operator==1UL );
  fd_memcpy( ctx.identity_pubkey, third, 32UL );
  failover_operator_notify( &ctx, bus_stem );
  fd_failover_operator_t operator = bus_operator();
  FD_TEST( !ctx.operator_owed && operator.epoch==1UL );
  FD_TEST( fd_memeq( operator.identity, third, 32UL ) && fd_memeq( operator.failover_identity, third, 32UL ) );

  /* The junk key keeps the failover identity.  With three credits left
     OPERATOR is owed, and goes out once there is room. */
  bus_cr_avail = 3UL;
  failover_operator_begin( &ctx, ctx.junk_pubkey );
  fd_memcpy( ctx.identity_pubkey, ctx.junk_pubkey, 32UL );
  failover_operator_notify( &ctx, bus_stem );
  FD_TEST( ctx.operator_owed && bus_seq==1UL && fd_memeq( ctx.failover_pubkey, third, 32UL ) );
  FD_TEST( fd_sha512_join( fd_sha512_new( ctx.sha512 ) ) );
  ctx.adminctl = fd_adminctl_join( fd_adminctl_new( adminctl_mem ) );
  FD_TEST( ctx.adminctl );
  void * payload;
  ulong  payload_max;
  ulong  slot_idx = fd_adminctl_reserve( ctx.adminctl, &payload, &payload_max );
  FD_TEST( slot_idx!=ULONG_MAX );
  fd_adminctl_failover_req_t creq = { .version=FD_ADMINCTL_FAILOVER_PAYLOAD_VERSION, .cmd=FD_ADMINCTL_FAILOVER_CMD_HANDOFF };
  fd_memcpy( payload, &creq, sizeof(creq) );
  fd_adminctl_publish( ctx.adminctl, slot_idx, FD_ADMINCTL_CMD_FAILOVER, sizeof(creq) );
  ulong  poll_idx;
  void * data;
  ulong  data_sz;
  FD_TEST( fd_adminctl_poll( ctx.adminctl, &poll_idx, &data, &data_sz )==FD_ADMINCTL_CMD_FAILOVER );
  failover_request( &ctx, bus_stem, poll_idx, data, data_sz );
  FD_TEST( bus_seq==1UL );
  FD_TEST( fd_adminctl_wait( ctx.adminctl, slot_idx )==FD_FAILOVER_CONTROL_RESULT_BUSY );
  bus_cr_avail = 8UL;
  failover_operator_notify( &ctx, bus_stem );
  operator = bus_operator();
  FD_TEST( !ctx.operator_owed && operator.epoch==2UL );
  FD_TEST( fd_memeq( operator.identity, ctx.junk_pubkey, 32UL ) && fd_memeq( operator.failover_identity, third, 32UL ) );

  /* A switch request from before set-identity gets STALE with what it
     installed. */
  ctx.failov_in.nonce = 9UL;
  fd_failover_switch_req_t sreq = { .epoch=1UL };
  fd_memcpy( sreq.identity, third, 32UL );
  fd_memcpy( ctx.failov_in.payload, &sreq, sizeof(sreq) );
  failover_switch_request( &ctx, bus_stem );
  fd_failover_switch_resp_t answer;
  fd_memcpy( &answer, ((fd_failover_bus_msg_t const *)bus_out)->payload, sizeof(answer) );
  FD_TEST( answer.result==FD_FAILOVER_SWITCH_ERR_STALE && answer.operator.epoch==2UL );
  FD_TEST( fd_memeq( answer.operator.identity, ctx.junk_pubkey, 32UL ) && fd_memeq( answer.operator.failover_identity, third, 32UL ) );
  ctx.topo = NULL;
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_add_authorized_voter( 0 );
  test_add_authorized_voter( 1 );
  test_remove_all_authorized_voters( 0 );
  test_remove_all_authorized_voters( 1 );
  test_set_identity( 0 );
  test_set_identity( 1 );
  test_set_identity_invalid_vote_history( 0 );
  test_set_identity_invalid_vote_history( 1 );
  test_failover_identity();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
