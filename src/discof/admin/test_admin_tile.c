#include "fd_admin_tile.c"
#include "../../disco/topo/fd_topob.h"

#define TEST_SIGN_CNT (2UL)

static fd_admin_tile_ctx_t ctx;
static fd_keyswitch_t      voter [1];
static fd_keyswitch_t      sign  [ TEST_SIGN_CNT ];

static void
setup( void ) {
  memset( &ctx, 0, sizeof(ctx) );
  ctx.voter_av_keyswitch  = fd_keyswitch_join( fd_keyswitch_new( voter,  FD_KEYSWITCH_STATE_UNLOCKED ) );
  FD_TEST( ctx.voter_av_keyswitch );
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

/* The sign tiles learn a new authorized voter before votor does. */

static void
test_add_authorized_voter( void ) {
  setup();
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
}

/* Votor drops its authorized voters before the sign tiles do. */

static void
test_remove_all_authorized_voters( void ) {
  setup();
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
  fd_topo_tile_t * tile = fd_topob_tile( test_topo, name, "wksp", "wksp", 0UL, 1, 0, 0 );
  fd_keyswitch_t * ks   = fd_keyswitch_join( fd_keyswitch_new( &id_keyswitch[ tile->id ], FD_KEYSWITCH_STATE_UNLOCKED ) );
  FD_TEST( ks );
  test_topo->objs[ tile->id_keyswitch_obj_id ].offset = (ulong)ks;
  return ks;
}

/* Votor and rotor stop signing before the sign tiles switch keys, and
   resume after. */

static void
test_set_identity( void ) {
  setup();
  FD_TEST( fd_topob_new( test_topo, "admin-test" ) );
  fd_topob_wksp( test_topo, "wksp" )->wksp = NULL;
  fd_keyswitch_t * replay_ks = mock_tile( "replay" );
  fd_keyswitch_t * repair_ks = mock_tile( "rotor" );
  fd_keyswitch_t * voter_ks  = mock_tile( "votor" );
  fd_keyswitch_t * gossip_ks = mock_tile( "gossip" );
  fd_keyswitch_t * sign_ks   = mock_tile( "sign" );
  fd_keyswitch_t * gui_ks    = mock_tile( "gui" );
  ctx.topo = test_topo;

  uchar keypair[ 64 ]; memset( keypair, 0x44, sizeof(keypair) );
  ulong vote_history_slot = 8UL;
  ulong state = FD_SET_IDENTITY_STATE_UNLOCKED;

  poll_set_identity( &ctx, &state, 0UL, keypair, vote_history_slot );
  FD_TEST( state==FD_SET_IDENTITY_STATE_LOCKED && replay_ks->state==FD_KEYSWITCH_STATE_LOCKED );

  poll_set_identity( &ctx, &state, 0UL, keypair, vote_history_slot );
  FD_TEST( state==FD_SET_IDENTITY_STATE_REPLAY_HALT_REQUESTED && replay_ks->state==FD_KEYSWITCH_STATE_SWITCH_PENDING );
  replay_ks->result = 40UL;
  fd_keyswitch_state( replay_ks, FD_KEYSWITCH_STATE_COMPLETED );
  poll_set_identity( &ctx, &state, 0UL, keypair, vote_history_slot );
  FD_TEST( state==FD_SET_IDENTITY_STATE_REPLAY_HALTED );

  poll_set_identity( &ctx, &state, 0UL, keypair, vote_history_slot );
  FD_TEST( state==FD_SET_IDENTITY_STATE_VOTER_HALT_REQUESTED );
  FD_TEST( voter_ks->state==FD_KEYSWITCH_STATE_SWITCH_PENDING && voter_ks->param==40UL );
  FD_TEST( FD_LOAD( ulong, voter_ks->bytes+32UL )==8UL );
  voter_ks->result = 42UL;
  fd_keyswitch_state( voter_ks, FD_KEYSWITCH_STATE_COMPLETED );
  poll_set_identity( &ctx, &state, 0UL, keypair, vote_history_slot );
  FD_TEST( state==FD_SET_IDENTITY_STATE_VOTER_HALTED );

  poll_set_identity( &ctx, &state, 0UL, keypair, vote_history_slot );
  FD_TEST( state==FD_SET_IDENTITY_STATE_SIGNERS_HALT_REQUESTED );
  FD_TEST( repair_ks->state==FD_KEYSWITCH_STATE_SWITCH_PENDING && voter_ks->state==FD_KEYSWITCH_STATE_COMPLETED );
  FD_TEST( gossip_ks->state==FD_KEYSWITCH_STATE_SWITCH_PENDING && gossip_ks->param==0UL );
  FD_TEST( sign_ks->state==FD_KEYSWITCH_STATE_UNLOCKED && gui_ks->state==FD_KEYSWITCH_STATE_UNLOCKED );
  fd_keyswitch_state( repair_ks, FD_KEYSWITCH_STATE_COMPLETED );
  fd_keyswitch_state( gossip_ks, FD_KEYSWITCH_STATE_COMPLETED );
  poll_set_identity( &ctx, &state, 0UL, keypair, vote_history_slot );
  FD_TEST( state==FD_SET_IDENTITY_STATE_SIGNERS_HALTED );

  poll_set_identity( &ctx, &state, 0UL, keypair, vote_history_slot );
  FD_TEST( state==FD_SET_IDENTITY_STATE_ALL_SWITCH_REQUESTED );
  FD_TEST( sign_ks->state==FD_KEYSWITCH_STATE_SWITCH_PENDING && gui_ks->state==FD_KEYSWITCH_STATE_SWITCH_PENDING );
  FD_TEST( repair_ks->state==FD_KEYSWITCH_STATE_COMPLETED && voter_ks->state==FD_KEYSWITCH_STATE_COMPLETED );
  fd_keyswitch_state( sign_ks, FD_KEYSWITCH_STATE_COMPLETED );
  fd_keyswitch_state( gui_ks,  FD_KEYSWITCH_STATE_COMPLETED );
  poll_set_identity( &ctx, &state, 0UL, keypair, vote_history_slot );
  FD_TEST( state==FD_SET_IDENTITY_STATE_ALL_SWITCHED );

  poll_set_identity( &ctx, &state, 0UL, keypair, vote_history_slot );
  FD_TEST( state==FD_SET_IDENTITY_STATE_SIGNERS_UNHALT_REQUESTED );
  FD_TEST( repair_ks->state==FD_KEYSWITCH_STATE_UNHALT_PENDING && voter_ks->state==FD_KEYSWITCH_STATE_UNHALT_PENDING );
  FD_TEST( gossip_ks->state==FD_KEYSWITCH_STATE_UNHALT_PENDING && gossip_ks->param==0UL /* identity_outset */ );
  FD_TEST( gui_ks->state==FD_KEYSWITCH_STATE_COMPLETED );
  fd_keyswitch_state( repair_ks, FD_KEYSWITCH_STATE_COMPLETED );
  fd_keyswitch_state( voter_ks,  FD_KEYSWITCH_STATE_COMPLETED );
  fd_keyswitch_state( gossip_ks, FD_KEYSWITCH_STATE_COMPLETED );
  poll_set_identity( &ctx, &state, 0UL, keypair, vote_history_slot );
  FD_TEST( state==FD_SET_IDENTITY_STATE_SIGNERS_UNHALTED );

  poll_set_identity( &ctx, &state, 0UL, keypair, vote_history_slot );
  FD_TEST( state==FD_SET_IDENTITY_STATE_REPLAY_UNHALT_REQUESTED && replay_ks->state==FD_KEYSWITCH_STATE_UNHALT_PENDING );
  fd_keyswitch_state( replay_ks, FD_KEYSWITCH_STATE_COMPLETED );
  FD_TEST( poll_set_identity( &ctx, &state, 0UL, keypair, vote_history_slot ) );
  FD_TEST( state==FD_SET_IDENTITY_STATE_UNLOCKED && replay_ks->state==FD_KEYSWITCH_STATE_UNLOCKED );
}

static uchar adminctl_mem[ 1UL<<18 ] __attribute__((aligned(FD_ADMINCTL_ALIGN)));

/* With failover, set-identity changes the failover identity.  OPERATOR
   waits while the link has no room and failover commands are busy until
   it goes out.  A switch request from before set-identity gets STALE
   with the failover identity. */

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
  FD_TEST( bus_seq && bus_mcache[ bus_seq-1UL ].sig==FD_FAILOVER_BUS_OPERATOR_ACTION );
  fd_failover_operator_t operator;
  fd_memcpy( &operator, ((fd_failover_bus_msg_t const *)bus_out)->payload, sizeof(operator) );
  return operator;
}

/* Events identify the public command on completion and on rejection,
   including requests whose payload cannot be decoded. */
static void
test_failover_command( ulong cmd_id,
                       ulong payload_cmd,
                       ulong flags,
                       int   event_type ) {
  setup();
  bus_setup( 8UL );
  ctx.adminctl          = fd_adminctl_join( fd_adminctl_new( adminctl_mem ) );
  ctx.failover_enabled  = 1;
  ctx.failover_slot_idx = ULONG_MAX;
  FD_TEST( ctx.adminctl );

  static fd_frag_meta_t event_mcache[ 128 ] __attribute__((aligned(128)));
  static uchar event_mem[ 1024 ] __attribute__((aligned(128)));
  ulong               event_seq = 0UL;
  fd_event_reporter_t reporter  = { .mcache=event_mcache, .depth=128UL, .seq_store=&event_seq,
                                   .mem=(fd_wksp_t *)event_mem, .mtu=sizeof(event_mem) };
  fd_event_tl = &reporter;

  for( ulong i=0UL; i<4UL; i++ ) {
    void * payload;
    ulong  payload_max;
    ulong  slot_idx = fd_adminctl_reserve( ctx.adminctl, &payload, &payload_max );
    FD_TEST( slot_idx!=ULONG_MAX && payload_max>=sizeof(fd_adminctl_failover_req_t) );
    fd_adminctl_failover_req_t req = { .version=FD_ADMINCTL_FAILOVER_PAYLOAD_VERSION, .cmd=payload_cmd, .flags=flags };
    /* An unknown command. */
    if( i==3UL ) req.cmd = FD_ADMINCTL_FAILOVER_CMD_CNT;
    fd_memcpy( payload, &req, sizeof(req) );
    fd_adminctl_publish( ctx.adminctl, slot_idx, cmd_id, i==2UL ? 0UL : sizeof(req) );
    int   poll_in    = 1;
    int   busy       = 0;
    ulong seq_before = bus_seq;
    for( ulong j=0UL; j<FD_ADMINCTL_SLOT_CNT && !busy; j++ ) after_credit( &ctx, bus_stem, &poll_in, &busy );
    FD_TEST( busy );

    ulong result;
    int   event_result;
    if( i<2UL ) {
      FD_TEST( bus_seq==seq_before+1UL && event_seq==i );
      fd_adminctl_failover_req_t forwarded;
      fd_memcpy( &forwarded, ((fd_failover_bus_msg_t const *)bus_out)->payload, sizeof(forwarded) );
      FD_TEST( forwarded.cmd==payload_cmd && forwarded.flags==flags );
      result       = i ? FD_FAILOVER_CONTROL_RESULT_WRONG_HOLDER : FD_ADMINCTL_RESULT_SUCCESS;
      event_result = i ? FD_EVENT_ADMIN_COMMAND_RESULT_CUSTOM : FD_EVENT_ADMIN_COMMAND_RESULT_SUCCESS;
      ctx.failov_in.nonce  = ctx.failover_nonce;
      ctx.failov_in.result = result;
      failover_response( &ctx );
    } else {
      FD_TEST( bus_seq==seq_before );
      result       = i==2UL ? FD_ADMINCTL_RESULT_ABI_SIZE_MISMATCH : FD_ADMINCTL_RESULT_UNKNOWN_COMMAND;
      event_result = i==2UL ? FD_EVENT_ADMIN_COMMAND_RESULT_ABI_SIZE_MISMATCH : FD_EVENT_ADMIN_COMMAND_RESULT_UNKNOWN_COMMAND;
    }
    FD_TEST( fd_adminctl_wait( ctx.adminctl, slot_idx )==result );
    FD_TEST( event_seq==i+1UL );
    fd_event_admin_command_t event;
    fd_memcpy( &event, event_mem, sizeof(event) );
    FD_TEST( event.type==event_type && event.result==event_result );
    if( i<2UL ) {
      char const * args = flags & FD_ADMINCTL_FAILOVER_FLAG_FORCE ? "{\"yes\":true,\"force\":true,\"adopt\":false}" :
                          flags & FD_ADMINCTL_FAILOVER_FLAG_ADOPT ? "{\"yes\":false,\"force\":false,\"adopt\":true}" : "{\"yes\":false,\"force\":false,\"adopt\":false}";
      FD_TEST( event.args_json_len==strlen( args ) && !memcmp( event.args_json, args, event.args_json_len ) );
    }
  }
  fd_event_tl = NULL;
}

static void
test_failover_identity( void ) {
  setup();
  FD_TEST( fd_topob_new( test_topo, "admin-test" ) );
  fd_topob_wksp( test_topo, "wksp" )->wksp = NULL;
  fd_keyswitch_t * votor_ks = mock_tile( "votor" );
  fd_keyswitch_t * sign_ks  = mock_tile( "sign" );
  ctx.topo             = test_topo;
  ctx.failover_enabled = 1;
  uchar spare[ 32 ]; fd_memset( spare, 0x11, 32UL );
  fd_memset( ctx.failover_pubkey, 0x5A, 32UL );
  fd_memcpy( ctx.identity_pubkey, spare, 32UL );
  uchar third[ 32 ]; fd_memset( third, 0x66, 32UL );
  bus_setup( 8UL );

  /* The set-identity key becomes the failover identity, and nothing
     goes to the failover tile until every tile switched. */
  failover_operator_begin( &ctx, third );
  FD_TEST( ctx.failover_epoch==1UL && fd_memeq( ctx.failover_pubkey, third, 32UL ) && ctx.failover_pending && !bus_seq );
  FD_TEST( sign_ks->param==FD_KEYSWITCH_PARAM_IDENTITY_KEYPAIR && votor_ks->failover==0UL );
  fd_memcpy( ctx.identity_pubkey, third, 32UL );
  failover_operator_notify( &ctx, bus_stem );
  fd_failover_operator_t operator = bus_operator();
  FD_TEST( !ctx.failover_pending && operator.epoch==1UL );
  FD_TEST( fd_memeq( operator.identity, third, 32UL ) && fd_memeq( operator.failover_identity, third, 32UL ) );

  /* So does any other key.  With three credits left OPERATOR waits,
     and goes out once there is room. */
  bus_cr_avail = 3UL;
  failover_operator_begin( &ctx, spare );
  fd_memcpy( ctx.identity_pubkey, spare, 32UL );
  failover_operator_notify( &ctx, bus_stem );
  FD_TEST( ctx.failover_pending && bus_seq==1UL && fd_memeq( ctx.failover_pubkey, spare, 32UL ) );
  FD_TEST( fd_sha512_join( fd_sha512_new( ctx.sha512 ) ) );
  ctx.adminctl = fd_adminctl_join( fd_adminctl_new( adminctl_mem ) );
  FD_TEST( ctx.adminctl );
  void * payload;
  ulong  payload_max;
  ulong  slot_idx = fd_adminctl_reserve( ctx.adminctl, &payload, &payload_max );
  FD_TEST( slot_idx!=ULONG_MAX );
  fd_adminctl_failover_req_t creq = { .version=FD_ADMINCTL_FAILOVER_PAYLOAD_VERSION, .cmd=FD_ADMINCTL_FAILOVER_CMD_HANDOFF };
  fd_memcpy( payload, &creq, sizeof(creq) );
  fd_adminctl_publish( ctx.adminctl, slot_idx, FD_ADMINCTL_CMD_FAILOVER_PROMOTE, sizeof(creq) );
  ulong  poll_idx;
  void * data;
  ulong  data_sz;
  FD_TEST( fd_adminctl_poll( ctx.adminctl, &poll_idx, &data, &data_sz )==FD_ADMINCTL_CMD_FAILOVER_PROMOTE );
  failover_request( &ctx, bus_stem, poll_idx, FD_ADMINCTL_CMD_FAILOVER_PROMOTE, data, data_sz );
  FD_TEST( bus_seq==1UL );
  FD_TEST( fd_adminctl_wait( ctx.adminctl, slot_idx )==FD_FAILOVER_CONTROL_RESULT_BUSY );
  bus_cr_avail = 8UL;
  failover_operator_notify( &ctx, bus_stem );
  operator = bus_operator();
  FD_TEST( !ctx.failover_pending && operator.epoch==2UL );
  FD_TEST( fd_memeq( operator.identity, spare, 32UL ) && fd_memeq( operator.failover_identity, spare, 32UL ) );

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
  FD_TEST( fd_memeq( answer.operator.identity, spare, 32UL ) && fd_memeq( answer.operator.failover_identity, spare, 32UL ) );

  /* Another key becomes the target, also while this machine runs the
     current one, the CLI warns about that case. */
  uchar keypair[ 64 ]; fd_memset( keypair, 0x77, 32UL );
  fd_ed25519_public_from_private( keypair+32UL, keypair, ctx.sha512 );
  fd_memcpy( ctx.identity_pubkey, third, 32UL );
  ctx.failover_pending = 0;
  FD_TEST( fd_topob_new( test_topo, "admin-test" ) );
  fd_topob_wksp( test_topo, "wksp" )->wksp = NULL;
  (void)mock_tile( "votor" );
  FD_TEST( failover_prepare( &ctx, keypair )==FD_ADMINCTL_RESULT_SUCCESS );
  FD_TEST( ctx.failover_epoch==3UL && ctx.failover_pending && ctx.failover_retargeted );
  FD_TEST( fd_memeq( ctx.failover_pubkey, keypair+32UL, 32UL ) && fd_memeq( ctx.identity_pubkey, third, 32UL ) );

  /* Same key is a no-op, a mismatched keypair is refused. */
  uchar other[ 64 ]; fd_memset( other, 0x78, 32UL );
  fd_ed25519_public_from_private( other+32UL, other, ctx.sha512 );
  FD_TEST( failover_prepare( &ctx, other )==FD_ADMINCTL_RESULT_SUCCESS );
  FD_TEST( ctx.failover_epoch==4UL && fd_memeq( ctx.failover_pubkey, other+32UL, 32UL ) );
  FD_TEST( failover_prepare( &ctx, other )==FD_ADMINCTL_RESULT_SUCCESS && ctx.failover_epoch==4UL );
  uchar bad[ 64 ]; fd_memcpy( bad, other, 64UL ); bad[ 32 ]^=1;
  FD_TEST( failover_prepare( &ctx, bad )==FD_SET_IDENTITY_RESULT_KEYPAIR_MISMATCH );
  FD_TEST( ctx.failover_epoch==4UL && fd_memeq( ctx.failover_pubkey, other+32UL, 32UL ) );
  ctx.topo = NULL;
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_add_authorized_voter();
  test_remove_all_authorized_voters();
  test_set_identity();
  test_failover_command( FD_ADMINCTL_CMD_FAILOVER_PROMOTE, FD_ADMINCTL_FAILOVER_CMD_HANDOFF, 0UL, FD_EVENT_ADMIN_COMMAND_TYPE_FAILOVER_PROMOTE );
  test_failover_command( FD_ADMINCTL_CMD_FAILOVER_PROMOTE, FD_ADMINCTL_FAILOVER_CMD_PROMOTE,
                         FD_ADMINCTL_FAILOVER_FLAG_YES|FD_ADMINCTL_FAILOVER_FLAG_FORCE, FD_EVENT_ADMIN_COMMAND_TYPE_FAILOVER_PROMOTE );
  test_failover_command( FD_ADMINCTL_CMD_FAILOVER_PROMOTE, FD_ADMINCTL_FAILOVER_CMD_PROMOTE,
                         FD_ADMINCTL_FAILOVER_FLAG_ADOPT, FD_EVENT_ADMIN_COMMAND_TYPE_FAILOVER_PROMOTE );
  test_failover_identity();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
