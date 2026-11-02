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

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_add_authorized_voter();
  test_remove_all_authorized_voters();
  test_set_identity();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
