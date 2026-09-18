#include "fd_failover_proto.h"
#include "../../util/fd_util.h"

#include <string.h>

static ulong expected[ 2 ][ FD_FAILOVER_SESSION_CNT ][ FD_FAILOVER_EV_CNT ];

static void
build_expected( void ) {
  int lost[] = { FD_FAILOVER_EV_LINK_LOST, FD_FAILOVER_EV_TIMEOUT, FD_FAILOVER_EV_HELLO_FATAL };
  for( int dial_peer=0; dial_peer<2; dial_peer++ ) {
    for( ulong s=0UL; s<FD_FAILOVER_SESSION_CNT; s++ ) {
      for( int e=0; e<FD_FAILOVER_EV_CNT; e++ ) expected[ dial_peer ][ s ][ e ] = s;
    }
  }
  /* Listener: candidates never show in the aggregate state. */
  expected[ 0 ][ FD_FAILOVER_SESSION_LISTENING ][ FD_FAILOVER_EV_HELLO_OK ] = FD_FAILOVER_SESSION_PAIRED;
  for( ulong i=0UL; i<3UL; i++ ) expected[ 0 ][ FD_FAILOVER_SESSION_PAIRED ][ lost[ i ] ] = FD_FAILOVER_SESSION_LISTENING;
  /* Dialer. */
  expected[ 1 ][ FD_FAILOVER_SESSION_BACKOFF ][ FD_FAILOVER_EV_RETRY     ] = FD_FAILOVER_SESSION_DIALING;
  expected[ 1 ][ FD_FAILOVER_SESSION_DIALING ][ FD_FAILOVER_EV_CONNECTED ] = FD_FAILOVER_SESSION_HELLO;
  expected[ 1 ][ FD_FAILOVER_SESSION_HELLO   ][ FD_FAILOVER_EV_HELLO_OK  ] = FD_FAILOVER_SESSION_PAIRED;
  for( ulong i=0UL; i<3UL; i++ ) {
    expected[ 1 ][ FD_FAILOVER_SESSION_DIALING ][ lost[ i ] ] = FD_FAILOVER_SESSION_BACKOFF;
    expected[ 1 ][ FD_FAILOVER_SESSION_HELLO   ][ lost[ i ] ] = FD_FAILOVER_SESSION_BACKOFF;
    expected[ 1 ][ FD_FAILOVER_SESSION_PAIRED  ][ lost[ i ] ] = FD_FAILOVER_SESSION_BACKOFF;
  }
}

static void
test_session_exhaustive( void ) {
  build_expected();
  for( int dial_peer=0; dial_peer<2; dial_peer++ ) {
    for( ulong s=0UL; s<FD_FAILOVER_SESSION_CNT; s++ ) {
      for( int e=0; e<FD_FAILOVER_EV_CNT; e++ ) {
        FD_TEST( fd_failover_session_step( s, dial_peer, e )==expected[ dial_peer ][ s ][ e ] );
      }
    }
  }
  FD_LOG_NOTICE(( "pass: test_session_exhaustive" ));
}

static void
test_session_properties( void ) {
  /* PAIRED is reachable only through HELLO_OK */
  for( int dial_peer=0; dial_peer<2; dial_peer++ ) {
    for( ulong s=0UL; s<FD_FAILOVER_SESSION_CNT; s++ ) {
      if( s==FD_FAILOVER_SESSION_PAIRED ) continue;
      for( int e=0; e<FD_FAILOVER_EV_CNT; e++ ) {
        if( e==FD_FAILOVER_EV_HELLO_OK ) continue;
        FD_TEST( fd_failover_session_step( s, dial_peer, e )!=FD_FAILOVER_SESSION_PAIRED );
      }
    }
  }

  /* From its resting state each role reaches exactly its own states:
     the listener never dials or backs off, the dialer never listens. */
  for( int dial_peer=0; dial_peer<2; dial_peer++ ) {
    int reachable[ FD_FAILOVER_SESSION_CNT ] = {0};
    ulong queue[ FD_FAILOVER_SESSION_CNT ];
    ulong head = 0UL, tail = 0UL;
    ulong init = fd_failover_session_init( dial_peer );
    reachable[ init ] = 1; queue[ tail++ ] = init;
    while( head<tail ) {
      ulong s = queue[ head++ ];
      for( int e=0; e<FD_FAILOVER_EV_CNT; e++ ) {
        ulong n = fd_failover_session_step( s, dial_peer, e );
        if( !reachable[ n ] ) { reachable[ n ] = 1; queue[ tail++ ] = n; }
      }
    }
    FD_TEST( reachable[ FD_FAILOVER_SESSION_PAIRED ] );
    FD_TEST( reachable[ FD_FAILOVER_SESSION_LISTENING ]==!dial_peer );
    FD_TEST( reachable[ FD_FAILOVER_SESSION_BACKOFF   ]==!!dial_peer );
    FD_TEST( reachable[ FD_FAILOVER_SESSION_DIALING   ]==!!dial_peer );
    FD_TEST( reachable[ FD_FAILOVER_SESSION_HELLO     ]==!!dial_peer );
  }
  FD_TEST( fd_failover_session_init( 0 )==FD_FAILOVER_SESSION_LISTENING );
  FD_TEST( fd_failover_session_init( 1 )==FD_FAILOVER_SESSION_BACKOFF );

  /* Out of range inputs change nothing */
  FD_TEST( fd_failover_session_step( 99UL, 1, FD_FAILOVER_EV_RETRY )==99UL );
  FD_TEST( fd_failover_session_step( FD_FAILOVER_SESSION_BACKOFF, 2, FD_FAILOVER_EV_RETRY )==FD_FAILOVER_SESSION_BACKOFF );
  FD_TEST( fd_failover_session_step( FD_FAILOVER_SESSION_PAIRED, 1, 99 )==FD_FAILOVER_SESSION_PAIRED );
  FD_TEST( fd_failover_session_step( FD_FAILOVER_SESSION_PAIRED, 1, -1 )==FD_FAILOVER_SESSION_PAIRED );

  FD_LOG_NOTICE(( "pass: test_session_properties" ));
}

static void
fill_hello( fd_failover_hello_t * h,
            uchar                 junk,
            uchar                 staked,
            uchar                 vote,
            uchar                 role ) {
  fd_memset( h, 0, sizeof(fd_failover_hello_t) );
  h->version = (ushort)FD_FAILOVER_VERSION;
  fd_memset( h->junk_pubkey,   junk,   32UL );
  fd_memset( h->staked_pubkey, staked, 32UL );
  fd_memset( h->vote_account,  vote,   32UL );
  h->role = role;
}

static void
test_hello_checks( void ) {
  fd_failover_hello_t self;
  fd_failover_hello_t peer;

  /* A well formed pair passes */
  fill_hello( &self, 0x01, 0xAA, 0xBB, (uchar)FD_FAILOVER_ROLE_ACTIVE  );
  fill_hello( &peer, 0x02, 0xAA, 0xBB, (uchar)FD_FAILOVER_ROLE_STANDBY );
  FD_TEST( fd_failover_hello_check( &self, &peer )==FD_FAILOVER_HELLO_OK );
  FD_TEST( fd_failover_hello_check( &peer, &self )==FD_FAILOVER_HELLO_OK );

  fill_hello( &peer, 0x02, 0xAA, 0xBB, 2U );
  FD_TEST( fd_failover_hello_check( &self, &peer )==FD_FAILOVER_HELLO_ERR_ROLE );

  fill_hello( &peer, 0x02, 0xAA, 0xBB, (uchar)FD_FAILOVER_ROLE_STANDBY );

  /* Version mismatch */
  peer.version = (ushort)( FD_FAILOVER_VERSION+1U );
  FD_TEST( fd_failover_hello_check( &self, &peer )==FD_FAILOVER_HELLO_ERR_VERSION );
  peer.version = (ushort)FD_FAILOVER_VERSION;

  /* Staked identity mismatch */
  fill_hello( &peer, 0x02, 0xAC, 0xBB, (uchar)FD_FAILOVER_ROLE_STANDBY );
  FD_TEST( fd_failover_hello_check( &self, &peer )==FD_FAILOVER_HELLO_ERR_STAKED );

  /* Vote account mismatch */
  fill_hello( &peer, 0x02, 0xAA, 0xBC, (uchar)FD_FAILOVER_ROLE_STANDBY );
  FD_TEST( fd_failover_hello_check( &self, &peer )==FD_FAILOVER_HELLO_ERR_VOTE_ACCT );

  /* Junk identity collision */
  fill_hello( &peer, 0x01, 0xAA, 0xBB, (uchar)FD_FAILOVER_ROLE_STANDBY );
  FD_TEST( fd_failover_hello_check( &self, &peer )==FD_FAILOVER_HELLO_ERR_JUNK_EQ );

  /* Junk equal to staked on either side */
  fill_hello( &peer, 0xAA, 0xAA, 0xBB, (uchar)FD_FAILOVER_ROLE_STANDBY );
  FD_TEST( fd_failover_hello_check( &self, &peer )==FD_FAILOVER_HELLO_ERR_JUNK_STAKE );
  fill_hello( &self, 0xAA, 0xAA, 0xBB, (uchar)FD_FAILOVER_ROLE_ACTIVE  );
  fill_hello( &peer, 0x02, 0xAA, 0xBB, (uchar)FD_FAILOVER_ROLE_STANDBY );
  FD_TEST( fd_failover_hello_check( &self, &peer )==FD_FAILOVER_HELLO_ERR_JUNK_STAKE );

  /* Both sides claiming active */
  fill_hello( &self, 0x01, 0xAA, 0xBB, (uchar)FD_FAILOVER_ROLE_ACTIVE );
  fill_hello( &peer, 0x02, 0xAA, 0xBB, (uchar)FD_FAILOVER_ROLE_ACTIVE );
  FD_TEST( fd_failover_hello_check( &self, &peer )==FD_FAILOVER_HELLO_ERR_BOTH_ACT );
  peer.term = 1UL;
  FD_TEST( fd_failover_hello_check( &self, &peer )==FD_FAILOVER_HELLO_OK );

  /* A safety relevant config mismatch is fatal */
  fill_hello( &self, 0x01, 0xAA, 0xBB, (uchar)FD_FAILOVER_ROLE_ACTIVE  );
  fill_hello( &peer, 0x02, 0xAA, 0xBB, (uchar)FD_FAILOVER_ROLE_STANDBY );
  peer.cfg_hash = 7UL;
  FD_TEST( fd_failover_hello_check( &self, &peer )==FD_FAILOVER_HELLO_ERR_CFG );
  peer.cfg_hash = 0UL;

  /* Both nodes may remain standby until an operator promotes one */
  fill_hello( &self, 0x01, 0xAA, 0xBB, (uchar)FD_FAILOVER_ROLE_STANDBY );
  fill_hello( &peer, 0x02, 0xAA, 0xBB, (uchar)FD_FAILOVER_ROLE_STANDBY );
  FD_TEST( fd_failover_hello_check( &self, &peer )==FD_FAILOVER_HELLO_OK );

  FD_LOG_NOTICE(( "pass: test_hello_checks" ));
}

static void
test_state_boot( void ) {
  FD_TEST( fd_failover_state_boot( FD_FAILOVER_STATE_STANDBY   )==FD_FAILOVER_STATE_STANDBY );
  FD_TEST( fd_failover_state_boot( FD_FAILOVER_STATE_ACTIVE    )==FD_FAILOVER_STATE_RECLAIMING );
  FD_TEST( fd_failover_state_boot( FD_FAILOVER_STATE_DEMOTING  )==FD_FAILOVER_STATE_STANDBY );
  FD_TEST( fd_failover_state_boot( FD_FAILOVER_STATE_PROMOTING )==FD_FAILOVER_STATE_STANDBY );
  FD_TEST( fd_failover_state_boot( FD_FAILOVER_STATE_RECLAIMING)==FD_FAILOVER_STATE_RECLAIMING );
  FD_TEST( fd_failover_state_boot( 99UL )==FD_FAILOVER_STATE_STANDBY );

  FD_LOG_NOTICE(( "pass: test_state_boot" ));
}

static void
test_demoted_terms( void ) {
  FD_TEST(  fd_failover_demoted_term_check( 8UL, 7UL, 8UL, FD_FAILOVER_ROLE_STANDBY, 0 ) );
  FD_TEST(  fd_failover_demoted_term_check( 8UL, 7UL, 7UL, FD_FAILOVER_ROLE_STANDBY, 0 ) );
  FD_TEST(  fd_failover_demoted_term_check( 7UL, 7UL, 7UL, FD_FAILOVER_ROLE_STANDBY, 1 ) );
  FD_TEST( !fd_failover_demoted_term_check( 7UL, 7UL, 7UL, FD_FAILOVER_ROLE_STANDBY, 0 ) );
  FD_TEST( !fd_failover_demoted_term_check( 8UL, 7UL, 8UL, FD_FAILOVER_ROLE_ACTIVE,  0 ) );
  FD_TEST( !fd_failover_demoted_term_check( 6UL, 7UL, 6UL, FD_FAILOVER_ROLE_STANDBY, 1 ) );
  FD_TEST( !fd_failover_demoted_term_check( 9UL, 7UL, 9UL, FD_FAILOVER_ROLE_STANDBY, 1 ) );
  FD_TEST( !fd_failover_demoted_term_check( ULONG_MAX-1UL, ULONG_MAX-2UL,
                                            ULONG_MAX-1UL, FD_FAILOVER_ROLE_STANDBY, 0 ) );

  FD_LOG_NOTICE(( "pass: test_demoted_terms" ));
}

static void
test_handoff_checks( void ) {
  fd_failover_handoff_req_t req = {
    .proposed_term = 8UL,
    .reason         = FD_FAILOVER_HANDOFF_REASON_STANDBY,
    .deadline_slots = 64U,
  };
  fd_failover_status_t local;
  fd_failover_status_t peer;
  fd_memset( &local, 0, sizeof(local) );
  fd_memset( &peer,  0, sizeof(peer)  );
  local.term             = 7UL;
  local.role             = FD_FAILOVER_ROLE_ACTIVE;
  local.replay_slot      = 1000UL;
  local.next_leader_slot = 1200UL;
  local.flags            = FD_FAILOVER_FLAG_CAUGHT_UP;
  peer.term              = 7UL;
  peer.role              = FD_FAILOVER_ROLE_STANDBY;
  peer.flags             = FD_FAILOVER_FLAG_CAUGHT_UP;

  uchar reason = 0U;
  FD_TEST( fd_failover_handoff_check( &req, &local, &peer, 1, 1, 1, 0, 150UL, 64UL, &reason )==FD_FAILOVER_HANDOFF_PROCEED );
  FD_TEST( reason==FD_FAILOVER_REJECT_NONE );

#define CHECK_REJECT(change, expected) do {                                    \
    fd_failover_handoff_req_t r = req;                                         \
    fd_failover_status_t      l = local;                                       \
    fd_failover_status_t      p = peer;                                        \
    int fresh=1, replicated=1, accept=1, local_req=0;                          \
    ulong min_leader=150UL, deadline=64UL;                                     \
    change;                                                                    \
    uchar why = 0U;                                                            \
    FD_TEST( fd_failover_handoff_check( &r, &l, &p, fresh, replicated, accept, \
                                        local_req, min_leader, deadline, &why )==FD_FAILOVER_HANDOFF_REJECTED ); \
    FD_TEST( why==(expected) );                                                \
  } while(0)

  CHECK_REJECT( r.deadline_slots=1U,                 FD_FAILOVER_REJECT_BAD_REQUEST       );
  CHECK_REJECT( r.baton_slot=1UL,                    FD_FAILOVER_REJECT_BAD_REQUEST       );
  CHECK_REJECT( r.attempt=1U,                        FD_FAILOVER_REJECT_BAD_REQUEST       );
  CHECK_REJECT( min_leader=64UL,                     FD_FAILOVER_REJECT_BAD_REQUEST       );
  CHECK_REJECT( r.reason=FD_FAILOVER_HANDOFF_REASON_OPERATOR,
                                                     FD_FAILOVER_REJECT_BAD_REQUEST       );
  CHECK_REJECT( r.drill=1U,                          FD_FAILOVER_REJECT_BAD_REQUEST       );
  CHECK_REJECT( l.term=ULONG_MAX-2UL; r.proposed_term=ULONG_MAX-1UL,
                                                     FD_FAILOVER_REJECT_TERM_EXHAUSTED    );
  CHECK_REJECT( accept=0,                            FD_FAILOVER_REJECT_REQUESTS_DISABLED );
  CHECK_REJECT( fresh=0,                             FD_FAILOVER_REJECT_STATUS_STALE      );
  CHECK_REJECT( p.term=6UL; fresh=0,                 FD_FAILOVER_REJECT_STATUS_STALE      );
  CHECK_REJECT( p.term=6UL,                          FD_FAILOVER_REJECT_STATE_MISMATCH    );
  CHECK_REJECT( p.status=FD_FAILOVER_STATUS_BUSY,    FD_FAILOVER_REJECT_BUSY              );
  CHECK_REJECT( l.status=FD_FAILOVER_STATUS_PAUSED,  FD_FAILOVER_REJECT_PAUSED            );
  CHECK_REJECT( l.status=FD_FAILOVER_STATUS_STUCK,   FD_FAILOVER_REJECT_LOCAL_UNHEALTHY   );
  CHECK_REJECT( p.status=FD_FAILOVER_STATUS_STUCK,   FD_FAILOVER_REJECT_PEER_UNHEALTHY    );
  CHECK_REJECT( l.status=FD_FAILOVER_STATUS_REPLAG,  FD_FAILOVER_REJECT_PEER_BEHIND       );
  CHECK_REJECT( p.status=FD_FAILOVER_STATUS_REPLAG,  FD_FAILOVER_REJECT_PEER_BEHIND       );
  CHECK_REJECT( p.flags=0U,                          FD_FAILOVER_REJECT_PEER_BEHIND       );
  CHECK_REJECT( replicated=0,                        FD_FAILOVER_REJECT_PEER_BEHIND       );
  CHECK_REJECT( l.flags|=FD_FAILOVER_FLAG_IS_LEADER, FD_FAILOVER_REJECT_LEADER_ACTIVE     );
  CHECK_REJECT( l.next_leader_slot=1149UL,           FD_FAILOVER_REJECT_LEADER_NEAR       );
  CHECK_REJECT( l.turbine_slot=1051UL,               FD_FAILOVER_REJECT_LEADER_NEAR       );
  CHECK_REJECT( p.role=FD_FAILOVER_ROLE_ACTIVE,      FD_FAILOVER_REJECT_STATE_MISMATCH    );
#undef CHECK_REJECT

  req.proposed_term = 7UL;
  FD_TEST( fd_failover_handoff_check( &req, &local, &peer, 1, 1, 1, 0, 150UL, 64UL, &reason )==FD_FAILOVER_HANDOFF_STALE_TERM );
  local.role = FD_FAILOVER_ROLE_STANDBY;
  FD_TEST( fd_failover_handoff_check( &req, &local, &peer, 1, 1, 1, 0, 150UL, 64UL, &reason )==FD_FAILOVER_HANDOFF_ALREADY_STANDBY );

#define CHECK_STANDBY_BAD(change) do {                                 \
    fd_failover_handoff_req_t r = req;                                 \
    change;                                                            \
    uchar why = 0U;                                                    \
    FD_TEST( fd_failover_handoff_check( &r, &local, &peer, 1, 1, 1, 0, \
                                        150UL, 64UL, &why )==FD_FAILOVER_HANDOFF_REJECTED ); \
    FD_TEST( why==FD_FAILOVER_REJECT_BAD_REQUEST );                    \
  } while(0)
  CHECK_STANDBY_BAD( r.proposed_term=0UL );
  CHECK_STANDBY_BAD( r.proposed_term=9UL );
  CHECK_STANDBY_BAD( r.baton_slot=1UL );
  CHECK_STANDBY_BAD( r.attempt=1U );
  CHECK_STANDBY_BAD( r.deadline_slots=1U );
  CHECK_STANDBY_BAD( r.drill=2U );
  CHECK_STANDBY_BAD( r.reason=FD_FAILOVER_HANDOFF_REASON_CNT );
#undef CHECK_STANDBY_BAD

  local.role        = FD_FAILOVER_ROLE_ACTIVE;
  req.proposed_term = 8UL;
  req.reason        = FD_FAILOVER_HANDOFF_REASON_OPERATOR;
  FD_TEST( fd_failover_handoff_check( &req, &local, &peer, 1, 1, 0, 1, 150UL, 64UL, &reason )==FD_FAILOVER_HANDOFF_PROCEED );

  req.reason = FD_FAILOVER_HANDOFF_REASON_STANDBY;
  FD_TEST( fd_failover_handoff_check( &req, &local, &peer, 1, 1, 1, 1, 150UL, 64UL, &reason )==FD_FAILOVER_HANDOFF_REJECTED );
  FD_TEST( reason==FD_FAILOVER_REJECT_BAD_REQUEST );

  req.reason = FD_FAILOVER_HANDOFF_REASON_DRILL;
  req.drill  = 1U;
  FD_TEST( fd_failover_handoff_check( &req, &local, &peer, 1, 1, 0, 0, 150UL, 64UL, &reason )==FD_FAILOVER_HANDOFF_PROCEED );

  fd_failover_handoff_resp_t resp = {
    .proposed_term  = req.proposed_term,
    .baton_slot     = req.baton_slot,
    .attempt        = req.attempt,
    .deadline_slots = req.deadline_slots,
    .code           = FD_FAILOVER_HANDOFF_PROCEED,
    .reason         = FD_FAILOVER_REJECT_NONE,
    .drill          = req.drill,
  };
  FD_TEST( fd_failover_handoff_resp_check( &resp, &req ) );

#define CHECK_BAD_RESP(change) do {                         \
    fd_failover_handoff_resp_t r = resp;                    \
    change;                                                 \
    FD_TEST( !fd_failover_handoff_resp_check( &r, &req ) ); \
  } while(0)
  CHECK_BAD_RESP( r.proposed_term++ );
  CHECK_BAD_RESP( r.baton_slot++ );
  CHECK_BAD_RESP( r.attempt++ );
  CHECK_BAD_RESP( r.deadline_slots++ );
  CHECK_BAD_RESP( r.drill=0U );
  CHECK_BAD_RESP( r.code=FD_FAILOVER_HANDOFF_CODE_CNT );
  CHECK_BAD_RESP( r.reason=FD_FAILOVER_REJECT_BAD_REQUEST );
  CHECK_BAD_RESP( r.code=FD_FAILOVER_HANDOFF_REJECTED );
  CHECK_BAD_RESP( r.code=FD_FAILOVER_HANDOFF_REJECTED; r.reason=FD_FAILOVER_REJECT_CNT );
#undef CHECK_BAD_RESP

  req.baton_slot = 1UL;
  resp.baton_slot = 1UL;
  FD_TEST( !fd_failover_handoff_resp_check( &resp, &req ) );
  req.baton_slot = 0UL;
  resp.baton_slot = 0UL;

  resp.code   = FD_FAILOVER_HANDOFF_REJECTED;
  resp.reason = FD_FAILOVER_REJECT_BUSY;
  FD_TEST( fd_failover_handoff_resp_check( &resp, &req ) );
  resp.code   = FD_FAILOVER_HANDOFF_ALREADY_STANDBY;
  resp.reason = FD_FAILOVER_REJECT_NONE;
  FD_TEST( fd_failover_handoff_resp_check( &resp, &req ) );
  resp.code = FD_FAILOVER_HANDOFF_STALE_TERM;
  FD_TEST( fd_failover_handoff_resp_check( &resp, &req ) );

  FD_LOG_NOTICE(( "pass: test_handoff_checks" ));
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_session_exhaustive();
  test_session_properties();
  test_hello_checks();
  test_state_boot();
  test_demoted_terms();
  test_handoff_checks();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
