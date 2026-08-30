#include "fd_failover_proto.h"
#include "../../util/fd_util.h"

#include <string.h>

static ulong expected[ 2 ][ FD_FAILOVER_SESSION_CNT ][ FD_FAILOVER_EV_CNT ];

static void
build_expected( void ) {
  for( int dial_peer=0; dial_peer<2; dial_peer++ ) {
    for( ulong s=0UL; s<FD_FAILOVER_SESSION_CNT; s++ ) {
      for( int e=0; e<FD_FAILOVER_EV_CNT; e++ ) expected[ dial_peer ][ s ][ e ] = s;
    }
    expected[ dial_peer ][ FD_FAILOVER_SESSION_LISTENING ][ FD_FAILOVER_EV_PEER_CONNECTED ] = FD_FAILOVER_SESSION_HELLO;
    expected[ dial_peer ][ FD_FAILOVER_SESSION_DIALING   ][ FD_FAILOVER_EV_CONNECTED      ] = FD_FAILOVER_SESSION_HELLO;
    expected[ dial_peer ][ FD_FAILOVER_SESSION_DIALING   ][ FD_FAILOVER_EV_TIMEOUT        ] = FD_FAILOVER_SESSION_BACKOFF;
    expected[ dial_peer ][ FD_FAILOVER_SESSION_DIALING   ][ FD_FAILOVER_EV_LINK_LOST      ] = FD_FAILOVER_SESSION_BACKOFF;
    expected[ dial_peer ][ FD_FAILOVER_SESSION_HELLO     ][ FD_FAILOVER_EV_HELLO_OK       ] = FD_FAILOVER_SESSION_PAIRED;
    expected[ dial_peer ][ FD_FAILOVER_SESSION_HELLO     ][ FD_FAILOVER_EV_HELLO_FATAL    ] = FD_FAILOVER_SESSION_REJECTED;
    expected[ dial_peer ][ FD_FAILOVER_SESSION_HELLO     ][ FD_FAILOVER_EV_TIMEOUT        ] = FD_FAILOVER_SESSION_BACKOFF;
    expected[ dial_peer ][ FD_FAILOVER_SESSION_HELLO     ][ FD_FAILOVER_EV_LINK_LOST      ] = FD_FAILOVER_SESSION_BACKOFF;
    expected[ dial_peer ][ FD_FAILOVER_SESSION_PAIRED    ][ FD_FAILOVER_EV_TIMEOUT        ] = FD_FAILOVER_SESSION_BACKOFF;
    expected[ dial_peer ][ FD_FAILOVER_SESSION_PAIRED    ][ FD_FAILOVER_EV_LINK_LOST      ] = FD_FAILOVER_SESSION_BACKOFF;
  }
  expected[ 0 ][ FD_FAILOVER_SESSION_BACKOFF ][ FD_FAILOVER_EV_RETRY ] = FD_FAILOVER_SESSION_LISTENING;
  expected[ 1 ][ FD_FAILOVER_SESSION_BACKOFF ][ FD_FAILOVER_EV_RETRY ] = FD_FAILOVER_SESSION_DIALING;
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
  /* REJECTED absorbs everything */
  for( int dial_peer=0; dial_peer<2; dial_peer++ ) {
    for( int e=0; e<FD_FAILOVER_EV_CNT; e++ ) {
      FD_TEST( fd_failover_session_step( FD_FAILOVER_SESSION_REJECTED, dial_peer, e )==FD_FAILOVER_SESSION_REJECTED );
    }
  }

  /* PAIRED is reachable only through HELLO_OK */
  for( int dial_peer=0; dial_peer<2; dial_peer++ ) {
    for( ulong s=0UL; s<FD_FAILOVER_SESSION_CNT; s++ ) {
      if( s==FD_FAILOVER_SESSION_PAIRED ) continue;
      for( int e=0; e<FD_FAILOVER_EV_CNT; e++ ) {
        if( s==FD_FAILOVER_SESSION_HELLO && e==FD_FAILOVER_EV_HELLO_OK ) continue;
        FD_TEST( fd_failover_session_step( s, dial_peer, e )!=FD_FAILOVER_SESSION_PAIRED );
      }
    }
  }

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
  memset( h, 0, sizeof(fd_failover_hello_t) );
  h->version = (ushort)FD_FAILOVER_VERSION;
  memset( h->junk_pubkey,   junk,   32UL );
  memset( h->staked_pubkey, staked, 32UL );
  memset( h->vote_account,  vote,   32UL );
  h->session_nonce[ 0 ] = (uchar)( junk ^ ( role ? 0x80U : 0x40U ) );
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
  memcpy( peer.session_nonce, self.session_nonce, sizeof(peer.session_nonce) );
  FD_TEST( fd_failover_hello_check( &self, &peer )==FD_FAILOVER_HELLO_ERR_NONCE );

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

  /* Both nodes may remain standby until an operator promotes one */
  fill_hello( &self, 0x01, 0xAA, 0xBB, (uchar)FD_FAILOVER_ROLE_STANDBY );
  fill_hello( &peer, 0x02, 0xAA, 0xBB, (uchar)FD_FAILOVER_ROLE_STANDBY );
  FD_TEST( fd_failover_hello_check( &self, &peer )==FD_FAILOVER_HELLO_OK );

  FD_LOG_NOTICE(( "pass: test_hello_checks" ));
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_session_exhaustive();
  test_session_properties();
  test_hello_checks();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
