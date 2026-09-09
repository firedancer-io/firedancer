#include "fd_failover_channel.h"
#include "../../util/fd_util.h"
#include "../../util/net/fd_ip4.h"

#include <string.h>
#include <sys/resource.h>

static uchar const secret[ 32 ] = { 0x5e, 0xc2, 0xe7 };

static uchar scratch_a[ 1<<18 ] __attribute__((aligned(128)));
static uchar scratch_b[ 1<<18 ] __attribute__((aligned(128)));
static uchar scratch_c[ 1<<18 ] __attribute__((aligned(128)));

static uchar payload_buf[ FD_FAILOVER_PAYLOAD_MAX ];

static fd_failover_hello_t
make_hello( uchar junk,
            uchar staked,
            uchar role ) {
  fd_failover_hello_t h;
  memset( &h, 0, sizeof(h) );
  h.version = (ushort)FD_FAILOVER_VERSION;
  memset( h.junk_pubkey,   junk,   32UL );
  memset( h.staked_pubkey, staked, 32UL );
  memset( h.vote_account,  0xBB,   32UL );
  h.role = role;
  return h;
}

/* pump polls both ends until pred( a, b ) holds or the deadline passes. */
#define PUMP_UNTIL( a, b, pred ) do {                                        \
    long deadline = fd_log_wallclock() + (long)5e9;                          \
    for(;;) {                                                                \
      long now = fd_log_wallclock();                                         \
      FD_TEST( now<deadline );                                               \
      int           busy = 0;                                                \
      ushort        type;                                                    \
      ulong         psz;                                                     \
      fd_failover_channel_poll( (a), now, &busy, &type, payload_buf, &psz ); \
      fd_failover_channel_poll( (b), now, &busy, &type, payload_buf, &psz ); \
      if( pred ) break;                                                      \
      if( !busy ) fd_log_sleep( (long)1e6 );                                 \
    }                                                                        \
  } while(0)

#define PAIRED( ch ) ( fd_failover_channel_state( ch )==FD_FAILOVER_SESSION_PAIRED )

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_failover_channel_t * a = fd_failover_channel_join( fd_failover_channel_new( scratch_a ) );
  fd_failover_channel_t * b = fd_failover_channel_join( fd_failover_channel_new( scratch_b ) );
  fd_failover_channel_t * c = fd_failover_channel_join( fd_failover_channel_new( scratch_c ) );
  FD_TEST( a ); FD_TEST( b ); FD_TEST( c );
  FD_TEST( fd_failover_channel_footprint()<=sizeof(scratch_a) );
  FD_TEST( !fd_failover_channel_new( NULL ) );
  FD_TEST( !fd_failover_channel_new( scratch_c+1UL ) );
  FD_TEST( !fd_failover_channel_join( NULL ) );
  FD_TEST( !fd_failover_channel_join( scratch_c+1UL ) );

  /* Resource exhaustion leaves the dialer in reconnect backoff. */
  struct rlimit old_limit;
  FD_TEST( !getrlimit( RLIMIT_NOFILE, &old_limit ) );
  struct rlimit zero_limit = old_limit;
  zero_limit.rlim_cur = 0UL;
  FD_TEST( !setrlimit( RLIMIT_NOFILE, &zero_limit ) );
  fd_failover_channel_init_dialer( c, FD_IP4_ADDR( 127, 0, 0, 1 ), 1U );
  {
    int    busy = 0;
    ushort type;
    ulong  psz;
    fd_failover_channel_poll( c, fd_log_wallclock(), &busy, &type, payload_buf, &psz );
    FD_TEST( busy );
    FD_TEST( fd_failover_channel_state( c )==FD_FAILOVER_SESSION_BACKOFF );
  }
  FD_TEST( !setrlimit( RLIMIT_NOFILE, &old_limit ) );
  FD_LOG_NOTICE(( "pass: socket resource exhaustion" ));

  fd_failover_hello_t hello_a = make_hello( 0x01, 0xAA, (uchar)FD_FAILOVER_ROLE_STANDBY );
  fd_failover_hello_t hello_b = make_hello( 0x02, 0xAA, (uchar)FD_FAILOVER_ROLE_ACTIVE  );

  fd_failover_channel_init_listener( a, FD_IP4_ADDR( 127, 0, 0, 1 ), 0 );
  fd_failover_channel_set_identity( a, secret, &hello_a );

  ushort port = fd_failover_channel_listen_port( a );
  FD_TEST( port );

  fd_failover_channel_init_dialer( b, FD_IP4_ADDR( 127, 0, 0, 1 ), port );
  fd_failover_channel_set_identity( b, secret, &hello_b );

  /* Descriptor exhaustion does not take down the listener. */
  {
    long deadline = fd_log_wallclock() + (long)5e9;
    while( fd_failover_channel_state( b )!=FD_FAILOVER_SESSION_HELLO ) {
      long now = fd_log_wallclock();
      FD_TEST( now<deadline );
      int    busy = 0;
      ushort type;
      ulong  psz;
      fd_failover_channel_poll( b, now, &busy, &type, payload_buf, &psz );
      if( !busy ) fd_log_sleep( (long)1e6 );
    }
  }
  FD_TEST( !setrlimit( RLIMIT_NOFILE, &zero_limit ) );
  {
    int    busy = 0;
    ushort type;
    ulong  psz;
    fd_failover_channel_poll( a, fd_log_wallclock(), &busy, &type, payload_buf, &psz );
    FD_TEST( fd_failover_channel_state( a )==FD_FAILOVER_SESSION_LISTENING );
  }
  FD_TEST( !setrlimit( RLIMIT_NOFILE, &old_limit ) );

  /* The pair connects and completes HELLO in both directions. */
  PUMP_UNTIL( a, b, PAIRED( a ) && PAIRED( b ) );
  FD_TEST( fd_failover_channel_peer_hello( a )->role==(uchar)FD_FAILOVER_ROLE_ACTIVE  );
  FD_TEST( fd_failover_channel_peer_hello( b )->role==(uchar)FD_FAILOVER_ROLE_STANDBY );
  FD_LOG_NOTICE(( "pass: pairing" ));

  /* Messages cross in both directions and arrive intact. */
  fd_failover_status_t status;
  memset( &status, 0, sizeof(status) );
  status.role           = (uchar)FD_FAILOVER_ROLE_ACTIVE;
  status.replay_slot    = 12345UL;
  status.last_vote_slot = FD_FAILOVER_SLOT_NULL;
  status.ack_seq        = fd_failover_channel_ack_seq( b );
  FD_TEST( !fd_failover_channel_send( b, fd_log_wallclock(), (ushort)FD_FAILOVER_MSG_STATUS,
                                      (uchar const *)&status, sizeof(status) ) );

  {
    long deadline = fd_log_wallclock() + (long)5e9;
    int  got      = 0;
    while( !got ) {
      long now = fd_log_wallclock();
      FD_TEST( now<deadline );
      int    busy = 0;
      ushort type;
      ulong  psz;
      if( fd_failover_channel_poll( a, now, &busy, &type, payload_buf, &psz ) ) {
        FD_TEST( type==(ushort)FD_FAILOVER_MSG_STATUS );
        FD_TEST( psz==sizeof(fd_failover_status_t) );
        fd_failover_status_t rx;
        memcpy( &rx, payload_buf, sizeof(rx) );
        FD_TEST( rx.replay_slot==12345UL );
        FD_TEST( rx.last_vote_slot==FD_FAILOVER_SLOT_NULL );
        got = 1;
      }
      if( !busy && !got ) fd_log_sleep( (long)1e6 );
    }
  }
  FD_LOG_NOTICE(( "pass: status delivery" ));

  /* A paired session with no authenticated traffic is dropped. */
  fd_failover_channel_set_timing( a, FD_FAILOVER_CHANNEL_HELLO_TIMEOUT_NANOS, 1L,
                                  FD_FAILOVER_CHANNEL_BACKOFF_MIN_NANOS,
                                  FD_FAILOVER_CHANNEL_BACKOFF_MAX_NANOS );
  {
    int    busy = 0;
    ushort type;
    ulong  psz;
    fd_failover_channel_poll( a, fd_log_wallclock()+2L, &busy, &type, payload_buf, &psz );
  }
  FD_TEST( fd_failover_channel_state( a )==FD_FAILOVER_SESSION_LISTENING );
  fd_failover_channel_set_timing( a, FD_FAILOVER_CHANNEL_HELLO_TIMEOUT_NANOS,
                                  5L*FD_FAILOVER_CHANNEL_HELLO_TIMEOUT_NANOS,
                                  FD_FAILOVER_CHANNEL_BACKOFF_MIN_NANOS,
                                  FD_FAILOVER_CHANNEL_BACKOFF_MAX_NANOS );
  PUMP_UNTIL( a, b, PAIRED( a ) && PAIRED( b ) );
  FD_LOG_NOTICE(( "pass: silence timeout" ));

  /* A hangup on one side is seen by the other and the pair heals on its own. */
  fd_failover_channel_hangup( b, fd_log_wallclock() );
  PUMP_UNTIL( a, b, PAIRED( a ) && PAIRED( b ) );
  FD_TEST( fd_failover_channel_metrics( a )->connect_cnt==3UL );
  FD_TEST( fd_failover_channel_metrics( b )->connect_cnt==3UL );
  FD_LOG_NOTICE(( "pass: reconnect" ));

  /* Buffered frames remain ordered and intact even when the peer
     closes before the receiver drains the socket. */
  status.replay_slot = 111UL;
  FD_TEST( !fd_failover_channel_send( b, fd_log_wallclock(), (ushort)FD_FAILOVER_MSG_STATUS,
                                      (uchar const *)&status, sizeof(status) ) );
  while( fd_failover_channel_tx_pending( b ) ) {
    int    busy = 0;
    ushort type;
    ulong  psz;
    fd_failover_channel_poll( b, fd_log_wallclock(), &busy, &type, payload_buf, &psz );
  }
  status.replay_slot = 222UL;
  FD_TEST( !fd_failover_channel_send( b, fd_log_wallclock(), (ushort)FD_FAILOVER_MSG_STATUS,
                                      (uchar const *)&status, sizeof(status) ) );
  while( fd_failover_channel_tx_pending( b ) ) {
    int    busy = 0;
    ushort type;
    ulong  psz;
    fd_failover_channel_poll( b, fd_log_wallclock(), &busy, &type, payload_buf, &psz );
  }
  fd_failover_channel_hangup( b, fd_log_wallclock() );

  for( ulong expected=111UL; expected<=222UL; expected+=111UL ) {
    long deadline = fd_log_wallclock() + (long)5e9;
    for(;;) {
      long now = fd_log_wallclock();
      FD_TEST( now<deadline );
      int    busy = 0;
      ushort type;
      ulong  psz;
      if( fd_failover_channel_poll( a, now, &busy, &type, payload_buf, &psz ) ) {
        fd_failover_status_t rx;
        FD_TEST( type==(ushort)FD_FAILOVER_MSG_STATUS );
        FD_TEST( psz==sizeof(rx) );
        memcpy( &rx, payload_buf, sizeof(rx) );
        FD_TEST( rx.replay_slot==expected );
        break;
      }
      FD_TEST( fd_failover_channel_state( a )==FD_FAILOVER_SESSION_PAIRED );
      if( !busy ) fd_log_sleep( (long)1e6 );
    }
  }
  PUMP_UNTIL( a, b, PAIRED( a ) && PAIRED( b ) );
  FD_LOG_NOTICE(( "pass: buffered frames before EOF" ));

  /* Logical roles can change without changing transport direction. */
  hello_a.role = (uchar)FD_FAILOVER_ROLE_ACTIVE;
  hello_a.term = 1UL;
  hello_b.role = (uchar)FD_FAILOVER_ROLE_STANDBY;
  hello_b.term = 1UL;
  fd_failover_channel_set_identity( a, secret, &hello_a );
  fd_failover_channel_set_identity( b, secret, &hello_b );
  fd_failover_channel_hangup( b, fd_log_wallclock() );
  PUMP_UNTIL( a, b, PAIRED( a ) && PAIRED( b ) );
  FD_TEST( fd_failover_channel_peer_hello( a )->role==(uchar)FD_FAILOVER_ROLE_STANDBY );
  FD_TEST( fd_failover_channel_peer_hello( b )->role==(uchar)FD_FAILOVER_ROLE_ACTIVE  );

  hello_a.role = (uchar)FD_FAILOVER_ROLE_STANDBY;
  hello_a.term = 2UL;
  hello_b.role = (uchar)FD_FAILOVER_ROLE_ACTIVE;
  hello_b.term = 2UL;
  fd_failover_channel_set_identity( a, secret, &hello_a );
  fd_failover_channel_set_identity( b, secret, &hello_b );
  fd_failover_channel_hangup( b, fd_log_wallclock() );
  PUMP_UNTIL( a, b, PAIRED( a ) && PAIRED( b ) );
  FD_LOG_NOTICE(( "pass: logical role changes" ));

  /* A local encoding failure drops and reconnects the session. */
  FD_TEST( fd_failover_channel_send( a, fd_log_wallclock(),
                                     (ushort)FD_FAILOVER_MSG_STATUS,
                                     payload_buf, FD_FAILOVER_PAYLOAD_MAX+1UL )==-1 );
  FD_TEST( fd_failover_channel_state( a )==FD_FAILOVER_SESSION_LISTENING );
  PUMP_UNTIL( a, b, PAIRED( a ) && PAIRED( b ) );
  FD_LOG_NOTICE(( "pass: encoding failure reconnects" ));

  /* A dialer holding the wrong secret cannot pair. */
  fd_failover_channel_hangup( a, fd_log_wallclock() );
  fd_failover_channel_hangup( b, fd_log_wallclock() );

  c = fd_failover_channel_join( fd_failover_channel_new( scratch_c ) );
  uchar const other_secret[ 32 ] = { 0x99 };
  fd_failover_hello_t hello_c = make_hello( 0x03, 0xAA, (uchar)FD_FAILOVER_ROLE_ACTIVE );
  fd_failover_channel_init_dialer( c, FD_IP4_ADDR( 127, 0, 0, 1 ), port );
  fd_failover_channel_set_identity( c, other_secret, &hello_c );

  PUMP_UNTIL( a, c, fd_failover_channel_metrics( a )->mac_fail_cnt>0UL );
  FD_TEST( fd_failover_channel_state( a )==FD_FAILOVER_SESSION_LISTENING );
  FD_TEST( fd_failover_channel_state( c )!=FD_FAILOVER_SESSION_REJECTED );
  FD_LOG_NOTICE(( "pass: wrong secret" ));

  /* A misconfigured pair with a different staked identity is rejected. */
  fd_failover_hello_t hello_d = make_hello( 0x04, 0xCC, (uchar)FD_FAILOVER_ROLE_ACTIVE );
  fd_failover_channel_init_dialer( b, FD_IP4_ADDR( 127, 0, 0, 1 ), port );
  fd_failover_channel_set_identity( b, secret, &hello_d );

  PUMP_UNTIL( a, b, fd_failover_channel_state( a )==FD_FAILOVER_SESSION_REJECTED &&
                    fd_failover_channel_state( b )==FD_FAILOVER_SESSION_REJECTED );
  FD_TEST( fd_failover_channel_metrics( a )->hello_reject_cnt==1UL );
  FD_LOG_NOTICE(( "pass: fatal hello parks the channel" ));

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
