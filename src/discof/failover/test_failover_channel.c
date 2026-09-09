#include "fd_failover_channel.c"
#include "../../ballet/ed25519/fd_ed25519.h"
#include "../../util/net/fd_ip4.h"
#include <sys/resource.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <fcntl.h>

static uchar scratch_a[ 8UL<<20 ] __attribute__((aligned(128)));
static uchar scratch_b[ 8UL<<20 ] __attribute__((aligned(128)));
static uchar scratch_c[ 8UL<<20 ] __attribute__((aligned(128)));
static uchar payload_buf[ FD_FAILOVER_PAYLOAD_MAX ];
static uchar key_a[ 64 ] = { 1 };
static uchar key_b[ 64 ] = { 2 };
static uchar key_c[ 64 ] = { 3 };
static long now;

static fd_failover_hello_t
hello( uchar const * key, uchar role ) {
  fd_failover_hello_t h = { .version=FD_FAILOVER_VERSION, .role=role };
  memcpy( h.junk_pubkey, key+32, 32UL );
  memset( h.staked_pubkey, 0xAA, 32UL );
  memset( h.vote_account, 0xBB, 32UL );
  return h;
}

static int
poll_channel( fd_failover_channel_t * ch ) {
  int busy = 0;
  ushort type;
  ulong sz;
  return fd_failover_channel_poll( ch, now, &busy, &type, payload_buf, &sz );
}

static int
paired( fd_failover_channel_t * ch ) { return ch->state==FD_FAILOVER_SESSION_PAIRED; }

static void
pump( fd_failover_channel_t * a, fd_failover_channel_t * b ) {
  for( ulong i=0; i<10000UL; i++ ) {
    poll_channel( a );
    poll_channel( b );
    if( paired( a ) && paired( b ) ) return;
    now += 100000L;
    fd_log_sleep( 100000L );
  }
  FD_LOG_ERR(( "pairing timed out: states %lu %lu, TLS failures %lu %lu", a->state, b->state,
               a->metrics.tls_fail_cnt, b->metrics.tls_fail_cnt ));
}

static int
raw_connect( ushort port, uint address ) {
  int fd = socket( AF_INET, SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC, 0 );
  FD_TEST( fd>=0 );
  struct sockaddr_in local = { .sin_family=AF_INET, .sin_addr.s_addr=address };
  FD_TEST( !bind( fd, fd_type_pun( &local ), sizeof(local) ) );
  struct sockaddr_in remote = { .sin_family=AF_INET, .sin_port=fd_ushort_bswap( port ),
                               .sin_addr.s_addr=FD_IP4_ADDR(127,0,0,1) };
  FD_TEST( !connect( fd, fd_type_pun( &remote ), sizeof(remote) ) || errno==EINPROGRESS );
  return fd;
}

static void
transfer( fd_failover_channel_t * a, fd_failover_channel_t * b, ulong sz ) {
  static uchar data[ FD_FAILOVER_PAYLOAD_MAX ];
  for( ulong i=0; i<sz; i++ ) data[i] = (uchar)i;
  FD_TEST( !fd_failover_channel_send( b, now, FD_FAILOVER_MSG_STATUS, data, sz ) );
  for( ulong i=0; i<10000UL; i++ ) {
    int busy = 0;
    ushort type;
    ulong got;
    poll_channel( b );
    if( fd_failover_channel_poll( a, now, &busy, &type, payload_buf, &got ) ) {
      FD_TEST( type==FD_FAILOVER_MSG_STATUS && got==sz && !memcmp( data, payload_buf, sz ) );
      return;
    }
    now += 100000L;
    fd_log_sleep( 100000L );
  }
  FD_LOG_ERR(( "transfer timed out" ));
}

static void
test_admission_buckets( void ) {
  fd_failover_channel_t * ch = fd_failover_channel_join( fd_failover_channel_new( scratch_c ) );
  long tick = 1000000000L;
  for( uint i=0U; i<16U; i++ ) FD_TEST( admit( ch, i+1U, tick ) );
  FD_TEST( !admit( ch, 17U, tick ) );
  FD_TEST( !admit( ch, 17U, tick+31249999L ) );
  FD_TEST(  admit( ch, 17U, tick+31250000L ) );
  FD_TEST( !admit( ch, 18U, tick+31250000L ) );
  FD_TEST( !admit( ch, 18U, tick-1L ) );
  /* A long idle interval fills only the burst, without overflow. */
  tick = LONG_MAX-1000000000L;
  for( uint i=0U; i<16U; i++ ) FD_TEST( admit( ch, i+1U, tick ) );
  FD_TEST( !admit( ch, 17U, tick ) );

  ch = fd_failover_channel_join( fd_failover_channel_new( scratch_c ) );
  tick = 1000000000L;
  /* A full source table cannot evict an unrefilled bucket to reset its
     rate limit.  Reuse is allowed only once that bucket is full. */
  for( ulong i=0UL; i<SOURCE_CNT; i++ ) {
    ch->sources[i] = (struct source){ .used=1, .address=(uint)i+1U, .updated=tick, .credit=0UL };
  }
  FD_TEST( !admit( ch, 1000U, tick ) );
  FD_TEST( !admit( ch, 1000U, tick+499999999L ) );
  FD_TEST(  admit( ch, 1000U, tick+500000000L ) );
  FD_TEST(  admit( ch, 1000U, tick+500000000L ) );
  FD_TEST( !admit( ch, 1000U, tick+500000000L ) );
  FD_TEST( !admit( ch, 1000U, tick+749999999L ) );
  FD_TEST(  admit( ch, 1000U, tick+750000000L ) );
  FD_LOG_NOTICE(( "pass: global token refill, burst cap, backwards clock and source table reuse" ));
}

static void
test_tls_profile( fd_failover_channel_t * a, fd_failover_channel_t * b, ushort port ) {
  /* A legacy ClientHello: TLS 1.2 record and handshake versions, one
     cipher suite, and no extensions, so no supported_versions.  fd_tls
     speaks TLS 1.3 only and answers it with protocol_version. */
  static uchar const legacy_hello[] = {
    0x16, 0x03, 0x01, 0x00, 0x2f,             /* handshake record, 47 bytes    */
    0x01, 0x00, 0x00, 0x2b,                   /* ClientHello, 43 bytes         */
    0x03, 0x03,                               /* legacy_version TLS 1.2        */
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,         /* random                        */
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    0x00,                                     /* legacy_session_id             */
    0x00, 0x02, 0x13, 0x01,                   /* TLS_AES_128_GCM_SHA256        */
    0x01, 0x00,                               /* legacy_compression_methods    */
    0x00, 0x00,                               /* extensions                    */
  };
  static fd_failover_tls_t tls;
  for( uint variant=0U; variant<4U; variant++ ) {
    fd_failover_channel_hangup( a, now );
    fd_failover_channel_hangup( b, now );
    now += 2000000001L;
    int fd = raw_connect( port, FD_IP4_ADDR(127,0,0,2) );
    FD_TEST( !fd_failover_tls_new( &tls, &b->tls_ctx, fd, 1 ) );
    int failed = 0;
    /* The connection's copied fd_tls template is the rogue client's
       profile, it is read when the first handshake call emits the
       ClientHello. */
    switch( variant ) {
      case 0U: {
        /* fd_tls has no downgrade knob, so send the legacy hello by hand. */
        for(;;) {
          long n = send( fd, legacy_hello, sizeof(legacy_hello), MSG_NOSIGNAL );
          if( n==(long)sizeof(legacy_hello) ) break;
          FD_TEST( n<0L && (errno==EAGAIN || errno==ENOTCONN || errno==EINPROGRESS) );
          fd_log_sleep( 100000L );
        }
        failed = 1;
        break;
      }
      case 1U: memcpy( tls.conn.tls.alpn, "\x05other", 6UL ); tls.conn.tls.alpn_sz = 6UL; break;
      case 2U: tls.conn.tls.alpn_sz = 0UL; break;
      case 3U: tls.conn.tls.cert_x509_sz = 0UL; break;
    }
    ulong failures = a->metrics.tls_fail_cnt;
    ulong pairings = a->metrics.paired_cnt;
    for( ulong i=0UL; i<10000UL && a->metrics.tls_fail_cnt==failures; i++ ) {
      if( !failed ) {
        fd_failover_tls_budget( &tls );
        failed = fd_failover_tls_handshake( &tls )<0;
      }
      poll_channel( a );
      FD_TEST( !paired( a ) );
      now += 100000L;
      fd_log_sleep( 100000L );
    }
    FD_TEST( a->metrics.tls_fail_cnt==failures+1UL && a->metrics.paired_cnt==pairings );
    FD_TEST( !fd_failover_channel_pending( a ) && a->state==FD_FAILOVER_SESSION_LISTENING );
    FD_TEST( !memcmp( &a->peer_hello, &(fd_failover_hello_t){0}, sizeof(a->peer_hello) ) );
    fd_failover_tls_fini( &tls );
    FD_TEST( !close( fd ) );
    now += 2000000001L;
    pump( a, b );
    FD_TEST( a->metrics.paired_cnt==pairings+1UL );
    transfer( a, b, 70UL );
  }
  FD_LOG_NOTICE(( "pass: TLS 1.2, wrong or missing ALPN, and missing client certificate are rejected" ));
}

static void
test_disconnects( fd_failover_channel_t * a, fd_failover_channel_t * b, ushort port ) {
  for( int rst=0; rst<2; rst++ ) {
    fd_failover_channel_hangup( a, now );
    fd_failover_channel_hangup( b, now );
    now += 2000000001L;
    int fd = raw_connect( port, FD_IP4_ADDR(127,0,0,2) );
    poll_channel( a );
    FD_TEST( fd_failover_channel_pending( a )==1UL );
    struct linger linger = { .l_onoff=1, .l_linger=0 };
    if( rst ) FD_TEST( !setsockopt( fd, SOL_SOCKET, SO_LINGER, &linger, sizeof(linger) ) );
    ulong failures = a->metrics.tls_fail_cnt;
    FD_TEST( !close( fd ) );
    for( ulong i=0UL; i<10000UL && fd_failover_channel_pending( a ); i++ ) {
      poll_channel( a );
      now += 100000L;
      fd_log_sleep( 100000L );
    }
    FD_TEST( !fd_failover_channel_pending( a ) && a->metrics.tls_fail_cnt==failures+1UL );
    now += 2000000001L;
    pump( a, b );
    transfer( a, b, 70UL );
    fd = b->candidates[b->active].fd;
    if( rst ) FD_TEST( !setsockopt( fd, SOL_SOCKET, SO_LINGER, &linger, sizeof(linger) ) );
    failures = a->metrics.tls_fail_cnt;
    ulong pairings = a->metrics.paired_cnt;
    fd_failover_channel_hangup( b, now );
    for( ulong i=0UL; i<10000UL && paired( a ); i++ ) {
      poll_channel( a );
      now += 100000L;
      fd_log_sleep( 100000L );
    }
    FD_TEST( a->state==FD_FAILOVER_SESSION_LISTENING );
    FD_TEST( a->metrics.tls_fail_cnt==failures && a->metrics.paired_cnt==pairings );
    FD_TEST( !memcmp( &a->peer_hello, &(fd_failover_hello_t){0}, sizeof(a->peer_hello) ) );
    now += 2000000001L;
    pump( a, b );
    FD_TEST( a->metrics.paired_cnt==pairings+1UL );
    transfer( b, a, FD_FAILOVER_PAYLOAD_MAX );
  }
  FD_LOG_NOTICE(( "pass: handshake and paired TCP EOF/reset permit clean reconnect" ));
}

static void
test_short_session_backoff( fd_failover_channel_t * a, fd_failover_channel_t * b ) {
  /* A session lost inside the handshake window is a failed
     establishment, so the dialer backs off.  One that outlived the
     window redials at once. */
  fd_failover_channel_hangup( a, now );
  fd_failover_channel_hangup( b, now );
  now += 2000000001L;
  pump( a, b );
  /* Consecutive short sessions keep doubling the backoff up to its cap. */
  long backoff = b->backoff;
  for( int i=0; i<4; i++ ) {
    fd_failover_channel_hangup( b, now );
    FD_TEST( b->state==FD_FAILOVER_SESSION_BACKOFF && b->retry_at==now+backoff );
    backoff = fd_long_min( 2L*backoff, b->backoff_max );
    FD_TEST( b->backoff==backoff );
    now += 2000000001L;
    pump( a, b );
  }
  FD_TEST( backoff==b->backoff_max );
  now += 2000000001L; /* outlive the handshake window while paired */
  poll_channel( a ); poll_channel( b );
  FD_TEST( paired( a ) && paired( b ) );
  fd_failover_channel_hangup( b, now );
  FD_TEST( b->state==FD_FAILOVER_SESSION_BACKOFF && b->retry_at==now && b->backoff==b->backoff_min );
  now += 2000000001L;
  pump( a, b );
  FD_LOG_NOTICE(( "pass: a session lost inside the handshake window backs off, an established one redials at once" ));
}

static void
test_fd_exhaustion( fd_failover_channel_t * a, fd_failover_channel_t * b, ushort port ) {
  fd_failover_channel_hangup( a, now );
  fd_failover_channel_hangup( b, now );
  now += 2000000001L;
  pid_t pid = fork();
  FD_TEST( pid>=0 );
  if( !pid ) {
    /* The junk private keys live on protected pages that are wiped on
       fork, so the child reinstalls both identities before pairing. */
    FD_TEST( !fd_failover_channel_set_identity( a, key_a, key_b+32, &a->self_hello ) );
    FD_TEST( !fd_failover_channel_set_identity( b, key_b, key_a+32, &b->self_hello ) );
    int slow = raw_connect( port, FD_IP4_ADDR(127,0,0,2) );
    struct rlimit limit = { .rlim_cur=32UL, .rlim_max=32UL };
    FD_TEST( !setrlimit( RLIMIT_NOFILE, &limit ) );
    int held[32];
    ulong cnt = 0UL;
    for(;;) {
      int fd = open( "/dev/null", O_RDONLY|O_CLOEXEC );
      if( fd<0 ) { FD_TEST( errno==EMFILE ); break; }
      FD_TEST( cnt<32UL );
      held[cnt++] = fd;
    }
    FD_TEST( cnt );
    ulong starts = a->metrics.connection_attempt_cnt;
    poll_channel( a );
    FD_TEST( a->state==FD_FAILOVER_SESSION_LISTENING && !fd_failover_channel_pending( a ) );
    FD_TEST( a->metrics.connection_attempt_cnt==starts );
    poll_channel( b );
    FD_TEST( b->state==FD_FAILOVER_SESSION_BACKOFF && !fd_failover_channel_pending( b ) );
    FD_TEST( b->retry_at>now );
    for( ulong i=0UL; i<cnt; i++ ) FD_TEST( !close( held[i] ) );
    poll_channel( a );
    FD_TEST( fd_failover_channel_pending( a )==1UL );
    FD_TEST( !close( slow ) );
    now += 2000000001L;
    pump( a, b );
    transfer( a, b, FD_FAILOVER_PAYLOAD_MAX );
    fd_failover_channel_fini( a );
    fd_failover_channel_fini( b );
    _exit( 0 );
  }
  int status;
  FD_TEST( waitpid( pid, &status, 0 )==pid );
  FD_TEST( WIFEXITED( status ) && !WEXITSTATUS( status ) );
  FD_LOG_NOTICE(( "pass: accept and dial descriptor exhaustion recover after descriptors are released" ));
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );
  test_admission_buckets();
  FD_TEST( fd_failover_channel_footprint()<=sizeof(scratch_a) );
  FD_TEST( !fd_failover_channel_new( NULL ) );
  FD_TEST( !fd_failover_channel_new( scratch_a+1 ) );
  FD_TEST( !fd_failover_channel_join( NULL ) );
  FD_TEST( !fd_failover_channel_join( scratch_a+1 ) );
  fd_sha512_t sha[1];
  fd_sha512_join( fd_sha512_new( sha ) );
  fd_ed25519_public_from_private( key_a+32, key_a, sha );
  fd_ed25519_public_from_private( key_b+32, key_b, sha );
  fd_ed25519_public_from_private( key_c+32, key_c, sha );
  fd_failover_channel_t * a = fd_failover_channel_join( fd_failover_channel_new( scratch_a ) );
  fd_failover_channel_t * b = fd_failover_channel_join( fd_failover_channel_new( scratch_b ) );
  fd_failover_channel_t * c = fd_failover_channel_join( fd_failover_channel_new( scratch_c ) );
  fd_failover_hello_t ha = hello( key_a, FD_FAILOVER_ROLE_STANDBY );
  fd_failover_hello_t hb = hello( key_b, FD_FAILOVER_ROLE_ACTIVE );
  fd_failover_hello_t hc = hello( key_c, FD_FAILOVER_ROLE_ACTIVE );
  FD_TEST( !fd_failover_channel_set_identity( a, key_a, key_b+32, &ha ) );
  FD_TEST( !fd_failover_channel_set_identity( b, key_b, key_a+32, &hb ) );
  FD_TEST( !fd_failover_channel_set_identity( c, key_c, key_a+32, &hc ) );
  fd_failover_channel_init_listener( a, FD_IP4_ADDR(127,0,0,1), 0 );
  ushort port = fd_failover_channel_listen_port( a );
  fd_failover_channel_init_dialer( b, FD_IP4_ADDR(127,0,0,1), port );
  fd_failover_channel_init_dialer( c, FD_IP4_ADDR(127,0,0,1), port );
  now = fd_log_wallclock();
  fd_failover_channel_set_timing( b, 2000000000L, 10000000000L, 1000000L, 10000000L );
  fd_failover_channel_set_timing( c, 2000000000L, 10000000000L, 1000000L, 10000000L );

  /* The wrong pinned identity cannot change the listener or peer state. */
  for( ulong i=0; i<100UL; i++ ) { poll_channel( c ); poll_channel( a ); now += 1000000L; }
  FD_TEST( a->metrics.tls_fail_cnt>0UL && !paired( a ) && !paired( c ) );
  FD_TEST( !memcmp( &a->peer_hello, &(fd_failover_hello_t){0}, sizeof(ha) ) );
  fd_failover_channel_hangup( c, now );
  now += 2000000001L;
  poll_channel( a );
  FD_LOG_NOTICE(( "pass: wrong peer pin" ));

  /* A slow client cannot occupy the only handshake slot. */
  int slow = raw_connect( port, FD_IP4_ADDR(127,0,0,2) );
  poll_channel( a );
  FD_TEST( fd_failover_channel_pending( a )==1UL );
  pump( a, b );
  FD_TEST( !fd_failover_channel_pending( a ) );
  FD_TEST( a->metrics.paired_cnt==1UL && b->metrics.paired_cnt==1UL );
  close( slow );
  transfer( a, b, sizeof(fd_failover_status_t) );
  transfer( b, a, FD_FAILOVER_PAYLOAD_MAX );
  FD_LOG_NOTICE(( "pass: concurrent slow handshake, mutual TLS and bounded large-frame I/O" ));

  /* An established connection is not displaced, even by a pinned peer. */
  ulong starts = a->metrics.connection_attempt_cnt;
  ulong admissions = a->metrics.admission_drop_cnt;
  for( ulong i=0; i<128UL; i++ ) {
    int attacker = raw_connect( port, FD_IP4_ADDR(127,0,0,2) );
    poll_channel( a );
    close( attacker );
    FD_TEST( paired( a ) && paired( b ) && !fd_failover_channel_pending( a ) );
  }
  FD_TEST( a->metrics.connection_attempt_cnt==starts );
  FD_TEST( a->metrics.admission_drop_cnt==admissions+128UL );
  FD_TEST( a->metrics.paired_cnt==1UL && b->metrics.paired_cnt==1UL );
  transfer( a, b, 70UL );
  FD_LOG_NOTICE(( "pass: established session survives connection flood" ));

  fd_failover_channel_hangup( a, now );
  fd_failover_channel_hangup( b, now );
  now += 2000000001L;
  int fds[20];
  for( uint i=0; i<20U; i++ ) fds[i] = raw_connect( port, FD_IP4_ADDR(127,0,0,i+2U) );
  poll_channel( a );
  FD_TEST( fd_failover_channel_pending( a )==8UL );
  poll_channel( a );
  FD_TEST( fd_failover_channel_pending( a )==16UL );
  poll_channel( a );
  FD_TEST( fd_failover_channel_pending( a )==16UL );
  now += 1999999999L;
  ulong timeouts = a->metrics.handshake_timeout_cnt;
  poll_channel( a );
  FD_TEST( fd_failover_channel_pending( a )==16UL );
  now++;
  poll_channel( a );
  FD_TEST( !fd_failover_channel_pending( a ) );
  FD_TEST( a->metrics.handshake_timeout_cnt==timeouts+16UL );
  for( uint i=0; i<20U; i++ ) close( fds[i] );
  FD_LOG_NOTICE(( "pass: accept bound, pool bound and absolute deadline" ));

  for( uint i=0; i<3U; i++ ) fds[i] = raw_connect( port, FD_IP4_ADDR(127,0,0,2) );
  poll_channel( a );
  FD_TEST( fd_failover_channel_pending( a )==2UL );
  for( uint i=0; i<3U; i++ ) close( fds[i] );
  fd_failover_channel_hangup( a, now );
  /* Releasing slots does not refill per-source tokens. */
  fds[0] = raw_connect( port, FD_IP4_ADDR(127,0,0,2) );
  poll_channel( a );
  FD_TEST( !fd_failover_channel_pending( a ) );
  close( fds[0] );
  now += 250000000L;
  fds[0] = raw_connect( port, FD_IP4_ADDR(127,0,0,2) );
  poll_channel( a );
  FD_TEST( fd_failover_channel_pending( a )==1UL );
  close( fds[0] );
  fd_failover_channel_hangup( a, now );
  FD_LOG_NOTICE(( "pass: per-source capacity and refill" ));

  /* Authenticated stale HELLO rejects only this candidate. */
  now += 2000000001L;
  b->self_hello.cfg_hash = 1UL;
  ulong rejects = a->metrics.hello_reject_cnt;
  for( ulong i=0; i<1000UL && a->metrics.hello_reject_cnt==rejects; i++ ) {
    poll_channel( a ); poll_channel( b ); now += 1000000L;
  }
  FD_TEST( a->metrics.hello_reject_cnt>rejects && a->state==FD_FAILOVER_SESSION_LISTENING );
  b->self_hello.cfg_hash = 0UL;
  fd_failover_channel_hangup( b, now );
  now += 2000000001L;
  pump( a, b );
  transfer( a, b, 0UL );
  FD_LOG_NOTICE(( "pass: rejected HELLO permits reconnect" ));

  test_tls_profile( a, b, port );
  test_disconnects( a, b, port );
  test_short_session_backoff( a, b );
  test_fd_exhaustion( a, b, port );

  fd_failover_channel_fini( a );
  fd_failover_channel_fini( b );
  fd_failover_channel_fini( c );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
