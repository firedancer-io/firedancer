#include "fd_failover_channel.c"
#include "../../ballet/ed25519/fd_ed25519.h"
#include "../../disco/keyguard/fd_keyguard.h"
#include "../../util/net/fd_ip4.h"
#include "../../util/sandbox/fd_sandbox_private.h"
#include "generated/fd_failover_tile_seccomp.h"
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
static uchar key_s[ 64 ] = { 9 }; /* the staked key */
static fd_sha512_t sha[ 1 ];
static long now;

static fd_failover_hello_t
hello( uchar const * key,
       uchar         role ) {
  fd_failover_hello_t h = { .version=FD_FAILOVER_VERSION, .role=role, .mode=FD_FAILOVER_MODE_TOWER, .boot_id=0x1000UL+key[0] };
  fd_memcpy( h.junk_pubkey, key+32, 32UL );
  fd_memcpy( h.staked_pubkey, key_s+32, 32UL );
  fd_memset( h.vote_account, 0xBB, 32UL );
  return h;
}

/* The member certificate for junk key, signed by signer. */
static void
member_cert( uchar *       cert,
             uchar const * key,
             uchar const * signer ) {
  uchar msg[ FD_KEYGUARD_MEMBER_CERT_MSG_SZ ];
  fd_failover_member_cert_msg( msg, key+32 );
  fd_ed25519_sign( cert, msg, sizeof(msg), signer+32, signer, sha );
}

/* Sets up a member with junk key and a certificate by the staked key. */
static void
identity( fd_failover_channel_t * ch,
          uchar const *           key,
          uchar                   role ) {
  fd_failover_hello_t h = hello( key, role );
  FD_TEST( !fd_failover_channel_set_identity( ch, key, &h ) );
  uchar cert[ 64 ];
  member_cert( cert, key, key_s );
  FD_TEST( !fd_failover_channel_set_member_cert( ch, cert ) );
}

/* A dialer that retries fast and tolerates the test's clock jumps. */
static void
fast_dialer( fd_failover_channel_t * ch ) {
  ch->silence_timeout = 2L*FD_FAILOVER_CHANNEL_IDLE_NANOS;
  ch->backoff_min     = 1000000L;
  ch->backoff_max     = 10000000L;
  ch->backoff         = ch->backoff_min;
}

static int
poll_channel( fd_failover_channel_t * ch ) {
  int busy = 0;
  ushort type;
  ulong sz;
  return fd_failover_channel_poll( ch, now, &busy, &type, payload_buf, &sz );
}

static int
paired( fd_failover_channel_t * ch ) {
  return ch->state==FD_FAILOVER_SESSION_PAIRED;
}

static void
test_seccomp( void ) {
  /* One child per role, each under its own production filter.  The
     active's listener is opened before the fork so both know the port,
     and the standby opens its own, every member listens.  progress[0]
     counts frames the listener took, progress[1] frames the dialer saw
     acknowledged. */
  volatile int * progress = mmap( NULL, 4096UL, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0 );
  FD_TEST( progress!=MAP_FAILED );
  progress[0] = 0; progress[1] = 0;
  fd_failover_channel_t * a = fd_failover_channel_join( fd_failover_channel_new( scratch_a ) );
  identity( a, key_a, FD_FAILOVER_ROLE_ACTIVE );
  fd_failover_channel_init_listener( a, FD_IP4_ADDR(127,0,0,1), 0 );
  ushort port      = fd_failover_channel_listen_port( a );
  int    listen_fd = fd_failover_channel_listen_fd( a );
  pid_t pids[ 2 ];
  for( int dial=0; dial<2; dial++ ) {
    pids[ dial ] = fork();
    FD_TEST( pids[ dial ]>=0 );
    if( pids[ dial ] ) continue;
    fd_failover_channel_t * ch = a;
    if( dial ) {
      FD_TEST( !close( listen_fd ) );
      ch = fd_failover_channel_join( fd_failover_channel_new( scratch_b ) );
      identity( ch, key_b, FD_FAILOVER_ROLE_STANDBY );
      fd_failover_channel_init_listener( ch, FD_IP4_ADDR(127,0,0,1), 0 );
      fd_failover_channel_init_dialer( ch, FD_IP4_ADDR(127,0,0,1), port );
      fast_dialer( ch );
    } else {
      /* The junk private key lives on a page wiped on fork. */
      identity( ch, key_a, FD_FAILOVER_ROLE_ACTIVE );
    }
    struct rlimit limit = { .rlim_cur=32UL, .rlim_max=32UL };
    FD_TEST( !setrlimit( RLIMIT_NOFILE, &limit ) );
    struct sock_filter filter[ 128 ];
    populate_sock_filter_policy_fd_failover_tile( 128UL, filter, (uint)fd_log_private_logfile_fd(), (uint)fd_failover_channel_listen_fd( ch ) );
    ushort instr_cnt = (ushort)sock_filter_policy_fd_failover_tile_instr_cnt;
    FD_TEST( !prctl( PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0 ) );
    fd_sandbox_private_set_seccomp_filter( instr_cnt, filter );
    for( int round=0; round<3; round++ ) {
      long deadline = fd_log_wallclock()+5000000000L;
      while( !paired( ch ) ) {
        now = fd_log_wallclock();
        if( now>=deadline ) __builtin_trap();
        poll_channel( ch );
      }
      if( dial ) {
        if( fd_failover_channel_send( ch, now, FD_FAILOVER_MSG_STATUS, (uchar const *)"test", 4UL ) ) __builtin_trap();
        while( progress[ 0 ]<=round ) {
          now = fd_log_wallclock();
          if( now>=deadline ) __builtin_trap();
          poll_channel( ch );
        }
        progress[ 1 ] = round+1;
      } else {
        while( !poll_channel( ch ) ) {
          now = fd_log_wallclock();
          if( now>=deadline ) __builtin_trap();
        }
        progress[ 0 ] = round+1;
        while( progress[ 1 ]<=round ) {
          now = fd_log_wallclock();
          if( now>=deadline ) __builtin_trap();
          poll_channel( ch );
        }
      }
      fd_failover_channel_hangup( ch, now );
    }
    /* A forbidden syscall must kill each child.  The listener may not
       close its own socket, the dialer may not accept4 on another
       descriptor. */
    if( dial ) (void)syscall( SYS_accept4, 0, NULL, NULL, 0 );
    else       (void)close( listen_fd );
    __builtin_trap();
  }
  for( int dial=0; dial<2; dial++ ) {
    int status;
    FD_TEST( waitpid( pids[ dial ], &status, 0 )==pids[ dial ] );
    if( !WIFSIGNALED( status ) || WTERMSIG( status )!=SIGSYS )
      FD_LOG_ERR(( "seccomp child %i status %i, progress %i %i", dial, status, progress[ 0 ], progress[ 1 ] ));
  }
  FD_TEST( progress[ 0 ]==3 && progress[ 1 ]==3 );
  fd_failover_channel_fini( a );
  FD_TEST( !munmap( (void *)progress, 4096UL ) );
  FD_LOG_NOTICE(( "pass: TLS pairing, transfer and reconnect under the failover tile seccomp filter" ));
}

static void
pump( fd_failover_channel_t * a,
      fd_failover_channel_t * b ) {
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
raw_connect( ushort port,
             uint   address ) {
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
transfer( fd_failover_channel_t * a,
          fd_failover_channel_t * b,
          ulong                   sz ) {
  static uchar data[ FD_FAILOVER_PAYLOAD_MAX ];
  for( ulong i=0; i<sz; i++ ) data[i] = (uchar)i;
  FD_TEST( !fd_failover_channel_send( b, now, FD_FAILOVER_MSG_STATUS, data, sz ) );
  for( ulong i=0; i<10000UL; i++ ) {
    int busy = 0;
    ushort type;
    ulong got;
    poll_channel( b );
    if( fd_failover_channel_poll( a, now, &busy, &type, payload_buf, &got ) ) {
      FD_TEST( type==FD_FAILOVER_MSG_STATUS && got==sz && fd_memeq( data, payload_buf, sz ) );
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

  /* The expected peer is admitted with the global bucket empty, others
     are not. */
  ch = fd_failover_channel_join( fd_failover_channel_new( scratch_c ) );
  fd_failover_channel_expect_peer( ch, 7U );
  ch->rate_credit  = 0UL;
  ch->rate_updated = tick;
  FD_TEST( !admit( ch, 8U, tick ) );
  FD_TEST(  admit( ch, 7U, tick ) );

  /* A burst cannot become a burst of diagnostics.  Real categories
     have independent limits, and suppressed counts survive until the
     next permitted line, including at the exact timer boundary. */
  ulong suppressed = ULONG_MAX;
  FD_TEST( fd_failover_log_take( &ch->dial_log[0], tick, &suppressed ) && !suppressed );
  for( ulong i=0; i<100000UL; i++ ) FD_TEST( !fd_failover_log_take( &ch->dial_log[0], tick+(long)i, &suppressed ) );
  FD_TEST( !fd_failover_log_take( &ch->dial_log[0], tick-1L, &suppressed ) );
  FD_TEST( !fd_failover_log_take( &ch->dial_log[0], tick+59999999999L, &suppressed ) );
  FD_TEST( fd_failover_log_take( &ch->dial_log[0], tick+60000000000L, &suppressed ) && suppressed==100002UL );
  FD_TEST( ch->dial_log[0].count==100004UL && !ch->dial_log[0].suppressed );
  FD_TEST( fd_failover_log_take( &ch->hello_log[FD_FAILOVER_HELLO_ERR_BOTH_ACT], tick, &suppressed ) && !suppressed );
  FD_TEST( fd_failover_log_take( &ch->hello_log[FD_FAILOVER_HELLO_ERR_CERT], tick, &suppressed ) && !suppressed );
  FD_TEST( tls_log_kind( FD_TLS_REASON_ALPN_NEG )!=tls_log_kind( FD_TLS_REASON_ED25519_FAIL ) );
  FD_TEST( tls_log_kind( 0U )!=tls_log_kind( FD_TLS_REASON_ALPN_NEG ) );
  /* Saturating counts and a monotonic clock near its upper bound never
     wrap the quota back into a fresh first occurrence. */
  fd_failover_log_t limit = { .at=LONG_MAX-5L, .count=ULONG_MAX, .suppressed=ULONG_MAX };
  FD_TEST( !fd_failover_log_take( &limit, LONG_MAX, &suppressed ) );
  FD_TEST( limit.count==ULONG_MAX && limit.suppressed==ULONG_MAX );
  FD_LOG_NOTICE(( "pass: global token refill, burst cap, backwards clock and source table reuse" ));
}

static void
test_tls_profile( fd_failover_channel_t * a,
                  fd_failover_channel_t * b,
                  ushort                  port ) {
  /* A legacy ClientHello with TLS 1.2 record and handshake versions,
     one cipher suite and no extensions, so no supported_versions.
     fd_tls speaks TLS 1.3 only and answers it with protocol_version. */
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
      case 1U: fd_memcpy( tls.conn.tls.alpn, "\x05other", 6UL ); tls.conn.tls.alpn_sz = 6UL; break;
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
    FD_TEST( fd_memeq( &a->peer_hello, &(fd_failover_hello_t){0}, sizeof(a->peer_hello) ) );
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
test_disconnects( fd_failover_channel_t * a,
                  fd_failover_channel_t * b,
                  ushort                  port ) {
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
    FD_TEST( fd_memeq( &a->peer_hello, &(fd_failover_hello_t){0}, sizeof(a->peer_hello) ) );
    now += 2000000001L;
    pump( a, b );
    FD_TEST( a->metrics.paired_cnt==pairings+1UL );
    transfer( b, a, FD_FAILOVER_PAYLOAD_MAX );
  }
  FD_LOG_NOTICE(( "pass: handshake and paired TCP EOF/reset permit clean reconnect" ));
}

static void
test_short_session_backoff( fd_failover_channel_t * a,
                            fd_failover_channel_t * b ) {
  /* A session lost inside the handshake window is a failed
     establishment, so the dialer backs off.  One that outlived the
     window redials at once. */
  fd_failover_channel_hangup( a, now );
  fd_failover_channel_hangup( b, now );
  now += 2000000001L;
  pump( a, b );
  /* Consecutive short sessions keep doubling the backoff up to its cap.
     Start from the minimum so the doubling is observable. */
  b->backoff = b->backoff_min;
  long backoff = b->backoff;
  for( int i=0; i<4; i++ ) {
    fd_failover_channel_hangup( b, now );
    FD_TEST( b->state==FD_FAILOVER_SESSION_BACKOFF && b->retry_at>=now+backoff && b->retry_at<now+backoff+b->backoff_min );
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
  FD_TEST( b->state==FD_FAILOVER_SESSION_BACKOFF && b->retry_at>=now && b->retry_at<now+b->backoff_min );
  FD_TEST( b->backoff==b->backoff_min );
  now += 2000000001L;
  pump( a, b );
  FD_LOG_NOTICE(( "pass: a session lost inside the handshake window backs off, an established one redials at once" ));
}

/* test_silence: traffic every half silence window keeps the pair up.
   A peer that goes quiet, or stops reading while we have a frame to
   send, is dropped once the window passes. */
static void
test_silence( fd_failover_channel_t * a,
              fd_failover_channel_t * b ) {
  fd_failover_channel_hangup( a, now );
  fd_failover_channel_hangup( b, now );
  now += 2000000001L;
  pump( a, b );
  long silence = a->silence_timeout;
  FD_TEST( silence<b->silence_timeout );
  for( int i=0; i<6; i++ ) {
    now += silence/2L;
    transfer( a, b, 70UL );
    transfer( b, a, 70UL );
    FD_TEST( paired( a ) && paired( b ) );
  }

  /* b stops polling, so a hears nothing. */
  now = a->last_rx+silence;
  poll_channel( a );
  FD_TEST( paired( a ) );
  now++;
  poll_channel( a );
  FD_TEST( a->state==FD_FAILOVER_SESSION_LISTENING );
  fd_failover_channel_hangup( b, now );
  now += 2000000001L;
  pump( a, b );

  /* b stops reading, so our frames back up until the socket is full. */
  static uchar       data[ FD_FAILOVER_PAYLOAD_MAX ];
  struct candidate * c = &a->candidates[ a->active ];
  for( ulong i=0UL; i<100000UL && !fd_tlsrec_sock_tx_pending( &c->tls.sock ); i++ ) {
    if( !fd_failover_channel_tx_pending( a ) ) FD_TEST( !fd_failover_channel_send( a, now, FD_FAILOVER_MSG_STATUS, data, sizeof(data) ) );
    poll_channel( a );
  }
  FD_TEST( fd_tlsrec_sock_tx_pending( &c->tls.sock ) );
  now += silence+1L;
  poll_channel( a );
  FD_TEST( a->state==FD_FAILOVER_SESSION_LISTENING );
  fd_failover_channel_hangup( b, now );
  now += 2000000001L;
  pump( a, b );
  FD_LOG_NOTICE(( "pass: traffic keeps a pair up, a silent or stalled peer is dropped" ));
}

/* A frame can be fully encrypted while its ciphertext is still queued.
   Completion must wait for that ciphertext, including the last RESULT. */
static void
test_ciphertext_drain( fd_failover_channel_t * a,
                       fd_failover_channel_t * b ) {
  struct candidate * c = &a->candidates[ a->active ];
  int sndbuf = 4096;
  FD_TEST( !setsockopt( c->fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf) ) );
  uchar payload[1024];
  ulong sent = 0UL;
  for( ulong i=0UL; i<100000UL; i++ ) {
    if( !fd_failover_channel_tx_pending( a ) ) {
      fd_memset( payload, (int)(sent & 255UL), sizeof(payload) );
      fd_memcpy( payload, &sent, sizeof(sent) );
      FD_TEST( !fd_failover_channel_send( a, now, FD_FAILOVER_MSG_HANDOFF_RESULT, payload, sizeof(payload) ) );
      sent++;
    }
    poll_channel( a );
    if( !c->tx_used && fd_tlsrec_sock_tx_pending( &c->tls.sock ) ) break;
  }
  FD_TEST( sent && !c->tx_used && fd_tlsrec_sock_tx_pending( &c->tls.sock ) );
  FD_TEST( fd_failover_channel_tx_pending( a ) );
  ulong received = 0UL;
  long until = fd_log_wallclock()+5000000000L;
  while( received<sent || fd_failover_channel_tx_pending( a ) ) {
    FD_TEST( fd_log_wallclock()<until );
    int busy = 0;
    ushort type;
    ulong sz;
    if( fd_failover_channel_poll( b, now, &busy, &type, payload_buf, &sz ) ) {
      ulong seq;
      fd_memcpy( &seq, payload_buf, sizeof(seq) );
      FD_TEST( type==FD_FAILOVER_MSG_HANDOFF_RESULT && sz==sizeof(payload) && seq==received );
      for( ulong j=sizeof(seq); j<sz; j++ ) FD_TEST( payload_buf[j]==(uchar)received );
      received++;
    }
    poll_channel( a );
    fd_log_sleep( 10000L );
  }
  FD_TEST( received==sent && !fd_tlsrec_sock_tx_pending( &c->tls.sock ) );
  FD_LOG_NOTICE(( "pass: ciphertext remains pending after plaintext drains and reaches a slow reader in order" ));
}

/* A network outage must not hide a later protocol rejection in the
   same minute.  Repeated failures of the same kind still coalesce. */
static void
test_loss_log_causes( fd_failover_channel_t * a,
                      fd_failover_channel_t * b ) {
  fd_memset( a->loss_log, 0, sizeof(a->loss_log) );
  pump( a, b );
  a->expected_close = 0;
  fd_failover_channel_hangup( b, now );
  for( ulong i=0; i<10000UL && paired( a ); i++ ) {
    poll_channel( a ); now+=100000L; fd_log_sleep( 100000L );
  }
  FD_TEST( !paired( a ) && a->loss_log[LOSS_TRANSPORT].count==1UL );
  for( ulong i=1UL; i<=2UL; i++ ) {
    fd_failover_channel_hangup( b, now );
    now += 2000000001L;
    pump( a, b );
    fd_failover_channel_protocol_error( a, now );
    FD_TEST( a->loss_log[LOSS_PROTOCOL].count==i );
    FD_TEST( a->loss_log[LOSS_PROTOCOL].suppressed==i-1UL );
    FD_TEST( a->loss_log[LOSS_TRANSPORT].count==1UL );
  }
  fd_failover_channel_hangup( b, now );
  now += 2000000001L;
  pump( a, b );
  FD_LOG_NOTICE(( "pass: transport loss cannot suppress a new protocol cause, repeated protocol failures coalesce" ));
}

/* An orderly peer close after a drained RESULT is routine for on-demand connections.
   A damaged TLS record at the same point remains a protocol failure. */
static void
test_result_close( fd_failover_channel_t * a,
                   fd_failover_channel_t * b ) {
  for( int corrupt=0; corrupt<2; corrupt++ ) {
    pump( a, b );
    fd_failover_handoff_result_t result = { .handoff_id=17UL, .result=0UL };
    FD_TEST( !fd_failover_channel_tx_pending( a ) );
    FD_TEST( !fd_failover_channel_send( a, now, FD_FAILOVER_MSG_HANDOFF_RESULT, (uchar const *)&result, sizeof(result) ) );
    int received = 0;
    for( ulong i=0; i<10000UL && !received; i++ ) {
      poll_channel( a );
      int busy=0; ushort type; ulong sz;
      if( fd_failover_channel_poll( b, now, &busy, &type, payload_buf, &sz ) ) {
        FD_TEST( type==FD_FAILOVER_MSG_HANDOFF_RESULT && sz==sizeof(result) );
        FD_TEST( fd_memeq( payload_buf, &result, sizeof(result) ) );
        received = 1;
      }
      now += 100000L;
      fd_log_sleep( 100000L );
    }
    FD_TEST( received && !fd_failover_channel_tx_pending( a ) );
    ulong warnings = a->loss_log[corrupt ? LOSS_TLS : LOSS_TRANSPORT].count;
    if( corrupt ) {
      /* A complete application-data record with an invalid AEAD tag. */
      uchar bad[22] = {23,3,3,0,17};
      FD_TEST( send( b->candidates[b->active].fd, bad, sizeof(bad), MSG_NOSIGNAL )==(long)sizeof(bad) );
    } else fd_failover_channel_hangup( b, now );
    for( ulong i=0; i<10000UL && paired( a ); i++ ) {
      poll_channel( a ); now+=100000L; fd_log_sleep( 100000L );
    }
    FD_TEST( !paired( a ) );
    FD_TEST( a->loss_log[corrupt ? LOSS_TLS : LOSS_TRANSPORT].count==warnings+(ulong)(corrupt || !FD_FAILOVER_ON_DEMAND) );
    fd_failover_channel_hangup( b, now );
    now += 2000000001L;
  }
  pump( a, b );
  FD_LOG_NOTICE(( "pass: normal RESULT close is quiet only on demand, corrupted TLS after RESULT remains visible" ));
}

static void
test_fd_exhaustion( fd_failover_channel_t * a,
                    fd_failover_channel_t * b,
                    ushort                  port ) {
  fd_failover_channel_hangup( a, now );
  fd_failover_channel_hangup( b, now );
  now += 2000000001L;
  pid_t pid = fork();
  FD_TEST( pid>=0 );
  if( !pid ) {
    /* The junk private keys live on protected pages that are wiped on
       fork, so the child reinstalls both identities before pairing. */
    identity( a, key_a, FD_FAILOVER_ROLE_ACTIVE  );
    identity( b, key_b, FD_FAILOVER_ROLE_STANDBY );
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

/* A listener that never accepts, so a dial to it connects and then
   waits for the handshake. */
static int
dead_port( ushort * port ) {
  int fd = socket( AF_INET, SOCK_STREAM|SOCK_CLOEXEC, 0 );
  FD_TEST( fd>=0 );
  struct sockaddr_in addr = { .sin_family=AF_INET, .sin_addr.s_addr=FD_IP4_ADDR(127,0,0,1) };
  FD_TEST( !bind( fd, fd_type_pun( &addr ), sizeof(addr) ) && !listen( fd, 8 ) );
  socklen_t len = sizeof(addr);
  FD_TEST( !getsockname( fd, fd_type_pun( &addr ), &len ) );
  *port = fd_ushort_bswap( addr.sin_port );
  return fd;
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  fd_sha512_join( fd_sha512_new( sha ) );
  fd_ed25519_public_from_private( key_a+32, key_a, sha );
  fd_ed25519_public_from_private( key_b+32, key_b, sha );
  fd_ed25519_public_from_private( key_c+32, key_c, sha );
  fd_ed25519_public_from_private( key_s+32, key_s, sha );
  test_admission_buckets();
  test_seccomp();
  FD_TEST( fd_failover_channel_footprint()<=sizeof(scratch_a) );
  FD_TEST( !fd_failover_channel_new( NULL ) );
  FD_TEST( !fd_failover_channel_new( scratch_a+1 ) );
  FD_TEST( !fd_failover_channel_join( NULL ) );
  FD_TEST( !fd_failover_channel_join( scratch_a+1 ) );
  fd_failover_channel_t * a = fd_failover_channel_join( fd_failover_channel_new( scratch_a ) );
  fd_failover_channel_t * b = fd_failover_channel_join( fd_failover_channel_new( scratch_b ) );
  fd_failover_channel_t * c = fd_failover_channel_join( fd_failover_channel_new( scratch_c ) );
  fd_failover_hello_t ha = hello( key_a, FD_FAILOVER_ROLE_ACTIVE  );
  fd_failover_hello_t hb = hello( key_b, FD_FAILOVER_ROLE_STANDBY );
  fd_failover_hello_t hc = hello( key_c, FD_FAILOVER_ROLE_STANDBY );
  FD_TEST( !fd_failover_channel_set_identity( a, key_a, &ha ) );
  FD_TEST( !fd_failover_channel_set_identity( b, key_b, &hb ) );
  FD_TEST( !fd_failover_channel_set_identity( c, key_c, &hc ) );
  fd_failover_channel_init_listener( a, FD_IP4_ADDR(127,0,0,1), 0 );
  fd_failover_channel_init_listener( b, FD_IP4_ADDR(127,0,0,1), 0 );
  fd_failover_channel_init_listener( c, FD_IP4_ADDR(127,0,0,1), 0 );
  ushort port   = fd_failover_channel_listen_port( a );
  ushort port_b = fd_failover_channel_listen_port( b );
  fd_failover_channel_init_dialer( b, FD_IP4_ADDR(127,0,0,1), port );
  now = fd_log_wallclock();
  fast_dialer( b );
  fast_dialer( c );

  /* The TLS keypair has to be the junk key in HELLO and not the staked
     key, and the certificate has to be the staked key's signature over
     our junk key. */
  fd_failover_hello_t hs = hello( key_s, FD_FAILOVER_ROLE_STANDBY );
  FD_TEST( fd_failover_channel_set_identity( c, key_a, &hc ) );
  FD_TEST( fd_failover_channel_set_identity( c, key_s, &hs ) );
  FD_TEST( !fd_failover_channel_set_identity( c, key_c, &hc ) );
  uchar cert[ 64 ];
  member_cert( cert, key_c, key_c );
  FD_TEST( fd_failover_channel_set_member_cert( c, cert ) && !c->member_cert_set );
  member_cert( cert, key_b, key_s );
  FD_TEST( fd_failover_channel_set_member_cert( c, cert ) && !c->member_cert_set );
  FD_LOG_NOTICE(( "pass: identity and member certificate checks" ));

  /* Without a member certificate we neither accept nor dial. */
  int early = raw_connect( port, FD_IP4_ADDR(127,0,0,2) );
  for( ulong i=0; i<100UL; i++ ) { poll_channel( a ); poll_channel( b ); now += 1000000L; }
  FD_TEST( !a->metrics.connection_attempt_cnt && !b->metrics.connection_attempt_cnt );
  FD_TEST( !paired( a ) && !paired( b ) && !fd_failover_channel_pending( a ) && !fd_failover_channel_pending( b ) );
  FD_TEST( b->state==FD_FAILOVER_SESSION_BACKOFF );
  member_cert( cert, key_a, key_s );
  FD_TEST( !fd_failover_channel_set_member_cert( a, cert ) );
  member_cert( cert, key_b, key_s );
  FD_TEST( !fd_failover_channel_set_member_cert( b, cert ) );
  FD_TEST( fd_memeq( b->self_hello.member_cert, cert, 64UL ) );
  poll_channel( a );
  FD_TEST( a->metrics.connection_attempt_cnt==1UL && fd_failover_channel_pending( a )==1UL );
  close( early );
  FD_LOG_NOTICE(( "pass: nothing starts before the member certificate" ));

  /* A standby that does not know the active's address yet never dials. */
  fd_failover_channel_hangup( b, now );
  fd_failover_channel_init_dialer( b, 0U, port );
  FD_TEST( b->state==FD_FAILOVER_SESSION_LISTENING && !b->dial_peer );
  ulong starts = b->metrics.connection_attempt_cnt;
  for( ulong i=0; i<100UL; i++ ) { poll_channel( b ); now += 1000000L; }
  FD_TEST( b->state==FD_FAILOVER_SESSION_LISTENING && !fd_failover_channel_pending( b ) );
  FD_TEST( b->metrics.connection_attempt_cnt==starts );
  fd_failover_channel_init_dialer( b, FD_IP4_ADDR(127,0,0,1), port );
  FD_TEST( b->state==FD_FAILOVER_SESSION_BACKOFF && b->dial_peer && !b->retry_at );
  FD_LOG_NOTICE(( "pass: no dial before the active's address is known" ));

  /* A member without the staked key cannot pair.  Its certificate is
     signed by another key, or it copies b's junk key and certificate
     into HELLO while TLS runs on its own key.  It never gets our HELLO
     either. */
  fd_failover_channel_init_dialer( c, FD_IP4_ADDR(127,0,0,1), port );
  for( int variant=0; variant<2; variant++ ) {
    if( variant ) {
      fd_memcpy( c->self_hello.junk_pubkey, key_b+32, 32UL );
      member_cert( c->self_hello.member_cert, key_b, key_s );
    } else {
      member_cert( c->self_hello.member_cert, key_c, key_c );
    }
    c->member_cert_set = 1;
    ulong rejects  = a->metrics.hello_reject_cnt;
    ulong received = c->metrics.frames_received;
    for( ulong i=0; i<1000UL && a->metrics.hello_reject_cnt==rejects; i++ ) { poll_channel( c ); poll_channel( a ); now += 1000000L; fd_log_sleep( 100000L ); }
    FD_TEST( a->metrics.hello_reject_cnt>rejects && !paired( a ) );
    FD_TEST( fd_memeq( &a->peer_hello, &(fd_failover_hello_t){0}, sizeof(ha) ) );
    for( ulong i=0; i<100UL; i++ ) { poll_channel( c ); fd_log_sleep( 100000L ); }
    FD_TEST( c->metrics.frames_received==received && !paired( c ) );
    fd_failover_channel_hangup( c, now );
  }
  fd_failover_channel_init_dialer( c, 0U, 0 );
  identity( c, key_c, FD_FAILOVER_ROLE_STANDBY );
  now += 2000000001L;
  poll_channel( a );
  FD_LOG_NOTICE(( "pass: a bad member certificate or a HELLO key other than the TLS key" ));

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

  /* An established connection is not displaced by a connection flood. */
  starts = a->metrics.connection_attempt_cnt;
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

  /* Role changes and a new dial address keep a paired session. */
  fd_failover_channel_set_role( a, FD_FAILOVER_ROLE_STANDBY );
  fd_failover_channel_set_role( b, FD_FAILOVER_ROLE_ACTIVE  );
  fd_failover_channel_init_dialer( b, FD_IP4_ADDR(127,0,0,3), port );
  poll_channel( a ); poll_channel( b );
  FD_TEST( paired( a ) && paired( b ) );
  transfer( a, b, 70UL );
  fd_failover_channel_set_role( a, FD_FAILOVER_ROLE_ACTIVE  );
  fd_failover_channel_set_role( b, FD_FAILOVER_ROLE_STANDBY );
  fd_failover_channel_init_dialer( b, FD_IP4_ADDR(127,0,0,1), port );
  poll_channel( a ); poll_channel( b );
  FD_TEST( paired( a ) && paired( b ) );
  transfer( b, a, 70UL );
  FD_TEST( a->metrics.paired_cnt==1UL && b->metrics.paired_cnt==1UL );
  FD_LOG_NOTICE(( "pass: a paired session survives role changes and a new dial address" ));

  /* Only an armed operation dials.  Ending it disables retries even
     after the requester has become active. */
  fd_failover_channel_set_role( b, FD_FAILOVER_ROLE_ACTIVE );
  fd_failover_channel_init_dialer( b, 0U, 0 );
  fd_failover_channel_hangup( a, now );
  fd_failover_channel_hangup( b, now );
  FD_TEST( b->state==FD_FAILOVER_SESSION_LISTENING && !b->dial_peer );
  now += 2000000001L;
  starts = b->metrics.connection_attempt_cnt;
  for( ulong i=0; i<100UL; i++ ) { poll_channel( a ); poll_channel( b ); now += 1000000L; }
  FD_TEST( b->metrics.connection_attempt_cnt==starts && !paired( a ) && !paired( b ) );
  fd_failover_channel_set_role( b, FD_FAILOVER_ROLE_STANDBY );
  fd_failover_channel_init_dialer( b, FD_IP4_ADDR(127,0,0,1), port );
  FD_TEST( b->state==FD_FAILOVER_SESSION_BACKOFF && b->dial_peer && !b->retry_at );
  pump( a, b );
  FD_TEST( a->peer_hello.role==FD_FAILOVER_ROLE_STANDBY && b->peer_hello.role==FD_FAILOVER_ROLE_ACTIVE );
  transfer( a, b, 70UL );
  FD_LOG_NOTICE(( "pass: only an unpaired standby dials" ));

  /* A new address drops the dial in flight and dials the new one at
     once. */
  ushort dead;
  int dead_fd = dead_port( &dead );
  fd_failover_channel_hangup( a, now );
  fd_failover_channel_hangup( b, now );
  now += 2000000001L;
  fd_failover_channel_init_dialer( b, FD_IP4_ADDR(127,0,0,1), dead );
  starts = b->metrics.connection_attempt_cnt;
  poll_channel( b );
  FD_TEST( b->metrics.connection_attempt_cnt==starts+1UL && fd_failover_channel_pending( b )==1UL );
  fd_failover_channel_init_dialer( b, FD_IP4_ADDR(127,0,0,1), port );
  FD_TEST( b->state==FD_FAILOVER_SESSION_BACKOFF && !fd_failover_channel_pending( b ) && !b->retry_at );
  pump( a, b );
  transfer( a, b, 70UL );
  FD_LOG_NOTICE(( "pass: a new dial address redials" ));

  /* Every member listens.  A session that comes in while we dial pairs
     as the listener and closes our dial, and once it ends we dial
     again. */
  fd_failover_channel_hangup( a, now );
  fd_failover_channel_hangup( b, now );
  now += 2000000001L;
  fd_failover_channel_init_dialer( b, FD_IP4_ADDR(127,0,0,1), dead );
  poll_channel( b );
  FD_TEST( b->dial_peer && fd_failover_channel_pending( b )==1UL );
  /* A client that connects to us and goes away leaves our dial alone. */
  for( ulong i=0UL; i<10000UL && b->state!=FD_FAILOVER_SESSION_HELLO; i++ ) { poll_channel( b ); fd_log_sleep( 100000L ); }
  FD_TEST( b->state==FD_FAILOVER_SESSION_HELLO );
  ulong dial_state    = b->state;
  long  dial_backoff  = b->backoff;
  long  dial_retry_at = b->retry_at;
  int   quitter       = raw_connect( port_b, FD_IP4_ADDR(127,0,0,2) );
  for( ulong i=0UL; i<10000UL && fd_failover_channel_pending( b )<2UL; i++ ) { poll_channel( b ); fd_log_sleep( 100000L ); }
  FD_TEST( fd_failover_channel_pending( b )==2UL );
  close( quitter );
  for( ulong i=0UL; i<10000UL && fd_failover_channel_pending( b )>1UL; i++ ) { poll_channel( b ); fd_log_sleep( 100000L ); }
  FD_TEST( fd_failover_channel_pending( b )==1UL );
  FD_TEST( b->state==dial_state && b->backoff==dial_backoff && b->retry_at==dial_retry_at );
  fd_failover_channel_init_dialer( c, FD_IP4_ADDR(127,0,0,1), port_b );
  pump( b, c );
  FD_TEST( !b->dial_peer && c->dial_peer && !fd_failover_channel_pending( b ) );
  FD_TEST( fd_memeq( b->peer_hello.junk_pubkey, key_c+32, 32UL ) );
  transfer( b, c, 70UL );
  starts = b->metrics.connection_attempt_cnt;
  long backoff = b->backoff;
  fd_failover_channel_hangup( c, now );
  for( ulong i=0UL; i<10000UL && paired( b ); i++ ) {
    poll_channel( b );
    fd_log_sleep( 100000L );
  }
  /* That session was short, so the redial backs off like a dial would. */
  FD_TEST( b->dial_peer && b->retry_at>=now+backoff && b->retry_at<now+backoff+b->backoff_min );
  now = b->retry_at-1L;
  poll_channel( b );
  FD_TEST( b->metrics.connection_attempt_cnt==starts );
  now = b->retry_at;
  poll_channel( b );
  FD_TEST( b->metrics.connection_attempt_cnt==starts+1UL && fd_failover_channel_pending( b )==1UL );
  fd_failover_channel_init_dialer( c, 0U, 0 );
  fd_failover_channel_init_dialer( b, FD_IP4_ADDR(127,0,0,1), port );
  close( dead_fd );
  now += 2000000001L;
  pump( a, b );
  transfer( a, b, 70UL );
  FD_LOG_NOTICE(( "pass: a standby listens too, and the first session to authenticate wins" ));

  fd_failover_channel_hangup( a, now );
  fd_failover_channel_hangup( b, now );
  now += 2000000001L;

  /* Eight addresses hold every handshake slot of a standby.  Its dial
     gets a slot anyway, the oldest holder is closed for it, and the
     pair completes while the rest hold on. */
  fd_failover_channel_init_dialer( b, 0U, port );
  int held[16];
  for( uint i=0; i<16U; i++ ) held[i] = raw_connect( port_b, FD_IP4_ADDR(127,0,0,(i>>1)+2U) );
  poll_channel( b );
  poll_channel( b );
  FD_TEST( fd_failover_channel_pending( b )==16UL );
  ulong evicted = b->metrics.evicted_cnt;
  fd_failover_channel_init_dialer( b, FD_IP4_ADDR(127,0,0,1), port );
  pump( a, b );
  FD_TEST( paired( a ) && paired( b ) && !fd_failover_channel_pending( b ) );
  FD_TEST( b->metrics.evicted_cnt==evicted+1UL );
  for( uint i=0; i<16U; i++ ) close( held[i] );
  transfer( a, b, 70UL );
  FD_LOG_NOTICE(( "pass: our dial gets a slot while every slot is held" ));

  /* Eight addresses hold every handshake slot of the listener and drain
     its start bucket.  The configured peer is admitted anyway, the oldest
     holder is closed for it, and the pair completes while the rest hold
     on. */
  fd_failover_channel_hangup( a, now );
  fd_failover_channel_hangup( b, now );
  now += 2000000001L;
  fd_failover_channel_expect_peer( a, FD_IP4_ADDR(127,0,0,1) );
  for( uint i=0; i<16U; i++ ) held[i] = raw_connect( port, FD_IP4_ADDR(127,0,0,(i>>1)+2U) );
  poll_channel( a );
  poll_channel( a );
  FD_TEST( fd_failover_channel_pending( a )==16UL );
  evicted = a->metrics.evicted_cnt;
  pump( a, b );
  FD_TEST( paired( a ) && paired( b ) && !fd_failover_channel_pending( a ) );
  FD_TEST( a->metrics.evicted_cnt==evicted+1UL );
  for( uint i=0; i<16U; i++ ) close( held[i] );
  transfer( a, b, 70UL );
  fd_failover_channel_expect_peer( a, 0U );
  FD_LOG_NOTICE(( "pass: the configured peer is admitted while every slot is held" ));

  /* The RNG outlives a connection, so it must not be able to rebuild the
     connection's key share.  Replaying the RNG state from before the
     connection yields something else. */
  static fd_chacha_rng_t snap[1];
  *snap = *b->tls_ctx.rng;
  fd_failover_tls_t probe;
  int probe_fd = socket( AF_INET, SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC, 0 );
  FD_TEST( probe_fd>=0 );
  FD_TEST( !fd_failover_tls_new( &probe, &b->tls_ctx, probe_fd, 1 ) );
  uchar share[ 32 ];
  fd_memcpy( share, probe.conn.tls.kex_private_key, 32UL );
  fd_failover_tls_fini( &probe );
  close( probe_fd );
  uchar replay[ 32 ];
  fd_chacha_rng_read32( snap, replay );
  FD_TEST( !fd_memeq( replay, share, 32UL ) );
  FD_TEST( !fd_memeq( probe.conn.tls.kex_private_key, share, 32UL ) ); /* wiped with the connection */
  FD_LOG_NOTICE(( "pass: a wiped connection's key share is gone for good" ));

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
  FD_LOG_NOTICE(( "pass: accept bound, candidate bound and absolute deadline" ));

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

  /* Two candidates from one address is the limit, even with a token to
     spare. */
  for( uint i=0; i<2U; i++ ) fds[i] = raw_connect( port, FD_IP4_ADDR(127,0,0,40) );
  poll_channel( a );
  FD_TEST( fd_failover_channel_pending( a )==2UL );
  now += 250000000L;
  fds[2] = raw_connect( port, FD_IP4_ADDR(127,0,0,40) );
  poll_channel( a );
  FD_TEST( fd_failover_channel_pending( a )==2UL );
  for( uint i=0; i<3U; i++ ) close( fds[i] );
  fd_failover_channel_hangup( a, now );
  FD_LOG_NOTICE(( "pass: two candidates per address" ));

  /* Authenticated stale HELLO rejects only this candidate. */
  now += 2000000001L;
  b->self_hello.cfg_hash = 1UL;
  ulong rejects = a->metrics.hello_reject_cnt;
  for( ulong i=0; i<1000UL && a->metrics.hello_reject_cnt==rejects; i++ ) {
    poll_channel( a ); poll_channel( b ); now += 1000000L; fd_log_sleep( 100000L );
  }
  FD_TEST( a->metrics.hello_reject_cnt>rejects && a->state==FD_FAILOVER_SESSION_LISTENING );
  b->self_hello.cfg_hash = 0UL;
  fd_failover_channel_hangup( b, now );
  now += 2000000001L;
  pump( a, b );
  transfer( a, b, 0UL );
  FD_LOG_NOTICE(( "pass: rejected HELLO permits reconnect" ));

  /* Two standbys that dial each other end up on one session, even when
     both dial at once and each first pairs the other's dial. */
  fd_failover_channel_hangup( a, now );
  fd_failover_channel_hangup( b, now );
  now += 2000000001L;
  long a_silence = a->silence_timeout;
  fast_dialer( a );
  fd_failover_channel_set_role( a, FD_FAILOVER_ROLE_STANDBY );
  fd_failover_channel_init_dialer( a, FD_IP4_ADDR(127,0,0,1), port_b );
  fd_failover_channel_init_dialer( b, FD_IP4_ADDR(127,0,0,1), port   );
  int one = 0;
  for( ulong i=0UL; i<100000UL && !one; i++ ) {
    poll_channel( a );
    poll_channel( b );
    one = paired( a ) && paired( b ) && a->candidates[ a->active ].dialed!=b->candidates[ b->active ].dialed;
    now += 100000L;
    fd_log_sleep( 10000L );
  }
  FD_TEST( one );
  transfer( a, b, 70UL );
  transfer( b, a, 70UL );
  fd_failover_channel_hangup( a, now );
  fd_failover_channel_hangup( b, now );
  fd_failover_channel_init_dialer( a, 0U, 0 );
  fd_failover_channel_set_role( a, FD_FAILOVER_ROLE_ACTIVE );
  a->silence_timeout = a_silence;
  a->backoff_min     = FD_FAILOVER_CHANNEL_BACKOFF_MIN_NANOS;
  a->backoff_max     = FD_FAILOVER_CHANNEL_BACKOFF_MAX_NANOS;
  a->backoff         = a->backoff_min;
  now += 2000000001L;
  pump( a, b );
  FD_LOG_NOTICE(( "pass: two standbys that dial each other settle on one session" ));

  test_tls_profile( a, b, port );
  test_disconnects( a, b, port );
  test_short_session_backoff( a, b );
  test_silence( a, b );
  test_ciphertext_drain( a, b );
  test_result_close( a, b );
  test_loss_log_causes( a, b );
  test_fd_exhaustion( a, b, port );

  fd_failover_channel_fini( a );
  fd_failover_channel_fini( b );
  fd_failover_channel_fini( c );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
