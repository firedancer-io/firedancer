#define _GNU_SOURCE
#include "fd_sshead.h"

#include "../../../util/fd_util.h"

#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

/* HTTP redirect responses using known-good base58 hashes from
   test_ssarchive.c. */

#define FULL_REDIRECT \
  "HTTP/1.1 302 Found\r\n" \
  "Location: /snapshot-1000-AGoNxxXQK4kCjeK4y8eJDaEfobS4QjMmCQm5zbEGq9kM.tar.zst\r\n" \
  "\r\n"

#define INCR_REDIRECT \
  "HTTP/1.1 302 Found\r\n" \
  "Location: /incremental-snapshot-1000-1500-J7FkN5APJtHepZGwd155s3V26TUHQ3r2Xu7UbX9y75mN.tar.zst\r\n" \
  "\r\n"

#define MALFORMED_RESPONSE "GARBAGE\r\n\r\n"

#define OK_200_RESPONSE "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"

/* Creates a TCP listening socket on 127.0.0.1 with an OS-assigned port.
   Populates addr with the bound address. Returns the listen fd. */
static int
create_test_server( fd_ip4_port_t * addr ) {
  int listen_fd = socket( AF_INET, SOCK_STREAM|SOCK_NONBLOCK, 0 );
  FD_TEST( listen_fd>=0 );

  int optval = 1;
  FD_TEST( !setsockopt( listen_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(int) ) );

  struct sockaddr_in sin = {
    .sin_family = AF_INET,
    .sin_addr   = { .s_addr = FD_IP4_ADDR( 127, 0, 0, 1 ) },
    .sin_port   = 0, /* OS-assigned */
  };

  FD_TEST( !bind( listen_fd, fd_type_pun( &sin ), sizeof(sin) ) );
  FD_TEST( !listen( listen_fd, 1 ) );

  socklen_t len = sizeof(sin);
  FD_TEST( !getsockname( listen_fd, fd_type_pun( &sin ), &len ) );

  addr->addr = sin.sin_addr.s_addr;
  addr->port = sin.sin_port;
  return listen_fd;
}

/* Drives fd_sshead_advance in a loop, interleaving server-side
   accept/recv/send.  Returns the final advance return code.
   If response is NULL, the server accepts but never sends (for
   timeout/hangup tests).  If close_immediately is set, the server
   closes the accepted socket right after accepting. */
static int
drive_to_completion( fd_sshead_t *           head,
                     fd_ssresolve_result_t * result,
                     int                     listen_fd,
                     char const *            response,
                     ulong                   response_len,
                     int                     close_immediately,
                     long                    now ) {
  int peer_fd       = -1;
  int request_read  = 0;
  int response_sent = 0;

  for( ulong iter=0; iter<10000UL; iter++ ) {
    int rc = fd_sshead_advance( head, result, now );
    if( rc!=FD_SSHEAD_ADVANCE_AGAIN ) {
      if( peer_fd!=-1 ) close( peer_fd );
      return rc;
    }

    /* Try to accept if not yet done */
    if( peer_fd==-1 ) {
      peer_fd = accept4( listen_fd, NULL, NULL, SOCK_NONBLOCK );
      if( peer_fd!=-1 && close_immediately ) {
        close( peer_fd );
        peer_fd = -1;
        /* Keep looping to let fd_sshead see POLLERR/POLLHUP */
        continue;
      }
    }

    /* Try to read the request from peer */
    if( peer_fd!=-1 && !request_read ) {
      char buf[ 4096 ];
      long n = recv( peer_fd, buf, sizeof(buf), MSG_DONTWAIT );
      if( n>0 ) request_read = 1;
    }

    /* Send response once request is read */
    if( request_read && !response_sent && response ) {
      FD_TEST( (long)response_len==send( peer_fd, response, response_len, MSG_NOSIGNAL ) );
      response_sent = 1;
    }
  }

  if( peer_fd!=-1 ) close( peer_fd );
  FD_LOG_ERR(( "drive_to_completion did not complete within iteration limit" ));
  return -999;
}

static void
test_align_and_footprint( void ) {
  FD_LOG_NOTICE(( "testing align and footprint" ));

  FD_TEST( fd_sshead_align()>0UL );
  FD_TEST( fd_ulong_is_pow2( fd_sshead_align() ) );
  FD_TEST( fd_sshead_footprint()>0UL );
  FD_TEST( fd_ulong_is_aligned( fd_sshead_footprint(), fd_sshead_align() ) );

  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_new_join( void * shmem ) {
  FD_LOG_NOTICE(( "testing new and join" ));

  FD_TEST( !fd_sshead_new( NULL ) );
  FD_TEST( !fd_sshead_join( NULL ) );

  fd_sshead_t * head = fd_sshead_join( fd_sshead_new( shmem ) );
  FD_TEST( head );
  FD_TEST( !fd_sshead_active( head ) );

  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_advance_idle( fd_sshead_t * head ) {
  FD_LOG_NOTICE(( "testing advance when idle" ));

  fd_ssresolve_result_t result;
  long now = fd_log_wallclock();
  FD_TEST( fd_sshead_advance( head, &result, now )==FD_SSHEAD_ADVANCE_IDLE );
  FD_TEST( !fd_sshead_active( head ) );

  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_cancel_idle( fd_sshead_t * head ) {
  FD_LOG_NOTICE(( "testing cancel when idle" ));

  FD_TEST( !fd_sshead_active( head ) );
  fd_sshead_cancel( head ); /* must not crash */
  FD_TEST( !fd_sshead_active( head ) );

  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_lifecycle_full( fd_sshead_t * head ) {
  FD_LOG_NOTICE(( "testing full snapshot lifecycle" ));

  fd_ip4_port_t addr;
  int listen_fd = create_test_server( &addr );

  long now = fd_log_wallclock();
  FD_TEST( !fd_sshead_start( head, addr, 1/*full*/, now, FD_SSHEAD_DEFAULT_TIMEOUT ) );
  FD_TEST( fd_sshead_active( head ) );

  fd_ssresolve_result_t result;
  int rc = drive_to_completion( head, &result, listen_fd,
                                FULL_REDIRECT, sizeof(FULL_REDIRECT)-1,
                                0/*close_immediately*/, now );
  FD_TEST( rc==FD_SSHEAD_ADVANCE_DONE );
  FD_TEST( !fd_sshead_active( head ) );
  FD_TEST( result.slot==1000UL );
  FD_TEST( result.base_slot==ULONG_MAX ); /* full snapshot */

  close( listen_fd );
  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_lifecycle_incremental( fd_sshead_t * head ) {
  FD_LOG_NOTICE(( "testing incremental snapshot lifecycle" ));

  fd_ip4_port_t addr;
  int listen_fd = create_test_server( &addr );

  long now = fd_log_wallclock();
  FD_TEST( !fd_sshead_start( head, addr, 0/*incremental*/, now, FD_SSHEAD_DEFAULT_TIMEOUT ) );
  FD_TEST( fd_sshead_active( head ) );

  fd_ssresolve_result_t result;
  int rc = drive_to_completion( head, &result, listen_fd,
                                INCR_REDIRECT, sizeof(INCR_REDIRECT)-1,
                                0/*close_immediately*/, now );
  FD_TEST( rc==FD_SSHEAD_ADVANCE_DONE );
  FD_TEST( !fd_sshead_active( head ) );
  FD_TEST( result.slot==1500UL );
  FD_TEST( result.base_slot==1000UL );

  close( listen_fd );
  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_timeout( fd_sshead_t * head ) {
  FD_LOG_NOTICE(( "testing timeout" ));

  fd_ip4_port_t addr;
  int listen_fd = create_test_server( &addr );

  long now     = fd_log_wallclock();
  long timeout = 1000L; /* 1 microsecond */
  FD_TEST( !fd_sshead_start( head, addr, 1/*full*/, now, timeout ) );
  FD_TEST( fd_sshead_active( head ) );

  /* Advance with a time past the deadline */
  fd_ssresolve_result_t result;
  int rc = fd_sshead_advance( head, &result, now + timeout + 1L );
  FD_TEST( rc==FD_SSHEAD_ADVANCE_TIMEOUT );
  FD_TEST( !fd_sshead_active( head ) );

  close( listen_fd );
  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_cancel_active( fd_sshead_t * head ) {
  FD_LOG_NOTICE(( "testing cancel while active" ));

  fd_ip4_port_t addr;
  int listen_fd = create_test_server( &addr );

  long now = fd_log_wallclock();
  FD_TEST( !fd_sshead_start( head, addr, 1/*full*/, now, FD_SSHEAD_DEFAULT_TIMEOUT ) );
  FD_TEST( fd_sshead_active( head ) );

  fd_sshead_cancel( head );
  FD_TEST( !fd_sshead_active( head ) );

  /* Advance after cancel should return IDLE */
  fd_ssresolve_result_t result;
  FD_TEST( fd_sshead_advance( head, &result, now )==FD_SSHEAD_ADVANCE_IDLE );

  close( listen_fd );
  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_connect_failure( fd_sshead_t * head ) {
  FD_LOG_NOTICE(( "testing connect failure" ));

  /* Port 1 on loopback with nobody listening, should get ECONNREFUSED */
  fd_ip4_port_t addr = { .addr = FD_IP4_ADDR( 127, 0, 0, 1 ), .port = fd_ushort_bswap( 1 ) };
  long now = fd_log_wallclock();
  int rc = fd_sshead_start( head, addr, 1/*full*/, now, FD_SSHEAD_DEFAULT_TIMEOUT );

  if( rc==-1 ) {
    /* connect() returned ECONNREFUSED immediately, which is expected
       on most systems for localhost. */
    FD_TEST( !fd_sshead_active( head ) );
  } else {
    /* On some systems connect to localhost:1 returns EINPROGRESS and
       the error surfaces asynchronously via poll.  Drive until we get
       an error or timeout. */
    FD_TEST( fd_sshead_active( head ) );
    fd_ssresolve_result_t result;
    for( ulong i=0; i<10000UL; i++ ) {
      int adv = fd_sshead_advance( head, &result, now );
      if( adv!=FD_SSHEAD_ADVANCE_AGAIN ) {
        FD_TEST( adv==FD_SSHEAD_ADVANCE_ERROR || adv==FD_SSHEAD_ADVANCE_TIMEOUT );
        break;
      }
    }
    if( fd_sshead_active( head ) ) fd_sshead_cancel( head );
  }

  FD_TEST( !fd_sshead_active( head ) );

  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_malformed_response( fd_sshead_t * head ) {
  FD_LOG_NOTICE(( "testing malformed response" ));

  fd_ip4_port_t addr;
  int listen_fd = create_test_server( &addr );

  long now = fd_log_wallclock();
  FD_TEST( !fd_sshead_start( head, addr, 1/*full*/, now, FD_SSHEAD_DEFAULT_TIMEOUT ) );

  fd_ssresolve_result_t result;
  int rc = drive_to_completion( head, &result, listen_fd,
                                MALFORMED_RESPONSE, sizeof(MALFORMED_RESPONSE)-1,
                                0/*close_immediately*/, now );
  FD_TEST( rc==FD_SSHEAD_ADVANCE_ERROR );
  FD_TEST( !fd_sshead_active( head ) );

  close( listen_fd );
  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_non_redirect_response( fd_sshead_t * head ) {
  FD_LOG_NOTICE(( "testing non-redirect (200 OK) response" ));

  fd_ip4_port_t addr;
  int listen_fd = create_test_server( &addr );

  long now = fd_log_wallclock();
  FD_TEST( !fd_sshead_start( head, addr, 1/*full*/, now, FD_SSHEAD_DEFAULT_TIMEOUT ) );

  fd_ssresolve_result_t result;
  int rc = drive_to_completion( head, &result, listen_fd,
                                OK_200_RESPONSE, sizeof(OK_200_RESPONSE)-1,
                                0/*close_immediately*/, now );
  FD_TEST( rc==FD_SSHEAD_ADVANCE_ERROR );
  FD_TEST( !fd_sshead_active( head ) );

  close( listen_fd );
  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_peer_hangup( fd_sshead_t * head ) {
  FD_LOG_NOTICE(( "testing peer hangup" ));

  fd_ip4_port_t addr;
  int listen_fd = create_test_server( &addr );

  long now = fd_log_wallclock();
  FD_TEST( !fd_sshead_start( head, addr, 1/*full*/, now, FD_SSHEAD_DEFAULT_TIMEOUT ) );

  fd_ssresolve_result_t result;
  int rc = drive_to_completion( head, &result, listen_fd,
                                NULL, 0,
                                1/*close_immediately*/, now );
  FD_TEST( rc==FD_SSHEAD_ADVANCE_ERROR );
  FD_TEST( !fd_sshead_active( head ) );

  close( listen_fd );
  FD_LOG_NOTICE(( "... pass" ));
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong       page_cnt = 1;
  char *      _page_sz = "gigantic";
  ulong       numa_idx = fd_shmem_numa_idx( 0 );
  fd_wksp_t * wksp     = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  void * shmem = fd_wksp_alloc_laddr( wksp, fd_sshead_align(), fd_sshead_footprint(), 1UL );
  FD_TEST( shmem );

  test_align_and_footprint();
  test_new_join( shmem );

  fd_sshead_t * head = fd_sshead_join( fd_sshead_new( shmem ) );
  FD_TEST( head );

  test_advance_idle( head );
  test_cancel_idle( head );
  test_connect_failure( head );
  test_lifecycle_full( head );
  test_lifecycle_incremental( head );
  test_timeout( head );
  test_cancel_active( head );
  test_malformed_response( head );
  test_non_redirect_response( head );
  test_peer_hangup( head );

  fd_wksp_free_laddr( shmem );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
