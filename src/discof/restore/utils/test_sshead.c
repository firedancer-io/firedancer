#define _GNU_SOURCE
#include "fd_sshead.h"

#include "../../../ballet/base58/fd_base58.h"
#include "../../../util/fd_util.h"

#include <string.h>
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

#define REDIRECT_301 \
  "HTTP/1.1 301 Moved Permanently\r\n" \
  "Location: /snapshot-1000-AGoNxxXQK4kCjeK4y8eJDaEfobS4QjMmCQm5zbEGq9kM.tar.zst\r\n" \
  "\r\n"

#define REDIRECT_303 \
  "HTTP/1.1 303 See Other\r\n" \
  "Location: /snapshot-1000-AGoNxxXQK4kCjeK4y8eJDaEfobS4QjMmCQm5zbEGq9kM.tar.zst\r\n" \
  "\r\n"

#define REDIRECT_307 \
  "HTTP/1.1 307 Temporary Redirect\r\n" \
  "Location: /snapshot-1000-AGoNxxXQK4kCjeK4y8eJDaEfobS4QjMmCQm5zbEGq9kM.tar.zst\r\n" \
  "\r\n"

#define REDIRECT_308 \
  "HTTP/1.1 308 Permanent Redirect\r\n" \
  "Location: /snapshot-1000-AGoNxxXQK4kCjeK4y8eJDaEfobS4QjMmCQm5zbEGq9kM.tar.zst\r\n" \
  "\r\n"

#define REDIRECT_NO_LOCATION \
  "HTTP/1.1 302 Found\r\n" \
  "\r\n"

#define REDIRECT_BAD_LOCATION \
  "HTTP/1.1 302 Found\r\n" \
  "Location: http://example.com/snapshot.tar.zst\r\n" \
  "\r\n"

#define REDIRECT_NON_ZSTD \
  "HTTP/1.1 302 Found\r\n" \
  "Location: /snapshot-1000-AGoNxxXQK4kCjeK4y8eJDaEfobS4QjMmCQm5zbEGq9kM.tar\r\n" \
  "\r\n"

#define REDIRECT_BAD_FILENAME \
  "HTTP/1.1 302 Found\r\n" \
  "Location: /not-a-snapshot-filename.tar.zst\r\n" \
  "\r\n"

#define REDIRECT_EMPTY_PATH \
  "HTTP/1.1 302 Found\r\n" \
  "Location: /\r\n" \
  "\r\n"

#define ERROR_404_RESPONSE "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"

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
  int   peer_fd       = -1;
  int   request_read  = 0;
  int   response_sent = 0;
  ulong response_off  = 0UL;

  for( ulong iter=0; iter<10000UL; iter++ ) {
    int rc = fd_sshead_advance( head, result, now );
    if( rc!=FD_SSHEAD_ADVANCE_AGAIN ) {
      if( peer_fd!=-1 ) FD_TEST( !close( peer_fd ) );
      return rc;
    }

    /* Try to accept if not yet done */
    if( peer_fd==-1 ) {
      peer_fd = accept4( listen_fd, NULL, NULL, SOCK_NONBLOCK );
      if( peer_fd!=-1 && close_immediately ) {
        FD_TEST( !close( peer_fd ) );
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
      long n = send( peer_fd, response+response_off, response_len-response_off, MSG_NOSIGNAL );
      if( n>0 ) {
        response_off += (ulong)n;
        if( response_off==response_len ) response_sent = 1;
      }
    }
  }

  if( peer_fd!=-1 ) FD_TEST( !close( peer_fd ) );
  FD_LOG_ERR(( "drive_to_completion did not complete within iteration limit" ));
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

  uchar expected_hash[ 32 ];
  FD_TEST( fd_base58_decode_32( "AGoNxxXQK4kCjeK4y8eJDaEfobS4QjMmCQm5zbEGq9kM", expected_hash ) );
  FD_TEST( !memcmp( result.hash, expected_hash, FD_HASH_FOOTPRINT ) );

  FD_TEST( !close( listen_fd ) );
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

  uchar expected_hash[ 32 ];
  FD_TEST( fd_base58_decode_32( "J7FkN5APJtHepZGwd155s3V26TUHQ3r2Xu7UbX9y75mN", expected_hash ) );
  FD_TEST( !memcmp( result.hash, expected_hash, FD_HASH_FOOTPRINT ) );

  FD_TEST( !close( listen_fd ) );
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

  FD_TEST( !close( listen_fd ) );
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

  /* Starting again while active should fail */
  FD_TEST( fd_sshead_start( head, addr, 1/*full*/, now, FD_SSHEAD_DEFAULT_TIMEOUT )==FD_SSHEAD_START_ERR_ACTIVE );

  fd_sshead_cancel( head );
  FD_TEST( !fd_sshead_active( head ) );

  /* Advance after cancel should return IDLE */
  fd_ssresolve_result_t result;
  FD_TEST( fd_sshead_advance( head, &result, now )==FD_SSHEAD_ADVANCE_IDLE );

  FD_TEST( !close( listen_fd ) );
  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_connect_failure( fd_sshead_t * head ) {
  FD_LOG_NOTICE(( "testing connect failure" ));

  /* Use port 1 (tcpmux) on loopback — virtually never has a listener,
     but the test handles both immediate ECONNREFUSED and async failure
     via EINPROGRESS so it is safe even if a service is bound. */
  fd_ip4_port_t addr = { .addr = FD_IP4_ADDR( 127, 0, 0, 1 ), .port = fd_ushort_bswap( 1 ) };
  long now = fd_log_wallclock();
  int rc = fd_sshead_start( head, addr, 1/*full*/, now, FD_SSHEAD_DEFAULT_TIMEOUT );

  if( rc==FD_SSHEAD_START_ERR_CONN ) {
    /* connect() returned ECONNREFUSED immediately, which is expected
       on most systems for localhost. */
    FD_TEST( !fd_sshead_active( head ) );
  } else {
    /* On some systems connect to localhost:1 returns EINPROGRESS and
       the error surfaces asynchronously via poll.  Drive until we get
       an error or timeout. */
    FD_TEST( fd_sshead_active( head ) );
    fd_ssresolve_result_t result;
    int adv = FD_SSHEAD_ADVANCE_AGAIN;
    for( ulong i=0UL; i<10000UL; i++ ) {
      adv = fd_sshead_advance( head, &result, now );
      if( adv!=FD_SSHEAD_ADVANCE_AGAIN ) {
        FD_TEST( adv==FD_SSHEAD_ADVANCE_ERROR || adv==FD_SSHEAD_ADVANCE_TIMEOUT );
        break;
      }
    }
    FD_TEST( adv!=FD_SSHEAD_ADVANCE_AGAIN );
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

  FD_TEST( !close( listen_fd ) );
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

  FD_TEST( !close( listen_fd ) );
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

  FD_TEST( !close( listen_fd ) );
  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_redirect_301( fd_sshead_t * head ) {
  FD_LOG_NOTICE(( "testing 301 redirect" ));

  fd_ip4_port_t addr;
  int listen_fd = create_test_server( &addr );

  long now = fd_log_wallclock();
  FD_TEST( !fd_sshead_start( head, addr, 1/*full*/, now, FD_SSHEAD_DEFAULT_TIMEOUT ) );

  fd_ssresolve_result_t result;
  int rc = drive_to_completion( head, &result, listen_fd,
                                REDIRECT_301, sizeof(REDIRECT_301)-1,
                                0/*close_immediately*/, now );
  FD_TEST( rc==FD_SSHEAD_ADVANCE_DONE );
  FD_TEST( !fd_sshead_active( head ) );
  FD_TEST( result.slot==1000UL );
  FD_TEST( result.base_slot==ULONG_MAX );

  FD_TEST( !close( listen_fd ) );
  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_redirect_307( fd_sshead_t * head ) {
  FD_LOG_NOTICE(( "testing 307 redirect" ));

  fd_ip4_port_t addr;
  int listen_fd = create_test_server( &addr );

  long now = fd_log_wallclock();
  FD_TEST( !fd_sshead_start( head, addr, 1/*full*/, now, FD_SSHEAD_DEFAULT_TIMEOUT ) );

  fd_ssresolve_result_t result;
  int rc = drive_to_completion( head, &result, listen_fd,
                                REDIRECT_307, sizeof(REDIRECT_307)-1,
                                0/*close_immediately*/, now );
  FD_TEST( rc==FD_SSHEAD_ADVANCE_DONE );
  FD_TEST( !fd_sshead_active( head ) );
  FD_TEST( result.slot==1000UL );
  FD_TEST( result.base_slot==ULONG_MAX );

  FD_TEST( !close( listen_fd ) );
  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_redirect_303( fd_sshead_t * head ) {
  FD_LOG_NOTICE(( "testing 303 redirect" ));

  fd_ip4_port_t addr;
  int listen_fd = create_test_server( &addr );

  long now = fd_log_wallclock();
  FD_TEST( !fd_sshead_start( head, addr, 1/*full*/, now, FD_SSHEAD_DEFAULT_TIMEOUT ) );

  fd_ssresolve_result_t result;
  int rc = drive_to_completion( head, &result, listen_fd,
                                REDIRECT_303, sizeof(REDIRECT_303)-1,
                                0/*close_immediately*/, now );
  FD_TEST( rc==FD_SSHEAD_ADVANCE_DONE );
  FD_TEST( !fd_sshead_active( head ) );
  FD_TEST( result.slot==1000UL );
  FD_TEST( result.base_slot==ULONG_MAX );

  FD_TEST( !close( listen_fd ) );
  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_redirect_308( fd_sshead_t * head ) {
  FD_LOG_NOTICE(( "testing 308 redirect" ));

  fd_ip4_port_t addr;
  int listen_fd = create_test_server( &addr );

  long now = fd_log_wallclock();
  FD_TEST( !fd_sshead_start( head, addr, 1/*full*/, now, FD_SSHEAD_DEFAULT_TIMEOUT ) );

  fd_ssresolve_result_t result;
  int rc = drive_to_completion( head, &result, listen_fd,
                                REDIRECT_308, sizeof(REDIRECT_308)-1,
                                0/*close_immediately*/, now );
  FD_TEST( rc==FD_SSHEAD_ADVANCE_DONE );
  FD_TEST( !fd_sshead_active( head ) );
  FD_TEST( result.slot==1000UL );
  FD_TEST( result.base_slot==ULONG_MAX );

  FD_TEST( !close( listen_fd ) );
  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_redirect_no_location( fd_sshead_t * head ) {
  FD_LOG_NOTICE(( "testing redirect with no Location header" ));

  fd_ip4_port_t addr;
  int listen_fd = create_test_server( &addr );

  long now = fd_log_wallclock();
  FD_TEST( !fd_sshead_start( head, addr, 1/*full*/, now, FD_SSHEAD_DEFAULT_TIMEOUT ) );

  fd_ssresolve_result_t result;
  int rc = drive_to_completion( head, &result, listen_fd,
                                REDIRECT_NO_LOCATION, sizeof(REDIRECT_NO_LOCATION)-1,
                                0/*close_immediately*/, now );
  FD_TEST( rc==FD_SSHEAD_ADVANCE_ERROR );
  FD_TEST( !fd_sshead_active( head ) );

  FD_TEST( !close( listen_fd ) );
  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_redirect_bad_location( fd_sshead_t * head ) {
  FD_LOG_NOTICE(( "testing redirect with bad Location header" ));

  fd_ip4_port_t addr;
  int listen_fd = create_test_server( &addr );

  long now = fd_log_wallclock();
  FD_TEST( !fd_sshead_start( head, addr, 1/*full*/, now, FD_SSHEAD_DEFAULT_TIMEOUT ) );

  fd_ssresolve_result_t result;
  int rc = drive_to_completion( head, &result, listen_fd,
                                REDIRECT_BAD_LOCATION, sizeof(REDIRECT_BAD_LOCATION)-1,
                                0/*close_immediately*/, now );
  FD_TEST( rc==FD_SSHEAD_ADVANCE_ERROR );
  FD_TEST( !fd_sshead_active( head ) );

  FD_TEST( !close( listen_fd ) );
  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_redirect_non_zstd( fd_sshead_t * head ) {
  FD_LOG_NOTICE(( "testing redirect to non-zstd file" ));

  fd_ip4_port_t addr;
  int listen_fd = create_test_server( &addr );

  long now = fd_log_wallclock();
  FD_TEST( !fd_sshead_start( head, addr, 1/*full*/, now, FD_SSHEAD_DEFAULT_TIMEOUT ) );

  fd_ssresolve_result_t result;
  int rc = drive_to_completion( head, &result, listen_fd,
                                REDIRECT_NON_ZSTD, sizeof(REDIRECT_NON_ZSTD)-1,
                                0/*close_immediately*/, now );
  FD_TEST( rc==FD_SSHEAD_ADVANCE_ERROR );
  FD_TEST( !fd_sshead_active( head ) );

  FD_TEST( !close( listen_fd ) );
  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_redirect_bad_filename( fd_sshead_t * head ) {
  FD_LOG_NOTICE(( "testing redirect with unparseable filename" ));

  fd_ip4_port_t addr;
  int listen_fd = create_test_server( &addr );

  long now = fd_log_wallclock();
  FD_TEST( !fd_sshead_start( head, addr, 1/*full*/, now, FD_SSHEAD_DEFAULT_TIMEOUT ) );

  fd_ssresolve_result_t result;
  int rc = drive_to_completion( head, &result, listen_fd,
                                REDIRECT_BAD_FILENAME, sizeof(REDIRECT_BAD_FILENAME)-1,
                                0/*close_immediately*/, now );
  FD_TEST( rc==FD_SSHEAD_ADVANCE_ERROR );
  FD_TEST( !fd_sshead_active( head ) );

  FD_TEST( !close( listen_fd ) );
  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_redirect_empty_path( fd_sshead_t * head ) {
  FD_LOG_NOTICE(( "testing redirect with empty path (Location: /)" ));

  fd_ip4_port_t addr;
  int listen_fd = create_test_server( &addr );

  long now = fd_log_wallclock();
  FD_TEST( !fd_sshead_start( head, addr, 1/*full*/, now, FD_SSHEAD_DEFAULT_TIMEOUT ) );

  fd_ssresolve_result_t result;
  int rc = drive_to_completion( head, &result, listen_fd,
                                REDIRECT_EMPTY_PATH, sizeof(REDIRECT_EMPTY_PATH)-1,
                                0/*close_immediately*/, now );
  FD_TEST( rc==FD_SSHEAD_ADVANCE_ERROR );
  FD_TEST( !fd_sshead_active( head ) );

  FD_TEST( !close( listen_fd ) );
  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_error_status_code( fd_sshead_t * head ) {
  FD_LOG_NOTICE(( "testing 404 error response" ));

  fd_ip4_port_t addr;
  int listen_fd = create_test_server( &addr );

  long now = fd_log_wallclock();
  FD_TEST( !fd_sshead_start( head, addr, 1/*full*/, now, FD_SSHEAD_DEFAULT_TIMEOUT ) );

  fd_ssresolve_result_t result;
  int rc = drive_to_completion( head, &result, listen_fd,
                                ERROR_404_RESPONSE, sizeof(ERROR_404_RESPONSE)-1,
                                0/*close_immediately*/, now );
  FD_TEST( rc==FD_SSHEAD_ADVANCE_ERROR );
  FD_TEST( !fd_sshead_active( head ) );

  FD_TEST( !close( listen_fd ) );
  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_timeout_boundary( fd_sshead_t * head ) {
  FD_LOG_NOTICE(( "testing timeout boundary (now == deadline should NOT timeout)" ));

  fd_ip4_port_t addr;
  int listen_fd = create_test_server( &addr );

  long now     = fd_log_wallclock();
  long timeout = 1000L;
  FD_TEST( !fd_sshead_start( head, addr, 1/*full*/, now, timeout ) );
  FD_TEST( fd_sshead_active( head ) );

  /* Advance with now == deadline (strictly > is needed to timeout) */
  fd_ssresolve_result_t result;
  int rc = fd_sshead_advance( head, &result, now + timeout );
  FD_TEST( rc!=FD_SSHEAD_ADVANCE_TIMEOUT );
  FD_TEST( fd_sshead_active( head ) );

  fd_sshead_cancel( head );

  FD_TEST( !close( listen_fd ) );
  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_fragmented_response( fd_sshead_t * head ) {
  FD_LOG_NOTICE(( "testing fragmented response" ));

  fd_ip4_port_t addr;
  int listen_fd = create_test_server( &addr );

  long now = fd_log_wallclock();
  FD_TEST( !fd_sshead_start( head, addr, 1/*full*/, now, FD_SSHEAD_DEFAULT_TIMEOUT ) );

  /* Drive manually: accept, read request, send response in two parts
     to exercise the phr_parse_response partial-parse (-2) code path. */
  int peer_fd      = -1;
  int request_read = 0;
  int frag1_sent   = 0;
  int frag2_sent   = 0;

  char const frag1[] = "HTTP/1.1 302 Found\r\n";
  char const frag2[] = "Location: /snapshot-1000-AGoNxxXQK4kCjeK4y8eJDaEfobS4QjMmCQm5zbEGq9kM.tar.zst\r\n\r\n";

  fd_ssresolve_result_t result;
  for( ulong iter=0; iter<10000UL; iter++ ) {
    int rc = fd_sshead_advance( head, &result, now );
    if( rc!=FD_SSHEAD_ADVANCE_AGAIN ) {
      FD_TEST( rc==FD_SSHEAD_ADVANCE_DONE );
      FD_TEST( result.slot==1000UL );
      FD_TEST( result.base_slot==ULONG_MAX );

      uchar expected_hash[ 32 ];
      FD_TEST( fd_base58_decode_32( "AGoNxxXQK4kCjeK4y8eJDaEfobS4QjMmCQm5zbEGq9kM", expected_hash ) );
      FD_TEST( !memcmp( result.hash, expected_hash, FD_HASH_FOOTPRINT ) );

      if( peer_fd!=-1 ) FD_TEST( !close( peer_fd ) );
      FD_TEST( !close( listen_fd ) );
      FD_LOG_NOTICE(( "... pass" ));
      return;
    }

    if( peer_fd==-1 ) {
      peer_fd = accept4( listen_fd, NULL, NULL, SOCK_NONBLOCK );
    }
    if( peer_fd!=-1 && !request_read ) {
      char buf[ 4096 ];
      long n = recv( peer_fd, buf, sizeof(buf), MSG_DONTWAIT );
      if( n>0 ) request_read = 1;
    }
    if( request_read && !frag1_sent ) {
      FD_TEST( (long)(sizeof(frag1)-1)==send( peer_fd, frag1, sizeof(frag1)-1, MSG_NOSIGNAL ) );
      frag1_sent = 1;
    } else if( frag1_sent && !frag2_sent ) {
      FD_TEST( (long)(sizeof(frag2)-1)==send( peer_fd, frag2, sizeof(frag2)-1, MSG_NOSIGNAL ) );
      frag2_sent = 1;
    }
  }

  if( peer_fd!=-1 ) FD_TEST( !close( peer_fd ) );
  FD_TEST( !close( listen_fd ) );
  FD_LOG_ERR(( "fragmented response test did not complete" ));
}

static void
test_response_buffer_full( fd_sshead_t * head,
                           fd_wksp_t *   wksp ) {
  FD_LOG_NOTICE(( "testing response buffer full" ));

  /* Send a response that fills the USHORT_MAX (65535 byte) response
     buffer in fd_ssresolve without completing a valid HTTP response.
     This exercises the buffer-full error path. */

  fd_ip4_port_t addr;
  int listen_fd = create_test_server( &addr );

  long now = fd_log_wallclock();
  FD_TEST( !fd_sshead_start( head, addr, 1/*full*/, now, FD_SSHEAD_DEFAULT_TIMEOUT ) );

  /* Build an incomplete HTTP response that is larger than USHORT_MAX.
     Use a valid status line followed by a huge header that never
     terminates (no \r\n\r\n). */
  ulong buf_sz = USHORT_MAX + 1UL;
  char * big_response = (char *)fd_wksp_alloc_laddr( wksp, 1UL, buf_sz, 2UL );
  FD_TEST( big_response );

  char const prefix[] = "HTTP/1.1 302 Found\r\nX-Pad: ";
  ulong prefix_len = sizeof(prefix) - 1;
  memcpy( big_response, prefix, prefix_len );
  memset( big_response + prefix_len, 'A', buf_sz - prefix_len );

  fd_ssresolve_result_t result;
  int rc = drive_to_completion( head, &result, listen_fd,
                                big_response, buf_sz,
                                0/*close_immediately*/, now );
  FD_TEST( rc==FD_SSHEAD_ADVANCE_ERROR );
  FD_TEST( !fd_sshead_active( head ) );

  fd_wksp_free_laddr( big_response );
  FD_TEST( !close( listen_fd ) );
  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_start_after_error( fd_sshead_t * head ) {
  FD_LOG_NOTICE(( "testing start after error lifecycle" ));

  /* First: drive to an error via malformed response */
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
  FD_TEST( !close( listen_fd ) );

  /* Second: start a new session and drive to success */
  listen_fd = create_test_server( &addr );
  now = fd_log_wallclock();
  FD_TEST( !fd_sshead_start( head, addr, 1/*full*/, now, FD_SSHEAD_DEFAULT_TIMEOUT ) );
  FD_TEST( fd_sshead_active( head ) );

  rc = drive_to_completion( head, &result, listen_fd,
                            FULL_REDIRECT, sizeof(FULL_REDIRECT)-1,
                            0/*close_immediately*/, now );
  FD_TEST( rc==FD_SSHEAD_ADVANCE_DONE );
  FD_TEST( !fd_sshead_active( head ) );
  FD_TEST( result.slot==1000UL );

  FD_TEST( !close( listen_fd ) );
  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_leave_delete( void * shmem ) {
  FD_LOG_NOTICE(( "testing leave and delete" ));

  FD_TEST( !fd_sshead_leave( NULL ) );
  FD_TEST( !fd_sshead_delete( NULL ) );

  fd_sshead_t * head = fd_sshead_join( fd_sshead_new( shmem ) );
  FD_TEST( head );

  void * shhead = fd_sshead_leave( head );
  FD_TEST( shhead==shmem );

  /* After leave, join should still work (magic intact). */
  head = fd_sshead_join( shhead );
  FD_TEST( head );

  /* Leave again before delete. */
  shhead = fd_sshead_leave( head );
  FD_TEST( shhead );

  void * deleted = fd_sshead_delete( shhead );
  FD_TEST( deleted==shmem );

  /* After delete, join should fail (magic zeroed). */
  FD_TEST( !fd_sshead_join( deleted ) );

  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_start_after_timeout( fd_sshead_t * head ) {
  FD_LOG_NOTICE(( "testing start after timeout lifecycle" ));

  /* First: drive to a timeout */
  fd_ip4_port_t addr;
  int listen_fd = create_test_server( &addr );

  long now     = fd_log_wallclock();
  long timeout = 1000L;
  FD_TEST( !fd_sshead_start( head, addr, 1/*full*/, now, timeout ) );
  FD_TEST( fd_sshead_active( head ) );

  fd_ssresolve_result_t result;
  int rc = fd_sshead_advance( head, &result, now + timeout + 1L );
  FD_TEST( rc==FD_SSHEAD_ADVANCE_TIMEOUT );
  FD_TEST( !fd_sshead_active( head ) );
  FD_TEST( !close( listen_fd ) );

  /* Second: start a new session and drive to success */
  listen_fd = create_test_server( &addr );
  now = fd_log_wallclock();
  FD_TEST( !fd_sshead_start( head, addr, 1/*full*/, now, FD_SSHEAD_DEFAULT_TIMEOUT ) );
  FD_TEST( fd_sshead_active( head ) );

  rc = drive_to_completion( head, &result, listen_fd,
                            FULL_REDIRECT, sizeof(FULL_REDIRECT)-1,
                            0/*close_immediately*/, now );
  FD_TEST( rc==FD_SSHEAD_ADVANCE_DONE );
  FD_TEST( !fd_sshead_active( head ) );
  FD_TEST( result.slot==1000UL );

  FD_TEST( !close( listen_fd ) );
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
  test_redirect_301( head );
  test_redirect_303( head );
  test_redirect_307( head );
  test_redirect_308( head );
  test_redirect_no_location( head );
  test_redirect_bad_location( head );
  test_redirect_non_zstd( head );
  test_redirect_bad_filename( head );
  test_redirect_empty_path( head );
  test_error_status_code( head );
  test_timeout_boundary( head );
  test_fragmented_response( head );
  test_response_buffer_full( head, wksp );
  test_start_after_error( head );
  test_start_after_timeout( head );
  fd_sshead_delete( fd_sshead_leave( head ) );
  test_leave_delete( shmem );

  fd_wksp_free_laddr( shmem );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
