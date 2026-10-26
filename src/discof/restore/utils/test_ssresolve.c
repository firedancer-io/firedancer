#include "fd_ssresolve.h"

#include "../../../util/fd_util.h"

#include <fcntl.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static uchar _ssresolve[ 1UL<<20 ] __attribute__((aligned(FD_SSRESOLVE_ALIGN)));

/* connect_pair wires an fd_ssresolve_t up to one end of a socketpair
   and returns the other end for the test to play the server on.  The
   plain-HTTP init starts in the request state, so no connect is
   needed. */

static int
connect_pair( fd_ssresolve_t ** out,
              int               full ) {
  int sv[ 2 ];
  FD_TEST( 0==socketpair( AF_UNIX, SOCK_STREAM, 0, sv ) );
  FD_TEST( -1!=fcntl( sv[ 0 ], F_SETFL, fcntl( sv[ 0 ], F_GETFL, 0 )|O_NONBLOCK ) );

  FD_TEST( fd_ssresolve_footprint()<=sizeof(_ssresolve) );
  fd_ssresolve_t * ssresolve = fd_ssresolve_join( fd_ssresolve_new( _ssresolve ) );
  FD_TEST( ssresolve );

  fd_ip4_port_t addr = { .addr = 0x7F000001U, .port = fd_ushort_bswap( 80 ) };
  fd_ssresolve_init( ssresolve, addr, sv[ 0 ], full, "localhost" );

  /* Flush the request out so the state machine is waiting on a
     response. */
  FD_TEST( FD_SSRESOLVE_ADVANCE_SUCCESS==fd_ssresolve_advance_poll_out( ssresolve ) );

  *out = ssresolve;
  return sv[ 1 ];
}

/* respond plays the server, then drives one poll_in. */

static int
respond( fd_ssresolve_t *        ssresolve,
         int                     server,
         char const *            resp,
         fd_ssresolve_result_t * result ) {
  FD_TEST( (long)strlen( resp )==send( server, resp, strlen( resp ), 0 ) );
  return fd_ssresolve_advance_poll_in( ssresolve, result );
}

static void
test_incremental_absent( void ) {
  char const * responses[] = {
    "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n",
    "HTTP/1.1 410 Gone\r\nContent-Length: 0\r\n\r\n"
  };

  for( ulong i=0UL; i<sizeof(responses)/sizeof(responses[0]); i++ ) {
    fd_ssresolve_t * ssresolve;
    int server = connect_pair( &ssresolve, 0 /* incremental */ );

    fd_ssresolve_result_t result;
    FD_TEST( FD_SSRESOLVE_ADVANCE_ABSENT==respond( ssresolve, server, responses[ i ], &result ) );
    FD_TEST( fd_ssresolve_is_done( ssresolve ) );

    FD_TEST( 0==close( server ) );
    fd_ssresolve_cancel( ssresolve );
  }
  FD_LOG_NOTICE(( "pass: test_incremental_absent" ));
}

static void
test_full_absent_error( void ) {
  char const * responses[] = {
    "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n",
    "HTTP/1.1 410 Gone\r\nContent-Length: 0\r\n\r\n"
  };

  for( ulong i=0UL; i<sizeof(responses)/sizeof(responses[0]); i++ ) {
    fd_ssresolve_t * ssresolve;
    int server = connect_pair( &ssresolve, 1 /* full */ );

    fd_ssresolve_result_t result;
    FD_TEST( FD_SSRESOLVE_ADVANCE_ERROR==respond( ssresolve, server, responses[ i ], &result ) );
    FD_TEST( !fd_ssresolve_is_done( ssresolve ) );

    FD_TEST( 0==close( server ) );
    fd_ssresolve_cancel( ssresolve );
  }
  FD_LOG_NOTICE(( "pass: test_full_absent_error" ));
}

static void
test_incremental_other_error( void ) {
  char const * responses[] = {
    "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n",
    "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n"
  };

  for( ulong i=0UL; i<sizeof(responses)/sizeof(responses[0]); i++ ) {
    fd_ssresolve_t * ssresolve;
    int server = connect_pair( &ssresolve, 0 /* incremental */ );

    fd_ssresolve_result_t result;
    FD_TEST( FD_SSRESOLVE_ADVANCE_ERROR==respond( ssresolve, server, responses[ i ], &result ) );
    FD_TEST( !fd_ssresolve_is_done( ssresolve ) );

    FD_TEST( 0==close( server ) );
    fd_ssresolve_cancel( ssresolve );
  }
  FD_LOG_NOTICE(( "pass: test_incremental_other_error" ));
}

static void
test_incremental_redirect_result( void ) {
  fd_ssresolve_t * ssresolve;
  int server = connect_pair( &ssresolve, 0 /* incremental */ );

  fd_ssresolve_result_t result;
  char const * resp = "HTTP/1.1 302 Found\r\n"
                      "Location: /incremental-snapshot-100-200-9NUeyNtZH1uoYsivVTvCHrWeqcMHvxrBCvvwHcwQG1L4.tar.zst\r\n"
                      "Content-Length: 0\r\n\r\n";
  FD_TEST( FD_SSRESOLVE_ADVANCE_RESULT==respond( ssresolve, server, resp, &result ) );
  FD_TEST( fd_ssresolve_is_done( ssresolve ) );
  FD_TEST( result.base_slot==100UL );
  FD_TEST( result.slot     ==200UL );

  FD_TEST( 0==close( server ) );
  fd_ssresolve_cancel( ssresolve );
  FD_LOG_NOTICE(( "pass: test_incremental_redirect_result" ));
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_incremental_absent();
  test_full_absent_error();
  test_incremental_other_error();
  test_incremental_redirect_result();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
