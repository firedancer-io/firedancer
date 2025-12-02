#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <errno.h>

#include "../../../util/fd_util.h"
#include "../../../util/sanitize/fd_fuzz.h"
#include "fd_sshttp_private.h"

static fd_sshttp_t * http_mem;

extern _Bool fd_sshttp_fuzz;

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  putenv( "FD_LOG_BACKTRACE=0" );
  putenv( "FD_LOG_PATH=" );
  fd_boot( argc, argv );
  atexit( fd_halt );
  fd_log_level_stderr_set(4);

  ulong align     = fd_sshttp_align();
  ulong footprint = fd_sshttp_footprint();
  http_mem = aligned_alloc( align, footprint );
  FD_TEST( http_mem );

  fd_sshttp_fuzz = 1;

  return 0;
}

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         data_sz ) {
  fd_sshttp_t * http = fd_sshttp_join( fd_sshttp_new( http_mem ) );
  FD_TEST( http );

  int sockfds[2];
  FD_TEST( 0==socketpair( AF_UNIX, SOCK_STREAM, 0, sockfds ) );

  int client_fd = sockfds[0];
  int fuzzer_fd = sockfds[1];

  int flags = fcntl( client_fd, F_GETFL, 0 );
  fcntl( client_fd, F_SETFL, flags | O_NONBLOCK );

  uchar dummy[1];
  (void)recv( fuzzer_fd, dummy, sizeof(dummy), MSG_DONTWAIT|MSG_NOSIGNAL );

  fd_ip4_port_t addr = {
    .addr = 0x7F000001U,
    .port = fd_ushort_bswap( 80 )
  };

  char const * path = "/test";

  http->hostname = "localhost";
  http->is_https = 0;
  http->hops = 4UL;
  http->request_sent = 0UL;
  FD_TEST( fd_cstr_printf_check( http->request, sizeof(http->request), &http->request_len,
    "GET %s HTTP/1.1\r\n"
    "User-Agent: Firedancer\r\n"
    "Accept: */*\r\n"
    "Accept-Encoding: identity\r\n"
    "Host: " FD_IP4_ADDR_FMT "\r\n\r\n",
    path, FD_IP4_ADDR_FMT_ARGS( addr.addr ) ) );

  http->response_len = 0UL;
  http->content_len  = 0UL;
  http->content_read = 0UL;
  http->empty_recvs  = 0UL;

  http->addr   = addr;
  http->sockfd = client_fd;

  http->state        = FD_SSHTTP_STATE_REQ;
  http->deadline     = 0UL;
  http->request_sent = 0UL;

  ulong written = 0UL;
  int write_done = (data_sz == 0UL);
  int read_done = 0;

  uchar buffer[4096];
  ulong buffer_sz = sizeof(buffer);

  for( int i=0; i<16 && (!write_done || !read_done); i++ ) {
    FD_FUZZ_MUST_BE_COVERED;

    if( (i % 2 == 0) && !write_done ) {
      ulong chunk_sz = fd_ulong_min( 1024UL, data_sz - written );
      if( chunk_sz > 0UL ) {
        long n = send( fuzzer_fd, data + written, chunk_sz, MSG_NOSIGNAL );
        if( n > 0 ) {
          written += (ulong)n;
          if( written >= data_sz ) {
            write_done = 1;
            shutdown( fuzzer_fd, SHUT_WR );
          }
        } else if( n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR ) {
          write_done = 1;
        }
      } else {
        write_done = 1;
      }
    } else {
      buffer_sz = sizeof(buffer);
      ulong prev_sent_sz = http->request_sent;
      int result = fd_sshttp_advance( http, &buffer_sz, buffer, 0L );
      if( prev_sent_sz != http->request_sent ) {
        uchar discard_buf[1024];
        long n;
        do {
          n = recv( fuzzer_fd, discard_buf, sizeof(discard_buf), MSG_DONTWAIT|MSG_NOSIGNAL );
        } while( n > 0 );
      }

      if( result == FD_SSHTTP_ADVANCE_DATA && buffer_sz > 0UL ) {
        uchar x = 0;
        for( ulong j = 0; j < buffer_sz; j++ ) {
          x ^= buffer[j];
        }
        FD_COMPILER_FORGET( x );
      } else if( result == FD_SSHTTP_ADVANCE_DONE ) {
        read_done = 1;
      } else if( result == FD_SSHTTP_ADVANCE_ERROR ) {
        read_done = 1;
      }
    }
  }

  if( fuzzer_fd != -1 ) close( fuzzer_fd );
  fd_sshttp_cancel( http );

  FD_FUZZ_MUST_BE_COVERED;
  return 0;
}
