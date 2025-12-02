#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <errno.h>
#include <string.h>

#include "../../util/fd_util.h"
#include "../../util/sanitize/fd_fuzz.h"
#include "../../disco/topo/fd_topo.h"
#include "fd_genesis_client_private.h"

static fd_genesis_client_t * client_mem;

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  putenv( "FD_LOG_BACKTRACE=0" );
  putenv( "FD_LOG_PATH=" );
  fd_boot( argc, argv );
  atexit( fd_halt );
  fd_log_level_stderr_set(4);

  ulong align     = fd_genesis_client_align();
  ulong footprint = fd_genesis_client_footprint();
  client_mem = aligned_alloc( align, footprint );
  FD_TEST( client_mem );

  return 0;
}

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         data_sz ) {
  fd_genesis_client_t * client = fd_genesis_client_join( fd_genesis_client_new( client_mem ) );
  FD_TEST( client );
  int sockfds[2];
  FD_TEST( 0==socketpair( AF_UNIX, SOCK_STREAM, 0, sockfds ) );

  int client_fd = sockfds[0];
  int fuzzer_fd = sockfds[1];

  int flags = fcntl( client_fd, F_GETFL, 0 );
  fcntl( client_fd, F_SETFL, flags | O_NONBLOCK );
  flags = fcntl( fuzzer_fd, F_GETFL, 0 );
  fcntl( fuzzer_fd, F_SETFL, flags | O_NONBLOCK );

  client->start_time_nanos = fd_log_wallclock();
  client->peer_cnt = 1UL;
  client->remaining_peer_cnt = 1UL;
  client->pollfds[0] = (struct pollfd){
    .fd = client_fd,
    .events = POLLIN|POLLOUT,
    .revents = 0
  };
  client->peers[0].addr.addr = 0x7F000001U;
  client->peers[0].addr.port = fd_ushort_bswap( 8899 );
  client->peers[0].writing = 1;
  client->peers[0].request_bytes_sent = 0UL;
  client->peers[0].response_bytes_read = 0UL;
  for( ulong i=1UL; i<FD_TOPO_GOSSIP_ENTRYPOINTS_MAX; i++ ) {
    client->pollfds[i].fd = -1;
  }

  ulong written = 0UL;
  int write_done = (data_sz == 0UL);
  int read_done = 0;

  for( int i=0; i<8 && (!write_done || !read_done); i++ ) {
    FD_FUZZ_MUST_BE_COVERED;

    if( (i % 2 == 0) && !write_done ) {
      ulong chunk_sz = fd_ulong_min( 1024UL, data_sz - written );
      if( chunk_sz > 0UL ) {
        long n = send( fuzzer_fd, data + written, chunk_sz, MSG_NOSIGNAL );
        if( n > 0 ) {
          written += (ulong)n;
          if( written >= data_sz ) {
            write_done = 1;
            close( fuzzer_fd );
            fuzzer_fd = -1;
          }
        } else if( n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR ) {
          write_done = 1;
          close( fuzzer_fd );
          fuzzer_fd = -1;
        }
      } else {
        write_done = 1;
      }
    } else {
      uchar * buffer = NULL;
      ulong buffer_sz = 0UL;
      fd_ip4_port_t peer = {0};
      int charge_busy = 0;

      ulong prev_sent_sz = client->peers[0].request_bytes_sent;
      int result = fd_genesis_client_poll( client, &peer, &buffer, &buffer_sz, &charge_busy );
      if( prev_sent_sz != client->peers[0].request_bytes_sent && fuzzer_fd != -1 ) {
        uchar discard_buf[1024];
        long n;
        do {
          n = recv( fuzzer_fd, discard_buf, sizeof(discard_buf), MSG_DONTWAIT|MSG_NOSIGNAL );
        } while( n > 0 );
      }

      if( result == 0 && buffer && buffer_sz > 0UL ) {
        uchar x = 0;
        for( ulong j = 0; j < buffer_sz; j++ ) {
          x ^= buffer[j];
        }
        FD_COMPILER_FORGET( x );
        read_done = 1;
      }
      if( result == -1 ) {
        read_done = 1;
      }
    }
  }

  if( fuzzer_fd != -1 ) close( fuzzer_fd );
  if( client_fd != -1 ) close( client_fd );

  FD_FUZZ_MUST_BE_COVERED;
  return 0;
}
