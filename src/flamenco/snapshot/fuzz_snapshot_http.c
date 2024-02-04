#if !FD_HAS_HOSTED || !FD_HAS_THREADS
#error "This target requires FD_HAS_HOSTED and FD_HAS_THREADS"
#endif

/* fuzz_snapshot_http.c uses auto-generated fuzz inputs to mock the
   server-side of the snapshot downloader.  Communication runs over an
   unnamed AF_UNIX socket pair. */

#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <threads.h>
#include <unistd.h>

#include "../../util/sanitize/fd_fuzz.h"
#include "fd_snapshot_http.h"

struct shared_state {
  int          client_sock;
  int volatile done_sending;
};

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  /* Set up shell without signal handlers */
  putenv( "FD_LOG_BACKTRACE=0" );
  fd_boot( argc, argv );
  atexit( fd_halt );
  /* Don't print warning log */
  fd_log_level_logfile_set( 4 );
  fd_log_level_stderr_set( 4 );
  return 0;
}

static int
target_task( void * ctx ) {
  struct shared_state * st = ctx;

  int socket = st->client_sock;

  fd_snapshot_http_t  _http[1];
  fd_snapshot_http_t * http = fd_snapshot_http_new( _http, FD_IP4_ADDR( 127, 0, 0, 1 ), 80 );

  /* Hijack the HTTP state and make it think there is a successful connection */
  assert( http->socket_fd == -1 );
  http->socket_fd    = socket;
  http->state        = FD_SNAPSHOT_HTTP_STATE_REQ;
  http->req_timeout  = 1e9L;  /* 1s */
  http->req_deadline = fd_log_wallclock() + http->req_timeout;

  for(;;) {
    int stop = 0;
    switch( http->state ) {
    case FD_SNAPSHOT_HTTP_STATE_RESP:
    case FD_SNAPSHOT_HTTP_STATE_DL:
      if( st->done_sending ) {
        FD_FUZZ_MUST_BE_COVERED;
        /* Did we consume all bytes? */
        struct pollfd pfd[1] = {{.fd=socket, .events=(short)POLLIN}};
        poll( pfd, 1, 0 );
        stop = pfd[0].revents==0;
      }
      break;
    }
    if( stop ) break;

    uchar buf[1024];
    ulong out_sz;
    int ok = fd_io_istream_snapshot_http_read( http, buf, sizeof(buf), &out_sz );
    if( ok!=0 ) {
      FD_FUZZ_MUST_BE_COVERED;
      break;
    }

    FD_FUZZ_MUST_BE_COVERED;
  }

  fd_snapshot_http_delete( http );
  close( socket );
  return 0;
}

static void
io_task( int            sock,
         int volatile * done_sending,
         uchar const *  data,
         ulong          data_sz ) {

  uchar const * data_end       = data + data_sz;
  int           event_interest = POLLIN|POLLOUT;

  /* Do the I/O */

  for(;;) {
    struct pollfd pfd[1] = {{.fd=sock, .events=(short)event_interest}};
    if( FD_UNLIKELY( poll( pfd, 1, 0 )<0 ) ) {
      FD_LOG_ERR(( "poll() failed (%d-%s)", errno, fd_io_strerror( errno ) ));
      break;
    }

    if( pfd[0].revents==0 )
      sched_yield();

    /* Send a fragment of input data */

    if( pfd[0].revents & POLLOUT ) {
      if( FD_LIKELY( data<data_end ) ) {
        long n = send( sock, data, (ulong)(data_end - data), MSG_DONTWAIT|MSG_NOSIGNAL );
        if( n<=0 ) {
          if( FD_LIKELY( (errno==ECONNRESET) | (errno==EPIPE) ) ) break;
          if( FD_UNLIKELY( errno!=EAGAIN ) ) {  /* TODO use EWOULDBLOCK instead? */
            FD_LOG_CRIT(( "send() to target failed (%d-%s)", errno, fd_io_strerror( errno ) ));
            break;
          }
          continue;
        }
        data += (ulong)n;
      }
      if( data==data_end ) {
        event_interest &= ~POLLOUT;
        *done_sending   = 1;
      }
    }

    /* Discard any incoming data, for as long as the client keeps the
       connection open. */

    if( pfd[0].revents & POLLIN ) {
      char buf[1024];
      long n = recv( sock, buf, sizeof(buf), MSG_DONTWAIT );
      if( n<0 ) {
        if( FD_LIKELY( (errno==ECONNRESET) | (errno==EPIPE) ) ) break;
        if( FD_UNLIKELY( errno!=EAGAIN ) ) {  /* TODO use EWOULDBLOCK instead? */
          FD_LOG_CRIT(( "recv() from target failed (%d-%s)", errno, fd_io_strerror( errno ) ));
          break;
        }
      } else if( n==0 ) {
        break;  /* socket closed */
      }
    }

  }

}

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         data_sz ) {

  int sockets[2] = {-1, -1};
  if( FD_UNLIKELY( 0!=socketpair( AF_UNIX, SOCK_STREAM, 0, sockets ) ) ) {
    FD_LOG_ERR(( "socketpair(AF_UNIX,SOCK_STREAM) failed (%d-%s)", errno, fd_io_strerror( errno ) ));
    return 0;
  }

  FD_FUZZ_MUST_BE_COVERED;

  struct shared_state st = { .client_sock = sockets[1] };

  /* Launch a thread that does the HTTP client side */
  thrd_t thr;
  assert( thrd_create( &thr, target_task, &st )==thrd_success );

  /* Do the server side I/O */
  io_task( sockets[0], &st.done_sending, data, data_sz );
  close( sockets[0] );

  thrd_join( thr, NULL );
  return 0;
}
