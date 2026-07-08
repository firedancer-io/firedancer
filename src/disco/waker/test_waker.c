#define _GNU_SOURCE /* pipe2 */
#include "fd_waker.h"
#include "../../util/fd_util.h"
#include "../../tango/fseq/fd_fseq.h"

#include <fcntl.h>
#include <unistd.h>
#include <sys/epoll.h>

/* Exercises fd_waker_install (which self-tests the kernel's nested
   epoll wakeup + ONESHOT/MOD rearm behavior) and then the full wake
   protocol over the installed fds: ready -> outer fires once (ONESHOT)
   -> clear/drain/rearm -> pending readiness re-fires, drained
   readiness does not. */

static uchar fseq_mem[ FD_FSEQ_FOOTPRINT ] __attribute__((aligned(FD_FSEQ_ALIGN)));

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong const client_cnt = 2UL;
  fd_waker_install( client_cnt );

  /* client 0 registers a pipe in its inner set */
  int pfd[ 2 ];
  FD_TEST( !pipe2( pfd, O_CLOEXEC ) );
  struct epoll_event ev = { .events = EPOLLIN, .data.u64 = 42UL };
  FD_TEST( !epoll_ctl( FD_WAKER_INNER_FD( 0UL ), EPOLL_CTL_ADD, pfd[ 0 ], &ev ) );

  ulong * fseq = fd_fseq_join( fd_fseq_new( fseq_mem, 0UL ) );
  FD_TEST( fseq );

  /* quiet: no events */
  FD_TEST( 0==epoll_wait( FD_WAKER_OUTER_FD, &ev, 1, 0 ) );

  /* waker side: readiness on client 0's pipe fires the outer set with
     the client index as event data */
  FD_TEST( 1L==write( pfd[ 1 ], "x", 1UL ) );
  FD_TEST( 1==epoll_wait( FD_WAKER_OUTER_FD, &ev, 1, 0 ) );
  FD_TEST( ev.data.u64==0UL );
  fd_fseq_update( fseq, 1UL );

  /* ONESHOT: disarmed until the client rearms, even though readiness
     is still pending */
  FD_TEST( 0==epoll_wait( FD_WAKER_OUTER_FD, &ev, 1, 0 ) );

  /* client side, wake protocol: clear FIRST */
  FD_TEST( fd_fseq_query( fseq )==1UL );
  fd_fseq_update( fseq, 0UL );

  /* partial drain (nothing read): rearm re-polls and re-fires the
     outer set -- pending readiness is never lost to the race between
     drain and rearm */
  fd_waker_client_rearm( 0UL );
  FD_TEST( 1==epoll_wait( FD_WAKER_OUTER_FD, &ev, 1, 0 ) );
  FD_TEST( ev.data.u64==0UL );

  /* full drain: rearm with an empty inner set stays quiet */
  char c;
  FD_TEST( 1L==read( pfd[ 0 ], &c, 1UL ) );
  FD_TEST( 0==epoll_wait( FD_WAKER_INNER_FD( 0UL ), &ev, 1, 0 ) ); /* inner now empty */
  fd_waker_client_rearm( 0UL );
  FD_TEST( 0==epoll_wait( FD_WAKER_OUTER_FD, &ev, 1, 0 ) );

  /* closed fd drops out of the inner set with no epoll_ctl (sole
     reference: close is deregistration) */
  FD_TEST( 1L==write( pfd[ 1 ], "x", 1UL ) );
  FD_TEST( !close( pfd[ 0 ] ) );
  FD_TEST( !close( pfd[ 1 ] ) );
  fd_waker_client_rearm( 0UL );
  FD_TEST( 0==epoll_wait( FD_WAKER_OUTER_FD, &ev, 1, 0 ) );

  /* client 1's inner set exists and is independent */
  FD_TEST( 0==epoll_wait( FD_WAKER_INNER_FD( 1UL ), &ev, 1, 0 ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
