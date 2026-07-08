#define _GNU_SOURCE /* pipe2 */
#include "fd_waker.h"

#include "../../util/log/fd_log.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/wait.h>

int
fd_waker_tile_is_client( char const * name ) {
  return !strcmp( name, "gui"    ) |
         !strcmp( name, "metric" ) |
         !strcmp( name, "rpc"    ) |
         !strcmp( name, "ipecho" ) |
         !strcmp( name, "bundle" ) |
         !strcmp( name, "netlnk" ) |
         !strcmp( name, "event"  );
}

/* The wake protocol depends on two kernel behaviors of nested epoll:
   (a) an event arriving on an fd inside an inner set wakes a BLOCKED
   epoll_wait on the outer set (dropped by unpatched kernels v5.5 to
   v5.12; restored in v5.13 and the 5.4.y/5.10.y stable series), and
   (b) EPOLL_CTL_MOD re-polls the target immediately, so rearming an
   EPOLLONESHOT-disarmed inner entry with readiness still pending
   re-fires the outer set (what makes the clear/drain/rearm sequence
   lost-wake-proof).  (a) cannot be probed synchronously: a fresh
   epoll_wait call re-polls the inner set and succeeds even on broken
   kernels; only a sleeping waiter exposes the bug.  So: fork a child
   that makes an inner fd ready while we are blocked in the outer
   wait, and require the wake.  Runs once at boot, pre-fork.  Logs
   err (aborts boot) on a kernel where the protocol would lose
   wakes. */

static void
self_test( void ) {
  int outer = epoll_create1( 0 );
  int inner = epoll_create1( 0 );
  if( FD_UNLIKELY( -1==outer || -1==inner ) ) FD_LOG_ERR(( "epoll_create1() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  int pfd[ 2 ];
  if( FD_UNLIKELY( pipe2( pfd, O_CLOEXEC ) ) ) FD_LOG_ERR(( "pipe2() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  struct epoll_event ev = { .events = EPOLLIN };
  if( FD_UNLIKELY( -1==epoll_ctl( inner, EPOLL_CTL_ADD, pfd[ 0 ], &ev ) ) ) FD_LOG_ERR(( "epoll_ctl(ADD) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  ev = (struct epoll_event){ .events = EPOLLIN|EPOLLONESHOT };
  if( FD_UNLIKELY( -1==epoll_ctl( outer, EPOLL_CTL_ADD, inner, &ev ) ) ) FD_LOG_ERR(( "epoll_ctl(ADD) failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  pid_t pid = fork();
  if( FD_UNLIKELY( -1==pid ) ) FD_LOG_ERR(( "fork() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( !pid ) ) { /* child: make the inner fd ready while the parent sleeps */
    struct timespec ts = { .tv_sec = 0, .tv_nsec = (long)50e6 };
    nanosleep( &ts, NULL );
    long n = write( pfd[ 1 ], "x", 1UL );
    _exit( 1L==n ? 0 : 1 );
  }

  int n;
  do n = epoll_wait( outer, &ev, 1, 2000 );
  while( FD_UNLIKELY( -1==n && errno==EINTR ) );
  if( FD_UNLIKELY( -1==n ) ) FD_LOG_ERR(( "epoll_wait() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  int wstatus;
  if( FD_UNLIKELY( pid!=waitpid( pid, &wstatus, 0 ) ) ) FD_LOG_ERR(( "waitpid() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( !WIFEXITED( wstatus ) || WEXITSTATUS( wstatus ) ) ) FD_LOG_ERR(( "waker self test child failed" ));
  if( FD_UNLIKELY( 1!=n ) )
    FD_LOG_ERR(( "waker self test failed: an event inside a nested epoll set did not wake a blocked "
                 "epoll_wait on the outer set.  This kernel is missing the nested-epoll wakeup fixes "
                 "(present in v5.13+ and in the 5.4.y/5.10.y stable series); the waker tile would "
                 "lose wakes on it." ));

  /* (b) the wake above disarmed the ONESHOT entry; the pipe byte was
     never read so the inner set is still ready.  A disarmed entry
     must stay silent; MOD must re-poll and re-fire it. */
  if( FD_UNLIKELY( 0!=epoll_wait( outer, &ev, 1, 0 ) ) ) FD_LOG_ERR(( "waker self test failed: EPOLLONESHOT entry not disarmed after delivery" ));
  ev = (struct epoll_event){ .events = EPOLLIN|EPOLLONESHOT };
  if( FD_UNLIKELY( -1==epoll_ctl( outer, EPOLL_CTL_MOD, inner, &ev ) ) ) FD_LOG_ERR(( "epoll_ctl(MOD) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( 1!=epoll_wait( outer, &ev, 1, 0 ) ) )
    FD_LOG_ERR(( "waker self test failed: EPOLL_CTL_MOD rearm did not re-fire pending readiness; "
                 "the waker rearm protocol would lose wakes on this kernel." ));

  if( FD_UNLIKELY( close( pfd[ 0 ] ) || close( pfd[ 1 ] ) || close( inner ) || close( outer ) ) )
    FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
}

void
fd_waker_install( ulong client_cnt ) {
  FD_TEST( client_cnt<=FD_WAKER_CLIENT_MAX );

  if( FD_LIKELY( client_cnt ) ) self_test();

  int outer = epoll_create1( 0 );
  if( FD_UNLIKELY( -1==outer ) ) FD_LOG_ERR(( "epoll_create1() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( -1==dup2( outer, FD_WAKER_OUTER_FD ) ) ) FD_LOG_ERR(( "dup2(%d,%d) failed (%i-%s)", outer, FD_WAKER_OUTER_FD, errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( close( outer ) ) ) FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  for( ulong i=0UL; i<client_cnt; i++ ) {
    int inner = epoll_create1( 0 );
    if( FD_UNLIKELY( -1==inner ) ) FD_LOG_ERR(( "epoll_create1() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    if( FD_UNLIKELY( -1==dup2( inner, FD_WAKER_INNER_FD( i ) ) ) ) FD_LOG_ERR(( "dup2(%d,%d) failed (%i-%s)", inner, FD_WAKER_INNER_FD( i ), errno, fd_io_strerror( errno ) ));
    if( FD_UNLIKELY( close( inner ) ) ) FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

    struct epoll_event ev = { .events = EPOLLIN|EPOLLONESHOT, .data.u64 = i };
    if( FD_UNLIKELY( -1==epoll_ctl( FD_WAKER_OUTER_FD, EPOLL_CTL_ADD, FD_WAKER_INNER_FD( i ), &ev ) ) )
      FD_LOG_ERR(( "epoll_ctl(ADD,inner[%lu]) failed (%i-%s)", i, errno, fd_io_strerror( errno ) ));
  }
}

void
fd_waker_client_rearm( ulong idx ) {
  struct epoll_event ev = { .events = EPOLLIN|EPOLLONESHOT, .data.u64 = idx };
  if( FD_UNLIKELY( -1==epoll_ctl( FD_WAKER_OUTER_FD, EPOLL_CTL_MOD, FD_WAKER_INNER_FD( idx ), &ev ) ) )
    FD_LOG_ERR(( "epoll_ctl(MOD,inner[%lu]) failed (%i-%s)", idx, errno, fd_io_strerror( errno ) ));
}
