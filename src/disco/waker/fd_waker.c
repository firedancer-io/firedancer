#define _GNU_SOURCE /* pipe2 */
#include "fd_waker.h"

#include "../../util/log/fd_log.h"

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/syscall.h>
#include <sys/wait.h>

/* The wake protocol needs two nested-epoll behaviors: (a) an event
   in an inner set wakes a BLOCKED outer epoll_wait (broken on
   unpatched v5.5-v5.12), and (b) EPOLL_CTL_MOD re-polls, so a rearm
   with readiness pending re-fires (what makes clear/drain/rearm
   lost-wake-proof).  (a) only shows with a sleeping waiter, so fork
   a child that waits until /proc/<parent>/syscall shows us blocked
   in epoll_pwait, then makes an inner fd ready, and require the
   wake.  Runs once pre-fork; logs err on a broken kernel. */

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

  char path[ 32 ];
  FD_TEST( fd_cstr_printf_check( path, sizeof(path), NULL, "/proc/%d/syscall", (int)getpid() ) );

  pid_t pid = fork();
  if( FD_UNLIKELY( -1==pid ) ) FD_LOG_ERR(( "fork() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( !pid ) ) {
    /* child: spin until the parent is observably blocked in the outer
       epoll_pwait (first field of /proc/<pid>/syscall is the syscall
       number, or "running"), then make the inner fd ready.  Bounded;
       on exhaustion write anyway and report the coverage as
       unconfirmed (exit 2). */
    int blocked = 0;
    for( ulong i=0UL; i<1000000UL; i++ ) {
      int fd = open( path, O_RDONLY );
      if( FD_UNLIKELY( -1==fd ) ) break;
      char buf[ 64 ];
      long rd = read( fd, buf, sizeof(buf)-1UL );
      close( fd );
      if( FD_UNLIKELY( rd<=0L ) ) break;
      buf[ rd ] = '\0';
      long nr = strtol( buf, NULL, 10 );
      if( FD_LIKELY( nr==__NR_epoll_pwait || nr==__NR_epoll_wait ) ) { blocked = 1; break; }
      sched_yield();
    }
    long n = write( pfd[ 1 ], "x", 1UL );
    _exit( 1L!=n ? 1 : ( blocked ? 0 : 2 ) );
  }

  int n;
  do n = epoll_pwait( outer, &ev, 1, 2000, NULL );
  while( FD_UNLIKELY( -1==n && errno==EINTR ) );
  if( FD_UNLIKELY( -1==n ) ) FD_LOG_ERR(( "epoll_pwait() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  int wstatus;
  if( FD_UNLIKELY( pid!=waitpid( pid, &wstatus, 0 ) ) ) FD_LOG_ERR(( "waitpid() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( !WIFEXITED( wstatus ) || WEXITSTATUS( wstatus )==1 ) ) FD_LOG_ERR(( "waker self test child failed" ));
  if( FD_UNLIKELY( WEXITSTATUS( wstatus )==2 ) )
    FD_LOG_WARNING(( "waker self test could not observe the parent blocked in epoll_pwait via %s; blocked-waiter coverage unconfirmed", path ));
  if( FD_UNLIKELY( 1!=n ) )
    FD_LOG_ERR(( "waker self test failed: an event inside a nested epoll set did not wake a blocked "
                 "epoll_wait on the outer set.  This kernel is missing the nested-epoll wakeup fixes "
                 "(present in v5.13+ and in the 5.4.y/5.10.y stable series); the waker tile would "
                 "lose wakes on it." ));

  /* (b) entry now disarmed, inner set still ready (byte unread):
     must stay silent until the MOD rearm re-fires it. */
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
  if( FD_LIKELY( outer!=FD_WAKER_OUTER_FD ) ) {
    if( FD_UNLIKELY( -1==dup2( outer, FD_WAKER_OUTER_FD ) ) ) FD_LOG_ERR(( "dup2(%d,%d) failed (%i-%s)", outer, FD_WAKER_OUTER_FD, errno, fd_io_strerror( errno ) ));
    if( FD_UNLIKELY( close( outer ) ) ) FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  for( ulong i=0UL; i<client_cnt; i++ ) {
    int inner = epoll_create1( 0 );
    if( FD_UNLIKELY( -1==inner ) ) FD_LOG_ERR(( "epoll_create1() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    if( FD_LIKELY( inner!=FD_WAKER_INNER_FD( i ) ) ) {
      if( FD_UNLIKELY( -1==dup2( inner, FD_WAKER_INNER_FD( i ) ) ) ) FD_LOG_ERR(( "dup2(%d,%d) failed (%i-%s)", inner, FD_WAKER_INNER_FD( i ), errno, fd_io_strerror( errno ) ));
      if( FD_UNLIKELY( close( inner ) ) ) FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    }

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
