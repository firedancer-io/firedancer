#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>

#include "fd_util_base.h"
#include "log/fd_log.h"

/* fd_linux_enter_netns: Replaces the network namespace of the calling
   thread with the namespace located at the given nsfs mount path. */
static void
fd_linux_enter_netns( char const * netns ) {
  /* These syscalls mirror `ip netns exec` */
  int ns_fd = open( netns, O_RDONLY|O_CLOEXEC );
  if( FD_UNLIKELY( ns_fd<0 ) ) {
    FD_LOG_WARNING(( "Entering netns failed: open(%s) returned (%d-%s)",
                      netns, errno, strerror( errno ) ));
    return;
  }
  if( FD_UNLIKELY( 0!=setns( ns_fd, CLONE_NEWNET ) ) ) {
    FD_LOG_WARNING(( "setns(%s,CLONE_NEWNET) failed (%d-%s)",
                      netns, errno, strerror( errno ) ));
    return;
  }
  FD_LOG_INFO(( "Using netns %s", netns ));
}

static void
fd_linux_private_boot( int  *   pargc,
                       char *** pargv ) {
  char const * netns = fd_env_strip_cmdline_cstr( pargc, pargv, "--netns", "NETNS", NULL );
  if( netns ) fd_linux_enter_netns( netns );
}

