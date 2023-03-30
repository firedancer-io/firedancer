#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/utsname.h>

#include "fd_util_base.h"
#include "log/fd_log.h"

/* FD_LINUX_VERSION_MIN_{W,X}: min supported Linux kernel version.
   Currently Linux 4.18. */

#define FD_LINUX_VERSION_MIN_W ( 4)
#define FD_LINUX_VERSION_MIN_X (18)

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
fd_linux_check_kernel( void ) {
  struct utsname uts = {0};
  if( FD_UNLIKELY( 0!=uname( &uts ) ) ) {
    FD_LOG_WARNING(( "uname() failed (%d-%s)", errno, strerror( errno ) ));
    return;
  }

  FD_LOG_INFO(( "fd_util: running Linux %s", uts.release ));

  /* Parse kernel version */

  char *version_tok[ 3UL ];
  if( FD_UNLIKELY( fd_cstr_tokenize( version_tok, 3UL, uts.release, '.' )<3UL ) ) {
    FD_LOG_INFO(( "fd_util: unknown kernel version" ));
    return;
  }

  char * w_cstr = version_tok[ 0UL ]; uint w = fd_cstr_to_uint( w_cstr );
  char * x_cstr = version_tok[ 1UL ]; uint x = fd_cstr_to_uint( x_cstr );
  if( FD_UNLIKELY( (w==0) || (x_cstr[0]!='0' && x==0 ) ) ) {
    FD_LOG_INFO(( "fd_util: unknown kernel version" ));
    return;
  }

  if( FD_UNLIKELY( w<FD_LINUX_VERSION_MIN_W || x<FD_LINUX_VERSION_MIN_X ) )
    FD_LOG_WARNING(( "fd_util: Linux %u.%u is too old (min supported %u.%u)",
                     w, x, FD_LINUX_VERSION_MIN_W, FD_LINUX_VERSION_MIN_X ));
}

static void
fd_linux_private_boot( int  *   pargc,
                       char *** pargv ) {

  char const * netns = fd_env_strip_cmdline_cstr( pargc, pargv, "--netns", "NETNS", NULL );
  if( netns ) fd_linux_enter_netns( netns );

  fd_linux_check_kernel();
}

