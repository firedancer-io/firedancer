#define _GNU_SOURCE
#include "security.h"

#include <unistd.h>
#include <sys/syscall.h>
#include <linux/capability.h>

void
check_root( security_t * security,
            const char * name,
            const char * reason ) {
  if( FD_LIKELY( !getuid() ) ) return;

  if( FD_UNLIKELY( security->idx >= MAX_SECURITY_ERRORS ) )
    FD_LOG_ERR(( "too many security checks failed" ));

  snprintf1( security->errors[ security->idx++ ], 256, "%s ... process requires root to %s", name, reason );
}

static int
has_capability( uint cap ) {
  struct __user_cap_data_struct   capdata[2];
  struct __user_cap_header_struct capheader = {
    .pid = 0,
    .version = _LINUX_CAPABILITY_VERSION_3
  };

  if( FD_UNLIKELY( syscall( SYS_capget, &capheader, capdata ) ) )
    FD_LOG_ERR(( "capget failed (%i-%s)", errno, fd_io_strerror( errno ) ) );
  return !!(capdata[ 0 ].effective & (1U << cap));
}

void
check_cap( security_t * security,
           const char * name,
           uint         cap,
           const char * reason ) {
  if( FD_LIKELY( has_capability( cap ) ) ) return;

  if( FD_UNLIKELY( security->idx >= MAX_SECURITY_ERRORS ) )
    FD_LOG_ERR(( "too many security checks failed" ));

  snprintf1( security->errors[ security->idx++ ], 256, "%s ... process requires capability %u to %s", name, cap, reason );
}

void
check_res( security_t *    security,
           const char *    name,
           fd_rlimit_res_t resource,
           ulong           limit,
           const char *    reason ) {
  struct rlimit rlim;
  if( FD_UNLIKELY( getrlimit( resource, &rlim ) ) )
    FD_LOG_ERR(( "getrlimit failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_LIKELY( rlim.rlim_cur >= limit ) ) return;

  if( FD_LIKELY( ! has_capability( CAP_SYS_RESOURCE ) ) ) {
    if( FD_LIKELY( resource == RLIMIT_NICE && has_capability( CAP_SYS_NICE ) ) ) {
        /* special case, if we have CAP_SYS_NICE we can set any nice
           value without raising the limit with CAP_SYS_RESOURCE. */
        return;
    }

    if( FD_UNLIKELY( security->idx >= MAX_SECURITY_ERRORS ) )
      FD_LOG_ERR(( "too many security checks failed" ));

    snprintf1( security->errors[ security->idx++ ], 256, "%s ... process requires `CAP_SYS_RESOURCE` or `CAP_SYS_NICE` to %s", name, reason );
  } else {
    rlim.rlim_cur = limit;
    rlim.rlim_max = limit;
    if( FD_UNLIKELY( setrlimit( resource, &rlim ) ) )
      FD_LOG_ERR(( "setrlimit failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
}
