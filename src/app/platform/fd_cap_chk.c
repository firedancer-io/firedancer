#define _GNU_SOURCE
#include "fd_cap_chk.h"

#include "fd_file_util.h"
#include "../../util/fd_util.h"

#include <unistd.h>
#include <stdarg.h>
#include <stdio.h>
#include <errno.h>
#include <sys/syscall.h>
#include <sys/resource.h>
#ifdef __linux__
#include <linux/capability.h>
#endif

#define MAX_ERROR_ENTRIES (16UL)
#define MAX_ERROR_MSG_LEN (256UL)

struct fd_cap_chk_private {
  ulong err_cnt;
  char  err[ MAX_ERROR_ENTRIES ][ MAX_ERROR_MSG_LEN ];
};

__attribute__ ((format (printf, 2, 3)))
static void
fd_cap_chk_add_error( fd_cap_chk_t * chk,
                      char const *   fmt,
                      ... ) {
  if( FD_UNLIKELY( chk->err_cnt>=MAX_ERROR_ENTRIES ) ) FD_LOG_ERR(( "too many capability checks failed" ));

  va_list ap;
  va_start( ap, fmt );
  int result = vsnprintf( chk->err[ chk->err_cnt++ ], MAX_ERROR_MSG_LEN, fmt, ap );
  if( FD_UNLIKELY( result<0 ) ) FD_LOG_ERR(( "vsnprintf failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  else if ( FD_UNLIKELY( (ulong)result>=MAX_ERROR_MSG_LEN ) ) FD_LOG_ERR(( "vsnprintf truncated message" ));
  va_end( ap );
}

void *
fd_cap_chk_new( void * shmem ) {
  fd_cap_chk_t * chk = (fd_cap_chk_t *)shmem;
  chk->err_cnt = 0UL;
  return chk;
}

fd_cap_chk_t *
fd_cap_chk_join( void * shchk ) {
  return (fd_cap_chk_t *)shchk;
}

void
fd_cap_chk_root( fd_cap_chk_t * chk,
                 char const *   name,
                 char const *   reason ) {
  if( FD_LIKELY( !getuid() ) ) return;
  fd_cap_chk_add_error( chk, "%s ... process requires root to %s", name, reason );
}

static int
has_capability( uint capability ) {
#ifdef __linux__
  struct __user_cap_data_struct   capdata[2];
  struct __user_cap_header_struct capheader = {
    .pid = 0,
    .version = _LINUX_CAPABILITY_VERSION_3
  };

  if( FD_UNLIKELY( syscall( SYS_capget, &capheader, capdata ) ) ) FD_LOG_ERR(( "capget syscall failed (%i-%s)", errno, fd_io_strerror( errno ) ) );
  fd_msan_unpoison( capdata, sizeof(capdata) );
  uint idx = capability / 32U;
  uint bit = capability % 32U;
  if( FD_UNLIKELY( idx>=2 ) ) return 0;
  return !!(capdata[ idx ].effective & (1U << bit));
#else
  (void)capability;
  /* On macOS, we don't have POSIX capabilities. We assume the user has the necessary permissions (e.g. root for mlock). */
  return 1; 
#endif
}

FD_FN_CONST static char const *
cap_cstr( uint capability ) {
  switch( capability ) {
#ifdef CAP_CHOWN
    case CAP_CHOWN:              return "CAP_CHOWN";
#endif
#ifdef CAP_DAC_OVERRIDE
    case CAP_DAC_OVERRIDE:       return "CAP_DAC_OVERRIDE";
#endif
#ifdef CAP_DAC_READ_SEARCH
    case CAP_DAC_READ_SEARCH:    return "CAP_DAC_READ_SEARCH";
#endif
#ifdef CAP_FOWNER
    case CAP_FOWNER:             return "CAP_FOWNER";
#endif
#ifdef CAP_FSETID
    case CAP_FSETID:             return "CAP_FSETID";
#endif
#ifdef CAP_KILL
    case CAP_KILL:               return "CAP_KILL";
#endif
#ifdef CAP_SETGID
    case CAP_SETGID:             return "CAP_SETGID";
#endif
#ifdef CAP_SETUID
    case CAP_SETUID:             return "CAP_SETUID";
#endif
#ifdef CAP_SETPCAP
    case CAP_SETPCAP:            return "CAP_SETPCAP";
#endif
#ifdef CAP_LINUX_IMMUTABLE
    case CAP_LINUX_IMMUTABLE:    return "CAP_LINUX_IMMUTABLE";
#endif
#ifdef CAP_NET_BIND_SERVICE
    case CAP_NET_BIND_SERVICE:   return "CAP_NET_BIND_SERVICE";
#endif
#ifdef CAP_NET_BROADCAST
    case CAP_NET_BROADCAST:      return "CAP_NET_BROADCAST";
#endif
#ifdef CAP_NET_ADMIN
    case CAP_NET_ADMIN:          return "CAP_NET_ADMIN";
#endif
#ifdef CAP_NET_RAW
    case CAP_NET_RAW:            return "CAP_NET_RAW";
#endif
#ifdef CAP_IPC_LOCK
    case CAP_IPC_LOCK:           return "CAP_IPC_LOCK";
#endif
#ifdef CAP_IPC_OWNER
    case CAP_IPC_OWNER:          return "CAP_IPC_OWNER";
#endif
#ifdef CAP_SYS_MODULE
    case CAP_SYS_MODULE:         return "CAP_SYS_MODULE";
#endif
#ifdef CAP_SYS_RAWIO
    case CAP_SYS_RAWIO:          return "CAP_SYS_RAWIO";
#endif
#ifdef CAP_SYS_CHROOT
    case CAP_SYS_CHROOT:         return "CAP_SYS_CHROOT";
#endif
#ifdef CAP_SYS_PTRACE
    case CAP_SYS_PTRACE:         return "CAP_SYS_PTRACE";
#endif
#ifdef CAP_SYS_PACCT
    case CAP_SYS_PACCT:          return "CAP_SYS_PACCT";
#endif
#ifdef CAP_SYS_ADMIN
    case CAP_SYS_ADMIN:          return "CAP_SYS_ADMIN";
#endif
#ifdef CAP_SYS_BOOT
    case CAP_SYS_BOOT:           return "CAP_SYS_BOOT";
#endif
#ifdef CAP_SYS_NICE
    case CAP_SYS_NICE:           return "CAP_SYS_NICE";
#endif
#ifdef CAP_SYS_RESOURCE
    case CAP_SYS_RESOURCE:       return "CAP_SYS_RESOURCE";
#endif
#ifdef CAP_SYS_TIME
    case CAP_SYS_TIME:           return "CAP_SYS_TIME";
#endif
#ifdef CAP_SYS_TTY_CONFIG
    case CAP_SYS_TTY_CONFIG:     return "CAP_SYS_TTY_CONFIG";
#endif
#ifdef CAP_MKNOD
    case CAP_MKNOD:              return "CAP_MKNOD";
#endif
#ifdef CAP_LEASE
    case CAP_LEASE:              return "CAP_LEASE";
#endif
#ifdef CAP_AUDIT_WRITE
    case CAP_AUDIT_WRITE:        return "CAP_AUDIT_WRITE";
#endif
#ifdef CAP_AUDIT_CONTROL
    case CAP_AUDIT_CONTROL:      return "CAP_AUDIT_CONTROL";
#endif
#ifdef CAP_SETFCAP
    case CAP_SETFCAP:            return "CAP_SETFCAP";
#endif
#ifdef CAP_MAC_OVERRIDE
    case CAP_MAC_OVERRIDE:       return "CAP_MAC_OVERRIDE";
#endif
#ifdef CAP_MAC_ADMIN
    case CAP_MAC_ADMIN:          return "CAP_MAC_ADMIN";
#endif
#ifdef CAP_SYSLOG
    case CAP_SYSLOG:             return "CAP_SYSLOG";
#endif
#ifdef CAP_WAKE_ALARM
    case CAP_WAKE_ALARM:         return "CAP_WAKE_ALARM";
#endif
#ifdef CAP_BLOCK_SUSPEND
    case CAP_BLOCK_SUSPEND:      return "CAP_BLOCK_SUSPEND";
#endif
#ifdef CAP_AUDIT_READ
    case CAP_AUDIT_READ:         return "CAP_AUDIT_READ";
#endif
#ifdef CAP_PERFMON
    case CAP_PERFMON:            return "CAP_PERFMON";
#endif
#ifdef CAP_BPF
    case CAP_BPF:                return "CAP_BPF";
#endif
#ifdef CAP_CHECKPOINT_RESTORE
    case CAP_CHECKPOINT_RESTORE: return "CAP_CHECKPOINT_RESTORE";
#endif
    default:                     return "UNKNOWN";
  }
}

void
fd_cap_chk_cap( fd_cap_chk_t * chk,
                char const *    name,
                uint            capability,
                char const *    reason ) {
  if( FD_LIKELY( has_capability( capability ) ) ) return;
  fd_cap_chk_add_error( chk, "%s ... process requires capability `%s` to %s", name, cap_cstr( capability ), reason );
}

FD_FN_CONST static char *
rlimit_cstr( int resource ) {
  switch( resource ) {
    case RLIMIT_CPU:        return "RLIMIT_CPU";
    case RLIMIT_FSIZE:      return "RLIMIT_FSIZE";
    case RLIMIT_DATA:       return "RLIMIT_DATA";
    case RLIMIT_STACK:      return "RLIMIT_STACK";
    case RLIMIT_CORE:       return "RLIMIT_CORE";
#if RLIMIT_RSS != RLIMIT_AS
    case RLIMIT_RSS:        return "RLIMIT_RSS";
#endif
    case RLIMIT_NOFILE:     return "RLIMIT_NOFILE";
    case RLIMIT_AS:         return "RLIMIT_AS";
#ifdef RLIMIT_NPROC
    case RLIMIT_NPROC:      return "RLIMIT_NPROC";
#endif
    case RLIMIT_MEMLOCK:    return "RLIMIT_MEMLOCK";
#ifdef RLIMIT_LOCKS
    case RLIMIT_LOCKS:      return "RLIMIT_LOCKS";
#endif
#ifdef RLIMIT_SIGPENDING
    case RLIMIT_SIGPENDING: return "RLIMIT_SIGPENDING";
#endif
#ifdef RLIMIT_MSGQUEUE
    case RLIMIT_MSGQUEUE:   return "RLIMIT_MSGQUEUE";
#endif
#ifdef RLIMIT_NICE
    case RLIMIT_NICE:       return "RLIMIT_NICE";
#endif
#ifdef RLIMIT_RTPRIO
    case RLIMIT_RTPRIO:     return "RLIMIT_RTPRIO";
#endif
#ifdef RLIMIT_RTTIME
    case RLIMIT_RTTIME:     return "RLIMIT_RTTIME";
#endif
#ifdef RLIMIT_NLIMITS
    case RLIMIT_NLIMITS:    return "RLIMIT_NLIMITS";
#endif
    default:                return "UNKNOWN";
  }
}

#ifdef __GLIBC__
typedef __rlimit_resource_t fd_rlimit_res_t;
#else /* non-glibc */
typedef int fd_rlimit_res_t;
#endif /* __GLIBC__ */

void
fd_cap_chk_raise_rlimit( fd_cap_chk_t *  chk,
                         char const *    name,
                         int             _resource,
                         ulong           limit,
                         char const *    reason ) {
  fd_rlimit_res_t resource = (fd_rlimit_res_t)_resource;

  struct rlimit rlim;
  if( FD_UNLIKELY( getrlimit( resource, &rlim ) ) ) FD_LOG_ERR(( "getrlimit failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_LIKELY( rlim.rlim_cur>=limit ) ) return;

#ifdef __linux__
  if( FD_LIKELY( !has_capability( CAP_SYS_RESOURCE ) ) ) {
    int is_nice = 0;
#ifdef RLIMIT_NICE
    if( resource==RLIMIT_NICE && has_capability( CAP_SYS_NICE ) ) is_nice = 1;
#endif

    if( is_nice ) return;

#ifdef RLIMIT_NICE
    if( resource==RLIMIT_NICE ) {
      fd_cap_chk_add_error( chk, "%s ... process requires capability `CAP_SYS_RESOURCE` or `CAP_SYS_NICE` to %s", name, reason );
    } else {
#endif
      fd_cap_chk_add_error( chk, "%s ... process requires capability `CAP_SYS_RESOURCE` to %s", name, reason );
#ifdef RLIMIT_NICE
    }
#endif
  } else {
    if( FD_UNLIKELY( resource==RLIMIT_NOFILE ) ) {
      uint file_nr;
      if( FD_UNLIKELY( -1==fd_file_util_read_uint( "/proc/sys/fs/nr_open", &file_nr ) ) ) {
        FD_LOG_ERR(( "failed to read `/proc/sys/fs/nr_open` (%i-%s)", errno, fd_io_strerror( errno ) ));
      }
      if( FD_UNLIKELY( file_nr<limit ) )
        FD_LOG_ERR(( "Firedancer requires `/proc/sys/fs/nr_open` to be at least %lu to raise RLIMIT_NOFILE, but it is %u.", limit, file_nr ));
    }
    rlim.rlim_cur = limit;
    rlim.rlim_max = limit;
    if( FD_UNLIKELY( setrlimit( resource, &rlim ) ) ) FD_LOG_ERR(( "setrlimit failed (%i-%s) for resource %s", errno, fd_io_strerror( errno ), rlimit_cstr( _resource ) ));
  }
#else
  (void)chk; (void)name; (void)reason;
  rlim.rlim_cur = limit;
  rlim.rlim_max = limit;
  if( FD_UNLIKELY( setrlimit( resource, &rlim ) ) ) FD_LOG_ERR(( "setrlimit failed (%i-%s) for resource %s", errno, fd_io_strerror( errno ), rlimit_cstr( _resource ) ));
#endif
}

ulong
fd_cap_chk_err_cnt( fd_cap_chk_t const * chk ) {
  return chk->err_cnt;
}

char const *
fd_cap_chk_err( fd_cap_chk_t const * chk,
                ulong                idx ) {
  return chk->err[ idx ];
}
