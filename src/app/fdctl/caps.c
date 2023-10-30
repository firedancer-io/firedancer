#define _GNU_SOURCE
#include "caps.h"

#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/capability.h>

static void
fd_caps_private_add_error( fd_caps_ctx_t * ctx,
                           char const *    fmt,
                           ... ) {
  if( FD_UNLIKELY( ctx->err_cnt >= MAX_ERROR_ENTRIES ) )
    FD_LOG_ERR(( "too many capability checks failed" ));

  va_list ap;
  va_start( ap, fmt );
  int result = vsnprintf( ctx->err[ ctx->err_cnt++ ], MAX_ERROR_MSG_LEN, fmt, ap );
  if( FD_UNLIKELY( result < 0 ) ) FD_LOG_ERR(( "vsnprintf failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  else if ( FD_UNLIKELY( (ulong)result >= MAX_ERROR_MSG_LEN ) ) FD_LOG_ERR(( "vsnprintf truncated message" ));
  va_end( ap );
}

void
fd_caps_check_root( fd_caps_ctx_t * ctx,
                    char const *    name,
                    char const *    reason ) {
  if( FD_LIKELY( !getuid() ) ) return;

  fd_caps_private_add_error( ctx, "%s ... process requires root to %s", name, reason );
}

static int
has_capability( uint capability ) {
  struct __user_cap_data_struct   capdata[2];
  struct __user_cap_header_struct capheader = {
    .pid = 0,
    .version = _LINUX_CAPABILITY_VERSION_3
  };

  if( FD_UNLIKELY( syscall( SYS_capget, &capheader, capdata ) ) )
    FD_LOG_ERR(( "capget syscall failed (%i-%s)", errno, fd_io_strerror( errno ) ) );
  return !!(capdata[ 0 ].effective & (1U << capability));
}

FD_FN_CONST static char *
fd_caps_str( uint capability ) {
  switch( capability ) {
    case CAP_CHOWN:              return "CAP_CHOWN";
    case CAP_DAC_OVERRIDE:       return "CAP_DAC_OVERRIDE";
    case CAP_DAC_READ_SEARCH:    return "CAP_DAC_READ_SEARCH";
    case CAP_FOWNER:             return "CAP_FOWNER";
    case CAP_FSETID:             return "CAP_FSETID";
    case CAP_KILL:               return "CAP_KILL";
    case CAP_SETGID:             return "CAP_SETGID";
    case CAP_SETUID:             return "CAP_SETUID";
    case CAP_SETPCAP:            return "CAP_SETPCAP";
    case CAP_LINUX_IMMUTABLE:    return "CAP_LINUX_IMMUTABLE";
    case CAP_NET_BIND_SERVICE:   return "CAP_NET_BIND_SERVICE";
    case CAP_NET_BROADCAST:      return "CAP_NET_BROADCAST";
    case CAP_NET_ADMIN:          return "CAP_NET_ADMIN";
    case CAP_NET_RAW:            return "CAP_NET_RAW";
    case CAP_IPC_LOCK:           return "CAP_IPC_LOCK";
    case CAP_IPC_OWNER:          return "CAP_IPC_OWNER";
    case CAP_SYS_MODULE:         return "CAP_SYS_MODULE";
    case CAP_SYS_RAWIO:          return "CAP_SYS_RAWIO";
    case CAP_SYS_CHROOT:         return "CAP_SYS_CHROOT";
    case CAP_SYS_PTRACE:         return "CAP_SYS_PTRACE";
    case CAP_SYS_PACCT:          return "CAP_SYS_PACCT";
    case CAP_SYS_ADMIN:          return "CAP_SYS_ADMIN";
    case CAP_SYS_BOOT:           return "CAP_SYS_BOOT";
    case CAP_SYS_NICE:           return "CAP_SYS_NICE";
    case CAP_SYS_RESOURCE:       return "CAP_SYS_RESOURCE";
    case CAP_SYS_TIME:           return "CAP_SYS_TIME";
    case CAP_SYS_TTY_CONFIG:     return "CAP_SYS_TTY_CONFIG";
    case CAP_MKNOD:              return "CAP_MKNOD";
    case CAP_LEASE:              return "CAP_LEASE";
    case CAP_AUDIT_WRITE:        return "CAP_AUDIT_WRITE";
    case CAP_AUDIT_CONTROL:      return "CAP_AUDIT_CONTROL";
    case CAP_SETFCAP:            return "CAP_SETFCAP";
    case CAP_MAC_OVERRIDE:       return "CAP_MAC_OVERRIDE";
    case CAP_MAC_ADMIN:          return "CAP_MAC_ADMIN";
    case CAP_SYSLOG:             return "CAP_SYSLOG";
    case CAP_WAKE_ALARM:         return "CAP_WAKE_ALARM";
    case CAP_BLOCK_SUSPEND:      return "CAP_BLOCK_SUSPEND";
    case CAP_AUDIT_READ:         return "CAP_AUDIT_READ";
    case CAP_PERFMON:            return "CAP_PERFMON";
    case CAP_BPF:                return "CAP_BPF";
    case CAP_CHECKPOINT_RESTORE: return "CAP_CHECKPOINT_RESTORE";
    default:                     return "UNKNOWN";
  }
}

void
fd_caps_check_capability( fd_caps_ctx_t * ctx,
                          char const *    name,
                          uint            capability,
                          char const *    reason ) {
  if( FD_LIKELY( has_capability( capability ) ) ) return;

  fd_caps_private_add_error( ctx, "%s ... process requires capability `%s` to %s", name, fd_caps_str( capability ), reason );
}

FD_FN_CONST static char *
fd_caps_resource_str( fd_rlimit_res_t resource ) {
  switch( resource ) {
    case RLIMIT_CPU:     return "RLIMIT_CPU";
    case RLIMIT_FSIZE:   return "RLIMIT_FSIZE";
    case RLIMIT_DATA:    return "RLIMIT_DATA";
    case RLIMIT_STACK:   return "RLIMIT_STACK";
    case RLIMIT_CORE:    return "RLIMIT_CORE";
    case RLIMIT_RSS:     return "RLIMIT_RSS";
    case RLIMIT_NOFILE:  return "RLIMIT_NOFILE";
    case RLIMIT_AS:      return "RLIMIT_AS";
    case RLIMIT_NPROC:   return "RLIMIT_NPROC";
    case RLIMIT_MEMLOCK: return "RLIMIT_MEMLOCK";
    default:             return "UNKNOWN";
  }
}

void
fd_caps_check_resource( fd_caps_ctx_t * ctx,
                        char const *    name,
                        fd_rlimit_res_t resource,
                        ulong           limit,
                        char const *    reason ) {
  struct rlimit rlim;
  if( FD_UNLIKELY( getrlimit( resource, &rlim ) ) )
    FD_LOG_ERR(( "getrlimit failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_LIKELY( rlim.rlim_cur >= limit ) ) return;

  if( FD_LIKELY( !has_capability( CAP_SYS_RESOURCE ) ) ) {
    if( FD_LIKELY( resource == RLIMIT_NICE && has_capability( CAP_SYS_NICE ) ) ) {
        /* special case, if we have CAP_SYS_NICE we can set any nice
           value without raising the limit with CAP_SYS_RESOURCE. */
        return;
    }

    if( FD_UNLIKELY( resource == RLIMIT_NICE ) )
      fd_caps_private_add_error( ctx,
                                "%s ... process requires capability `%s` or `%s` to %s",
                                name,
                                fd_caps_str( CAP_SYS_RESOURCE ),
                                fd_caps_str( CAP_SYS_NICE ),
                                reason );
    else
      fd_caps_private_add_error( ctx,
                                "%s ... process requires capability `%s` to %s",
                                name,
                                fd_caps_str( CAP_SYS_RESOURCE ),
                                reason );
  } else {
    rlim.rlim_cur = limit;
    rlim.rlim_max = limit;
    if( FD_UNLIKELY( setrlimit( resource, &rlim ) ) )
      FD_LOG_ERR(( "setrlimit failed (%i-%s) for resource %s", errno, fd_io_strerror( errno ), fd_caps_resource_str( resource ) ));
  }
}
