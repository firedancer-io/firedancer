#include "configure.h"

#define NAME "sysctl"

#include "../../../platform/fd_file_util.h"

#include <errno.h>
#include <stdio.h>
#include <linux/capability.h>

static void
init_perm( fd_cap_chk_t *   chk,
           config_t const * config FD_PARAM_UNUSED ) {
  fd_cap_chk_cap( chk, NAME, CAP_SYS_ADMIN, "set kernel parameters in `/proc/sys`" );
}

#define ENFORCE_MINIMUM 0
#define WARN_MINIMUM    1
#define WARN_EXACT      2

typedef struct {
  char const * path;
  ulong        value;
  int          mode;
  int          allow_missing;
} sysctl_param_t;

static const sysctl_param_t params[] = {
  {
    "/proc/sys/vm/max_map_count", /* int */
    1000000,
    ENFORCE_MINIMUM,
    0,
  },
  {
    "/proc/sys/fs/file-max", /* ulong */
    CONFIGURE_NR_OPEN_FILES,
    ENFORCE_MINIMUM,
    0,
  },
  {
    "/proc/sys/fs/nr_open", /* uint */
    CONFIGURE_NR_OPEN_FILES,
    ENFORCE_MINIMUM,
    0,
  },
  {
    "/proc/sys/kernel/numa_balancing", /* int? */
    0,
    WARN_EXACT,
    1,
  },
  {0}
};

static const sysctl_param_t xdp_params[] = {
  {
    "/proc/sys/net/ipv4/conf/lo/rp_filter",
    2,
    ENFORCE_MINIMUM,
    0,
  },
  {
    "/proc/sys/net/ipv4/conf/lo/accept_local",
    1,
    ENFORCE_MINIMUM,
    0,
  },
  {
    "/proc/sys/net/core/bpf_jit_enable",
    1,
    WARN_MINIMUM,
    0,
  },
  {0}
};

static sysctl_param_t sock_params[] = {
  {
    "/proc/sys/net/core/rmem_max",
    0,
    ENFORCE_MINIMUM,
    0,
  },
  {
    "/proc/sys/net/core/wmem_max",
    0,
    ENFORCE_MINIMUM,
    0,
  },
  {0}
};

/* Some of these sysctl limits are needed for the Agave client, not
   Firedancer.  We set them on their behalf to make configuration easier
   for users. */

static void
init_param_list( sysctl_param_t const * list ) {
  for( sysctl_param_t const * p=list; p->path; p++ ) {
    ulong param;
    if( FD_UNLIKELY( -1==fd_file_util_read_ulong( p->path, &param ) ) ) {
      /* If the syctl file does not exist in /proc/sys, it's likely it
         doesn't exist anywhere else */
      if( FD_UNLIKELY( p->allow_missing && errno==ENOENT ) ) continue;

      FD_LOG_ERR(( "could not read kernel parameter `%s`, system might not support configuring sysctl (%i-%s)", p->path, errno, fd_io_strerror( errno ) ));
    }
    switch( p->mode ) {
      case ENFORCE_MINIMUM:
        if( FD_UNLIKELY( param<(p->value) ) ) {
          FD_LOG_NOTICE(( "RUN: `echo \"%lu\" > %s`", p->value, p->path ) );
          if( FD_UNLIKELY( -1==fd_file_util_write_ulong( p->path, p->value ) ) )
            FD_LOG_ERR(( "could not set kernel parameter `%s` to %lu (%i-%s)", p->path, p->value, errno, fd_io_strerror( errno ) ));
        }
        break;
      default:
        break;
    }
  }
}

static void
init( config_t const * config ) {
  init_param_list( params );
  if( 0==strcmp( config->net.provider, "xdp" ) ) {
    init_param_list( xdp_params );
  } else if( 0==strcmp( config->net.provider, "socket" ) ) {
    sock_params[ 0 ].value = config->net.socket.receive_buffer_size;
    sock_params[ 1 ].value = config->net.socket.send_buffer_size;
    init_param_list( sock_params );
  }
}

static configure_result_t
check_param_list( sysctl_param_t const * list ) {
  static int has_warned = 0;

  for( sysctl_param_t const * p=list; p->path; p++ ) {
    ulong param;
    if( FD_UNLIKELY( -1==fd_file_util_read_ulong( p->path, &param ) ) ) {
      if( FD_UNLIKELY( p->allow_missing && errno==ENOENT ) ) continue;
      FD_LOG_ERR(( "could not read kernel parameter `%s`, system might not support configuring sysctl (%i-%s)", p->path, errno, fd_io_strerror( errno ) ));
    }
    switch( p->mode ) {
      case ENFORCE_MINIMUM:
        if( FD_UNLIKELY( param<(p->value) ) )
          NOT_CONFIGURED( "kernel parameter `%s` is too low (got %lu but expected at least %lu)", p->path, param, p->value );
        break;
      case WARN_MINIMUM:
        if( FD_UNLIKELY( !has_warned && param<(p->value) ) )
          FD_LOG_WARNING(( "kernel parameter `%s` is too low (got %lu but expected at least %lu). Proceeding but performance may be reduced.", p->path, param, p->value ));
        break;
      case WARN_EXACT:
        if( FD_UNLIKELY( !has_warned && param!=(p->value) ) )
          FD_LOG_WARNING(( "kernel parameter `%s` is set to %lu, not the expected value of %lu. Proceeding but performance may be reduced.", p->path, param, p->value ));
        break;
    }
  }

  has_warned = 1;

  CONFIGURE_OK();
}

static configure_result_t
check( config_t const * config ) {
  configure_result_t r;

  r = check_param_list( params );
  if( r.result!=CONFIGURE_OK ) return r;

  if( 0==strcmp( config->net.provider, "xdp" ) ) {
    r = check_param_list( xdp_params );
  } else if( 0==strcmp( config->net.provider, "socket" ) ) {
    sock_params[ 0 ].value = config->net.socket.receive_buffer_size;
    sock_params[ 1 ].value = config->net.socket.send_buffer_size;
    r = check_param_list( sock_params );
  } else {
    FD_LOG_ERR(( "unknown net provider: %s", config->net.provider ));
  }
  if( r.result!=CONFIGURE_OK ) return r;

  CONFIGURE_OK();
}

configure_stage_t fd_cfg_stage_sysctl = {
  .name            = NAME,
  .always_recreate = 0,
  .enabled         = NULL,
  .init_perm       = init_perm,
  .fini_perm       = NULL,
  .init            = init,
  .fini            = NULL,
  .check           = check,
};

#undef NAME
