#include "configure.h"

#define NAME "sysctl"

#include <stdio.h>
#include <linux/capability.h>

static void
init_perm( fd_caps_ctx_t *  caps,
           config_t * const config ) {
  (void)config;
  fd_caps_check_capability( caps, NAME, CAP_SYS_ADMIN, "set kernel parameters in `/proc/sys`" );
}

#define ENFORCE_MINIMUM 0
#define WARN_MINIMUM    1
#define WARN_EXACT      2

typedef struct {
  char const * path;
  uint         value;
  int          mode;
} sysctl_param_t;

static const sysctl_param_t params[] = {
  {
    "/proc/sys/vm/max_map_count",
    1000000,
    ENFORCE_MINIMUM,
  },
  {
    "/proc/sys/fs/file-max",
    CONFIGURE_NR_OPEN_FILES,
    ENFORCE_MINIMUM,
  },
  {
    "/proc/sys/fs/nr_open",
    CONFIGURE_NR_OPEN_FILES,
    ENFORCE_MINIMUM,
  },
  {
    "/proc/sys/net/ipv4/conf/lo/rp_filter",
    2,
    ENFORCE_MINIMUM,
  },
  {
    "/proc/sys/net/ipv4/conf/lo/accept_local",
    1,
    ENFORCE_MINIMUM,
  },
  {
    "/proc/sys/net/core/bpf_jit_enable",
    1,
    WARN_MINIMUM,
  },
  {
    "/proc/sys/kernel/numa_balancing",
    0,
    WARN_EXACT,
  }
};

static const char * ERR_MSG = "system might not support configuring sysctl,";


/* Some of these sysctl limits are needed for the Agave client, not
   Firedancer.  We set them on their behalf to make configuration easier
   for users. */

static void
init( config_t * const config ) {
  (void)config;
  for( ulong i=0; i<sizeof( params ) / sizeof( params[ 0 ] ); i++ ) {
    uint param = read_uint_file( params[ i ].path, ERR_MSG );
    switch( params[ i ].mode ) {
      case ENFORCE_MINIMUM:
        if( FD_UNLIKELY( param<params[ i ].value ) ) {
          FD_LOG_NOTICE(( "RUN: `echo \"%u\" > %s`", params[ i ].value, params[ i ].path ) );
          write_uint_file( params[ i ].path, params[ i ].value );
        }
        break;
      default:
        break;
    }
  }
}

static configure_result_t
check( config_t * const config ) {
  static int has_warned = 0;

  (void)config;
  for( ulong i=0; i<sizeof( params ) / sizeof( params[ 0 ] ); i++ ) {
    uint param = read_uint_file( params[ i ].path, ERR_MSG );
    switch( params[ i ].mode ) {
      case ENFORCE_MINIMUM:
        if( FD_UNLIKELY( param<params[ i ].value ) )
          NOT_CONFIGURED( "kernel parameter `%s` is too low (got %u but expected at least %u)", params[ i ].path, param, params[ i ].value );
        break;
      case WARN_MINIMUM:
        if( FD_UNLIKELY( !has_warned && param<params[ i ].value ) )
          FD_LOG_WARNING(( "kernel parameter `%s` is too low (got %u but expected at least %u). Proceeding but performance may be reduced.", params[ i ].path, param, params[ i ].value ));
        break;
      case WARN_EXACT:
        if( FD_UNLIKELY( !has_warned && param!=params[ i ].value ) )
          FD_LOG_WARNING(( "kernel parameter `%s` is set to %u, not the expected value of %u. Proceeding but performance may be reduced.", params[ i ].path, param, params[ i ].value ));
        break;
    }
  }

  has_warned = 1;

  CONFIGURE_OK();
}

configure_stage_t sysctl = {
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
