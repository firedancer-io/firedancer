#define _GNU_SOURCE
#include "../fd_config.h"
#include "../fd_action.h"
#include "../fd_bootinfo.h"

#include <errno.h>
#include <stdio.h>
#include <unistd.h>


void
ps_cmd_args( int *    pargc,
             char *** pargv,
             args_t * args ) {
  args->ps.clean = fd_env_strip_cmdline_contains( pargc, pargv, "--clean" );
}

void
ps_cmd_fn( args_t *   args,
           config_t * config FD_PARAM_UNUSED ) {
  fd_bootinfo_instance_t instances[ FD_BOOTINFO_INSTANCE_MAX ];
  ulong cnt = fd_bootinfo_discover( instances, FD_BOOTINFO_INSTANCE_MAX );

  fd_bootinfo_print( instances, cnt );

  if( FD_UNLIKELY( args->ps.clean ) ) {
    for( ulong i=0UL; i<cnt; i++ ) {
      if( FD_LIKELY( instances[ i ].live ) ) continue;
      char const * suffix[ 2 ] = { "bootinfo", "config" };
      for( ulong j=0UL; j<2UL; j++ ) {
        char path[ PATH_MAX ];
        FD_TEST( fd_cstr_printf_check( path, sizeof(path), NULL, "%s/%s.%s", instances[ i ].mount_path, instances[ i ].info.name, suffix[ j ] ) );
        if( FD_UNLIKELY( -1==unlink( path ) ) ) {
          if( FD_UNLIKELY( errno!=ENOENT ) ) FD_LOG_WARNING(( "unlink(%s) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
        }
        else FD_LOG_STDOUT(( "removed %s\n", path ));
      }
    }
  }
}

static void
ps_args_help( fd_action_help_t * help ) {
  fd_action_help_arg( help, "--clean", NULL, "Remove descriptors of validators that are no longer running.  Only\n"
                                             "provably stale descriptors are removed, never live ones" );
}

action_t fd_action_ps = {
  .name           = "ps",
  .args           = ps_cmd_args,
  .fn             = ps_cmd_fn,
  .require_config = 0,
  .perm           = NULL,
  .is_diagnostic  = 1,
  .description    = "List validators running on this host",
  .detail         = "Lists validator instances discovered on this host, live or stale.  A\n"
                    "stale entry means a validator was stopped or crashed without cleaning up.\n",
  .usage          = "ps [--clean]",
  .args_help      = ps_args_help,
};
