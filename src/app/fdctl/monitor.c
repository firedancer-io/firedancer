#include "fdctl.h"

#include "../frank/fd_frank.h"

#include <linux/capability.h>

void
monitor_cmd_args( int *    pargc,
                  char *** pargv,
                  args_t * args ) {
  args->monitor.dt_min   = fd_env_strip_cmdline_long( pargc, pargv, "--dt-min",   NULL,   66666667.          );
  args->monitor.dt_max   = fd_env_strip_cmdline_long( pargc, pargv, "--dt-max",   NULL, 1333333333.          );
  args->monitor.duration = fd_env_strip_cmdline_long( pargc, pargv, "--duration", NULL,          0.          );
  args->monitor.seed     = fd_env_strip_cmdline_uint( pargc, pargv, "--seed",     NULL, (uint)fd_tickcount() );

  if( FD_UNLIKELY( args->monitor.dt_min<0L                   ) ) FD_LOG_ERR(( "--dt-min should be positive"          ));
  if( FD_UNLIKELY( args->monitor.dt_max<args->monitor.dt_min ) ) FD_LOG_ERR(( "--dt-max should be at least --dt-min" ));
  if( FD_UNLIKELY( args->monitor.duration<0L                 ) ) FD_LOG_ERR(( "--duration should be non-negative"    ));
}

void
monitor_cmd_perm( args_t *         args,
                  security_t *     security,
                  config_t * const config ) {
  (void)args;

  ulong limit = workspace_bytes( config );
  check_res( security, "monitor", RLIMIT_MEMLOCK, limit, "increase `RLIMIT_MEMLOCK` to lock the workspace in memory with `mlock(2)`" );
  check_cap( security, "monitor", CAP_SETUID, "switch uid by calling `setuid(2)`" );
  check_cap( security, "monitor", CAP_SETGID, "switch gid by calling `setgid(2)`" );
}

void monitor_cmd_fn( args_t *         args,
                     config_t * const config ) {
  char line[ 4096 ];
  const char * pod  = load_var_pod( config, line );

  char log_app[ NAME_SZ ];
  strcpy( log_app, config->name );

  char * argv[] = {
    "--log-app",    log_app,
    "--log-thread", "mon",
    NULL,
  };

  int     argc = sizeof(argv) / sizeof(argv[ 0 ]) - 1;
  char ** pargv = argv;
  fd_frank_mon( &argc,
                &pargv,
                pod,
                args->monitor.dt_min,
                args->monitor.dt_max,
                args->monitor.duration,
                args->monitor.seed );
}
