#include "fdctl.h"
#include "configure/configure.h"

#include "../frank/fd_frank.h"

#include <stdio.h>
#include <unistd.h>
#include <linux/capability.h>

void
run_cmd_args( int *     pargc,
              char ***  pargv,
              args_t *  args ) {
  args->run.configure = fd_env_strip_cmdline_contains( pargc, pargv, "--configure" );
}

void
run_cmd_perm( args_t *         args,
              security_t *     security,
              config_t * const config ) {
  if( FD_UNLIKELY( args->run.configure ) ) {
    args_t configure_args = {
      .configure.command = CONFIGURE_CMD_INIT,
    };
    fd_memcpy( &configure_args.configure.stages, STAGES, sizeof( configure_args.configure.stages ) );
    configure_cmd_perm( &configure_args, security, config );
  }

  ulong limit = workspace_bytes( config );
  check_res( security, "run", RLIMIT_MEMLOCK, limit, "increase `RLIMIT_MEMLOCK` to lock the workspace in memory with `mlock(2)`" );
  check_res( security, "run", RLIMIT_NICE, 40, "call `setpriority(2)` to increase thread priorities" );
  check_cap( security, "run", CAP_NET_RAW, "call `bind(2)` to bind to a socket with `SOCK_RAW`" );
  check_cap( security, "run", CAP_SYS_ADMIN, "initialize XDP by calling `bpf_obj_get`" );
  check_cap( security, "run", CAP_SETUID, "switch uid by calling `setuid(2)`" );
  check_cap( security, "run", CAP_SETGID, "switch gid by calling `setgid(2)`" );
}

void run_cmd_fn( args_t *         args,
                 config_t * const config ) {
  char line[ 4096 ];
  const char * pod  = load_var_pod( config, line );

  if( FD_UNLIKELY( args->run.configure ) ) {
    args_t configure_args = {
      .configure.command = CONFIGURE_CMD_INIT,
    };
    fd_memcpy( &configure_args.configure.stages, STAGES, sizeof( configure_args.configure.stages ) );
    configure_cmd_fn( &configure_args, config );
  }

  char log_app[ NAME_SZ ];
  strcpy( log_app, config->name );
  char cpus[ AFFINITY_SZ ];
  strcpy( cpus, config->layout.affinity );
  char * argv[] = {
    "--log-app",    log_app,
    "--log-thread", "main",
    "--tile-cpus",  cpus,
    NULL,
  };

  int     argc  = sizeof(argv) / sizeof(argv[ 0 ]) - 1;
  char ** pargv = argv;
  fd_frank_run( &argc, &pargv, pod );
}
