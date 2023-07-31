#include "fdctl.h"

#include "../frank/fd_frank.h"

#include <stdio.h>
#include <signal.h>
#include <sys/syscall.h>
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
  if( getuid() != config->uid )
    check_cap( security, "monitor", CAP_SETUID, "switch uid by calling `setuid(2)`" );
  if( getgid() != config->gid )
    check_cap( security, "monitor", CAP_SETGID, "switch gid by calling `setgid(2)`" );
}

#define TEXT_ALTBUF_DISABLE "\033[?1049l"

static void
signal1( int sig ) {
  (void)sig;
  printf( TEXT_ALTBUF_DISABLE );
  exit_group( 0 );
}

void
monitor_cmd_fn( args_t *         args,
                config_t * const config ) {
  char line[ 4096 ];
  const char * pod_gaddr = load_var_pod( config, "POD", line );
  const uchar * pod = fd_wksp_pod_attach( pod_gaddr );

  struct sigaction sa = {
    .sa_handler = signal1,
    .sa_flags   = 0,
  };
  if( FD_UNLIKELY( sigaction( SIGTERM, &sa, NULL ) ) )
    FD_LOG_ERR(( "sigaction(SIGTERM) failed (%i-%s)", errno, strerror( errno ) ));
  if( FD_UNLIKELY( sigaction( SIGINT, &sa, NULL ) ) )
    FD_LOG_ERR(( "sigaction(SIGINT) failed (%i-%s)", errno, strerror( errno ) ));

  long allow_syscalls[] = {
    __NR_write,       /* logging */
    __NR_futex,       /* logging, glibc fprintf unfortunately uses a futex internally */
    __NR_nanosleep,   /* fd_log_wait_until */
    __NR_sched_yield, /* fd_log_wait_until */
    __NR_exit_group,  /* exit process */
  };
  if( config->development.sandbox )
    fd_sandbox( config->uid,
                config->gid,
                4, /* stdin, stdout, stderr, logfile */
                sizeof(allow_syscalls)/sizeof(allow_syscalls[0]),
                allow_syscalls );

  fd_frank_mon( pod,
                args->monitor.dt_min,
                args->monitor.dt_max,
                args->monitor.duration,
                args->monitor.seed );

  printf( TEXT_ALTBUF_DISABLE );
  exit_group( 0 );
}
