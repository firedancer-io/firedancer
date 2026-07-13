#define _GNU_SOURCE
#include "../../shared/fd_config.h"
#include "../../shared/fd_bootinfo.h"
#include "../../shared/fd_action.h"
#include "../../platform/fd_sys_util.h"
#include "../../../disco/metrics/fd_metrics.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <linux/capability.h>

FD_IMPORT_BINARY( fd_flamegraph_template, "src/app/shared_dev/commands/flamegraph_template.html" );
FD_IMPORT_BINARY( fd_flamegraph_script,   "src/app/shared_dev/commands/flamegraph.py" );

static int
memfd_from( char const *  name,
            uchar const * data,
            ulong         data_sz ) {
  int fd = memfd_create( name, 0U );
  if( FD_UNLIKELY( -1==fd ) ) FD_LOG_ERR(( "memfd_create() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_LIKELY( data_sz ) ) {
    int err = fd_io_write( fd, data, data_sz, data_sz, &(ulong){0} );
    if( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "write() failed (%i-%s)", err, fd_io_strerror( err ) ));
  }
  return fd;
}

static void
dump_child_output( int fd ) {
  if( FD_UNLIKELY( -1==lseek( fd, 0L, SEEK_SET ) ) ) return;
  char buf[ 4096 ];
  long sz;
  while( (sz = read( fd, buf, sizeof(buf) ))>0L ) {
    ulong written = 0UL;
    while( written<(ulong)sz ) {
      long w = write( STDERR_FILENO, buf+written, (ulong)sz-written );
      if( FD_UNLIKELY( w<=0L ) ) return;
      written += (ulong)w;
    }
  }
}

static int record_pid;

static void
parent_signal( int sig ) {
  FD_LOG_NOTICE(( "Received signal %s%s%s %s(%s)%s", fd_log_style_bold(), fd_io_strsignal_name( sig ), fd_log_style_normal(), fd_log_style_dim(), fd_io_strsignal_desc( sig ), fd_log_style_normal() ));
  if( FD_LIKELY( record_pid ) ) {
    if( FD_UNLIKELY( -1==kill( record_pid, SIGINT ) ) ) FD_LOG_ERR(( "kill() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
}

static void
install_parent_signals( void ) {
  struct sigaction sa = {
    .sa_handler = parent_signal,
    .sa_flags   = 0,
  };
  if( FD_UNLIKELY( sigaction( SIGTERM, &sa, NULL ) ) )
    FD_LOG_ERR(( "sigaction(SIGTERM) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( sigaction( SIGINT, &sa, NULL ) ) )
    FD_LOG_ERR(( "sigaction(SIGINT) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
}

void
flame_cmd_perm( args_t *         args   FD_PARAM_UNUSED,
                fd_cap_chk_t *   chk,
                config_t const * config FD_PARAM_UNUSED ) {
  fd_cap_chk_root( chk, "flame", "read system performance counters with `/usr/bin/perf`" );
}

void
flame_cmd_args( int *    pargc,
                char *** pargv,
                args_t * args ) {
  args->flame.freq = fd_env_strip_cmdline_uint( pargc, pargv, "--freq", NULL, 997U );
  if( FD_UNLIKELY( !args->flame.freq ) ) FD_LOG_ERR(( "--freq must be non-zero" ));

  if( FD_UNLIKELY( !*pargc ) ) {
    strncpy( args->flame.name, "all", sizeof( args->flame.name ) - 1 );
    return;
  }
  strncpy( args->flame.name, **pargv, sizeof( args->flame.name ) - 1 );

  (*pargc)--;
  (*pargv)++;
}

void
flame_cmd_fn( args_t *   args,
              config_t * config ) {
  install_parent_signals();

  fd_bootinfo_adopt( config );
  fd_bootinfo_check_layout( config );
  fd_topo_join_workspaces( &config->topo, FD_SHMEM_JOIN_MODE_READ_ONLY, FD_TOPO_CORE_DUMP_LEVEL_DISABLED );
  fd_topo_fill( &config->topo );

  ulong tile_cnt = 0UL;
  ulong tile_idxs[ 128UL ];

  int whole_process = 0;
  if( FD_UNLIKELY( !strcmp( "all", args->flame.name ) ) ) {
    FD_TEST( config->topo.tile_cnt<sizeof(tile_idxs)/sizeof(tile_idxs[0]) );
    for( ulong i=0UL; i<config->topo.tile_cnt; i++ ) {
      tile_idxs[ tile_cnt ] = i;
      tile_cnt++;
    }
  } else if( FD_UNLIKELY( !strcmp( "agave", args->flame.name ) ) ) {
    /* Find the bank tile so we can get the Agave PID */
    ulong bank_tile_idx = fd_topo_find_tile( &config->topo, "bank", 0UL );
    if( FD_UNLIKELY( bank_tile_idx==ULONG_MAX ) ) FD_LOG_ERR(( "tile `bank` not found" ));
    whole_process = 1;
    tile_idxs[ 0 ] = bank_tile_idx;
    tile_cnt = 1UL;
  } else {
    char * sep = strchr( args->flame.name, ':' );

    ulong tile_idx;
    if( FD_UNLIKELY( !sep ) ) {
      tile_idx = fd_topo_find_tile( &config->topo, args->flame.name, 0UL );
    } else {
      char * endptr;
      *sep = '\0';
      ulong kind_id = strtoul( sep+1, &endptr, 10 );
      if( FD_UNLIKELY( *endptr!='\0' || kind_id==ULONG_MAX ) ) FD_LOG_ERR(( "invalid tile kind id provided `%s`", sep+1 ));
      tile_idx = fd_topo_find_tile( &config->topo, args->flame.name, kind_id );
    }

    if( FD_UNLIKELY( tile_idx==ULONG_MAX ) ) FD_LOG_ERR(( "tile %s%s%s not found", fd_log_style_bold(), args->flame.name, fd_log_style_normal() ));
    tile_idxs[ 0 ] = tile_idx;
    tile_cnt = 1UL;
  }

  char threads[ 4096 ] = {0};
  ulong len = 0UL;
  for( ulong i=0UL; i<tile_cnt; i++ ) {
    ulong tid = fd_metrics_tile( config->topo.tiles[ tile_idxs[ i ] ].metrics )[ FD_METRICS_GAUGE_TILE_TID_OFF ];
    ulong pid = fd_metrics_tile( config->topo.tiles[ tile_idxs[ i ] ].metrics )[ FD_METRICS_GAUGE_TILE_PID_OFF ];

    FD_TEST( pid<=INT_MAX );
    if( FD_UNLIKELY( -1==kill( (int)tid, 0 ) ) ) {
      if( FD_LIKELY( config->topo.tiles[ tile_idxs[ i ] ].allow_shutdown ) ) continue;

      if( FD_UNLIKELY( errno==ESRCH ) ) FD_LOG_ERR(( "tile %s%s:%lu%s is not running", fd_log_style_bold(), config->topo.tiles[ tile_idxs[ i ] ].name, config->topo.tiles[ tile_idxs[ i ] ].kind_id, fd_log_style_normal() ));
      else                              FD_LOG_ERR(( "kill() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    }

    ulong arg_len;
    FD_TEST( fd_cstr_printf_check( threads+len, sizeof(threads)-len, &arg_len, "%lu", fd_ulong_if( whole_process, pid, tid ) ) );
    len += arg_len;

    if( FD_LIKELY( i!=tile_cnt-1UL ) ) {
      FD_TEST( fd_cstr_printf_check( threads+len, sizeof(threads)-len, NULL, "," ) );
      len += 1UL;
    }
  }
  FD_TEST( len<sizeof(threads) );

  char freq[ 16UL ];
  FD_TEST( fd_cstr_printf_check( freq, sizeof(freq), NULL, "%u", args->flame.freq ) );

  FD_LOG_NOTICE(( "%s/usr/bin/perf record -e task-clock --off-cpu -g -F %s -%c %s && /usr/bin/perf script report flamegraph%s", fd_log_style_bold(), freq, fd_char_if( whole_process, 'p', 't' ), threads, fd_log_style_normal() ));

  int record_out = memfd_from( "perf_record_output", NULL, 0UL );

  record_pid = fork();
  if( FD_UNLIKELY( -1==record_pid ) ) FD_LOG_ERR(( "fork() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_LIKELY( !record_pid ) ) {
    /* Silence perf unless it fails */
    if( FD_UNLIKELY( -1==dup2( record_out, STDOUT_FILENO ) || -1==dup2( record_out, STDERR_FILENO ) ) ) FD_LOG_ERR(( "dup2() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    char * perf_args[ 13 ] = {
      "/usr/bin/perf",
      "record",
      "-e",
      "task-clock",
      "--off-cpu",
      "-g",
      "-F",
      freq,
      whole_process ? "-p" : "-t",
      threads,
      NULL,
    };
    if( FD_UNLIKELY( -1==execve( "/usr/bin/perf", (char * const *)perf_args, NULL ) ) ) FD_LOG_ERR(( "execve() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  FD_LOG_NOTICE(( "perf collection running, %sCtrl+C%s to stop", fd_log_style_bold(), fd_log_style_normal() ));

  for(;;) {
    int wstatus;
    int exited_pid = waitpid( -1, &wstatus, 0 );
    if( FD_UNLIKELY( -1==exited_pid ) ) {
      if( FD_LIKELY( errno==EAGAIN || errno==EINTR ) ) continue;
      FD_LOG_ERR(( "waitpid() failed (%d-%s)", errno, fd_io_strerror( errno ) ));
    }

    int graceful_exit = !WIFEXITED( wstatus ) && WTERMSIG( wstatus )==SIGINT;
    if( FD_UNLIKELY( !graceful_exit ) ) {
      dump_child_output( record_out );
      if( FD_UNLIKELY( !WIFEXITED( wstatus ) ) ) FD_LOG_ERR(( "%sperf record%s exited unexpectedly with signal %s%s%s %s(%s)%s", fd_log_style_bold(), fd_log_style_normal(), fd_log_style_bold(), fd_io_strsignal_name( WTERMSIG( wstatus ) ), fd_log_style_normal(), fd_log_style_dim(), fd_io_strsignal_desc( WTERMSIG( wstatus ) ), fd_log_style_normal() ));
      if( FD_UNLIKELY( WEXITSTATUS( wstatus ) ) ) FD_LOG_ERR(( "%sperf record%s exited unexpectedly with code %d", fd_log_style_bold(), fd_log_style_normal(), WEXITSTATUS( wstatus ) ));
    }
    break;
  }

  int template_fd = memfd_from( "flamegraph_template", fd_flamegraph_template, fd_flamegraph_template_sz );
  int script_fd   = memfd_from( "flamegraph_script",   fd_flamegraph_script,   fd_flamegraph_script_sz   );

  char template_env[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( template_env, sizeof(template_env), NULL, "FD_FLAMEGRAPH_TEMPLATE=/dev/fd/%d", template_fd ) );
  char script_path[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( script_path, sizeof(script_path), NULL, "py:/dev/fd/%d", script_fd ) );

  int report_out = memfd_from( "perf_report_output", NULL, 0UL );

  int report_pid = fork();
  if( FD_UNLIKELY( -1==report_pid ) ) FD_LOG_ERR(( "fork() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_LIKELY( !report_pid ) ) {
    if( FD_UNLIKELY( -1==dup2( report_out, STDOUT_FILENO ) || -1==dup2( report_out, STDERR_FILENO ) ) ) FD_LOG_ERR(( "dup2() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    /* Sandboxed tiles pivot_root into an empty mount namespace.  perf
       with CAP_SYS_ADMIN setns()es into it to resolve symbols and finds
       nothing, so all stacks show as [unknown].  Drop the capability so
       perf falls back to the host namespace paths. */
    if( FD_UNLIKELY( -1==prctl( PR_CAPBSET_DROP, CAP_SYS_ADMIN, 0, 0, 0 ) ) ) FD_LOG_ERR(( "prctl(PR_CAPBSET_DROP) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    char * args[ 5 ] = {
      "/usr/bin/perf",
      "script",
      "-s",
      script_path,
      NULL,
    };
    char * envp[ 2 ] = { template_env, NULL };
    if( FD_UNLIKELY( -1==execve( "/usr/bin/perf", (char * const *)args, envp ) ) ) FD_LOG_ERR(( "execve() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  for(;;) {
    int wstatus;
    int exited_pid = waitpid( -1, &wstatus, 0 );
    if( FD_UNLIKELY( -1==exited_pid ) ) {
      if( FD_LIKELY( errno==EAGAIN || errno==EINTR ) ) continue;
      FD_LOG_ERR(( "waitpid() failed (%d-%s)", errno, fd_io_strerror( errno ) ));
    }

    if( FD_UNLIKELY( !WIFEXITED( wstatus ) || WEXITSTATUS( wstatus ) ) ) dump_child_output( report_out );
    if( FD_UNLIKELY( !WIFEXITED( wstatus ) ) ) FD_LOG_ERR(( "%sperf report%s exited unexpectedly with signal %s%s%s %s(%s)%s", fd_log_style_bold(), fd_log_style_normal(), fd_log_style_bold(), fd_io_strsignal_name( WTERMSIG( wstatus ) ), fd_log_style_normal(), fd_log_style_dim(), fd_io_strsignal_desc( WTERMSIG( wstatus ) ), fd_log_style_normal() ));
    if( FD_UNLIKELY( WEXITSTATUS( wstatus ) ) ) FD_LOG_ERR(( "%sperf report%s exited unexpectedly with code %d", fd_log_style_bold(), fd_log_style_normal(), WEXITSTATUS( wstatus ) ));
    break;
  }

  char cwd[ PATH_MAX ];
  if( FD_LIKELY( getcwd( cwd, sizeof(cwd) ) ) ) FD_LOG_NOTICE(( "flamegraph written to %s%s/flamegraph.html%s", fd_log_style_bold(), cwd, fd_log_style_normal() ));

  fd_sys_util_exit_group( 0 );
}

static void
flame_args_help( fd_action_help_t * help ) {
  fd_action_help_arg( help, "--freq", "<hz>", "Sampling frequency in Hz (default 997)" );
}

action_t fd_action_flame = {
  .name          = "flame",
  .args          = flame_cmd_args,
  .fn            = flame_cmd_fn,
  .perm          = flame_cmd_perm,
  .description   = "Capture a perf flamegraph",
  .usage         = "flame [all|tile|tile:idx|agave] [--freq <hz>]",
  .args_help     = flame_args_help,
  .is_diagnostic = 1
};
