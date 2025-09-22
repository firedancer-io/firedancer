#define _GNU_SOURCE
#include "../../shared/fd_config.h"
#include "../../shared/fd_action.h"
#include "../../platform/fd_sys_util.h"
#include "../../../disco/metrics/fd_metrics.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/random.h>

static int record_pid;

static void
parent_signal( int sig ) {
  FD_LOG_NOTICE(( "Received signal %s\n", fd_io_strsignal( sig ) ));
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

  if( FD_UNLIKELY( !*pargc ) ) FD_LOG_ERR(( "usage: flame [all|tile|tile:idx|agave]" ));
  strncpy( args->flame.name, **pargv, sizeof( args->flame.name ) - 1 );

  (*pargc)--;
  (*pargv)++;
}

void
flame_cmd_fn( args_t *   args,
              config_t * config ) {
  install_parent_signals();

  fd_topo_join_workspaces( &config->topo, FD_SHMEM_JOIN_MODE_READ_ONLY );
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

    if( FD_UNLIKELY( tile_idx==ULONG_MAX ) ) FD_LOG_ERR(( "tile `%s` not found", args->flame.name ));
    tile_idxs[ 0 ] = tile_idx;
    tile_cnt = 1UL;
  }

  char threads[ 4096 ] = {0};
  ulong len = 0UL;
  for( ulong i=0UL; i<tile_cnt; i++ ) {
    if( FD_LIKELY( i!=0UL ) ) {
      FD_TEST( fd_cstr_printf_check( threads+len, sizeof(threads)-len, NULL, "," ) );
      len += 1UL;
    }

    ulong tid = fd_metrics_tile( config->topo.tiles[ tile_idxs[ i ] ].metrics )[ FD_METRICS_GAUGE_TILE_TID_OFF ];
    ulong pid = fd_metrics_tile( config->topo.tiles[ tile_idxs[ i ] ].metrics )[ FD_METRICS_GAUGE_TILE_PID_OFF ];

    FD_TEST( pid<=INT_MAX );
    if( FD_UNLIKELY( -1==kill( (int)tid, 0 ) ) ) {
      if( FD_LIKELY( config->topo.tiles[ i ].allow_shutdown ) ) continue;

      if( FD_UNLIKELY( errno==ESRCH ) ) FD_LOG_ERR(( "tile %s:%lu is not running", config->topo.tiles[ i ].name, config->topo.tiles[ i ].kind_id ));
      else                              FD_LOG_ERR(( "kill() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    }

    ulong arg_len;
    FD_TEST( fd_cstr_printf_check( threads+len, sizeof(threads)-len, &arg_len, "%lu", fd_ulong_if( whole_process, pid, tid ) ) );
    len += arg_len;
  }
  FD_TEST( len<sizeof(threads) );

  FD_LOG_NOTICE(( "/usr/bin/perf script record flamegraph -F 99 -%c %s && /usr/bin/perf script report flamegraph", fd_char_if( whole_process, 'p', 't' ), threads ));

  record_pid = fork();
  if( FD_UNLIKELY( -1==record_pid ) ) FD_LOG_ERR(( "fork() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_LIKELY( !record_pid ) ) {
    char * args[ 11 ] = {
      "/usr/bin/perf",
      "script",
      "record",
      "flamegraph",
      "-F",
      "99",
      whole_process ? "-p" : "-t",
      threads,
      NULL,
    };
    if( FD_UNLIKELY( -1==execve( "/usr/bin/perf", (char * const *)args, NULL ) ) ) FD_LOG_ERR(( "execve() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  FD_LOG_NOTICE(( "Perf collection running. Send SIGINT / Crl+C to stop." ));

  for(;;) {
    int wstatus;
    int exited_pid = waitpid( -1, &wstatus, 0 );
    if( FD_UNLIKELY( -1==exited_pid ) ) {
      if( FD_LIKELY( errno==EAGAIN || errno==EINTR ) ) continue;
      FD_LOG_ERR(( "waitpid() failed (%d-%s)", errno, fd_io_strerror( errno ) ));
    }

    int graceful_exit = !WIFEXITED( wstatus ) && WTERMSIG( wstatus )==SIGINT;
    if( FD_UNLIKELY( !graceful_exit ) ) {
      if( FD_UNLIKELY( !WIFEXITED( wstatus ) ) ) FD_LOG_ERR(( "perf record exited unexpectedly with signal %d (%s)", WTERMSIG( wstatus ), fd_io_strsignal( WTERMSIG( wstatus ) ) ));
      if( FD_UNLIKELY( WEXITSTATUS( wstatus ) ) ) FD_LOG_ERR(( "perf record exited unexpectedly with code %d", WEXITSTATUS( wstatus ) ));
    }
    break;
  }

  int report_pid = fork();
  if( FD_UNLIKELY( -1==report_pid ) ) FD_LOG_ERR(( "fork() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_LIKELY( !report_pid ) ) {
    char * args[ 7 ] = {
      "/usr/bin/perf",
      "script",
      "report",
      "flamegraph",
      NULL,
    };
    if( FD_UNLIKELY( -1==execve( "/usr/bin/perf", (char * const *)args, NULL ) ) ) FD_LOG_ERR(( "execve() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  for(;;) {
    int wstatus;
    int exited_pid = waitpid( -1, &wstatus, 0 );
    if( FD_UNLIKELY( -1==exited_pid ) ) {
      if( FD_LIKELY( errno==EAGAIN || errno==EINTR ) ) continue;
      FD_LOG_ERR(( "waitpid() failed (%d-%s)", errno, fd_io_strerror( errno ) ));
    }

    if( FD_UNLIKELY( !WIFEXITED( wstatus ) ) ) FD_LOG_ERR(( "perf report exited unexpectedly with signal %d (%s)", WTERMSIG( wstatus ), fd_io_strsignal( WTERMSIG( wstatus ) ) ));
    if( FD_UNLIKELY( WEXITSTATUS( wstatus ) ) ) FD_LOG_ERR(( "perf report exited unexpectedly with code %d", WEXITSTATUS( wstatus ) ));
    break;
  }

  fd_sys_util_exit_group( 0 );
}

action_t fd_action_flame = {
  .name          = "flame",
  .args          = flame_cmd_args,
  .fn            = flame_cmd_fn,
  .perm          = flame_cmd_perm,
  .description   = "Capture a perf flamegraph",
  .is_diagnostic = 1
};
