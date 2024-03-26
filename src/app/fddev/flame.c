#define _GNU_SOURCE
#include "fddev.h"
#include "../../util/net/fd_pcap.h"

#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>

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
flame_cmd_perm( args_t *         args,
                fd_caps_ctx_t *  caps,
                config_t * const config ) {
  (void)args;
  (void)config;

  fd_caps_check_root( caps, "flame", "read system performance counters with `/usr/bin/perf`" );
}

void
flame_cmd_args( int *    pargc,
                char *** pargv,
                args_t * args ) {

  if( FD_UNLIKELY( !*pargc ) ) FD_LOG_ERR(( "usage: flame [all|tile|tile:idx]" ));
  strncpy( args->flame.name, **pargv, sizeof( args->flame.name ) - 1 );

  (*pargc)--;
  (*pargv)++;
}

void
flame_cmd_fn( args_t *         args,
              config_t * const config ) {
  install_parent_signals();

  fd_topo_join_workspaces( &config->topo, FD_SHMEM_JOIN_MODE_READ_ONLY );
  fd_topo_fill( &config->topo );

  ulong tile_cnt = 0UL;
  ulong tile_idxs[ 128UL ];

  if( FD_UNLIKELY( !strcmp( "all", args->flame.name ) ) ) {
    FD_TEST( config->topo.tile_cnt<sizeof(tile_idxs)/sizeof(tile_idxs[0]) );
    for( ulong i=0UL; i<config->topo.tile_cnt; i++ ) {
      tile_idxs[ tile_cnt ] = i;
      tile_cnt++;
    }
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

  char threads[ 256 ] = {0};
  ulong len = 0UL;
  for( ulong i=0UL; i<tile_cnt; i++ ) {
    if( FD_LIKELY( i!=0UL ) ) {
      FD_TEST( fd_cstr_printf_check( threads+len, sizeof(threads)-len, NULL, "," ) );
      len += 1UL;
    }

    ulong tid = fd_metrics_tile( config->topo.tiles[ tile_idxs[ i ] ].metrics )[ FD_METRICS_GAUGE_TILE_TID_OFF ];
    ulong pid = fd_metrics_tile( config->topo.tiles[ tile_idxs[ i ] ].metrics )[ FD_METRICS_GAUGE_TILE_PID_OFF ];

    FD_TEST( pid<=INT_MAX );
    if( FD_UNLIKELY( -1==kill( (int)pid, 0 ) ) ) {
      if( FD_UNLIKELY( errno==ESRCH ) ) FD_LOG_ERR(( "tile %s:%lu is not running", config->topo.tiles[ i ].name, config->topo.tiles[ i ].kind_id ));
      else                              FD_LOG_ERR(( "kill() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    }

    ulong arg_len;
    FD_TEST( fd_cstr_printf_check( threads+len, sizeof(threads)-len, &arg_len, "%lu", tid ) );
    len += arg_len;
  }
  FD_TEST( len<sizeof(threads) );

  FD_LOG_NOTICE(( "/usr/bin/perf script record flamegraph -o - -F 99 -t %s | /usr/bin/perf script report flamegraph -i -", threads ));

  int pipefd[ 2 ];
  if( FD_UNLIKELY( -1==pipe( pipefd ) ) ) FD_LOG_ERR(( "pipe() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  record_pid = fork();
  if( FD_UNLIKELY( -1==record_pid ) ) FD_LOG_ERR(( "fork() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_LIKELY( !record_pid ) ) {
    if( FD_UNLIKELY( -1==close( pipefd[ 0 ] ) ) ) FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    if( FD_UNLIKELY( -1==dup2( pipefd[ 1 ], STDOUT_FILENO ) ) ) FD_LOG_ERR(( "dup2() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    if( FD_UNLIKELY( -1==close( pipefd[ 1 ] ) ) ) FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

    char * args[ 11 ] = {
      "/usr/bin/perf",
      "script",
      "record",
      "flamegraph",
      "-o",
      "-",
      "-F",
      "99",
      "-t",
      threads,
      NULL,
    };
    if( FD_UNLIKELY( -1==execve( "/usr/bin/perf", (char * const *)args, NULL ) ) ) FD_LOG_ERR(( "execve() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  int report_pid = fork();
  if( FD_UNLIKELY( -1==report_pid ) ) FD_LOG_ERR(( "fork() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_LIKELY( !report_pid ) ) {
    if( FD_UNLIKELY( -1==close( pipefd[ 1 ] ) ) ) FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    if( FD_UNLIKELY( -1==dup2( pipefd[ 0 ], STDIN_FILENO ) ) ) FD_LOG_ERR(( "dup2() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    if( FD_UNLIKELY( -1==close( pipefd[ 0 ] ) ) ) FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    if( FD_UNLIKELY( -1==setpgid( 0, 0 ) ) ) FD_LOG_ERR(( "setpgid() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

    char * args[ 7 ] = {
      "/usr/bin/perf",
      "script",
      "report",
      "flamegraph",
      "-i",
      "-",
      NULL,
    };
    if( FD_UNLIKELY( -1==execve( "/usr/bin/perf", (char * const *)args, NULL ) ) ) FD_LOG_ERR(( "execve() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  if( FD_UNLIKELY( -1==close( pipefd[ 0 ] ) ) ) FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( -1==close( pipefd[ 1 ] ) ) ) FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  FD_LOG_NOTICE(( "Perf collection running. Send SIGINT / Crl+C to stop." ));

  ulong exited_cnt = 0UL;
  while( FD_UNLIKELY( exited_cnt<2UL ) ) {
    int wstatus;
    int exited_pid = waitpid( -1, &wstatus, 0 );
    if( FD_UNLIKELY( -1==exited_pid ) ) {
      if( FD_LIKELY( errno==EAGAIN || errno==EINTR ) ) continue;
      FD_LOG_ERR(( "waitpid() failed (%d-%s)", errno, fd_io_strerror( errno ) ));
    }

    char const * process_name = exited_pid==record_pid ? "record" : "report";

    int record_graceful = exited_pid==record_pid && !WIFEXITED( wstatus ) && WTERMSIG( wstatus )==SIGINT;

    if( FD_UNLIKELY( !WIFEXITED( wstatus ) && !record_graceful ) ) FD_LOG_ERR(( "perf %s exited unexpectedly with signal %d (%s)", process_name, WTERMSIG( wstatus ), fd_io_strsignal( WTERMSIG( wstatus ) ) ));
    if( FD_UNLIKELY( WEXITSTATUS( wstatus ) && !record_graceful ) ) FD_LOG_ERR(( "perf %s exited unexpectedly with code %d", process_name, WEXITSTATUS( wstatus ) ));

    exited_cnt++;
  }

  exit_group( 0 );
}
