#include "../fdctl.h"

#include "helper.h"
#include "../run/run.h"
#include "../run/tiles/tiles.h"
#include "../../../disco/fd_disco.h"

#include <stdio.h>
#include <signal.h>
#include <sys/syscall.h>
#include <linux/capability.h>

void
monitor_cmd_args( int *    pargc,
                  char *** pargv,
                  args_t * args ) {
  args->monitor.drain_output_fd = -1; /* only accessible to development commands, not the command line */
  args->monitor.dt_min          = fd_env_strip_cmdline_long( pargc, pargv, "--dt-min",   NULL,    6666667.          );
  args->monitor.dt_max          = fd_env_strip_cmdline_long( pargc, pargv, "--dt-max",   NULL,  133333333.          );
  args->monitor.duration        = fd_env_strip_cmdline_long( pargc, pargv, "--duration", NULL,          0.          );
  args->monitor.seed            = fd_env_strip_cmdline_uint( pargc, pargv, "--seed",     NULL, (uint)fd_tickcount() );
  args->monitor.ns_per_tic      = 1./fd_tempo_tick_per_ns( NULL ); /* calibrate during init */

  if( FD_UNLIKELY( args->monitor.dt_min<0L                   ) ) FD_LOG_ERR(( "--dt-min should be positive"          ));
  if( FD_UNLIKELY( args->monitor.dt_max<args->monitor.dt_min ) ) FD_LOG_ERR(( "--dt-max should be at least --dt-min" ));
  if( FD_UNLIKELY( args->monitor.duration<0L                 ) ) FD_LOG_ERR(( "--duration should be non-negative"    ));
}

void
monitor_cmd_perm( args_t *         args,
                  fd_caps_ctx_t *  caps,
                  config_t * const config ) {
  (void)args;

  ulong mlock_limit = fd_topo_mlock( &config->topo );
  fd_caps_check_resource( caps, "monitor", RLIMIT_MEMLOCK, mlock_limit, "increase `RLIMIT_MEMLOCK` to lock the workspace in memory with `mlock(2)`" );
  if( getuid() != config->uid )
    fd_caps_check_capability( caps, "monitor", CAP_SETUID, "switch uid by calling `setuid(2)`" );
  if( getgid() != config->gid )
    fd_caps_check_capability( caps, "monitor", CAP_SETGID, "switch gid by calling `setgid(2)`" );
}

typedef struct {
  long  cnc_heartbeat;
  ulong cnc_signal;

  ulong cnc_diag_pid;
  ulong cnc_diag_in_backp;
  ulong cnc_diag_backp_cnt;
  ulong cnc_diag_ha_filt_cnt;
  ulong cnc_diag_ha_filt_sz;
  ulong cnc_diag_sv_filt_cnt;
  ulong cnc_diag_sv_filt_sz;
} tile_snap_t;

typedef struct {
  ulong mcache_seq;

  ulong fseq_seq;

  ulong fseq_diag_tot_cnt;
  ulong fseq_diag_tot_sz;
  ulong fseq_diag_filt_cnt;
  ulong fseq_diag_filt_sz;
  ulong fseq_diag_ovrnp_cnt;
  ulong fseq_diag_ovrnr_cnt;
  ulong fseq_diag_slow_cnt;
} link_snap_t;

static void
tile_snap( tile_snap_t * snap_cur,     /* Snaphot for each tile, indexed [0,tile_cnt) */
           fd_topo_t *   topo ) {
  for( ulong tile_idx=0UL; tile_idx<topo->tile_cnt; tile_idx++ ) {
    tile_snap_t * snap = &snap_cur[ tile_idx ];

    fd_cnc_t const * cnc = topo->tiles[ tile_idx ].cnc;
    snap->cnc_heartbeat = fd_cnc_heartbeat_query( cnc );
    snap->cnc_signal    = fd_cnc_signal_query   ( cnc );
    ulong const * cnc_diag = (ulong const *)fd_cnc_app_laddr_const( cnc );
    FD_COMPILER_MFENCE();
    snap->cnc_diag_pid         = cnc_diag[ FD_APP_CNC_DIAG_PID         ];
    snap->cnc_diag_in_backp    = cnc_diag[ FD_APP_CNC_DIAG_IN_BACKP    ];
    snap->cnc_diag_backp_cnt   = cnc_diag[ FD_APP_CNC_DIAG_BACKP_CNT   ];
    snap->cnc_diag_ha_filt_cnt = cnc_diag[ FD_APP_CNC_DIAG_HA_FILT_CNT ];
    snap->cnc_diag_ha_filt_sz  = cnc_diag[ FD_APP_CNC_DIAG_HA_FILT_SZ  ];
    snap->cnc_diag_sv_filt_cnt = cnc_diag[ FD_APP_CNC_DIAG_SV_FILT_CNT ];
    snap->cnc_diag_sv_filt_sz  = cnc_diag[ FD_APP_CNC_DIAG_SV_FILT_SZ  ];
    FD_COMPILER_MFENCE();
  }
}

static void
link_snap( link_snap_t * snap_cur,
           fd_topo_t *   topo ) {
  ulong link_idx = 0UL;
  for( ulong tile_idx=0UL; tile_idx<topo->tile_cnt; tile_idx++ ) {
    for( ulong in_idx=0UL; in_idx<topo->tiles[ tile_idx ].in_cnt; in_idx++ ) {
      link_snap_t * snap = &snap_cur[ link_idx ];
      fd_frag_meta_t const * mcache = topo->links[ topo->tiles[ tile_idx ].in_link_id[ in_idx  ] ].mcache;
      ulong const * seq = (ulong const *)fd_mcache_seq_laddr_const( mcache );
      snap->mcache_seq = fd_mcache_seq_query( seq );

      ulong const * fseq = topo->tiles[ tile_idx ].in_link_fseq[ in_idx ];
      snap->fseq_seq = fd_fseq_query( fseq );
      ulong const * fseq_diag = (ulong const *)fd_fseq_app_laddr_const( fseq );
      FD_COMPILER_MFENCE();
      snap->fseq_diag_tot_cnt   = fseq_diag[ FD_FSEQ_DIAG_PUB_CNT   ];
      snap->fseq_diag_tot_sz    = fseq_diag[ FD_FSEQ_DIAG_PUB_SZ    ];
      snap->fseq_diag_filt_cnt  = fseq_diag[ FD_FSEQ_DIAG_FILT_CNT  ];
      snap->fseq_diag_filt_sz   = fseq_diag[ FD_FSEQ_DIAG_FILT_SZ   ];
      snap->fseq_diag_ovrnp_cnt = fseq_diag[ FD_FSEQ_DIAG_OVRNP_CNT ];
      snap->fseq_diag_ovrnr_cnt = fseq_diag[ FD_FSEQ_DIAG_OVRNR_CNT ];
      snap->fseq_diag_slow_cnt  = fseq_diag[ FD_FSEQ_DIAG_SLOW_CNT  ];
      FD_COMPILER_MFENCE();
      snap->fseq_diag_tot_cnt += snap->fseq_diag_filt_cnt;
      snap->fseq_diag_tot_sz  += snap->fseq_diag_filt_sz;
      link_idx++;
    }
  }
}

/**********************************************************************/

static void write_stdout( char * buf, ulong buf_sz ) {
  ulong written = 0;
  ulong total = buf_sz;
  while( written < total ) {
    long n = write( STDOUT_FILENO, buf + written, total - written );
    if( FD_UNLIKELY( n < 0 ) ) {
      if( errno == EINTR ) continue;
      FD_LOG_ERR(( "error writing to stdout (%i-%s)", errno, fd_io_strerror( errno ) ));
    }
    written += (ulong)n;
  }
}

static int stop1 = 0;

#define FD_MONITOR_TEXT_BUF_SZ 32768
char buffer[ FD_MONITOR_TEXT_BUF_SZ ];
char buffer2[ FD_MONITOR_TEXT_BUF_SZ ];

static void
drain_to_buffer( char ** buf,
                 ulong * buf_sz,
                 int fd ) {
  while(1) {
    long nread = read( fd, buffer2, *buf_sz );
    if( FD_LIKELY( nread == -1 && errno == EAGAIN ) ) break; /* no data available */
    else if( FD_UNLIKELY( nread == -1 ) ) FD_LOG_ERR(( "read() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

    char * ptr = buffer2;
    char * next;
    while(( next = memchr( ptr, '\n', (ulong)nread - (ulong)(ptr - buffer2) ))) {
      ulong len = (ulong)(next - ptr);
      if( FD_UNLIKELY( *buf_sz < len ) ) {
        write_stdout( buffer, FD_MONITOR_TEXT_BUF_SZ - *buf_sz );
        *buf = buffer;
        *buf_sz = FD_MONITOR_TEXT_BUF_SZ;
      }
      fd_memcpy( *buf, ptr, len );
      *buf += len;
      *buf_sz -= len;

      if( FD_UNLIKELY( *buf_sz < sizeof(TEXT_NEWLINE)-1 ) ) {
        write_stdout( buffer, FD_MONITOR_TEXT_BUF_SZ - *buf_sz );
        *buf = buffer;
        *buf_sz = FD_MONITOR_TEXT_BUF_SZ;
      }
      fd_memcpy( *buf, TEXT_NEWLINE, sizeof(TEXT_NEWLINE)-1 );
      *buf += sizeof(TEXT_NEWLINE)-1;
      *buf_sz -= sizeof(TEXT_NEWLINE)-1;

      ptr = next + 1;
    }
  }
}

void
run_monitor( config_t * const config,
             int              drain_output_fd,
             long             dt_min,
             long             dt_max,
             long             duration,
             uint             seed,
             double           ns_per_tic ) {
  fd_topo_t * topo = &config->topo;

  /* Setup local objects used by this app */
  fd_rng_t _rng[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, seed, 0UL ) );

  tile_snap_t * tile_snap_prv = (tile_snap_t *)fd_alloca( alignof(tile_snap_t), sizeof(tile_snap_t)*2UL*topo->tile_cnt );
  if( FD_UNLIKELY( !tile_snap_prv ) ) FD_LOG_ERR(( "fd_alloca failed" )); /* Paranoia */
  tile_snap_t * tile_snap_cur = tile_snap_prv + topo->tile_cnt;

  ulong link_cnt = 0UL;
  for( ulong tile_idx=0UL; tile_idx<topo->tile_cnt; tile_idx++ ) link_cnt += topo->tiles[ tile_idx ].in_cnt;
  link_snap_t * link_snap_prv = (link_snap_t *)fd_alloca( alignof(link_snap_t), sizeof(link_snap_t)*2UL*link_cnt );
  if( FD_UNLIKELY( !link_snap_prv ) ) FD_LOG_ERR(( "fd_alloca failed" )); /* Paranoia */
  link_snap_t * link_snap_cur = link_snap_prv + link_cnt;

  /* Get the inital reference diagnostic snapshot */
  tile_snap( tile_snap_prv, topo );
  link_snap( link_snap_prv, topo );
  long then; long tic; fd_tempo_observe_pair( &then, &tic );

  /* Monitor for duration ns.  Note that for duration==0, this
     will still do exactly one pretty print. */
  FD_LOG_NOTICE(( "monitoring --dt-min %li ns, --dt-max %li ns, --duration %li ns, --seed %u", dt_min, dt_max, duration, seed ));

  long stop = then + duration;
  if( duration == 0 ) stop = LONG_MAX;

#define PRINT( ... ) do {                                                       \
    int n = snprintf( buf, buf_sz, __VA_ARGS__ );                               \
    if( FD_UNLIKELY( n<0 ) ) FD_LOG_ERR(( "snprintf failed" ));                 \
    if( FD_UNLIKELY( (ulong)n>=buf_sz ) ) FD_LOG_ERR(( "snprintf truncated" )); \
    buf += n; buf_sz -= (ulong)n;                                               \
  } while(0)

  ulong line_count = 0;
  for(;;) {
    /* Wait a somewhat randomized amount and then make a diagnostic
       snapshot */
    fd_log_wait_until( then + dt_min + (long)fd_rng_ulong_roll( rng, 1UL+(ulong)(dt_max-dt_min) ) );

    tile_snap( tile_snap_cur, topo );
    link_snap( link_snap_cur, topo );
    long now; long toc; fd_tempo_observe_pair( &now, &toc );

    /* Pretty print a comparison between this diagnostic snapshot and
       the previous one. */

    char * buf = buffer;
    ulong buf_sz = FD_MONITOR_TEXT_BUF_SZ;

    /* move to beginning of line, n lines ago */
    PRINT( "\033[%luF", line_count );

    /* drain any firedancer log messages into the terminal */
    if( FD_UNLIKELY( drain_output_fd >= 0 ) ) drain_to_buffer( &buf, &buf_sz, drain_output_fd );
    if( FD_UNLIKELY( buf_sz < FD_MONITOR_TEXT_BUF_SZ / 2 ) ) {
      /* make sure there's enough space to print the whole monitor in one go */
      write_stdout( buffer, FD_MONITOR_TEXT_BUF_SZ - buf_sz );
      buf = buffer;
      buf_sz = FD_MONITOR_TEXT_BUF_SZ;
    }

    char * mon_start = buf;
    if( FD_UNLIKELY( drain_output_fd >= 0 ) ) PRINT( TEXT_NEWLINE );

    char now_cstr[ FD_LOG_WALLCLOCK_CSTR_BUF_SZ ];
    PRINT( "snapshot for %s" TEXT_NEWLINE, fd_log_wallclock_cstr( now, now_cstr ) );
    PRINT( "    tile |     pid |      stale | heart |        sig | in backp |           backp cnt |         sv_filt cnt " TEXT_NEWLINE );
    PRINT( "---------+---------+------------+-------+------------+----------+---------------------+---------------------" TEXT_NEWLINE );
    for( ulong tile_idx=0UL; tile_idx<topo->tile_cnt; tile_idx++ ) {
      tile_snap_t * prv = &tile_snap_prv[ tile_idx ];
      tile_snap_t * cur = &tile_snap_cur[ tile_idx ];
      PRINT( " %7s", fd_topo_tile_kind_str( topo->tiles[ tile_idx ].kind ) );
      PRINT( " | %7lu", cur->cnc_diag_pid );
      PRINT( " | " ); printf_stale   ( &buf, &buf_sz, (long)(0.5+ns_per_tic*(double)(toc - cur->cnc_heartbeat)), 1e8 /* 100 millis */ );
      PRINT( " | " ); printf_heart   ( &buf, &buf_sz, cur->cnc_heartbeat,        prv->cnc_heartbeat        );
      PRINT( " | " ); printf_sig     ( &buf, &buf_sz, cur->cnc_signal,           prv->cnc_signal           );
      PRINT( " | " ); printf_err_bool( &buf, &buf_sz, cur->cnc_diag_in_backp,    prv->cnc_diag_in_backp    );
      PRINT( " | " ); printf_err_cnt ( &buf, &buf_sz, cur->cnc_diag_backp_cnt,   prv->cnc_diag_backp_cnt   );
      PRINT( " | " ); printf_err_cnt ( &buf, &buf_sz, cur->cnc_diag_sv_filt_cnt, prv->cnc_diag_sv_filt_cnt );
      PRINT( TEXT_NEWLINE );
    }
    PRINT( TEXT_NEWLINE );
    PRINT( "             link |  tot TPS |  tot bps | uniq TPS | uniq bps |   ha tr%% | uniq bw%% | filt tr%% | filt bw%% |           ovrnp cnt |           ovrnr cnt |            slow cnt |             tx seq" TEXT_NEWLINE );
    PRINT( "------------------+----------+----------+----------+----------+----------+----------+----------+----------+---------------------+---------------------+---------------------+-------------------" TEXT_NEWLINE );
    long dt = now-then;

    ulong link_idx = 0UL;
    for( ulong tile_idx=0UL; tile_idx<topo->tile_cnt; tile_idx++ ) {
      for( ulong in_idx=0UL; in_idx<topo->tiles[ tile_idx ].in_cnt; in_idx++ ) {
        link_snap_t * prv = &link_snap_prv[ link_idx ];
        link_snap_t * cur = &link_snap_cur[ link_idx ];
        PRINT( " %7s->%-7s", fd_topo_tile_kind_str( topo->tiles[ fd_topo_find_link_producer( topo, &topo->links[ topo->tiles[ tile_idx ].in_link_id[ in_idx ] ] ) ].kind ), fd_topo_tile_kind_str( topo->tiles[ tile_idx ].kind ) );
        ulong cur_raw_cnt = /* cur->cnc_diag_ha_filt_cnt + */ cur->fseq_diag_tot_cnt;
        ulong cur_raw_sz  = /* cur->cnc_diag_ha_filt_sz  + */ cur->fseq_diag_tot_sz;
        ulong prv_raw_cnt = /* prv->cnc_diag_ha_filt_cnt + */ prv->fseq_diag_tot_cnt;
        ulong prv_raw_sz  = /* prv->cnc_diag_ha_filt_sz  + */ prv->fseq_diag_tot_sz;

        PRINT( " | " ); printf_rate( &buf, &buf_sz, 1e9, 0., cur_raw_cnt,             prv_raw_cnt,             dt );
        PRINT( " | " ); printf_rate( &buf, &buf_sz, 8e9, 0., cur_raw_sz,              prv_raw_sz,              dt ); /* Assumes sz incl framing */
        PRINT( " | " ); printf_rate( &buf, &buf_sz, 1e9, 0., cur->fseq_diag_tot_cnt,  prv->fseq_diag_tot_cnt,  dt );
        PRINT( " | " ); printf_rate( &buf, &buf_sz, 8e9, 0., cur->fseq_diag_tot_sz,   prv->fseq_diag_tot_sz,   dt ); /* Assumes sz incl framing */

        PRINT( " | " ); printf_pct ( &buf, &buf_sz, cur->fseq_diag_tot_cnt,  prv->fseq_diag_tot_cnt, 0.,
                                    cur_raw_cnt,             prv_raw_cnt,            DBL_MIN );
        PRINT( " | " ); printf_pct ( &buf, &buf_sz, cur->fseq_diag_tot_sz,   prv->fseq_diag_tot_sz,  0.,
                                    cur_raw_sz,              prv_raw_sz,             DBL_MIN ); /* Assumes sz incl framing */
        PRINT( " | " ); printf_pct ( &buf, &buf_sz, cur->fseq_diag_filt_cnt, prv->fseq_diag_filt_cnt, 0.,
                                    cur->fseq_diag_tot_cnt,  prv->fseq_diag_tot_cnt,  DBL_MIN );
        PRINT( " | " ); printf_pct ( &buf, &buf_sz, cur->fseq_diag_filt_sz,  prv->fseq_diag_filt_sz, 0.,
                                    cur->fseq_diag_tot_sz,   prv->fseq_diag_tot_sz,  DBL_MIN ); /* Assumes sz incl framing */

        PRINT( " | " ); printf_err_cnt( &buf, &buf_sz, cur->fseq_diag_ovrnp_cnt, prv->fseq_diag_ovrnp_cnt );
        PRINT( " | " ); printf_err_cnt( &buf, &buf_sz, cur->fseq_diag_ovrnr_cnt, prv->fseq_diag_ovrnr_cnt );
        PRINT( " | " ); printf_err_cnt( &buf, &buf_sz, cur->fseq_diag_slow_cnt,  prv->fseq_diag_slow_cnt  );
        PRINT( " | " ); printf_seq(     &buf, &buf_sz, cur->mcache_seq,          prv->mcache_seq  );
        PRINT( TEXT_NEWLINE );
        link_idx++;
      }
    }

    /* write entire monitor output buffer */
    write_stdout( buffer, sizeof(buffer) - buf_sz );

    if( FD_UNLIKELY( stop1 || (now-stop)>=0L ) ) {
      /* Stop once we've been monitoring for duration ns */
      break;
    }

    /* Still more monitoring to do ... wind up for the next iteration by
       swaping the two snap arrays. */
    line_count = 0;
    for ( ulong i=(ulong)(mon_start-buffer); i<sizeof(buffer) - buf_sz; i++ ) {
      if( buffer[i] == '\n' ) line_count++;
    }

    then = now; tic = toc;
    tile_snap_t * tmp = tile_snap_prv; tile_snap_prv = tile_snap_cur; tile_snap_cur = tmp;
    link_snap_t * tmp2 = link_snap_prv; link_snap_prv = link_snap_cur; link_snap_cur = tmp2;
  }
}

static void
signal1( int sig ) {
  (void)sig;
  exit_group( 0 );
}

void
monitor_cmd_fn( args_t *         args,
                config_t * const config ) {
  struct sigaction sa = {
    .sa_handler = signal1,
    .sa_flags   = 0,
  };
  if( FD_UNLIKELY( sigaction( SIGTERM, &sa, NULL ) ) )
    FD_LOG_ERR(( "sigaction(SIGTERM) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( sigaction( SIGINT, &sa, NULL ) ) )
    FD_LOG_ERR(( "sigaction(SIGINT) failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  long allow_syscalls[] = {
    __NR_write,        /* logging */
    __NR_fsync,        /* logging, WARNING and above fsync immediately */
    __NR_nanosleep,    /* fd_log_wait_until */
    __NR_sched_yield,  /* fd_log_wait_until */
    __NR_exit_group,   /* exit process */
    __NR_read,         /* read from firedancer stdout to interpose their log messages */
  };

  int allow_fds[] = {
    1, /* stdout */
    2, /* stderr */
    3, /* logfile */
    args->monitor.drain_output_fd, /* maybe we are interposing firedancer log output with the monitor */
  };

  ulong num_fds = sizeof(allow_fds)/sizeof(allow_fds[0]);
  ushort num_syscalls = sizeof(allow_syscalls)/sizeof(allow_syscalls[0]);

  ulong allow_fds_sz = args->monitor.drain_output_fd >= 0 ? num_fds : num_fds - 1;
  ushort allow_syscalls_cnt = args->monitor.drain_output_fd >= 0 ? num_syscalls : (ushort)(num_syscalls - 1);

  /* join all workspaces needed by the toplogy before sandboxing, so
     we can access them later */
  fd_topo_join_workspaces( config->name, &config->topo );

  if( FD_UNLIKELY( close( 0 ) ) ) FD_LOG_ERR(( "close(0) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  fd_sandbox( config->development.sandbox,
              config->uid,
              config->gid,
              allow_fds_sz,
              allow_fds,
              allow_syscalls_cnt,
              allow_syscalls );

  fd_topo_fill( &config->topo, FD_TOPO_FILL_MODE_FOOTPRINT );
  fd_topo_fill( &config->topo, FD_TOPO_FILL_MODE_JOIN );

  run_monitor( config,
               args->monitor.drain_output_fd,
               args->monitor.dt_min,
               args->monitor.dt_max,
               args->monitor.duration,
               args->monitor.seed,
               args->monitor.ns_per_tic );

  exit_group( 0 );
}
