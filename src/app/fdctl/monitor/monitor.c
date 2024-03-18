#include "../fdctl.h"

#include "generated/monitor_seccomp.h"
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
  ulong pid;
  long  cnc_heartbeat;
  ulong cnc_signal;

  ulong in_backp;
  ulong backp_cnt;

  ulong housekeeping_ticks;
  ulong backpressure_ticks;
  ulong caught_up_ticks;
  ulong overrun_polling_ticks;
  ulong overrun_reading_ticks;
  ulong filter_before_frag_ticks;
  ulong filter_after_frag_ticks;
  ulong finish_ticks;
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

static ulong
tile_total_ticks( tile_snap_t * snap ) {
  return snap->housekeeping_ticks +
         snap->backpressure_ticks +
         snap->caught_up_ticks +
         snap->overrun_polling_ticks +
         snap->overrun_reading_ticks +
         snap->filter_before_frag_ticks +
         snap->filter_after_frag_ticks +
         snap->finish_ticks;
}

static void
tile_snap( tile_snap_t * snap_cur,     /* Snapshot for each tile, indexed [0,tile_cnt) */
           fd_topo_t *   topo ) {
  for( ulong tile_idx=0UL; tile_idx<topo->tile_cnt; tile_idx++ ) {
    tile_snap_t * snap = &snap_cur[ tile_idx ];

    fd_topo_tile_t * tile = &topo->tiles[ tile_idx ];
    snap->cnc_heartbeat = fd_cnc_heartbeat_query( tile->cnc );
    snap->cnc_signal    = fd_cnc_signal_query   ( tile->cnc );

    fd_metrics_register( tile->metrics );

    FD_COMPILER_MFENCE();
    snap->pid                      = FD_MGAUGE_GET( TILE, PID );
    snap->in_backp                 = FD_MGAUGE_GET( STEM, IN_BACKPRESSURE );
    snap->backp_cnt                = FD_MCNT_GET( STEM, BACKPRESSURE_COUNT );
    snap->housekeeping_ticks       = FD_MHIST_SUM( STEM, LOOP_HOUSEKEEPING_DURATION_SECONDS );
    snap->backpressure_ticks       = FD_MHIST_SUM( STEM, LOOP_BACKPRESSURE_DURATION_SECONDS );
    snap->caught_up_ticks          = FD_MHIST_SUM( STEM, LOOP_CAUGHT_UP_DURATION_SECONDS );
    snap->overrun_polling_ticks    = FD_MHIST_SUM( STEM, LOOP_OVERRUN_POLLING_DURATION_SECONDS );
    snap->overrun_reading_ticks    = FD_MHIST_SUM( STEM, LOOP_OVERRUN_READING_DURATION_SECONDS );
    snap->filter_before_frag_ticks = FD_MHIST_SUM( STEM, LOOP_FILTER_BEFORE_FRAGMENT_DURATION_SECONDS );
    snap->filter_after_frag_ticks  = FD_MHIST_SUM( STEM, LOOP_FILTER_AFTER_FRAGMENT_DURATION_SECONDS );
    snap->finish_ticks             = FD_MHIST_SUM( STEM, LOOP_FINISH_DURATION_SECONDS );
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

      ulong const * in_metrics = NULL;
      if( FD_LIKELY( topo->tiles[ tile_idx ].in_link_poll[ in_idx ] ) ) {
        in_metrics = (ulong const *)fd_metrics_link_in( topo->tiles[ tile_idx ].metrics, in_idx );
      }
      
      fd_topo_link_t * link = &topo->links[ topo->tiles[ tile_idx ].in_link_id[ in_idx ] ];
      ulong producer_id = fd_topo_find_link_producer( topo, link );
      ulong const * out_metrics = NULL;
      if( FD_LIKELY( producer_id!=ULONG_MAX && topo->tiles[ tile_idx ].in_link_reliable[ in_idx ] ) ) {
        fd_topo_tile_t * producer = &topo->tiles[ producer_id ];
        ulong out_idx;
        for( out_idx=0UL; out_idx<producer->out_cnt; out_idx++ ) {
          if( producer->out_link_id[ out_idx ]==link->id ) break;
        }
        out_metrics = fd_metrics_link_out( producer->metrics, out_idx );
      }
      FD_COMPILER_MFENCE();
      if( FD_LIKELY( in_metrics ) ) {
        snap->fseq_diag_tot_cnt   = in_metrics[ FD_METRICS_COUNTER_LINK_PUBLISHED_COUNT_OFF ];
        snap->fseq_diag_tot_sz    = in_metrics[ FD_METRICS_COUNTER_LINK_PUBLISHED_SIZE_BYTES_OFF ];
        snap->fseq_diag_filt_cnt  = in_metrics[ FD_METRICS_COUNTER_LINK_FILTERED_COUNT_OFF ];
        snap->fseq_diag_filt_sz   = in_metrics[ FD_METRICS_COUNTER_LINK_FILTERED_SIZE_BYTES_OFF ];
        snap->fseq_diag_ovrnp_cnt = in_metrics[ FD_METRICS_COUNTER_LINK_OVERRUN_POLLING_COUNT_OFF ];
        snap->fseq_diag_ovrnr_cnt = in_metrics[ FD_METRICS_COUNTER_LINK_OVERRUN_READING_COUNT_OFF ];
      } else {
        snap->fseq_diag_tot_cnt   = 0UL;
        snap->fseq_diag_tot_sz    = 0UL;
        snap->fseq_diag_filt_cnt  = 0UL;
        snap->fseq_diag_filt_sz   = 0UL;
        snap->fseq_diag_ovrnp_cnt = 0UL;
        snap->fseq_diag_ovrnr_cnt = 0UL;
      }

      if( FD_LIKELY( out_metrics ) )
        snap->fseq_diag_slow_cnt  = out_metrics[ FD_METRICS_COUNTER_LINK_SLOW_COUNT_OFF ];
      else
        snap->fseq_diag_slow_cnt  = 0UL;
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

#define FD_MONITOR_TEXT_BUF_SZ 65536
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

  /* Get the initial reference diagnostic snapshot */
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
    PRINT( "    tile |     pid |      stale | heart |        sig | in backp |           backp cnt |  %% hkeep |  %% backp |   %% wait |  %% ovrnp |  %% ovrnr |  %% filt1 |  %% filt2 | %% finish" TEXT_NEWLINE );
    PRINT( "---------+---------+------------+-------+------------+----------+---------------------+----------+----------+----------+----------+----------+----------+----------+----------" TEXT_NEWLINE );
    for( ulong tile_idx=0UL; tile_idx<topo->tile_cnt; tile_idx++ ) {
      tile_snap_t * prv = &tile_snap_prv[ tile_idx ];
      tile_snap_t * cur = &tile_snap_cur[ tile_idx ];
      PRINT( " %7s", topo->tiles[ tile_idx ].name );
      PRINT( " | %7lu", cur->pid );
      PRINT( " | " ); printf_stale   ( &buf, &buf_sz, (long)(0.5+ns_per_tic*(double)(toc - cur->cnc_heartbeat)), 1e8 /* 100 millis */ );
      PRINT( " | " ); printf_heart   ( &buf, &buf_sz, cur->cnc_heartbeat, prv->cnc_heartbeat        );
      PRINT( " | " ); printf_sig     ( &buf, &buf_sz, cur->cnc_signal,    prv->cnc_signal           );
      PRINT( " | " ); printf_err_bool( &buf, &buf_sz, cur->in_backp,      prv->in_backp             );
      PRINT( " | " ); printf_err_cnt ( &buf, &buf_sz, cur->backp_cnt,     prv->backp_cnt            );

      PRINT( " | " ); printf_pct( &buf, &buf_sz, cur->housekeeping_ticks,       prv->housekeeping_ticks,       0., tile_total_ticks( cur ), tile_total_ticks( prv ), DBL_MIN );
      PRINT( " | " ); printf_pct( &buf, &buf_sz, cur->backpressure_ticks,       prv->backpressure_ticks,       0., tile_total_ticks( cur ), tile_total_ticks( prv ), DBL_MIN );
      PRINT( " | " ); printf_pct( &buf, &buf_sz, cur->caught_up_ticks,          prv->caught_up_ticks,          0., tile_total_ticks( cur ), tile_total_ticks( prv ), DBL_MIN );
      PRINT( " | " ); printf_pct( &buf, &buf_sz, cur->overrun_polling_ticks,    prv->overrun_polling_ticks,    0., tile_total_ticks( cur ), tile_total_ticks( prv ), DBL_MIN );
      PRINT( " | " ); printf_pct( &buf, &buf_sz, cur->overrun_reading_ticks,    prv->overrun_reading_ticks,    0., tile_total_ticks( cur ), tile_total_ticks( prv ), DBL_MIN );
      PRINT( " | " ); printf_pct( &buf, &buf_sz, cur->filter_before_frag_ticks, prv->filter_before_frag_ticks, 0., tile_total_ticks( cur ), tile_total_ticks( prv ), DBL_MIN );
      PRINT( " | " ); printf_pct( &buf, &buf_sz, cur->filter_after_frag_ticks , prv->filter_after_frag_ticks,  0., tile_total_ticks( cur ), tile_total_ticks( prv ), DBL_MIN );
      PRINT( " | " ); printf_pct( &buf, &buf_sz, cur->finish_ticks,             prv->finish_ticks,             0., tile_total_ticks( cur ), tile_total_ticks( prv ), DBL_MIN );
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

        fd_topo_link_t * link = &topo->links[ topo->tiles[ tile_idx ].in_link_id[ in_idx ] ];
        ulong producer_tile_id = fd_topo_find_link_producer( topo, link );
        FD_TEST( producer_tile_id != ULONG_MAX );
        char const * producer = topo->tiles[ producer_tile_id ].name;
        PRINT( " %7s->%-7s", producer, topo->tiles[ tile_idx ].name );
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
       swapping the two snap arrays. */
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

  int allow_fds[ 4 ];
  ulong allow_fds_cnt = 0;
  allow_fds[ allow_fds_cnt++ ] = 1; /* stdout */
  allow_fds[ allow_fds_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( fd_log_private_logfile_fd()!=-1 ) )
    allow_fds[ allow_fds_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  if( FD_UNLIKELY( args->monitor.drain_output_fd!=-1 ) )
    allow_fds[ allow_fds_cnt++ ] = args->monitor.drain_output_fd; /* maybe we are interposing firedancer log output with the monitor */

  fd_topo_join_workspaces( &config->topo, FD_SHMEM_JOIN_MODE_READ_ONLY );

  struct sock_filter seccomp_filter[ 128UL ];
  uint drain_output_fd = args->monitor.drain_output_fd >= 0 ? (uint)args->monitor.drain_output_fd : (uint)-1;
  populate_sock_filter_policy_monitor( 128UL, seccomp_filter, (uint)fd_log_private_logfile_fd(), drain_output_fd );

  if( FD_UNLIKELY( close( STDIN_FILENO ) ) ) FD_LOG_ERR(( "close(0) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( close( config->log.lock_fd ) ) ) FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  fd_sandbox( config->development.sandbox,
              config->uid,
              config->gid,
              0,
              allow_fds_cnt,
              allow_fds,
              sock_filter_policy_monitor_instr_cnt,
              seccomp_filter );

  fd_topo_fill( &config->topo );

  run_monitor( config,
               args->monitor.drain_output_fd,
               args->monitor.dt_min,
               args->monitor.dt_max,
               args->monitor.duration,
               args->monitor.seed,
               args->monitor.ns_per_tic );

  exit_group( 0 );
}
