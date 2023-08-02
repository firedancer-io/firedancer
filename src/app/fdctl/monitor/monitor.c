#include "../fdctl.h"

#include "helper.h"
#include "../run.h"
#include "../../../disco/fd_disco.h"

#include <stdio.h>
#include <signal.h>
#include <sys/syscall.h>
#include <linux/capability.h>

void
monitor_cmd_args( int *    pargc,
                  char *** pargv,
                  args_t * args ) {
  args->monitor.dt_min     = fd_env_strip_cmdline_long( pargc, pargv, "--dt-min",   NULL,   66666667.          );
  args->monitor.dt_max     = fd_env_strip_cmdline_long( pargc, pargv, "--dt-max",   NULL, 1333333333.          );
  args->monitor.duration   = fd_env_strip_cmdline_long( pargc, pargv, "--duration", NULL,          0.          );
  args->monitor.seed       = fd_env_strip_cmdline_uint( pargc, pargv, "--seed",     NULL, (uint)fd_tickcount() );
  args->monitor.ns_per_tic = 1./fd_tempo_tick_per_ns( NULL ); /* calibrate during init */

  if( FD_UNLIKELY( args->monitor.dt_min<0L                   ) ) FD_LOG_ERR(( "--dt-min should be positive"          ));
  if( FD_UNLIKELY( args->monitor.dt_max<args->monitor.dt_min ) ) FD_LOG_ERR(( "--dt-max should be at least --dt-min" ));
  if( FD_UNLIKELY( args->monitor.duration<0L                 ) ) FD_LOG_ERR(( "--duration should be non-negative"    ));
}

void
monitor_cmd_perm( args_t *         args,
                  security_t *     security,
                  config_t * const config ) {
  (void)args;

  ulong limit = memlock_max_bytes( config );
  check_res( security, "monitor", RLIMIT_MEMLOCK, limit, "increase `RLIMIT_MEMLOCK` to lock the workspace in memory with `mlock(2)`" );
  if( getuid() != config->uid )
    check_cap( security, "monitor", CAP_SETUID, "switch uid by calling `setuid(2)`" );
  if( getgid() != config->gid )
    check_cap( security, "monitor", CAP_SETGID, "switch gid by calling `setgid(2)`" );
}

/* snap reads all the IPC diagnostics in a frank instance and stores
   them into the easy to process structure snap */

struct snap {
  ulong pmap; /* Bit {0,1,2} set <> {cnc,mcache,fseq} values are valid */

  long  cnc_heartbeat;
  ulong cnc_signal;

  ulong cnc_diag_in_backp;
  ulong cnc_diag_backp_cnt;
  ulong cnc_diag_ha_filt_cnt;
  ulong cnc_diag_ha_filt_sz;
  ulong cnc_diag_sv_filt_cnt;
  ulong cnc_diag_sv_filt_sz;

  ulong mcache_seq;

  ulong fseq_seq;

  ulong fseq_diag_tot_cnt;
  ulong fseq_diag_tot_sz;
  ulong fseq_diag_filt_cnt;
  ulong fseq_diag_filt_sz;
  ulong fseq_diag_ovrnp_cnt;
  ulong fseq_diag_ovrnr_cnt;
  ulong fseq_diag_slow_cnt;
};

typedef struct snap snap_t;

static void
snap( ulong             tile_cnt,     /* Number of tiles to snapshot */
      snap_t *          snap_cur,     /* Snaphot for each tile, indexed [0,tile_cnt) */
      fd_cnc_t **       tile_cnc,     /* Local cnc    joins for each tile, NULL if n/a, indexed [0,tile_cnt) */
      fd_frag_meta_t ** tile_mcache,  /* Local mcache joins for each tile, NULL if n/a, indexed [0,tile_cnt) */
      ulong **          tile_fseq ) { /* Local fseq   joins for each tile, NULL if n/a, indexed [0,tile_cnt) */

  for( ulong tile_idx=0UL; tile_idx<tile_cnt; tile_idx++ ) {
    snap_t * snap = &snap_cur[ tile_idx ];

    ulong pmap = 0UL;

    fd_cnc_t const * cnc = tile_cnc[ tile_idx ];
    if( FD_LIKELY( cnc ) ) {
      snap->cnc_heartbeat = fd_cnc_heartbeat_query( cnc );
      snap->cnc_signal    = fd_cnc_signal_query   ( cnc );
      ulong const * cnc_diag = (ulong const *)fd_cnc_app_laddr_const( cnc );
      FD_COMPILER_MFENCE();
      snap->cnc_diag_in_backp    = cnc_diag[ FD_FRANK_CNC_DIAG_IN_BACKP    ];
      snap->cnc_diag_backp_cnt   = cnc_diag[ FD_FRANK_CNC_DIAG_BACKP_CNT   ];
      snap->cnc_diag_ha_filt_cnt = cnc_diag[ FD_FRANK_CNC_DIAG_HA_FILT_CNT ];
      snap->cnc_diag_ha_filt_sz  = cnc_diag[ FD_FRANK_CNC_DIAG_HA_FILT_SZ  ];
      snap->cnc_diag_sv_filt_cnt = cnc_diag[ FD_FRANK_CNC_DIAG_SV_FILT_CNT ];
      snap->cnc_diag_sv_filt_sz  = cnc_diag[ FD_FRANK_CNC_DIAG_SV_FILT_SZ  ];
      FD_COMPILER_MFENCE();

      pmap |= 1UL;
    }

    fd_frag_meta_t const * mcache = tile_mcache[ tile_idx ];
    if( FD_LIKELY( mcache ) ) {
      ulong const * seq = (ulong const *)fd_mcache_seq_laddr_const( mcache );
      snap->mcache_seq = fd_mcache_seq_query( seq );

      pmap |= 2UL;
    }

    ulong const * fseq = tile_fseq[ tile_idx ];
    if( FD_LIKELY( fseq ) ) {
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
      pmap |= 4UL;
    }

    snap->pmap = pmap;
  }
}

/**********************************************************************/

static void
printf_link( snap_t *      snap_prv,
             snap_t *      snap_cur,
             char const ** tile_name,
             ulong         src_tile_idx,
             ulong         dst_tile_idx,
             long          dt ) {
  snap_t * prv = &snap_prv[ src_tile_idx ];
  snap_t * cur = &snap_cur[ src_tile_idx ];
  printf( " %6s->%-5s", tile_name[ src_tile_idx ], tile_name[ dst_tile_idx ] );
  ulong cur_raw_cnt = cur->cnc_diag_ha_filt_cnt + cur->fseq_diag_tot_cnt;
  ulong cur_raw_sz  = cur->cnc_diag_ha_filt_sz  + cur->fseq_diag_tot_sz;
  ulong prv_raw_cnt = prv->cnc_diag_ha_filt_cnt + prv->fseq_diag_tot_cnt;
  ulong prv_raw_sz  = prv->cnc_diag_ha_filt_sz  + prv->fseq_diag_tot_sz;

  printf( " | " ); printf_rate( 1e9, 0., cur_raw_cnt,             prv_raw_cnt,             dt );
  printf( " | " ); printf_rate( 8e9, 0., cur_raw_sz,              prv_raw_sz,              dt ); /* Assumes sz incl framing */
  printf( " | " ); printf_rate( 1e9, 0., cur->fseq_diag_tot_cnt,  prv->fseq_diag_tot_cnt,  dt );
  printf( " | " ); printf_rate( 8e9, 0., cur->fseq_diag_tot_sz,   prv->fseq_diag_tot_sz,   dt ); /* Assumes sz incl framing */

  printf( " | " ); printf_pct ( cur->fseq_diag_tot_cnt,  prv->fseq_diag_tot_cnt, 0.,
                                cur_raw_cnt,             prv_raw_cnt,            DBL_MIN );
  printf( " | " ); printf_pct ( cur->fseq_diag_tot_sz,   prv->fseq_diag_tot_sz,  0.,
                                cur_raw_sz,              prv_raw_sz,             DBL_MIN ); /* Assumes sz incl framing */
  printf( " | " ); printf_pct ( cur->fseq_diag_filt_cnt, prv->fseq_diag_filt_cnt, 0.,
                                cur->fseq_diag_tot_cnt,  prv->fseq_diag_tot_cnt,  DBL_MIN );
  printf( " | " ); printf_pct ( cur->fseq_diag_filt_sz,  prv->fseq_diag_filt_sz, 0.,
                                cur->fseq_diag_tot_sz,   prv->fseq_diag_tot_sz,  DBL_MIN ); /* Assumes sz incl framing */

  printf( " | " ); printf_err_cnt( cur->fseq_diag_ovrnp_cnt, prv->fseq_diag_ovrnp_cnt );
  printf( " | " ); printf_err_cnt( cur->fseq_diag_ovrnr_cnt, prv->fseq_diag_ovrnr_cnt );
  printf( " | " ); printf_err_cnt( cur->fseq_diag_slow_cnt,  prv->fseq_diag_slow_cnt  );
  printf( TEXT_NEWLINE );
}

const uchar *
find_pod( config_t * const config,
          int kind,
          const uchar ** pods ) {
  for( ulong i=0; i<config->shmem.workspaces_cnt; i++ ) {
    workspace_config_t * wksp = &config->shmem.workspaces[ i ];
    if( (int)wksp->kind == kind ) return pods[i];
  }
  FD_LOG_ERR(( "no pod of kind %d found", kind ));
}

void
run_monitor( config_t * const config,
             const uchar **   pods,
             long             dt_min,
             long             dt_max,
             long             duration,
             uint             seed,
             double           ns_per_tic ) {
  /* tile indices */
  ulong tile_pack_idx    = 0UL;
  ulong tile_dedup_idx   = tile_pack_idx +1UL;
  ulong tile_verify_idx0 = tile_dedup_idx+1UL;
  ulong tile_verify_idx1 = tile_verify_idx0 + config->layout.verify_tile_count;
  ulong tile_quic_idx0   = tile_verify_idx1;
  ulong tile_quic_idx1   = tile_quic_idx0 + config->layout.verify_tile_count;

  /* join all IPC objects for this frank instance */
  ulong tile_cnt = tile_quic_idx1;
  char const **     tile_name   = fd_alloca( alignof(char const *    ), sizeof(char const *    )*tile_cnt );
  fd_cnc_t **       tile_cnc    = fd_alloca( alignof(fd_cnc_t *      ), sizeof(fd_cnc_t *      )*tile_cnt );
  fd_frag_meta_t ** tile_mcache = fd_alloca( alignof(fd_frag_meta_t *), sizeof(fd_frag_meta_t *)*tile_cnt );
  ulong **          tile_fseq   = fd_alloca( alignof(ulong *         ), sizeof(ulong *         )*tile_cnt );
  if( FD_UNLIKELY( (!tile_name) | (!tile_cnc) | (!tile_mcache) | (!tile_fseq) ) ) FD_LOG_ERR(( "fd_alloca failed" )); /* paranoia */

  ulong tile_idx = 0;
  for( ulong j=0; j<config->shmem.workspaces_cnt; j++ ) {
    workspace_config_t * wksp = &config->shmem.workspaces[ j ];
    const uchar * pod = workspace_pod_join( config->name, wksp->name, wksp->kind_idx );

    char buf[ 64 ];
#define FIND(kind) find_pod( config, kind, pods )
#define IDX(fmt) snprintf1( buf, 64, fmt "%lu", wksp->kind_idx )

    switch( wksp->kind ) {
      case wksp_quic_verify:
        break;
      case wksp_verify_dedup:
        break;
      case wksp_dedup_pack:
        break;
      case wksp_pack_bank:
        break;
      case wksp_quic:
        tile_name[ tile_idx ] = "quic";
        tile_cnc [ tile_idx ] = fd_cnc_join( fd_wksp_pod_map( pod, "cnc" ) );
        if( FD_UNLIKELY( !tile_cnc[tile_idx] ) ) FD_LOG_ERR(( "fd_cnc_join failed" ));
        if( FD_UNLIKELY( fd_cnc_app_sz( tile_cnc[ tile_idx ] )<64UL ) ) FD_LOG_ERR(( "cnc app sz should be at least 64 bytes" ));
        tile_mcache[ tile_idx ] = fd_mcache_join( fd_wksp_pod_map( FIND(wksp_quic_verify), IDX("mcache") ) );
        if( FD_UNLIKELY( !tile_mcache[ tile_idx ] ) ) FD_LOG_ERR(( "fd_mcache_join failed" ));
        tile_fseq[ tile_idx ] = fd_fseq_join( fd_wksp_pod_map( FIND(wksp_quic_verify), IDX("fseq") ) );
        if( FD_UNLIKELY( !tile_fseq[ tile_idx ] ) ) FD_LOG_ERR(( "fd_fseq_join failed" ));
        tile_idx++;
        break;
      case wksp_verify:
        tile_name[ tile_idx ] = "verify";
        tile_cnc [ tile_idx ] = fd_cnc_join( fd_wksp_pod_map( pod, "cnc" ) );
        if( FD_UNLIKELY( !tile_cnc[tile_idx] ) ) FD_LOG_ERR(( "fd_cnc_join failed" ));
        if( FD_UNLIKELY( fd_cnc_app_sz( tile_cnc[ tile_idx ] )<64UL ) ) FD_LOG_ERR(( "cnc app sz should be at least 64 bytes" ));
        tile_mcache[ tile_idx ] = fd_mcache_join( fd_wksp_pod_map( FIND(wksp_verify_dedup), IDX("mcache") ) );
        if( FD_UNLIKELY( !tile_mcache[ tile_idx ] ) ) FD_LOG_ERR(( "fd_mcache_join failed" ));
        tile_fseq[ tile_idx ] = fd_fseq_join( fd_wksp_pod_map( FIND(wksp_verify_dedup), IDX("fseq") ) );
        if( FD_UNLIKELY( !tile_fseq[ tile_idx ] ) ) FD_LOG_ERR(( "fd_fseq_join failed" ));
        tile_idx++;
        break;
      case wksp_dedup:
        tile_name[ tile_idx ] = "dedup";
        tile_cnc[ tile_idx ] = fd_cnc_join( fd_wksp_pod_map( pod, "dedup.cnc" ) );
        if( FD_UNLIKELY( !tile_cnc[ tile_idx ] ) ) FD_LOG_ERR(( "fd_cnc_join failed" ));
        if( FD_UNLIKELY( fd_cnc_app_sz( tile_cnc[ tile_idx ] )<64UL ) ) FD_LOG_ERR(( "cnc app sz should be at least 64 bytes" ));
        tile_mcache[ tile_idx ] = fd_mcache_join( fd_wksp_pod_map( FIND(wksp_dedup_pack), "mcache" ) );
        if( FD_UNLIKELY( !tile_mcache[ tile_idx ] ) ) FD_LOG_ERR(( "fd_mcache_join failed" ));
        FD_LOG_INFO(( "joining firedancer.dedup.fseq" ));
        tile_fseq[ tile_idx ] = fd_fseq_join( fd_wksp_pod_map( FIND(wksp_dedup_pack), "fseq" ) );
        if( FD_UNLIKELY( !tile_fseq[ tile_idx ] ) ) FD_LOG_ERR(( "fd_fseq_join failed" ));
        tile_idx++;
        break;
      case wksp_pack:
        tile_name[ tile_idx ] = "pack";
        tile_cnc[ tile_idx ] = fd_cnc_join( fd_wksp_pod_map( pod, "cnc" ) );
        if( FD_UNLIKELY( !tile_cnc[ tile_idx ] ) ) FD_LOG_ERR(( "fd_cnc_join failed" ));
        if( FD_UNLIKELY( fd_cnc_app_sz( tile_cnc[ tile_idx ] )<64UL ) ) FD_LOG_ERR(( "cnc app sz should be at least 64 bytes" ));
        tile_mcache[ tile_idx ] = NULL; /* pack currently has no mcache */
        // if( FD_UNLIKELY( !tile_mcache[ tile_idx ] ) ) FD_LOG_ERR(( "fd_mcache_join failed" ));
        tile_fseq[ tile_idx ] = NULL; /* pack currently has no fseq */
        if( FD_UNLIKELY( !tile_fseq[ tile_idx ] ) ) FD_LOG_ERR(( "fd_fseq_join failed" ));
        tile_idx++;
        break;
    }
  }

  /* Setup local objects used by this app */
  fd_rng_t _rng[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, seed, 0UL ) );

  snap_t * snap_prv = (snap_t *)fd_alloca( alignof(snap_t), sizeof(snap_t)*2UL*tile_cnt );
  if( FD_UNLIKELY( !snap_prv ) ) FD_LOG_ERR(( "fd_alloca failed" )); /* Paranoia */
  snap_t * snap_cur = snap_prv + tile_cnt;

  /* Get the inital reference diagnostic snapshot */
  snap( tile_cnt, snap_prv, tile_cnc, tile_mcache, tile_fseq );
  long then; long tic; fd_tempo_observe_pair( &then, &tic );

  /* Monitor for duration ns.  Note that for duration==0, this
     will still do exactly one pretty print. */
  FD_LOG_NOTICE(( "monitoring --dt-min %li ns, --dt-max %li ns, --duration %li ns, --seed %u", dt_min, dt_max, duration, seed ));

  /* Setup TTY */
  printf( TEXT_CUP_HOME );

  long stop = then + duration;
  if( duration == 0) stop = LONG_MAX;

  for(;;) {
    /* Wait a somewhat randomized amount and then make a diagnostic
       snapshot */
    fd_log_wait_until( then + dt_min + (long)fd_rng_ulong_roll( rng, 1UL+(ulong)(dt_max-dt_min) ) );

    snap( tile_cnt, snap_cur, tile_cnc, tile_mcache, tile_fseq );
    long now; long toc; fd_tempo_observe_pair( &now, &toc );

    /* Pretty print a comparison between this diagnostic snapshot and
       the previous one. */

    /* FIXME: CONSIDER DOING CNC ACKS AND INCL IN SNAPSHOT */
    /* FIXME: CONSIDER INCLUDING TILE UPTIME */
    /* FIXME: CONSIDER ADDING INFO LIKE PID OF INSTANCE */

    char now_cstr[ FD_LOG_WALLCLOCK_CSTR_BUF_SZ ];
    printf( "snapshot for %s" TEXT_NEWLINE, fd_log_wallclock_cstr( now, now_cstr ) );
    printf( "  tile |      stale | heart |        sig | in backp |           backp cnt |         sv_filt cnt |                    tx seq |                    rx seq"  TEXT_NEWLINE );
    printf( "-------+------------+-------+------------+----------+---------------------+---------------------+---------------------------+---------------------------" TEXT_NEWLINE );
    for( ulong tile_idx=0UL; tile_idx<tile_cnt; tile_idx++ ) {
      snap_t * prv = &snap_prv[ tile_idx ];
      snap_t * cur = &snap_cur[ tile_idx ];
      printf( " %5s", tile_name[ tile_idx ] );
      if( FD_LIKELY( cur->pmap & 1UL ) ) {
        printf( " | " ); printf_stale   ( (long)(0.5+ns_per_tic*(double)(toc - cur->cnc_heartbeat)), dt_min );
        printf( " | " ); printf_heart   ( cur->cnc_heartbeat,        prv->cnc_heartbeat        );
        printf( " | " ); printf_sig     ( cur->cnc_signal,           prv->cnc_signal           );
        printf( " | " ); printf_err_bool( cur->cnc_diag_in_backp,    prv->cnc_diag_in_backp    );
        printf( " | " ); printf_err_cnt ( cur->cnc_diag_backp_cnt,   prv->cnc_diag_backp_cnt   );
        printf( " | " ); printf_err_cnt ( cur->cnc_diag_sv_filt_cnt, prv->cnc_diag_sv_filt_cnt );
      } else {
        printf(       " |          - |     - |          - |        - |                   -" );
      }
      if( FD_LIKELY( cur->pmap & 2UL ) ) {
        printf( " | " ); printf_seq( cur->mcache_seq, prv->mcache_seq );
      } else {
        printf( " |                         -" );
      }
      if( FD_LIKELY( cur->pmap & 4UL ) ) {
        printf( " | " ); printf_seq( cur->fseq_seq, prv->fseq_seq );
      } else {
        printf( " |                         -" );
      }
      printf( TEXT_NEWLINE );
    }
    printf( TEXT_NEWLINE );
    printf( "          link |  tot TPS |  tot bps | uniq TPS | uniq bps |   ha tr%% | uniq bw%% | filt tr%% | filt bw%% |           ovrnp cnt |           ovrnr cnt |            slow cnt" TEXT_NEWLINE );
    printf( "---------------+----------+----------+----------+----------+----------+----------+-----------+----------+---------------------+---------------------+---------------------"    TEXT_NEWLINE );
    long dt = now-then;
    for( ulong i=0; i<config->layout.verify_tile_count; i++ ) {
      printf_link( snap_prv, snap_cur, tile_name, tile_quic_idx0+i, tile_verify_idx0+i, dt );
    }
    for( ulong tile_idx=tile_verify_idx0; tile_idx<tile_verify_idx1; tile_idx++ ) {
      printf_link( snap_prv, snap_cur, tile_name, tile_idx, tile_dedup_idx, dt );
    }
    printf_link( snap_prv, snap_cur, tile_name, tile_dedup_idx, tile_pack_idx, dt );
    printf( TEXT_NEWLINE );

    /* Switch to alternate screen and erase junk below
       TODO ideally we'd have the last iteration on the main buffer and only the rest on ALTBUF */

    printf( TEXT_ALTBUF_ENABLE
            TEXT_ED
            TEXT_CUP_HOME );

    /* Stop once we've been monitoring for duration ns */

    if( FD_UNLIKELY( (now-stop)>=0L ) ) break;

    /* Still more monitoring to do ... wind up for the next iteration by
       swaping the two snap arrays. */

    then = now; tic = toc;
    snap_t * tmp = snap_prv; snap_prv = snap_cur; snap_cur = tmp;
  }
}

static void
signal1( int sig ) {
  (void)sig;
  printf( TEXT_ALTBUF_DISABLE );
  exit_group( 0 );
}

void
monitor_cmd_fn( args_t *         args,
                config_t * const config ) {
  ulong pods_cnt = 0;
  const uchar * pods[ 256 ] = { 0 };
  for( ulong i=0; i<config->shmem.workspaces_cnt; i++ ) {
    workspace_config_t * wksp = &config->shmem.workspaces[ i ];
    pods[ pods_cnt++ ] = workspace_pod_join( config->name, wksp->name, wksp->kind_idx );
  }

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

  run_monitor( config,
               pods,
               args->monitor.dt_min,
               args->monitor.dt_max,
               args->monitor.duration,
               args->monitor.seed,
               args->monitor.ns_per_tic );

  printf( TEXT_ALTBUF_DISABLE );
  exit_group( 0 );
}
