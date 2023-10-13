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

typedef struct {
  char const *     name;
  fd_cnc_t *       cnc;
} tile_t;

typedef struct {
  char const *     src_name;
  char const *     dst_name;
  fd_frag_meta_t * mcache;
  ulong *          fseq;
} link_t;

static void
tile_snap( tile_snap_t *     snap_cur,     /* Snaphot for each tile, indexed [0,tile_cnt) */
           ulong             tile_cnt,     /* Number of tiles to snapshot */
           tile_t *          tiles ) {     /* Joined IPC objects for each tile, indexed [0,tile_cnt) */
  for( ulong tile_idx=0UL; tile_idx<tile_cnt; tile_idx++ ) {
    tile_snap_t * snap = &snap_cur[ tile_idx ];

    fd_cnc_t const * cnc = tiles[ tile_idx ].cnc;
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
           ulong         link_cnt,
           link_t *      links) {
  for( ulong link_idx=0UL; link_idx<link_cnt; link_idx++ ) {
    link_snap_t * snap = &snap_cur[ link_idx ];

    fd_frag_meta_t const * mcache = links[ link_idx ].mcache;
    ulong const * seq = (ulong const *)fd_mcache_seq_laddr_const( mcache );
    snap->mcache_seq = fd_mcache_seq_query( seq );

    ulong const * fseq = links[ link_idx ].fseq;
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
             const uchar **   pods,
             int              drain_output_fd,
             long             dt_min,
             long             dt_max,
             long             duration,
             uint             seed,
             double           ns_per_tic ) {
  ulong tile_cnt = 0;
  for( ulong i=0; i<config->shmem.workspaces_cnt; i++ ) {
    switch( config->shmem.workspaces[ i ].kind ) {
      case wksp_netmux_inout:
      case wksp_quic_verify:
      case wksp_verify_dedup:
      case wksp_dedup_pack:
      case wksp_pack_bank:
      case wksp_bank_shred:
      case wksp_metrics_quic:
      case wksp_metrics_verify:
      case wksp_metrics_dedup:
      case wksp_metrics_pack:
      case wksp_metrics_bank:
        break;
      case wksp_net:
        tile_cnt += config->layout.net_tile_count;
        break;
      case wksp_netmux:
        tile_cnt += 1;
        break;
      case wksp_quic:
      case wksp_verify:
        tile_cnt += config->layout.verify_tile_count;
        break;
      case wksp_dedup:
        tile_cnt += 1;
        break;
      case wksp_pack:
        tile_cnt += 1;
        break;
      case wksp_metrics:
        break;
      case wksp_bank:
        tile_cnt += config->layout.bank_tile_count;
        break;
    }
  }

  ulong link_cnt =
    config->layout.net_tile_count +    // net -> netmux
    config->layout.net_tile_count +    // netmux -> net
    config->layout.verify_tile_count + // quic -> netmux
    config->layout.verify_tile_count + // netmux -> quic
    config->layout.verify_tile_count + // quic -> verify
    config->layout.verify_tile_count + // verify -> dedup
    1 +                                // dedup -> pack
    config->layout.bank_tile_count;    // pack -> bank

  tile_t * tiles = fd_alloca( alignof(tile_t *), sizeof(tile_t)*tile_cnt );
  link_t * links = fd_alloca( alignof(link_t *), sizeof(link_t)*link_cnt );
  if( FD_UNLIKELY( (!tiles) | (!links)) ) FD_LOG_ERR(( "fd_alloca failed" )); /* paranoia */

  ulong tile_idx = 0;
  ulong link_idx = 0;
  for( ulong j=0; j<config->shmem.workspaces_cnt; j++ ) {
    workspace_config_t * wksp = &config->shmem.workspaces[ j ];
    const uchar * pod = workspace_pod_join( config->name, wksp->name );

    char buf[ 64 ];
    switch( wksp->kind ) {
      case wksp_netmux_inout:
        for( ulong i=0; i<config->layout.net_tile_count; i++ ) {
          links[ link_idx ].src_name = "net";
          links[ link_idx ].dst_name = "netmux";
          links[ link_idx ].mcache = fd_mcache_join( fd_wksp_pod_map( pods[ j ], snprintf1( buf, 64, "net-out-mcache%lu", i ) ) );
          if( FD_UNLIKELY( !links[ link_idx ].mcache ) ) FD_LOG_ERR(( "fd_mcache_join failed" ));
          links[ link_idx ].fseq = fd_fseq_join( fd_wksp_pod_map( pods[ j ], snprintf1( buf, 64, "net-out-fseq%lu", i ) ) );
          if( FD_UNLIKELY( !links[ link_idx ].fseq ) ) FD_LOG_ERR(( "fd_fseq_join failed" ));
          link_idx++;
        }
        for( ulong i=0; i<config->layout.verify_tile_count; i++ ) {
          links[ link_idx ].src_name = "quic";
          links[ link_idx ].dst_name = "netmux";
          links[ link_idx ].mcache = fd_mcache_join( fd_wksp_pod_map( pods[ j ], snprintf1( buf, 64, "quic-out-mcache%lu", i ) ) );
          if( FD_UNLIKELY( !links[ link_idx ].mcache ) ) FD_LOG_ERR(( "fd_mcache_join failed" ));
          links[ link_idx ].fseq = fd_fseq_join( fd_wksp_pod_map( pods[ j ], snprintf1( buf, 64, "quic-out-fseq%lu", i ) ) );
          if( FD_UNLIKELY( !links[ link_idx ].fseq ) ) FD_LOG_ERR(( "fd_fseq_join failed" ));
          link_idx++;
        }
        for( ulong i=0; i<config->layout.net_tile_count; i++ ) {
          links[ link_idx ].src_name = "netmux";
          links[ link_idx ].dst_name = "net";
          links[ link_idx ].mcache = fd_mcache_join( fd_wksp_pod_map( pods[ j ], "mcache" ) );
          if( FD_UNLIKELY( !links[ link_idx ].mcache ) ) FD_LOG_ERR(( "fd_mcache_join failed" ));
          links[ link_idx ].fseq = fd_fseq_join( fd_wksp_pod_map( pods[ j ], snprintf1( buf, 64, "net-in-fseq%lu", i ) ) );
          if( FD_UNLIKELY( !links[ link_idx ].fseq ) ) FD_LOG_ERR(( "fd_fseq_join failed" ));
          link_idx++;
        }
        for( ulong i=0; i<config->layout.verify_tile_count; i++ ) {
          links[ link_idx ].src_name = "netmux";
          links[ link_idx ].dst_name = "quic";
          links[ link_idx ].mcache = fd_mcache_join( fd_wksp_pod_map( pods[ j ], "mcache" ) );
          if( FD_UNLIKELY( !links[ link_idx ].mcache ) ) FD_LOG_ERR(( "fd_mcache_join failed" ));
          links[ link_idx ].fseq = fd_fseq_join( fd_wksp_pod_map( pods[ j ], snprintf1( buf, 64, "quic-in-fseq%lu", i ) ) );
          if( FD_UNLIKELY( !links[ link_idx ].fseq ) ) FD_LOG_ERR(( "fd_fseq_join failed" ));
          link_idx++;
        }
        break;
      case wksp_quic_verify:
        for( ulong i=0; i<config->layout.verify_tile_count; i++ ) {
          links[ link_idx ].src_name = "quic";
          links[ link_idx ].dst_name = "verify";
          links[ link_idx ].mcache = fd_mcache_join( fd_wksp_pod_map( pods[ j ], snprintf1( buf, 64, "mcache%lu", i ) ) );
          if( FD_UNLIKELY( !links[ link_idx ].mcache ) ) FD_LOG_ERR(( "fd_mcache_join failed" ));
          links[ link_idx ].fseq = fd_fseq_join( fd_wksp_pod_map( pods[ j ], snprintf1( buf, 64, "fseq%lu", i ) ) );
          if( FD_UNLIKELY( !links[ link_idx ].fseq ) ) FD_LOG_ERR(( "fd_fseq_join failed" ));
          link_idx++;
        }
        break;
      case wksp_verify_dedup:
        for( ulong i=0; i<config->layout.verify_tile_count; i++ ) {
          links[ link_idx ].src_name = "verify";
          links[ link_idx ].dst_name = "dedup";
          links[ link_idx ].mcache = fd_mcache_join( fd_wksp_pod_map( pods[ j ], snprintf1( buf, 64, "mcache%lu", i ) ) );
          if( FD_UNLIKELY( !links[ link_idx ].mcache ) ) FD_LOG_ERR(( "fd_mcache_join failed" ));
          links[ link_idx ].fseq = fd_fseq_join( fd_wksp_pod_map( pods[ j ], snprintf1( buf, 64, "fseq%lu", i ) ) );
          if( FD_UNLIKELY( !links[ link_idx ].fseq ) ) FD_LOG_ERR(( "fd_fseq_join failed" ));
          link_idx++;
        }
        break;
      case wksp_dedup_pack:
        links[ link_idx ].src_name = "dedup";
        links[ link_idx ].dst_name = "pack";
        links[ link_idx ].mcache = fd_mcache_join( fd_wksp_pod_map( pods[ j ], "mcache" ) );
        if( FD_UNLIKELY( !links[ link_idx ].mcache ) ) FD_LOG_ERR(( "fd_mcache_join failed" ));
        links[ link_idx ].fseq = fd_fseq_join( fd_wksp_pod_map( pods[ j ], "fseq" ) );
        if( FD_UNLIKELY( !links[ link_idx ].fseq ) ) FD_LOG_ERR(( "fd_fseq_join failed" ));
        link_idx++;
        break;
      case wksp_pack_bank:
        for( ulong i=0; i<config->layout.bank_tile_count; i++ ) {
          links[ link_idx ].src_name = "pack";
          links[ link_idx ].dst_name = "bank";
          links[ link_idx ].mcache = fd_mcache_join( fd_wksp_pod_map( pods[ j ], "mcache" ) ); /* shared mcache from mux tile */
          if( FD_UNLIKELY( !links[ link_idx ].mcache ) ) FD_LOG_ERR(( "fd_mcache_join failed" ));
          links[ link_idx ].fseq = fd_fseq_join( fd_wksp_pod_map( pods[ j ], snprintf1( buf, 64, "fseq%lu", i ) ) );
          if( FD_UNLIKELY( !links[ link_idx ].fseq ) ) FD_LOG_ERR(( "fd_fseq_join failed" ));
          link_idx++;
        }
        break;
      case wksp_bank_shred:
        break;
      case wksp_net:
        for( ulong i=0; i<config->layout.net_tile_count; i++ ) {
          tiles[ tile_idx ].name = "net";
          tiles[ tile_idx ].cnc = fd_cnc_join( fd_wksp_pod_map1( pod, "cnc%lu", i ) );
          if( FD_UNLIKELY( !tiles[ tile_idx ].cnc ) ) FD_LOG_ERR(( "fd_cnc_join failed" ));
          if( FD_UNLIKELY( fd_cnc_app_sz( tiles[ tile_idx ].cnc )<64UL ) ) FD_LOG_ERR(( "cnc app sz should be at least 64 bytes" ));
          tile_idx++;
        }
        break;
      case wksp_netmux:
        tiles[ tile_idx ].name = "netmux";
        tiles[ tile_idx ].cnc = fd_cnc_join( fd_wksp_pod_map( pod, "cnc" ) );
        if( FD_UNLIKELY( !tiles[ tile_idx ].cnc ) ) FD_LOG_ERR(( "fd_cnc_join failed" ));
        if( FD_UNLIKELY( fd_cnc_app_sz( tiles[ tile_idx ].cnc )<64UL ) ) FD_LOG_ERR(( "cnc app sz should be at least 64 bytes" ));
        tile_idx++;
        break;
      case wksp_quic:
        for( ulong i=0; i<config->layout.verify_tile_count; i++ ) {
          tiles[ tile_idx ].name = "quic";
          tiles[ tile_idx ].cnc = fd_cnc_join( fd_wksp_pod_map1( pod, "cnc%lu", i ) );
          if( FD_UNLIKELY( !tiles[ tile_idx ].cnc ) ) FD_LOG_ERR(( "fd_cnc_join failed" ));
          if( FD_UNLIKELY( fd_cnc_app_sz( tiles[ tile_idx ].cnc )<64UL ) ) FD_LOG_ERR(( "cnc app sz should be at least 64 bytes" ));
          tile_idx++;
        }
        break;
      case wksp_verify:
        for( ulong i=0; i<config->layout.verify_tile_count; i++ ) {
          tiles[ tile_idx ].name = "verify";
          tiles[ tile_idx ].cnc = fd_cnc_join( fd_wksp_pod_map1( pod, "cnc%lu", i ) );
          if( FD_UNLIKELY( !tiles[tile_idx].cnc ) ) FD_LOG_ERR(( "fd_cnc_join failed" ));
          if( FD_UNLIKELY( fd_cnc_app_sz( tiles[ tile_idx ].cnc )<64UL ) ) FD_LOG_ERR(( "cnc app sz should be at least 64 bytes" ));
          tile_idx++;
        }
        break;
      case wksp_dedup:
        tiles[ tile_idx ].name = "dedup";
        tiles[ tile_idx ].cnc = fd_cnc_join( fd_wksp_pod_map( pod, "cnc" ) );
        if( FD_UNLIKELY( !tiles[ tile_idx ].cnc ) ) FD_LOG_ERR(( "fd_cnc_join failed" ));
        if( FD_UNLIKELY( fd_cnc_app_sz( tiles[ tile_idx ].cnc )<64UL ) ) FD_LOG_ERR(( "cnc app sz should be at least 64 bytes" ));
        tile_idx++;
        break;
      case wksp_pack:
        tiles[ tile_idx ].name = "pack";
        tiles[ tile_idx ].cnc = fd_cnc_join( fd_wksp_pod_map( pod, "cnc" ) );
        if( FD_UNLIKELY( !tiles[ tile_idx ].cnc ) ) FD_LOG_ERR(( "fd_cnc_join failed" ));
        if( FD_UNLIKELY( fd_cnc_app_sz( tiles[ tile_idx ].cnc )<64UL ) ) FD_LOG_ERR(( "cnc app sz should be at least 64 bytes" ));
        tile_idx++;
        break;
      case wksp_bank:
        for( ulong i=0; i<config->layout.verify_tile_count; i++ ) {
          tiles[ tile_idx ].name = "bank";
          tiles[ tile_idx ].cnc = fd_cnc_join( fd_wksp_pod_map1( pod, "cnc%lu", i ) );
          if( FD_UNLIKELY( !tiles[ tile_idx ].cnc ) ) FD_LOG_ERR(( "fd_cnc_join failed" ));
          if( FD_UNLIKELY( fd_cnc_app_sz( tiles[ tile_idx ].cnc )<64UL ) ) FD_LOG_ERR(( "cnc app sz should be at least 64 bytes" ));
          tile_idx++;
        }
        break;
      case wksp_metrics:
      case wksp_metrics_quic:
      case wksp_metrics_verify:
      case wksp_metrics_dedup:
      case wksp_metrics_pack:
      case wksp_metrics_bank:
        break;
    }
  }

  FD_TEST( tile_idx == tile_cnt );
  FD_TEST( link_idx == link_cnt );

  /* Setup local objects used by this app */
  fd_rng_t _rng[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, seed, 0UL ) );

  tile_snap_t * tile_snap_prv = (tile_snap_t *)fd_alloca( alignof(tile_snap_t), sizeof(tile_snap_t)*2UL*tile_cnt );
  if( FD_UNLIKELY( !tile_snap_prv ) ) FD_LOG_ERR(( "fd_alloca failed" )); /* Paranoia */
  tile_snap_t * tile_snap_cur = tile_snap_prv + tile_cnt;

  link_snap_t * link_snap_prv = (link_snap_t *)fd_alloca( alignof(link_snap_t), sizeof(link_snap_t)*2UL*link_cnt );
  if( FD_UNLIKELY( !link_snap_prv ) ) FD_LOG_ERR(( "fd_alloca failed" )); /* Paranoia */
  link_snap_t * link_snap_cur = link_snap_prv + link_cnt;

  /* Get the inital reference diagnostic snapshot */
  tile_snap( tile_snap_prv, tile_cnt, tiles );
  link_snap( link_snap_prv, link_cnt, links );
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

    tile_snap( tile_snap_cur, tile_cnt, tiles );
    link_snap( link_snap_cur, link_cnt, links );
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
    for( ulong tile_idx=0UL; tile_idx<tile_cnt; tile_idx++ ) {
      tile_snap_t * prv = &tile_snap_prv[ tile_idx ];
      tile_snap_t * cur = &tile_snap_cur[ tile_idx ];
      PRINT( " %7s", tiles[ tile_idx ].name );
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
    for( ulong link_idx=0UL; link_idx<link_cnt; link_idx++ ) {
      link_snap_t * prv = &link_snap_prv[ link_idx ];
      link_snap_t * cur = &link_snap_cur[ link_idx ];
      PRINT( " %7s->%-7s", links[ link_idx ].src_name, links[ link_idx ].dst_name );
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
  ulong pods_cnt = 0;
  const uchar * pods[ 256 ] = { 0 };
  for( ulong i=0; i<config->shmem.workspaces_cnt; i++ ) {
    workspace_config_t * wksp = &config->shmem.workspaces[ i ];
    pods[ pods_cnt++ ] = workspace_pod_join( config->name, wksp->name );
  }

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

  if( FD_UNLIKELY( close( 0 ) ) ) FD_LOG_ERR(( "close(0) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  fd_sandbox( config->development.sandbox ? SANDBOX_MODE_FULL : SANDBOX_MODE_NONE,
              config->uid,
              config->gid,
              allow_fds_sz,
              allow_fds,
              allow_syscalls_cnt,
              allow_syscalls );

  run_monitor( config,
               pods,
               args->monitor.drain_output_fd,
               args->monitor.dt_min,
               args->monitor.dt_max,
               args->monitor.duration,
               args->monitor.seed,
               args->monitor.ns_per_tic );

  exit_group( 0 );
}
