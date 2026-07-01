#include "../../shared/fd_config.h"
#include "../../shared/fd_action.h"
#include "../../../disco/metrics/fd_metrics.h"
#include "../../../discof/backup/fd_backup.h"
#include "../../../discof/replay/fd_replay_tile.h"

#if !FD_HAS_ATOMIC
#error "This compile unit requires FD_HAS_ATOMIC"
#endif

static ulong
send_admin_cmd( fd_frag_meta_t *       admin_cmd,
                fd_frag_meta_t const * admin_rsp,
                ulong                  orig ) {
  /* Send request */
  ulong   cmd_depth = fd_mcache_depth( admin_cmd );
  ulong * seq_next  = &fd_mcache_seq_laddr( admin_cmd )[1];
  ulong   seq       = FD_ATOMIC_FETCH_AND_ADD( seq_next, 1UL );
  ulong   ctl       = fd_frag_meta_ctl( orig, 0, 0, 0 );
  ulong   tspub     = fd_frag_meta_ts_comp( fd_tickcount() );
  fd_mcache_publish( admin_cmd, cmd_depth, seq, 0UL, 0UL, 0UL, ctl, 0UL, tspub );

  /* Spin-wait for reply */
  ulong rsp_depth = fd_mcache_depth( admin_rsp );
  fd_frag_meta_t meta;
  for(;;) {
    fd_frag_meta_t const * mline;
    ulong                  seq_found;
    long                   seq_diff;
    ulong                  poll_max = 0UL;
    FD_MCACHE_WAIT( &meta, mline, seq_found, seq_diff, poll_max, admin_rsp, rsp_depth, seq );
    (void)mline; (void)seq_diff;
    if( FD_UNLIKELY( fd_seq_gt( seq_found, seq ) ) ) {
      FD_LOG_ERR(( "corrupt admin queue (seq=%lu seq_found=%lu)", seq, seq_found ));
    }
    if( FD_UNLIKELY( fd_seq_eq( seq_found, seq ) ) ) break;
    fd_log_sleep( (long)1e6 ); /* sleep 1ms */
    /* FIXME also check the replay tile's heartbeat to bail if it's down */
  }

  return meta.sig;
}

static fd_topo_tile_t *
join_tile_metrics( fd_topo_t * topo,
                   fd_topo_tile_t * tile ) {
  fd_topo_obj_t const * metrics_obj = &topo->objs[ tile->metrics_obj_id ];
  fd_topo_wksp_t * metrics_wksp = &topo->workspaces[ metrics_obj->wksp_id ];
  if( FD_LIKELY( !metrics_wksp->wksp ) ) {
    fd_topo_join_workspace( topo, metrics_wksp, FD_SHMEM_JOIN_MODE_READ_ONLY, FD_TOPO_CORE_DUMP_LEVEL_DISABLED );
  }
  fd_topo_workspace_fill( topo, metrics_wksp );

  FD_TEST( tile->metrics );
  return tile;
}

static fd_topo_tile_t *
join_tile_metrics_by_kind( fd_topo_t * topo,
                           char const * name,
                           ulong        kind_id ) {
  ulong tile_id = fd_topo_find_tile( topo, name, kind_id );
  if( FD_UNLIKELY( tile_id==ULONG_MAX ) ) return NULL;

  return join_tile_metrics( topo, &topo->tiles[ tile_id ] );
}

static ulong
join_tile_metrics_all( fd_topo_t *               topo,
                       char const *              name,
                       fd_topo_tile_t const **   tiles,
                       ulong                     tiles_max ) {
  ulong tile_cnt = 0UL;
  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t * tile = &topo->tiles[ i ];
    if( FD_LIKELY( strcmp( tile->name, name ) ) ) continue;
    if( FD_UNLIKELY( tile_cnt>=tiles_max ) ) {
      FD_LOG_ERR(( "too many %s tiles for snapshot creation progress", name ));
    }
    tiles[ tile_cnt++ ] = join_tile_metrics( topo, tile );
  }
  return tile_cnt;
}

/* fmt_bytes pretty-prints a byte count into a human-readable size string
   (e.g. "4.32 GiB").  Adapted from fmt_bytes in
   src/app/shared/commands/watch/watch.c (which prints bit rates). */

static char *
fmt_bytes( char * buf,
           ulong  buf_sz,
           ulong  bytes ) {
  char * tmp = fd_alloca_check( 1UL, buf_sz );
  if(      FD_LIKELY( bytes<(1UL<<10) ) ) FD_TEST( fd_cstr_printf_check( tmp, buf_sz, NULL, "%lu B",    bytes ) );
  else if( FD_LIKELY( bytes<(1UL<<20) ) ) FD_TEST( fd_cstr_printf_check( tmp, buf_sz, NULL, "%.2f KiB", (double)bytes/(double)(1UL<<10) ) );
  else if( FD_LIKELY( bytes<(1UL<<30) ) ) FD_TEST( fd_cstr_printf_check( tmp, buf_sz, NULL, "%.2f MiB", (double)bytes/(double)(1UL<<20) ) );
  else                                    FD_TEST( fd_cstr_printf_check( tmp, buf_sz, NULL, "%.2f GiB", (double)bytes/(double)(1UL<<30) ) );

  FD_TEST( fd_cstr_printf_check( buf, buf_sz, NULL, "%11s", tmp ) );
  return buf;
}

static char *
fmt_sci( char * buf,
         ulong  buf_sz,
         double val,
         int    width,
         int    precision ) {
  char tmp[ 64UL ];
  FD_TEST( fd_cstr_printf_check( tmp, sizeof(tmp), NULL, "%.*e", precision, val ) );

  char * exp = strchr( tmp, 'e' );
  if( FD_LIKELY( exp && ( exp[1]=='+' || exp[1]=='-' ) ) ) {
    char * src = exp+2;
    while( src[0]=='0' && src[1] ) src++;
    if( FD_LIKELY( src!=exp+2 ) ) memmove( exp+2, src, strlen( src )+1UL );
  }

  FD_TEST( fd_cstr_printf_check( buf, buf_sz, NULL, "%*s", width, tmp ) );
  return buf;
}

typedef struct {
  ulong accounts_compressed;
  ulong bytes_compressed;
  ulong bytes_written;
} snapshot_create_metric_sample_t;

/* snapshot-create logs once per second, so one sample is roughly a
   1000ms moving window. */
#define SNAPSHOT_CREATE_RATE_SAMPLE_CNT (1UL)

typedef struct {
  ulong accounts_delta[ SNAPSHOT_CREATE_RATE_SAMPLE_CNT ];
  ulong account_bytes_delta[ SNAPSHOT_CREATE_RATE_SAMPLE_CNT ];
  ulong read_bytes_delta[ SNAPSHOT_CREATE_RATE_SAMPLE_CNT ];
  ulong raw_bytes_delta[ SNAPSHOT_CREATE_RATE_SAMPLE_CNT ];
  ulong compressed_bytes_delta[ SNAPSHOT_CREATE_RATE_SAMPLE_CNT ];
  ulong nanos_delta   [ SNAPSHOT_CREATE_RATE_SAMPLE_CNT ];
  ulong idx;
  int   initialized;
  ulong prev_accounts_compressed;
  ulong prev_account_bytes_compressed;
  ulong prev_read_bytes;
  ulong prev_raw_bytes_compressed;
  ulong prev_compressed_bytes_written;
  long  prev_time;
} snapshot_create_rate_estimator_t;

static ulong
counter_delta( ulong now,
               ulong start ) {
  return FD_LIKELY( now>=start ) ? now-start : now;
}

static ulong
monotonic_delta( ulong now,
                 ulong prev ) {
  return FD_LIKELY( now>=prev ) ? now-prev : 0UL;
}

static snapshot_create_metric_sample_t
sample_snapmk_metrics( volatile ulong const * metrics ) {
  return (snapshot_create_metric_sample_t) {
    .accounts_compressed = 0UL,
    .bytes_compressed = FD_VOLATILE_CONST( metrics[ MIDX( COUNTER, SNAPMK, BYTES_COMPRESSED ) ] ),
    .bytes_written    = FD_VOLATILE_CONST( metrics[ MIDX( COUNTER, SNAPMK, BYTES_WRITTEN    ) ] )
  };
}

static snapshot_create_metric_sample_t
sample_snapzp_metrics( volatile ulong const * metrics ) {
  return (snapshot_create_metric_sample_t) {
    .accounts_compressed = FD_VOLATILE_CONST( metrics[ MIDX( COUNTER, SNAPZP, ACCOUNTS_COMPRESSED ) ] ),
    .bytes_compressed = FD_VOLATILE_CONST( metrics[ MIDX( COUNTER, SNAPZP, BYTES_COMPRESSED ) ] ),
    .bytes_written    = FD_VOLATILE_CONST( metrics[ MIDX( COUNTER, SNAPZP, BYTES_WRITTEN    ) ] )
  };
}

static ulong
snapshot_create_bytes_written( volatile ulong const *                  snapmk_metrics,
                               snapshot_create_metric_sample_t         snapmk_start,
                               volatile ulong const **                 snapzp_metrics,
                               snapshot_create_metric_sample_t const * snapzp_start,
                               ulong                                   snapzp_metrics_cnt ) {
  snapshot_create_metric_sample_t snapmk_now = sample_snapmk_metrics( snapmk_metrics );
  ulong bytes_written = counter_delta( snapmk_now.bytes_written, snapmk_start.bytes_written );
  for( ulong i=0UL; i<snapzp_metrics_cnt; i++ ) {
    snapshot_create_metric_sample_t snapzp_now = sample_snapzp_metrics( snapzp_metrics[ i ] );
    bytes_written += counter_delta( snapzp_now.bytes_written, snapzp_start[ i ].bytes_written );
  }
  return bytes_written;
}

static void
update_snapshot_create_rate_estimator( snapshot_create_rate_estimator_t * estimator,
                                       ulong                              accounts_compressed,
                                       ulong                              account_bytes_compressed,
                                       ulong                              read_bytes,
                                       ulong                              raw_bytes_compressed,
                                       ulong                              compressed_bytes_written,
                                       long                               now ) {
  if( FD_UNLIKELY( !estimator->initialized ) ) {
    estimator->initialized                    = 1;
    estimator->prev_accounts_compressed       = accounts_compressed;
    estimator->prev_account_bytes_compressed  = account_bytes_compressed;
    estimator->prev_read_bytes                = read_bytes;
    estimator->prev_raw_bytes_compressed      = raw_bytes_compressed;
    estimator->prev_compressed_bytes_written  = compressed_bytes_written;
    estimator->prev_time                      = now;
    return;
  }

  long elapsed = now>estimator->prev_time ? now-estimator->prev_time : 0L;
  estimator->prev_time = now;
  if( FD_UNLIKELY( elapsed<=0L ) ) return;

  ulong slot = estimator->idx % SNAPSHOT_CREATE_RATE_SAMPLE_CNT;
  estimator->accounts_delta        [ slot ] = monotonic_delta( accounts_compressed,       estimator->prev_accounts_compressed       );
  estimator->account_bytes_delta   [ slot ] = monotonic_delta( account_bytes_compressed,  estimator->prev_account_bytes_compressed  );
  estimator->read_bytes_delta      [ slot ] = monotonic_delta( read_bytes,                estimator->prev_read_bytes                );
  estimator->raw_bytes_delta       [ slot ] = monotonic_delta( raw_bytes_compressed,      estimator->prev_raw_bytes_compressed      );
  estimator->compressed_bytes_delta[ slot ] = monotonic_delta( compressed_bytes_written,  estimator->prev_compressed_bytes_written  );
  estimator->nanos_delta           [ slot ] = (ulong)elapsed;
  estimator->idx++;

  estimator->prev_accounts_compressed      = accounts_compressed;
  estimator->prev_account_bytes_compressed = account_bytes_compressed;
  estimator->prev_read_bytes               = read_bytes;
  estimator->prev_raw_bytes_compressed     = raw_bytes_compressed;
  estimator->prev_compressed_bytes_written = compressed_bytes_written;
}

static void
log_snapshot_create_progress( volatile ulong const *               snapmk_metrics,
                              snapshot_create_metric_sample_t      snapmk_start,
                              volatile ulong const *               snaprd_metrics,
                              volatile ulong const **              snapzp_metrics,
                              snapshot_create_metric_sample_t const * snapzp_start,
                              ulong                                snapzp_metrics_cnt,
                              snapshot_create_rate_estimator_t *    rate_estimator,
                              long                                 now ) {
  snapshot_create_metric_sample_t snapmk_now = sample_snapmk_metrics( snapmk_metrics );
  ulong accounts_compressed = 0UL;
  ulong account_bytes_compressed = 0UL;
  ulong bytes_compressed = counter_delta( snapmk_now.bytes_compressed, snapmk_start.bytes_compressed );
  ulong bytes_written    = counter_delta( snapmk_now.bytes_written,    snapmk_start.bytes_written    );
  for( ulong i=0UL; i<snapzp_metrics_cnt; i++ ) {
    snapshot_create_metric_sample_t snapzp_now = sample_snapzp_metrics( snapzp_metrics[ i ] );
    accounts_compressed += counter_delta( snapzp_now.accounts_compressed, snapzp_start[ i ].accounts_compressed );
    ulong account_bytes_delta = counter_delta( snapzp_now.bytes_compressed, snapzp_start[ i ].bytes_compressed );
    account_bytes_compressed += account_bytes_delta;
    bytes_compressed += account_bytes_delta;
    bytes_written    += counter_delta( snapzp_now.bytes_written,    snapzp_start[ i ].bytes_written    );
  }

  ulong progress_bytes = FD_VOLATILE_CONST( snaprd_metrics[ MIDX( GAUGE, SNAPRD, EXPORT_PROGRESS_BYTES ) ] );
  ulong total_bytes    = FD_VOLATILE_CONST( snaprd_metrics[ MIDX( GAUGE, SNAPRD, EXPORT_TOTAL_BYTES    ) ] );

  update_snapshot_create_rate_estimator( rate_estimator, accounts_compressed, account_bytes_compressed, progress_bytes, bytes_compressed, bytes_written, now );

  char compressed_str[ 64UL ]; fmt_bytes( compressed_str, sizeof(compressed_str), bytes_compressed );
  char written_str  [ 64UL ]; fmt_bytes( written_str,    sizeof(written_str),    bytes_written    );

  ulong accounts_sum         = 0UL;
  ulong account_bytes_sum    = 0UL;
  ulong read_bytes_sum       = 0UL;
  ulong raw_bytes_sum        = 0UL;
  ulong compressed_bytes_sum = 0UL;
  ulong nanos_sum            = 0UL;
  ulong sample_cnt           = fd_ulong_min( rate_estimator->idx, SNAPSHOT_CREATE_RATE_SAMPLE_CNT );
  for( ulong i=0UL; i<sample_cnt; i++ ) {
    accounts_sum         += rate_estimator->accounts_delta        [ i ];
    account_bytes_sum    += rate_estimator->account_bytes_delta   [ i ];
    read_bytes_sum       += rate_estimator->read_bytes_delta      [ i ];
    raw_bytes_sum        += rate_estimator->raw_bytes_delta       [ i ];
    compressed_bytes_sum += rate_estimator->compressed_bytes_delta[ i ];
    nanos_sum            += rate_estimator->nanos_delta           [ i ];
  }

  double accounts_per_second = nanos_sum ? (double)accounts_sum * 1e9 / (double)nanos_sum : 0.0;
  ulong read_bytes_per_second       = nanos_sum ? (ulong)( (double)read_bytes_sum       * 1e9 / (double)nanos_sum ) : 0UL;
  ulong raw_bytes_per_second        = nanos_sum ? (ulong)( (double)raw_bytes_sum        * 1e9 / (double)nanos_sum ) : 0UL;
  ulong compressed_bytes_per_second = nanos_sum ? (ulong)( (double)compressed_bytes_sum * 1e9 / (double)nanos_sum ) : 0UL;
  char read_rate_str      [ 64UL ]; fmt_bytes( read_rate_str,       sizeof(read_rate_str),       read_bytes_per_second       );
  char raw_rate_str       [ 64UL ]; fmt_bytes( raw_rate_str,        sizeof(raw_rate_str),        raw_bytes_per_second        );
  char compressed_rate_str[ 64UL ]; fmt_bytes( compressed_rate_str, sizeof(compressed_rate_str), compressed_bytes_per_second );
  char accounts_str[ 64UL ]; fmt_sci( accounts_str, sizeof(accounts_str), (double)accounts_compressed, 10, 4 );
  char accounts_rate_str[ 64UL ]; fmt_sci( accounts_rate_str, sizeof(accounts_rate_str), accounts_per_second, 10, 4 );
  char account_size_str[ 64UL ];
  if( FD_LIKELY( accounts_sum ) ) fmt_bytes( account_size_str, sizeof(account_size_str), account_bytes_sum / accounts_sum );
  else FD_TEST( fd_cstr_printf_check( account_size_str, sizeof(account_size_str), NULL, "%11s", "-" ) );

  double pct = 100.0 * (double)fd_ulong_min( progress_bytes, total_bytes ) / (double)total_bytes;
  char progress_str[ 64UL ]; fmt_bytes( progress_str, sizeof(progress_str), progress_bytes );
  char total_str   [ 64UL ]; fmt_bytes( total_str,    sizeof(total_str),    total_bytes    );
  FD_LOG_NOTICE(( "progress=%5.1f%% read=%s / %s [%s/s] raw=%s [%s/s] compressed=%s [%s/s] accounts=%s [%s/s] acct_sz=%s",
                  pct,
                  progress_str,
                  total_str,
                  read_rate_str,
                  compressed_str,
                  raw_rate_str,
                  written_str,
                  compressed_rate_str,
                  accounts_str,
                  accounts_rate_str,
                  account_size_str ));
}

static void
wait_snapshot_create( fd_topo_tile_t const *            snapmk_tile,
                      fd_topo_tile_t const *            snaprd_tile,
                      fd_topo_tile_t const **           snapzp_tiles,
                      ulong                             snapzp_tile_cnt,
                      snapshot_create_metric_sample_t   snapmk_start,
                      snapshot_create_metric_sample_t * snapzp_start,
                      ulong                             start_snapshots_created,
                      int                               attach_existing,
                      ulong *                           final_bytes_written ) {
  volatile ulong const * snapmk_metrics = fd_metrics_tile( snapmk_tile->metrics );
  volatile ulong const * snaprd_metrics = fd_metrics_tile( snaprd_tile->metrics );
  volatile ulong const * snapzp_metrics[ FD_TOPO_MAX_TILES ];
  for( ulong i=0UL; i<snapzp_tile_cnt; i++ ) {
    snapzp_metrics[ i ] = fd_metrics_tile( snapzp_tiles[ i ]->metrics );
  }
  snapshot_create_rate_estimator_t rate_estimator = {0};

  int  started  = 0;
  int  metrics_rebased = 0;
  long next_log = fd_log_wallclock();
  for(;;) {
    ulong state = FD_VOLATILE_CONST( snapmk_metrics[ MIDX( GAUGE, SNAPMK, STATE ) ] );
    ulong snapshots_created = FD_VOLATILE_CONST( snapmk_metrics[ MIDX( COUNTER, SNAPMK, SNAPSHOTS_CREATED ) ] );

    if( FD_UNLIKELY( attach_existing ) ) {
      if( FD_UNLIKELY( state!=SNAPMK_STATE_IDLE ) ) started = 1;
    } else if( FD_UNLIKELY( snapshots_created!=start_snapshots_created ) ) {
      started = 1;
    }
    int metrics_ready = started && !metrics_rebased;
    if( FD_LIKELY( metrics_ready ) ) {
      ulong progress_bytes = FD_VOLATILE_CONST( snaprd_metrics[ MIDX( GAUGE, SNAPRD, EXPORT_PROGRESS_BYTES ) ] );
      ulong total_bytes    = FD_VOLATILE_CONST( snaprd_metrics[ MIDX( GAUGE, SNAPRD, EXPORT_TOTAL_BYTES    ) ] );
      metrics_ready = state>=SNAPMK_STATE_ACCOUNTS_DISK && total_bytes>0UL &&
                      ( state>SNAPMK_STATE_ACCOUNTS_DISK || progress_bytes<total_bytes );
    }
    if( FD_UNLIKELY( metrics_ready ) ) {
      snapmk_start = attach_existing ? (snapshot_create_metric_sample_t) {0} : sample_snapmk_metrics( snapmk_metrics );
      for( ulong i=0UL; i<snapzp_tile_cnt; i++ ) {
        snapzp_start[ i ] = (snapshot_create_metric_sample_t) {0};
      }
      memset( &rate_estimator, 0, sizeof(rate_estimator) );
      metrics_rebased = 1;
      next_log = fd_log_wallclock() + 1000L*1000L*1000L;
    }
    if( FD_LIKELY( metrics_rebased ) ) {
      ulong bytes_written = snapshot_create_bytes_written( snapmk_metrics, snapmk_start, snapzp_metrics, snapzp_start, snapzp_tile_cnt );
      *final_bytes_written = fd_ulong_max( *final_bytes_written, bytes_written );
    }
    if( FD_UNLIKELY( started && state==SNAPMK_STATE_FAIL ) ) {
      FD_LOG_ERR(( "snapshot creation failed" ));
    }
    if( FD_LIKELY( started && state==SNAPMK_STATE_IDLE ) ) break;

    long now = fd_log_wallclock();
    if( FD_UNLIKELY( now>=next_log ) ) {
      if( FD_LIKELY( metrics_rebased ) ) {
        log_snapshot_create_progress( snapmk_metrics, snapmk_start, snaprd_metrics, snapzp_metrics, snapzp_start, snapzp_tile_cnt, &rate_estimator, now );
      }
      next_log = now + 1000L*1000L*1000L;
    }
    fd_log_sleep( (long)1e6 ); /* sleep 1ms */
  }
}

static void
snapshot_create_cmd_args( int *    pargc,
                          char *** pargv,
                          args_t * args ) {
  args->snapshot_create.cont = fd_env_strip_cmdline_contains( pargc, pargv, "--continue" );
}

static void
snapshot_create_cmd_args_help( fd_action_help_t * help ) {
  fd_action_help_arg( help, "--continue", NULL, "If a snapshot is already being created, attach to it and show progress\n"
                                                "instead of failing with busy." );
}

static void
snapshot_create_cmd_fn( args_t *   args,
                        config_t * config ) {
  /* Topology boilerplate: Find admin command/response queues */
  fd_topo_t * topo = &config->topo;
  ulong admin_cmd_wksp_id = fd_topo_find_wksp( topo, "admin_replay" ); FD_TEST( admin_cmd_wksp_id!=ULONG_MAX );
  fd_topo_wksp_t * admin_topo_wksp = &topo->workspaces[ admin_cmd_wksp_id ];
  fd_topo_join_workspace( topo, admin_topo_wksp, FD_SHMEM_JOIN_MODE_READ_WRITE, FD_TOPO_CORE_DUMP_LEVEL_REGULAR );
  fd_topo_workspace_fill( topo, admin_topo_wksp );
  ulong admin_cmd_link_id = fd_topo_find_link( topo, "admin_replay", 0UL ); FD_TEST( admin_cmd_link_id!=ULONG_MAX );
  ulong admin_rsp_link_id = fd_topo_find_link( topo, "replay_admin", 0UL ); FD_TEST( admin_rsp_link_id!=ULONG_MAX );
  fd_topo_link_t const * admin_cmd_link   = &topo->links[ admin_cmd_link_id ];
  fd_topo_link_t const * admin_rsp_link   = &topo->links[ admin_rsp_link_id ];
  fd_frag_meta_t *       admin_cmd_mcache = admin_cmd_link->mcache;
  fd_frag_meta_t const * admin_rsp_mcache = admin_rsp_link->mcache;

  fd_topo_tile_t const * snapmk_tile = join_tile_metrics_by_kind( topo, "snapmk", 0UL ); FD_TEST( snapmk_tile );
  fd_topo_tile_t const * snaprd_tile = join_tile_metrics_by_kind( topo, "snaprd", 0UL ); FD_TEST( snaprd_tile );
  fd_topo_tile_t const * snapzp_tiles[ FD_TOPO_MAX_TILES ];
  ulong snapzp_tile_cnt = join_tile_metrics_all( topo, "snapzp", snapzp_tiles, FD_TOPO_MAX_TILES );
  snapshot_create_metric_sample_t snapmk_start = {0};
  snapshot_create_metric_sample_t snapzp_start[ FD_TOPO_MAX_TILES ];
  ulong start_snapshots_created = 0UL;
  if( FD_LIKELY( snapmk_tile ) ) {
    volatile ulong const * snapmk_metrics = fd_metrics_tile( snapmk_tile->metrics );
    snapmk_start = sample_snapmk_metrics( snapmk_metrics );
    start_snapshots_created = FD_VOLATILE_CONST( snapmk_metrics[ MIDX( COUNTER, SNAPMK, SNAPSHOTS_CREATED ) ] );
  }
  for( ulong i=0UL; i<snapzp_tile_cnt; i++ ) {
    snapzp_start[ i ] = sample_snapzp_metrics( fd_metrics_tile( snapzp_tiles[ i ]->metrics ) );
  }
  ulong final_bytes_written = 0UL;
  long  start_time          = fd_log_wallclock();

  /* Send snapshot create command */
  ulong err = send_admin_cmd( admin_cmd_mcache, admin_rsp_mcache, REPLAY_ADMIN_CMD_SNAP_CREATE );
  if( FD_UNLIKELY( err ) ) {
    if( FD_LIKELY( args->snapshot_create.cont && err==REPLAY_ADMIN_ERR_BUSY ) ) {
      FD_LOG_NOTICE(( "snapshot creation already in progress; continuing progress display" ));
    } else {
      FD_LOG_ERR(( "failed to request snapshot creation %lu-%s", err, fd_replay_admin_strerror( err ) ));
    }
  } else {
    FD_LOG_NOTICE(( "Snapshot creation started" ));
  }

  if( FD_UNLIKELY( !snapmk_tile ) ) {
    FD_LOG_ERR(( "snapshot creation was accepted, but no snapmk tile was found" ));
  }

  wait_snapshot_create( snapmk_tile, snaprd_tile, snapzp_tiles, snapzp_tile_cnt, snapmk_start, snapzp_start, start_snapshots_created, args->snapshot_create.cont && err==REPLAY_ADMIN_ERR_BUSY, &final_bytes_written );
  FD_LOG_NOTICE(( "Snapshot created in %.3f seconds (%.3f GB)",
                  (double)( fd_log_wallclock() - start_time )/1e9,
                  (double)final_bytes_written/1e9 ));
}

action_t fd_action_snapshot_create = {
  .name           = "snapshot-create",
  .args           = snapshot_create_cmd_args,
  .fn             = snapshot_create_cmd_fn,
  .description    = "Create a snapshot",
  .usage          = "snapshot-create [OPTIONS]",
  .args_help      = snapshot_create_cmd_args_help,
  .require_config = 1
};
