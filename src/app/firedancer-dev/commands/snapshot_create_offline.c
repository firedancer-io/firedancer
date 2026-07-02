#define _GNU_SOURCE
#include "../../shared/fd_config.h"
#include "../../shared/fd_action.h"
#include "../../shared/commands/configure/configure.h"
#include "../../shared/commands/run/run.h"
#include "../../firedancer/topology.h"
#include "../../../disco/metrics/fd_metrics.h"
#include "../../../disco/pack/fd_pack_cost.h"
#include "../../../disco/topo/fd_topob.h"
#include "../../../discof/backup/fd_backup.h"
#include "../../../discof/replay/fd_replay_tile.h"
#include "../../../flamenco/accdb/fd_accdb.h"
#define FD_ACCDB_NO_FORK_ID
#include "../../../flamenco/accdb/fd_accdb_private.h"
#undef FD_ACCDB_NO_FORK_ID
#include "../../../flamenco/runtime/fd_bank.h"
#include "../../../util/pod/fd_pod_format.h"

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

extern fd_topo_obj_callbacks_t * CALLBACKS[];

fd_topo_run_tile_t
fdctl_tile_run( fd_topo_tile_t const * tile );

#define OFFLINE_ACCDB_JOINER_CNT (1UL) /* accdb tile */

static void
snapshot_create_offline_topo( config_t * config ) {
  config->firedancer.layout.resolv_tile_count = 0UL;

  fd_topo_t * topo = &config->topo;
  fd_topob_new( topo, config->name );
  topo->max_page_size = fd_cstr_to_shmem_page_sz( config->hugetlbfs.max_page_size );

  ulong snapzp_tile_cnt = config->firedancer.layout.snapzp_tile_count;
# define FOR(cnt) for( ulong i=0UL; i<(cnt); i++ )

  fd_topob_wksp( topo, "replay_out" );
  fd_topob_wksp( topo, "metric_in"  );
  fd_topob_wksp( topo, "snapmk"     );
  fd_topob_wksp( topo, "snapzp"     );
  fd_topob_wksp( topo, "snapmk_zp"  );
  fd_topob_wksp( topo, "snapmk_replay" );
  fd_topob_wksp( topo, "snaprd"     );
  fd_topob_wksp( topo, "snaprd_out" );
  fd_topob_wksp( topo, "accdb"      );

  /* Stateful workspaces from the stopped validator. */
  fd_topob_wksp( topo, "accdb_data" );
  fd_topob_wksp( topo, "banks"      );
  fd_topob_wksp( topo, "txncache"   );

  fd_topo_obj_t * banks_obj = setup_topo_banks( topo, "banks",
      config->firedancer.runtime.max_live_slots,
      config->firedancer.runtime.max_fork_width,
      config->development.bench.larger_max_cost_per_block );
  FD_TEST( fd_pod_insertf_ulong( topo->props, banks_obj->id, "banks" ) );

  fd_topo_obj_t * txncache_obj = setup_topo_txncache( topo, "txncache",
      config->firedancer.runtime.max_live_slots,
      FD_PACK_MAX_TXNCACHE_TXN_PER_SLOT );
  FD_TEST( fd_pod_insertf_ulong( topo->props, txncache_obj->id, "txncache" ) );

  ulong partition_sz = config->development.accdb.partition_size_gib*(1UL<<30UL);
  fd_topo_obj_t * accdb_obj = setup_topo_accdb( topo, "accdb_data",
      config->firedancer.accounts.max_accounts,
      config->firedancer.runtime.max_live_slots,
      FD_RUNTIME_MAX_WRITABLE_ACCOUNTS_PER_SLOT,
      8192UL,
      partition_sz,
      config->firedancer.accounts.cache_size_gib*(1UL<<30UL),
      config->tiles.bundle.enabled,
      3UL+snapzp_tile_cnt );
  FD_TEST( fd_pod_insertf_ulong( topo->props, accdb_obj->id, "accdb" ) );

  fd_topo_obj_t * zp_fseq = fd_topob_obj( topo, "fseq", "snapmk" );
  FD_TEST( fd_pod_insert_ulong( topo->props, "snapzp.fseq", zp_fseq->id ) );

  fd_topo_obj_t * visited_set = fd_topob_obj( topo, "visited_set", "snapmk" );
  FD_TEST( fd_pod_insertf_ulong( topo->props, config->firedancer.accounts.max_accounts, "obj.%lu.max_accounts", visited_set->id ) );
  FD_TEST( fd_pod_insert_ulong( topo->props, "backup.visited_set", visited_set->id ) );

  fd_topo_obj_t * accdb_epoch = fd_topob_obj( topo, "fseq", "metric_in" );
  FD_TEST( fd_pod_insertf_ulong( topo->props, accdb_epoch->id, "accdb_epoch.snapmk" ) );

  fd_topob_link( topo, "replay_out",    "replay_out",    8192UL, sizeof(fd_replay_message_t), 1UL )->permit_no_producers = 1;
  FOR(snapzp_tile_cnt) fd_topob_link( topo, "snapmk_zp", "snapmk_zp", 1024UL, sizeof(fd_backup_frag_t), 1UL );
  fd_topob_link( topo, "snapmk_replay", "snapmk_replay", 128UL,  0UL,              1UL )->permit_no_consumers = 1;
  fd_topob_link( topo, "snaprd_out",    "snaprd_out",    8192UL, FD_BACKUP_RD_MTU, 1UL );

  fd_topo_tile_t * snapmk_tile = fd_topob_tile( topo, "snapmk", "snapmk", "metric_in", ULONG_MAX, 0, 0, 0 );
  FOR(snapzp_tile_cnt) fd_topob_tile( topo, "snapzp", "snapzp", "metric_in", ULONG_MAX, 0, 0, 0 );
  fd_topo_tile_t * snaprd_tile = fd_topob_tile( topo, "snaprd", "snaprd", "metric_in", ULONG_MAX, 0, 0, 0 );
  fd_topo_tile_t * accdb_tile  = fd_topob_tile( topo, "accdb",  "accdb",  "metric_in", ULONG_MAX, 0, 0, 0 );

  fd_topob_tile_in ( topo, "snapmk", 0UL, "metric_in", "replay_out",    0UL, FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED   );
  FOR(snapzp_tile_cnt) fd_topob_tile_out( topo, "snapmk", 0UL,          "snapmk_zp",     i                                           );
  FOR(snapzp_tile_cnt) fd_topob_tile_in ( topo, "snapzp", i,   "metric_in", "snapmk_zp", i,   FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED   );
  fd_topob_tile_out( topo, "snapmk", 0UL,              "snapmk_replay", 0UL                                         );
  fd_topob_tile_out( topo, "snaprd", 0UL,              "snaprd_out",    0UL                                         );
  fd_topob_tile_in ( topo, "snapmk", 0UL, "metric_in", "snaprd_out",    0UL, FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED   );
  FOR(snapzp_tile_cnt) fd_topob_tile_in ( topo, "snapzp", i, "metric_in", "snaprd_out", 0UL, FD_TOPOB_UNRELIABLE, FD_TOPOB_UNPOLLED );

  fd_topob_tile_uses( topo, snapmk_tile, accdb_obj,    FD_SHMEM_JOIN_MODE_READ_WRITE );
  fd_topob_tile_uses( topo, snapmk_tile, banks_obj,    FD_SHMEM_JOIN_MODE_READ_WRITE );
  fd_topob_tile_uses( topo, snapmk_tile, txncache_obj, FD_SHMEM_JOIN_MODE_READ_ONLY  );
  fd_topob_tile_uses( topo, snapmk_tile, zp_fseq,      FD_SHMEM_JOIN_MODE_READ_WRITE );
  fd_topob_tile_uses( topo, snapmk_tile, visited_set,  FD_SHMEM_JOIN_MODE_READ_WRITE );
  fd_topob_tile_uses( topo, snapmk_tile, accdb_epoch,  FD_SHMEM_JOIN_MODE_READ_WRITE );
  fd_topob_tile_uses( topo, snaprd_tile, accdb_obj,    FD_SHMEM_JOIN_MODE_READ_ONLY  );
  fd_topob_tile_uses( topo, accdb_tile,  accdb_obj,    FD_SHMEM_JOIN_MODE_READ_WRITE );
  fd_topob_tile_uses( topo, accdb_tile,  accdb_epoch,  FD_SHMEM_JOIN_MODE_READ_ONLY  );
  FOR(snapzp_tile_cnt) {
    fd_topo_tile_t * snapzp_tile = &topo->tiles[ fd_topo_find_tile( topo, "snapzp", i ) ];
    fd_topob_tile_uses( topo, snapzp_tile, accdb_obj,   FD_SHMEM_JOIN_MODE_READ_ONLY  );
    fd_topob_tile_uses( topo, snapzp_tile, zp_fseq,     FD_SHMEM_JOIN_MODE_READ_WRITE );
    fd_topob_tile_uses( topo, snapzp_tile, visited_set, FD_SHMEM_JOIN_MODE_READ_WRITE );
  }

# undef FOR

  for( ulong i=0UL; i<topo->tile_cnt; i++ ) fd_topo_configure_tile( &topo->tiles[ i ], config );

  fd_topob_auto_layout( topo, 0 );
  fd_topob_finish( topo, CALLBACKS );
}

static args_t
configure_args( void ) {
  args_t args = {
    .configure.command = CONFIGURE_CMD_INIT,
  };
  ulong stage_idx = 0UL;
  args.configure.stages[ stage_idx++ ] = &fd_cfg_stage_hugetlbfs;
  args.configure.stages[ stage_idx++ ] = NULL;
  return args;
}

static void
open_accdb_fds( config_t const * config ) {
  int fd = open( config->paths.accounts, O_RDWR|O_NOATIME );
  if( FD_UNLIKELY( fd<0 ) ) FD_LOG_ERR(( "open(%s) failed (%i-%s)", config->paths.accounts, errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( dup2( fd, FD_ACCDB_FD_RW )!=FD_ACCDB_FD_RW ) ) FD_LOG_ERR(( "dup2(%d,%d) failed (%i-%s)", fd, FD_ACCDB_FD_RW, errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( close( fd ) ) ) FD_LOG_ERR(( "close(%s) failed (%i-%s)", config->paths.accounts, errno, fd_io_strerror( errno ) ));

  char proc_path[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( proc_path, sizeof(proc_path), NULL, "/proc/self/fd/%d", FD_ACCDB_FD_RW ) );
  int ro_fd = open( proc_path, O_RDONLY|O_NOATIME );
  if( FD_UNLIKELY( ro_fd<0 ) ) FD_LOG_ERR(( "open(%s) failed (%i-%s)", proc_path, errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( dup2( ro_fd, FD_ACCDB_FD_RO )!=FD_ACCDB_FD_RO ) ) FD_LOG_ERR(( "dup2(%d,%d) failed (%i-%s)", ro_fd, FD_ACCDB_FD_RO, errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( close( ro_fd ) ) ) FD_LOG_ERR(( "close(%s) failed (%i-%s)", proc_path, errno, fd_io_strerror( errno ) ));
}

static void
reclaim_accdb_tail_joiners( fd_topo_t * topo ) {
  ulong accdb_obj_id = fd_pod_query_ulong( topo->props, "accdb", ULONG_MAX );
  FD_TEST( accdb_obj_id!=ULONG_MAX );

  fd_accdb_shmem_t * shmem = fd_accdb_shmem_join( fd_topo_obj_laddr( topo, accdb_obj_id ) );
  FD_TEST( shmem );

  ulong joiner_cnt_max = FD_VOLATILE_CONST( shmem->joiner_cnt_max );
  FD_TEST( OFFLINE_ACCDB_JOINER_CNT<=joiner_cnt_max );

  ulong first_offline_joiner = joiner_cnt_max - OFFLINE_ACCDB_JOINER_CNT;

  for( ulong i=first_offline_joiner; i<joiner_cnt_max; i++ ) {
    __atomic_store_n( &shmem->joiner_epochs[ i ].val, ULONG_MAX, __ATOMIC_RELEASE );
  }
  __atomic_store_n( &shmem->joiner_cnt, first_offline_joiner, __ATOMIC_RELEASE );
}

/* Keep progress reporting in sync with src/app/firedancer/commands/snapshot_create.c. */

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
  ulong accounts_packed;
  ulong account_bytes_written;
  ulong data_read_bytes;
  ulong uncompressed_bytes_written;
  ulong compressed_bytes_written;
} snapshot_create_metric_sample_t;

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
monotonic_delta( ulong now,
                 ulong prev ) {
  return FD_LIKELY( now>=prev ) ? now-prev : 0UL;
}

static snapshot_create_metric_sample_t
sample_snapshot_create_metrics( volatile ulong const *  snapmk_metrics,
                                volatile ulong const ** snapzp_metrics,
                                ulong                  snapzp_metrics_cnt ) {
  snapshot_create_metric_sample_t sample = {
    .accounts_packed              = 0UL,
    .account_bytes_written        = 0UL,
    .data_read_bytes              = FD_VOLATILE_CONST( snapmk_metrics[ MIDX( GAUGE, SNAPMK, SNAPSHOT_DATA_READ_BYTES                 ) ] ),
    .uncompressed_bytes_written   = FD_VOLATILE_CONST( snapmk_metrics[ MIDX( GAUGE, SNAPMK, SNAPSHOT_UNCOMPRESSED_DATA_WRITTEN_BYTES ) ] ),
    .compressed_bytes_written     = FD_VOLATILE_CONST( snapmk_metrics[ MIDX( GAUGE, SNAPMK, SNAPSHOT_COMPRESSED_DATA_WRITTEN_BYTES   ) ] )
  };
  for( ulong i=0UL; i<snapzp_metrics_cnt; i++ ) {
    volatile ulong const * metrics = snapzp_metrics[ i ];
    ulong account_bytes_written = FD_VOLATILE_CONST( metrics[ MIDX( GAUGE, SNAPZP, SNAPSHOT_UNCOMPRESSED_DATA_WRITTEN_BYTES ) ] );
    sample.accounts_packed            += FD_VOLATILE_CONST( metrics[ MIDX( GAUGE, SNAPZP, SNAPSHOT_ACCOUNTS_PACKED                 ) ] );
    sample.account_bytes_written      += account_bytes_written;
    sample.uncompressed_bytes_written += account_bytes_written;
    sample.compressed_bytes_written   += FD_VOLATILE_CONST( metrics[ MIDX( GAUGE, SNAPZP, SNAPSHOT_COMPRESSED_DATA_WRITTEN_BYTES   ) ] );
  }
  return sample;
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
log_snapshot_create_progress( volatile ulong const *                  snapmk_metrics,
                              volatile ulong const *                  snaprd_metrics,
                              volatile ulong const **                 snapzp_metrics,
                              ulong                                   snapzp_metrics_cnt,
                              snapshot_create_rate_estimator_t *       rate_estimator,
                              long                                    now ) {
  snapshot_create_metric_sample_t sample = sample_snapshot_create_metrics( snapmk_metrics, snapzp_metrics, snapzp_metrics_cnt );

  ulong progress_bytes = sample.data_read_bytes;
  ulong total_bytes    = FD_VOLATILE_CONST( snaprd_metrics[ MIDX( GAUGE, SNAPRD, EXPORT_TOTAL_BYTES    ) ] );

  update_snapshot_create_rate_estimator( rate_estimator, sample.accounts_packed, sample.account_bytes_written, progress_bytes, sample.uncompressed_bytes_written, sample.compressed_bytes_written, now );

  char compressed_str[ 64UL ]; fmt_bytes( compressed_str, sizeof(compressed_str), sample.uncompressed_bytes_written );
  char written_str  [ 64UL ]; fmt_bytes( written_str,    sizeof(written_str),    sample.compressed_bytes_written   );

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
  char accounts_str[ 64UL ]; fmt_sci( accounts_str, sizeof(accounts_str), (double)sample.accounts_packed, 10, 4 );
  char accounts_rate_str[ 64UL ]; fmt_sci( accounts_rate_str, sizeof(accounts_rate_str), accounts_per_second, 10, 4 );
  char account_size_str[ 64UL ];
  if( FD_LIKELY( accounts_sum ) ) fmt_bytes( account_size_str, sizeof(account_size_str), account_bytes_sum / accounts_sum );
  else FD_TEST( fd_cstr_printf_check( account_size_str, sizeof(account_size_str), NULL, "%11s", "-" ) );

  double pct = total_bytes ? 100.0 * (double)fd_ulong_min( progress_bytes, total_bytes ) / (double)total_bytes : 0.0;
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
wait_snapshot_create_offline( volatile ulong const *            snapmk_metrics,
                              volatile ulong const *            snaprd_metrics,
                              volatile ulong const **           snapzp_metrics,
                              ulong                             snapzp_metrics_cnt,
                              ulong                             start_snapshots_created,
                              ulong *                           final_bytes_written ) {
  snapshot_create_rate_estimator_t rate_estimator = {0};

  int  started  = 0;
  int  metrics_rebased = 0;
  long next_log = fd_log_wallclock();
  for(;;) {
    ulong state = FD_VOLATILE_CONST( snapmk_metrics[ MIDX( GAUGE, SNAPMK, STATE ) ] );
    ulong snapshots_created = FD_VOLATILE_CONST( snapmk_metrics[ MIDX( COUNTER, SNAPMK, SNAPSHOTS_CREATED ) ] );

    if( FD_UNLIKELY( snapshots_created!=start_snapshots_created ) ) started = 1;

    int metrics_ready = started && !metrics_rebased;
    if( FD_LIKELY( metrics_ready ) ) {
      ulong progress_bytes = FD_VOLATILE_CONST( snaprd_metrics[ MIDX( GAUGE, SNAPRD, EXPORT_PROGRESS_BYTES ) ] );
      ulong total_bytes    = FD_VOLATILE_CONST( snaprd_metrics[ MIDX( GAUGE, SNAPRD, EXPORT_TOTAL_BYTES    ) ] );
      metrics_ready = state>=SNAPMK_STATE_ACCOUNTS_DISK && total_bytes>0UL &&
                      ( state>SNAPMK_STATE_ACCOUNTS_DISK || progress_bytes<total_bytes );
    }
    if( FD_UNLIKELY( metrics_ready ) ) {
      memset( &rate_estimator, 0, sizeof(rate_estimator) );
      metrics_rebased = 1;
      next_log = fd_log_wallclock() + 1000L*1000L*1000L;
    }
    if( FD_LIKELY( metrics_rebased ) ) {
      snapshot_create_metric_sample_t sample = sample_snapshot_create_metrics( snapmk_metrics, snapzp_metrics, snapzp_metrics_cnt );
      *final_bytes_written = fd_ulong_max( *final_bytes_written, sample.compressed_bytes_written );
    }
    if( FD_UNLIKELY( started && state==SNAPMK_STATE_FAIL ) ) FD_LOG_ERR(( "snapshot creation failed" ));
    if( FD_LIKELY( started && state==SNAPMK_STATE_IDLE ) ) break;

    long now = fd_log_wallclock();
    if( FD_UNLIKELY( now>=next_log ) ) {
      if( FD_LIKELY( metrics_rebased ) ) {
        log_snapshot_create_progress( snapmk_metrics, snaprd_metrics, snapzp_metrics, snapzp_metrics_cnt, &rate_estimator, now );
      }
      next_log = now + 1000L*1000L*1000L;
    }
    fd_log_sleep( (long)1e6 );
  }
}

static void
snapshot_create_offline_cmd_fn( args_t *   args,
                                config_t * config ) {
  (void)args;

  fd_topo_t * topo = &config->topo;
  args_t c_args = configure_args();
  configure_cmd_fn( &c_args, config );

  open_accdb_fds( config );

  for( ulong i=0UL; i<topo->wksp_cnt; i++ ) {
    fd_topo_wksp_t * wksp = &topo->workspaces[ i ];
    if( !strcmp( wksp->name, "accdb_data" ) ) continue;
    if( !strcmp( wksp->name, "banks"      ) ) continue;
    if( !strcmp( wksp->name, "txncache"   ) ) continue;

    if( FD_UNLIKELY( fd_topo_create_workspace( topo, wksp, 1 )==-1 ) ) {
      FD_TEST( fd_topo_create_workspace( topo, wksp, 0 )==0 );
    }
    fd_topo_join_workspace( topo, wksp, FD_SHMEM_JOIN_MODE_READ_WRITE, 0 );
    fd_topo_wksp_new( topo, wksp, CALLBACKS );
    fd_topo_leave_workspace( topo, wksp );
  }

  initialize_stacks( config );

  fd_topo_join_workspaces( topo, FD_SHMEM_JOIN_MODE_READ_WRITE, FD_TOPO_CORE_DUMP_LEVEL_DISABLED );
  fd_topo_fill( topo );
  reclaim_accdb_tail_joiners( topo );

  ulong replay_out_link_id = fd_topo_find_link( topo, "replay_out", 0UL ); FD_TEST( replay_out_link_id!=ULONG_MAX );
  fd_topo_link_t const * replay_out_link = &topo->links[ replay_out_link_id ];
  fd_frag_meta_t *       replay_mcache   = replay_out_link->mcache; FD_TEST( replay_mcache );
  void *                 replay_dcache   = replay_out_link->dcache; FD_TEST( replay_dcache );
  fd_wksp_t *            replay_wksp     = fd_wksp_containing( replay_dcache ); FD_TEST( replay_wksp );
  ulong                  replay_depth    = fd_mcache_depth( replay_mcache );
  for( ulong i=0UL; i<replay_depth; i++ ) replay_mcache[ i ].seq = i-1UL;
  fd_mcache_seq_update( fd_mcache_seq_laddr( replay_mcache ), ULONG_MAX );

  fd_topo_run_single_process( topo, 2, config->uid, config->gid, fdctl_tile_run );

  ulong banks_obj_id = fd_pod_query_ulong( topo->props, "banks", ULONG_MAX ); FD_TEST( banks_obj_id!=ULONG_MAX );
  fd_banks_t * banks = fd_banks_join( fd_topo_obj_laddr( topo, banks_obj_id ) ); FD_TEST( banks );
  ulong bank_idx = banks->root_idx;
  FD_TEST( bank_idx < banks->max_total_banks );

  ulong snapmk_tile_id = fd_topo_find_tile( topo, "snapmk", 0UL ); FD_TEST( snapmk_tile_id!=ULONG_MAX );
  fd_topo_tile_t const * snapmk_tile = &topo->tiles[ snapmk_tile_id ];
  volatile ulong const * snapmk_metrics = fd_metrics_tile( snapmk_tile->metrics );

  ulong snaprd_tile_id = fd_topo_find_tile( topo, "snaprd", 0UL ); FD_TEST( snaprd_tile_id!=ULONG_MAX );
  fd_topo_tile_t const * snaprd_tile = &topo->tiles[ snaprd_tile_id ];
  volatile ulong const * snaprd_metrics = fd_metrics_tile( snaprd_tile->metrics );

  ulong snapzp_cnt = fd_topo_tile_name_cnt( topo, "snapzp" );
  volatile ulong const * snapzp_metrics[ FD_TOPO_MAX_TILES ];
  for( ulong i=0UL; i<snapzp_cnt; i++ ) {
    ulong snapzp_tile_id = fd_topo_find_tile( topo, "snapzp", i ); FD_TEST( snapzp_tile_id!=ULONG_MAX );
    snapzp_metrics[ i ] = fd_metrics_tile( topo->tiles[ snapzp_tile_id ].metrics );
  }

  ulong start_snapshots_created = FD_VOLATILE_CONST( snapmk_metrics[ MIDX( COUNTER, SNAPMK, SNAPSHOTS_CREATED ) ] );
  ulong final_bytes_written     = 0UL;

  ulong chunk0 = fd_dcache_compact_chunk0( replay_wksp, replay_dcache );
  fd_replay_snap_create_t * msg = fd_chunk_to_laddr( replay_wksp, chunk0 );
  msg->bank_idx = bank_idx;
  ulong chunk = fd_laddr_to_chunk( replay_wksp, msg );
  ulong ctl   = fd_frag_meta_ctl( 0, 1, 1, 0 );
  ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );
  fd_mcache_publish( replay_mcache, replay_depth, 0UL, REPLAY_SIG_SNAP_CREATE, chunk, sizeof(fd_replay_snap_create_t), ctl, 0UL, tspub );

  wait_snapshot_create_offline( snapmk_metrics, snaprd_metrics, snapzp_metrics, snapzp_cnt,
                                start_snapshots_created, &final_bytes_written );

  if( FD_UNLIKELY( close( FD_ACCDB_FD_RO ) ) ) FD_LOG_ERR(( "close(FD_ACCDB_FD_RO) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( close( FD_ACCDB_FD_RW ) ) ) FD_LOG_ERR(( "close(FD_ACCDB_FD_RW) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
}

action_t fd_action_snapshot_create_offline = {
  .name           = "snapshot-create-offline",
  .topo           = snapshot_create_offline_topo,
  .fn             = snapshot_create_offline_cmd_fn,
  .description    = "Create a snapshot (offline)",
  .require_config = 1
};
