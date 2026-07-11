#include "watch.h"
#include "generated/watch_seccomp.h"

#include "../../fd_bootinfo.h"

#include "../../../../discof/restore/fd_snapct_tile.h"
#include "../../../../discof/gossip/fd_gossip_tile.h"
#include "../../../../disco/metrics/fd_metrics.h"
#include "../../../../disco/node_info/fd_node_info.h"
#include "../../../../disco/genesis/fd_genesis_cluster.h"
#include "../../../../util/pod/fd_pod.h"
#include "../../../../util/tile/fd_tile.h"

#include <errno.h>
#include <unistd.h>
#include <sys/resource.h>
#include <linux/capability.h>

void
watch_cmd_perm( args_t *         args FD_PARAM_UNUSED,
                fd_cap_chk_t *   chk,
                config_t const * config ) {
  ulong mlock_limit = fd_topo_mlock( &config->topo );

  fd_cap_chk_raise_rlimit( chk, "watch", RLIMIT_MEMLOCK, mlock_limit, "call `rlimit(2)` to increase `RLIMIT_MEMLOCK` so all memory can be locked with `mlock(2)`" );

  if( fd_sandbox_requires_cap_sys_admin( config->uid, config->gid ) )
    fd_cap_chk_cap( chk, "watch", CAP_SYS_ADMIN,               "call `unshare(2)` with `CLONE_NEWUSER` to sandbox the process in a user namespace" );
  if( FD_LIKELY( getuid() != config->uid ) )
    fd_cap_chk_cap( chk, "watch", CAP_SETUID,                  "call `setresuid(2)` to switch uid to the sanbox user" );
  if( FD_LIKELY( getgid() != config->gid ) )
    fd_cap_chk_cap( chk, "watch", CAP_SETGID,                  "call `setresgid(2)` to switch gid to the sandbox user" );
}


static ulong lines_printed;
static int ended_on_newline = 1;

static char  frame_buf[ 65536UL ];
static ulong frame_len;

/* Show all category detail rows, not just the primary row of each.
   Set from --full. */
static int watch_full = 0;

static void
flush_frame( void ) {
  ulong written = 0UL;
  while( written<frame_len ) {
    long w = write( STDOUT_FILENO, frame_buf+written, frame_len-written );
    if( FD_UNLIKELY( -1==w && errno==EAGAIN ) ) continue;
    else if( FD_UNLIKELY( -1==w ) ) FD_LOG_ERR(( "write() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    else if( FD_UNLIKELY( 0==w ) ) break;
    written += (ulong)w;
  }
  frame_len = 0UL;
}

static int
drain( int fd ) {
  int needs_reprint = 0;

  while( 1 ) {
    uchar buf[ 16384UL ];
    long result = read( fd, buf, sizeof(buf) );
    if( FD_UNLIKELY( -1==result && errno==EAGAIN ) ) break;
    else if( FD_UNLIKELY( -1==result ) ) FD_LOG_ERR(( "read() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

    if( FD_LIKELY( !needs_reprint ) ) {
      /* Buffer the erase sequence and first log chunk together so the
         terminal never renders a blank frame between erase and content. */
      frame_len = 0UL;
      if( FD_UNLIKELY( !ended_on_newline ) ) {
        FD_TEST( fd_cstr_printf_check( frame_buf, sizeof(frame_buf), &frame_len, "\033[%luA\033[%luM\033[1A\033[0J", lines_printed, lines_printed ) );
      } else {
        FD_TEST( fd_cstr_printf_check( frame_buf, sizeof(frame_buf), &frame_len, "\033[%luA\033[%luM\033[0J", lines_printed, lines_printed ) );
      }
    }
    FD_TEST( frame_len+(ulong)result<=sizeof(frame_buf) );
    fd_memcpy( frame_buf+frame_len, buf, (ulong)result );
    frame_len += (ulong)result;
    flush_frame();
    needs_reprint = 1;

    ended_on_newline = buf[ (ulong)result-1UL ]=='\n';
  }

  return needs_reprint;
}

static char *
fmt_bytes( char * buf,
           ulong  buf_sz,
           long   bytes ) {
  char * tmp = fd_alloca_check( 1UL, buf_sz );
  if( FD_LIKELY( 8L*bytes<1000L ) ) FD_TEST( fd_cstr_printf_check( tmp, buf_sz, NULL, "%ld bits", 8L*bytes ) );
  else if( FD_LIKELY( 8L*bytes<1000000L ) ) FD_TEST( fd_cstr_printf_check( tmp, buf_sz, NULL, "%.1f Kbit", (double)(8L*bytes)/1000.0 ) );
  else if( FD_LIKELY( 8L*bytes<1000000000L ) ) FD_TEST( fd_cstr_printf_check( tmp, buf_sz, NULL, "%.1f Mbit", (double)(8L*bytes)/1000000.0 ) );
  else FD_TEST( fd_cstr_printf_check( tmp, buf_sz, NULL, "%.1f Gbit", (double)(8L*bytes)/1000000000.0 ) );

  FD_TEST( fd_cstr_printf_check( buf, buf_sz, NULL, "%10s", tmp ) );
  return buf;
}

static char *
fmt_count( char * buf,
           ulong  buf_sz,
           ulong  count ) {
  char * tmp = fd_alloca_check( 1UL, buf_sz );
  if( FD_LIKELY( count<1000UL ) ) FD_TEST( fd_cstr_printf_check( tmp, buf_sz, NULL, "%lu", count ) );
  else if( FD_LIKELY( count<1000000UL ) ) FD_TEST( fd_cstr_printf_check( tmp, buf_sz, NULL, "%.1f K", (double)count/1000.0 ) );
  else if( FD_LIKELY( count<1000000000UL ) ) FD_TEST( fd_cstr_printf_check( tmp, buf_sz, NULL, "%.1f M", (double)count/1000000.0 ) );

  FD_TEST( fd_cstr_printf_check( buf, buf_sz, NULL, "%10s", tmp ) );
  return buf;
}

static char *
fmt_countf( char * buf,
            ulong  buf_sz,
            double count ) {
  char * tmp = fd_alloca_check( 1UL, buf_sz );
  if( FD_LIKELY( count<1000UL ) ) FD_TEST( fd_cstr_printf_check( tmp, buf_sz, NULL, "%.1f", count ) );
  else if( FD_LIKELY( count<1000000UL ) ) FD_TEST( fd_cstr_printf_check( tmp, buf_sz, NULL, "%.1f K", (double)count/1000.0 ) );
  else if( FD_LIKELY( count<1000000000UL ) ) FD_TEST( fd_cstr_printf_check( tmp, buf_sz, NULL, "%.1f M", (double)count/1000000.0 ) );
  else memcpy( tmp, "-", 2UL );

  FD_TEST( fd_cstr_printf_check( buf, buf_sz, NULL, "%10s", tmp ) );
  return buf;
}

static char *
fmt_count_tight( char * buf,
                 ulong  buf_sz,
                 ulong  count ) {
  char * tmp = fd_alloca_check( 1UL, buf_sz );
  if(      count<1000UL )       FD_TEST( fd_cstr_printf_check( tmp, buf_sz, NULL, "%lu",    count            ) );
  else if( count<1000000UL )    FD_TEST( fd_cstr_printf_check( tmp, buf_sz, NULL, "%.1fK", (double)count/1e3 ) );
  else if( count<1000000000UL ) FD_TEST( fd_cstr_printf_check( tmp, buf_sz, NULL, "%.1fM", (double)count/1e6 ) );
  else                          FD_TEST( fd_cstr_printf_check( tmp, buf_sz, NULL, "%.1fG", (double)count/1e9 ) );
  FD_TEST( fd_cstr_printf_check( buf, buf_sz, NULL, "%6s", tmp ) );
  return buf;
}

static char *
fmt_countf_tight( char * buf,
                  ulong  buf_sz,
                  double count ) {
  char * tmp = fd_alloca_check( 1UL, buf_sz );
  if(      count<1000.0 )       FD_TEST( fd_cstr_printf_check( tmp, buf_sz, NULL, "%.1f",  count     ) );
  else if( count<1000000.0 )    FD_TEST( fd_cstr_printf_check( tmp, buf_sz, NULL, "%.1fK", count/1e3 ) );
  else if( count<1000000000.0 ) FD_TEST( fd_cstr_printf_check( tmp, buf_sz, NULL, "%.1fM", count/1e6 ) );
  else                          FD_TEST( fd_cstr_printf_check( tmp, buf_sz, NULL, "%.1fG", count/1e9 ) );
  FD_TEST( fd_cstr_printf_check( buf, buf_sz, NULL, "%6s", tmp ) );
  return buf;
}

static long
diff_link( config_t const * config,
                 char const *     link_name,
                 ulong const *    prev_link,
                 ulong const *    cur_link,
                 ulong            idx ) {
  long result = 0L;

  ulong overall_polled_idx = 0UL;
  for( ulong i=0UL; i<config->topo.tile_cnt; i++ ) {
    fd_topo_tile_t const * tile = &config->topo.tiles[ i ];
    for( ulong j=0UL; j<config->topo.tiles[ i ].in_cnt; j++ ) {
      fd_topo_link_t const * link = &config->topo.links[ tile->in_link_id[ j ] ];
      if( FD_UNLIKELY( !tile->in_link_poll[ j ] ) ) continue;

      if( FD_LIKELY( !strcmp( link->name, link_name ) ) ) {
        result += (long)cur_link[ overall_polled_idx*8UL+idx ]-(long)prev_link[ overall_polled_idx*8UL+idx ];
      }

      overall_polled_idx++;
    }
  }
  return result;
}

static long
diff_tile( config_t const * config,
           char const *     tile_name,
           ulong const *    prev_tile,
           ulong const *    cur_tile,
           ulong            idx ) {
  long result = 0L;

  for( ulong i=0UL; i<config->topo.tile_cnt; i++ ) {
    fd_topo_tile_t const * tile = &config->topo.tiles[ i ];
    if( FD_UNLIKELY( strcmp( tile->name, tile_name ) ) ) continue;
    result += (long)cur_tile[ i*FD_METRICS_TOTAL_SZ+idx ]-(long)prev_tile[ i*FD_METRICS_TOTAL_SZ+idx ];
  }
  return result;
}

static ulong
total_crds( ulong const * metrics ) {
  ulong sum = 0UL;
  for( ulong i=0UL; i<FD_METRICS_ENUM_CRDS_VALUE_CNT; i++ ) {
    sum += metrics[ MIDX( GAUGE, GOSSIP, CRDS_OCCUPIED_CONTACT_INFO_V1 )+i ];
  }
  return sum;
}

static ulong
total_regime( ulong const * metrics ) {
  ulong sum = 0UL;
  for( ulong i=0UL; i<FD_METRICS_ENUM_TILE_REGIME_CNT; i++ ) {
    sum += metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS )+i ];
  }
  return sum;
}

/* Bench */
static ulong tps_sent_samples_idx = 0UL;
static ulong tps_sent_samples[ 200UL ];
/* Replay */
static ulong cups_samples_idx = 0UL;
static ulong cups_samples[ 100UL ];
static ulong sps_samples_idx = 0UL;
static ulong sps_samples[ 200UL ];
static ulong tps_samples_idx = 0UL;
static ulong tps_samples[ 200UL ];
/* Snapshot */
static ulong snapshot_rx_idx = 0UL;
static ulong snapshot_rx_samples[ 100UL ];
static ulong snapshot_acc_idx = 0UL;
static ulong snapshot_acc_samples[ 100UL ];
static ulong snapshot_wr_idx = 0UL;
static ulong snapshot_wr_samples[ 100UL ];
/* Event */
static ulong events_sent_samples_idx = 0UL;
static ulong events_sent_samples[ 100UL ];
static ulong events_acked_samples_idx = 0UL;
static ulong events_acked_samples[ 100UL ];
static ulong event_bytes_written_samples_idx = 0UL;
static ulong event_bytes_written_samples[ 100UL ];
static ulong event_bytes_read_samples_idx = 0UL;
static ulong event_bytes_read_samples[ 100UL ];
/* Accounts */
static ulong accdb_samples_idx = 0UL;
static ulong accdb_acquired_samples[ 200UL ];
static ulong accdb_writable_samples[ 200UL ];
static ulong accdb_missed_samples  [ 200UL ];
static ulong accdb_evicted_samples [ 200UL ];
static ulong accdb_waited_samples  [ 200UL ];
static ulong accdb_bytes_rd_samples[ 200UL ];
static ulong accdb_bytes_wr_samples[ 200UL ];
static ulong accdb_bytes_cp_samples[ 200UL ];
static ulong accdb_bytes_pe_samples[ 200UL ];
static ulong accdb_evicted_class_samples[ 8UL ][ 200UL ];
static ulong accdb_preevicted_samples[ 200UL ];
static ulong accdb_preevicted_class_samples[ 8UL ][ 200UL ];
static ulong accdb_committed_new_class_samples[ 8UL ][ 200UL ];
static ulong accdb_committed_overwrite_class_samples[ 8UL ][ 200UL ];
/* Repair server */
static ulong shreds_stored_samples_idx = 0UL;
static ulong shreds_stored_sample[ 200UL ]  ;
static ulong rserve_rps_valid_samples_idx = 0UL;
static ulong rserve_rps_valid_samples[ 100UL ];
static ulong rserve_rps_invalid_samples_idx = 0UL;
static ulong rserve_rps_invalid_samples[ 100UL ];
static ulong rserve_rps_miss_samples[ 100UL ];
static ulong rserve_rps_sigvfy_samples[ 100UL ];
static ulong rserve_rps_stale_samples[ 100UL ];
static ulong rserve_rps_other_rej_samples[ 100UL ];

#define RESET   "\033[0m"
#define BOLD    "\033[1m"
#define UNBOLD  "\033[22m"

#define RED     "\033[31m"
#define GREEN   "\033[32m"
#define ORANGE  "\033[38;5;208m"
#define YELLOW  "\033[33m"
#define BLUE    "\033[34m"
#define MAGENTA "\033[35m"
#define CYAN    "\033[36m"

#define BGREEN  "\033[92m"
#define BYELLOW "\033[93m"

#define CLEARLN "\033[K"

#define PRINT(...) do {                          \
  ulong _len;                                    \
  FD_TEST( fd_cstr_printf_check( frame_buf+frame_len, sizeof(frame_buf)-frame_len, &_len, __VA_ARGS__ ) ); \
  frame_len += _len;                             \
} while(0)

#define DIFF_LINK_BYTES( link_name, metric_type, metric_subtype, metric ) (__extension__({ \
    long bytes = diff_link( config, link_name, prev_link, cur_link, MIDX( metric_type, metric_subtype, metric ) ); \
     fmt_bytes( fd_alloca_check( 1UL, 64UL ), 64UL, bytes );                               \
  }))

#define DIFF_BYTES( tile_name, metric_type, metric_subtype, metric ) (__extension__({ \
    long bytes = diff_tile( config, tile_name, prev_tile, cur_tile, MIDX( metric_type, metric_subtype, metric ) ); \
     fmt_bytes( fd_alloca_check( 1UL, 64UL ), 64UL, bytes );                               \
  }))

#define COUNT( count ) (__extension__({                     \
    fmt_count( fd_alloca_check( 1UL, 64UL ), 64UL, count ); \
  }))

#define COUNTF( count ) (__extension__({                     \
    fmt_countf( fd_alloca_check( 1UL, 64UL ), 64UL, count ); \
  }))

#define COUNT_T( count ) (__extension__({                          \
    fmt_count_tight( fd_alloca_check( 1UL, 32UL ), 32UL, count );  \
  }))

#define COUNTF_T( count ) (__extension__({                         \
    fmt_countf_tight( fd_alloca_check( 1UL, 32UL ), 32UL, count ); \
  }))

static int
write_bench( config_t const * config,
             ulong const *    cur_tile,
             ulong const *    prev_tile ) {
  if( FD_UNLIKELY( fd_topo_find_tile( &config->topo, "benchs", 0UL )==ULONG_MAX ) ) return 0;

  ulong tps_sum = 0UL;
  ulong num_tps_samples = fd_ulong_min( tps_sent_samples_idx, sizeof(tps_sent_samples)/sizeof(tps_sent_samples[0]));
  for( ulong i=0UL; i<num_tps_samples; i++ ) tps_sum += tps_sent_samples[ i ];
  char * tps_str = COUNTF( 100.0*(double)tps_sum/(double)num_tps_samples );

  PRINT( "🌶  " BOLD BGREEN "BENCH......." RESET UNBOLD
         " " BOLD "GENERATED TPS" UNBOLD " %s"
         " " BOLD "BENCHG BUSY"   UNBOLD, tps_str );
  for( ulong i=0UL; i<config->topo.tile_cnt; i++ ) {
    if( FD_LIKELY( strcmp( config->topo.tiles[ i ].name, "benchg" ) ) ) continue;

    ulong total_ticks = total_regime( &cur_tile[ i*FD_METRICS_TOTAL_SZ ] )-total_regime( &prev_tile[ i*FD_METRICS_TOTAL_SZ ] );
    double backp_pct = 100.0*(double)( diff_tile( config, "benchg", prev_tile, cur_tile, MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_BACKPRESSURE_PREFRAG ) ) )/(double)total_ticks;
    double idle_pct = 100.0*(double)( diff_tile( config, "benchg", prev_tile, cur_tile, MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_CAUGHT_UP_POSTFRAG ) ) )/(double)total_ticks;
    double busy_pct = 100.0 - idle_pct - backp_pct;

    PRINT( " %.1f %%", busy_pct );
  }

  PRINT( " " BOLD "BENCHS BUSY" UNBOLD );
  for( ulong i=0UL; i<config->topo.tile_cnt; i++ ) {
    if( FD_LIKELY( strcmp( config->topo.tiles[ i ].name, "benchs" ) ) ) continue;

    ulong total_ticks = total_regime( &cur_tile[ i*FD_METRICS_TOTAL_SZ ] )-total_regime( &prev_tile[ i*FD_METRICS_TOTAL_SZ ] );
    double backp_pct = 100.0*(double)( diff_tile( config, "benchs", prev_tile, cur_tile, MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_BACKPRESSURE_PREFRAG ) ) )/(double)total_ticks;
    double idle_pct = 100.0*(double)( diff_tile( config, "benchs", prev_tile, cur_tile, MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_CAUGHT_UP_POSTFRAG ) ) )/(double)total_ticks;
    double busy_pct = 100.0 - idle_pct - backp_pct;

    PRINT( " %.1f %%", busy_pct );
  }

  PRINT( CLEARLN "\n" );
  return 1;
}

static void
write_backtest( config_t const * config,
                ulong const *    cur_tile ) {
  ulong backt_idx = fd_topo_find_tile( &config->topo, "backt", 0UL );
  ulong start_slot = cur_tile[ backt_idx*FD_METRICS_TOTAL_SZ+MIDX( GAUGE, BACKT, START_SLOT ) ];
  ulong final_slot = cur_tile[ backt_idx*FD_METRICS_TOTAL_SZ+MIDX( GAUGE, BACKT, FINAL_SLOT ) ];

  ulong replay_idx = fd_topo_find_tile( &config->topo, "replay", 0UL );
  ulong current_slot = cur_tile[ replay_idx*FD_METRICS_TOTAL_SZ+MIDX( GAUGE, REPLAY, ROOT_SLOT ) ];
  current_slot = current_slot ? current_slot : start_slot;

  ulong completed_slots = current_slot-start_slot;

  if( FD_UNLIKELY( final_slot==ULONG_MAX ) ) {
    PRINT( "🧪 " BOLD BGREEN "BACKTEST...." RESET UNBOLD
            " " BOLD "PCT" UNBOLD "     ? (%lu/?)" CLEARLN "\n", completed_slots );
    return;
  }

  ulong  total_slots = final_slot-start_slot;
  double progress    = total_slots ? 100.0 * (double)completed_slots / (double)total_slots : 100.0;
  PRINT( "🧪 " BOLD BGREEN "BACKTEST...." RESET UNBOLD
         " " BOLD "PCT" UNBOLD " %.1f %% (%lu/%lu)" CLEARLN "\n",
    progress, completed_slots, total_slots );
}

static void
write_snapshots( config_t const * config,
                 ulong const *    cur_tile,
                 ulong const *    prev_tile ) {
  ulong snapct_idx = fd_topo_find_tile( &config->topo, "snapct", 0UL );
  ulong state = cur_tile[ snapct_idx*FD_METRICS_TOTAL_SZ+MIDX( GAUGE, SNAPCT, STATE ) ];

  ulong bytes_read = cur_tile[ snapct_idx*FD_METRICS_TOTAL_SZ+MIDX( GAUGE, SNAPCT, FULL_BYTES_READ ) ];
  ulong bytes_total = cur_tile[ snapct_idx*FD_METRICS_TOTAL_SZ+MIDX( GAUGE, SNAPCT, FULL_SIZE_BYTES ) ];

  double progress = 0.0;
  switch( state ) {
    case FD_SNAPCT_STATE_WAITING_FOR_PEERS:
    case FD_SNAPCT_STATE_WAITING_FOR_PEERS_INCREMENTAL:
    case FD_SNAPCT_STATE_COLLECTING_PEERS:
    case FD_SNAPCT_STATE_COLLECTING_PEERS_INCREMENTAL:
      break;
    case FD_SNAPCT_STATE_READING_FULL_FILE:
    case FD_SNAPCT_STATE_FLUSHING_FULL_FILE_FINI:
    case FD_SNAPCT_STATE_FLUSHING_FULL_FILE_DONE:
    case FD_SNAPCT_STATE_READING_INCREMENTAL_FILE:
    case FD_SNAPCT_STATE_FLUSHING_INCREMENTAL_FILE_FINI:
    case FD_SNAPCT_STATE_FLUSHING_INCREMENTAL_FILE_DONE:
    case FD_SNAPCT_STATE_READING_FULL_HTTP:
    case FD_SNAPCT_STATE_FLUSHING_FULL_HTTP_FINI:
    case FD_SNAPCT_STATE_FLUSHING_FULL_HTTP_DONE:
    case FD_SNAPCT_STATE_READING_INCREMENTAL_HTTP:
    case FD_SNAPCT_STATE_FLUSHING_INCREMENTAL_HTTP_FINI:
    case FD_SNAPCT_STATE_FLUSHING_INCREMENTAL_HTTP_DONE:
      if( FD_LIKELY( bytes_total>0UL ) ) progress = 100.0 * (double)bytes_read / (double)bytes_total;
      break;
    case FD_SNAPCT_STATE_SHUTDOWN:
      progress = 100.0;
      break;
  }

  ulong snap_rx_sum = 0UL;
  ulong num_snap_rx_samples = fd_ulong_min( snapshot_rx_idx, sizeof(snapshot_rx_samples)/sizeof(snapshot_rx_samples[0]) );
  for( ulong i=0UL; i<num_snap_rx_samples; i++ ) snap_rx_sum += snapshot_rx_samples[ i ];
  double megabytes_per_second = 0.0;
  if( FD_LIKELY( num_snap_rx_samples ) ) megabytes_per_second = 100.0*(double)snap_rx_sum/(double)num_snap_rx_samples/1e6;

  ulong accounts_sum = 0UL;
  ulong num_accounts_samples = fd_ulong_min( snapshot_acc_idx, sizeof(snapshot_acc_samples)/sizeof(snapshot_acc_samples[0]) );
  for( ulong i=0UL; i<num_accounts_samples; i++ ) accounts_sum += snapshot_acc_samples[ i ];
  double million_accounts_per_second = 0.0;
  if( FD_LIKELY( num_accounts_samples ) ) million_accounts_per_second = 100.0*(double)accounts_sum/(double)num_accounts_samples/1e6;

  ulong snap_wr_sum = 0UL;
  ulong num_snap_wr_samples = fd_ulong_min( snapshot_wr_idx, sizeof(snapshot_wr_samples)/sizeof(snapshot_wr_samples[0]) );
  for( ulong i=0UL; i<num_snap_wr_samples; i++ ) snap_wr_sum += snapshot_wr_samples[ i ];
  double wr_megabytes_per_second = 0.0;
  if( FD_LIKELY( num_snap_wr_samples ) ) wr_megabytes_per_second = 100.0*(double)snap_wr_sum/(double)num_snap_wr_samples/1e6;

  ulong snapct_total_ticks = total_regime( &cur_tile[ snapct_idx*FD_METRICS_TOTAL_SZ ] )-total_regime( &prev_tile[ snapct_idx*FD_METRICS_TOTAL_SZ ] );
  ulong snapld_total_ticks = total_regime( &cur_tile[ fd_topo_find_tile( &config->topo, "snapld", 0UL )*FD_METRICS_TOTAL_SZ ] )-total_regime( &prev_tile[ fd_topo_find_tile( &config->topo, "snapld", 0UL )*FD_METRICS_TOTAL_SZ ] );
  ulong snapdc_total_ticks = total_regime( &cur_tile[ fd_topo_find_tile( &config->topo, "snapdc", 0UL )*FD_METRICS_TOTAL_SZ ] )-total_regime( &prev_tile[ fd_topo_find_tile( &config->topo, "snapdc", 0UL )*FD_METRICS_TOTAL_SZ ] );
  ulong snapin_total_ticks = total_regime( &cur_tile[ fd_topo_find_tile( &config->topo, "snapin", 0UL )*FD_METRICS_TOTAL_SZ ] )-total_regime( &prev_tile[ fd_topo_find_tile( &config->topo, "snapin", 0UL )*FD_METRICS_TOTAL_SZ ] );
  ulong snapwr_total_ticks = total_regime( &cur_tile[ fd_topo_find_tile( &config->topo, "snapwr", 0UL )*FD_METRICS_TOTAL_SZ ] )-total_regime( &prev_tile[ fd_topo_find_tile( &config->topo, "snapwr", 0UL )*FD_METRICS_TOTAL_SZ ] );
  snapct_total_ticks = fd_ulong_max( snapct_total_ticks, 1UL );
  snapld_total_ticks = fd_ulong_max( snapld_total_ticks, 1UL );
  snapdc_total_ticks = fd_ulong_max( snapdc_total_ticks, 1UL );
  snapin_total_ticks = fd_ulong_max( snapin_total_ticks, 1UL );
  snapwr_total_ticks = fd_ulong_max( snapwr_total_ticks, 1UL );

  double snapct_backp_pct = 100.0*(double)diff_tile( config, "snapct", prev_tile, cur_tile, MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_BACKPRESSURE_PREFRAG ) )/(double)snapct_total_ticks;
  double snapld_backp_pct = 100.0*(double)diff_tile( config, "snapld", prev_tile, cur_tile, MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_BACKPRESSURE_PREFRAG ) )/(double)snapld_total_ticks;
  double snapdc_backp_pct = 100.0*(double)diff_tile( config, "snapdc", prev_tile, cur_tile, MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_BACKPRESSURE_PREFRAG ) )/(double)snapdc_total_ticks;
  double snapin_backp_pct = 100.0*(double)diff_tile( config, "snapin", prev_tile, cur_tile, MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_BACKPRESSURE_PREFRAG ) )/(double)snapin_total_ticks;
  double snapwr_backp_pct = 100.0*(double)diff_tile( config, "snapwr", prev_tile, cur_tile, MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_BACKPRESSURE_PREFRAG ) )/(double)snapwr_total_ticks;

  double snapct_idle_pct = 100.0*(double)diff_tile( config, "snapct", prev_tile, cur_tile, MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_CAUGHT_UP_POSTFRAG ) )/(double)snapct_total_ticks;
  double snapld_idle_pct = 100.0*(double)diff_tile( config, "snapld", prev_tile, cur_tile, MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_CAUGHT_UP_POSTFRAG ) )/(double)snapld_total_ticks;
  double snapdc_idle_pct = 100.0*(double)diff_tile( config, "snapdc", prev_tile, cur_tile, MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_CAUGHT_UP_POSTFRAG ) )/(double)snapdc_total_ticks;
  double snapin_idle_pct = 100.0*(double)diff_tile( config, "snapin", prev_tile, cur_tile, MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_CAUGHT_UP_POSTFRAG ) )/(double)snapin_total_ticks;
  double snapwr_idle_pct = 100.0*(double)diff_tile( config, "snapwr", prev_tile, cur_tile, MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_CAUGHT_UP_POSTFRAG ) )/(double)snapwr_total_ticks;

  PRINT( "⚡ " BOLD BYELLOW "SNAPSHOTS..." RESET UNBOLD
          " " BOLD "STATE" UNBOLD " %s"
          " " BOLD "PCT"   UNBOLD " %.1f %%"
          " " BOLD "RX"    UNBOLD " %3.f MB/s"
          " " BOLD "WR"    UNBOLD " %3.f MB/s"
          " " BOLD "ACC"   UNBOLD " %3.1f M/s"
          " " BOLD "BACKP" UNBOLD " %3.0f%%,%3.0f%%,%3.0f%%,%3.0f%%,%3.0f%%"
          " " BOLD "BUSY"  UNBOLD " %3.0f%%,%3.0f%%,%3.0f%%,%3.0f%%,%3.0f%%" CLEARLN "\n",
    fd_snapct_state_str( (int)state ),
    progress,
    megabytes_per_second,
    wr_megabytes_per_second,
    million_accounts_per_second,
    snapct_backp_pct,
    snapld_backp_pct,
    snapdc_backp_pct,
    snapin_backp_pct,
    snapwr_backp_pct,
    100.0-snapct_idle_pct-snapct_backp_pct,
    100.0-snapld_idle_pct-snapld_backp_pct,
    100.0-snapdc_idle_pct-snapdc_backp_pct,
    100.0-snapin_idle_pct-snapin_backp_pct,
    100.0-snapwr_idle_pct-snapwr_backp_pct );
}

static long
diff_tile_idx( ulong const * prev_tile,
               ulong const * cur_tile,
               ulong         tile_idx,
               ulong         metric_off ) {
  return (long)cur_tile [ tile_idx*FD_METRICS_TOTAL_SZ+metric_off ] -
         (long)prev_tile[ tile_idx*FD_METRICS_TOTAL_SZ+metric_off ];
}

static void
accdb_per_tile_offsets( char const * name,
                        ulong *      offs /* 11 entries: acquired, writable, missed, waited, rd, wr, cp, evicted_class_base, preevicted_class_base, committed_new_class_base, committed_overwrite_class_base */ ) {
  if(      !strcmp( name, "execle" ) ) {
    offs[0] =MIDX(COUNTER,EXECLE,ACCDB_ACCOUNT_ACQUIRED         ); offs[1]=MIDX(COUNTER,EXECLE,ACCDB_ACCOUNT_WRITABLE_ACQUIRED);
    offs[2] =MIDX(COUNTER,EXECLE,ACCDB_ACCOUNT_NOT_FOUND        ); offs[3]=MIDX(COUNTER,EXECLE,ACCDB_ACCOUNT_WAITED          );
    offs[4] =MIDX(COUNTER,EXECLE,ACCDB_BYTES_READ                ); offs[5]=MIDX(COUNTER,EXECLE,ACCDB_BYTES_WRITTEN            );
    offs[6] =MIDX(COUNTER,EXECLE,ACCDB_BYTES_COPIED              ); offs[7]=MIDX(COUNTER,EXECLE,ACCDB_ACCOUNT_EVICTED         );
    offs[8] =ULONG_MAX                                            ; offs[9]=MIDX(COUNTER,EXECLE,ACCDB_ACCOUNT_COMMITTED_NEW   );
    offs[10]=MIDX(COUNTER,EXECLE,ACCDB_ACCOUNT_COMMITTED_OVERWRITE);
  } else if( !strcmp( name, "execrp" ) ) {
    offs[0] =MIDX(COUNTER,EXECRP,ACCDB_ACCOUNT_ACQUIRED         ); offs[1]=MIDX(COUNTER,EXECRP,ACCDB_ACCOUNT_WRITABLE_ACQUIRED);
    offs[2] =MIDX(COUNTER,EXECRP,ACCDB_ACCOUNT_NOT_FOUND        ); offs[3]=MIDX(COUNTER,EXECRP,ACCDB_ACCOUNT_WAITED          );
    offs[4] =MIDX(COUNTER,EXECRP,ACCDB_BYTES_READ                ); offs[5]=MIDX(COUNTER,EXECRP,ACCDB_BYTES_WRITTEN            );
    offs[6] =MIDX(COUNTER,EXECRP,ACCDB_BYTES_COPIED              ); offs[7]=MIDX(COUNTER,EXECRP,ACCDB_ACCOUNT_EVICTED         );
    offs[8] =ULONG_MAX                                            ; offs[9]=MIDX(COUNTER,EXECRP,ACCDB_ACCOUNT_COMMITTED_NEW   );
    offs[10]=MIDX(COUNTER,EXECRP,ACCDB_ACCOUNT_COMMITTED_OVERWRITE);
  } else if( !strcmp( name, "replay" ) ) {
    offs[0] =MIDX(COUNTER,REPLAY,ACCDB_ACCOUNT_ACQUIRED         ); offs[1]=MIDX(COUNTER,REPLAY,ACCDB_ACCOUNT_WRITABLE_ACQUIRED);
    offs[2] =MIDX(COUNTER,REPLAY,ACCDB_ACCOUNT_NOT_FOUND        ); offs[3]=MIDX(COUNTER,REPLAY,ACCDB_ACCOUNT_WAITED          );
    offs[4] =MIDX(COUNTER,REPLAY,ACCDB_BYTES_READ                ); offs[5]=MIDX(COUNTER,REPLAY,ACCDB_BYTES_WRITTEN            );
    offs[6] =MIDX(COUNTER,REPLAY,ACCDB_BYTES_COPIED              ); offs[7]=MIDX(COUNTER,REPLAY,ACCDB_ACCOUNT_EVICTED         );
    offs[8] =ULONG_MAX                                            ; offs[9]=MIDX(COUNTER,REPLAY,ACCDB_ACCOUNT_COMMITTED_NEW   );
    offs[10]=MIDX(COUNTER,REPLAY,ACCDB_ACCOUNT_COMMITTED_OVERWRITE);
  } else if( !strcmp( name, "tower" ) ) {
    offs[0] =MIDX(COUNTER,TOWER,ACCDB_ACCOUNT_ACQUIRED          ); offs[1]=MIDX(COUNTER,TOWER,ACCDB_ACCOUNT_WRITABLE_ACQUIRED );
    offs[2] =MIDX(COUNTER,TOWER,ACCDB_ACCOUNT_NOT_FOUND         ); offs[3]=MIDX(COUNTER,TOWER,ACCDB_ACCOUNT_WAITED            );
    offs[4] =MIDX(COUNTER,TOWER,ACCDB_BYTES_READ                 ); offs[5]=MIDX(COUNTER,TOWER,ACCDB_BYTES_WRITTEN              );
    offs[6] =MIDX(COUNTER,TOWER,ACCDB_BYTES_COPIED               ); offs[7]=MIDX(COUNTER,TOWER,ACCDB_ACCOUNT_EVICTED           );
    offs[8] =ULONG_MAX                                            ; offs[9]=MIDX(COUNTER,TOWER,ACCDB_ACCOUNT_COMMITTED_NEW     );
    offs[10]=MIDX(COUNTER,TOWER,ACCDB_ACCOUNT_COMMITTED_OVERWRITE);
  } else if( !strcmp( name, "accdb" ) ) {
    /* The accdb tile only runs background work (compact, preevict,
       advance_root, purge); it never acquires/releases.  Sentinel
       everything that comes from the acquire/release path. */
    offs[0] =ULONG_MAX                                            ; offs[1]=ULONG_MAX                                            ;
    offs[2] =ULONG_MAX                                            ; offs[3]=ULONG_MAX                                            ;
    offs[4] =MIDX(COUNTER,ACCDB,BYTES_READ                       ); offs[5]=MIDX(COUNTER,ACCDB,BYTES_WRITTEN                    );
    offs[6] =ULONG_MAX                                            ; offs[7]=ULONG_MAX                                            ;
    offs[8] =MIDX(COUNTER,ACCDB,ACCOUNT_PREEVICTED               ); offs[9]=ULONG_MAX                                            ;
    offs[10]=ULONG_MAX;
  } else if( !strcmp( name, "rpc" ) ) {
    /* RPC is a read-only accdb consumer.  It only emits the subset
       of counters that fd_accdb_read_one_nocache touches; everything
       else is sentinel and skipped by sample_accdb. */
    offs[0] =MIDX(COUNTER,RPC,ACCDB_ACCOUNT_ACQUIRED); offs[1]=ULONG_MAX;
    offs[2] =MIDX(COUNTER,RPC,ACCDB_ACCOUNT_NOT_FOUND); offs[3]=MIDX(COUNTER,RPC,ACCDB_ACCOUNT_WAITED);
    offs[4] =MIDX(COUNTER,RPC,ACCDB_BYTES_READ       ); offs[5]=ULONG_MAX;
    offs[6] =MIDX(COUNTER,RPC,ACCDB_BYTES_COPIED     ); offs[7]=ULONG_MAX;
    offs[8] =ULONG_MAX;                                 offs[9]=ULONG_MAX;
    offs[10]=ULONG_MAX;
  } else if( !strcmp( name, "resolv" ) ) {
    /* Resolv is a read-only accdb consumer (address lookup table
       reads on the receive path).  Same RO subset as RPC. */
    offs[0] =MIDX(COUNTER,RESOLV,ACCDB_ACCOUNT_ACQUIRED ); offs[1]=ULONG_MAX;
    offs[2] =MIDX(COUNTER,RESOLV,ACCDB_ACCOUNT_NOT_FOUND); offs[3]=MIDX(COUNTER,RESOLV,ACCDB_ACCOUNT_WAITED);
    offs[4] =MIDX(COUNTER,RESOLV,ACCDB_BYTES_READ        ); offs[5]=ULONG_MAX;
    offs[6] =MIDX(COUNTER,RESOLV,ACCDB_BYTES_COPIED      ); offs[7]=ULONG_MAX;
    offs[8] =ULONG_MAX;                                     offs[9]=ULONG_MAX;
    offs[10]=ULONG_MAX;
  } else {
    for( ulong i=0UL; i<11UL; i++ ) offs[i] = ULONG_MAX;
  }
}

static void
sample_accdb( config_t const * config,
              ulong const *    prev_tile,
              ulong const *    cur_tile ) {
  long acquired = 0L, writable = 0L, missed = 0L, evicted = 0L, waited = 0L;
  long bytes_rd = 0L, bytes_wr = 0L, bytes_cp = 0L, bytes_pe = 0L;
  long preevicted = 0L;
  long evicted_class[ 8 ] = {0};
  long preevicted_class[ 8 ] = {0};
  long committed_new_class[ 8 ] = {0};
  long committed_overwrite_class[ 8 ] = {0};

  for( ulong i=0UL; i<config->topo.tile_cnt; i++ ) {
    ulong offs[11];
    accdb_per_tile_offsets( config->topo.tiles[ i ].name, offs );
    if( offs[0]!=ULONG_MAX ) {
      for( ulong c=0UL; c<8UL; c++ ) acquired += diff_tile_idx( prev_tile, cur_tile, i, offs[0] + c );
    }
    if( offs[1]!=ULONG_MAX ) {
      for( ulong c=0UL; c<8UL; c++ ) writable += diff_tile_idx( prev_tile, cur_tile, i, offs[1] + c );
    }
    if( offs[3]!=ULONG_MAX ) waited   += diff_tile_idx( prev_tile, cur_tile, i, offs[3] );
    if( offs[4]!=ULONG_MAX ) bytes_rd += diff_tile_idx( prev_tile, cur_tile, i, offs[4] );
    if( offs[6]!=ULONG_MAX ) bytes_cp += diff_tile_idx( prev_tile, cur_tile, i, offs[6] );
    if( offs[5]!=ULONG_MAX ) {
      long this_wr = diff_tile_idx( prev_tile, cur_tile, i, offs[5] );
      if( !strcmp( config->topo.tiles[ i ].name, "accdb" ) ) bytes_pe += this_wr;
      else                                                   bytes_wr += this_wr;
    }
    for( ulong c=0UL; c<8UL; c++ ) {
      if( offs[2]!=ULONG_MAX ) missed += diff_tile_idx( prev_tile, cur_tile, i, offs[2] + c );
      if( offs[7]!=ULONG_MAX ) {
        long d = diff_tile_idx( prev_tile, cur_tile, i, offs[7] + c );
        evicted_class[ c ] += d;
        evicted            += d;
      }
      if( offs[8]!=ULONG_MAX ) {
        long d = diff_tile_idx( prev_tile, cur_tile, i, offs[8] + c );
        preevicted_class[ c ] += d;
        preevicted            += d;
      }
      if( offs[9] !=ULONG_MAX ) committed_new_class      [ c ] += diff_tile_idx( prev_tile, cur_tile, i, offs[9]  + c );
      if( offs[10]!=ULONG_MAX ) committed_overwrite_class[ c ] += diff_tile_idx( prev_tile, cur_tile, i, offs[10] + c );
    }
  }

  ulong slot = accdb_samples_idx % (sizeof(accdb_acquired_samples)/sizeof(accdb_acquired_samples[0]));
  accdb_acquired_samples[ slot ] = (ulong)acquired;
  accdb_writable_samples[ slot ] = (ulong)writable;
  accdb_missed_samples  [ slot ] = (ulong)missed;
  accdb_evicted_samples [ slot ] = (ulong)evicted;
  accdb_waited_samples  [ slot ] = (ulong)waited;
  accdb_bytes_rd_samples[ slot ] = (ulong)bytes_rd;
  accdb_bytes_wr_samples[ slot ] = (ulong)bytes_wr;
  accdb_bytes_cp_samples[ slot ] = (ulong)bytes_cp;
  accdb_bytes_pe_samples[ slot ] = (ulong)bytes_pe;
  accdb_preevicted_samples[ slot ] = (ulong)preevicted;
  for( ulong c=0UL; c<8UL; c++ ) {
    accdb_evicted_class_samples            [ c ][ slot ] = (ulong)evicted_class            [ c ];
    accdb_preevicted_class_samples         [ c ][ slot ] = (ulong)preevicted_class         [ c ];
    accdb_committed_new_class_samples      [ c ][ slot ] = (ulong)committed_new_class      [ c ];
    accdb_committed_overwrite_class_samples[ c ][ slot ] = (ulong)committed_overwrite_class[ c ];
  }
  accdb_samples_idx++;
}

static uint
write_accdb( config_t const * config,
             ulong const *    cur_tile,
             ulong const *    prev_tile ) {
  ulong accdb_tile_idx = fd_topo_find_tile( &config->topo, "accdb", 0UL );
  if( accdb_tile_idx==ULONG_MAX ) return 0U;

  ulong const * t = cur_tile + accdb_tile_idx*FD_METRICS_TOTAL_SZ;

  ulong accdb_total_ticks = total_regime( &cur_tile[ accdb_tile_idx*FD_METRICS_TOTAL_SZ ] )-total_regime( &prev_tile[ accdb_tile_idx*FD_METRICS_TOTAL_SZ ] );
  accdb_total_ticks = fd_ulong_max( accdb_total_ticks, 1UL );
  double accdb_backp_pct = 100.0*(double)diff_tile( config, "accdb", prev_tile, cur_tile, MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_BACKPRESSURE_PREFRAG ) )/(double)accdb_total_ticks;
  double accdb_idle_pct  = 100.0*(double)diff_tile( config, "accdb", prev_tile, cur_tile, MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_CAUGHT_UP_POSTFRAG  ) )/(double)accdb_total_ticks;
  double accdb_busy_pct  = 100.0 - accdb_backp_pct - accdb_idle_pct;

  ulong acct_cnt        = t[ MIDX( GAUGE,   ACCDB, ACCOUNT_COUNT         ) ];
  ulong acct_cap        = t[ MIDX( GAUGE,   ACCDB, ACCOUNT_CAPACITY      ) ];
  ulong used_bytes      = t[ MIDX( GAUGE,   ACCDB, DISK_USED_BYTES       ) ];
  ulong current_bytes   = t[ MIDX( GAUGE,   ACCDB, DISK_CURRENT_BYTES    ) ];
  ulong alloc_bytes     = t[ MIDX( GAUGE,   ACCDB, DISK_ALLOCATED_BYTES  ) ];
  ulong in_compaction   = t[ MIDX( GAUGE,   ACCDB, IN_COMPACTION         ) ];
  ulong compact_req     = t[ MIDX( COUNTER, ACCDB, COMPACTION_REQUESTED  ) ];
  ulong compact_done    = t[ MIDX( COUNTER, ACCDB, COMPACTION_COMPLETED  ) ];

  ulong  frag_bytes  = current_bytes>used_bytes ? current_bytes-used_bytes : 0UL;
  double data_gb     = (double)alloc_bytes/1e9;
  double live_gb     = (double)used_bytes/1e9;
  double frag_gb     = (double)frag_bytes/1e9;
  double frag_pct    = current_bytes ? 100.0*(double)frag_bytes/(double)current_bytes : 0.0;
  double index_pct   = acct_cap      ? 100.0*(double)acct_cnt/(double)acct_cap        : 0.0;

  PRINT( "💾 " BOLD GREEN "ACCOUNTS...." RESET UNBOLD
         " " BOLD "CACHE SIZE"    UNBOLD " %lu GiB"
         " " BOLD "DISK"          UNBOLD " %.1f GB"
         " " BOLD "LIVE DATA"     UNBOLD " %.1f GB"
         " " BOLD "FRAGMENTATION" UNBOLD " %.1f GB (%4.1f%%)"
         " " BOLD "INDEX"         UNBOLD " %4.1f%% (%.1fM / %.1fM)"
         " " BOLD "COMPACTION"    UNBOLD " %s (%lu / %lu)"
         " " BOLD "BUSY"          UNBOLD " %3.0f%%" CLEARLN "\n",
    config->firedancer.accounts.cache_size_gib,
    data_gb, live_gb, frag_gb, frag_pct,
    index_pct, (double)acct_cnt/1e6, (double)acct_cap/1e6,
    in_compaction ? "running" : "idle", compact_done, compact_req,
    accdb_busy_pct );

  ulong const cap = sizeof(accdb_acquired_samples)/sizeof(accdb_acquired_samples[0]);
  ulong n = fd_ulong_min( accdb_samples_idx, cap );
  if( !n ) n = 1UL;

  ulong sum_acq = 0UL, sum_wr = 0UL, sum_miss = 0UL, sum_evict = 0UL, sum_wait = 0UL;
  ulong sum_brd = 0UL, sum_bwr = 0UL, sum_bcp = 0UL, sum_bpe = 0UL;
  ulong sum_pre = 0UL;
  for( ulong i=0UL; i<n; i++ ) {
    sum_acq   += accdb_acquired_samples[ i ];
    sum_wr    += accdb_writable_samples[ i ];
    sum_miss  += accdb_missed_samples  [ i ];
    sum_evict += accdb_evicted_samples [ i ];
    sum_wait  += accdb_waited_samples  [ i ];
    sum_brd   += accdb_bytes_rd_samples[ i ];
    sum_bwr   += accdb_bytes_wr_samples[ i ];
    sum_bcp   += accdb_bytes_cp_samples[ i ];
    sum_bpe   += accdb_bytes_pe_samples[ i ];
    sum_pre   += accdb_preevicted_samples[ i ];
  }

  /* Snap interval is 10ms, so per-second rate = mean diff * 100. */
  double acquired = 100.0*(double)sum_acq  /(double)n;
  double writable = 100.0*(double)sum_wr   /(double)n;
  double missed   = 100.0*(double)sum_miss /(double)n;
  double evicted  = 100.0*(double)sum_evict/(double)n;
  double waited   = 100.0*(double)sum_wait /(double)n;
  double bytes_rd = 100.0*(double)sum_brd  /(double)n;
  double bytes_wr = 100.0*(double)sum_bwr  /(double)n;
  double bytes_cp = 100.0*(double)sum_bcp  /(double)n;
  double bytes_pe = 100.0*(double)sum_bpe  /(double)n;
  double preevicted = 100.0*(double)sum_pre/(double)n;

  double hit_pct = acquired>0.0 ? 100.0*(acquired-missed)/acquired : 0.0;

  char * read_str    = fmt_bytes( fd_alloca_check( 1UL, 64UL ), 64UL, (long)bytes_rd );
  char * write_str   = fmt_bytes( fd_alloca_check( 1UL, 64UL ), 64UL, (long)bytes_wr );
  char * copy_str    = fmt_bytes( fd_alloca_check( 1UL, 64UL ), 64UL, (long)bytes_cp );
  char * preevict_str= fmt_bytes( fd_alloca_check( 1UL, 64UL ), 64UL, (long)bytes_pe );
  char * acq_str   = COUNTF( acquired );
  char * wr_str    = COUNTF( writable );
  char * miss_str  = COUNTF( missed   );
  char * evict_str = COUNTF( evicted  );
  char * pre_str   = COUNTF( preevicted );
  char * wait_str  = COUNTF( waited   );

  if( FD_LIKELY( !watch_full ) ) return 1;

  PRINT( "               "
         " " BOLD "ACQUIRE" UNBOLD " %s /s (%s wr /s)"
         " " BOLD "HIT"     UNBOLD " %5.1f%%"
         " " BOLD "MISS"    UNBOLD " %s /s"
         " " BOLD "EVICT"   UNBOLD " %s /s (+%s /s)"
         " " BOLD "WAIT"    UNBOLD " %s /s"
         " " BOLD "IO"      UNBOLD " %s rd %s wr-acq %s wr-pe %s cp" CLEARLN "\n",
    acq_str, wr_str, hit_pct, miss_str, evict_str, pre_str, wait_str,
    read_str, write_str, preevict_str, copy_str );

  char * evict_class_str[ 8 ];
  char * preevict_class_str[ 8 ];
  char * commit_new_class_str[ 8 ];
  char * commit_overwrite_class_str[ 8 ];
  for( ulong c=0UL; c<8UL; c++ ) {
    ulong sum_c = 0UL, sum_pc = 0UL, sum_cn = 0UL, sum_co = 0UL;
    for( ulong i=0UL; i<n; i++ ) {
      sum_c  += accdb_evicted_class_samples            [ c ][ i ];
      sum_pc += accdb_preevicted_class_samples         [ c ][ i ];
      sum_cn += accdb_committed_new_class_samples      [ c ][ i ];
      sum_co += accdb_committed_overwrite_class_samples[ c ][ i ];
    }
    evict_class_str           [ c ] = COUNTF_T( 100.0*(double)sum_c /(double)n );
    preevict_class_str        [ c ] = COUNTF_T( 100.0*(double)sum_pc/(double)n );
    commit_new_class_str      [ c ] = COUNTF_T( 100.0*(double)sum_cn/(double)n );
    commit_overwrite_class_str[ c ] = COUNTF_T( 100.0*(double)sum_co/(double)n );
  }

  PRINT( "               "
         " " BOLD "EVICT/s BY CLASS" UNBOLD
         " " BOLD "128B" UNBOLD " %s (+%s)"
         " " BOLD "512B" UNBOLD " %s (+%s)"
         " " BOLD "2K"   UNBOLD " %s (+%s)"
         " " BOLD "8K"   UNBOLD " %s (+%s)"
         " " BOLD "32K"  UNBOLD " %s (+%s)"
         " " BOLD "128K" UNBOLD " %s (+%s)"
         " " BOLD "1M"   UNBOLD " %s (+%s)"
         " " BOLD "10M"  UNBOLD " %s (+%s)" CLEARLN "\n",
    evict_class_str[0], preevict_class_str[0],
    evict_class_str[1], preevict_class_str[1],
    evict_class_str[2], preevict_class_str[2],
    evict_class_str[3], preevict_class_str[3],
    evict_class_str[4], preevict_class_str[4],
    evict_class_str[5], preevict_class_str[5],
    evict_class_str[6], preevict_class_str[6],
    evict_class_str[7], preevict_class_str[7] );

  PRINT( "               "
         " " BOLD "COMMIT/s        " UNBOLD
         " " BOLD "128B" UNBOLD " %s (=%s)"
         " " BOLD "512B" UNBOLD " %s (=%s)"
         " " BOLD "2K"   UNBOLD " %s (=%s)"
         " " BOLD "8K"   UNBOLD " %s (=%s)"
         " " BOLD "32K"  UNBOLD " %s (=%s)"
         " " BOLD "128K" UNBOLD " %s (=%s)"
         " " BOLD "1M"   UNBOLD " %s (=%s)"
         " " BOLD "10M"  UNBOLD " %s (=%s)" CLEARLN "\n",
    commit_new_class_str[0], commit_overwrite_class_str[0],
    commit_new_class_str[1], commit_overwrite_class_str[1],
    commit_new_class_str[2], commit_overwrite_class_str[2],
    commit_new_class_str[3], commit_overwrite_class_str[3],
    commit_new_class_str[4], commit_overwrite_class_str[4],
    commit_new_class_str[5], commit_overwrite_class_str[5],
    commit_new_class_str[6], commit_overwrite_class_str[6],
    commit_new_class_str[7], commit_overwrite_class_str[7] );

  ulong cache_used_off = MIDX( GAUGE, ACCDB, CACHE_CLASS_USED );
  ulong cache_max_off  = MIDX( GAUGE, ACCDB, CACHE_CLASS_MAX  );
  char * cache_used_str[ 8 ];
  char * cache_max_str [ 8 ];
  double cache_pct     [ 8 ];
  for( ulong c=0UL; c<8UL; c++ ) {
    ulong used = t[ cache_used_off + c ];
    ulong max  = t[ cache_max_off  + c ];
    cache_used_str[ c ] = COUNT_T( used );
    cache_max_str [ c ] = COUNT_T( max  );
    cache_pct     [ c ] = max ? 100.0*(double)used/(double)max : 0.0;
  }

  PRINT( "               "
         " " BOLD "CACHE FULL" UNBOLD
         " " BOLD "128B" UNBOLD " %s/%s (%5.1f%%)"
         " " BOLD "512B" UNBOLD " %s/%s (%5.1f%%)"
         " " BOLD "2K"   UNBOLD " %s/%s (%5.1f%%)"
         " " BOLD "8K"   UNBOLD " %s/%s (%5.1f%%)"
         " " BOLD "32K"  UNBOLD " %s/%s (%5.1f%%)"
         " " BOLD "128K" UNBOLD " %s/%s (%5.1f%%)"
         " " BOLD "1M"   UNBOLD " %s/%s (%5.1f%%)"
         " " BOLD "10M"  UNBOLD " %s/%s (%5.1f%%)" CLEARLN "\n",
    cache_used_str[0], cache_max_str[0], cache_pct[0],
    cache_used_str[1], cache_max_str[1], cache_pct[1],
    cache_used_str[2], cache_max_str[2], cache_pct[2],
    cache_used_str[3], cache_max_str[3], cache_pct[3],
    cache_used_str[4], cache_max_str[4], cache_pct[4],
    cache_used_str[5], cache_max_str[5], cache_pct[5],
    cache_used_str[6], cache_max_str[6], cache_pct[6],
    cache_used_str[7], cache_max_str[7], cache_pct[7] );

  ulong cache_resv_off = MIDX( GAUGE, ACCDB, CACHE_CLASS_RESERVED );
  char * cache_resv_str[ 8 ];
  for( ulong c=0UL; c<8UL; c++ ) {
    ulong resv = t[ cache_resv_off + c ];
    if( resv==ULONG_MAX ) cache_resv_str[ c ] = "  off ";
    else                  cache_resv_str[ c ] = COUNT_T( resv );
  }

  PRINT( "               "
         " " BOLD "RESERVED  " UNBOLD
         " " BOLD "128B" UNBOLD " %s         "
         " " BOLD "512B" UNBOLD " %s         "
         " " BOLD "2K"   UNBOLD " %s         "
         " " BOLD "8K"   UNBOLD " %s         "
         " " BOLD "32K"  UNBOLD " %s         "
         " " BOLD "128K" UNBOLD " %s         "
         " " BOLD "1M"   UNBOLD " %s         "
         " " BOLD "10M"  UNBOLD " %s         " CLEARLN "\n",
    cache_resv_str[0], cache_resv_str[1], cache_resv_str[2], cache_resv_str[3],
    cache_resv_str[4], cache_resv_str[5], cache_resv_str[6], cache_resv_str[7] );
  return 6;
}

static uint
write_wfs( config_t const * config,
           ulong const *    cur_tile ) {
  ulong gossip_tile_idx = fd_topo_find_tile( &config->topo, "gossip", 0UL );
  if( FD_UNLIKELY( gossip_tile_idx==ULONG_MAX ) ) return 0U;

  int wfs_state = (int)cur_tile[ gossip_tile_idx*FD_METRICS_TOTAL_SZ+MIDX( GAUGE, GOSSIP, WAIT_FOR_SUPERMAJORITY_STATE ) ];
  if( FD_LIKELY( wfs_state==FD_GOSSIP_WFS_STATE_DONE ) ) return 0U;

  char const * state_str;
  switch( wfs_state ) {
    case FD_GOSSIP_WFS_STATE_INIT:    state_str = "loading snapshot";      break;
    case FD_GOSSIP_WFS_STATE_WAIT:    state_str = "waiting";               break;
    case FD_GOSSIP_WFS_STATE_PUBLISH: state_str = "starting";              break;
    default:                          return 0U;
  }

  ulong _stake_online = cur_tile[ gossip_tile_idx*FD_METRICS_TOTAL_SZ+MIDX( GAUGE, GOSSIP, WAIT_FOR_SUPERMAJORITY_STAKE_ONLINE ) ];
  ulong _stake_total  = cur_tile[ gossip_tile_idx*FD_METRICS_TOTAL_SZ+MIDX( GAUGE, GOSSIP, WAIT_FOR_SUPERMAJORITY_STAKE_TOTAL  ) ];
  ulong peers_online  = cur_tile[ gossip_tile_idx*FD_METRICS_TOTAL_SZ+MIDX( GAUGE, GOSSIP, WAIT_FOR_SUPERMAJORITY_STAKED_PEER_ONLINE ) ];
  ulong peers_total   = cur_tile[ gossip_tile_idx*FD_METRICS_TOTAL_SZ+MIDX( GAUGE, GOSSIP, WAIT_FOR_SUPERMAJORITY_STAKED_PEER_TOTAL  ) ];

  ulong ipecho_tile_idx = fd_topo_find_tile( &config->topo, "ipecho", 0UL );
  ulong shred_ver       = 0UL;
  if( FD_LIKELY( ipecho_tile_idx!=ULONG_MAX ) ) shred_ver = cur_tile[ ipecho_tile_idx*FD_METRICS_TOTAL_SZ+MIDX( GAUGE, IPECHO, CURRENT_SHRED_VERSION ) ];

  double stake_pct = _stake_total>0UL ? 100.0*(double)_stake_online/(double)_stake_total : 0.0;
  double         stake_div     = (_stake_total<(ulong)1e14) ? 1e9 : 1e15;
  char const *   stake_unit    = (_stake_total<(ulong)1e14) ? " SOL" : "M";
  double         stake_online  = (double)_stake_online / stake_div;
  double         stake_total   = (double)_stake_total  / stake_div;

  PRINT( "⏳ " BOLD YELLOW "CLUSTER BOOT" RESET UNBOLD
         " " BOLD "STATE" UNBOLD " %s"
         " " BOLD "STAKE" UNBOLD " %3.0f%% (%.1f%s / %.1f%s)"
         " " BOLD "SHRED VERSION" UNBOLD " %lu"
         " " BOLD "PEERS" UNBOLD " %lu online %lu offline"
         " " BOLD "BANK HASH"  UNBOLD " %s" CLEARLN "\n",
    state_str,
    stake_pct,
    stake_online,
    stake_unit,
    stake_total,
    stake_unit,
    shred_ver,
    peers_online,
    peers_total>peers_online ? peers_total-peers_online : 0UL,
    config->firedancer.consensus.wait_for_supermajority_with_bank_hash );
  return 1U;
}

static uint
write_gossip( config_t const * config,
              ulong const *    cur_tile,
              ulong const *    prev_tile,
              ulong const *    cur_link,
              ulong const *    prev_link ) {
  ulong gossip_tile_idx = fd_topo_find_tile( &config->topo, "gossip", 0UL );
  if( gossip_tile_idx==ULONG_MAX ) return 0U;
  char * contact_info = COUNT( cur_tile[ gossip_tile_idx*FD_METRICS_TOTAL_SZ+MIDX( GAUGE, GOSSIP, CRDS_OCCUPIED_CONTACT_INFO_V2 ) ] );

  ulong gossip_total_ticks = total_regime( &cur_tile[ gossip_tile_idx*FD_METRICS_TOTAL_SZ ] )-total_regime( &prev_tile[ gossip_tile_idx*FD_METRICS_TOTAL_SZ ] );
  gossip_total_ticks = fd_ulong_max( gossip_total_ticks, 1UL );
  double gossip_backp_pct = 100.0*(double)diff_tile( config, "gossip", prev_tile, cur_tile, MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_BACKPRESSURE_PREFRAG ) )/(double)gossip_total_ticks;
  double gossip_idle_pct = 100.0*(double)diff_tile( config, "gossip", prev_tile, cur_tile, MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_CAUGHT_UP_POSTFRAG ) )/(double)gossip_total_ticks;
  double gossip_busy_pct = 100.0 - gossip_backp_pct - gossip_idle_pct;

  PRINT( "💬 " BOLD BLUE "GOSSIP......" RESET UNBOLD
         " " BOLD "RX"    UNBOLD " %s"
         " " BOLD "TX"    UNBOLD " %s"
         " " BOLD "CRDS"  UNBOLD " %s"
         " " BOLD "PEERS" UNBOLD " %s"
         " " BOLD "BUSY"  UNBOLD " %3.0f%%"
         " " BOLD "BACKP" UNBOLD " %3.0f%%" CLEARLN "\n",
    DIFF_LINK_BYTES( "net_gossvf", COUNTER, LINK, FRAG_CONSUMED_BYTES ),
    DIFF_LINK_BYTES( "gossip_net", COUNTER, LINK, FRAG_CONSUMED_BYTES ),
    COUNT( total_crds( &cur_tile[ fd_topo_find_tile( &config->topo, "gossip", 0UL )*FD_METRICS_TOTAL_SZ ] ) ),
    contact_info,
    gossip_busy_pct,
    gossip_backp_pct );
  return 1U;
}

static uint
write_repair( config_t const * config,
              ulong const *    cur_tile,
              ulong const *    cur_link,
              ulong const *    prev_link ) {
  ulong repair_tile_idx = fd_topo_find_tile( &config->topo, "repair", 0UL );
  if( repair_tile_idx==ULONG_MAX ) return 0U;
  ulong repair_slot = cur_tile[ repair_tile_idx*FD_METRICS_TOTAL_SZ+MIDX( GAUGE, REPAIR, SLOT_HIGHEST_REPAIRED ) ];
  ulong turbine_slot = cur_tile[ repair_tile_idx*FD_METRICS_TOTAL_SZ+MIDX( GAUGE, REPAIR, SLOT_CURRENT ) ];
  PRINT( "🧱 " BOLD RED "REPAIR......" RESET UNBOLD
         " " BOLD "RX"            UNBOLD " %s"
         " " BOLD "TX"            UNBOLD " %s"
         " " BOLD "REPAIR SLOT"   UNBOLD " %lu (%02ld)"
         " " BOLD "TURBINE SLOT"  UNBOLD " %lu" CLEARLN "\n",
    DIFF_LINK_BYTES( "net_repair", COUNTER, LINK, FRAG_CONSUMED_BYTES ),
    DIFF_LINK_BYTES( "repair_net", COUNTER, LINK, FRAG_CONSUMED_BYTES ),
    repair_slot,
    (long)repair_slot-(long)turbine_slot,
    turbine_slot );
  return 1U;
}

static uint
write_rserve( config_t const * config,
              ulong const * cur_tile,
              ulong const * cur_link,
              ulong const * prev_link ) {
  ulong rserve_tile_idx = fd_topo_find_tile( &config->topo, "rserve", 0UL );
  if( rserve_tile_idx==ULONG_MAX ) return 0UL;

  ulong const * t = cur_tile + rserve_tile_idx*FD_METRICS_TOTAL_SZ;

  ulong shreds_stored_sum = 0UL;
  ulong num_stored_shreds = fd_ulong_min( shreds_stored_samples_idx, sizeof(shreds_stored_sample)/sizeof(shreds_stored_sample[0]));
  for( ulong i=0UL; i<num_stored_shreds; i++ ) shreds_stored_sum += shreds_stored_sample[ i ];
  char * shreds_stored = COUNTF( 100.0*(double)shreds_stored_sum/(double)num_stored_shreds );

  ulong shreds_cur = t[ MIDX( GAUGE, RSERVE, SHREDS_CURRENT ) ];
  ulong shreds_max = t[ MIDX( GAUGE, RSERVE, SHREDS_MAX     ) ];

  ulong valid_sum = 0UL;
  ulong num_valid_samples = fd_ulong_min( rserve_rps_valid_samples_idx, sizeof(rserve_rps_valid_samples)/sizeof(rserve_rps_valid_samples[0]) );
  for( ulong i=0UL; i<num_valid_samples; i++ ) valid_sum += rserve_rps_valid_samples[ i ];
  char * valid_str = COUNTF( 100.0*(double)valid_sum/(double)num_valid_samples );

  ulong invalid_sum = 0UL;
  ulong num_invalid_samples = fd_ulong_min( rserve_rps_invalid_samples_idx, sizeof(rserve_rps_invalid_samples)/sizeof(rserve_rps_invalid_samples[0]) );
  for( ulong i=0UL; i<num_invalid_samples; i++ ) invalid_sum += rserve_rps_invalid_samples[ i ];
  char * invalid_str = COUNTF( 100.0*(double)invalid_sum/(double)num_invalid_samples );

  ulong num_total_samples = fd_ulong_max( num_valid_samples, 1UL );
  char * total_str = COUNTF( 100.0*(double)(valid_sum+invalid_sum)/(double)num_total_samples );

  ulong n_inv = fd_ulong_max( num_invalid_samples, 1UL );

  ulong miss_sum = 0UL;
  for( ulong i=0UL; i<num_invalid_samples; i++ ) miss_sum += rserve_rps_miss_samples[ i ];
  char * miss_str = COUNTF( 100.0*(double)miss_sum/(double)n_inv );

  ulong sigvfy_sum = 0UL;
  for( ulong i=0UL; i<num_invalid_samples; i++ ) sigvfy_sum += rserve_rps_sigvfy_samples[ i ];
  char * sigvfy_str = COUNTF( 100.0*(double)sigvfy_sum/(double)n_inv );

  ulong stale_sum = 0UL;
  for( ulong i=0UL; i<num_invalid_samples; i++ ) stale_sum += rserve_rps_stale_samples[ i ];
  char * stale_str = COUNTF( 100.0*(double)stale_sum/(double)n_inv );

  ulong other_sum = 0UL;
  for( ulong i=0UL; i<num_invalid_samples; i++ ) other_sum += rserve_rps_other_rej_samples[ i ];
  char * other_str = COUNTF( 100.0*(double)other_sum/(double)n_inv );

  ulong  disk_used  = t[ MIDX( GAUGE, RSERVE, DISK_CURRENT_BYTES   ) ];
  ulong  disk_alloc = t[ MIDX( GAUGE, RSERVE, DISK_ALLOCATED_BYTES ) ];
  double disk_gb    = (double)disk_alloc/1e9;
  double disk_pct   = disk_alloc ? 100.0*(double)disk_used/(double)disk_alloc : 0.0;

  char * shreds_cur_str = COUNT( shreds_cur );
  char * shreds_max_str = COUNT( shreds_max );

  PRINT( "🔧 " BOLD GREEN "RSERVE......" RESET UNBOLD
         " " BOLD "RX" UNBOLD " %s"
         " " BOLD "TX" UNBOLD " %s"
         " " BOLD "STORED SHREDS" UNBOLD " %s /s (%s / %s)"
         " " BOLD "DISK" UNBOLD " %.1f GB (%4.1f%%)",
      DIFF_LINK_BYTES( "net_rserve", COUNTER, LINK, FRAG_CONSUMED_BYTES ),
      DIFF_LINK_BYTES( "rserve_net", COUNTER, LINK, FRAG_CONSUMED_BYTES ),
      shreds_stored, shreds_cur_str, shreds_max_str,
      disk_gb, disk_pct );
  PRINT( " " BOLD "RPS" UNBOLD " %s (%s valid, %s invalid) /s" CLEARLN "\n",
      total_str, valid_str, invalid_str );

  if( FD_LIKELY( !watch_full ) ) return 1U;

  PRINT( "               "
         " " BOLD "MISS"    UNBOLD " %s /s"
         " " BOLD "SIGVFY"  UNBOLD " %s /s"
         " " BOLD "STALE"   UNBOLD " %s /s"
         " " BOLD "OTHER"   UNBOLD " %s /s" CLEARLN "\n",
      miss_str, sigvfy_str, stale_str, other_str );
  return 2U;
}

static uint
write_replay( config_t const * config,
              ulong const *    cur_tile ) {
  ulong repair_tile_idx = fd_topo_find_tile( &config->topo, "repair", 0UL );
  ulong replay_tile_idx = fd_topo_find_tile( &config->topo, "replay", 0UL );
  if( replay_tile_idx==ULONG_MAX ) return 0U;

  ulong reset_slot       = cur_tile[ replay_tile_idx*FD_METRICS_TOTAL_SZ+MIDX( GAUGE, REPLAY, RESET_SLOT       ) ];
  ulong next_leader_slot = cur_tile[ replay_tile_idx*FD_METRICS_TOTAL_SZ+MIDX( GAUGE, REPLAY, NEXT_LEADER_SLOT ) ];
  ulong leader_slot      = cur_tile[ replay_tile_idx*FD_METRICS_TOTAL_SZ+MIDX( GAUGE, REPLAY, LEADER_SLOT      ) ];
  char * next_leader_slot_str = fd_alloca_check( 1UL, 64UL );

  ulong turbine_slot;
  if( repair_tile_idx!=ULONG_MAX ) {
    turbine_slot = cur_tile[ repair_tile_idx*FD_METRICS_TOTAL_SZ+MIDX( GAUGE, REPAIR, SLOT_CURRENT ) ];
  } else {
    turbine_slot = reset_slot;
  }

  ulong slot_in_seconds = (ulong)((double)(next_leader_slot-reset_slot)*0.4);
  if( FD_UNLIKELY( leader_slot ) ) FD_TEST( fd_cstr_printf_check( next_leader_slot_str, 64UL, NULL, "now" ) );
  else if( FD_LIKELY( next_leader_slot>0UL ) ) FD_TEST( fd_cstr_printf_check( next_leader_slot_str, 64UL, NULL, "%lum %lus", slot_in_seconds/60UL, slot_in_seconds%60UL ) );
  else FD_TEST( fd_cstr_printf_check( next_leader_slot_str, 64UL, NULL, "never" ) );

  ulong root_distance = cur_tile[ replay_tile_idx*FD_METRICS_TOTAL_SZ+MIDX( GAUGE, REPLAY, ROOT_DISTANCE ) ];
  ulong live_banks    = cur_tile[ replay_tile_idx*FD_METRICS_TOTAL_SZ+MIDX( GAUGE, REPLAY, BANK_LIVE     ) ];

  ulong sps_sum = 0UL;
  ulong num_sps_samples = fd_ulong_min( sps_samples_idx, sizeof(sps_samples)/sizeof(sps_samples[0]));
  for( ulong i=0UL; i<num_sps_samples; i++ ) sps_sum += sps_samples[ i ];
  char * sps_str = COUNTF( 100.0*(double)sps_sum/(double)num_sps_samples );

  ulong tps_sum = 0UL;
  ulong num_tps_samples = fd_ulong_min( tps_samples_idx, sizeof(tps_samples)/sizeof(tps_samples[0]));
  for( ulong i=0UL; i<num_tps_samples; i++ ) tps_sum += tps_samples[ i ];
  char * tps_str = COUNTF( 100.0*(double)tps_sum/(double)num_tps_samples );

  ulong cups_sum = 0UL;
  ulong num_cups_samples = fd_ulong_min( cups_samples_idx, sizeof(cups_samples)/sizeof(cups_samples[0]));
  for( ulong i=0UL; i<num_cups_samples; i++ ) cups_sum += cups_samples[ i ];
  char * mcups_str = COUNTF( 100.0*(double)cups_sum/(double)num_cups_samples );

  PRINT( "💥 " BOLD MAGENTA "REPLAY......" RESET UNBOLD
         " " BOLD "SLOT"      UNBOLD " %lu (%02ld)"
         " " BOLD "CU/s"      UNBOLD " %s"
         " " BOLD "TPS"       UNBOLD " %s"
         " " BOLD "SPS"       UNBOLD " %s"
         " " BOLD "LEADER IN" UNBOLD " %s"
         " " BOLD "ROOT DIST" UNBOLD " %lu"
         " " BOLD "BANKS"     UNBOLD " %2lu" CLEARLN "\n",
    reset_slot,
    (long)reset_slot-(long)turbine_slot,
    mcups_str,
    tps_str,
    sps_str,
    next_leader_slot_str,
    root_distance,
    live_banks );
  return 1U;
}

static uint
write_gui( config_t const * config,
           ulong const *    cur_tile,
           ulong const *    prev_tile ) {
  char const * gui_name = "gui";
  ulong gui_tile_idx = fd_topo_find_tile( &config->topo, gui_name, 0UL );

  ulong off_conn_active, off_websocket_conn_active, off_websocket_frame_tx, off_websocket_frame_rx;
  char * bytes_read_s;
  char * bytes_written_s;
  if( FD_LIKELY( gui_tile_idx!=ULONG_MAX ) ) {
    off_conn_active           = MIDX( GAUGE,   GUI, CONN_ACTIVE           );
    off_websocket_conn_active = MIDX( GAUGE,   GUI, WEBSOCKET_CONN_ACTIVE );
    off_websocket_frame_tx    = MIDX( COUNTER, GUI, WEBSOCKET_FRAME_TX    );
    off_websocket_frame_rx    = MIDX( COUNTER, GUI, WEBSOCKET_FRAME_RX    );

    bytes_read_s              = DIFF_BYTES( gui_name, COUNTER, GUI, BYTES_READ    );
    bytes_written_s           = DIFF_BYTES( gui_name, COUNTER, GUI, BYTES_WRITTEN );
  } else {
    gui_name = "guih";
    gui_tile_idx = fd_topo_find_tile( &config->topo, gui_name, 0UL );
    if( FD_UNLIKELY( gui_tile_idx==ULONG_MAX ) ) return 0U;
    off_conn_active           = MIDX( GAUGE,   GUIH, CONN_ACTIVE           );
    off_websocket_conn_active = MIDX( GAUGE,   GUIH, WEBSOCKET_CONN_ACTIVE );
    off_websocket_frame_tx    = MIDX( COUNTER, GUIH, WEBSOCKET_FRAME_TX    );
    off_websocket_frame_rx    = MIDX( COUNTER, GUIH, WEBSOCKET_FRAME_RX    );

    bytes_read_s              = DIFF_BYTES( gui_name, COUNTER, GUIH, BYTES_READ    );
    bytes_written_s           = DIFF_BYTES( gui_name, COUNTER, GUIH, BYTES_WRITTEN );
  }

  ulong connection_count = cur_tile[ gui_tile_idx*FD_METRICS_TOTAL_SZ+off_conn_active ]+cur_tile[ gui_tile_idx*FD_METRICS_TOTAL_SZ+off_websocket_conn_active ];
  ulong gui_total_ticks = total_regime( &cur_tile[ gui_tile_idx*FD_METRICS_TOTAL_SZ ] )-total_regime( &prev_tile[ gui_tile_idx*FD_METRICS_TOTAL_SZ ] );
  gui_total_ticks = fd_ulong_max( gui_total_ticks, 1UL );
  double gui_backp_pct = 100.0*(double)diff_tile( config, gui_name, prev_tile, cur_tile, MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_BACKPRESSURE_PREFRAG ) )/(double)gui_total_ticks;
  double gui_idle_pct  = 100.0*(double)diff_tile( config, gui_name, prev_tile, cur_tile, MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_CAUGHT_UP_POSTFRAG ) )/(double)gui_total_ticks;
  double gui_busy_pct  = 100.0 - gui_backp_pct - gui_idle_pct;

  long sent_frame_count = diff_tile( config, gui_name, prev_tile, cur_tile, off_websocket_frame_tx );
  char * sent_frame_count_s = COUNT( (ulong)sent_frame_count );
  long received_frame_count = diff_tile( config, gui_name, prev_tile, cur_tile, off_websocket_frame_rx );

  PRINT( "👁  " BOLD CYAN "GUI........." RESET UNBOLD
         " " BOLD "CONNS"  UNBOLD " %lu"
         " " BOLD "FRAMES" UNBOLD " %s in %s out"
         " " BOLD "BW"     UNBOLD " %s in %s out"
         " " BOLD "BUSY"   UNBOLD " %3.0f%% " CLEARLN "\n",
    connection_count,
    COUNT( (ulong)received_frame_count ),
    sent_frame_count_s,
    bytes_read_s,
    bytes_written_s,
    gui_busy_pct );
  return 1U;
}

static uint
write_event( config_t const * config,
             ulong const *    cur_tile ) {
  ulong event_tile_idx = fd_topo_find_tile( &config->topo, "event", 0UL );
  if( event_tile_idx==ULONG_MAX ) return 0U;

  ulong connection_state = cur_tile[ event_tile_idx*FD_METRICS_TOTAL_SZ+MIDX( GAUGE, EVENT, CONN_STATE ) ];
  char const * connection_state_str;
  switch( connection_state ) {
    case 0UL: connection_state_str = "disconnected";    break;
    case 1UL: connection_state_str = "connecting";      break;
    case 2UL: connection_state_str = "authenticating";  break;
    case 3UL: connection_state_str = "confirming_auth"; break;
    case 4UL: connection_state_str = "connected";       break;
    default:  connection_state_str = "unknown";         break;
  }

  ulong event_queue_count = cur_tile[ event_tile_idx*FD_METRICS_TOTAL_SZ+MIDX( GAUGE, EVENT, QUEUE_DEPTH ) ];
  ulong event_queue_unsent = cur_tile[ event_tile_idx*FD_METRICS_TOTAL_SZ+MIDX( GAUGE, EVENT, QUEUE_UNSENT ) ];
  ulong event_queue_unacked = event_queue_count>event_queue_unsent ? event_queue_count-event_queue_unsent : 0UL;
  ulong event_last_acked_id = cur_tile[ event_tile_idx*FD_METRICS_TOTAL_SZ+MIDX( GAUGE, EVENT, LAST_ACKED_ID ) ];
  ulong event_queue_drops = cur_tile[ event_tile_idx*FD_METRICS_TOTAL_SZ+MIDX( COUNTER, EVENT, QUEUE_DROPPED ) ];
  ulong event_queue_bytes_used = cur_tile[ event_tile_idx*FD_METRICS_TOTAL_SZ+MIDX( GAUGE, EVENT, QUEUE_BYTES_USED ) ];
  ulong event_queue_bytes_capacity = cur_tile[ event_tile_idx*FD_METRICS_TOTAL_SZ+MIDX( GAUGE, EVENT, QUEUE_BYTES_CAPACITY ) ];

  double event_queue_pct_full = event_queue_bytes_capacity>0UL ? 100.0*(double)event_queue_bytes_used/(double)event_queue_bytes_capacity : 0.0;

  ulong events_sent_sum = 0UL;
  ulong num_events_sent_samples = fd_ulong_min( events_sent_samples_idx, sizeof(events_sent_samples)/sizeof(events_sent_samples[0]));
  for( ulong i=0UL; i<num_events_sent_samples; i++ ) events_sent_sum += events_sent_samples[ i ];
  char * events_sent_str = COUNTF( 100.0*(double)events_sent_sum/(double)num_events_sent_samples );

  ulong events_acked_sum = 0UL;
  ulong num_events_acked_samples = fd_ulong_min( events_acked_samples_idx, sizeof(events_acked_samples)/sizeof(events_acked_samples[0]));
  for( ulong i=0UL; i<num_events_acked_samples; i++ ) events_acked_sum += events_acked_samples[ i ];
  char * events_acked_str = COUNTF( 100.0*(double)events_acked_sum/(double)num_events_acked_samples );

  ulong bytes_written_sum = 0UL;
  ulong num_bytes_written_samples = fd_ulong_min( event_bytes_written_samples_idx, sizeof(event_bytes_written_samples)/sizeof(event_bytes_written_samples[0]));
  for( ulong i=0UL; i<num_bytes_written_samples; i++ ) bytes_written_sum += event_bytes_written_samples[ i ];
  long bytes_written_per_sec = (long)(100.0*(double)bytes_written_sum/(double)num_bytes_written_samples);
  char * bytes_written_str = fmt_bytes( fd_alloca_check( 1UL, 64UL ), 64UL, bytes_written_per_sec );

  ulong bytes_read_sum = 0UL;
  ulong num_bytes_read_samples = fd_ulong_min( event_bytes_read_samples_idx, sizeof(event_bytes_read_samples)/sizeof(event_bytes_read_samples[0]));
  for( ulong i=0UL; i<num_bytes_read_samples; i++ ) bytes_read_sum += event_bytes_read_samples[ i ];
  long bytes_read_per_sec = (long)(100.0*(double)bytes_read_sum/(double)num_bytes_read_samples);
  char * bytes_read_str = fmt_bytes( fd_alloca_check( 1UL, 64UL ), 64UL, bytes_read_per_sec );

  char * event_queue_unacked_s = COUNT( event_queue_unacked );
  char * event_queue_unsent_s  = COUNT( event_queue_unsent );
  char * event_last_acked_id_s = COUNT( event_last_acked_id );

  PRINT( "📡 " BOLD YELLOW "EVENT......." RESET UNBOLD
         " " BOLD "STATE"    UNBOLD " %12s"
         " " BOLD "UNACKED"  UNBOLD " %s"
         " " BOLD "QUEUE"    UNBOLD " %s"
         " " BOLD "SENT"     UNBOLD " %s /s"
         " " BOLD "ACKED"    UNBOLD " %s /s"
         " " BOLD "LAST ACK" UNBOLD " %s"
         " " BOLD "BW"       UNBOLD " %s in %s out"
         " " BOLD "DROPS"    UNBOLD " %s"
         " " BOLD "FULL"     UNBOLD " %3.0f%%" CLEARLN "\n",
    connection_state_str,
    event_queue_unacked_s,
    event_queue_unsent_s,
    events_sent_str,
    events_acked_str,
    event_last_acked_id_s,
    bytes_read_str,
    bytes_written_str,
    COUNT( event_queue_drops ),
    event_queue_pct_full );
  return 1U;
}

static char *
base58_short( char        out[ static 16 ],
              uchar const key[ static 32 ] ) {
  char enc[ FD_BASE58_ENCODED_32_SZ ];
  ulong len;
  fd_base58_encode_32( key, &len, enc );
  char * p = fd_cstr_init( out );
  p = fd_cstr_append_text( p, enc, 6 ),
  p = fd_cstr_append_text( p, "…", sizeof("…")-1 ),
  p = fd_cstr_append_text( p, enc+len-6, 6 );
  fd_cstr_fini( p );
  return out;
}

static void
fmt_balance( char  out[ static 64 ],
             ulong lamports ) {
  ulong maj = lamports / 1000000000UL;
  ulong min = lamports % 1000000000UL;
  fd_cstr_printf_check( out, 64UL, NULL, "%lu.%09lu", maj, min );
}

static uint
write_node_info( config_t const *       config,
                 ulong const *          cur_tile,
                 fd_node_info_t const * node_info ) {

  char identity_str[ FD_BASE58_ENCODED_32_SZ ];
  if( FD_LIKELY( node_info && !fd_pubkey_check_zero( &node_info->identity ) ) ) {
    fd_base58_encode_32( node_info->identity.key, NULL, identity_str );
  } else {
    strcpy( identity_str, "???" );
  }

  char vote_acc_str[ FD_BASE58_ENCODED_32_SZ ];
  if( FD_LIKELY( node_info && !fd_pubkey_check_zero( &node_info->vote_account ) ) ) {
    fd_base58_encode_32( node_info->vote_account.key, NULL, vote_acc_str );
  } else {
    strcpy( vote_acc_str, "???" );
  }

  char shred_ver_str[ 16 ];
  ulong ipecho_idx = fd_topo_find_tile( &config->topo, "ipecho", 0UL );
  ushort shred_version = 0;
  if( FD_LIKELY( ipecho_idx!=ULONG_MAX ) ) shred_version = (ushort)cur_tile[ ipecho_idx*FD_METRICS_TOTAL_SZ+MIDX( GAUGE, IPECHO, CURRENT_SHRED_VERSION ) ];
  if( shred_version ) {
    fd_cstr_printf_check( shred_ver_str, sizeof(shred_ver_str), NULL, "%hu", shred_version );
  } else if( config->consensus.expected_shred_version ) {
    fd_cstr_printf_check( shred_ver_str, sizeof(shred_ver_str), NULL, "(%hu)", config->consensus.expected_shred_version );
  } else {
    fd_cstr_printf_check( shred_ver_str, sizeof(shred_ver_str), NULL, "???" );
  }

  char genesis_hash_b58[ FD_BASE58_ENCODED_32_SZ ] = {0};
  char genesis_short[ 16 ] = {0};
  int  has_genesis_b58 = 0;
  if( FD_LIKELY( node_info && !fd_pubkey_check_zero( &node_info->genesis_hash ) ) ) {
    fd_base58_encode_32( node_info->genesis_hash.key, NULL, genesis_hash_b58 );
    base58_short( genesis_short, node_info->genesis_hash.key );
    has_genesis_b58 = 1;
  } else {
    fd_cstr_ncpy( genesis_short, "???", sizeof(genesis_short) );
  }

  char const * cluster_str = "unknown";
  if( has_genesis_b58 ) {
    ulong cluster_id = fd_genesis_cluster_identify( genesis_hash_b58 );
    cluster_str = fd_genesis_cluster_name( cluster_id );
  }

  char uptime_str[ 32UL ];
  long now = fd_log_wallclock();
  if( FD_LIKELY( config->boot_timestamp_nanos>0L && now>config->boot_timestamp_nanos ) ) {
    ulong elapsed_s = (ulong)( (now - config->boot_timestamp_nanos) / (long)1e9 );
    ulong days  = elapsed_s / 86400UL;
    ulong hours = (elapsed_s % 86400UL) / 3600UL;
    ulong mins  = (elapsed_s % 3600UL) / 60UL;
    ulong secs  = elapsed_s % 60UL;
    if( days ) fd_cstr_printf_check( uptime_str, sizeof(uptime_str), NULL, "%lud %luh %lum", days, hours, mins );
    else if( hours ) fd_cstr_printf_check( uptime_str, sizeof(uptime_str), NULL, "%luh %lum %lus", hours, mins, secs );
    else fd_cstr_printf_check( uptime_str, sizeof(uptime_str), NULL, "%lum %lus", mins, secs );
  } else {
    fd_cstr_printf_check( uptime_str, sizeof(uptime_str), NULL, "???" );
  }

  ulong replay_idx = fd_topo_find_tile( &config->topo, "replay", 0UL );
  ulong const * replay_metrics = &cur_tile[ replay_idx*FD_METRICS_TOTAL_SZ ];
  ulong identity_balance = replay_metrics[ MIDX( GAUGE, REPLAY, IDENTITY_BALANCE_LAMPORTS     ) ];
  ulong stake_amount     = replay_metrics[ MIDX( GAUGE, REPLAY, ACTIVE_STAKE_LAMPORTS         ) ];
  ulong epoch_credits    = replay_metrics[ MIDX( GAUGE, REPLAY, EPOCH_CREDITS                 ) ];
  ulong tot_stake        = replay_metrics[ MIDX( GAUGE, REPLAY, CLUSTER_ACTIVE_STAKE_LAMPORTS ) ];
  char identity_balance_str[ 64 ]; fmt_balance( identity_balance_str, identity_balance );
  char stake_amount_str    [ 64 ]; fmt_balance( stake_amount_str,     stake_amount     );
  double stake_percent = 0.0;
  if( tot_stake>0UL ) stake_percent = 100.0*(double)stake_amount/(double)tot_stake;

  PRINT( "🔑" BOLD ORANGE " NODE........" RESET UNBOLD
         " " BOLD "ID"      UNBOLD " %44s"
         " " BOLD "VOTE"    UNBOLD " %44s"
         " " BOLD "CLUSTER" UNBOLD " %s"
         " " BOLD "UPTIME"  UNBOLD " %s"
         " " BOLD "SHRED"   UNBOLD " %s"
         " " BOLD "GENESIS" UNBOLD " %s",
    identity_str,
    vote_acc_str,
    cluster_str,
    uptime_str,
    shred_ver_str,
    genesis_short );
  PRINT( CLEARLN "\n" );

  if( FD_LIKELY( !watch_full ) ) return 1U;

  PRINT( "                " BOLD "BALANCE" UNBOLD " %s"
         " " BOLD "STAKE"   UNBOLD " %s (%.2f %%)"
         " " BOLD "CREDITS" UNBOLD " %lu" CLEARLN "\n",
         identity_balance_str, stake_amount_str, stake_percent, epoch_credits );

  return 2U;
}

static void
write_summary( config_t const *           config,
               fd_node_info_box_t const * shinfo,
               ulong const *              cur_tile,
               ulong const *              prev_tile,
               ulong const *              cur_link,
               ulong const *              prev_link ) {
  (void)config;
  (void)prev_tile;
  (void)cur_tile;

  if( FD_UNLIKELY( !ended_on_newline ) ) PRINT( "\n" );
  PRINT( "\033[?7l" ); /* disable autowrap mode */
  lines_printed = 0UL;

  ulong snapct_idx = fd_topo_find_tile( &config->topo, "snapct", 0UL );
  int shutdown = 1;
  if( FD_LIKELY( snapct_idx!=ULONG_MAX ) ) shutdown = cur_tile[ snapct_idx*FD_METRICS_TOTAL_SZ+MIDX( GAUGE, SNAPCT, STATE ) ]==FD_SNAPCT_STATE_SHUTDOWN;

  static long snap_shutdown_time = 0L;
  if( FD_UNLIKELY( !snap_shutdown_time && !shutdown ) ) snap_shutdown_time = 1L; /* Was not shutdown on boot */
  if( FD_UNLIKELY( !snap_shutdown_time && shutdown  ) ) snap_shutdown_time = 2L; /* Was shutdown on boot */
  if( FD_UNLIKELY( snap_shutdown_time==1L && shutdown  ) ) snap_shutdown_time = fd_log_wallclock();

  fd_node_info_t node_info[1]; fd_node_info_read( node_info, shinfo );
  lines_printed += write_node_info( config, cur_tile, node_info );

  if( FD_UNLIKELY( write_bench( config, cur_tile, prev_tile ) ) ) lines_printed++;

  ulong backt_idx = fd_topo_find_tile( &config->topo, "backt", 0UL );
  if( FD_UNLIKELY( backt_idx!=ULONG_MAX ) ) {
    lines_printed++;
    write_backtest( config, cur_tile );
  }

  long now = fd_log_wallclock();
  if( FD_UNLIKELY( snap_shutdown_time==1L || now<snap_shutdown_time+(long)2e9 ) ) {
    lines_printed++;
    write_snapshots( config, cur_tile, prev_tile );
  }

  lines_printed += write_accdb( config, cur_tile, prev_tile );
  lines_printed += write_wfs( config, cur_tile );
  lines_printed += write_gossip( config, cur_tile, prev_tile, cur_link, prev_link );
  lines_printed += write_repair( config, cur_tile, cur_link, prev_link );
  lines_printed += write_rserve( config, cur_tile, cur_link, prev_link );
  lines_printed += write_replay( config, cur_tile );
  lines_printed += write_gui( config, cur_tile, prev_tile );
  lines_printed += write_event( config, cur_tile );

  PRINT( "\033[?7h" ); /* enable autowrap mode */
}

static void
snap_tiles( fd_topo_t const * topo,
            ulong *           tiles ) {
  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t const * tile = &topo->tiles[ i ];
    volatile ulong const * metrics = fd_metrics_tile( tile->metrics );
    FD_TEST( metrics );
    for( ulong j=0UL; j<FD_METRICS_TOTAL_SZ/8UL; j++ ) tiles[ i*FD_METRICS_TOTAL_SZ+j ] = metrics[ j ];
  }
}

static void
snap_links( fd_topo_t const * topo,
            ulong *           links ) {
  ulong overall_polled_idx = 0UL;

  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t const * tile = &topo->tiles[ i ];

    ulong polled_in_idx = 0UL;
    for( ulong j=0UL; j<topo->tiles[ i ].in_cnt; j++ ) {
      if( FD_UNLIKELY( !tile->in_link_poll[ j ] ) ) continue;

      volatile ulong const * metrics = fd_metrics_link_in( tile->metrics, polled_in_idx );
      FD_TEST( metrics );
      for( ulong k=0UL; k<FD_METRICS_ALL_LINK_IN_TOTAL; k++ ) links[ overall_polled_idx*8UL+k ] = metrics[ k ];
      polled_in_idx++;
      overall_polled_idx++;
    }
  }
}

static ulong tiles[ 2UL*FD_TILE_MAX*FD_METRICS_TOTAL_SZ ];
static ulong links[ 2UL*4096UL*8UL*FD_METRICS_ALL_LINK_IN_TOTAL ];

static void
run( config_t const * config,
     int              drain_output_fd ) {
  (void)config;
  (void)drain_output_fd;

  ulong node_info_obj_id = fd_pod_query_ulong( config->topo.props, "node_info", ULONG_MAX );
  FD_TEST( node_info_obj_id!=ULONG_MAX );
  fd_node_info_box_t * node_info = fd_node_info_box_join( fd_topo_obj_laddr( &config->topo, node_info_obj_id ) );
  FD_TEST( node_info );

  ulong tile_cnt = config->topo.tile_cnt;

  ulong cons_cnt = 0UL;
  for( ulong i=0UL; i<config->topo.tile_cnt; i++ ) {
    for( ulong j=0UL; j<config->topo.tiles[ i ].in_cnt; j++ ) {
      if( FD_UNLIKELY( config->topo.tiles[ i ].in_link_poll[ j ] ) ) cons_cnt++;
    }
  }

  FD_TEST( tile_cnt<=FD_TILE_MAX );
  FD_TEST( cons_cnt<=4096UL );

  snap_tiles( &config->topo, tiles );
  fd_memcpy( tiles+tile_cnt*FD_METRICS_TOTAL_SZ, tiles, tile_cnt*FD_METRICS_TOTAL_SZ*sizeof(ulong) );

  snap_links( &config->topo, links );
  fd_memcpy( links+(cons_cnt*8UL*FD_METRICS_ALL_LINK_IN_TOTAL), links, cons_cnt*8UL*FD_METRICS_ALL_LINK_IN_TOTAL*sizeof(ulong) );

  ulong last_snap = 1UL;


  frame_len = 0UL;
  write_summary( config, node_info, tiles+last_snap*tile_cnt*FD_METRICS_TOTAL_SZ, tiles+(1UL-last_snap)*tile_cnt*FD_METRICS_TOTAL_SZ, links+last_snap*(cons_cnt*8UL*FD_METRICS_ALL_LINK_IN_TOTAL), links+(1UL-last_snap)*(cons_cnt*8UL*FD_METRICS_ALL_LINK_IN_TOTAL) );
  flush_frame();

  long next = fd_log_wallclock()+(long)1e9;
  for(;;) {
    if( FD_UNLIKELY( drain_output_fd>=0 ) ) {
      if( FD_UNLIKELY( drain( drain_output_fd ) ) ) {
        frame_len = 0UL;
        write_summary( config, node_info, tiles+last_snap*tile_cnt*FD_METRICS_TOTAL_SZ, tiles+(1UL-last_snap)*tile_cnt*FD_METRICS_TOTAL_SZ, links+last_snap*(cons_cnt*8UL*FD_METRICS_ALL_LINK_IN_TOTAL), links+(1UL-last_snap)*(cons_cnt*8UL*FD_METRICS_ALL_LINK_IN_TOTAL) );
        flush_frame();
      }
    }

    long now = fd_log_wallclock();
    if( FD_UNLIKELY( now>=next ) ) {
      last_snap = 1UL-last_snap;
      snap_tiles( &config->topo, tiles+last_snap*tile_cnt*FD_METRICS_TOTAL_SZ );
      snap_links( &config->topo, links+last_snap*(cons_cnt*8UL*FD_METRICS_ALL_LINK_IN_TOTAL) );

      /* Bench */
      tps_sent_samples[ tps_sent_samples_idx%(sizeof(tps_sent_samples)/sizeof(tps_sent_samples[0])) ] = (ulong)diff_tile( config, "benchs", tiles+(1UL-last_snap)*tile_cnt*FD_METRICS_TOTAL_SZ, tiles+last_snap*tile_cnt*FD_METRICS_TOTAL_SZ, MIDX( COUNTER, BENCHS, TXN_TX ) );
      tps_sent_samples_idx++;

      /* Replay */
      sps_samples[ sps_samples_idx%(sizeof(sps_samples)/sizeof(sps_samples[0])) ] = (ulong)diff_tile( config, "replay", tiles+(1UL-last_snap)*tile_cnt*FD_METRICS_TOTAL_SZ, tiles+last_snap*tile_cnt*FD_METRICS_TOTAL_SZ, MIDX( COUNTER, REPLAY, SLOT_REPLAYED ) );
      sps_samples_idx++;
      tps_samples[ tps_samples_idx%(sizeof(tps_samples)/sizeof(tps_samples[0])) ] = (ulong)diff_tile( config, "replay", tiles+(1UL-last_snap)*tile_cnt*FD_METRICS_TOTAL_SZ, tiles+last_snap*tile_cnt*FD_METRICS_TOTAL_SZ, MIDX( COUNTER, REPLAY, TXN_PROCESSED ) );
      tps_samples_idx++;
      cups_samples[ cups_samples_idx%(sizeof(cups_samples)/sizeof(cups_samples[0])) ] =
          (ulong)diff_tile( config, "execrp", tiles+(1UL-last_snap)*tile_cnt*FD_METRICS_TOTAL_SZ, tiles+last_snap*tile_cnt*FD_METRICS_TOTAL_SZ, MIDX( COUNTER, EXECRP, CU_EXECUTED ) ) +
          (ulong)diff_tile( config, "execle", tiles+(1UL-last_snap)*tile_cnt*FD_METRICS_TOTAL_SZ, tiles+last_snap*tile_cnt*FD_METRICS_TOTAL_SZ, MIDX( COUNTER, EXECLE, CU_EXECUTED ) );
      cups_samples_idx++;

      /* Snapshot */
      snapshot_rx_samples[ snapshot_rx_idx%(sizeof(snapshot_rx_samples)/sizeof(snapshot_rx_samples[0])) ] = (ulong)diff_tile( config, "snapct", tiles+(1UL-last_snap)*tile_cnt*FD_METRICS_TOTAL_SZ, tiles+last_snap*tile_cnt*FD_METRICS_TOTAL_SZ, MIDX( GAUGE, SNAPCT, FULL_BYTES_READ ) ) +
                                                                                                            (ulong)diff_tile( config, "snapct", tiles+(1UL-last_snap)*tile_cnt*FD_METRICS_TOTAL_SZ, tiles+last_snap*tile_cnt*FD_METRICS_TOTAL_SZ, MIDX( GAUGE, SNAPCT, INCREMENTAL_BYTES_READ ) );
      snapshot_rx_idx++;
      snapshot_acc_samples[ snapshot_acc_idx%(sizeof(snapshot_acc_samples)/sizeof(snapshot_acc_samples[0])) ] = (ulong)diff_tile( config, "snapin", tiles+(1UL-last_snap)*tile_cnt*FD_METRICS_TOTAL_SZ, tiles+last_snap*tile_cnt*FD_METRICS_TOTAL_SZ, MIDX( GAUGE, SNAPIN, ACCOUNT_LOADED ) );
      snapshot_acc_idx++;
      snapshot_wr_samples[ snapshot_wr_idx%(sizeof(snapshot_wr_samples)/sizeof(snapshot_wr_samples[0])) ] = (ulong)diff_tile( config, "snapwr", tiles+(1UL-last_snap)*tile_cnt*FD_METRICS_TOTAL_SZ, tiles+last_snap*tile_cnt*FD_METRICS_TOTAL_SZ, MIDX( GAUGE, SNAPWR, BYTES_WRITTEN ) );
      snapshot_wr_idx++;

      /* Events */
      events_sent_samples[ events_sent_samples_idx%(sizeof(events_sent_samples)/sizeof(events_sent_samples[0])) ] = (ulong)diff_tile( config, "event", tiles+(1UL-last_snap)*tile_cnt*FD_METRICS_TOTAL_SZ, tiles+last_snap*tile_cnt*FD_METRICS_TOTAL_SZ, MIDX( COUNTER, EVENT, SENT ) );
      events_sent_samples_idx++;
      events_acked_samples[ events_acked_samples_idx%(sizeof(events_acked_samples)/sizeof(events_acked_samples[0])) ] = (ulong)diff_tile( config, "event", tiles+(1UL-last_snap)*tile_cnt*FD_METRICS_TOTAL_SZ, tiles+last_snap*tile_cnt*FD_METRICS_TOTAL_SZ, MIDX( COUNTER, EVENT, ACKED ) );
      events_acked_samples_idx++;
      event_bytes_written_samples[ event_bytes_written_samples_idx%(sizeof(event_bytes_written_samples)/sizeof(event_bytes_written_samples[0])) ] = (ulong)diff_tile( config, "event", tiles+(1UL-last_snap)*tile_cnt*FD_METRICS_TOTAL_SZ, tiles+last_snap*tile_cnt*FD_METRICS_TOTAL_SZ, MIDX( COUNTER, EVENT, BYTES_WRITTEN ) );
      event_bytes_written_samples_idx++;
      event_bytes_read_samples[ event_bytes_read_samples_idx%(sizeof(event_bytes_read_samples)/sizeof(event_bytes_read_samples[0])) ] = (ulong)diff_tile( config, "event", tiles+(1UL-last_snap)*tile_cnt*FD_METRICS_TOTAL_SZ, tiles+last_snap*tile_cnt*FD_METRICS_TOTAL_SZ, MIDX( COUNTER, EVENT, BYTES_READ ) );
      event_bytes_read_samples_idx++;

      /* Accounts */
      sample_accdb( config, tiles+(1UL-last_snap)*tile_cnt*FD_METRICS_TOTAL_SZ, tiles+last_snap*tile_cnt*FD_METRICS_TOTAL_SZ );

      /* Repair server */
      shreds_stored_sample[ shreds_stored_samples_idx%(sizeof(shreds_stored_sample)/sizeof(shreds_stored_sample[0])) ] = (ulong)diff_tile( config, "rserve", tiles+(1UL-last_snap)*tile_cnt*FD_METRICS_TOTAL_SZ, tiles+last_snap*tile_cnt*FD_METRICS_TOTAL_SZ, MIDX( GAUGE, RSERVE, SHREDS_CURRENT ) );
      shreds_stored_samples_idx++;

      rserve_rps_valid_samples[ rserve_rps_valid_samples_idx%(sizeof(rserve_rps_valid_samples)/sizeof(rserve_rps_valid_samples[0])) ] = (ulong)(
          diff_tile( config, "rserve", tiles+(1UL-last_snap)*tile_cnt*FD_METRICS_TOTAL_SZ, tiles+last_snap*tile_cnt*FD_METRICS_TOTAL_SZ, MIDX( COUNTER, RSERVE, SENT_RESPONSE_TYPES_PING ) ) +
          diff_tile( config, "rserve", tiles+(1UL-last_snap)*tile_cnt*FD_METRICS_TOTAL_SZ, tiles+last_snap*tile_cnt*FD_METRICS_TOTAL_SZ, MIDX( COUNTER, RSERVE, SENT_RESPONSE_TYPES_WINDOW ) ) +
          diff_tile( config, "rserve", tiles+(1UL-last_snap)*tile_cnt*FD_METRICS_TOTAL_SZ, tiles+last_snap*tile_cnt*FD_METRICS_TOTAL_SZ, MIDX( COUNTER, RSERVE, SENT_RESPONSE_TYPES_HIGHEST_WINDOW ) ) +
          diff_tile( config, "rserve", tiles+(1UL-last_snap)*tile_cnt*FD_METRICS_TOTAL_SZ, tiles+last_snap*tile_cnt*FD_METRICS_TOTAL_SZ, MIDX( COUNTER, RSERVE, SENT_RESPONSE_TYPES_ORPHAN ) ) );
      rserve_rps_valid_samples_idx++;

      rserve_rps_invalid_samples[ rserve_rps_invalid_samples_idx%(sizeof(rserve_rps_invalid_samples)/sizeof(rserve_rps_invalid_samples[0])) ] = (ulong)(
          diff_tile( config, "rserve", tiles+(1UL-last_snap)*tile_cnt*FD_METRICS_TOTAL_SZ, tiles+last_snap*tile_cnt*FD_METRICS_TOTAL_SZ, MIDX( COUNTER, RSERVE, MISSED_RESPONSE_TYPES_PING ) ) +
          diff_tile( config, "rserve", tiles+(1UL-last_snap)*tile_cnt*FD_METRICS_TOTAL_SZ, tiles+last_snap*tile_cnt*FD_METRICS_TOTAL_SZ, MIDX( COUNTER, RSERVE, MISSED_RESPONSE_TYPES_WINDOW ) ) +
          diff_tile( config, "rserve", tiles+(1UL-last_snap)*tile_cnt*FD_METRICS_TOTAL_SZ, tiles+last_snap*tile_cnt*FD_METRICS_TOTAL_SZ, MIDX( COUNTER, RSERVE, MISSED_RESPONSE_TYPES_HIGHEST_WINDOW ) ) +
          diff_tile( config, "rserve", tiles+(1UL-last_snap)*tile_cnt*FD_METRICS_TOTAL_SZ, tiles+last_snap*tile_cnt*FD_METRICS_TOTAL_SZ, MIDX( COUNTER, RSERVE, MISSED_RESPONSE_TYPES_ORPHAN ) ) +
          diff_tile( config, "rserve", tiles+(1UL-last_snap)*tile_cnt*FD_METRICS_TOTAL_SZ, tiles+last_snap*tile_cnt*FD_METRICS_TOTAL_SZ, MIDX( COUNTER, RSERVE, FAILED_SIGVERIFY ) ) +
          diff_tile( config, "rserve", tiles+(1UL-last_snap)*tile_cnt*FD_METRICS_TOTAL_SZ, tiles+last_snap*tile_cnt*FD_METRICS_TOTAL_SZ, MIDX( COUNTER, RSERVE, FAILED_OWN_KEY ) ) +
          diff_tile( config, "rserve", tiles+(1UL-last_snap)*tile_cnt*FD_METRICS_TOTAL_SZ, tiles+last_snap*tile_cnt*FD_METRICS_TOTAL_SZ, MIDX( COUNTER, RSERVE, FAILED_INVALID_TOKEN ) ) +
          diff_tile( config, "rserve", tiles+(1UL-last_snap)*tile_cnt*FD_METRICS_TOTAL_SZ, tiles+last_snap*tile_cnt*FD_METRICS_TOTAL_SZ, MIDX( COUNTER, RSERVE, FAILED_NOT_FOR_US ) ) +
          diff_tile( config, "rserve", tiles+(1UL-last_snap)*tile_cnt*FD_METRICS_TOTAL_SZ, tiles+last_snap*tile_cnt*FD_METRICS_TOTAL_SZ, MIDX( COUNTER, RSERVE, FAILED_OUTDATED ) ) +
          diff_tile( config, "rserve", tiles+(1UL-last_snap)*tile_cnt*FD_METRICS_TOTAL_SZ, tiles+last_snap*tile_cnt*FD_METRICS_TOTAL_SZ, MIDX( COUNTER, RSERVE, FAILED_PING_CACHE_LOOKUP ) ) +
          diff_tile( config, "rserve", tiles+(1UL-last_snap)*tile_cnt*FD_METRICS_TOTAL_SZ, tiles+last_snap*tile_cnt*FD_METRICS_TOTAL_SZ, MIDX( COUNTER, RSERVE, FAILED_INVALID_SHRED_INDEX ) ) );
      {
        ulong slot = rserve_rps_invalid_samples_idx % (sizeof(rserve_rps_miss_samples)/sizeof(rserve_rps_miss_samples[0]));
        ulong const * prev = tiles+(1UL-last_snap)*tile_cnt*FD_METRICS_TOTAL_SZ;
        ulong const * cur  = tiles+last_snap*tile_cnt*FD_METRICS_TOTAL_SZ;

        rserve_rps_miss_samples[ slot ] = (ulong)(
            diff_tile( config, "rserve", prev, cur, MIDX( COUNTER, RSERVE, MISSED_RESPONSE_TYPES_PING ) ) +
            diff_tile( config, "rserve", prev, cur, MIDX( COUNTER, RSERVE, MISSED_RESPONSE_TYPES_WINDOW ) ) +
            diff_tile( config, "rserve", prev, cur, MIDX( COUNTER, RSERVE, MISSED_RESPONSE_TYPES_HIGHEST_WINDOW ) ) +
            diff_tile( config, "rserve", prev, cur, MIDX( COUNTER, RSERVE, MISSED_RESPONSE_TYPES_ORPHAN ) ) );

        rserve_rps_sigvfy_samples[ slot ] = (ulong)diff_tile( config, "rserve", prev, cur, MIDX( COUNTER, RSERVE, FAILED_SIGVERIFY ) );

        rserve_rps_stale_samples[ slot ] = (ulong)diff_tile( config, "rserve", prev, cur, MIDX( COUNTER, RSERVE, FAILED_OUTDATED ) );

        rserve_rps_other_rej_samples[ slot ] = (ulong)(
            diff_tile( config, "rserve", prev, cur, MIDX( COUNTER, RSERVE, FAILED_OWN_KEY ) ) +
            diff_tile( config, "rserve", prev, cur, MIDX( COUNTER, RSERVE, FAILED_INVALID_TOKEN ) ) +
            diff_tile( config, "rserve", prev, cur, MIDX( COUNTER, RSERVE, FAILED_NOT_FOR_US ) ) +
            diff_tile( config, "rserve", prev, cur, MIDX( COUNTER, RSERVE, FAILED_INVALID_SHRED_INDEX ) ) +
            diff_tile( config, "rserve", prev, cur, MIDX( COUNTER, RSERVE, FAILED_PING_CACHE_LOOKUP ) ) );
      }
      rserve_rps_invalid_samples_idx++;

      /* Move cursor to top of dashboard and overwrite in place.
         All output is buffered and flushed in a single write() so
         the terminal never renders a partially drawn frame. */
      frame_len = 0UL;
      PRINT( "\033[?25l" ); /* hide cursor during redraw */
      if( FD_UNLIKELY( !ended_on_newline ) ) {
        PRINT( "\033[%luA\r", lines_printed+1UL );
      } else {
        PRINT( "\033[%luA\r", lines_printed );
      }
      write_summary( config, node_info, tiles+last_snap*tile_cnt*FD_METRICS_TOTAL_SZ, tiles+(1UL-last_snap)*tile_cnt*FD_METRICS_TOTAL_SZ, links+last_snap*(cons_cnt*8UL*FD_METRICS_ALL_LINK_IN_TOTAL), links+(1UL-last_snap)*(cons_cnt*8UL*FD_METRICS_ALL_LINK_IN_TOTAL) );
      PRINT( "\033[0J" );    /* clear any leftover lines below */
      PRINT( "\033[?25h" ); /* show cursor */
      flush_frame();
      next += (long)1e7;
    }
  }
}

void
watch_cmd_args( int *    pargc,
                char *** pargv,
                args_t * args ) {
  args->watch.drain_output_fd = -1;
  args->watch.full            = fd_env_strip_cmdline_contains( pargc, pargv, "--full" );
}

void
watch_cmd_fn( args_t *   args,
              config_t * config ) {
  /* Development commands spawn watch internally with the validator's
     own config, only discover when invoked standalone. */
  if( FD_LIKELY( args->watch.drain_output_fd==-1 ) ) fd_bootinfo_adopt( config );

  int allow_fds[ 5 ];
  ulong allow_fds_cnt = 0;
  allow_fds[ allow_fds_cnt++ ] = 0; /* stdin */
  allow_fds[ allow_fds_cnt++ ] = 1; /* stdout */
  allow_fds[ allow_fds_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( fd_log_private_logfile_fd()!=-1 ) )
    allow_fds[ allow_fds_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  if( FD_UNLIKELY( args->watch.drain_output_fd!=-1 ) )
    allow_fds[ allow_fds_cnt++ ] = args->watch.drain_output_fd; /* maybe we are interposing firedancer log output with the monitor */

  if( FD_LIKELY( args->watch.drain_output_fd==-1 ) ) fd_bootinfo_check_layout( config );
  fd_topo_join_workspaces( &config->topo, FD_SHMEM_JOIN_MODE_READ_ONLY, FD_TOPO_CORE_DUMP_LEVEL_DISABLED );

  struct sock_filter seccomp_filter[ 128UL ];
  uint drain_output_fd = args->watch.drain_output_fd >= 0 ? (uint)args->watch.drain_output_fd : (uint)-1;
  populate_sock_filter_policy_watch( 128UL, seccomp_filter, (uint)fd_log_private_logfile_fd(), drain_output_fd );

  if( FD_LIKELY( config->development.sandbox ) ) {
    fd_sandbox_enter( config->uid,
                      config->gid,
                      0,
                      0,
                      0,
                      1, /* Keep controlling terminal for main so it can receive Ctrl+C */
                      0,
                      0UL,
                      0UL,
                      0UL,
                      0UL,
                      allow_fds_cnt,
                      allow_fds,
                      sock_filter_policy_watch_instr_cnt,
                      seccomp_filter );
  } else {
    fd_sandbox_switch_uid_gid( config->uid, config->gid );
  }

  fd_topo_fill( &config->topo );

  watch_full = args->watch.full;
  run( config, args->watch.drain_output_fd );
}

static void
watch_args_help( fd_action_help_t * help ) {
  fd_action_help_arg( help, "--full", NULL, "Show all detail rows for each category, not just the primary row" );
}

action_t fd_action_watch = {
  .name           = "watch",
  .args           = watch_cmd_args,
  .fn             = watch_cmd_fn,
  .require_config = 0,
  .perm           = watch_cmd_perm,
  .description    = "Watch a locally running Firedancer instance with a terminal GUI",
  .detail         = "Connects to a running validator and renders a terminal dashboard of the\n"
                    "most important monitoring and operational metrics.",
  .usage          = "watch [--full]",
  .args_help      = watch_args_help,
};
