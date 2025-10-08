#include "watch.h"
#include "generated/watch_seccomp.h"

#include "../../../../discof/restore/fd_snaprd_tile.h"
#include "../../../../disco/metrics/fd_metrics.h"

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

static int
drain( int fd ) {
  int needs_reprint = 0;

  while( 1 ) {
    uchar buf[ 16384UL ];
    long result = read( fd, buf, sizeof(buf) );
    if( FD_UNLIKELY( -1==result && errno==EAGAIN ) ) break;
    else if( FD_UNLIKELY( -1==result ) ) FD_LOG_ERR(( "read() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

    if( FD_LIKELY( !needs_reprint ) ) {
      /* move up n lines, delete n lines, and restore cursor and clear to end of screen */
      char erase[ 128UL ];
      ulong term_len = 0UL;
      if( FD_UNLIKELY( !ended_on_newline ) ) {
        FD_TEST( fd_cstr_printf_check( erase, 128UL, &term_len, "\033[%luA\033[%luM\033[1A\033[0J", lines_printed, lines_printed ) );
      } else {
        FD_TEST( fd_cstr_printf_check( erase, 128UL, &term_len, "\033[%luA\033[%luM\033[0J", lines_printed, lines_printed ) );
      }

      ulong erase_written = 0L;
      while( erase_written<term_len ) {
        long w = write( STDOUT_FILENO, erase+erase_written, term_len-erase_written );
        if( FD_UNLIKELY( -1==w && errno==EAGAIN ) ) continue;
        else if( FD_UNLIKELY( -1==w ) ) FD_LOG_ERR(( "write() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
        erase_written += (ulong)w;
      }
    }
    needs_reprint = 1;

    long written = 0L;
    while( written<result ) {
      long w = write( STDOUT_FILENO, buf+written, (ulong)result-(ulong)written );
      if( FD_UNLIKELY( -1==w && errno==EAGAIN ) ) continue;
      else if( FD_UNLIKELY( -1==w ) ) FD_LOG_ERR(( "write() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
      written += w;
    }

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
    sum += metrics[ MIDX( GAUGE, GOSSIP, CRDS_COUNT_CONTACT_INFO_V1 )+i ];
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

static ulong sps_samples_idx = 0UL;
static ulong sps_samples[ 200UL ];
static ulong tps_samples_idx = 0UL;
static ulong tps_samples[ 200UL ];
static ulong snapshot_rx_idx = 0UL;
static ulong snapshot_rx_samples[ 100UL ];
static ulong snapshot_acc_idx = 0UL;
static ulong snapshot_acc_samples[ 100UL ];

#define PRINT(...) do {                          \
  char * _buf = fd_alloca_check( 1UL, 1024UL );  \
  ulong _len;                                    \
  FD_TEST( fd_cstr_printf_check( _buf, 1024UL, &_len, __VA_ARGS__ ) ); \
  ulong _written = 0L;                           \
  while( _written<_len ) {                       \
    long w = write( STDOUT_FILENO, _buf+_written, _len-(ulong)_written ); \
    if( FD_UNLIKELY( -1==w && errno==EAGAIN ) ) continue; \
    else if( FD_UNLIKELY( -1==w ) ) FD_LOG_ERR(( "write() failed (%i-%s)", errno, fd_io_strerror( errno ) )); \
    _written += (ulong)w;                        \
  }                                              \
} while(0)                                       \

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

static void
write_backtest( config_t const * config,
                ulong const *    cur_tile ) {
  ulong backt_idx = fd_topo_find_tile( &config->topo, "backt", 0UL );
  ulong start_slot = cur_tile[ backt_idx*FD_METRICS_TOTAL_SZ+MIDX( GAUGE, BACKT, START_SLOT ) ];
  ulong final_slot = cur_tile[ backt_idx*FD_METRICS_TOTAL_SZ+MIDX( GAUGE, BACKT, FINAL_SLOT ) ];

  ulong replay_idx = fd_topo_find_tile( &config->topo, "replay", 0UL );
  ulong current_slot = cur_tile[ replay_idx*FD_METRICS_TOTAL_SZ+MIDX( GAUGE, REPLAY, ROOT_SLOT ) ];
  current_slot = current_slot ? current_slot : start_slot;

  ulong total_slots = final_slot-start_slot;
  ulong completed_slots = current_slot-start_slot;

  double progress = 0.0;
  if( FD_LIKELY( total_slots>0UL ) ) progress = 100.0 * (double)completed_slots / (double)total_slots;
  else progress = 100.0;

  PRINT( "🧪 \033[1m\033[92mBACKTEST....\033[0m\033[22m \033[1mPCT\033[22m %.1f %% (%lu/%lu)\033[K\n", progress, completed_slots, total_slots );
}

static void
write_snapshots( config_t const * config,
                 ulong const *    cur_tile,
                 ulong const *    prev_tile ) {
  ulong snaprd_idx = fd_topo_find_tile( &config->topo, "snaprd", 0UL );
  ulong state = cur_tile[ snaprd_idx*FD_METRICS_TOTAL_SZ+MIDX( GAUGE, SNAPRD, STATE ) ];

  ulong bytes_read = cur_tile[ snaprd_idx*FD_METRICS_TOTAL_SZ+MIDX( GAUGE, SNAPRD, FULL_BYTES_READ ) ];
  ulong bytes_total = cur_tile[ snaprd_idx*FD_METRICS_TOTAL_SZ+MIDX( GAUGE, SNAPRD, FULL_BYTES_TOTAL ) ];

  ulong gossip_fresh_count = cur_tile[ snaprd_idx*FD_METRICS_TOTAL_SZ+MIDX( GAUGE, SNAPRD, GOSSIP_FRESH_COUNT ) ];
  ulong gossip_total_count = cur_tile[ snaprd_idx*FD_METRICS_TOTAL_SZ+MIDX( GAUGE, SNAPRD, GOSSIP_TOTAL_COUNT ) ];

  double progress = 0.0;
  if( FD_LIKELY( bytes_total>0UL ) ) progress = 100.0 * (double)bytes_read / (double)bytes_total;
  else if( FD_LIKELY( gossip_total_count>0UL ) ) progress = 100.0 * (1.0 - (double)gossip_fresh_count / (double)gossip_total_count );
  else progress = 0.0;

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

  ulong snaprd_total_ticks = total_regime( &cur_tile[ snaprd_idx*FD_METRICS_TOTAL_SZ ] )-total_regime( &prev_tile[ snaprd_idx*FD_METRICS_TOTAL_SZ ] );
  ulong snapld_total_ticks = total_regime( &cur_tile[ fd_topo_find_tile( &config->topo, "snapld", 0UL )*FD_METRICS_TOTAL_SZ ] )-total_regime( &prev_tile[ fd_topo_find_tile( &config->topo, "snapld", 0UL )*FD_METRICS_TOTAL_SZ ] );
  ulong snapdc_total_ticks = total_regime( &cur_tile[ fd_topo_find_tile( &config->topo, "snapdc", 0UL )*FD_METRICS_TOTAL_SZ ] )-total_regime( &prev_tile[ fd_topo_find_tile( &config->topo, "snapdc", 0UL )*FD_METRICS_TOTAL_SZ ] );
  ulong snapin_total_ticks = total_regime( &cur_tile[ fd_topo_find_tile( &config->topo, "snapin", 0UL )*FD_METRICS_TOTAL_SZ ] )-total_regime( &prev_tile[ fd_topo_find_tile( &config->topo, "snapin", 0UL )*FD_METRICS_TOTAL_SZ ] );
  snaprd_total_ticks = fd_ulong_max( snaprd_total_ticks, 1UL );
  snapld_total_ticks = fd_ulong_max( snapld_total_ticks, 1UL );
  snapdc_total_ticks = fd_ulong_max( snapdc_total_ticks, 1UL );
  snapin_total_ticks = fd_ulong_max( snapin_total_ticks, 1UL );

  double snaprd_backp_pct = 100.0*(double)diff_tile( config, "snaprd", prev_tile, cur_tile, MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_BACKPRESSURE_PREFRAG ) )/(double)snaprd_total_ticks;
  double snapld_backp_pct = 100.0*(double)diff_tile( config, "snapld", prev_tile, cur_tile, MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_BACKPRESSURE_PREFRAG ) )/(double)snapld_total_ticks;
  double snapdc_backp_pct = 100.0*(double)diff_tile( config, "snapdc", prev_tile, cur_tile, MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_BACKPRESSURE_PREFRAG ) )/(double)snapdc_total_ticks;
  double snapin_backp_pct = 100.0*(double)diff_tile( config, "snapin", prev_tile, cur_tile, MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_BACKPRESSURE_PREFRAG ) )/(double)snapin_total_ticks;

  double snaprd_idle_pct = 100.0*(double)diff_tile( config, "snaprd", prev_tile, cur_tile, MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_CAUGHT_UP_POSTFRAG ) )/(double)snaprd_total_ticks;
  double snapld_idle_pct = 100.0*(double)diff_tile( config, "snapld", prev_tile, cur_tile, MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_CAUGHT_UP_POSTFRAG ) )/(double)snapld_total_ticks;
  double snapdc_idle_pct = 100.0*(double)diff_tile( config, "snapdc", prev_tile, cur_tile, MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_CAUGHT_UP_POSTFRAG ) )/(double)snapdc_total_ticks;
  double snapin_idle_pct = 100.0*(double)diff_tile( config, "snapin", prev_tile, cur_tile, MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_CAUGHT_UP_POSTFRAG ) )/(double)snapin_total_ticks;

  PRINT( "⚡ \033[1m\033[93mSNAPSHOTS...\033[0m\033[22m \033[1mSTATE\033[22m %s \033[1mPCT\033[22m %.1f %% \033[1mRX\033[22m %3.f MB/s \033[1mACC\033[22m %3.1f M/s \033[1mBACKP\033[22m %3.0f%%,%3.0f%%,%3.0f%%,%3.0f%% \033[1mBUSY\033[22m %3.0f%%,%3.0f%%,%3.0f%%,%3.0f%%\033[K\n",
    fd_snaprd_state_str( state ),
    progress,
    megabytes_per_second,
    million_accounts_per_second,
    snaprd_backp_pct,
    snapld_backp_pct,
    snapdc_backp_pct,
    snapin_backp_pct,
    100.0-snaprd_idle_pct-snaprd_backp_pct,
    100.0-snapld_idle_pct-snapld_backp_pct,
    100.0-snapdc_idle_pct-snapdc_backp_pct,
    100.0-snapin_idle_pct-snapin_backp_pct );
}

static uint
write_gossip( config_t const * config,
              ulong const *    cur_tile,
              ulong const *    cur_link,
              ulong const *    prev_link ) {
  ulong gossip_tile_idx = fd_topo_find_tile( &config->topo, "gossip", 0UL );
  if( gossip_tile_idx==ULONG_MAX ) return 0U;
  char * contact_info = COUNT( cur_tile[ gossip_tile_idx*FD_METRICS_TOTAL_SZ+MIDX( GAUGE, GOSSIP, CRDS_COUNT_CONTACT_INFO_V2 ) ] );
  PRINT( "💬 \033[1m\033[34mGOSSIP......\033[0m\033[22m \033[1mRX\033[22m %s \033[1mTX\033[22m %s \033[1mCRDS\033[22m %s \033[1mPEERS\033[22m %s\033[K\n",
    DIFF_LINK_BYTES( "net_gossvf", COUNTER, LINK, CONSUMED_SIZE_BYTES ),
    DIFF_LINK_BYTES( "gossip_net", COUNTER, LINK, CONSUMED_SIZE_BYTES ),
    COUNT( total_crds( &cur_tile[ fd_topo_find_tile( &config->topo, "gossip", 0UL )*FD_METRICS_TOTAL_SZ ] ) ),
    contact_info );
  return 1U;
}

static uint
write_repair( config_t const * config,
              ulong const *    cur_tile,
              ulong const *    cur_link,
              ulong const *    prev_link ) {
  ulong repair_tile_idx = fd_topo_find_tile( &config->topo, "repair", 0UL );
  if( repair_tile_idx==ULONG_MAX ) return 0U;
  ulong repair_slot = cur_tile[ repair_tile_idx*FD_METRICS_TOTAL_SZ+MIDX( COUNTER, REPAIR, REPAIRED_SLOTS ) ];
  ulong turbine_slot = cur_tile[ repair_tile_idx*FD_METRICS_TOTAL_SZ+MIDX( COUNTER, REPAIR, CURRENT_SLOT ) ];
  PRINT( "🧱 \033[1m\033[31mREPAIR......\033[0m\033[22m \033[1mRX\033[22m %s \033[1mTX\033[22m %s \033[1mREPAIR SLOT\033[22m %lu (%ld) \033[1mTURBINE SLOT\033[22m %lu\033[K\n",
    DIFF_LINK_BYTES( "net_repair", COUNTER, LINK, CONSUMED_SIZE_BYTES ),
    DIFF_LINK_BYTES( "repair_net", COUNTER, LINK, CONSUMED_SIZE_BYTES ),
    repair_slot,
    (long)repair_slot-(long)turbine_slot,
    turbine_slot );
  return 1U;
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
    turbine_slot = cur_tile[ repair_tile_idx*FD_METRICS_TOTAL_SZ+MIDX( COUNTER, REPAIR, CURRENT_SLOT ) ];
  } else {
    turbine_slot = reset_slot;
  }

  ulong slot_in_seconds = (ulong)((double)(next_leader_slot-reset_slot)*0.4);
  if( FD_UNLIKELY( leader_slot ) ) FD_TEST( fd_cstr_printf_check( next_leader_slot_str, 64UL, NULL, "now" ) );
  else if( FD_LIKELY( next_leader_slot>0UL ) ) FD_TEST( fd_cstr_printf_check( next_leader_slot_str, 64UL, NULL, "%lum %lus", slot_in_seconds/60UL, slot_in_seconds%60UL ) );
  else FD_TEST( fd_cstr_printf_check( next_leader_slot_str, 64UL, NULL, "never" ) );

  ulong root_distance = cur_tile[ replay_tile_idx*FD_METRICS_TOTAL_SZ+MIDX( GAUGE, REPLAY, ROOT_DISTANCE ) ];
  ulong live_banks    = cur_tile[ replay_tile_idx*FD_METRICS_TOTAL_SZ+MIDX( GAUGE, REPLAY, LIVE_BANKS    ) ];

  ulong sps_sum = 0UL;
  ulong num_sps_samples = fd_ulong_min( sps_samples_idx, sizeof(sps_samples)/sizeof(sps_samples[0]));
  for( ulong i=0UL; i<num_sps_samples; i++ ) sps_sum += sps_samples[ i ];
  char * sps_str = COUNTF( 100.0*(double)sps_sum/(double)num_sps_samples );

  ulong tps_sum = 0UL;
  ulong num_tps_samples = fd_ulong_min( tps_samples_idx, sizeof(tps_samples)/sizeof(tps_samples[0]));
  for( ulong i=0UL; i<num_tps_samples; i++ ) tps_sum += tps_samples[ i ];
  char * tps_str = COUNTF( 100.0*(double)tps_sum/(double)num_tps_samples );

  PRINT( "💥 \033[1m\033[35mREPLAY......\033[0m\033[22m \033[1mSLOT\033[22m %lu (%ld) \033[1mTPS\033[22m %s \033[1mSPS\033[22m %s \033[1mLEADER IN\033[22m %s \033[1mROOT DIST\033[22m %lu \033[1mBANKS\033[22m %lu\033[K\n",
    reset_slot,
    (long)reset_slot-(long)turbine_slot,
    tps_str,
    sps_str,
    next_leader_slot_str,
    root_distance,
    live_banks );
  return 1U;
}

static void
write_summary( config_t const * config,
               ulong const *    cur_tile,
               ulong const *    prev_tile,
               ulong const *    cur_link,
               ulong const *    prev_link ) {
  (void)config;
  (void)prev_tile;
  (void)cur_tile;

  if( FD_UNLIKELY( !ended_on_newline ) ) PRINT( "\n" );
  PRINT( "───────────────\033[K\n" );

  ulong snaprd_idx = fd_topo_find_tile( &config->topo, "snaprd", 0UL );
  int shutdown = 1;
  if( FD_LIKELY( snaprd_idx!=ULONG_MAX ) ) shutdown = cur_tile[ snaprd_idx*FD_METRICS_TOTAL_SZ+MIDX( GAUGE, SNAPRD, STATE ) ]==FD_SNAPRD_STATE_SHUTDOWN;

  static long snap_shutdown_time = 0L;
  if( FD_UNLIKELY( !snap_shutdown_time && !shutdown ) ) snap_shutdown_time = 1L; /* Was not shutdown on boot */
  if( FD_UNLIKELY( !snap_shutdown_time && shutdown  ) ) snap_shutdown_time = 2L; /* Was shutdown on boot */
  if( FD_UNLIKELY( snap_shutdown_time==1L && shutdown  ) ) snap_shutdown_time = fd_log_wallclock();

  lines_printed = 1UL;

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

  lines_printed += write_gossip( config, cur_tile, cur_link, prev_link );
  lines_printed += write_repair( config, cur_tile, cur_link, prev_link );
  lines_printed += write_replay( config, cur_tile );
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

static ulong tiles[ 2UL*128UL*FD_METRICS_TOTAL_SZ ];
static ulong links[ 2UL*4096UL*8UL*FD_METRICS_ALL_LINK_IN_TOTAL ];

static void
run( config_t const * config,
     int              drain_output_fd ) {
  (void)config;
  (void)drain_output_fd;

  ulong tile_cnt = config->topo.tile_cnt;

  ulong cons_cnt = 0UL;
  for( ulong i=0UL; i<config->topo.tile_cnt; i++ ) {
    for( ulong j=0UL; j<config->topo.tiles[ i ].in_cnt; j++ ) {
      if( FD_UNLIKELY( config->topo.tiles[ i ].in_link_poll[ j ] ) ) cons_cnt++;
    }
  }

  FD_TEST( tile_cnt<=128UL );
  FD_TEST( cons_cnt<=4096UL );

  snap_tiles( &config->topo, tiles );
  fd_memcpy( tiles+tile_cnt*FD_METRICS_TOTAL_SZ, tiles, tile_cnt*FD_METRICS_TOTAL_SZ );

  snap_links( &config->topo, links );
  fd_memcpy( links+(cons_cnt*8UL*FD_METRICS_ALL_LINK_IN_TOTAL), links, cons_cnt*8UL*FD_METRICS_ALL_LINK_IN_TOTAL );

  ulong last_snap = 1UL;

  write_summary( config, tiles+last_snap*tile_cnt*FD_METRICS_TOTAL_SZ, tiles+(1UL-last_snap)*tile_cnt*FD_METRICS_TOTAL_SZ, links+last_snap*(cons_cnt*8UL*FD_METRICS_ALL_LINK_IN_TOTAL), links+(1UL-last_snap)*(cons_cnt*8UL*FD_METRICS_ALL_LINK_IN_TOTAL) );

  long next = fd_log_wallclock()+(long)1e9;
  for(;;) {
    if( FD_UNLIKELY( drain_output_fd>=0 ) ) {
      if( FD_UNLIKELY( drain( drain_output_fd ) ) ) write_summary( config, tiles+last_snap*tile_cnt*FD_METRICS_TOTAL_SZ, tiles+(1UL-last_snap)*tile_cnt*FD_METRICS_TOTAL_SZ, links+last_snap*(cons_cnt*8UL*FD_METRICS_ALL_LINK_IN_TOTAL), links+(1UL-last_snap)*(cons_cnt*8UL*FD_METRICS_ALL_LINK_IN_TOTAL) );
    }

    long now = fd_log_wallclock();
    if( FD_UNLIKELY( now>=next ) ) {
      last_snap = 1UL-last_snap;
      snap_tiles( &config->topo, tiles+last_snap*tile_cnt*FD_METRICS_TOTAL_SZ );
      snap_links( &config->topo, links+last_snap*(cons_cnt*8UL*FD_METRICS_ALL_LINK_IN_TOTAL) );

      sps_samples[ sps_samples_idx%(sizeof(sps_samples)/sizeof(sps_samples[0])) ] = (ulong)diff_tile( config, "replay", tiles+(1UL-last_snap)*tile_cnt*FD_METRICS_TOTAL_SZ, tiles+last_snap*tile_cnt*FD_METRICS_TOTAL_SZ, MIDX( COUNTER, REPLAY, SLOTS_TOTAL ) );
      sps_samples_idx++;
      tps_samples[ tps_samples_idx%(sizeof(tps_samples)/sizeof(tps_samples[0])) ] = (ulong)diff_tile( config, "replay", tiles+(1UL-last_snap)*tile_cnt*FD_METRICS_TOTAL_SZ, tiles+last_snap*tile_cnt*FD_METRICS_TOTAL_SZ, MIDX( COUNTER, REPLAY, TRANSACTIONS_TOTAL ) );
      tps_samples_idx++;
      snapshot_rx_samples[ snapshot_rx_idx%(sizeof(snapshot_rx_samples)/sizeof(snapshot_rx_samples[0])) ] = (ulong)diff_tile( config, "snaprd", tiles+(1UL-last_snap)*tile_cnt*FD_METRICS_TOTAL_SZ, tiles+last_snap*tile_cnt*FD_METRICS_TOTAL_SZ, MIDX( GAUGE, SNAPRD, FULL_BYTES_READ ) ) +
                                                                                                            (ulong)diff_tile( config, "snaprd", tiles+(1UL-last_snap)*tile_cnt*FD_METRICS_TOTAL_SZ, tiles+last_snap*tile_cnt*FD_METRICS_TOTAL_SZ, MIDX( GAUGE, SNAPRD, INCREMENTAL_BYTES_READ ) );
      snapshot_rx_idx++;
      snapshot_acc_samples[ snapshot_acc_idx%(sizeof(snapshot_acc_samples)/sizeof(snapshot_acc_samples[0])) ] = (ulong)diff_tile( config, "snapin", tiles+(1UL-last_snap)*tile_cnt*FD_METRICS_TOTAL_SZ, tiles+last_snap*tile_cnt*FD_METRICS_TOTAL_SZ, MIDX( GAUGE, SNAPIN, ACCOUNTS_INSERTED ) );
      snapshot_acc_idx++;

      /* move up n lines, delete n lines, and restore cursor and clear to end of screen */
      char erase[ 128UL ];
      ulong term_len = 0UL;
      if( FD_UNLIKELY( !ended_on_newline ) ) {
        FD_TEST( fd_cstr_printf_check( erase, 128UL, &term_len, "\033[%luA\033[%luM\033[1A\033[0J", lines_printed, lines_printed ) );
      } else {
        FD_TEST( fd_cstr_printf_check( erase, 128UL, &term_len, "\033[%luA\033[%luM\033[0J", lines_printed, lines_printed ) );
      }
      ulong erase_written = 0UL;
      while( erase_written<term_len ) {
        long w = write( STDOUT_FILENO, erase+erase_written, term_len-(ulong)erase_written );
        if( FD_UNLIKELY( -1==w && errno==EAGAIN ) ) continue;
        else if( FD_UNLIKELY( -1==w ) ) FD_LOG_ERR(( "write() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
        erase_written += (ulong)w;
      }

      write_summary( config, tiles+last_snap*tile_cnt*FD_METRICS_TOTAL_SZ, tiles+(1UL-last_snap)*tile_cnt*FD_METRICS_TOTAL_SZ, links+last_snap*(cons_cnt*8UL*FD_METRICS_ALL_LINK_IN_TOTAL), links+(1UL-last_snap)*(cons_cnt*8UL*FD_METRICS_ALL_LINK_IN_TOTAL) );
      next += (long)1e7;
    }
  }
}

void
watch_cmd_fn( args_t *   args,
              config_t * config ) {
  int allow_fds[ 5 ];
  ulong allow_fds_cnt = 0;
  allow_fds[ allow_fds_cnt++ ] = 0; /* stdin */
  allow_fds[ allow_fds_cnt++ ] = 1; /* stdout */
  allow_fds[ allow_fds_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( fd_log_private_logfile_fd()!=-1 ) )
    allow_fds[ allow_fds_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  if( FD_UNLIKELY( args->watch.drain_output_fd!=-1 ) )
    allow_fds[ allow_fds_cnt++ ] = args->watch.drain_output_fd; /* maybe we are interposing firedancer log output with the monitor */

  fd_topo_join_workspaces( &config->topo, FD_SHMEM_JOIN_MODE_READ_ONLY );

  struct sock_filter seccomp_filter[ 128UL ];
  uint drain_output_fd = args->watch.drain_output_fd >= 0 ? (uint)args->watch.drain_output_fd : (uint)-1;
  populate_sock_filter_policy_watch( 128UL, seccomp_filter, (uint)fd_log_private_logfile_fd(), drain_output_fd );

  if( FD_LIKELY( config->development.sandbox ) ) {
    if( FD_UNLIKELY( close( config->log.lock_fd ) ) ) FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

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
                      allow_fds_cnt,
                      allow_fds,
                      sock_filter_policy_watch_instr_cnt,
                      seccomp_filter );
  } else {
    fd_sandbox_switch_uid_gid( config->uid, config->gid );
  }

  fd_topo_fill( &config->topo );

  run( config, args->watch.drain_output_fd );
}

action_t fd_action_watch = {
  .name           = "watch",
  .args           = NULL,
  .fn             = watch_cmd_fn,
  .require_config = 1,
  .perm           = watch_cmd_perm,
  .description    = "Watch a locally running Firedancer instance with a terminal GUI",
};
