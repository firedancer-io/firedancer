#define _GNU_SOURCE

#include "fd_diag_tile.h"

#include "../bundle/fd_bundle_tile.h"
#include "../metrics/fd_metrics.h"
#include "../stem/fd_stem.h"
#include "../topo/fd_topo.h"
#include "../topo/fd_cpu_topo.h"
#include "../../util/tile/fd_tile_private.h"
#include "../../util/io/fd_io.h"

#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/types.h> /* SEEK_SET */
#include <sys/stat.h>
#include <sys/vfs.h>
#include <time.h>
#include <unistd.h>

#include "fd_proc_interrupts.h"
#include "generated/fd_diag_tile_seccomp.h"

#define REPORT_INTERVAL_MILLIS (100L)
#define SYSTEM_REPORT_INTERVAL_NANOS (30000000000L)

#define DIAG_WKSP_TILE_IDX_SHARED (ULONG_MAX)


struct fd_diag_tile {
  long next_report_nanos;

  ulong tile_cnt;
  int is_voting;

  struct {
    ulong bundle_tile_idx[ FD_TILE_MAX ];
    ulong bundle_cnt;
    ulong shred_tile_idx[ FD_TILE_MAX ];
    ulong shred_cnt;
    ulong tower_idx;
    ulong votor_idx;
    ulong replay_idx;
  } tiles;

  ulong starttime_nanos[ FD_TILE_MAX ];
  long  first_seen_died[ FD_TILE_MAX ];

  int stat_fds[ FD_TILE_MAX ];
  int sched_fds[ FD_TILE_MAX ];

  ulong       irq_cnt[ FD_METRICS_ENUM_SOFTIRQ_CNT ][ FD_TILE_MAX ];
  fd_cpuset_t cpu_has_tile[ fd_cpuset_word_cnt ];
  int         proc_interrupts_fd;
  int         proc_softirqs_fd;
  int         proc_stat_fd;
  int         proc_meminfo_fd;
  ulong       device_irq_baseline[ FD_TILE_MAX ];
  ulong       tlb_baseline[ FD_TILE_MAX ];
  ulong       loc_baseline[ FD_TILE_MAX ];
  ulong       irq_ticks_baseline[ FD_TILE_MAX ];
  ulong       softirq_baseline[ FD_METRICS_ENUM_SOFTIRQ_CNT ][ FD_TILE_MAX ];

  ulong volatile * metrics    [ FD_TILE_MAX ];
  ushort           cpu_to_tile[ FD_TILE_MAX ];

  int    gui_enabled;
  long   next_system_report_nanos;
  ushort numa_entry_idx[ FD_DIAG_SYSTEM_TILE_MAX ][ FD_DIAG_SYSTEM_NUMA_MAX ];
  struct {
    ulong cnt;
    struct {
      char  name[ FD_SHMEM_NAME_MAX ];
      ulong tile_idx;
      ulong numa_idx;
      ulong bytes;
      ushort numa_slot;
    } wksp[ FD_TOPO_MAX_WKSPS ];
    ushort stack_numa_slot[ FD_DIAG_SYSTEM_TILE_MAX ];
  } memory;
  struct {
    ulong cnt;
    struct {
      ushort idx;
      int    meminfo_fd;
    } node[ FD_DIAG_SYSTEM_NUMA_MAX ];
  } numa;

  struct {
    void * mem;
    ulong  idx;
    ulong  chunk0;
    ulong  wmark;
    ulong  chunk;
  } system_out;
  fd_diag_system_resources_t system_resources;

  struct {
    int   fd;     /* O_PATH reference to an anonymous regular file */
    ulong mnt_id; /* mount ID from /proc/self/fdinfo */
    char  path[ PATH_MAX ];
  } mounts[ FD_DIAG_SYSTEM_FILE_MAX ];
  ulong mount_cnt;

  struct {
    char  path[ PATH_MAX ];
    uint  category;
    uint  mount_idx;
    int   data_fd;
    ulong volatile * metric;
  } files[ FD_DIAG_SYSTEM_FILE_MAX ];
  ulong file_cnt;

  struct {
    ulong prev_vote_slot;
    long  vote_slot_changed_ns;
    ulong prev_reset_slot;
    long  reset_slot_changed_ns;
    ulong prev_turbine_slot;
    long  turbine_slot_changed_ns;

    ulong snapshot_turbine_bytes;
    ulong snapshot_repair_bytes;
    long  byte_snapshot_ns;
    int   repair_outpacing;
  } check_engine;
};

typedef struct fd_diag_tile fd_diag_tile_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return alignof(fd_diag_tile_t);
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  return sizeof(fd_diag_tile_t);
}

static int
read_stat_file( int              fd,
                ulong            ns_per_tick,
                volatile ulong * metrics ) {
  if( FD_UNLIKELY( -1==lseek( fd, 0, SEEK_SET ) ) ) FD_LOG_ERR(( "lseek failed (%i-%s)", errno, strerror( errno ) ));

  char contents[ 4096 ] = {0};
  ulong contents_len = 0UL;

  while( 1 ) {
    if( FD_UNLIKELY( contents_len>=sizeof( contents ) ) ) FD_LOG_ERR(( "stat contents overflow" ));
    long n = read( fd, contents + contents_len, sizeof( contents ) - contents_len );
    if( FD_UNLIKELY( -1==n ) ) {
      if( FD_UNLIKELY( errno==ESRCH ) ) return 1;
      FD_LOG_ERR(( "read failed (%i-%s)", errno, strerror( errno ) ));
    }
    if( FD_LIKELY( 0==n ) ) break;
    contents_len += (ulong)n;
  }

  /* Parse stat file: fields are space-separated.
     Field 10 (1-indexed) = minflt, field 12 = majflt,
     field 14 = utime, field 15 = stime (all in clock ticks). */
  char * saveptr;
  char * token = strtok_r( contents, " ", &saveptr );
  ulong field_idx = 0UL;

  while( token ) {
    if( FD_UNLIKELY( 9UL==field_idx ) ) {
      char * endptr;
      ulong minflt = strtoul( token, &endptr, 10 );
      if( FD_UNLIKELY( *endptr!='\0' || minflt==ULONG_MAX ) ) FD_LOG_ERR(( "strtoul failed for minflt" ));
      metrics[ FD_METRICS_COUNTER_TILE_PAGE_FAULT_MINOR_OFF ] = minflt;
    } else if( FD_UNLIKELY( 11UL==field_idx ) ) {
      char * endptr;
      ulong majflt = strtoul( token, &endptr, 10 );
      if( FD_UNLIKELY( *endptr!='\0' || majflt==ULONG_MAX ) ) FD_LOG_ERR(( "strtoul failed for majflt" ));
      metrics[ FD_METRICS_COUNTER_TILE_PAGE_FAULT_MAJOR_OFF ] = majflt;
    } else if( FD_UNLIKELY( 13UL==field_idx ) ) {
      char * endptr;
      ulong utime_ticks = strtoul( token, &endptr, 10 );
      if( FD_UNLIKELY( *endptr!='\0' || utime_ticks==ULONG_MAX ) ) FD_LOG_ERR(( "strtoul failed for utime" ));
      metrics[ FD_METRICS_COUNTER_TILE_CPU_DURATION_NANOS_USER_OFF ] = utime_ticks*ns_per_tick;
    } else if( FD_UNLIKELY( 14UL==field_idx ) ) {
      char * endptr;
      ulong stime_ticks = strtoul( token, &endptr, 10 );
      if( FD_UNLIKELY( *endptr!='\0' || stime_ticks==ULONG_MAX ) ) FD_LOG_ERR(( "strtoul failed for stime" ));
      metrics[ FD_METRICS_COUNTER_TILE_CPU_DURATION_NANOS_SYSTEM_OFF ] = stime_ticks*ns_per_tick;
    } else if( FD_UNLIKELY( 38UL==field_idx ) ) {
      char * endptr;
      ulong last_cpu = strtoul( token, &endptr, 10 );
      if( FD_UNLIKELY( *endptr!='\0' || last_cpu==ULONG_MAX ) ) FD_LOG_ERR(( "strtoul failed for processor" ));
      metrics[ FD_METRICS_GAUGE_TILE_LAST_CPU_OFF ] = last_cpu;
      break; /* No need to parse stat further */
    }
    token = strtok_r( NULL, " ", &saveptr );
    field_idx++;
  }

  if( FD_UNLIKELY( field_idx!=38UL ) ) FD_LOG_ERR(( "failed to parse /proc/<pid>/task/<tid>/stat" ));

  return 0;
}

static int
read_sched_file( int              fd,
                 volatile ulong * metrics ) {
  if( FD_UNLIKELY( -1==lseek( fd, 0, SEEK_SET ) ) ) FD_LOG_ERR(( "lseek failed (%i-%s)", errno, strerror( errno ) ));

  char contents[ 8192 ] = {0};
  ulong contents_len = 0UL;

  while( 1 ) {
    if( FD_UNLIKELY( contents_len>=sizeof( contents ) ) ) FD_LOG_ERR(( "sched contents overflow" ));
    long n = read( fd, contents + contents_len, sizeof( contents ) - contents_len );
    if( FD_UNLIKELY( -1==n ) ) {
      if( FD_UNLIKELY( errno==ESRCH ) ) return 1;
      FD_LOG_ERR(( "read failed (%i-%s)", errno, strerror( errno ) ));
    }
    if( FD_LIKELY( 0==n ) ) break;
    contents_len += (ulong)n;
  }

  int found_wait_sum = 0;
  int found_voluntary = 0;
  int found_involuntary = 0;

  char * line = contents;
  while( 1 ) {
    char * next_line = strchr( line, '\n' );
    if( FD_UNLIKELY( NULL==next_line ) ) break;
    *next_line = '\0';

    if( FD_UNLIKELY( !strncmp( line, "wait_sum", 8UL ) ) ) {
      char * colon = strchr( line, ':' );
      if( FD_LIKELY( colon ) ) {
        char * value = colon + 1;
        while( ' '==*value || '\t'==*value ) value++;
        /* wait_sum is displayed as seconds.microseconds (e.g., "123.456789").
           Parse both components as integers and convert to nanoseconds. */
        char * endptr;
        ulong seconds = strtoul( value, &endptr, 10 );
        if( FD_UNLIKELY( '.'!=*endptr ) ) FD_LOG_ERR(( "expected '.' after seconds in wait_sum" ));
        if( FD_UNLIKELY( seconds==ULONG_MAX ) ) FD_LOG_ERR(( "strtoul overflow for wait_sum seconds" ));
        ulong microseconds = strtoul( endptr + 1, &endptr, 10 );
        if( FD_UNLIKELY( '\0'!=*endptr ) ) FD_LOG_ERR(( "unexpected char after microseconds in wait_sum" ));
        if( FD_UNLIKELY( microseconds==ULONG_MAX ) ) FD_LOG_ERR(( "strtoul overflow for wait_sum microseconds" ));
        ulong wait_sum_ns = seconds*1000000000UL + microseconds*1000UL;
        metrics[ FD_METRICS_COUNTER_TILE_CPU_DURATION_NANOS_WAIT_OFF ] = wait_sum_ns;
        found_wait_sum = 1;
      }
    } else if( FD_UNLIKELY( !strncmp( line, "nr_voluntary_switches", 21UL ) ) ) {
      char * colon = strchr( line, ':' );
      if( FD_LIKELY( colon ) ) {
        char * value = colon + 1;
        while( ' '==*value || '\t'==*value ) value++;
        char * endptr;
        ulong voluntary_switches = strtoul( value, &endptr, 10 );
        if( FD_UNLIKELY( '\0'!=*endptr ) ) FD_LOG_ERR(( "unexpected char after nr_voluntary_switches" ));
        if( FD_UNLIKELY( voluntary_switches==ULONG_MAX ) ) FD_LOG_ERR(( "strtoul overflow for nr_voluntary_switches" ));
        metrics[ FD_METRICS_COUNTER_TILE_CONTEXT_SWITCH_VOLUNTARY_OFF ] = voluntary_switches;
        found_voluntary = 1;
      }
    } else if( FD_UNLIKELY( !strncmp( line, "nr_involuntary_switches", 23UL ) ) ) {
      char * colon = strchr( line, ':' );
      if( FD_LIKELY( colon ) ) {
        char * value = colon + 1;
        while( ' '==*value || '\t'==*value ) value++;
        char * endptr;
        ulong involuntary_switches = strtoul( value, &endptr, 10 );
        if( FD_UNLIKELY( '\0'!=*endptr ) ) FD_LOG_ERR(( "unexpected char after nr_involuntary_switches" ));
        if( FD_UNLIKELY( involuntary_switches==ULONG_MAX ) ) FD_LOG_ERR(( "strtoul overflow for nr_involuntary_switches" ));
        metrics[ FD_METRICS_COUNTER_TILE_CONTEXT_SWITCH_INVOLUNTARY_OFF ] = involuntary_switches;
        found_involuntary = 1;
      }
    }

    line = next_line + 1;
  }

  // wait_sum not present on kernels compiled without CONFIG_SCHEDSTATS=y
  // if( FD_UNLIKELY( !found_wait_sum ) ) FD_LOG_ERR(( "wait_sum not found in sched file" ));
  (void)found_wait_sum;
  if( FD_UNLIKELY( !found_voluntary ) ) FD_LOG_ERR(( "nr_voluntary_switches not found in sched file" ));
  if( FD_UNLIKELY( !found_involuntary ) ) FD_LOG_ERR(( "nr_involuntary_switches not found in sched file" ));

  return 0;
}

static void
check_engine_metric( fd_diag_tile_t * ctx, long now ) {
  static ulong const vote_distance_threshold    = 150UL;
  static long  const vote_stall_threshold_ns    = 60L*1000L*1000L*1000L;
  static ulong const replay_distance_threshold  = 12UL;
  static long  const replay_stall_threshold_ns  = 12L*1000L*1000L*1000L;
  static long  const turbine_stall_threshold_ns = 12L*1000L*1000L*1000L;
  static long  const turbine_byte_cmp_window_ns = 12L*1000L*1000L*1000L;

  ulong bundle_cnt    = ctx->tiles.bundle_cnt;
  ulong bundle_status = FD_DIAG_BUNDLE_STATUS_DISABLED;
  if( FD_LIKELY( bundle_cnt ) ) {
    /* Find the best state across all bundle tiles.
       Priority: connected > sleeping > connecting > disconnected */
    int any_connected  = 0;
    int any_sleeping   = 0;
    int any_connecting = 0;
    for( ulong i=0UL; i<bundle_cnt; i++ ) {
      volatile ulong * m = ctx->metrics[ ctx->tiles.bundle_tile_idx[ i ] ];
      ulong state = m[ FD_METRICS_GAUGE_BUNDLE_STATE_OFF ];
      if( FD_LIKELY( state==FD_BUNDLE_STATE_CONNECTED ) ) any_connected  = 1;
      else if( state==FD_BUNDLE_STATE_SLEEPING )          any_sleeping   = 1;
      else if( state==FD_BUNDLE_STATE_CONNECTING )        any_connecting = 1;
    }
    if(      any_connected  ) bundle_status = FD_DIAG_BUNDLE_STATUS_CONNECTED;
    else if( any_sleeping   ) bundle_status = FD_DIAG_BUNDLE_STATUS_SLEEPING;
    else if( any_connecting ) bundle_status = FD_DIAG_BUNDLE_STATUS_CONNECTING;
    else                      bundle_status = FD_DIAG_BUNDLE_STATUS_DISCONNECTED;
  }

  ulong tower_idx   = ctx->tiles.tower_idx;
  ulong votor_idx   = ctx->tiles.votor_idx;
  ulong vote_status = FD_DIAG_VOTE_STATUS_DISABLED;

  if( FD_UNLIKELY( ctx->is_voting && votor_idx!=ULONG_MAX ) ) {
    ulong replay_idx_ag = ctx->tiles.replay_idx;
    if( FD_UNLIKELY( ctx->metrics[ votor_idx ][ FD_METRICS_GAUGE_TILE_STATUS_OFF ]!=1UL || replay_idx_ag==ULONG_MAX ) ) {
      vote_status = FD_DIAG_VOTE_STATUS_NOT_STARTED;
    } else {
      volatile ulong * m = ctx->metrics[ replay_idx_ag ];
      ulong vote_slot    = m[ FD_METRICS_GAUGE_REPLAY_VOTE_SLOT_LAST_REWARDED_OFF ];
      ulong replay_slot  = m[ FD_METRICS_GAUGE_REPLAY_RESET_SLOT_OFF ];
      if( FD_UNLIKELY( vote_slot==ULONG_MAX || !replay_slot ) ) {
        vote_status = FD_DIAG_VOTE_STATUS_NOT_STARTED;
      } else {
        int current = fd_int_if( replay_slot>=128UL, vote_slot+128UL>replay_slot, vote_slot>0UL );
        vote_status = fd_ulong_if( current, FD_DIAG_VOTE_STATUS_VOTING, FD_DIAG_VOTE_STATUS_DELINQUENT );
      }
    }
  } else if( FD_LIKELY( ctx->is_voting && tower_idx!=ULONG_MAX ) ) {
    if( FD_UNLIKELY( ctx->metrics[ tower_idx ][ FD_METRICS_GAUGE_TILE_STATUS_OFF ]!=1UL ) ) {
      vote_status = FD_DIAG_VOTE_STATUS_NOT_STARTED;
    } else {
      volatile ulong * m = ctx->metrics[ tower_idx ];
      ulong vote_slot    = m[ FD_METRICS_GAUGE_TOWER_VOTE_SLOT_OFF ];
      ulong replay_slot  = m[ FD_METRICS_GAUGE_TOWER_REPLAY_SLOT_OFF ];
      if( FD_UNLIKELY( vote_slot==ULONG_MAX || replay_slot==0UL ) ) {
        vote_status = FD_DIAG_VOTE_STATUS_NOT_STARTED;
      } else {
        if( FD_UNLIKELY( vote_slot!=ctx->check_engine.prev_vote_slot ) ) {
          ctx->check_engine.prev_vote_slot       = vote_slot;
          ctx->check_engine.vote_slot_changed_ns = now;
        }
        int delinquent = (replay_slot>vote_slot && replay_slot-vote_slot>vote_distance_threshold) ||
                         (now-ctx->check_engine.vote_slot_changed_ns>vote_stall_threshold_ns);
        vote_status = fd_ulong_if( delinquent,
                                   FD_DIAG_VOTE_STATUS_DELINQUENT,
                                   FD_DIAG_VOTE_STATUS_VOTING );
      }
    }
  }

  ulong replay_idx     = ctx->tiles.replay_idx;
  int   replay_running = replay_idx!=ULONG_MAX && ctx->metrics[ replay_idx ][ FD_METRICS_GAUGE_TILE_STATUS_OFF ]==1UL;
  ulong replay_status  = FD_DIAG_REPLAY_STATUS_DISABLED;
  if( FD_LIKELY( replay_idx!=ULONG_MAX ) ) {
    if( FD_UNLIKELY( !replay_running ) ) {
      replay_status = FD_DIAG_REPLAY_STATUS_NOT_STARTED;
    } else {
      volatile ulong * m = ctx->metrics[ replay_idx ];
      ulong turbine_slot = m[ FD_METRICS_GAUGE_REPLAY_REASSEMBLY_LATEST_SLOT_OFF ];
      ulong reset_slot   = m[ FD_METRICS_GAUGE_REPLAY_RESET_SLOT_OFF ];
      if( FD_UNLIKELY( reset_slot!=ctx->check_engine.prev_reset_slot ) ) {
        ctx->check_engine.prev_reset_slot       = reset_slot;
        ctx->check_engine.reset_slot_changed_ns = now;
      }
      if( FD_UNLIKELY( (turbine_slot==0UL) || (reset_slot==0UL) ) ) {
        replay_status = FD_DIAG_REPLAY_STATUS_NOT_STARTED;
      } else if( FD_UNLIKELY( ((turbine_slot>reset_slot) && (turbine_slot-reset_slot>replay_distance_threshold)) ||
                               (now-ctx->check_engine.reset_slot_changed_ns>replay_stall_threshold_ns) ) ) {
        replay_status = FD_DIAG_REPLAY_STATUS_BEHIND;
      } else {
        replay_status = FD_DIAG_REPLAY_STATUS_RUNNING;
      }
    }
  }

  ulong shred_cnt      = ctx->tiles.shred_cnt;
  ulong turbine_status = FD_DIAG_TURBINE_STATUS_DISABLED;
  if( FD_LIKELY( replay_idx!=ULONG_MAX && shred_cnt>0UL ) ) {
    if( FD_UNLIKELY( !replay_running ) ) {
      turbine_status = FD_DIAG_TURBINE_STATUS_NOT_STARTED;
    } else {
      int all_shred_running = 1;
      ulong cur_turbine_bytes = 0UL, cur_repair_bytes = 0UL;
      for( ulong i=0UL; i<shred_cnt; i++ ) {
        volatile ulong * sm = ctx->metrics[ ctx->tiles.shred_tile_idx[ i ] ];
        cur_turbine_bytes += sm[ FD_METRICS_COUNTER_SHRED_SHRED_TURBINE_RX_BYTES_OFF ];
        cur_repair_bytes  += sm[ FD_METRICS_COUNTER_SHRED_SHRED_REPAIR_RX_BYTES_OFF ];
        if( FD_UNLIKELY( sm[ FD_METRICS_GAUGE_TILE_STATUS_OFF ]!=1UL ) ) {
          all_shred_running = 0;
          break;
        }
      }
      if( FD_UNLIKELY( !all_shred_running ) ) {
        turbine_status = FD_DIAG_TURBINE_STATUS_NOT_STARTED;
      } else {
        ulong turbine_slot = ctx->metrics[ replay_idx ][ FD_METRICS_GAUGE_REPLAY_REASSEMBLY_LATEST_SLOT_OFF ];
        if( FD_UNLIKELY( turbine_slot!=ctx->check_engine.prev_turbine_slot ) ) {
          ctx->check_engine.prev_turbine_slot       = turbine_slot;
          ctx->check_engine.turbine_slot_changed_ns = now;
        }
        if( FD_UNLIKELY( now-ctx->check_engine.byte_snapshot_ns>=turbine_byte_cmp_window_ns ) ) {
          ctx->check_engine.repair_outpacing       = (cur_repair_bytes-ctx->check_engine.snapshot_repair_bytes)>(cur_turbine_bytes-ctx->check_engine.snapshot_turbine_bytes);
          ctx->check_engine.snapshot_turbine_bytes = cur_turbine_bytes;
          ctx->check_engine.snapshot_repair_bytes  = cur_repair_bytes;
          ctx->check_engine.byte_snapshot_ns       = now;
        }

        if( FD_UNLIKELY( turbine_slot==0UL ) ) {
          turbine_status = FD_DIAG_TURBINE_STATUS_NOT_STARTED;
        } else if( FD_UNLIKELY( now-ctx->check_engine.turbine_slot_changed_ns>turbine_stall_threshold_ns ) ) {
          turbine_status = FD_DIAG_TURBINE_STATUS_STALLED;
        } else if( FD_UNLIKELY( ctx->check_engine.repair_outpacing ) ) {
          turbine_status = FD_DIAG_TURBINE_STATUS_REPAIR_OUTPACING;
        } else {
          turbine_status = FD_DIAG_TURBINE_STATUS_RUNNING;
        }
      }
    }
  }

  FD_MGAUGE_SET( DIAG, BUNDLE_STATUS,  bundle_status  );
  FD_MGAUGE_SET( DIAG, VOTE_STATUS,    vote_status    );
  FD_MGAUGE_SET( DIAG, REPLAY_STATUS,  replay_status  );
  FD_MGAUGE_SET( DIAG, TURBINE_STATUS, turbine_status );
}

static void
irq_metrics( fd_diag_tile_t * ctx ) {
  if( FD_UNLIKELY( -1==lseek( ctx->proc_softirqs_fd, 0, SEEK_SET ) ) ) FD_LOG_ERR(( "lseek failed (%i-%s)", errno, strerror( errno ) ));
  ulong softirq_cpu_cnt = fd_proc_softirqs_sum( ctx->proc_softirqs_fd, ctx->irq_cnt );
  if( FD_UNLIKELY( !softirq_cpu_cnt ) ) return; /* parse fail */

  ulong volatile * softirq_total     = &fd_metrics_tl[ MIDX( COUNTER, DIAG, SOFTIRQ     ) ];
  ulong volatile * softirq_undesired = &fd_metrics_tl[ MIDX( COUNTER, DIAG, SOFTIRQ_UNDESIRED ) ];
  for( ulong j=0UL; j<FD_METRICS_ENUM_SOFTIRQ_CNT; j++ ) {
    ulong tot_cnt       = 0UL;
    ulong undesired_cnt = 0UL;
    for( ulong i=0UL; i<softirq_cpu_cnt; i++ ) {
      ulong since = fd_ulong_sat_sub( ctx->irq_cnt[ j ][ i ], ctx->softirq_baseline[ j ][ i ] );
      tot_cnt += since;
      if( fd_cpuset_test( ctx->cpu_has_tile, i ) ) {
        undesired_cnt += since;
      }
    }
    softirq_total    [ j ] = tot_cnt;
    softirq_undesired[ j ] = undesired_cnt;
  }

  ulong * cpu_irq = ctx->irq_cnt[ 0 ]; /* re-use as scratch memory */
  ulong * cpu_tlb = ctx->irq_cnt[ 1 ];
  ulong * cpu_loc = ctx->irq_cnt[ 2 ];
  if( FD_UNLIKELY( -1==lseek( ctx->proc_interrupts_fd, 0, SEEK_SET ) ) ) FD_LOG_ERR(( "lseek failed (%i-%s)", errno, strerror( errno ) ));
  ulong cpu_cnt = fd_proc_interrupts_read( ctx->proc_interrupts_fd, cpu_irq, cpu_tlb, cpu_loc );
  if( FD_UNLIKELY( !cpu_cnt ) ) return; /* parse fail */

  ulong tot_cnt       = 0UL;
  ulong undesired_cnt = 0UL;
  for( ulong i=0UL; i<cpu_cnt; i++ ) {
    ulong since = fd_ulong_sat_sub( cpu_irq[ i ], ctx->device_irq_baseline[ i ] );
    tot_cnt += since;
    if( fd_cpuset_test( ctx->cpu_has_tile, i ) ) {
      undesired_cnt += since;
    }
    ulong tile_id = ctx->cpu_to_tile[ i ];
    if( tile_id!=USHORT_MAX ) {
      ctx->metrics[ tile_id ][ FD_METRICS_COUNTER_TILE_IRQ_PREEMPTED_OFF ] = since;
    }
  }
  FD_MCNT_SET( DIAG, DEVICE_IRQ,           tot_cnt       );
  FD_MCNT_SET( DIAG, DEVICE_IRQ_UNDESIRED, undesired_cnt );

  for( ulong i=0UL; i<cpu_cnt; i++ ) {
    ulong tile_id = ctx->cpu_to_tile[ i ];
    if( tile_id!=USHORT_MAX ) {
      ulong since = fd_ulong_sat_sub( cpu_tlb[ i ], ctx->tlb_baseline[ i ] );
      ctx->metrics[ tile_id ][ FD_METRICS_COUNTER_TILE_TLB_SHOOTDOWN_OFF ] = since;
    }
  }

  for( ulong i=0UL; i<cpu_cnt; i++ ) {
    ulong tile_id = ctx->cpu_to_tile[ i ];
    if( tile_id!=USHORT_MAX ) {
      ulong since = fd_ulong_sat_sub( cpu_loc[ i ], ctx->loc_baseline[ i ] );
      ctx->metrics[ tile_id ][ FD_METRICS_COUNTER_TILE_TIMER_TICK_OFF ] = since;
    }
  }
}

/* interrupt_metrics reads per-CPU irq+softirq+steal tick counts from
   /proc/stat and publishes them as the INTERRUPT CPU regime for
   fixed tiles.  On kernels with CONFIG_IRQ_TIME_ACCOUNTING (near
   universal), these buckets are disjoint from utime/stime so
     idle = lifetime - user - system - wait - interrupt
   is exact up to sampling granularity; without it, the irq columns
   undercount and interrupt reads near zero (degrades gracefully). */

static void
interrupt_metrics( fd_diag_tile_t * ctx ) {
  ulong cpu_ticks[ FD_TILE_MAX ];
  if( FD_UNLIKELY( -1==lseek( ctx->proc_stat_fd, 0, SEEK_SET ) ) ) FD_LOG_ERR(( "lseek failed (%i-%s)", errno, strerror( errno ) ));
  ulong cpu_cnt = fd_proc_stat_irq_ticks( ctx->proc_stat_fd, cpu_ticks );
  if( FD_UNLIKELY( !cpu_cnt ) ) return; /* parse fail */

  for( ulong i=0UL; i<cpu_cnt; i++ ) {
    ulong tile_id = ctx->cpu_to_tile[ i ];
    if( tile_id!=USHORT_MAX ) {
      /* CLK_TCK is always 100, so 1 tick = 10ms = 10,000,000 ns */
      ulong since = fd_ulong_sat_sub( cpu_ticks[ i ], ctx->irq_ticks_baseline[ i ] );
      ctx->metrics[ tile_id ][ FD_METRICS_COUNTER_TILE_CPU_DURATION_NANOS_INTERRUPT_OFF ] = since*10000000UL;
    }
  }
}

static ulong
read_text( int    fd,
           char * buf,
           ulong  buf_sz ) {
  if( FD_UNLIKELY( -1==lseek( fd, 0, SEEK_SET ) ) ) FD_LOG_ERR(( "lseek failed (%i-%s)", errno, strerror( errno ) ));
  ulong len;
  int err = fd_io_read( fd, buf, buf_sz-1UL, buf_sz-1UL, &len );
  if( FD_UNLIKELY( err>0 ) ) FD_LOG_ERR(( "fd_io_read failed (%i-%s)", err, fd_io_strerror( err ) ));
  buf[ len ] = '\0';
  return len;
}

static void
add_numa_bytes( fd_diag_tile_t * ctx,
                ulong            tile_idx,
                ulong            numa_slot,
                ulong            bytes ) {
  if( FD_UNLIKELY( tile_idx==DIAG_WKSP_TILE_IDX_SHARED ) ) {
    ctx->system_resources.numa_mem[ numa_slot ].shared_bytes += bytes;
    return;
  }

  ushort * entry_idx = &ctx->numa_entry_idx[ tile_idx ][ numa_slot ];
  if( FD_UNLIKELY( *entry_idx==USHORT_MAX ) ) {
    FD_TEST( ctx->system_resources.tile_mem_cnt<FD_DIAG_SYSTEM_TILE_MEM_MAX );
    *entry_idx = (ushort)ctx->system_resources.tile_mem_cnt++;
    fd_diag_system_tile_mem_t * entry = &ctx->system_resources.tile_mem[ *entry_idx ];
    entry->tile_idx = (ushort)tile_idx;
    entry->numa_idx = ctx->numa.node[ numa_slot ].idx;
  }
  ctx->system_resources.tile_mem[ *entry_idx ].allocated_bytes += bytes;
}

static void
add_configured_memory_bytes( fd_diag_tile_t * ctx ) {
  /* Workspaces and tile stacks are hugetlbfs-backed, so their configured
     sizes are also their resident physical-memory footprint. */
  for( ulong i=0UL; i<ctx->memory.cnt; i++ ) {
    if( FD_UNLIKELY( ctx->memory.wksp[ i ].numa_slot==USHORT_MAX ) ) continue;
    add_numa_bytes( ctx,
                    ctx->memory.wksp[ i ].tile_idx,
                    ctx->memory.wksp[ i ].numa_slot,
                    ctx->memory.wksp[ i ].bytes );
  }
  for( ulong tile_idx=0UL; tile_idx<ctx->tile_cnt; tile_idx++ ) {
    ushort numa_slot = ctx->memory.stack_numa_slot[ tile_idx ];
    if( FD_UNLIKELY( numa_slot==USHORT_MAX ) ) continue;
    add_numa_bytes( ctx, tile_idx, numa_slot, FD_TILE_PRIVATE_STACK_SZ );
  }
}

static void
sample_disk( fd_diag_tile_t * ctx ) {
  ctx->system_resources.mount_cnt = (uint)ctx->mount_cnt;
  ctx->system_resources.file_cnt  = (uint)ctx->file_cnt;

  for( ulong i=0UL; i<ctx->mount_cnt; i++ ) {
    struct statfs st;
    if( FD_UNLIKELY( fstatfs( ctx->mounts[ i ].fd, &st ) ) ) FD_LOG_ERR(( "fstatfs failed (%i-%s)", errno, strerror( errno ) ));
    ulong block_sz = (ulong)( st.f_frsize ? st.f_frsize : st.f_bsize );
    fd_diag_system_mount_t * mount = &ctx->system_resources.mount[ i ];
    fd_cstr_ncpy( mount->path, ctx->mounts[ i ].path, sizeof(mount->path) );
    mount->total_bytes     = (ulong)st.f_blocks*block_sz;
    mount->free_bytes      = (ulong)st.f_bfree *block_sz;
    mount->available_bytes = (ulong)st.f_bavail*block_sz;
  }

  for( ulong i=0UL; i<ctx->file_cnt; i++ ) {
    fd_diag_system_file_t * file = &ctx->system_resources.file[ i ];
    fd_cstr_ncpy( file->path, ctx->files[ i ].path, sizeof(file->path) );
    file->category  = ctx->files[ i ].category;
    file->mount_idx = ctx->files[ i ].mount_idx;
    if( ctx->files[ i ].metric ) file->bytes = *ctx->files[ i ].metric;
    else if( ctx->files[ i ].data_fd>=0 ) {
      struct stat st;
      if( FD_UNLIKELY( fstat( ctx->files[ i ].data_fd, &st ) ) ) FD_LOG_ERR(( "fstat failed (%i-%s)", errno, strerror( errno ) ));
      file->bytes = (ulong)st.st_size;
    }
  }
}

static ulong
read_meminfo_kib( char const * buf,
                  char const * key ) {
  char const * p = strstr( buf, key );
  if( FD_UNLIKELY( !p ) ) return 0UL;
  p += strlen( key );
  while( *p==' ' || *p=='\t' || *p==':' ) p++;
  return strtoul( p, NULL, 10 );
}

static void
sample_system( fd_diag_tile_t * ctx,
               long             now ) {
  ctx->next_system_report_nanos = now + SYSTEM_REPORT_INTERVAL_NANOS;

  ctx->system_resources.mem_available_bytes = 0UL;
  ctx->system_resources.mem_free_bytes      = 0UL;
  ctx->system_resources.numa_mem_cnt         = (uint)ctx->numa.cnt;
  ctx->system_resources.tile_mem_cnt         = 0U;
  ctx->system_resources.mount_cnt            = 0U;
  ctx->system_resources.file_cnt             = 0U;
  fd_memset( ctx->system_resources.numa_mem, 0, sizeof(ctx->system_resources.numa_mem) );
  fd_memset( ctx->system_resources.tile_mem, 0, sizeof(ctx->system_resources.tile_mem) );
  fd_memset( ctx->system_resources.mount,    0, sizeof(ctx->system_resources.mount)    );
  fd_memset( ctx->system_resources.file,     0, sizeof(ctx->system_resources.file)     );
  fd_memset( ctx->numa_entry_idx, 0xFF, sizeof(ctx->numa_entry_idx) );
  char meminfo[ 4096 ];
  if( FD_LIKELY( read_text( ctx->proc_meminfo_fd, meminfo, sizeof(meminfo) ) ) ) {
    ctx->system_resources.mem_available_bytes = read_meminfo_kib( meminfo, "MemAvailable" )<<10;
    ctx->system_resources.mem_free_bytes      = read_meminfo_kib( meminfo, "MemFree"      )<<10;
  }
  for( ulong i=0UL; i<ctx->numa.cnt; i++ ) {
    ulong numa_idx = ctx->numa.node[ i ].idx;
    fd_diag_system_numa_mem_t * numa = &ctx->system_resources.numa_mem[ i ];
    numa->numa_idx = (ushort)numa_idx;

    if( FD_UNLIKELY( !read_text( ctx->numa.node[ i ].meminfo_fd, meminfo, sizeof(meminfo) ) ) ) continue;
    char key[ 64 ];
    FD_TEST( fd_cstr_printf_check( key, sizeof(key), NULL, "Node %lu MemTotal", numa_idx ) );
    numa->total_bytes = read_meminfo_kib( meminfo, key )<<10;
    FD_TEST( fd_cstr_printf_check( key, sizeof(key), NULL, "Node %lu MemFree", numa_idx ) );
    numa->free_bytes = read_meminfo_kib( meminfo, key )<<10;
  }
  add_configured_memory_bytes( ctx );
  sample_disk( ctx );
  ctx->system_resources.sample_time_nanos = (ulong)now;
}

static void
publish_system( fd_diag_tile_t *    ctx,
                fd_stem_context_t * stem,
                long                now ) {
  if( FD_LIKELY( now<ctx->next_system_report_nanos ) ) return;
  sample_system( ctx, now );

  fd_memcpy( fd_chunk_to_laddr( ctx->system_out.mem, ctx->system_out.chunk ),
             &ctx->system_resources, sizeof(fd_diag_system_resources_t) );
  fd_stem_publish( stem, ctx->system_out.idx, sizeof(fd_diag_system_resources_t),
                   ctx->system_out.chunk, sizeof(fd_diag_system_resources_t), 0UL, 0UL,
                   (ulong)fd_frag_meta_ts_comp( fd_tickcount() ) );
  ctx->system_out.chunk = fd_dcache_compact_next( ctx->system_out.chunk,
    sizeof(fd_diag_system_resources_t), ctx->system_out.chunk0, ctx->system_out.wmark );
}

static void
before_credit( fd_diag_tile_t *    ctx,
               fd_stem_context_t * stem,
               int *               charge_busy ) {
  (void)stem;

  long now = fd_log_wallclock();
  if( now<ctx->next_report_nanos ) {
    long diff = ctx->next_report_nanos - now;
    diff = fd_long_min( diff, 2e6 /* 2ms */ );
    struct timespec const ts = {
      .tv_sec  = diff / (long)1e9,
      .tv_nsec = diff % (long)1e9
    };
    clock_nanosleep( CLOCK_REALTIME, 0, &ts, NULL );
    return;
  }
  ctx->next_report_nanos += REPORT_INTERVAL_MILLIS*1000L*1000L;

  *charge_busy = 1;
  if( FD_UNLIKELY( ctx->gui_enabled ) ) publish_system( ctx, stem, now );

  struct timespec boottime;
  if( FD_UNLIKELY( -1==clock_gettime( CLOCK_BOOTTIME, &boottime ) ) ) FD_LOG_ERR(( "clock_gettime(CLOCK_BOOTTIME) failed (%i-%s)", errno, strerror( errno ) ));
  ulong now_since_boot_nanos = (ulong)boottime.tv_sec*1000000000UL + (ulong)boottime.tv_nsec;

  interrupt_metrics( ctx ); /* before idle computation below, which subtracts it */

  for( ulong i=0UL; i<ctx->tile_cnt; i++ ) {
    if( FD_UNLIKELY( -1==ctx->stat_fds[ i ] ) ) continue;

    /* CLK_TCK is typically 100, so 1 tick = 10ms = 10,000,000 ns */
    int process_died1 = read_stat_file( ctx->stat_fds[ i ], 10000000UL, ctx->metrics[ i ] );
    int process_died2 = read_sched_file( ctx->sched_fds[ i ], ctx->metrics[ i ] );

    if( FD_UNLIKELY( process_died1 || process_died2 ) ) {
      ctx->stat_fds[ i ] = -1;
      continue;
    }

    ulong task_lifetime_nanos = now_since_boot_nanos - ctx->starttime_nanos[ i ];
    ulong user_nanos      = ctx->metrics[ i ][ FD_METRICS_COUNTER_TILE_CPU_DURATION_NANOS_USER_OFF ];
    ulong system_nanos    = ctx->metrics[ i ][ FD_METRICS_COUNTER_TILE_CPU_DURATION_NANOS_SYSTEM_OFF ];
    ulong wait_nanos      = ctx->metrics[ i ][ FD_METRICS_COUNTER_TILE_CPU_DURATION_NANOS_WAIT_OFF ];
    ulong interrupt_nanos = ctx->metrics[ i ][ FD_METRICS_COUNTER_TILE_CPU_DURATION_NANOS_INTERRUPT_OFF ];
    ulong busy_nanos      = user_nanos+system_nanos+wait_nanos+interrupt_nanos;
    ulong idle_nanos      = (task_lifetime_nanos>busy_nanos) ? (task_lifetime_nanos-busy_nanos) : 0UL;

    /* Counter can't go backwards in Prometheus else it thinks the
       application restarted.  Use max to ensure monotonicity. */
    ctx->metrics[ i ][ FD_METRICS_COUNTER_TILE_CPU_DURATION_NANOS_IDLE_OFF ] = fd_ulong_max( idle_nanos, ctx->metrics[ i ][ FD_METRICS_COUNTER_TILE_CPU_DURATION_NANOS_IDLE_OFF ] );
  }

  for( ulong i=0UL; i<ctx->tile_cnt; i++ ) {
    if( FD_LIKELY( -1!=ctx->stat_fds[ i ] ) ) continue;

    /* The tile died, but it's a tile which is allowed to shutdown, so
       just stop updating metrics for it. */
    if( FD_LIKELY( 2UL==ctx->metrics[ i ][ FD_METRICS_GAUGE_TILE_STATUS_OFF ] ) ) continue;

    /* Supervisor is going to bring the whole process tree down if any
       of the target PIDs died, so we can ignore this and wait. */
    if( FD_UNLIKELY( !ctx->first_seen_died[ i ] ) ) {
      ctx->first_seen_died[ i ] = now;
    } else if( FD_LIKELY( ctx->first_seen_died[ i ]==LONG_MAX ) ) {
      /* We already reported this, so we can ignore it. */
    } else if( FD_UNLIKELY( now-ctx->first_seen_died[ i ] < 10L*1000L*1000L*1000L ) ) {
      /* Wait 10 seconds for supervisor to kill us before reporting WARNING */
    } else {
      FD_LOG_WARNING(( "cannot get metrics for dead tile idx %lu", i ));
      ctx->first_seen_died[ i ] = LONG_MAX;
    }
  }

  check_engine_metric( ctx, now );
  irq_metrics( ctx );
}

/* Disk mount discovery ************************************************/

static int
fd_mount_id( int     fd,
             ulong * mnt_id ) {
  char fdinfo_path[ 64 ];
  if( FD_UNLIKELY( !fd_cstr_printf_check( fdinfo_path, sizeof(fdinfo_path), NULL, "/proc/self/fdinfo/%d", fd ) ) ) return EINVAL;

  int fdinfo_fd = open( fdinfo_path, O_RDONLY|O_CLOEXEC );
  if( FD_UNLIKELY( fdinfo_fd<0 ) ) return errno;

  char  buf[ 256 ];
  ulong buf_sz = 0UL;
  int err = fd_io_read( fdinfo_fd, buf, sizeof(buf)-1UL, sizeof(buf)-1UL, &buf_sz );
  if( FD_UNLIKELY( err<0 ) ) err = 0; /* EOF before the buffer filled */
  if( FD_UNLIKELY( close( fdinfo_fd ) && !err ) ) err = errno;
  if( FD_UNLIKELY( err ) ) return err;
  buf[ buf_sz ] = '\0';

  char const * line = buf;
  while( line ) {
    if( FD_UNLIKELY( !strncmp( line, "mnt_id:", 7UL ) ) ) {
      char * end;
      ulong id = strtoul( line+7UL, &end, 10 );
      if( FD_UNLIKELY( end==line+7UL || (*end!='\n' && *end!='\0') || id==ULONG_MAX ) ) return EINVAL;
      *mnt_id = id;
      return 0;
    }
    line = strchr( line, '\n' );
    if( line ) line++;
  }
  return ENOENT;
}

static int
resolve_path_prefix( char const * path,
                     char         resolved[ static PATH_MAX ] ) {
  char candidate[ PATH_MAX ];
  fd_cstr_ncpy( candidate, path, sizeof(candidate) );
  while( !realpath( candidate, resolved ) ) {
    char * slash = strrchr( candidate, '/' );
    if( FD_UNLIKELY( !slash ) ) return 0;
    if( slash==candidate ) slash[ 1 ] = '\0';
    else                  *slash = '\0';
  }
  return 1;
}

static int
open_disk_probe_dir( char const * resolved,
                     char         probe_dir[ static PATH_MAX ],
                     ulong *      mnt_id ) {
  /* `probe_dir` is on the target mount used only to create the probe
     file; the descriptor for `probe_dir` is not retained. */
  int path_fd = open( resolved, O_PATH|O_CLOEXEC );
  if( FD_UNLIKELY( path_fd<0 ) ) return -1;

  struct stat path_st;
  if( FD_UNLIKELY( fstat( path_fd, &path_st ) ) ) {
    close( path_fd );
    return -1;
  }

  ulong path_mnt_id;
  int err = fd_mount_id( path_fd, &path_mnt_id );
  if( FD_UNLIKELY( err ) ) {
    close( path_fd );
    FD_LOG_WARNING(( "reading mount ID for `%s` failed (%i-%s); omitting filesystem from system resource reporting",
                     resolved, err, strerror( err ) ));
    return -1;
  }

  fd_cstr_ncpy( probe_dir, resolved, PATH_MAX );
  if( FD_UNLIKELY( !S_ISDIR( path_st.st_mode ) ) ) {
    char * slash = strrchr( probe_dir, '/' );
    if( FD_UNLIKELY( !slash ) ) {
      close( path_fd );
      return -1;
    }
    if( slash==probe_dir ) slash[ 1 ] = '\0';
    else                  *slash = '\0';
  }

  int dir_fd = open( probe_dir, O_PATH|O_DIRECTORY|O_CLOEXEC );
  if( FD_UNLIKELY( dir_fd<0 ) ) {
    int open_err = errno;
    close( path_fd );
    FD_LOG_WARNING(( "open `%s` for disk-capacity probe failed (%i-%s); omitting filesystem from system resource reporting",
                     probe_dir, open_err, strerror( open_err ) ));
    return -1;
  }

  ulong dir_mnt_id;
  err = fd_mount_id( dir_fd, &dir_mnt_id );
  if( FD_UNLIKELY( err ) ) {
    close( path_fd );
    close( dir_fd );
    FD_LOG_WARNING(( "reading mount ID for `%s` failed (%i-%s); omitting filesystem from system resource reporting",
                     probe_dir, err, strerror( err ) ));
    return -1;
  }
  close( path_fd );

  /* A regular file can itself be a bind mount.  In that case its
     containing directory is not on the mount we need to sample,
     and there is nowhere on that mount to create an anonymous file. */
  if( FD_UNLIKELY( path_mnt_id!=dir_mnt_id ) ) {
    close( dir_fd );
    FD_LOG_WARNING(( "cannot create anonymous disk-capacity probe for non-directory mount `%s`; omitting filesystem from system resource reporting",
                     resolved ));
    return -1;
  }

  *mnt_id = dir_mnt_id;
  return dir_fd;
}

static int
resolve_mount_path( char const * probe_dir,
                    ulong        mnt_id,
                    char          mount_path[ static PATH_MAX ] ) {
  fd_cstr_ncpy( mount_path, probe_dir, PATH_MAX );
  while( strcmp( mount_path, "/" ) ) {
    char parent[ PATH_MAX ];
    fd_cstr_ncpy( parent, mount_path, sizeof(parent) );
    char * slash = strrchr( parent, '/' );
    if( slash==parent ) slash[ 1 ] = '\0';
    else               *slash = '\0';

    int parent_fd = open( parent, O_PATH|O_DIRECTORY|O_CLOEXEC );
    if( FD_UNLIKELY( parent_fd<0 ) ) {
      int open_err = errno;
      FD_LOG_WARNING(( "open `%s` while resolving mount point failed (%i-%s); omitting filesystem from system resource reporting",
                       parent, open_err, strerror( open_err ) ));
      return 0;
    }
    ulong parent_mnt_id;
    int err = fd_mount_id( parent_fd, &parent_mnt_id );
    close( parent_fd );
    if( FD_UNLIKELY( err ) ) {
      FD_LOG_WARNING(( "reading mount ID for `%s` failed (%i-%s); omitting filesystem from system resource reporting",
                       parent, err, strerror( err ) ));
      return 0;
    }
    if( parent_mnt_id!=mnt_id ) break;
    fd_cstr_ncpy( mount_path, parent, PATH_MAX );
  }
  return 1;
}

static int
create_disk_probe( int          dir_fd,
                   char const * probe_dir,
                   ulong        mnt_id ) {
  /* Retain no directory fds after sandboxing.  O_EXCL ensures
     that the anonymous inode cannot later be linked into the filesystem;
     reopening it O_PATH also removes the temporary read/write authority. */
  int tmp_fd = openat( dir_fd, ".", O_TMPFILE|O_EXCL|O_RDWR|O_CLOEXEC, S_IRUSR|S_IWUSR );
  if( FD_UNLIKELY( tmp_fd<0 ) ) {
    int err = errno;
    FD_LOG_WARNING(( "anonymous disk-capacity probe in `%s` failed (%i-%s); omitting filesystem from system resource reporting",
                     probe_dir, err, strerror( err ) ));
    return -1;
  }

  char tmp_path[ 64 ];
  FD_TEST( fd_cstr_printf_check( tmp_path, sizeof(tmp_path), NULL, "/proc/self/fd/%d", tmp_fd ) );
  int mount_fd = open( tmp_path, O_PATH|O_CLOEXEC );
  if( FD_UNLIKELY( mount_fd<0 ) ) {
    int err = errno;
    close( tmp_fd );
    FD_LOG_WARNING(( "reopening anonymous disk-capacity probe in `%s` as O_PATH failed (%i-%s); omitting filesystem from system resource reporting",
                     probe_dir, err, strerror( err ) ));
    return -1;
  }

  struct stat probe_st;
  ulong probe_mnt_id;
  int probe_err = 0;
  if( FD_UNLIKELY( fstat( mount_fd, &probe_st ) ) ) probe_err = errno;
  else if( FD_UNLIKELY( !S_ISREG( probe_st.st_mode ) || probe_st.st_nlink ) ) probe_err = EINVAL;
  else probe_err = fd_mount_id( mount_fd, &probe_mnt_id );
  if( FD_UNLIKELY( !probe_err && probe_mnt_id!=mnt_id ) ) probe_err = EXDEV;
  if( FD_UNLIKELY( probe_err ) ) {
    close( mount_fd );
    close( tmp_fd );
    FD_LOG_WARNING(( "anonymous disk-capacity probe in `%s` failed validation (%i-%s); omitting filesystem from system resource reporting",
                     probe_dir, probe_err, strerror( probe_err ) ));
    return -1;
  }
  close( tmp_fd );
  return mount_fd;
}

static uint
add_disk_mount( fd_diag_tile_t * ctx,
                char const *     path ) {
  if( FD_UNLIKELY( !path[ 0 ] ) ) return UINT_MAX;

  /* Find longest prefix of `path` that is a real path. */
  char resolved[ PATH_MAX ];
  if( FD_UNLIKELY( !resolve_path_prefix( path, resolved ) ) ) return UINT_MAX;

  /* Find candidate dir at or above `resolved` where O_TMPFILE can create a probe file. */
  char  probe_dir[ PATH_MAX ];
  ulong mnt_id;
  int dir_fd = open_disk_probe_dir( resolved, probe_dir, &mnt_id );
  if( FD_UNLIKELY( dir_fd<0 ) ) return UINT_MAX;

  /* Share one probe file among all reported paths on the same mount. */
  for( ulong i=0UL; i<ctx->mount_cnt; i++ ) {
    if( ctx->mounts[ i ].mnt_id==mnt_id ) {
      close( dir_fd );
      return (uint)i;
    }
  }
  if( FD_UNLIKELY( ctx->mount_cnt>=FD_DIAG_SYSTEM_FILE_MAX ) ) {
    close( dir_fd );
    return UINT_MAX;
  }

  /* Get the path of the mount `path` is on. */
  char mount_path[ PATH_MAX ];
  if( FD_UNLIKELY( !resolve_mount_path( probe_dir, mnt_id, mount_path ) ) ) {
    close( dir_fd );
    return UINT_MAX;
  }

  /* Create the probe O_PATH descriptor kept after sandboxing. */
  int mount_fd = create_disk_probe( dir_fd, probe_dir, mnt_id );
  close( dir_fd );
  if( FD_UNLIKELY( mount_fd<0 ) ) return UINT_MAX;

  ulong idx = ctx->mount_cnt++;
  ctx->mounts[ idx ].fd     = mount_fd;
  ctx->mounts[ idx ].mnt_id = mnt_id;
  fd_cstr_ncpy( ctx->mounts[ idx ].path, mount_path, sizeof(ctx->mounts[ idx ].path) );
  return (uint)idx;
}

static int
resolve_file_path( char const * path,
                   int          data_fd,
                   char         resolved[ static PATH_MAX ] ) {
  char fd_path[ 64 ];
  if( FD_LIKELY( data_fd>=0 ) ) {
    struct stat st;
    if( FD_UNLIKELY( fstat( data_fd, &st ) || !S_ISREG( st.st_mode ) ) ) return 0;
    FD_TEST( fd_cstr_printf_check( fd_path, sizeof(fd_path), NULL, "/proc/self/fd/%d", data_fd ) );
    path = fd_path;
  }
  if( FD_UNLIKELY( !path || !path[ 0 ] ) ) return 0;

  if( FD_LIKELY( realpath( path, resolved ) ) ) return 1;
  if( FD_LIKELY( path[ 0 ]=='/' ) ) {
    if( FD_UNLIKELY( strlen( path )>=PATH_MAX ) ) return 0;
    fd_cstr_ncpy( resolved, path, PATH_MAX );
    return 1;
  }

  char cwd[ PATH_MAX ];
  if( FD_UNLIKELY( !getcwd( cwd, sizeof(cwd) ) ) ) return 0;
  return fd_cstr_printf_check( resolved, PATH_MAX, NULL, "%s/%s", cwd, path );
}

static void
add_file( fd_diag_tile_t * ctx,
          uint             category,
          char const *     path,
          int              data_fd,
          ulong volatile * metric ) {
  char resolved[ PATH_MAX ];
  if( FD_UNLIKELY( !resolve_file_path( path, data_fd, resolved ) ) ) return;

  uint mount_idx = add_disk_mount( ctx, resolved );
  if( FD_UNLIKELY( mount_idx==UINT_MAX || ctx->file_cnt>=FD_DIAG_SYSTEM_FILE_MAX ) ) return;
  ulong idx = ctx->file_cnt++;
  fd_cstr_ncpy( ctx->files[ idx ].path, resolved, sizeof(ctx->files[ idx ].path) );
  ctx->files[ idx ].category              = category;
  ctx->files[ idx ].mount_idx             = mount_idx;
  ctx->files[ idx ].data_fd               = data_fd;
  ctx->files[ idx ].metric                = metric;
}

static void
privileged_init( fd_topo_t const *      topo,
                 fd_topo_tile_t const * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_diag_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_diag_tile_t), sizeof(fd_diag_tile_t) );

  FD_TEST( topo->tile_cnt<=FD_DIAG_SYSTEM_TILE_MAX );

  FD_TEST( 100L == sysconf( _SC_CLK_TCK ) );

  ctx->tile_cnt    = topo->tile_cnt;
  ctx->gui_enabled = fd_topo_find_tile_out_link( topo, tile, "diag_gui", 0UL )!=ULONG_MAX;
  ctx->memory.cnt  = topo->wksp_cnt;
  FD_TEST( ctx->memory.cnt<=FD_TOPO_MAX_WKSPS );
  for( ulong wksp_idx=0UL; wksp_idx<ctx->memory.cnt; wksp_idx++ ) {
    fd_topo_wksp_t const * wksp = &topo->workspaces[ wksp_idx ];
    FD_TEST( fd_cstr_printf_check( ctx->memory.wksp[ wksp_idx ].name,
                                  sizeof(ctx->memory.wksp[ wksp_idx ].name), NULL,
                                  "%s_%s.wksp", topo->app_name, wksp->name ) );
    ctx->memory.wksp[ wksp_idx ].numa_idx  = wksp->numa_idx;
    ctx->memory.wksp[ wksp_idx ].bytes     = wksp->page_cnt*wksp->page_sz;
    ctx->memory.wksp[ wksp_idx ].numa_slot = USHORT_MAX;

    ushort owners[ FD_DIAG_SYSTEM_TILE_MAX ];
    ulong  owner_cnt = 0UL;
    for( ulong tile_idx=0UL; tile_idx<topo->tile_cnt; tile_idx++ ) {
      fd_topo_tile_t const * owner = &topo->tiles[ tile_idx ];
      if( topo->objs[ owner->tile_obj_id ].wksp_id!=wksp_idx ) continue;
      owners[ owner_cnt++ ] = (ushort)tile_idx;
    }
    if( FD_LIKELY( owner_cnt==1UL ) ) {
      ctx->memory.wksp[ wksp_idx ].tile_idx = owners[ 0 ];
      continue;
    }
    if( FD_UNLIKELY( owner_cnt>1UL ) ) {
      ctx->memory.wksp[ wksp_idx ].tile_idx = DIAG_WKSP_TILE_IDX_SHARED;
      continue;
    }

    owner_cnt = 0UL;
    for( ulong link_idx=0UL; link_idx<topo->link_cnt; link_idx++ ) {
      fd_topo_link_t const * link = &topo->links[ link_idx ];
      if( topo->objs[ link->mcache_obj_id ].wksp_id!=wksp_idx &&
          ( !link->mtu || topo->objs[ link->dcache_obj_id ].wksp_id!=wksp_idx ) ) continue;
      ulong producer_idx = fd_topo_find_link_producer( topo, link );
      if( producer_idx==ULONG_MAX ) continue;
      int found = 0;
      for( ulong owner_idx=0UL; owner_idx<owner_cnt; owner_idx++ )
        found |= owners[ owner_idx ]==(ushort)producer_idx;
      if( !found ) owners[ owner_cnt++ ] = (ushort)producer_idx;
    }
    if( FD_LIKELY( owner_cnt==1UL ) ) {
      ctx->memory.wksp[ wksp_idx ].tile_idx = owners[ 0 ];
      continue;
    }
    if( FD_UNLIKELY( owner_cnt>1UL ) ) {
      ctx->memory.wksp[ wksp_idx ].tile_idx = DIAG_WKSP_TILE_IDX_SHARED;
      continue;
    }

    for( ulong tile_idx=0UL; tile_idx<topo->tile_cnt; tile_idx++ ) {
      fd_topo_tile_t const * owner = &topo->tiles[ tile_idx ];
      int uses_writable = 0;
      for( ulong obj_idx=0UL; obj_idx<owner->uses_obj_cnt; obj_idx++ ) {
        ulong obj_id = owner->uses_obj_id[ obj_idx ];
        uses_writable |= topo->objs[ obj_id ].wksp_id==wksp_idx &&
                         owner->uses_obj_mode[ obj_idx ]==FD_SHMEM_JOIN_MODE_READ_WRITE;
      }
      if( uses_writable ) owners[ owner_cnt++ ] = (ushort)tile_idx;
    }
    ctx->memory.wksp[ wksp_idx ].tile_idx = owner_cnt==1UL ? owners[ 0 ] : DIAG_WKSP_TILE_IDX_SHARED;
  }
  for( ulong tile_idx=0UL; tile_idx<FD_DIAG_SYSTEM_TILE_MAX; tile_idx++ )
    ctx->memory.stack_numa_slot[ tile_idx ] = USHORT_MAX;
  ctx->mount_cnt = 0UL;
  ctx->file_cnt = 0UL;
  for( ulong i=0UL; i<FD_TILE_MAX; i++ ) {
    ctx->stat_fds[ i ]  = -1;
    ctx->sched_fds[ i ] = -1;
  }
  for( ulong i=0UL; i<FD_DIAG_SYSTEM_NUMA_MAX; i++ ) ctx->numa.node[ i ].meminfo_fd = -1;

  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    ulong * metrics = fd_metrics_join( fd_topo_obj_laddr( topo, topo->tiles[ i ].metrics_obj_id ) );

    for(;;) {
      ulong pid, tid;
      if( FD_UNLIKELY( tile->id==i ) ) {
        pid = fd_sandbox_getpid();
        tid = fd_sandbox_gettid();
      } else {
        pid = fd_metrics_tile( metrics )[ FD_METRICS_GAUGE_TILE_PID_OFF ];
        tid = fd_metrics_tile( metrics )[ FD_METRICS_GAUGE_TILE_TID_OFF ];
        if( FD_UNLIKELY( !pid || !tid ) ) {
          FD_SPIN_PAUSE();
          continue;
        }
      }

      ctx->metrics[ i ] = fd_metrics_tile( metrics );

      char path[ 64UL ];
      FD_TEST( fd_cstr_printf_check( path, sizeof( path ), NULL, "/proc/%lu/task/%lu/stat", pid, tid ) );
      ctx->stat_fds[ i ] = open( path, O_RDONLY );
      if( FD_UNLIKELY( -1==ctx->stat_fds[ i ] ) ) {
        /* Might be a tile that's allowed to shutdown already did so
           before we got to here, due to a race condition.  Just
           proceed, we will not be able to get metrics for the shut
           down process. */
        if( FD_LIKELY( 2UL!=ctx->metrics[ i ][ FD_METRICS_GAUGE_TILE_STATUS_OFF ] ) ) FD_LOG_ERR(( "open stat failed (%i-%s)", errno, strerror( errno ) ));
        break;
      }

      FD_TEST( fd_cstr_printf_check( path, sizeof( path ), NULL, "/proc/%lu/task/%lu/sched", pid, tid ) );
      ctx->sched_fds[ i ] = open( path, O_RDONLY );
      if( FD_UNLIKELY( -1==ctx->sched_fds[ i ] ) ) {
        if( FD_LIKELY( 2UL!=ctx->metrics[ i ][ FD_METRICS_GAUGE_TILE_STATUS_OFF ] ) ) FD_LOG_ERR(( "open sched failed (%i-%s)", errno, strerror( errno ) ));
        ctx->stat_fds[ i ] = -1;
      }
      break;
    }
  }

  ctx->proc_interrupts_fd = open( "/proc/interrupts", O_RDONLY );
  if( FD_UNLIKELY( -1==ctx->proc_interrupts_fd ) ) FD_LOG_ERR(( "open(/proc/interrupts) failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  ctx->proc_softirqs_fd = open( "/proc/softirqs", O_RDONLY );
  if( FD_UNLIKELY( -1==ctx->proc_softirqs_fd   ) ) FD_LOG_ERR(( "open(/proc/softirqs) failed (%i-%s)",   errno, fd_io_strerror( errno ) ));

  ctx->proc_stat_fd = open( "/proc/stat", O_RDONLY );
  if( FD_UNLIKELY( -1==ctx->proc_stat_fd       ) ) FD_LOG_ERR(( "open(/proc/stat) failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  ctx->proc_meminfo_fd = open( "/proc/meminfo", O_RDONLY );
  if( FD_UNLIKELY( -1==ctx->proc_meminfo_fd    ) ) FD_LOG_ERR(( "open(/proc/meminfo) failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  ctx->numa.cnt = 0UL;
  if( FD_UNLIKELY( !ctx->gui_enabled ) ) return;

  fd_topo_cpus_t cpus[ 1 ];
  fd_topo_cpus_init( cpus );
  ctx->system_resources.cpu_cnt = (uint)fd_ulong_min( cpus->cpu_cnt, FD_DIAG_SYSTEM_CPU_MAX );
  for( ulong i=0UL; i<ctx->system_resources.cpu_cnt; i++ ) {
    fd_diag_system_cpu_t * cpu = &ctx->system_resources.cpu[ i ];
    cpu->cpu_idx     = (ushort)i;
    cpu->numa_idx    = (ushort)cpus->cpu[ i ].numa_node;
    cpu->sibling_idx = cpus->cpu[ i ].sibling==ULONG_MAX ? USHORT_MAX : (ushort)cpus->cpu[ i ].sibling;
    cpu->online      = (uchar)cpus->cpu[ i ].online;
  }

  for( ulong numa_idx=0UL; numa_idx<cpus->numa_node_cnt && ctx->numa.cnt<FD_DIAG_SYSTEM_NUMA_MAX; numa_idx++ ) {
    char path[ 128 ];
    FD_TEST( fd_cstr_printf_check( path, sizeof(path), NULL, "/sys/devices/system/node/node%lu/meminfo", numa_idx ) );
    int fd = open( path, O_RDONLY );
    if( FD_UNLIKELY( fd<0 ) ) {
      if( FD_UNLIKELY( errno!=ENOENT ) ) FD_LOG_WARNING(( "open `%s` failed (%i-%s)", path, errno, strerror( errno ) ));
      continue;
    }
    ctx->numa.node[ ctx->numa.cnt ].idx        = (ushort)numa_idx;
    ctx->numa.node[ ctx->numa.cnt ].meminfo_fd = fd;
    ctx->numa.cnt++;
  }

  for( ulong wksp_idx=0UL; wksp_idx<ctx->memory.cnt; wksp_idx++ ) {
    ulong numa_slot = 0UL;
    while( numa_slot<ctx->numa.cnt && ctx->numa.node[ numa_slot ].idx!=ctx->memory.wksp[ wksp_idx ].numa_idx ) numa_slot++;
    if( FD_UNLIKELY( numa_slot==ctx->numa.cnt ) ) {
      FD_LOG_WARNING(( "workspace `%s` is assigned to unavailable NUMA node %lu; omitting it from system memory reporting",
                       ctx->memory.wksp[ wksp_idx ].name, ctx->memory.wksp[ wksp_idx ].numa_idx ));
      continue;
    }
    ctx->memory.wksp[ wksp_idx ].numa_slot = (ushort)numa_slot;
  }

  for( ulong tile_idx=0UL; tile_idx<topo->tile_cnt; tile_idx++ ) {
    /* Keep this placement rule in sync with initialize_stacks(). */
    ulong stack_cpu_idx = topo->tiles[ tile_idx ].cpu_idx<65535UL ? topo->tiles[ tile_idx ].cpu_idx : 0UL;
    FD_TEST( stack_cpu_idx<cpus->cpu_cnt );
    ulong stack_numa_idx = cpus->cpu[ stack_cpu_idx ].numa_node;
    ulong numa_slot = 0UL;
    while( numa_slot<ctx->numa.cnt && ctx->numa.node[ numa_slot ].idx!=stack_numa_idx ) numa_slot++;
    if( FD_UNLIKELY( numa_slot==ctx->numa.cnt ) ) {
      FD_LOG_WARNING(( "stack for tile %s:%lu is assigned to unavailable NUMA node %lu; omitting it from system memory reporting",
                       topo->tiles[ tile_idx ].name, topo->tiles[ tile_idx ].kind_id, stack_numa_idx ));
      continue;
    }
    ctx->memory.stack_numa_slot[ tile_idx ] = (ushort)numa_slot;
  }

  ulong accdb_idx = fd_topo_find_tile( topo, "accdb", 0UL );
  if( tile->diag.accounts_path[ 0 ] && accdb_idx!=ULONG_MAX )
    add_file( ctx, FD_DIAG_SYSTEM_FILE_CATEGORY_ACCOUNTS, tile->diag.accounts_path, -1, ctx->metrics[ accdb_idx ] + FD_METRICS_GAUGE_ACCDB_DISK_ALLOCATED_BYTES_OFF );
  ulong rserve_idx = fd_topo_find_tile( topo, "rserve", 0UL );
  if( tile->diag.shreds_path[ 0 ] && rserve_idx!=ULONG_MAX )
    add_file( ctx, FD_DIAG_SYSTEM_FILE_CATEGORY_SHREDS, tile->diag.shreds_path, -1, ctx->metrics[ rserve_idx ] + FD_METRICS_GAUGE_RSERVE_DISK_ALLOCATED_BYTES_OFF );
  ulong snapmk_idx = fd_topo_find_tile( topo, "snapmk", 0UL );
  if( tile->diag.snapshots_path[ 0 ] && snapmk_idx!=ULONG_MAX )
    add_file( ctx, FD_DIAG_SYSTEM_FILE_CATEGORY_SNAPSHOTS, tile->diag.snapshots_path, -1, ctx->metrics[ snapmk_idx ] + FD_METRICS_GAUGE_SNAPMK_DISK_ALLOCATED_BYTES_OFF );
  ulong gui_idx = fd_topo_find_tile( topo, "gui", 0UL );
  if( gui_idx!=ULONG_MAX )
    add_file( ctx, FD_DIAG_SYSTEM_FILE_CATEGORY_GUI, tile->diag.gui_path, -1, ctx->metrics[ gui_idx ] + FD_METRICS_GAUGE_GUI_DISK_ALLOCATED_BYTES_OFF );
  int logfile_fd = fd_log_private_logfile_fd();
  if( logfile_fd>=0 ) add_file( ctx, FD_DIAG_SYSTEM_FILE_CATEGORY_LOGS, tile->diag.log_path, logfile_fd, NULL );
}

/* Read starttime (field 22) from stat file. Returns 0 on success, 1 if
   process died (ESRCH). */

static int
read_starttime( int     fd,
                ulong   ns_per_tick,
                ulong * out_starttime_nanos ) {
  char contents[ 4096 ] = {0};
  ulong contents_len = 0UL;

  while( 1 ) {
    if( FD_UNLIKELY( contents_len>=sizeof( contents ) ) ) FD_LOG_ERR(( "stat contents overflow" ));
    long n = read( fd, contents + contents_len, sizeof( contents ) - contents_len );
    if( FD_UNLIKELY( -1==n ) ) {
      if( FD_UNLIKELY( errno==ESRCH ) ) return 1;
      FD_LOG_ERR(( "read stat failed (%i-%s)", errno, strerror( errno ) ));
    }
    if( FD_LIKELY( 0L==n ) ) break;
    contents_len += (ulong)n;
  }

  /* Parse field 22 (starttime) from stat file */
  char * saveptr;
  char * token = strtok_r( contents, " ", &saveptr );
  ulong field_idx = 0UL;

  while( token && field_idx<21UL ) {
    token = strtok_r( NULL, " ", &saveptr );
    field_idx++;
  }

  if( FD_UNLIKELY( !token || field_idx!=21UL ) ) FD_LOG_ERR(( "starttime (field 22) not found in stat" ));

  char * endptr;
  ulong starttime_ticks = strtoul( token, &endptr, 10 );
  if( FD_UNLIKELY( *endptr!=' ' && *endptr!='\0' ) ) FD_LOG_ERR(( "strtoul failed for starttime" ));
  if( FD_UNLIKELY( starttime_ticks==ULONG_MAX ) ) FD_LOG_ERR(( "strtoul overflow for starttime" ));

  *out_starttime_nanos = starttime_ticks * ns_per_tick;
  return 0;
}

static void
unprivileged_init( fd_topo_t const *      topo,
                   fd_topo_tile_t const * tile ) {
  fd_diag_tile_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  memset( ctx->first_seen_died, 0, sizeof( ctx->first_seen_died ) );
  ctx->next_report_nanos = fd_log_wallclock();
  ctx->next_system_report_nanos = ctx->next_report_nanos;
  if( FD_UNLIKELY( ctx->gui_enabled ) ) {
    ulong out_idx = fd_topo_find_tile_out_link( topo, tile, "diag_gui", 0UL );
    FD_TEST( out_idx!=ULONG_MAX );
    fd_topo_link_t const * link = &topo->links[ tile->out_link_id[ out_idx ] ];
    ctx->system_out.idx    = out_idx;
    ctx->system_out.mem    = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
    ctx->system_out.chunk0 = fd_dcache_compact_chunk0( ctx->system_out.mem, link->dcache );
    ctx->system_out.wmark  = fd_dcache_compact_wmark ( ctx->system_out.mem, link->dcache, link->mtu );
    ctx->system_out.chunk  = ctx->system_out.chunk0;
  }

  /* Snapshot the cumulative-since-boot /proc interrupt/softirq counters
     so the metrics we report are counted since process startup. */
  memset( ctx->softirq_baseline,    0, sizeof( ctx->softirq_baseline    ) );
  memset( ctx->device_irq_baseline, 0, sizeof( ctx->device_irq_baseline ) );
  memset( ctx->tlb_baseline,        0, sizeof( ctx->tlb_baseline        ) );
  memset( ctx->loc_baseline,        0, sizeof( ctx->loc_baseline        ) );
  if( FD_UNLIKELY( -1==lseek( ctx->proc_softirqs_fd, 0, SEEK_SET ) ) ) FD_LOG_ERR(( "lseek failed (%i-%s)", errno, strerror( errno ) ));
  ulong softirq_cpu_cnt = fd_proc_softirqs_sum( ctx->proc_softirqs_fd, ctx->softirq_baseline );
  if( FD_UNLIKELY( !softirq_cpu_cnt ) ) FD_LOG_WARNING(( "failed to read softirq baseline from /proc/softirqs" ));

  if( FD_UNLIKELY( -1==lseek( ctx->proc_interrupts_fd, 0, SEEK_SET ) ) ) FD_LOG_ERR(( "lseek failed (%i-%s)", errno, strerror( errno ) ));
  ulong interrupt_cpu_cnt = fd_proc_interrupts_read( ctx->proc_interrupts_fd,
                                                     ctx->device_irq_baseline,
                                                     ctx->tlb_baseline,
                                                     ctx->loc_baseline );
  if( FD_UNLIKELY( !interrupt_cpu_cnt ) ) FD_LOG_WARNING(( "failed to read IRQ baselines from /proc/interrupts" ));

  memset( ctx->irq_ticks_baseline, 0, sizeof( ctx->irq_ticks_baseline ) );
  if( FD_UNLIKELY( -1==lseek( ctx->proc_stat_fd, 0, SEEK_SET ) ) ) FD_LOG_ERR(( "lseek failed (%i-%s)", errno, strerror( errno ) ));
  ulong stat_cpu_cnt = fd_proc_stat_irq_ticks( ctx->proc_stat_fd, ctx->irq_ticks_baseline );
  if( FD_UNLIKELY( !stat_cpu_cnt ) ) FD_LOG_WARNING(( "failed to read irq tick baseline from /proc/stat" ));

  /* Read starttime (field 22) once at init for idle time calculation.
     CLK_TCK is always 100, so 1 tick = 10ms = 10,000,000 ns. */
  for( ulong i=0UL; i<ctx->tile_cnt; i++ ) {
    if( FD_LIKELY( -1!=ctx->stat_fds[ i ] ) ) {
      int died = read_starttime( ctx->stat_fds[ i ], 10000000UL, &ctx->starttime_nanos[ i ] );
      if( FD_UNLIKELY( died ) ) ctx->stat_fds[ i ] = -1;
    }
  }

  memset( &ctx->check_engine, 0, sizeof(ctx->check_engine) );

  ctx->tiles.bundle_cnt = fd_topo_tile_name_cnt( topo, "bundle" );
  for( ulong i=0UL; i<ctx->tiles.bundle_cnt; i++ ) ctx->tiles.bundle_tile_idx[ i ] = fd_topo_find_tile( topo, "bundle", i );
  ctx->tiles.shred_cnt = fd_topo_tile_name_cnt( topo, "shred" );
  for( ulong i=0UL; i<ctx->tiles.shred_cnt; i++ ) ctx->tiles.shred_tile_idx[ i ] = fd_topo_find_tile( topo, "shred", i );
  ctx->tiles.tower_idx  = fd_topo_find_tile( topo, "tower",  0UL );
  ctx->tiles.votor_idx  = fd_topo_find_tile( topo, "votor",  0UL );
  ctx->tiles.replay_idx = fd_topo_find_tile( topo, "replay", 0UL );

  fd_cpuset_new( &ctx->cpu_has_tile );
  for( ulong i=0UL; i<(topo->tile_cnt); i++ ) {
    ulong cpu_idx = topo->tiles[ i ].cpu_idx;
    if( cpu_idx>=FD_TILE_MAX ) continue;
    fd_cpuset_insert( ctx->cpu_has_tile, cpu_idx );
  }

  for( ulong i=0UL; i<FD_TILE_MAX; i++ ) ctx->cpu_to_tile[ i ] = USHORT_MAX;
  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    ulong cpu_idx = topo->tiles[ i ].cpu_idx;
    if( cpu_idx>=FD_TILE_MAX ) continue;
    ctx->cpu_to_tile[ cpu_idx ] = (ushort)i;
  }

  long now = fd_log_wallclock();
  ctx->is_voting = tile->diag.is_voting;
  ctx->check_engine.vote_slot_changed_ns = now;
  ctx->check_engine.reset_slot_changed_ns = now;
  ctx->check_engine.turbine_slot_changed_ns = now;
  ctx->check_engine.byte_snapshot_ns = now;
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  (void)topo;
  (void)tile;

  populate_sock_filter_policy_fd_diag_tile( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_fd_diag_tile_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  fd_diag_tile_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  int logfile_fd = fd_log_private_logfile_fd();
  ulong required_fds = 5UL+2UL*ctx->tile_cnt+ctx->numa.cnt+ctx->mount_cnt+(ulong)(-1!=logfile_fd);
  for( ulong i=0UL; i<ctx->file_cnt; i++ )
    required_fds += (ulong)( ctx->files[ i ].data_fd>=0 && ctx->files[ i ].data_fd!=logfile_fd );
  if( FD_UNLIKELY( out_fds_cnt<required_fds ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=logfile_fd ) )
    out_fds[ out_cnt++ ] = logfile_fd; /* logfile */
  out_fds[ out_cnt++ ] = ctx->proc_interrupts_fd; /* /proc/interrupts */
  out_fds[ out_cnt++ ] = ctx->proc_softirqs_fd;   /* /proc/softirqs */
  out_fds[ out_cnt++ ] = ctx->proc_stat_fd;       /* /proc/stat */
  out_fds[ out_cnt++ ] = ctx->proc_meminfo_fd;    /* /proc/meminfo */
  for( ulong i=0UL; i<ctx->tile_cnt; i++ ) {
    if( -1!=ctx->stat_fds[ i ] )  out_fds[ out_cnt++ ] = ctx->stat_fds[ i ];  /* /proc/<pid>/task/<tid>/stat */
    if( -1!=ctx->sched_fds[ i ] ) out_fds[ out_cnt++ ] = ctx->sched_fds[ i ]; /* /proc/<pid>/task/<tid>/sched */
  }
  for( ulong i=0UL; i<ctx->numa.cnt; i++ )
    if( ctx->numa.node[ i ].meminfo_fd>=0 ) out_fds[ out_cnt++ ] = ctx->numa.node[ i ].meminfo_fd;
  for( ulong i=0UL; i<ctx->mount_cnt; i++ ) out_fds[ out_cnt++ ] = ctx->mounts[ i ].fd;
  for( ulong i=0UL; i<ctx->file_cnt; i++ )
    if( ctx->files[ i ].data_fd>=0 && ctx->files[ i ].data_fd!=logfile_fd )
      out_fds[ out_cnt++ ] = ctx->files[ i ].data_fd;
  return out_cnt;
}

#define STEM_BURST (1UL)
#define STEM_LAZY  ((long)10e6) /* 10ms */

#define STEM_CALLBACK_CONTEXT_TYPE  fd_diag_tile_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_diag_tile_t)

#define STEM_CALLBACK_BEFORE_CREDIT before_credit

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_diag = {
  .name                     = "diag",
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
