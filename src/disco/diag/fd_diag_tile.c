#include "fd_diag_tile.h"

#include "../bundle/fd_bundle_tile.h"
#include "../metrics/fd_metrics.h"
#include "../stem/fd_stem.h"
#include "../topo/fd_topo.h"
#include "../../util/tile/fd_tile_private.h"

#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/types.h> /* SEEK_SET */
#include <time.h>
#include <unistd.h>

#include "fd_proc_interrupts.h"
#include "generated/fd_diag_tile_seccomp.h"

#define REPORT_INTERVAL_MILLIS (100L)

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
  ulong       device_irq_baseline[ FD_TILE_MAX ];
  ulong       tlb_baseline[ FD_TILE_MAX ];
  ulong       loc_baseline[ FD_TILE_MAX ];
  ulong       irq_ticks_baseline[ FD_TILE_MAX ];
  ulong       softirq_baseline[ FD_METRICS_ENUM_SOFTIRQ_CNT ][ FD_TILE_MAX ];

  ulong volatile * metrics    [ FD_TILE_MAX ];
  ushort           cpu_to_tile[ FD_TILE_MAX ];

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
  ulong vote_status = FD_DIAG_VOTE_STATUS_DISABLED;
  if( FD_LIKELY( ctx->is_voting && tower_idx!=ULONG_MAX ) ) {
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
  if( FD_UNLIKELY( -1==lseek( ctx->proc_interrupts_fd, 0, SEEK_SET ) ) ) FD_LOG_ERR(( "lseek failed (%i-%s)", errno, strerror( errno ) ));
  ulong device_cpu_cnt = fd_proc_interrupts_colwise( ctx->proc_interrupts_fd, cpu_irq );
  if( FD_UNLIKELY( !device_cpu_cnt ) ) return; /* parse fail */

  ulong tot_cnt       = 0UL;
  ulong undesired_cnt = 0UL;
  for( ulong i=0UL; i<device_cpu_cnt; i++ ) {
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

  ulong * cpu_tlb = ctx->irq_cnt[ 0 ]; /* re-use as scratch memory */
  if( FD_UNLIKELY( -1==lseek( ctx->proc_interrupts_fd, 0, SEEK_SET ) ) ) FD_LOG_ERR(( "lseek failed (%i-%s)", errno, strerror( errno ) ));
  ulong tlb_cpu_cnt = fd_proc_interrupts_tlb( ctx->proc_interrupts_fd, cpu_tlb );
  if( FD_UNLIKELY( !tlb_cpu_cnt ) ) return; /* parse fail */

  for( ulong i=0UL; i<tlb_cpu_cnt; i++ ) {
    ulong tile_id = ctx->cpu_to_tile[ i ];
    if( tile_id!=USHORT_MAX ) {
      ulong since = fd_ulong_sat_sub( cpu_tlb[ i ], ctx->tlb_baseline[ i ] );
      ctx->metrics[ tile_id ][ FD_METRICS_COUNTER_TILE_TLB_SHOOTDOWN_OFF ] = since;
    }
  }

  ulong * cpu_loc = ctx->irq_cnt[ 0 ]; /* re-use as scratch memory */
  if( FD_UNLIKELY( -1==lseek( ctx->proc_interrupts_fd, 0, SEEK_SET ) ) ) FD_LOG_ERR(( "lseek failed (%i-%s)", errno, strerror( errno ) ));
  ulong loc_cpu_cnt = fd_proc_interrupts_loc( ctx->proc_interrupts_fd, cpu_loc );
  if( FD_UNLIKELY( !loc_cpu_cnt ) ) return; /* parse fail */

  for( ulong i=0UL; i<loc_cpu_cnt; i++ ) {
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

static void
privileged_init( fd_topo_t const *      topo,
                 fd_topo_tile_t const * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_diag_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_diag_tile_t), sizeof(fd_diag_tile_t) );

  FD_TEST( topo->tile_cnt<FD_TILE_MAX );

  FD_TEST( 100L == sysconf( _SC_CLK_TCK ) );

  ctx->tile_cnt = topo->tile_cnt;
  for( ulong i=0UL; i<FD_TILE_MAX; i++ ) {
    ctx->stat_fds[ i ]  = -1;
    ctx->sched_fds[ i ] = -1;
  }

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
  if( FD_UNLIKELY( -1==ctx->proc_stat_fd       ) ) FD_LOG_ERR(( "open(/proc/stat) failed (%i-%s)",       errno, fd_io_strerror( errno ) ));
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

  /* Snapshot the cumulative-since-boot /proc interrupt/softirq counters
     so the metrics we report are counted since process startup. */
  memset( ctx->softirq_baseline,    0, sizeof( ctx->softirq_baseline    ) );
  memset( ctx->device_irq_baseline, 0, sizeof( ctx->device_irq_baseline ) );
  memset( ctx->tlb_baseline,        0, sizeof( ctx->tlb_baseline        ) );
  if( FD_UNLIKELY( -1==lseek( ctx->proc_softirqs_fd, 0, SEEK_SET ) ) ) FD_LOG_ERR(( "lseek failed (%i-%s)", errno, strerror( errno ) ));
  ulong softirq_cpu_cnt = fd_proc_softirqs_sum( ctx->proc_softirqs_fd, ctx->softirq_baseline );
  if( FD_UNLIKELY( !softirq_cpu_cnt ) ) FD_LOG_WARNING(( "failed to read softirq baseline from /proc/softirqs" ));

  if( FD_UNLIKELY( -1==lseek( ctx->proc_interrupts_fd, 0, SEEK_SET ) ) ) FD_LOG_ERR(( "lseek failed (%i-%s)", errno, strerror( errno ) ));
  ulong device_cpu_cnt = fd_proc_interrupts_colwise( ctx->proc_interrupts_fd, ctx->device_irq_baseline );
  if( FD_UNLIKELY( !device_cpu_cnt ) ) FD_LOG_WARNING(( "failed to read device IRQ baseline from /proc/interrupts" ));

  if( FD_UNLIKELY( -1==lseek( ctx->proc_interrupts_fd, 0, SEEK_SET ) ) ) FD_LOG_ERR(( "lseek failed (%i-%s)", errno, strerror( errno ) ));
  ulong tlb_cpu_cnt = fd_proc_interrupts_tlb( ctx->proc_interrupts_fd, ctx->tlb_baseline );
  if( FD_UNLIKELY( !tlb_cpu_cnt ) ) FD_LOG_WARNING(( "failed to read TLB baseline from /proc/interrupts" ));

  memset( ctx->loc_baseline, 0, sizeof( ctx->loc_baseline ) );
  if( FD_UNLIKELY( -1==lseek( ctx->proc_interrupts_fd, 0, SEEK_SET ) ) ) FD_LOG_ERR(( "lseek failed (%i-%s)", errno, strerror( errno ) ));
  ulong loc_cpu_cnt = fd_proc_interrupts_loc( ctx->proc_interrupts_fd, ctx->loc_baseline );
  if( FD_UNLIKELY( !loc_cpu_cnt ) ) FD_LOG_WARNING(( "failed to read LOC baseline from /proc/interrupts" ));

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

  if( FD_UNLIKELY( out_fds_cnt<5UL+2UL*ctx->tile_cnt ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  out_fds[ out_cnt++ ] = ctx->proc_interrupts_fd; /* /proc/interrupts */
  out_fds[ out_cnt++ ] = ctx->proc_softirqs_fd;   /* /proc/softirqs */
  out_fds[ out_cnt++ ] = ctx->proc_stat_fd;       /* /proc/stat */
  for( ulong i=0UL; i<ctx->tile_cnt; i++ ) {
    if( -1!=ctx->stat_fds[ i ] )  out_fds[ out_cnt++ ] = ctx->stat_fds[ i ];  /* /proc/<pid>/task/<tid>/stat */
    if( -1!=ctx->sched_fds[ i ] ) out_fds[ out_cnt++ ] = ctx->sched_fds[ i ]; /* /proc/<pid>/task/<tid>/sched */
  }
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
