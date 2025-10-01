#include "fd_repair_metrics.h"
#include <stdio.h>

#include "../../disco/metrics/fd_metrics.h"

void *
fd_repair_metrics_new( void * mem ) {
  fd_repair_metrics_t * repair_metrics = (fd_repair_metrics_t *)mem;
  repair_metrics->st = UINT_MAX;
  repair_metrics->en = UINT_MAX;
  repair_metrics->turbine_slot0 = 0;

  return repair_metrics;
}

fd_repair_metrics_t *
fd_repair_metrics_join( void * repair_metrics ) {
  return (fd_repair_metrics_t *)repair_metrics;
}

void
fd_repair_metrics_set_turbine_slot0( fd_repair_metrics_t * repair_metrics, ulong turbine_slot0 ) {
  repair_metrics->turbine_slot0 = turbine_slot0;
}

void
fd_repair_metrics_add_slot( fd_repair_metrics_t * repair_metrics,
                     ulong          slot,
                     long           first_ts,
                     long           slot_complete_ts,
                     uint           repair_cnt,
                     uint           turbine_cnt ) {
  uint next_en = (repair_metrics->en + 1) % FD_CATCHUP_METRICS_MAX;
  if( FD_UNLIKELY( next_en == repair_metrics->st || repair_metrics->st == UINT_MAX ) ) {
    repair_metrics->st = (repair_metrics->st + 1) % FD_CATCHUP_METRICS_MAX;
  }
  repair_metrics->slots[ next_en ].slot             = slot;
  repair_metrics->slots[ next_en ].first_ts         = first_ts;
  repair_metrics->slots[ next_en ].slot_complete_ts = slot_complete_ts;
  repair_metrics->slots[ next_en ].repair_cnt       = repair_cnt;
  repair_metrics->slots[ next_en ].turbine_cnt      = turbine_cnt;
  repair_metrics->en = next_en;

# if DEBUG_LOGGING
  if( FD_UNLIKELY( slot == repair_metrics->turbine_slot0 ) ) {
    fd_repair_metrics_print( repair_metrics );
  }
# endif
}

#define MAX_WIDTH 120
static char dashes[MAX_WIDTH + 1] = "========================================================================================================================";
static char spaces[MAX_WIDTH + 1] = "                                                                                                                        ";

static void
print_catchup_stats( fd_repair_metrics_t * repair_metrics ) {
  long min_ts               = repair_metrics->slots[ repair_metrics->st ].first_ts;
  long turbine_ts           = 0;
  long slot_cmpl_time_total = 0;
  long prev_slot_cmpl_ts    = LONG_MAX;
  long incr_slot_cmpl_total = 0;

  uint catchup_cnt = 0;
  for( uint i = repair_metrics->st;; i = (i + 1) % FD_CATCHUP_METRICS_MAX ) {
    ulong cur_slot      = repair_metrics->slots[ i ].slot;
    long  slot_cmpl_ts  = repair_metrics->slots[ i ].slot_complete_ts;
    long  slot_first_ts = repair_metrics->slots[ i ].first_ts;

    min_ts = fd_min( min_ts, slot_first_ts );

    if( cur_slot <= repair_metrics->turbine_slot0 ) {
      slot_cmpl_time_total += (slot_cmpl_ts - slot_first_ts);
      catchup_cnt++;
    }
    if( FD_UNLIKELY( cur_slot == repair_metrics->turbine_slot0 ) ) {
      turbine_ts = slot_cmpl_ts;
    }

    /* incremental slot completion time */
    if( cur_slot <= repair_metrics->turbine_slot0 && slot_cmpl_ts - prev_slot_cmpl_ts > 0 ) {
      incr_slot_cmpl_total += (slot_cmpl_ts - prev_slot_cmpl_ts);
    }
    prev_slot_cmpl_ts = slot_cmpl_ts;
    if( FD_UNLIKELY( i == repair_metrics->en ) ) break;
  }

  if( FD_LIKELY( turbine_ts > 0 ) ) { /* still have turbine slot0 in the catchup metrics */
    double pipelined_time = (double)(turbine_ts - min_ts);
    FD_LOG_NOTICE(( "took %.3fs to reach first turbine.", pipelined_time / 1e9 ));

    /* Compute pipeline factor */
    double non_pipelined_time = (double)slot_cmpl_time_total;
    FD_LOG_NOTICE(( "pipeline factor: %.2f, avg incremental slot completion time: %.2f ms",
                     non_pipelined_time / pipelined_time,
                     (double)fd_metrics_convert_ticks_to_nanoseconds((ulong)incr_slot_cmpl_total) / (double)catchup_cnt / 1e6 ));
  }
}

void
fd_repair_metrics_print( fd_repair_metrics_t * repair_metrics, int verbose ) {
  long min_ts   = repair_metrics->slots[ repair_metrics->st ].first_ts;
  long max_ts   = repair_metrics->slots[ repair_metrics->en ].slot_complete_ts;
  int  turbine0 = 0;
  uint cnt      = 0;

  long slot_cmpl_duration_total = 0;
  for( uint i = repair_metrics->st;; i = (i + 1) % FD_CATCHUP_METRICS_MAX ) {
    cnt++;
    ulong cur_slot      = repair_metrics->slots[ i ].slot;
    long  slot_cmpl_ts  = repair_metrics->slots[ i ].slot_complete_ts;
    long  slot_first_ts = repair_metrics->slots[ i ].first_ts;

    min_ts = fd_min( min_ts, slot_first_ts );
    max_ts = fd_max( max_ts, slot_cmpl_ts );
    slot_cmpl_duration_total += (slot_cmpl_ts - slot_first_ts);

    if( FD_UNLIKELY( cur_slot == repair_metrics->turbine_slot0 ) ) turbine0 = 1;
    if( FD_UNLIKELY( i == repair_metrics->en ) ) break;
  }

  /* prints a stacked depth chart of the catchup metrics like this:
     slot          |===============| (duration in ms)
     slot              |================|
     etc. */

  double tick_sz = (double)(max_ts - min_ts) / (double)MAX_WIDTH;

  for( uint i = repair_metrics->st;;i = (i + 1) % FD_CATCHUP_METRICS_MAX ) {
    long duration = repair_metrics->slots[ i ].slot_complete_ts - repair_metrics->slots[ i ].first_ts;
    int  width    = (int)((double)(duration) / tick_sz);
    int  start    = (int)((double)(repair_metrics->slots[ i ].first_ts - min_ts) / tick_sz);
    if( FD_UNLIKELY( verbose ) ) {
      printf( "%lu [repaired: %u/%u]%.*s|%.*s| (%.2f ms)",
               repair_metrics->slots[ i ].slot,
               repair_metrics->slots[ i ].repair_cnt, repair_metrics->slots[ i ].turbine_cnt + repair_metrics->slots[ i ].repair_cnt,
               start, spaces, width, dashes,
               (double)fd_metrics_convert_ticks_to_nanoseconds((ulong)duration) / 1e6 );
    } else {
      printf( "%lu %.*s|%.*s| (%.2f ms)",
             repair_metrics->slots[ i ].slot,
             start, spaces, width, dashes,
             (double)fd_metrics_convert_ticks_to_nanoseconds((ulong)duration) / 1e6 );
    }

    if( FD_UNLIKELY( repair_metrics->slots[ i ].slot == repair_metrics->turbine_slot0 ) ) {
      printf( " <--- (first turbine shred received)" );
    }
    printf( "\n" );
    if( i == repair_metrics->en ) break;
  }
  fflush( stdout );

  FD_LOG_NOTICE(( "Showing past %u slots, avg slot duration %.2f ms", cnt, (double)fd_metrics_convert_ticks_to_nanoseconds((ulong)slot_cmpl_duration_total) / (double)cnt / 1e6 ));
  if( FD_UNLIKELY( turbine0 ) ) { /* still have turbine slot0 in the catchup metrics */
    print_catchup_stats( repair_metrics );
  }
}

#undef MAX_WIDTH

