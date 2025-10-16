#include "fd_repair_metrics.h"
#include <stdio.h>
#include <stdlib.h>

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

#define print_slot_interval_bar( slot_metrics, tick_sz, min_ts, verbose )     \
  long duration = slot_metrics->slot_complete_ts - slot_metrics->first_ts;    \
  int  width    = (int)((double)(duration) / tick_sz);                        \
  int  start    = (int)((double)(slot_metrics->first_ts - min_ts) / tick_sz); \
  if( FD_UNLIKELY( verbose ) ) {                                              \
    printf( "%lu [repaired: %u/%u]%.*s|%.*s| (%.2f ms)",                      \
            slot_metrics->slot,                                               \
            slot_metrics->repair_cnt, slot_metrics->turbine_cnt + slot_metrics->repair_cnt, \
            start, spaces, width, dashes,                                                   \
            (double)fd_metrics_convert_ticks_to_nanoseconds((ulong)duration) / 1e6 );       \
  } else {                                                                                  \
    printf( "%lu %.*s|%.*s| (%.2f ms)",                                                     \
          slot_metrics->slot,                                                               \
          start, spaces, width, dashes,                                                     \
          (double)fd_metrics_convert_ticks_to_nanoseconds((ulong)duration) / 1e6 ); \
  }                                                                                 \
  if( FD_UNLIKELY( slot_metrics->slot == repair_metrics->turbine_slot0 ) ) {        \
    printf( " <--- (first turbine shred received)" );                               \
  }               \
  printf( "\n" );

/* Filters on slots that are behind the turbine slot0.  Should only be
   called when turbine slot0 is still in scope of the slot metrics. */
static void
print_catchup_stats( fd_repair_metrics_t * repair_metrics ) {
  long min_ts               = repair_metrics->slots[ repair_metrics->st ].first_ts;
  long turbine_ts           = 0;
  long slot_duration_sum    = 0;
  long prev_slot_ts         = LONG_MAX;
  long incremental_cmpl_sum = 0;

  uint catchup_cnt = 0;
  for( uint i = repair_metrics->st;; i = (i + 1) % FD_CATCHUP_METRICS_MAX ) {
    fd_slot_metrics_t * slot_ = &repair_metrics->slots[ i ];
    min_ts = fd_min( min_ts, slot_->first_ts );
    if( FD_LIKELY  ( slot_->slot <= repair_metrics->turbine_slot0 ) ) slot_duration_sum += (slot_->slot_complete_ts - slot_->first_ts);
    if( FD_LIKELY  ( slot_->slot <= repair_metrics->turbine_slot0 ) ) catchup_cnt++;
    if( FD_UNLIKELY( slot_->slot == repair_metrics->turbine_slot0 ) ) turbine_ts = slot_->slot_complete_ts;

    /* incremental slot completion time */
    if( slot_->slot <= repair_metrics->turbine_slot0 &&
        slot_->slot_complete_ts - prev_slot_ts > 0 ) {
      incremental_cmpl_sum += (slot_->slot_complete_ts - prev_slot_ts);
    }

    prev_slot_ts = slot_->slot_complete_ts;
    if( FD_UNLIKELY( i == repair_metrics->en ) ) break;
  }

  if( FD_LIKELY( turbine_ts > 0 ) ) { /* still have turbine slot0 in the catchup metrics */
    double pipelined_time = (double)(turbine_ts - min_ts);
    FD_LOG_NOTICE(( "took %.3fs to reach first turbine.", fd_metrics_convert_ticks_to_seconds((ulong)pipelined_time) ));

    /* Compute pipeline factor */
    double non_pipelined_time = (double)slot_duration_sum;
    FD_LOG_NOTICE(( "pipeline factor: %.2f, avg incremental slot completion time: %.2f ms",
                     non_pipelined_time / pipelined_time,
                     (double)fd_metrics_convert_ticks_to_nanoseconds((ulong)incremental_cmpl_sum) / (double)catchup_cnt / 1e6 ));
  }
}

static int
compare_slots( const void * a, const void * b ) {
  const fd_slot_metrics_t * slot_a = (const fd_slot_metrics_t *)a;
  const fd_slot_metrics_t * slot_b = (const fd_slot_metrics_t *)b;

  if( slot_a->slot < slot_b->slot ) return -1;
  if( slot_a->slot > slot_b->slot ) return 1;
  return 0;
}

void
fd_repair_metrics_print_sorted( fd_repair_metrics_t * repair_metrics, int verbose, fd_slot_metrics_t * temp_slots ) {
  if( repair_metrics->st == UINT_MAX ) return; // no data to sort

  uint temp_idx          = 0;
  long min_ts            = repair_metrics->slots[ repair_metrics->st ].first_ts;
  long max_ts            = repair_metrics->slots[ repair_metrics->en ].slot_complete_ts;
  long repair_kickoff_ts = 0;  /* When we receive the first turbine shred, is when we begin orphans. */
  long finish_catchup_ts = 0;  /* the max of all slot < turbine slot0 completion times */
  int  num_catchup_slots = 0;
  uint total_slots       = 0;

  for( uint i = repair_metrics->st;; i = (i + 1) % FD_CATCHUP_METRICS_MAX ) {
    fd_slot_metrics_t * slot_data = &repair_metrics->slots[ i ];
    temp_slots[ temp_idx++ ] = *slot_data;
    total_slots++;
    min_ts = fd_min( min_ts, slot_data->first_ts );
    max_ts = fd_max( max_ts, slot_data->slot_complete_ts );
    if( FD_UNLIKELY( slot_data->slot == repair_metrics->turbine_slot0 ) ) repair_kickoff_ts = slot_data->first_ts;
    if( FD_UNLIKELY( slot_data->slot <= repair_metrics->turbine_slot0 ) ) finish_catchup_ts = fd_max( finish_catchup_ts, slot_data->slot_complete_ts );
    if( FD_UNLIKELY( slot_data->slot <= repair_metrics->turbine_slot0 ) ) num_catchup_slots++;
    if( i == repair_metrics->en ) break;
  }

  /* Sort temp array by slot */
  qsort( temp_slots, total_slots, sizeof(fd_slot_metrics_t), compare_slots );

  /* prints a stacked depth chart of the catchup metrics:
    slot          |===============| (duration in ms)
    slot              |================|
    etc. */

  double tick_sz          = (double)(max_ts - min_ts) / (double)MAX_WIDTH;
  long   orphan_cmpl_ts   = temp_slots[0].first_ts; /* When we make the request for the snapshot slot, this is about when the full tree is connected. */
  int    orphans_cmpl_cnt = 0;                      /* Count of slots completed by the time orphan requests are done */
  for( uint i = 0; i < total_slots; i++ ) {
    fd_slot_metrics_t * slot_metrics = &temp_slots[ i ];
    if( FD_UNLIKELY( slot_metrics->slot_complete_ts < orphan_cmpl_ts ) ) orphans_cmpl_cnt++;
    print_slot_interval_bar( slot_metrics, tick_sz, min_ts, verbose );
  }
  fflush( stdout );

  FD_LOG_NOTICE(( "\n"
                  "Total time to finish catchup over %d slots: %.2f ms \n"
                  "Time to repair orphans: %.2f ms \n"
                  "Total time from connected orphan to done: %.2f ms \n"
                  "%d slots completed by the time of connected tree",
                  num_catchup_slots,
                  (double)fd_metrics_convert_ticks_to_nanoseconds((ulong)(finish_catchup_ts - repair_kickoff_ts)) / 1e6,
                  (double)fd_metrics_convert_ticks_to_nanoseconds((ulong)(orphan_cmpl_ts - repair_kickoff_ts)) / 1e6,
                  (double)fd_metrics_convert_ticks_to_nanoseconds((ulong)(finish_catchup_ts - orphan_cmpl_ts)) / 1e6,
                  orphans_cmpl_cnt ));
}

void
fd_repair_metrics_print( fd_repair_metrics_t * repair_metrics, int verbose ) {
  long min_ts            = repair_metrics->slots[ repair_metrics->st ].first_ts;
  long max_ts            = repair_metrics->slots[ repair_metrics->en ].slot_complete_ts;
  long finish_catchup_ts = 0;
  uint total_slots       = 0;
  long turbine_ts        = 0;

  long slot_durations_sum = 0;
  for( uint i = repair_metrics->st;; i = (i + 1) % FD_CATCHUP_METRICS_MAX ) {
    fd_slot_metrics_t * slot_data = &repair_metrics->slots[ i ];
    slot_durations_sum += (slot_data->slot_complete_ts - slot_data->first_ts);
    total_slots++;
    min_ts = fd_min( min_ts, slot_data->first_ts );
    max_ts = fd_max( max_ts, slot_data->slot_complete_ts );
    if( FD_UNLIKELY( slot_data->slot <= repair_metrics->turbine_slot0 ) ) finish_catchup_ts = fd_max( finish_catchup_ts, slot_data->slot_complete_ts );
    if( FD_UNLIKELY( slot_data->slot == repair_metrics->turbine_slot0 ) ) turbine_ts = slot_data->slot_complete_ts;
    if( FD_UNLIKELY( i == repair_metrics->en ) ) break;
  }

  /* prints a stacked depth chart of the catchup metrics:
     slot          |===============| (duration in ms)
     slot              |================|
     etc. */

  double tick_sz = (double)(max_ts - min_ts) / (double)MAX_WIDTH;
  for( uint i = repair_metrics->st;; i = (i + 1) % FD_CATCHUP_METRICS_MAX ) {
    fd_slot_metrics_t * slot_metrics = &repair_metrics->slots[ i ];
    print_slot_interval_bar( slot_metrics, tick_sz, min_ts, verbose );
    if( i == repair_metrics->en ) break;
  }
  fflush( stdout );

  FD_LOG_NOTICE(( "Showing past %u slots, avg slot duration %.2f ms",
                  total_slots,
                  (double)fd_metrics_convert_ticks_to_nanoseconds((ulong)slot_durations_sum) / (double)total_slots / 1e6 ));
  if( FD_UNLIKELY( turbine_ts > 0 ) ) {
    /* still have turbine slot0 in the catchup metrics */
    print_catchup_stats( repair_metrics );
  }
}

#undef MAX_WIDTH

