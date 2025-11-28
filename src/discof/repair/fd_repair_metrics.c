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
                     long           first_shred_ts,
                     long           slot_complete_ts,
                     uint           repair_cnt,
                     uint           turbine_cnt ) {
  uint next_en = (repair_metrics->en + 1) % FD_CATCHUP_METRICS_MAX;
  if( FD_UNLIKELY( next_en == repair_metrics->st || repair_metrics->st == UINT_MAX ) ) {
    repair_metrics->st = (repair_metrics->st + 1) % FD_CATCHUP_METRICS_MAX;
  }
  repair_metrics->slots[ next_en ].slot             = slot;
  repair_metrics->slots[ next_en ].first_shred_ts   = first_shred_ts;
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

#define print_slot_interval_bar( slot_metrics, tick_sz, min_ts, verbose )           \
  long duration = slot_metrics->slot_complete_ts - slot_metrics->first_shred_ts;    \
  int  width    = (int)((double)(duration) / tick_sz);                              \
  int  start    = (int)((double)(slot_metrics->first_shred_ts - min_ts) / tick_sz); \
  if( FD_UNLIKELY( verbose ) ) {                                                    \
    printf( "%lu [repaired: %u/%u]%.*s|%.*s| (%.2f ms)",                            \
            slot_metrics->slot,                                                     \
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

static int
compare_slots( const void * a, const void * b ) {
  const fd_slot_metrics_t * slot_a = (const fd_slot_metrics_t *)a;
  const fd_slot_metrics_t * slot_b = (const fd_slot_metrics_t *)b;

  if( slot_a->slot < slot_b->slot ) return -1;
  if( slot_a->slot > slot_b->slot ) return 1;
  return 0;
}

/* Should be typically only called once, at the end of a catchup.  Other
   wise the information is not meaningful (during regular turbine, the
   slots are pretty much sequentially arriving in order anyway) */
void
fd_repair_metrics_print_sorted( fd_repair_metrics_t * repair_metrics, int verbose, fd_slot_metrics_t * temp_slots ) {
  if( repair_metrics->st == UINT_MAX ) return; // no data to sort

  uint temp_idx          = 0;
  long min_ts            = repair_metrics->slots[ repair_metrics->st ].first_shred_ts;
  long max_ts            = repair_metrics->slots[ repair_metrics->en ].slot_complete_ts;
  long repair_kickoff_ts = 0;  /* When we receive the first turbine shred, is when we begin orphans. */
  long finish_catchup_ts = 0;  /* the max of all slot < turbine slot0 completion times */
  int  num_catchup_slots = 0;
  uint total_slots       = 0;
  long slot_durations_sum   = 0;
  long incremental_cmpl_sum = 0;
  long prev_slot_ts         = repair_metrics->slots[ repair_metrics->st ].slot_complete_ts;

  for( uint i = repair_metrics->st;; i = (i + 1) % FD_CATCHUP_METRICS_MAX ) {
    fd_slot_metrics_t * slot_data = &repair_metrics->slots[ i ];
    temp_slots[ temp_idx++ ] = *slot_data;
    total_slots++;
    min_ts = fd_min( min_ts, slot_data->first_shred_ts );
    max_ts = fd_max( max_ts, slot_data->slot_complete_ts );
    if( FD_UNLIKELY( slot_data->slot == repair_metrics->turbine_slot0 ) ) repair_kickoff_ts = slot_data->first_shred_ts;
    if( FD_UNLIKELY( slot_data->slot <= repair_metrics->turbine_slot0 ) ) finish_catchup_ts = fd_max( finish_catchup_ts, slot_data->slot_complete_ts );
    if( FD_UNLIKELY( slot_data->slot <= repair_metrics->turbine_slot0 ) ) num_catchup_slots++;
    slot_durations_sum += slot_data->slot_complete_ts - slot_data->first_shred_ts;

    incremental_cmpl_sum += slot_data->slot_complete_ts - prev_slot_ts;
    prev_slot_ts          = slot_data->slot_complete_ts;

    if( i == repair_metrics->en ) break;
  }

  /* Sort temp array by slot */
  qsort( temp_slots, total_slots, sizeof(fd_slot_metrics_t), compare_slots );

  /* prints a stacked depth chart of the catchup metrics:
    slot          |===============| (duration in ms)
    slot              |================|
    etc. */

  double tick_sz          = (double)(max_ts - min_ts) / (double)MAX_WIDTH;
  long   orphan_cmpl_ts   = temp_slots[0].first_shred_ts; /* When we make the request for the snapshot slot, this is about when the full tree is connected. */
  int    orphans_cmpl_cnt = 0;                      /* Count of slots completed by the time orphan requests are done */
  for( uint i = 0; i < total_slots; i++ ) {
    fd_slot_metrics_t * slot_metrics = &temp_slots[ i ];
    if( FD_UNLIKELY( slot_metrics->slot_complete_ts < orphan_cmpl_ts ) ) orphans_cmpl_cnt++;
    print_slot_interval_bar( slot_metrics, tick_sz, min_ts, verbose );
  }
  fflush( stdout );


  double pipelined_time     = (double)(max_ts - min_ts);
  double non_pipelined_time = (double)slot_durations_sum;
  FD_LOG_NOTICE(( "\n"
                  "Completed %u slots in %.2f seconds total. \n"
                  "Average slot duration (time from first shred/rq to all shreds received): %.2f ms\n"
                  "Average time between slot completions:                                   %.2f ms\n"
                  "Average slots per second:                                                %.2f\n"
                  "Pipeline factor (sum duration of all slots / total time):                %.2f\n",
                  total_slots,
                  (double)fd_metrics_convert_ticks_to_nanoseconds((ulong)pipelined_time) / 1e9,
                  (double)fd_metrics_convert_ticks_to_nanoseconds((ulong)slot_durations_sum) / (double)total_slots / 1e6,
                  (double)fd_metrics_convert_ticks_to_nanoseconds((ulong)incremental_cmpl_sum) / (double)total_slots / 1e6,
                  (double)total_slots / (double)fd_metrics_convert_ticks_to_nanoseconds((ulong)pipelined_time) * 1e9,
                  non_pipelined_time / pipelined_time ));

  FD_LOG_NOTICE(( "\n"
                  "Caught up %d slots in %.2f ms total. \n"
                  "Time to repair orphans:                    %.2f ms \n"
                  "Total time from connected orphan to done:  %.2f ms \n"
                  "Slots completed by orphans connected:      %d\n",
                  num_catchup_slots,
                  (double)fd_metrics_convert_ticks_to_nanoseconds((ulong)(finish_catchup_ts - repair_kickoff_ts)) / 1e6,
                  (double)fd_metrics_convert_ticks_to_nanoseconds((ulong)(orphan_cmpl_ts    - repair_kickoff_ts)) / 1e6,
                  (double)fd_metrics_convert_ticks_to_nanoseconds((ulong)(finish_catchup_ts - orphan_cmpl_ts   )) / 1e6,
                  orphans_cmpl_cnt ));
}

void
fd_repair_metrics_print( fd_repair_metrics_t * repair_metrics, int verbose ) {
  long min_ts            = repair_metrics->slots[ repair_metrics->st ].first_shred_ts;
  long max_ts            = repair_metrics->slots[ repair_metrics->en ].slot_complete_ts;
  uint total_slots       = 0;
  long prev_slot_ts         = repair_metrics->slots[ repair_metrics->st ].slot_complete_ts;
  long incremental_cmpl_sum = 0;

  long slot_durations_sum = 0;
  for( uint i = repair_metrics->st;; i = (i + 1) % FD_CATCHUP_METRICS_MAX ) {
    fd_slot_metrics_t * slot_data = &repair_metrics->slots[ i ];
    slot_durations_sum += (slot_data->slot_complete_ts - slot_data->first_shred_ts);
    total_slots++;
    min_ts = fd_min( min_ts, slot_data->first_shred_ts );
    max_ts = fd_max( max_ts, slot_data->slot_complete_ts );

    /* st -> en are already ordered by completion time. so this-prev
       is guaranteed to be > 0 */
    incremental_cmpl_sum += slot_data->slot_complete_ts - prev_slot_ts;
    prev_slot_ts          = slot_data->slot_complete_ts;

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

  double pipelined_time     = (double)(max_ts - min_ts);
  double non_pipelined_time = (double)slot_durations_sum;
  FD_LOG_NOTICE(( "\n"
                  "Over past %u completed slots: \n"
                  "Average slot duration (time from first shred/rq to all shreds received): %.2f ms\n"
                  "Average time between slot completions:                                   %.2f ms\n"
                  "Average slots per second:                                                %.2f\n"
                  "Pipeline factor (sum duration of all slots / total time):                %.2f\n",
                  total_slots,
                  (double)fd_metrics_convert_ticks_to_nanoseconds((ulong)slot_durations_sum) / (double)total_slots / 1e6,
                  (double)fd_metrics_convert_ticks_to_nanoseconds((ulong)incremental_cmpl_sum) / (double)total_slots / 1e6,
                  (double)total_slots / (double)fd_metrics_convert_ticks_to_nanoseconds((ulong)pipelined_time) * 1e9,
                  non_pipelined_time / pipelined_time ));
}

#undef MAX_WIDTH
