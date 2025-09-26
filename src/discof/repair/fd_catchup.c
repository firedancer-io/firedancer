#include "fd_catchup.h"
#include <stdio.h>

#include "../../disco/metrics/fd_metrics.h"

void *
fd_catchup_new( void * mem ) {
  fd_catchup_t * catchup = (fd_catchup_t *)mem;
  catchup->st = UINT_MAX;
  catchup->en = UINT_MAX;
  catchup->turbine_slot0 = 0;

  return catchup;
}

fd_catchup_t *
fd_catchup_join( void * catchup ) {
  return (fd_catchup_t *)catchup;
}

void
fd_catchup_set_turbine_slot0( fd_catchup_t * catchup, ulong turbine_slot0 ) {
  catchup->turbine_slot0 = turbine_slot0;
}

void
fd_catchup_add_slot( fd_catchup_t * catchup,
                     ulong          slot,
                     long           first_ts,
                     long           slot_complete_ts,
                     uint           repair_cnt,
                     uint           turbine_cnt ) {
  uint next_en = (catchup->en + 1) % FD_CATCHUP_METRICS_MAX;
  if( FD_UNLIKELY( next_en == catchup->st || catchup->st == UINT_MAX ) ) {
    catchup->st = (catchup->st + 1) % FD_CATCHUP_METRICS_MAX;
  }
  catchup->metrics[ next_en ].slot             = slot;
  catchup->metrics[ next_en ].first_ts         = first_ts;
  catchup->metrics[ next_en ].slot_complete_ts = slot_complete_ts;
  catchup->metrics[ next_en ].repair_cnt       = repair_cnt;
  catchup->metrics[ next_en ].turbine_cnt      = turbine_cnt;
  catchup->en = next_en;

# if DEBUG_LOGGING
  if( FD_UNLIKELY( slot == catchup->turbine_slot0 ) ) {
    fd_catchup_print( catchup );
  }
# endif
}

#define MAX_WIDTH 120
static char dashes[MAX_WIDTH + 1] = "========================================================================================================================";
static char spaces[MAX_WIDTH + 1] = "                                                                                                                        ";

void
fd_catchup_print( fd_catchup_t * catchup, int verbose ) {
  long min_ts = catchup->metrics[ catchup->st ].first_ts;
  long max_ts = catchup->metrics[ catchup->en ].slot_complete_ts;
  long turbine_ts = 0;
  uint cnt = 0;

  long total_slot_complete_duration = 0;
  for( uint i = catchup->st;; i = (i + 1) % FD_CATCHUP_METRICS_MAX ) {
    cnt++;
    min_ts = fd_min( min_ts, catchup->metrics[ i ].first_ts );
    max_ts = fd_max( max_ts, catchup->metrics[ i ].slot_complete_ts );
    total_slot_complete_duration += (catchup->metrics[ i ].slot_complete_ts - catchup->metrics[ i ].first_ts);
    if( catchup->metrics[ i ].slot == catchup->turbine_slot0 ) {
      turbine_ts = catchup->metrics[ i ].slot_complete_ts;
    }
    if( i == catchup->en ) break;
  }


  if( FD_LIKELY( turbine_ts > 0 ) ) { /* still have turbine slot0 in the catchup metrics */
    FD_LOG_NOTICE(( "took %.3fs to complete catchup.", (double)(turbine_ts - min_ts) / 1e9 ));
  }

  /* prints a stacked depth chart of the catchup metrics like this:
     slot          |===============| (duration in ms)
     slot              |================|
     etc. */

  double tick_sz = (double)(max_ts - min_ts) / (double)MAX_WIDTH;

  for( uint i = catchup->st;;i = (i + 1) % FD_CATCHUP_METRICS_MAX ) {
    long duration = catchup->metrics[ i ].slot_complete_ts - catchup->metrics[ i ].first_ts;
    int  width    = (int)((double)(duration) / tick_sz);
    int  start    = (int)((double)(catchup->metrics[ i ].first_ts - min_ts) / tick_sz);
    // print slot number, then start spaces, then '=' width times, then '|'
    if( FD_UNLIKELY( verbose ) ) {
    printf( "%lu [repaired: %u/%u]%.*s|%.*s| (%.2f ms)",
             catchup->metrics[ i ].slot,
             catchup->metrics[ i ].repair_cnt, catchup->metrics[ i ].turbine_cnt + catchup->metrics[ i ].repair_cnt,
             start, spaces, width, dashes,
             (double)fd_metrics_convert_ticks_to_nanoseconds((ulong)duration) / 1e6 );
    } else {
      printf( "%lu %.*s|%.*s| (%.2f ms)",
             catchup->metrics[ i ].slot,
             start, spaces, width, dashes,
             (double)fd_metrics_convert_ticks_to_nanoseconds((ulong)duration) / 1e6 );
    }

    if( catchup->metrics[ i ].slot == catchup->turbine_slot0 ) {
      printf( " <--- (first turbine shred received)" );
    }
    printf( "\n" );
    if( i == catchup->en ) break;
  }
  fflush( stdout );

  FD_LOG_NOTICE(( "Showing past %u slots, avg slot duration %.2f ms", cnt, (double)fd_metrics_convert_ticks_to_nanoseconds((ulong)total_slot_complete_duration) / (double)cnt / 1e6 ));
  if( FD_LIKELY( turbine_ts > 0 ) ) { /* still have turbine slot0 in the catchup metrics */
    FD_LOG_NOTICE(( "took %.3fs to complete catchup.", (double)(turbine_ts - min_ts) / 1e9 ));
  }
}

#undef MAX_WIDTH

