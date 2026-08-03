#include "fd_progcache_class.h"
#include "../../util/log/fd_log.h"
#include "../../disco/metrics/generated/fd_metrics_enums.h"

/* The per-class metric arrays are sized by FD_PROGCACHE_CLASS_CNT
   but FD_MCNT_ENUM_COPY iterates over the metrics enum, so a mismatch
   reads past the end of those arrays. */
FD_STATIC_ASSERT( FD_METRICS_ENUM_PROGCACHE_CLASS_CNT==FD_PROGCACHE_CLASS_CNT,
                  "FD_METRICS_ENUM_PROGCACHE_CLASS_CNT must match FD_PROGCACHE_CLASS_CNT" );

int
fd_progcache_class_cnt( ulong   cache_footprint,
                        ulong * class_cnt ) {
  /* Share of the budget given to each data class, as a percentage,
     computed from the mainnet program size distribution.  Class 0 takes
     whatever the others leave, so the shares must sum to 100.
     TODO: dynamically recompute these percentages, e.g. at epoch boundary. */
  enum {          /* slot size */
    PCT_CLASS_0 =  4, /* 128 KiB */
    PCT_CLASS_1 = 29, /* 512 KiB */
    PCT_CLASS_2 = 25, /*   1 MiB */
    PCT_CLASS_3 = 18, /*   2 MiB */
    PCT_CLASS_4 = 14, /*   4 MiB */
    PCT_CLASS_5 = 10, /*  11 MiB */
  };
  FD_STATIC_ASSERT( PCT_CLASS_0+PCT_CLASS_1+PCT_CLASS_2+
                    PCT_CLASS_3+PCT_CLASS_4+PCT_CLASS_5==100, progcache_class_pct );
  static const uint pct[ FD_PROGCACHE_DATA_CLASS_CNT ] = {
    PCT_CLASS_0, PCT_CLASS_1, PCT_CLASS_2, PCT_CLASS_3, PCT_CLASS_4, PCT_CLASS_5,
  };

  for( ulong c=0UL; c<FD_PROGCACHE_CLASS_CNT; c++ ) {
    class_cnt[c] = 0UL;
  }

  /* Seed every class with its guaranteed minimum.
     This is to avoid issues later due to rounding. */
  ulong seed_cost = 0UL;
  for( ulong c=0UL; c<FD_PROGCACHE_CLASS_CNT; c++ ) {
    class_cnt[ c ] = fd_progcache_class_min( c );
    seed_cost     += class_cnt[ c ]*fd_progcache_slot_sz[ c ];
  }
  if( FD_UNLIKELY( cache_footprint<seed_cost ) ) {
    FD_LOG_WARNING(( "progcache cache_footprint %lu B too small: the guaranteed class minimums need %lu B", cache_footprint, seed_cost ));
    return 0;
  }

  /* Distribute by percentage, rounding down (but min is already guaranteed). */
  ulong budget    = cache_footprint - seed_cost;
  ulong remaining = budget;
  for( ulong c=1UL; c<FD_PROGCACHE_DATA_CLASS_CNT; c++ ) {
    ulong slot_sz = fd_progcache_slot_sz[ c ];
    ulong want    = ((budget/100UL)*(ulong)pct[ c ]) / slot_sz;
    class_cnt[ c ] += want;
    remaining      -= want*slot_sz;
  }
  class_cnt[ 0 ] += remaining / fd_progcache_slot_sz[ 0 ];

  return 1;
}
