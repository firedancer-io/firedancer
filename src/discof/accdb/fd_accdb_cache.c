#include "fd_accdb_cache.h"

#include "../../util/bits/fd_bits.h"

int
fd_accdb_cache_class_cnt( ulong   cache_footprint,
                          ulong * class_cnt ) {
  /* Estimated max account population per class on mainnet.  Based on a
     full mainnet snapshot (1.118B accounts, 363.7 GiB, slot 393863972)
     with ~20% headroom. */

  static const ulong pop_max[ FD_ACCDB_CACHE_CLASS_CNT ] = {
     215000000UL,  /* class 0: ~16% of accounts   */
    1041000000UL,  /* class 1: ~77.6% of accounts */
      76000000UL,  /* class 2: ~5.6%              */
       8000000UL,  /* class 3: ~0.6%              */
       4000000UL,  /* class 4: ~0.3%              */
        461000UL,  /* class 5: ~0.03%             */
        244000UL,  /* class 6: ~0.02%             */
          5000UL,  /* class 7: ~0.0003%           */
  };

  /* Access density weights: total_accesses / slot_size from empirical
     mainnet replay (1000-slot sample), adjusted for 64-byte header
     offset when mapping data_sz to stored_sz cache classes.  Higher
     weight means more cache hits per byte of cache spent. Classes 6, 7
     are floored to 1. */

  static const ulong density[ FD_ACCDB_CACHE_CLASS_CNT ] = {
    53470UL,  /* class 0 */
    10682UL,  /* class 1 */
     1400UL,  /* class 2 */
      248UL,  /* class 3 */
        8UL,  /* class 4 */
        5UL,  /* class 5 */
        1UL,  /* class 6 */
        1UL,  /* class 7 */
  };

  ulong minimum_cost = 1300UL * ( fd_accdb_cache_slot_sz[ 0UL ] +
                                  fd_accdb_cache_slot_sz[ 1UL ] +
                                  fd_accdb_cache_slot_sz[ 2UL ] +
                                  fd_accdb_cache_slot_sz[ 3UL ] +
                                  fd_accdb_cache_slot_sz[ 4UL ] +
                                  fd_accdb_cache_slot_sz[ 5UL ] +
                                  fd_accdb_cache_slot_sz[ 6UL ] +
                                  fd_accdb_cache_slot_sz[ 7UL ] );

  if( FD_UNLIKELY( cache_footprint<minimum_cost ) ) {
    /* Budget too small to meet minimum requirement.  Return 0 to
        indicate failure. */
    for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ ) class_cnt[ c ] = 0UL;
    return 0;
  }

  /* Phase 1: Reserve 1300 of each class off the top.  This
     guarantees worst-case 5-transaction bundles (130 accounts
     per transaction) can execute fully in memory.  Each writable
     account reserves one original-class slot plus one destination
     per class.  Worst case all 650 writable accounts land in the
     same class: 650 originals + 650 destinations = 1300. */

  ulong remaining = cache_footprint;
  for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ ) {
    class_cnt[c] = 1300UL;
    remaining   -= 1300UL * fd_accdb_cache_slot_sz[c];
  }

  /* Phase 2: Reserve additional per-class minimums.  Each class
     gets at most 1% of the remaining budget, clamped to [1, 1024]
     slots, added on top of the 650 base. */

  for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ ) {
    ulong budget_frac = remaining / ( 100UL * fd_accdb_cache_slot_sz[c] );
    ulong mn = fd_ulong_max( 1UL, fd_ulong_min( 1024UL, fd_ulong_min( budget_frac, pop_max[c] ) ) );
    ulong cost = mn * fd_accdb_cache_slot_sz[c];
    if( FD_UNLIKELY( cost>remaining ) ) {
      class_cnt[c] += remaining / fd_accdb_cache_slot_sz[c];
      remaining     = 0UL;
    } else {
      class_cnt[c] += mn;
      remaining    -= cost;
    }
  }

  /* Phase 3: Iteratively allocate remaining budget proportional
     to access density.  When a class exceeds its population cap,
     freeze it and redistribute surplus to uncapped classes. */

  int capped[ FD_ACCDB_CACHE_CLASS_CNT ];
  for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ ) capped[c] = 0;

  for( ulong iter=0UL; iter<FD_ACCDB_CACHE_CLASS_CNT && remaining; iter++ ) {
    ulong total_w = 0UL;
    for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ )
      if( !capped[c] ) total_w += density[c];
    if( FD_UNLIKELY( !total_w ) ) break;

    int any_capped = 0;
    for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ ) {
      if( capped[c] ) continue;
      ulong budget = remaining * density[c] / total_w;
      ulong extra  = budget / fd_accdb_cache_slot_sz[c];
      if( class_cnt[c]+extra >= pop_max[c] ) {
        ulong added  = pop_max[c] - class_cnt[c];
        class_cnt[c] = pop_max[c];
        remaining   -= added * fd_accdb_cache_slot_sz[c];
        capped[c]    = 1;
        any_capped   = 1;
      }
    }

    if( !any_capped ) {
      /* No caps hit.  Final proportional allocation. */
      total_w = 0UL;
      for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ )
        if( !capped[c] ) total_w += density[c];
      if( FD_UNLIKELY( !total_w ) ) break;
      for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ ) {
        if( capped[c] ) continue;
        ulong budget = remaining * density[c] / total_w;
        class_cnt[c] += budget / fd_accdb_cache_slot_sz[c];
      }
      break;
    }
  }

  /* Phase 4: If all classes hit their population caps, there may
     still be remaining budget.  The accounts database can grow at
     runtime, so distribute excess uncapped, proportional to
     density.  This ensures we always use the full cache budget
     the operator gave us. */

  remaining = cache_footprint;
  for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ )
    remaining -= class_cnt[c] * fd_accdb_cache_slot_sz[c];

  if( remaining ) {
    ulong total_w = 0UL;
    for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ )
      total_w += density[c];
    for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ ) {
      ulong budget = remaining * density[c] / total_w;
      class_cnt[c] += budget / fd_accdb_cache_slot_sz[c];
    }
  }

  return 1;
}

ulong
fd_accdb_cache_class( ulong data_sz ) {
  if( FD_LIKELY( data_sz<=128UL ) ) return 0UL;
  else if( FD_LIKELY( data_sz<=512UL ) ) return 1UL;
  else if( FD_LIKELY( data_sz<=2048UL ) ) return 2UL;
  else if( FD_LIKELY( data_sz<=8192UL ) ) return 3UL;
  else if( FD_LIKELY( data_sz<=32768UL ) ) return 4UL;
  else if( FD_LIKELY( data_sz<=131072UL ) ) return 5UL;
  else if( FD_LIKELY( data_sz<=1048576UL ) ) return 6UL;
  return 7UL;
}
