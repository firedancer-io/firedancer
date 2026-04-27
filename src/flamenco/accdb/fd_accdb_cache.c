#include "fd_accdb_cache.h"

#include "../../util/bits/fd_bits.h"
#include "../../util/log/fd_log.h"

int
fd_accdb_cache_class_cnt( ulong   cache_footprint,
                          ulong   min_reserved,
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
     mainnet replay (1000-slot sample at slot 406546575), adjusted for
     64-byte header offset when mapping data_sz to stored_sz cache
     classes.  Higher weight means more cache hits per byte of cache
     spent.  Classes 6, 7 are floored to 1. */

  static const ulong density[ FD_ACCDB_CACHE_CLASS_CNT ] = {
    26861UL,  /* class 0 */
     7742UL,  /* class 1 */
      583UL,  /* class 2 */
      234UL,  /* class 3 */
       34UL,  /* class 4 */
        3UL,  /* class 5 */
        1UL,  /* class 6 */
        1UL,  /* class 7 */
  };

  /* Per-class working-set targets (slot counts).  Derived from p99 of
     the distinct-pubkey-per-class working set measured over a 32-slot
     sliding window on the same 1000-slot mainnet sample, with ~25-50%
     headroom so allocations cover the typical hot set without wasting
     budget on classes whose live working set is tiny.

     These are floors used by Phase 2: each class is topped up to
     ws_target[c] above the Phase 1 base reservation, before
     density-based distribution.  Phase 3 then distributes any remaining
     budget by density. */

  static const ulong ws_target[ FD_ACCDB_CACHE_CLASS_CNT ] = {
    16384UL,  /* class 0: p99 ~13.4K, ample headroom (small slots) */
    13000UL,  /* class 1: p99 ~10.4K */
     4096UL,  /* class 2: p99  ~3.2K */
     2560UL,  /* class 3: p99  ~2.0K — was undersized at 1.3K */
     1800UL,  /* class 4: p99  ~1.0K — needs headroom for pre-evict to keep up */
      128UL,  /* class 5: p99    ~66 — was wastefully sized at 1.3K */
      256UL,  /* class 6: p99   ~212 */
      256UL,  /* class 7: p99   ~179; staging covered by MIN_RESERVED */
  };

  ulong minimum_cost = min_reserved * ( fd_accdb_cache_slot_sz[ 0UL ] +
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
    FD_LOG_WARNING(( "cache_footprint must be at least %lu GiB to meet minimum requirements", (minimum_cost+(1UL<<30UL)-1)/(1UL<<30UL) ));
    FD_LOG_WARNING(( "%lu<%lu", cache_footprint, minimum_cost ));
    for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ ) class_cnt[ c ] = 0UL;
    return 0;
  }

  /* Phase 1: Reserve min_reserved of each class off the top.  This
     guarantees the worst-case batch (64 accounts per transaction,
     doubled to cover programdata, multiplied by max simultaneous
     transactions) can execute fully in memory.  Each referenced account
     reserves one slot in its own class plus one slot for its
     programdata account, which may land in any class.  Worst case all
     referenced accounts and all programdata accounts land in the same
     class. */

  ulong remaining = cache_footprint;
  for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ ) {
    class_cnt[c] = min_reserved;
    remaining   -= min_reserved * fd_accdb_cache_slot_sz[c];
  }

  /* Phase 2: Reserve up to ws_target[c] slots per class as a floor.
     Phase 1 already gave each class min_reserved slots; here we top up
     to ws_target[c] (or as much as remaining budget allows).  This
     keeps tiny working sets (128K/1M/10M classes) from being
     over-allocated and frees budget for hotter classes (8K, 2K) in
     Phase 3. */

  for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ ) {
    if( ws_target[c]<=class_cnt[c] ) continue;
    ulong want = ws_target[c] - class_cnt[c];
    want = fd_ulong_min( want, pop_max[c]>class_cnt[c] ? pop_max[c]-class_cnt[c] : 0UL );
    ulong cost = want * fd_accdb_cache_slot_sz[c];
    if( FD_UNLIKELY( cost>remaining ) ) {
      class_cnt[c] += remaining / fd_accdb_cache_slot_sz[c];
      remaining     = 0UL;
    } else {
      class_cnt[c] += want;
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
