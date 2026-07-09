/* Smoke test for fd_accdb_cache_class_cnt. */

#include "fd_accdb_cache.h"
#include "../../util/fd_util.h"

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong class_cnt[ FD_ACCDB_CACHE_CLASS_CNT ];

  /* Test a range of cache sizes. */

  static const ulong test_gb[] = { 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048 };

  for( ulong t=0UL; t<sizeof(test_gb)/sizeof(test_gb[0]); t++ ) {
    ulong footprint = test_gb[t] * (1UL<<30);

    int ok = fd_accdb_cache_class_cnt( footprint, 640UL, class_cnt );

    FD_LOG_NOTICE(( "=== %lu GiB cache === (%s)", test_gb[t],
                     ok ? "ok" : "too small" ));

    if( !ok ) {
      for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ )
        FD_TEST( class_cnt[c]==0UL );
      continue;
    }

    /* Verify every class has at least the min_reserved floor we
       requested above. */

    for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ ) {
      FD_TEST( class_cnt[c]>=640UL );
    }

    /* Verify total memory does not exceed budget. */

    ulong total = 0UL;
    for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ ) {
      total += class_cnt[c] * fd_accdb_cache_slot_sz[c];
    }
    FD_TEST( total<=footprint );

    /* For the 32 GiB production budget, lock in the rebalancing intent:
       the 8K class (3) must comfortably hold the measured ~2K p99
       working set, and the cold large classes (5/6/7) stay bounded.

       Phase 1/2 reserve only ws_target slots for the cold classes, but
       Phase 3 then spends all leftover budget by access density across
       the classes that have not hit their pop_max cap.  Since the small
       classes (0/1/2) saturate at their huge pop_max first, the residual
       budget lands on the surviving uncapped classes, so the 128K class
       (5) grows well past its p99 working set.  This is intentional: the
       accounts database grows at runtime and the operator-provisioned
       budget should be fully used rather than left idle.  The bounds
       below assert the cold classes stay well under their pop_max caps
       (no runaway), not that they hug the p99 working set. */

    if( test_gb[t]==32UL ) {
      FD_TEST( class_cnt[3]>=2500UL  );  /* 8K   must fit p99 ws + headroom */
      FD_TEST( class_cnt[5]<=16384UL );  /* 128K bounded (~8.8K observed)   */
      FD_TEST( class_cnt[6]<=2048UL  );  /* 1M   bounded (~1.0K observed)   */
      FD_TEST( class_cnt[7]<=2048UL  );  /* 10M  bounded (~0.7K observed)   */
    }

    /* Log the allocation. */

    for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ ) {
      ulong mem_mib = class_cnt[c] *
                      fd_accdb_cache_slot_sz[c] / (1UL<<20);
      FD_LOG_NOTICE(( "  class %lu: %12lu slots  %8lu MiB",
                       c, class_cnt[c], mem_mib ));
    }
    FD_LOG_NOTICE(( "  total: %lu MiB / %lu MiB  (%.1f%% used)",
                     total/(1UL<<20), footprint/(1UL<<20),
                     100.0*(double)total/(double)footprint ));
  }

  /* Edge case: budget too small for the per-class minimums.  Should
     return failure and zero all class counts. */

  FD_TEST( !fd_accdb_cache_class_cnt( 1UL<<20, 640UL, class_cnt ) );
  for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ ) {
    FD_TEST( class_cnt[c]==0UL );
  }
  FD_LOG_NOTICE(( "1 MiB edge case: correctly returned failure" ));

  /* Compute the all-caps threshold: the cache size at which all
     classes would exactly hit their pop_max. */

  static const ulong pop_max[] = {
     215000000UL, 1041000000UL, 76000000UL, 8000000UL,
       4000000UL,     461000UL,   244000UL,    5000UL,
  };
  ulong all_caps_cost = 0UL;
  for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ )
    all_caps_cost += pop_max[c] * fd_accdb_cache_slot_sz[c];
  ulong all_caps_gib = all_caps_cost / (1UL<<30) + 1UL;
  FD_LOG_NOTICE(( "all-caps threshold: %lu GiB (%lu bytes)",
                   all_caps_gib, all_caps_cost ));

  /* Test at exactly the all-caps threshold.  Every class should
     be at or above its pop_max.  The allocator clamps each class's
     effective pop_max to FD_ACCDB_CACHE_LINE_MAX (the 29-bit cidx line
     index space — see fd_accdb_cache.c), since a class can never hold
     more distinct lines than the index can represent.  class 1's raw
     pop_max (1.041B) exceeds that ceiling, so mirror the same clamp
     here when checking. */

  FD_TEST( fd_accdb_cache_class_cnt( (all_caps_gib+1UL)*(1UL<<30), 640UL, class_cnt ) );
  FD_LOG_NOTICE(( "=== %lu GiB cache (all-caps+1) ===", all_caps_gib+1UL ));
  ulong total_caps = 0UL;
  for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ ) {
    FD_TEST( class_cnt[c]>=fd_ulong_min( pop_max[c], FD_ACCDB_CACHE_LINE_MAX ) );
    ulong mem_mib = class_cnt[c] * fd_accdb_cache_slot_sz[c] / (1UL<<20);
    FD_LOG_NOTICE(( "  class %lu: %12lu slots  %8lu MiB",
                     c, class_cnt[c], mem_mib ));
    total_caps += class_cnt[c] * fd_accdb_cache_slot_sz[c];
  }
  FD_TEST( total_caps<=(all_caps_gib+1UL)*(1UL<<30) );
  FD_LOG_NOTICE(( "  total: %lu MiB / %lu MiB  (%.1f%% used)",
                   total_caps/(1UL<<20),
                   (all_caps_gib+1UL)*(1UL<<30)/(1UL<<20),
                   100.0*(double)total_caps/
                   (double)((all_caps_gib+1UL)*(1UL<<30)) ));

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
