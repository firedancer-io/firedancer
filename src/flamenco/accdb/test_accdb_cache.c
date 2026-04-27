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

    int ok = fd_accdb_cache_class_cnt( footprint, class_cnt );

    FD_LOG_NOTICE(( "=== %lu GiB cache === (%s)", test_gb[t],
                     ok ? "ok" : "too small" ));

    if( !ok ) {
      for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ )
        FD_TEST( class_cnt[c]==0UL );
      continue;
    }

    /* Verify every class has at least the FD_ACCDB_CACHE_MIN_RESERVED
       minimum. */

    for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ ) {
      FD_TEST( class_cnt[c]>=FD_ACCDB_CACHE_MIN_RESERVED );
    }

    /* Verify total memory does not exceed budget. */

    ulong total = 0UL;
    for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ ) {
      total += class_cnt[c] * fd_accdb_cache_slot_sz[c];
    }
    FD_TEST( total<=footprint );

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

  FD_TEST( !fd_accdb_cache_class_cnt( 1UL<<20, class_cnt ) );
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
     be at or above its pop_max. */

  FD_TEST( fd_accdb_cache_class_cnt( (all_caps_gib+1UL)*(1UL<<30), class_cnt ) );
  FD_LOG_NOTICE(( "=== %lu GiB cache (all-caps+1) ===", all_caps_gib+1UL ));
  ulong total_caps = 0UL;
  for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ ) {
    FD_TEST( class_cnt[c]>=pop_max[c] );
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
