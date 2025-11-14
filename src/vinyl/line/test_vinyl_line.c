#include "../fd_vinyl.h"

FD_STATIC_ASSERT( FD_VINYL_LINE_EVICT_PRIO_MRU==0, unit_test );
FD_STATIC_ASSERT( FD_VINYL_LINE_EVICT_PRIO_LRU==1, unit_test );
FD_STATIC_ASSERT( FD_VINYL_LINE_EVICT_PRIO_UNC==2, unit_test );

FD_STATIC_ASSERT( FD_VINYL_LINE_MAX    ==(1UL<<32)-1UL, unit_test );
FD_STATIC_ASSERT( FD_VINYL_LINE_REF_MAX==(1L <<32)-2L,  unit_test );
FD_STATIC_ASSERT( FD_VINYL_LINE_VER_MAX==(1UL<<32)-1UL, unit_test );

#define LINE_CNT (10UL)

static uint ref_newer[ LINE_CNT ];
static uint ref_older[ LINE_CNT ];
static uint ref_lru;

static void
ref_evict_prio( ulong _line_idx,
                int   evict_prio ) {
  uint line_idx = (uint)_line_idx;

  if( evict_prio>=FD_VINYL_LINE_EVICT_PRIO_UNC ) return;

  uint newer = ref_newer[ line_idx ];
  uint older = ref_older[ line_idx ];

  ref_older[ newer ] = older;
  ref_newer[ older ] = newer;

  if( ref_lru==line_idx ) ref_lru = newer;

  newer =            ref_lru;
  older = ref_older[ ref_lru ];

  ref_newer[ older    ] = line_idx; ref_older[ line_idx ] = older;
  ref_older[ newer    ] = line_idx; ref_newer[ line_idx ] = newer;

  if( evict_prio==FD_VINYL_LINE_EVICT_PRIO_LRU ) ref_lru = line_idx;
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_rng_t rng[1]; fd_rng_join( fd_rng_new( rng, 0U, 0UL ) );

  fd_vinyl_line_t line[ LINE_CNT ];

  for( ulong line_idx=0UL; line_idx<LINE_CNT; line_idx++ ) {
    uint line_idx_newer = (uint)((line_idx +            1UL) % LINE_CNT);
    uint line_idx_older = (uint)((line_idx + LINE_CNT - 1UL) % LINE_CNT);
    line[ line_idx ].line_idx_newer = line_idx_newer; ref_newer[ line_idx ] = line_idx_newer;
    line[ line_idx ].line_idx_older = line_idx_older; ref_older[ line_idx ] = line_idx_older;
  }

  uint line_idx_lru = 0U; ref_lru = 0U;

  for( ulong rem=1000000UL; rem; rem-- ) {
    ulong r = fd_rng_ulong( rng );

    ulong ver = fd_vinyl_line_ctl_ver( r ); FD_TEST(              (ver<=FD_VINYL_LINE_VER_MAX) );
    long  ref = fd_vinyl_line_ctl_ref( r ); FD_TEST( (-1L<=ref) & (ref<=FD_VINYL_LINE_REF_MAX) );

    FD_TEST( fd_vinyl_line_ctl( ver, ref )==r );

    int   evict_prio = (int)(r & 7U) - 4; r >>= 3;
    ulong line_idx   = r % LINE_CNT;
    fd_vinyl_line_evict_prio( &line_idx_lru, line, LINE_CNT, line_idx, evict_prio );
    ref_evict_prio( line_idx, evict_prio );

    FD_TEST( line_idx_lru==ref_lru );
    for( ulong line_idx=0UL; line_idx<LINE_CNT; line_idx++ ) {
      FD_TEST( line[ line_idx ].line_idx_newer==ref_newer[ line_idx ] );
      FD_TEST( line[ line_idx ].line_idx_older==ref_older[ line_idx ] );
    }

    /* Note: it would be nice to test evict_lru here but needs data and
       meta.  Could maybe do unit test by setting ref randomly and obj
       to NULL and ele_idx to ULONG_MAX and then randomly evicting and
       matching it with a reference implementation.  But evict_lru is
       implicitly covered by higher level vinyl tests so probably isn't
       worth it. */

  }

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
