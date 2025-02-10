
#include <assert.h>
#include <stdlib.h>
#include <limits.h>

#define BUNDLE_L_PRIME 37896771UL
#define BUNDLE_N       312671UL


#define RC_TO_REL_BUNDLE_IDX( r, c ) (BUNDLE_N - ((ulong)r * 1UL<<32)/((ulong)c * BUNDLE_L_PRIME))
/* Returns 1 if x.rewards/x.compute < y.rewards/y.compute. Not robust. */
#define COMPARE_WORSE(ri,ci,rj,cj) ( ((ulong)(ri)*(ulong)(cj)) < ((ulong)(rj)*(ulong)(ci)) )

void
harness( void ) {
  /* Input */
  ulong relative_bundle_idx;
  ulong c0;
  ulong c1;
  // ulong c2;
  // ulong c3;
  // ulong c4;

  __CPROVER_assume( relative_bundle_idx <= BUNDLE_N );
  __CPROVER_assume( 1020 <= c0 && c0 <= 1556782);
  __CPROVER_assume( 1020 <= c1 && c1 <= 1556782);
  // __CPROVER_assume( 1020 <= c2 && c2 <= 1556782);
  // __CPROVER_assume( 1020 <= c3 && c3 <= 1556782);
  // __CPROVER_assume( 1020 <= c4 && c4 <= 1556782);

  ulong prev_reward = ((BUNDLE_L_PRIME * (BUNDLE_N - relative_bundle_idx))) - 1UL;
  ulong prev_cost = 1UL<<32;

  ulong r0 = (((ulong)c0 * (prev_reward + 1UL) + prev_cost-1UL)/prev_cost);   prev_reward = r0; prev_cost = c0;
  ulong r1 = (((ulong)c1 * (prev_reward + 1UL) + prev_cost-1UL)/prev_cost);   prev_reward = r1; prev_cost = c1;
  // ulong r2 = (((ulong)c2 * (prev_reward + 1UL) + prev_cost-1UL)/prev_cost);   prev_reward = r2; prev_cost = c2;
  // ulong r3 = (((ulong)c3 * (prev_reward + 1UL) + prev_cost-1UL)/prev_cost);   prev_reward = r3; prev_cost = c3;
  // ulong r4 = (((ulong)c4 * (prev_reward + 1UL) + prev_cost-1UL)/prev_cost);   prev_reward = r4; prev_cost = c4;


  __CPROVER_assert( r0 <= UINT_MAX, "overflow" );
  __CPROVER_assert( r1 <= UINT_MAX, "overflow" );
  // __CPROVER_assert( r2 <= UINT_MAX, "overflow" );
  // __CPROVER_assert( r3 <= UINT_MAX, "overflow" );
  // __CPROVER_assert( r4 <= UINT_MAX, "overflow" );

  __CPROVER_assert( !COMPARE_WORSE( r1, c1, r0, c0 ), "comparison" );
  // __CPROVER_assert( !COMPARE_WORSE( r2, c2, r1, c1 ), "comparison" );
  // __CPROVER_assert( !COMPARE_WORSE( r3, c3, r2, c2 ), "comparison" );
  // __CPROVER_assert( !COMPARE_WORSE( r4, c4, r3, c3 ), "comparison" );

  __CPROVER_assert( RC_TO_REL_BUNDLE_IDX( r0, c0 )==relative_bundle_idx, "bundle_idx" );
  __CPROVER_assert( RC_TO_REL_BUNDLE_IDX( r1, c1 )==relative_bundle_idx, "bundle_idx" );
  // __CPROVER_assert( RC_TO_REL_BUNDLE_IDX( r2, c2 )==relative_bundle_idx, "bundle_idx" );
  // __CPROVER_assert( RC_TO_REL_BUNDLE_IDX( r3, c3 )==relative_bundle_idx, "bundle_idx" );
  // __CPROVER_assert( RC_TO_REL_BUNDLE_IDX( r4, c4 )==relative_bundle_idx, "bundle_idx" );
}
