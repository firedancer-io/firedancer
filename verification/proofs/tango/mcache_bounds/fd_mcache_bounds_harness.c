#include <tango/mcache/fd_mcache.h>

void
harness( void ) {
  /* Derive footprint for arbitrary input */

  ulong depth;   /* unconstrained */
  ulong app_sz;  /* unconstrained */
  ulong footprint = fd_mcache_footprint( depth, app_sz );
  if( !footprint        ) return;
  if( footprint>INT_MAX ) return;

  /* Allocate mcache region */

  uchar mcache_mem[ footprint ] __attribute__((aligned(FD_MCACHE_ALIGN)));
  __CPROVER_assume( (ulong)mcache_mem <= 0xffffffffffffff );  /* 56-bit address space */

  /* Create mcache */

  ulong seq0;  /* unconstrained */
  fd_frag_meta_t * mcache = fd_mcache_join( fd_mcache_new( mcache_mem, depth, app_sz, seq0 ) );
  __CPROVER_assert( mcache, "fd_mcache_new failed" );

  __CPROVER_assert( fd_mcache_depth( mcache )==depth, "incorrect depth" );
  __CPROVER_assert( fd_mcache_seq0 ( mcache )==seq0,  "incorrect seq0"  );

  /* Verify seq region */

  ulong * seq = fd_mcache_seq_laddr( mcache );
  __CPROVER_rw_ok( seq, FD_MCACHE_SEQ_CNT*sizeof(ulong) );

  /* Verify app region */

  __CPROVER_assert( fd_mcache_app_sz( mcache )==app_sz,
                    "unexpected app sz" );

  uchar * app = fd_mcache_app_laddr( mcache );
  __CPROVER_rw_ok( app, app_sz );

  __CPROVER_assert( (ulong)(seq+FD_MCACHE_SEQ_CNT) <= (ulong)app,
                    "seq region overlaps app region" );

  /* Clean up */

  fd_mcache_delete( fd_mcache_leave( mcache ) );
}
