#include <tango/dcache/fd_dcache.h>
#include <tango/fd_tango_base.h>

void
harness( void ) {
  /* Derive footprint for arbitrary input */

  ulong mtu;    /* unconstrained */
  ulong depth;  /* unconstrained */
  ulong burst;  /* unconstrained */
  int   compact = 1;

  ulong data_sz = fd_dcache_req_data_sz( mtu, depth, burst, compact );
  if( data_sz==0UL ) return;

  ulong data_headroom;  /* unconstrained */
  __CPROVER_assume( data_sz+data_headroom >= data_sz );

  ulong app_sz;  /* unconstrained */
  ulong footprint = fd_dcache_footprint( data_sz+data_headroom, app_sz );
  if( !footprint        ) return;
  if( footprint>INT_MAX ) return;

  /* Allocate dcache region */

  ulong offset;
  __CPROVER_assume( offset < (1UL<<24) );
  __CPROVER_assume( fd_ulong_is_aligned( offset, FD_DCACHE_ALIGN ) );
  __CPROVER_assume( offset+footprint >= footprint );

  uchar wksp[ offset+footprint ] __attribute__((aligned(FD_DCACHE_ALIGN)));
  __CPROVER_assume( (ulong)wksp <= 0xffffffffffffff );  /* 56-bit address space */
  void * dcache_mem = wksp + offset;
  void * dcache     = fd_dcache_join( fd_dcache_new( dcache_mem, data_sz+data_headroom, app_sz ) );
  __CPROVER_assert( dcache, "fd_dcache_new failed" );

  /* Verify app region */

  __CPROVER_assert( fd_dcache_app_sz( dcache )==app_sz,
                    "unexpected app sz" );

  uchar * app = fd_dcache_app_laddr( dcache );
  __CPROVER_rw_ok( app, app_sz );

  /* Verify data region */

  __CPROVER_assert( fd_dcache_data_sz( dcache )==data_sz,
                    "unexpected data sz" );

  ulong chunk0 = fd_dcache_compact_chunk0( wksp, dcache );
  ulong chunk1 = fd_dcache_compact_chunk1( wksp, dcache );
  ulong wmark  = fd_dcache_compact_wmark ( wksp, dcache, mtu );

  __CPROVER_assert( chunk0<=wmark && wmark<=chunk1, "chunk idx invariant" );
  __CPROVER_rw_ok( fd_chunk_to_laddr( wksp, chunk0 ), (chunk1-chunk0)*FD_CHUNK_SZ );

  /* Self-test compact ring */

  __CPROVER_assert( fd_dcache_compact_is_safe( wksp, dcache, mtu, depth ),
                    "compact ring self-test failed" );

  /* Verify compact_next */

  ulong frag0_chunk; __CPROVER_assume( frag0_chunk>=chunk0 && frag0_chunk<=wmark );
  ulong frag0_sz;    __CPROVER_assume( frag0_sz<=mtu );
  void * frag0_laddr = fd_chunk_to_laddr( wksp, frag0_chunk );
  __CPROVER_rw_ok( frag0_laddr, frag0_sz );

  ulong frag1_chunk = fd_dcache_compact_next( frag0_chunk, frag0_sz, chunk0, wmark );
  ulong frag1_sz;    __CPROVER_assume( frag1_sz<=mtu );
  void * frag1_laddr = fd_chunk_to_laddr( wksp, frag1_chunk );
  __CPROVER_rw_ok( frag1_laddr, frag1_sz );  /* new chunk in bounds */

  __CPROVER_assert( (ulong)frag0_laddr+frag0_sz <= (ulong)frag1_laddr,
                    "chunks overlap" );

  /* Clean up */

  fd_dcache_delete( fd_dcache_leave( dcache ) );
}
