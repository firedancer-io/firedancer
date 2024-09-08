#include <tango/dcache/fd_dcache.h>
#include <tango/fd_tango_base.h>

void
harness( void ) {
  ulong mtu;    /* unconstrained */
  ulong depth;  /* unconstrained */
  ulong burst;  /* unconstrained */
  int   compact = 1;

  ulong data_sz = fd_dcache_req_data_sz( mtu, depth, burst, compact );
  if( data_sz==0UL ) return;

  ulong chunk_off;
  __CPROVER_assume( chunk_off<=UINT_MAX );

  ulong chunk0    = chunk_off;
  ulong chunk1    = chunk_off + (data_sz >> FD_CHUNK_LG_SZ);
  ulong chunk_mtu = ((mtu + 2UL*FD_CHUNK_SZ-1UL) >> (1+FD_CHUNK_LG_SZ)) << 1;
  ulong wmark     = chunk1 - chunk_mtu;
  __CPROVER_assume( chunk_off<=chunk0 && chunk0<=chunk1 );

  /* Verify compact_next */

  ulong frag0_chunk; __CPROVER_assume( frag0_chunk>=chunk0 && frag0_chunk<=wmark );
  ulong frag0_sz;    __CPROVER_assume( frag0_sz<=mtu );
  ulong frag1_chunk = fd_dcache_compact_next( frag0_chunk, frag0_sz, chunk0, wmark );
  __CPROVER_assert( frag1_chunk>=chunk0 && frag1_chunk<=wmark, "bounds" );
}
