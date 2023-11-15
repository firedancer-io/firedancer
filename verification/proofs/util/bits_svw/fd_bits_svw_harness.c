#include <util/bits/fd_bits.h>
#include <string.h>

void
harness( void ) {
  ulong x;  /* unconstrained */
  ulong sz = fd_ulong_svw_enc_sz( x );
  __CPROVER_assert( sz<=FD_ULONG_SVW_ENC_MAX, "oversz encoding" );

  uchar b0[ sz ];
  uchar * b0_ = fd_ulong_svw_enc( b0, x );
  __CPROVER_assert( b0+sz==b0_, "enc retval" );

  uchar b1[ sz ];
  uchar * b1_ = fd_ulong_svw_enc_fixed( b1, sz, x );
  __CPROVER_assert( b1+sz==b1_, "enc_fixed retval" );

  __CPROVER_assert( 0==memcmp( b0, b1, sz ), "enc mismatch" );

  ulong sz_ = fd_ulong_svw_dec_sz( b0 );
  __CPROVER_assert( sz==sz_, "dec sz" );
  ulong x0 = fd_ulong_svw_dec_fixed( b0, sz );
  __CPROVER_assert( x==x0, "dec corrupt" );
}
