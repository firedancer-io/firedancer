#include "fd_bls12_381.h"

#include <blst.h>

int
fd_bls12_381_g1_add_syscall( uchar       rr[48],
                             uchar const pp[48],
                             uchar const qq[48] ) {
  blst_p1_affine pa[1], qa[1];
  blst_p1 p[1], r[1];
  if( FD_UNLIKELY( blst_p1_uncompress( pa, pp )!=BLST_SUCCESS ) ) {
    return -1;
  }
  if( FD_UNLIKELY( blst_p1_uncompress( qa, qq )!=BLST_SUCCESS ) ) {
    return -1;
  }
  blst_p1_from_affine( p, pa );
  blst_p1_add_or_double_affine( r, p, qa );
  blst_p1_compress( rr, r );
  return 0;
}
