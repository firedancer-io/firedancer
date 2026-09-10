#ifndef HEADER_fd_src_ballet_pcurves_fd_pcurve_ref_util_h
#define HEADER_fd_src_ballet_pcurves_fd_pcurve_ref_util_h

/* Helpers shared by the portable (fiat-crypto based) prime curve
   backends: src/ballet/secp256r1/fd_secp256r1_ref.c,
   src/ballet/secp384r1/fd_secp384r1_ref.c and
   src/ballet/secp256k1/fd_secp256k1_ref.c.

   These backends only ever operate on public data (ECDSA signature
   verification, public key recovery), so the code below is written
   for clarity over side channel resistance: the exponentiation table
   is indexed by exponent bits. */

#include "../fd_ballet_base.h"

/* fd_pcurve_ref_reduce_once computes r = a>=m ? a-m : a, where a, m
   and r are n little-endian 64-bit limbs.  r may alias a. */

static inline void
fd_pcurve_ref_reduce_once( ulong *       r,
                           ulong const * a,
                           ulong const * m,
                           ulong         n ) {
  ulong t[ 8 ];
  ulong borrow = 0UL;
  for( ulong i=0UL; i<n; i++ ) {
    ulong ai = a[ i ];
    ulong mi = m[ i ];
    ulong d0 = ai-mi;
    ulong b0 = (ulong)( ai<mi );
    ulong d1 = d0-borrow;
    ulong b1 = (ulong)( d0<borrow );
    t[ i ]   = d1;
    borrow   = b0|b1;
  }
  /* borrow set means a<m: keep a */
  for( ulong i=0UL; i<n; i++ ) r[ i ] = fd_ulong_if( (int)borrow, a[ i ], t[ i ] );
}

/* FD_PCURVE_REF_DEFINE_POW defines

     static inline void fn( ulong r[n], ulong const a[n], ulong const e[n] )

   computing r = a^e using the Montgomery domain multiplication mul,
   squaring sqr and constant one set_one (all fiat-crypto functions
   with signatures (out, in, in), (out, in) and (out)).  a is in the
   Montgomery domain and so is r; e is a plain little-endian integer.
   Fixed 4-bit window, MSB first.  r may alias a. */

#define FD_PCURVE_REF_DEFINE_POW( fn, n, mul, sqr, set_one )                       \
static inline void                                                                 \
fn( ulong       r[ n ],                                                            \
    ulong const a[ n ],                                                            \
    ulong const e[ n ] ) {                                                         \
  ulong tbl[ 16 ][ n ];                                                            \
  set_one( tbl[ 0 ] );                                                             \
  memcpy( tbl[ 1 ], a, sizeof(ulong)*(n) );                                        \
  for( ulong i=2UL; i<16UL; i++ ) mul( tbl[ i ], tbl[ i-1UL ], a );                \
  ulong acc[ n ];                                                                  \
  set_one( acc );                                                                  \
  for( long i=(long)((n)*64UL)-4L; i>=0L; i-=4L ) {                                \
    sqr( acc, acc ); sqr( acc, acc ); sqr( acc, acc ); sqr( acc, acc );            \
    ulong d = ( e[ i/64L ] >> (i%64L) ) & 15UL;                                    \
    mul( acc, acc, tbl[ d ] );                                                     \
  }                                                                                \
  memcpy( r, acc, sizeof(ulong)*(n) );                                             \
}

#endif /* HEADER_fd_src_ballet_pcurves_fd_pcurve_ref_util_h */
