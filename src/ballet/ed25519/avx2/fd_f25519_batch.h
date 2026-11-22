#ifndef HEADER_fd_src_ballet_ed25519_avx2_fd_f25519_batch_h
#define HEADER_fd_src_ballet_ed25519_avx2_fd_f25519_batch_h

/* Four independent field operations in the four AVX2 ulong lanes.  Keep
   the public five-limb representation and split each limb into radix
   2^26, 2^25 digits only inside these operations.

   Fiat's loose input bound is 3*2^51 per limb.  Thus even digits are less
   than 2^26 and odd digits are at most 3*2^25.  A product of two odd digits
   has an extra factor of two; terms wrapping past digit nine have a
   factor of 19 because 2^255 = 19 (mod p).  The largest accumulator is
   less than 2018*2^50, so all accumulation fits in ulong lanes.

   All input limbs are loaded before any output is stored.  The loop
   bounds and instruction sequence do not depend on field values.
   These public-data helpers do not clear stack scratch; secret-bearing
   curve operations retain the scalar field helpers. */

#include "../../../util/simd/fd_avx.h"

FD_25519_INLINE void
fd_f25519_avx2_load( wv_t a[10],
                     fd_f25519_t const * a0,
                     fd_f25519_t const * a1,
                     fd_f25519_t const * a2,
                     fd_f25519_t const * a3 ) {
  wv_t x[5];
  wv_transpose_4x4( wv_ldu( a0->el ), wv_ldu( a1->el ), wv_ldu( a2->el ),
                    a3 ? wv_ldu( a3->el ) : wv_zero(), x[0], x[1], x[2], x[3] );
  x[4] = wv( a0->el[4], a1->el[4], a2->el[4], a3 ? a3->el[4] : 0UL );
  for( int i=0; i<5; i++ ) {
    a[2*i  ] = wv_and( x[i], wv_bcast( 0x3ffffffUL ) );
    a[2*i+1] = wv_shr( x[i], 26 );
  }
}

FD_25519_INLINE wv_t
fd_f25519_avx2_times19( wv_t x ) {
  return wv_add( wv_add( x, wv_shl( x, 1 ) ), wv_shl( x, 4 ) );
}

FD_25519_INLINE void
fd_f25519_avx2_store( fd_f25519_t * r0,
                      fd_f25519_t * r1,
                      fd_f25519_t * r2,
                      fd_f25519_t * r3,
                      wv_t h[10] ) {
  wv_t mask26 = wv_bcast( 0x3ffffffUL );
  wv_t mask25 = wv_bcast( 0x1ffffffUL );
  for( int i=0; i<8; i+=2 ) {
    h[i+1] = wv_add( h[i+1], wv_shr( h[i],   26 ) );
    h[i  ] = wv_and( h[i  ], mask26 );
    h[i+2] = wv_add( h[i+2], wv_shr( h[i+1], 25 ) );
    h[i+1] = wv_and( h[i+1], mask25 );
  }
  h[9] = wv_add( h[9], wv_shr( h[8], 26 ) );
  h[8] = wv_and( h[8], mask26 );
  h[0] = wv_add( h[0], fd_f25519_avx2_times19( wv_shr( h[9], 25 ) ) );
  h[9] = wv_and( h[9], mask25 );
  h[1] = wv_add( h[1], wv_shr( h[0], 26 ) );
  h[0] = wv_and( h[0], mask26 );
  h[2] = wv_add( h[2], wv_shr( h[1], 25 ) );
  h[1] = wv_and( h[1], mask25 );

  /* The final carry into h[2] is at most one.  h[2] may equal 2^26,
     so recombine by addition, not OR.  Each result limb is <=2^51,
     matching Fiat's inclusive tight bound. */
  wv_t x[5];
  for( int i=0; i<5; i++ ) x[i] = wv_add( h[2*i], wv_shl( h[2*i+1], 26 ) );
  wv_transpose_4x4( x[0], x[1], x[2], x[3], x[0], x[1], x[2], x[3] );
  wv_stu( r0->el, x[0] );
  wv_stu( r1->el, x[1] );
  wv_stu( r2->el, x[2] );
  if( r3 ) wv_stu( r3->el, x[3] );
  r0->el[4] = wv_extract( x[4], 0 );
  r1->el[4] = wv_extract( x[4], 1 );
  r2->el[4] = wv_extract( x[4], 2 );
  if( r3 ) r3->el[4] = wv_extract( x[4], 3 );
}

#define FD_F25519_AVX2_SUM2(a,b) wv_add( (a), (b) )
#define FD_F25519_AVX2_SUM3(a,b,c) wv_add( FD_F25519_AVX2_SUM2( a,b ), (c) )
#define FD_F25519_AVX2_SUM4(a,b,c,d) wv_add( FD_F25519_AVX2_SUM2( a,b ), FD_F25519_AVX2_SUM2( c,d ) )
#define FD_F25519_AVX2_SUM5(a,b,c,d,e) \
  wv_add( wv_add( wv_add( (a), (b) ), wv_add( (c), (d) ) ), (e) )
#define FD_F25519_AVX2_SUM6(a,b,c,d,e,f) \
  wv_add( wv_add( wv_add( (a), (b) ), wv_add( (c), (d) ) ), wv_add( (e), (f) ) )
#define FD_F25519_AVX2_SUM7(a,b,c,d,e,f,g) wv_add( FD_F25519_AVX2_SUM4( a,b,c,d ), FD_F25519_AVX2_SUM3( e,f,g ) )
#define FD_F25519_AVX2_SUM8(a,b,c,d,e,f,g,h) wv_add( FD_F25519_AVX2_SUM4( a,b,c,d ), FD_F25519_AVX2_SUM4( e,f,g,h ) )
#define FD_F25519_AVX2_SUM9(a,b,c,d,e,f,g,h,i) wv_add( FD_F25519_AVX2_SUM5( a,b,c,d,e ), FD_F25519_AVX2_SUM4( f,g,h,i ) )
#define FD_F25519_AVX2_SUM10(a,b,c,d,e,f,g,h,i,j) \
  wv_add( FD_F25519_AVX2_SUM5( a,b,c,d,e ), FD_F25519_AVX2_SUM5( f,g,h,i,j ) )

FD_25519_INLINE void
fd_f25519_avx2_mul( fd_f25519_t * r0, fd_f25519_t const * a0, fd_f25519_t const * b0,
                    fd_f25519_t * r1, fd_f25519_t const * a1, fd_f25519_t const * b1,
                    fd_f25519_t * r2, fd_f25519_t const * a2, fd_f25519_t const * b2,
                    fd_f25519_t * r3, fd_f25519_t const * a3, fd_f25519_t const * b3 ) {
  wv_t a[10], b[10], h[10];
  fd_f25519_avx2_load( a, a0, a1, a2, a3 );
  fd_f25519_avx2_load( b, b0, b1, b2, b3 );
  /* Sum the wrapped products before multiplying by 19.  This is the
     same convolution, with nine fewer live input vectors than keeping
     19*b[j].  The unscaled sums and their products by 19 fit in ulong. */
#define M(i,j) wv_mul_ll( wv_shl( a[i], (i)&(j)&1 ), b[j] )
  h[0] = wv_add( M(0,0),
                  fd_f25519_avx2_times19( FD_F25519_AVX2_SUM9( M(1,9), M(2,8), M(3,7), M(4,6), M(5,5), M(6,4), M(7,3), M(8,2), M(9,1) ) ) );
  h[1] = wv_add( FD_F25519_AVX2_SUM2( M(0,1), M(1,0) ),
                  fd_f25519_avx2_times19( FD_F25519_AVX2_SUM8( M(2,9), M(3,8), M(4,7), M(5,6), M(6,5), M(7,4), M(8,3), M(9,2) ) ) );
  h[2] = wv_add( FD_F25519_AVX2_SUM3( M(0,2), M(1,1), M(2,0) ),
                  fd_f25519_avx2_times19( FD_F25519_AVX2_SUM7( M(3,9), M(4,8), M(5,7), M(6,6), M(7,5), M(8,4), M(9,3) ) ) );
  h[3] = wv_add( FD_F25519_AVX2_SUM4( M(0,3), M(1,2), M(2,1), M(3,0) ),
                  fd_f25519_avx2_times19( FD_F25519_AVX2_SUM6( M(4,9), M(5,8), M(6,7), M(7,6), M(8,5), M(9,4) ) ) );
  h[4] = wv_add( FD_F25519_AVX2_SUM5( M(0,4), M(1,3), M(2,2), M(3,1), M(4,0) ),
                  fd_f25519_avx2_times19( FD_F25519_AVX2_SUM5( M(5,9), M(6,8), M(7,7), M(8,6), M(9,5) ) ) );
  h[5] = wv_add( FD_F25519_AVX2_SUM6( M(0,5), M(1,4), M(2,3), M(3,2), M(4,1), M(5,0) ),
                  fd_f25519_avx2_times19( FD_F25519_AVX2_SUM4( M(6,9), M(7,8), M(8,7), M(9,6) ) ) );
  h[6] = wv_add( FD_F25519_AVX2_SUM7( M(0,6), M(1,5), M(2,4), M(3,3), M(4,2), M(5,1), M(6,0) ),
                  fd_f25519_avx2_times19( FD_F25519_AVX2_SUM3( M(7,9), M(8,8), M(9,7) ) ) );
  h[7] = wv_add( FD_F25519_AVX2_SUM8( M(0,7), M(1,6), M(2,5), M(3,4), M(4,3), M(5,2), M(6,1), M(7,0) ),
                  fd_f25519_avx2_times19( FD_F25519_AVX2_SUM2( M(8,9), M(9,8) ) ) );
  h[8] = wv_add( FD_F25519_AVX2_SUM9( M(0,8), M(1,7), M(2,6), M(3,5), M(4,4), M(5,3), M(6,2), M(7,1), M(8,0) ),
                  fd_f25519_avx2_times19( M(9,9) ) );
  h[9] = FD_F25519_AVX2_SUM10( M(0,9), M(1,8), M(2,7), M(3,6), M(4,5), M(5,4), M(6,3), M(7,2), M(8,1), M(9,0) );
#undef M
  fd_f25519_avx2_store( r0, r1, r2, r3, h );
}

FD_25519_INLINE void
fd_f25519_avx2_sqr( fd_f25519_t * r0, fd_f25519_t const * a0,
                    fd_f25519_t * r1, fd_f25519_t const * a1,
                    fd_f25519_t * r2, fd_f25519_t const * a2,
                    fd_f25519_t * r3, fd_f25519_t const * a3 ) {
  wv_t a[10], a19[10], h[10];
  fd_f25519_avx2_load( a, a0, a1, a2, a3 );
  for( int i=5; i<10; i++ ) a19[i] = fd_f25519_avx2_times19( a[i] );

  /* Fold symmetric terms together: 55 products instead of 100.  The
     first operand is at most 4*(3*2^25), and the second is below 2^31.
     Splitting the factors this way avoids truncating a coefficient-76
     product before the 32x32->64 multiplication. */
#define S(i,j) wv_mul_ll( wv_shl( a[i], ((i)&(j)&1)+((i)!=(j)) ), (i)+(j)>=10 ? a19[j] : a[j] )
  h[0] = FD_F25519_AVX2_SUM6( S(0,0), S(1,9), S(2,8), S(3,7), S(4,6), S(5,5) );
  h[1] = FD_F25519_AVX2_SUM5( S(0,1), S(2,9), S(3,8), S(4,7), S(5,6) );
  h[2] = FD_F25519_AVX2_SUM6( S(0,2), S(1,1), S(3,9), S(4,8), S(5,7), S(6,6) );
  h[3] = FD_F25519_AVX2_SUM5( S(0,3), S(1,2), S(4,9), S(5,8), S(6,7) );
  h[4] = FD_F25519_AVX2_SUM6( S(0,4), S(1,3), S(2,2), S(5,9), S(6,8), S(7,7) );
  h[5] = FD_F25519_AVX2_SUM5( S(0,5), S(1,4), S(2,3), S(6,9), S(7,8) );
  h[6] = FD_F25519_AVX2_SUM6( S(0,6), S(1,5), S(2,4), S(3,3), S(7,9), S(8,8) );
  h[7] = FD_F25519_AVX2_SUM5( S(0,7), S(1,6), S(2,5), S(3,4), S(8,9) );
  h[8] = FD_F25519_AVX2_SUM6( S(0,8), S(1,7), S(2,6), S(3,5), S(4,4), S(9,9) );
  h[9] = FD_F25519_AVX2_SUM5( S(0,9), S(1,8), S(2,7), S(3,6), S(4,5) );
#undef S
  fd_f25519_avx2_store( r0, r1, r2, r3, h );
}

#undef FD_F25519_AVX2_SUM2
#undef FD_F25519_AVX2_SUM3
#undef FD_F25519_AVX2_SUM4
#undef FD_F25519_AVX2_SUM5
#undef FD_F25519_AVX2_SUM6
#undef FD_F25519_AVX2_SUM7
#undef FD_F25519_AVX2_SUM8
#undef FD_F25519_AVX2_SUM9
#undef FD_F25519_AVX2_SUM10

#endif /* HEADER_fd_src_ballet_ed25519_avx2_fd_f25519_batch_h */
