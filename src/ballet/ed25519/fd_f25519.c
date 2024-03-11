#include "fd_f25519.h"
#include "../hex/fd_hex.h"

#if FD_HAS_AVX512
#include "avx512/fd_f25519.c"
#else
#include "ref/fd_f25519.c"
#endif

/* fd_f25519_pow22523 computes r = a^(2^252-3), and returns r. */
fd_f25519_t *
fd_f25519_pow22523( fd_f25519_t *       r,
                    fd_f25519_t const * a ) {
  fd_f25519_t t0[1];
  fd_f25519_t t1[1];
  fd_f25519_t t2[1];

  fd_f25519_sqr( t0, a      );
  fd_f25519_sqr( t1, t0     );
  for( int i=1; i<  2; i++ ) fd_f25519_sqr( t1, t1 );

  fd_f25519_mul( t1, a,  t1 );
  fd_f25519_mul( t0, t0, t1 );
  fd_f25519_sqr( t0, t0     );
  fd_f25519_mul( t0, t1, t0 );
  fd_f25519_sqr( t1, t0     );
  for( int i=1; i<  5; i++ ) fd_f25519_sqr( t1, t1 );

  fd_f25519_mul( t0, t1, t0 );
  fd_f25519_sqr( t1, t0     );
  for( int i=1; i< 10; i++ ) fd_f25519_sqr( t1, t1 );

  fd_f25519_mul( t1, t1, t0 );
  fd_f25519_sqr( t2, t1     );
  for( int i=1; i< 20; i++ ) fd_f25519_sqr( t2, t2 );

  fd_f25519_mul( t1, t2, t1 );
  fd_f25519_sqr( t1, t1     );
  for( int i=1; i< 10; i++ ) fd_f25519_sqr( t1, t1 );

  fd_f25519_mul( t0, t1, t0 );
  fd_f25519_sqr( t1, t0     );
  for( int i=1; i< 50; i++ ) fd_f25519_sqr( t1, t1 );

  fd_f25519_mul( t1, t1, t0 );
  fd_f25519_sqr( t2, t1     );
  for( int i=1; i<100; i++ ) fd_f25519_sqr( t2, t2 );

  fd_f25519_mul( t1, t2, t1 );
  fd_f25519_sqr( t1, t1     );
  for( int i=1; i< 50; i++ ) fd_f25519_sqr( t1, t1 );

  fd_f25519_mul( t0, t1, t0 );
  fd_f25519_sqr( t0, t0     );
  for( int i=1; i<  2; i++ ) fd_f25519_sqr( t0, t0 );

  fd_f25519_mul(r, t0, a  );
  return r;
}

/* fd_f25519_inv computes r = 1/a, and returns r. */
fd_f25519_t *
fd_f25519_inv( fd_f25519_t *       r,
               fd_f25519_t const * a ) {
  fd_f25519_t t0[1];
  fd_f25519_t t1[1];
  fd_f25519_t t2[1];
  fd_f25519_t t3[1];

  /* Compute z**-1 = z**(2**255 - 19 - 2) with the exponent as
     2**255 - 21 = (2**5) * (2**250 - 1) + 11. */

  fd_f25519_sqr( t0,  a     );                        /* t0 = z**2 */
  fd_f25519_sqr( t1, t0     );
  fd_f25519_sqr( t1, t1     );                        /* t1 = t0**(2**2) = z**8 */
  fd_f25519_mul( t1,  a, t1 );                        /* t1 = z * t1 = z**9 */
  fd_f25519_mul( t0, t0, t1 );                        /* t0 = t0 * t1 = z**11 -- stash t0 away for the end. */
  fd_f25519_sqr( t2, t0     );                        /* t2 = t0**2 = z**22 */
  fd_f25519_mul( t1, t1, t2 );                        /* t1 = t1 * t2 = z**(2**5 - 1) */
  fd_f25519_sqr( t2, t1     );
  for( int i=1; i<  5; i++ ) fd_f25519_sqr( t2, t2 ); /* t2 = t1**(2**5) = z**((2**5) * (2**5 - 1)) */
  fd_f25519_mul( t1, t2, t1 );                        /* t1 = t1 * t2 = z**((2**5 + 1) * (2**5 - 1)) = z**(2**10 - 1) */
  fd_f25519_sqr( t2, t1     );
  for( int i=1; i< 10; i++ ) fd_f25519_sqr( t2, t2 );
  fd_f25519_mul( t2, t2, t1 );                        /* t2 = z**(2**20 - 1) */
  fd_f25519_sqr( t3, t2     );
  for( int i=1; i< 20; i++ ) fd_f25519_sqr( t3, t3 );
  fd_f25519_mul( t2, t3, t2 );                        /* t2 = z**(2**40 - 1) */
  for( int i=0; i< 10; i++ ) fd_f25519_sqr( t2, t2 ); /* t2 = z**(2**10) * (2**40 - 1) */
  fd_f25519_mul( t1, t2, t1 );                        /* t1 = z**(2**50 - 1) */
  fd_f25519_sqr( t2, t1     );
  for( int i=1; i< 50; i++ ) fd_f25519_sqr( t2, t2 );
  fd_f25519_mul( t2, t2, t1 );                        /* t2 = z**(2**100 - 1) */
  fd_f25519_sqr( t3, t2     );
  for( int i=1; i<100; i++ ) fd_f25519_sqr( t3, t3 );
  fd_f25519_mul( t2, t3, t2 );                        /* t2 = z**(2**200 - 1) */
  fd_f25519_sqr( t2, t2     );
  for( int i=1; i< 50; i++ ) fd_f25519_sqr( t2, t2 ); /* t2 = z**((2**50) * (2**200 - 1) */
  fd_f25519_mul( t1, t2, t1 );                        /* t1 = z**(2**250 - 1) */
  fd_f25519_sqr( t1, t1     );
  for( int i=1; i<  5; i++ ) fd_f25519_sqr( t1, t1 ); /* t1 = z**((2**5) * (2**250 - 1)) */
  return fd_f25519_mul( r, t1, t0 );                  /* Recall t0 = z**11; out = z**(2**255 - 21) */
}

/* fd_f25519_sqrt_ratio computes r = (u * v^3) * (u * v^7)^((p-5)/8),
   returns 0 on success, 1 on failure. */
int
fd_f25519_sqrt_ratio( fd_f25519_t *       r,
                      fd_f25519_t const * u,
                      fd_f25519_t const * v ) {
  /* r = (u * v^3) * (u * v^7)^((p-5)/8) */
  fd_f25519_t  v2[1]; fd_f25519_sqr(  v2, v      );
  fd_f25519_t  v3[1]; fd_f25519_mul(  v3, v2, v  );
  fd_f25519_t uv3[1]; fd_f25519_mul( uv3, u,  v3 );
  fd_f25519_t  v6[1]; fd_f25519_sqr(  v6, v3     );
  fd_f25519_t  v7[1]; fd_f25519_mul(  v7, v6, v  );
  fd_f25519_t uv7[1]; fd_f25519_mul( uv7, u,  v7 );
  fd_f25519_pow22523( r, uv7    );
  fd_f25519_mul     ( r, r, uv3 );

  /* check = v * r^2 */
  fd_f25519_t check[1];
  fd_f25519_sqr( check, r        );
  fd_f25519_mul( check, check, v );

  /* (correct_sign_sqrt)    check == u
     (flipped_sign_sqrt)    check == !u
     (flipped_sign_sqrt_i)  check == (!u * SQRT_M1) */
  fd_f25519_t u_neg[1];        fd_f25519_neg( u_neg,        u );
  fd_f25519_t u_neg_sqrtm1[1]; fd_f25519_mul( u_neg_sqrtm1, u_neg, fd_f25519_sqrtm1 );
  int correct_sign_sqrt   = fd_f25519_eq( check, u );
  int flipped_sign_sqrt   = fd_f25519_eq( check, u_neg );
  int flipped_sign_sqrt_i = fd_f25519_eq( check, u_neg_sqrtm1 );

  /* r_prime = SQRT_M1 * r */
  fd_f25519_t r_prime[1];
  fd_f25519_mul( r_prime, r, fd_f25519_sqrtm1 );

  /* r = CT_SELECT(r_prime IF flipped_sign_sqrt | flipped_sign_sqrt_i ELSE r) */
  fd_f25519_if( r, flipped_sign_sqrt|flipped_sign_sqrt_i, r_prime, r );
  fd_f25519_abs( r, r );
  return correct_sign_sqrt|flipped_sign_sqrt;
}
