#include "fd_f25519.h"
#include "../hex/fd_hex.h"

#if FD_HAS_AVX512
#include "avx512/fd_f25519.c"
#else
#include "ref/fd_f25519.c"
#endif

#ifdef FD_HAS_S2NBIGNUM
#include <stdint.h>
#include "../../third_party/s2n-bignum/include/s2n-bignum.h"
#include "../../util/sanitize/fd_msan.h"
#endif

void
fd_f25519_debug( char const * name,
                 fd_f25519_t const * a ) {
  char *
  fd_hex_encode( char *       FD_RESTRICT dst,
                 void const * FD_RESTRICT src,
                 ulong                    sz );
  uchar out[ 32 ];
  char buf[ 65 ] = { 0 };
  fd_f25519_tobytes( out, a );
  fd_hex_encode( buf, out, 32UL );
  FD_LOG_WARNING(( "%s: %s", name, buf ));
  FD_LOG_HEXDUMP_WARNING(( name, a, sizeof(fd_f25519_t) ));
}

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

#ifdef FD_HAS_S2NBIGNUM

/* fd_f25519_inv computes r = 1/a, and returns r. */
fd_f25519_t *
fd_f25519_inv( fd_f25519_t *       r,
               fd_f25519_t const * a ) {
  ulong x[ 4 ];
  ulong z[ 4 ];
  fd_f25519_tobytes( (uchar *)x, a );
  bignum_inv_p25519( z, x );
  fd_msan_unpoison( z, 32UL );
  return fd_f25519_frombytes( r, (uchar const *)z );
}

#else

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

#endif /* FD_HAS_S2NBIGNUM */

/* Variable time Jacobi symbol mod p, a port of
   secp256k1_jacobi64_maybe_var from libsecp256k1 v0.7.1
   (src/modinv64_impl.h, MIT license, see NOTICE).  It runs Bernstein-
   Yang "posdivsteps" in batches of 62 on numbers stored as 5 signed
   62-bit limbs, tracking the sign of the Jacobi symbol (g|f) from f mod
   8 and g mod 4.  See doc/safegcd_implementation.md in libsecp256k1. */

#define FD_F25519_M62 (ULONG_MAX>>2)

/* fd_f25519_posdivsteps_62_var runs 62 posdivsteps on f,g given their
   bottom 64 bits f0,g0 and returns the new eta.  t is set to the
   transition matrix [u,v,q,r] scaled by 2^62.  Bit 0 of *jac is flipped
   iff the Jacobi symbol (g|f) changes sign. */

static long
fd_f25519_posdivsteps_62_var( long  eta,
                              ulong f0,
                              ulong g0,
                              long  t[ 4 ],
                              int * jac ) {
  ulong u = 1UL, v = 0UL, q = 0UL, r = 1UL;
  ulong f = f0, g = g0;
  int   i = 62;
  int   j = *jac;

  for(;;) {
    /* Divide g by 2 as often as possible (at most i times).  When
       dividing by an odd power of 2, the symbol flips if f mod 8 is 3
       or 5. */
    int zeros = fd_ulong_find_lsb( g | (ULONG_MAX << i) );
    g   >>= zeros;
    u   <<= zeros;
    v   <<= zeros;
    eta  -= zeros;
    i    -= zeros;
    j    ^= (int)( (ulong)zeros & ((f>>1) ^ (f>>2)) );
    if( !i ) break;

    ulong m;
    ulong w;
    int   limit;
    if( eta<0L ) {
      /* Swap f,g.  The symbol flips if both are 3 mod 4.  Then cancel
         up to 6 bottom bits of g with a multiple of f. */
      ulong tmp;
      eta = -eta;
      tmp = f; f = g; g = tmp;
      tmp = u; u = q; q = tmp;
      tmp = v; v = r; r = tmp;
      j    ^= (int)( (f & g)>>1 );
      limit = fd_int_min( (int)eta+1, i );
      m     = (ULONG_MAX >> (64-limit)) & 63UL;
      w     = (f*g*(f*f-2UL)) & m;
    } else {
      /* Cancel up to 4 bottom bits of g with a multiple of f. */
      limit = fd_int_min( (int)eta+1, i );
      m     = (ULONG_MAX >> (64-limit)) & 15UL;
      w     = f + (((f+1UL) & 4UL)<<1);
      w     = (-w*g) & m;
    }
    g += f*w;
    q += u*w;
    r += v*w;
  }

  t[0] = (long)u; t[1] = (long)v; t[2] = (long)q; t[3] = (long)r;
  *jac = j;
  return eta;
}

/* fd_f25519_update_fg_62_var computes [f,g] = t [f,g] / 2^62 on the
   bottom len limbs of f and g. */

static void
fd_f25519_update_fg_62_var( int        len,
                            long *     f,
                            long *     g,
                            long const t[ 4 ] ) {
  long const u = t[0], v = t[1], q = t[2], r = t[3];
  int128 cf = (int128)u*(int128)f[0] + (int128)v*(int128)g[0];
  int128 cg = (int128)q*(int128)f[0] + (int128)r*(int128)g[0];
  cf >>= 62;
  cg >>= 62;
  for( int i=1; i<len; i++ ) {
    cf += (int128)u*(int128)f[i] + (int128)v*(int128)g[i];
    cg += (int128)q*(int128)f[i] + (int128)r*(int128)g[i];
    f[i-1] = (long)( (ulong)cf & FD_F25519_M62 ); cf >>= 62;
    g[i-1] = (long)( (ulong)cg & FD_F25519_M62 ); cg >>= 62;
  }
  f[len-1] = (long)cf;
  g[len-1] = (long)cg;
}

/* fd_f25519_jacobi_var returns the Jacobi symbol (x|p) in {-1,1} for x
   in [1,p) given as 5 non-negative 62-bit limbs, or 0 if it did not
   converge within 25*62 posdivsteps (never observed for random input,
   typically ~12 batches are needed). */

static int
fd_f25519_jacobi_var( long const x[ 5 ] ) {
  long f[5] = { (1L<<62)-19L, (1L<<62)-1L, (1L<<62)-1L, (1L<<62)-1L, 127L }; /* p */
  long g[5] = { x[0], x[1], x[2], x[3], x[4] };
  int  len  = 5;
  long eta  = -1L;
  int  jac  = 0;

  for( int cnt=0; cnt<25; cnt++ ) {
    long t[4];
    eta = fd_f25519_posdivsteps_62_var( eta, (ulong)f[0] | ((ulong)f[1]<<62), (ulong)g[0] | ((ulong)g[1]<<62), t, &jac );
    fd_f25519_update_fg_62_var( len, f, g, t );

    /* Done when f==1 */
    if( f[0]==1L ) {
      long hi = 0L;
      for( int j=1; j<len; j++ ) hi |= f[j];
      if( !hi ) return 1 - 2*(jac & 1);
    }

    /* Drop the top limb when it is zero in both f and g */
    if( len>1 && !(f[len-1] | g[len-1]) ) len--;
  }
  return 0;
}

int
fd_f25519_is_square_var( fd_f25519_t const * a ) {
  uchar buf[32];
  fd_f25519_tobytes( buf, a ); /* canonical, in [0,p) */
  ulong a0 = fd_ulong_load_8_fast( buf    );
  ulong a1 = fd_ulong_load_8_fast( buf+ 8 );
  ulong a2 = fd_ulong_load_8_fast( buf+16 );
  ulong a3 = fd_ulong_load_8_fast( buf+24 );
  if( FD_UNLIKELY( !(a0|a1|a2|a3) ) ) return 1;

  long x[5] = { (long)(   a0                   & FD_F25519_M62 ),
                (long)( ((a0>>62) | (a1<< 2)) & FD_F25519_M62 ),
                (long)( ((a1>>60) | (a2<< 4)) & FD_F25519_M62 ),
                (long)( ((a2>>58) | (a3<< 6)) & FD_F25519_M62 ),
                (long)(   a3>>56                               ) };
  int jac = fd_f25519_jacobi_var( x );
  if( FD_UNLIKELY( !jac ) ) {
    /* Did not converge: a is a nonzero square iff sqrt(a/1) exists */
    fd_f25519_t r[1];
    return fd_f25519_sqrt_ratio( r, a, fd_f25519_one );
  }
  return jac>0;
}

#undef FD_F25519_M62

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
