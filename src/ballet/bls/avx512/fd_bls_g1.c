#include "fd_bls_g1.h"
#include "fd_bls_field.h"
#include "fd_bls_miller.h"

#include "fd_bls_constants.h"

/* The G1 curve is y^2 = x^3 + 4, thus 3b = 12. */

/* Complete projective addition p += q.
   p and q are (X:Y:Z) triples.
   As it is complete, it handles all cases including doubling and the
   identitiy. */
void
fd_bls_g1_add( fd_bls_fp_t *       p,
               fd_bls_fp_t const * q ) {
  fd_bls_fp_wide_t w1[9];
  fd_bls_fp_wide_mul_raw( &w1[0], &q[0], &p[0] ); /* xqx = Xq*X */
  fd_bls_fp_wide_mul_raw( &w1[1], &q[0], &p[1] ); /* xqy = Xq*Y */
  fd_bls_fp_wide_mul_raw( &w1[2], &q[0], &p[2] ); /* xqz = Xq*Z */
  fd_bls_fp_wide_mul_raw( &w1[3], &q[1], &p[0] ); /* yqx = Yq*X */
  fd_bls_fp_wide_mul_raw( &w1[4], &q[1], &p[1] ); /* yqy = Yq*Y */
  fd_bls_fp_wide_mul_raw( &w1[5], &q[1], &p[2] ); /* yqz = Yq*Z */
  fd_bls_fp_wide_mul_raw( &w1[6], &p[0], &q[2] ); /* xzq = X*Zq */
  fd_bls_fp_wide_mul_raw( &w1[7], &p[1], &q[2] ); /* yzq = Y*Zq */
  fd_bls_fp_wide_mul_raw( &w1[8], &p[2], &q[2] ); /* zzq = Z*Zq */

  fd_bls_fp_t r1[9];
  fd_bls_fp_reduce_wide_batch9( r1, w1 );

  fd_bls_fp_t const * xqx=&r1[0], * xqy=&r1[1], * xqz=&r1[2];
  fd_bls_fp_t const * yqx=&r1[3], * yqy=&r1[4], * yqz=&r1[5];
  fd_bls_fp_t const * xzq=&r1[6], * yzq=&r1[7], * zzq=&r1[8];

  fd_bls_fp_t xysum, ym, yp, xzsum, yzsum, three_xx, b3_zzq, bx;
  fd_bls_fp_add( &xysum, xqy, yqx );         /* xysum    = XqY+YqX      */
  fd_bls_fp_mul_small( &b3_zzq, zzq, 12U );  /* b3_zzq   = 3b*Z*Zq, b=4 */
  fd_bls_fp_sub( &ym, yqy, &b3_zzq );        /* ym       = YqY-3bZZq    */
  fd_bls_fp_add( &yp, yqy, &b3_zzq );        /* yp       = YqY+3bZZq    */
  fd_bls_fp_add( &xzsum, xqz, xzq );         /* xzsum    = XqZ+XZq      */
  fd_bls_fp_add( &yzsum, yqz, yzq );         /* yzsum    = YqZ+YZq      */
  fd_bls_fp_mul_small( &three_xx, xqx, 3U ); /* three_xx = 3*Xq*X       */
  fd_bls_fp_mul_small( &bx, &xzsum, 12U );   /* bx       = 3b(XqZ+XZq)  */

  /* Three sums of two products and the reduction. */
  fd_bls_fp_wide_t w2[3];
  fd_bls_fp_wide_offset( &w2[0] );
  fd_bls_fp_wide_addmul( &w2[0], &xysum, &ym );       /* X3 = xysum*ym ...    */
  fd_bls_fp_wide_submul( &w2[0], &bx,    &yzsum );    /* ... - bx*yzsum       */
  fd_bls_fp_wide_offset( &w2[1] );
  fd_bls_fp_wide_addmul( &w2[1], &bx,    &three_xx ); /* Y3 = bx*three_xx ... */
  fd_bls_fp_wide_addmul( &w2[1], &yp,    &ym );       /* ... + yp*ym          */
  fd_bls_fp_wide_offset( &w2[2] );
  fd_bls_fp_wide_addmul( &w2[2], &yp,    &yzsum );    /* Z3 = yp*yzsum ...    */
  fd_bls_fp_wide_addmul( &w2[2], &xysum, &three_xx ); /* ... + xysum*three_xx */
  fd_bls_fp_reduce_wide_batch3( p, w2 );
}

static inline void
g1_madd_r1( fd_bls_fp_wide_t    w[5],
            fd_bls_fp_t const * p,
            fd_bls_fp_t const * q ) {
  fd_bls_fp_t sp, sq;
  fd_bls_fp_add( &sp, &p[0], &p[1] );            /* sp = X1+Y1     */
  fd_bls_fp_add( &sq, &q[0], &q[1] );            /* sq = x2+y2     */
  fd_bls_fp_wide_mul_raw( &w[0], &p[0], &q[0] ); /* t0 = X1*x2     */
  fd_bls_fp_wide_mul_raw( &w[1], &p[1], &q[1] ); /* t1 = Y1*y2     */
  fd_bls_fp_wide_mul_raw( &w[2], &sp,   &sq   ); /* (X1+Y1)(x2+y2) */
  fd_bls_fp_wide_mul_raw( &w[3], &p[2], &q[1] ); /* y2*Z1          */
  fd_bls_fp_wide_mul_raw( &w[4], &p[2], &q[0] ); /* x2*Z1          */
}

/* Round 2, frmo the reduced round 1 products r:
    X3 = t3*t1' - t4*Y3'
    Y3 = t1'*Z3' + Y3'*t0'
    Z3 = Z3'*t4 + t0'*t3
   with t3 = X1y2+x2Y1, t4 = y2Z1+Y1, Y3' = 3b(x2Z1+X1), t0' = 3t0,
   Z3' = t1+3bZ1, t1' = t1-3bZ1. */
static inline void
g1_madd_r2( fd_bls_fp_wide_t    w[3],
            fd_bls_fp_t const * p,
            fd_bls_fp_t const   r[5] ) {
  fd_bls_fp_t s01, t3, t4, y3, t0, t2, z3, t1;
  fd_bls_fp_add( &s01, &r[0], &r[1] );    /* s01 = t0+t1       */
  fd_bls_fp_sub( &t3, &r[2], &s01 );      /* t3  = X1y2+x2Y1   */
  fd_bls_fp_add( &t4, &r[3], &p[1] );     /* t4  = y2Z1+Y1     */
  fd_bls_fp_add( &y3, &r[4], &p[0] );     /* y3  = x2Z1+X1     */
  fd_bls_fp_mul_small( &y3, &y3, 12U );   /* Y3' = 3b(x2Z1+X1) */
  fd_bls_fp_mul_small( &t0, &r[0], 3U );  /* t0' = 3 X1x2      */
  fd_bls_fp_mul_small( &t2, &p[2], 12U ); /* t2  = 3b Z1       */
  fd_bls_fp_add( &z3, &r[1], &t2 );       /* Z3' = t1+3bZ1     */
  fd_bls_fp_sub( &t1, &r[1], &t2 );       /* t1' = t1-3bZ1     */

  fd_bls_fp_wide_offset( &w[0] );
  fd_bls_fp_wide_addmul( &w[0], &t3, &t1 ); /* X3 = t3*t1' ...  */
  fd_bls_fp_wide_submul( &w[0], &t4, &y3 ); /* ... - t4*Y3'     */
  fd_bls_fp_wide_offset( &w[1] );
  fd_bls_fp_wide_addmul( &w[1], &t1, &z3 ); /* Y3 = t1'*Z3' ... */
  fd_bls_fp_wide_addmul( &w[1], &y3, &t0 ); /* ... + Y3'*t0'    */
  fd_bls_fp_wide_offset( &w[2] );
  fd_bls_fp_wide_addmul( &w[2], &z3, &t4 ); /* Z3 = Z3'*t4 ...  */
  fd_bls_fp_wide_addmul( &w[2], &t0, &t3 ); /* ... + t0'*t3     */
}

/* Complete mixed addition acc += (xq, yq) (RCB Algorithm 8 with 3b = 12).
   Complete for any acc, q MUST NOT be the identity. */
static void
g1_madd( fd_bls_fp_t *       acc,
         fd_bls_fp_t const * q ) {
  fd_bls_fp_wide_t w1[5], w2[3];
  fd_bls_fp_t      r1[5];
  g1_madd_r1( w1, acc, q );
  fd_bls_fp_reduce_wide_batch5( r1, w1 );
  g1_madd_r2( w2, acc, r1 );
  fd_bls_fp_reduce_wide_batch3( acc, w2 );
}

/* Two mixed additions where the reductions are batched. */
static void
g1_madd2( fd_bls_fp_t *       a,
          fd_bls_fp_t const * qa,
          fd_bls_fp_t *       b,
          fd_bls_fp_t const * qb ) {
  fd_bls_fp_wide_t w1[10], w2[6];
  fd_bls_fp_t      r1[10], r2[6];
  g1_madd_r1( w1,   a, qa );
  g1_madd_r1( w1+5, b, qb );
  fd_bls_fp_reduce_wide_batch10( r1, w1 );
  g1_madd_r2( w2,   a, r1   );
  g1_madd_r2( w2+3, b, r1+5 );
  fd_bls_fp_reduce_wide_batch6( r2, w2 );
  a[0]=r2[0]; a[1]=r2[1]; a[2]=r2[2];
  b[0]=r2[3]; b[1]=r2[4]; b[2]=r2[5];
}

/* Sum public keys. Inputs that are not all affine (or the identity) use
   the sequential complete-add fallback.

   Fast as we use two independent mixed-add chains whose rounds share their
   reductions, only the final merge needs a complete projective
   addition. */
void
fd_bls_g1_sum_batch( fd_bls_pub_t *             out,
                     fd_bls_pub_t const * const pubs[],
                     ulong                      cnt ) {

  while( cnt && fd_bls_pub_is_inf( pubs[0] ) ) {
    pubs++;
    cnt--;
  }
  if( FD_UNLIKELY( !cnt ) ) {
    fd_memset( out, 0, sizeof(*out) );
    return;
  }

  int affine = 1;
  fd_bls_fp_t one; fd_bls_fp_one( &one );
  for( ulong i=0UL; i<cnt; i++ ) {
    affine &= fd_bls_fp_equal( &pubs[i]->z, &one ) | fd_bls_pub_is_inf( pubs[i] );
  }
  if( FD_UNLIKELY( !affine ) ) {
    fd_bls_pub_t acc = *pubs[0];
    for( ulong i=1UL; i<cnt; i++ ) {
      if( !fd_bls_pub_is_inf( pubs[i] ) ) fd_bls_g1_add( &acc.x, &pubs[i]->x );
    }
    *out = acc;
    return;
  }

  fd_bls_fp_t a[3] = { pubs[0]->x, pubs[0]->y, pubs[0]->z };
  ulong i = 1UL;
  while( i<cnt && fd_bls_pub_is_inf( pubs[i] ) ) i++;
  if( FD_UNLIKELY( i==cnt ) ) {
    out->x=a[0]; out->y=a[1]; out->z=a[2];
    return;
  }
  fd_bls_fp_t b[3] = { pubs[i]->x, pubs[i]->y, pubs[i]->z };
  i++;
  for(;;) {
    while( i<cnt && fd_bls_pub_is_inf( pubs[i] ) ) i++;
    if( i==cnt ) break;
    fd_bls_pub_t const * q0 = pubs[i++];
    while( i<cnt && fd_bls_pub_is_inf( pubs[i] ) ) i++;
    if( i==cnt ) { g1_madd( a, &q0->x ); break; }
    fd_bls_pub_t const * q1 = pubs[i++];
    g1_madd2( a, &q0->x, b, &q1->x );
  }
  fd_bls_g1_add( a, b );
  out->x=a[0]; out->y=a[1]; out->z=a[2];
}

/* Complete projective doubling.
   out may alias p. */
static void
g1_double( fd_bls_fp_t       * out,
           fd_bls_fp_t const * p ) {
  fd_bls_fp_wide_t w1[4];
  fd_bls_fp_wide_mul_raw( &w1[0], &p[1], &p[1] ); /* yy = Y^2 */
  fd_bls_fp_wide_mul_raw( &w1[1], &p[2], &p[2] ); /* zz = Z^2 */
  fd_bls_fp_wide_mul_raw( &w1[2], &p[0], &p[1] ); /* xy = X*Y */
  fd_bls_fp_wide_mul_raw( &w1[3], &p[1], &p[2] ); /* yz = Y*Z */

  fd_bls_fp_t r1[4];
  fd_bls_fp_reduce_wide_batch4( r1, w1 );

  fd_bls_fp_t const * yy=&r1[0], * zz=&r1[1], * xy=&r1[2], * yz=&r1[3];

  fd_bls_fp_t eight_yy, b3_zz, yy_plus_b3, b9_zz, yy_minus_b9, two_xy;
  fd_bls_fp_mul_small( &eight_yy, yy, 8U );  /* eight_yy    = 8Y^2      */
  fd_bls_fp_mul_small( &b3_zz, zz, 12U );    /* b3_zz       = 3bZ^2     */
  fd_bls_fp_add( &yy_plus_b3, yy, &b3_zz );  /* yy_plus_b3  = Y^2+3bZ^2 */
  fd_bls_fp_mul_small( &b9_zz, &b3_zz, 3U ); /* b9_zz       = 9bZ^2     */
  fd_bls_fp_sub( &yy_minus_b9, yy, &b9_zz ); /* yy_minus_b9 = Y^2-9bZ^2 */
  fd_bls_fp_mul_small( &two_xy, xy, 2U );    /* two_xy      = 2XY       */

  fd_bls_fp_wide_t w2[3];
  fd_bls_fp_wide_offset( &w2[0] );
  fd_bls_fp_wide_addmul( &w2[0], &yy_minus_b9, &two_xy );     /* X3 = (Y^2-9bZ^2)(2XY)           */
  fd_bls_fp_wide_offset( &w2[1] );
  fd_bls_fp_wide_addmul( &w2[1], &yy_minus_b9, &yy_plus_b3 ); /* Y3 = (Y^2-9bZ^2)(Y^2+3bZ^2) ... */
  fd_bls_fp_wide_addmul( &w2[1], &eight_yy, &b3_zz );         /* ... + (8Y^2)(3bZ^2)             */
  fd_bls_fp_wide_offset( &w2[2] );
  fd_bls_fp_wide_addmul( &w2[2], &eight_yy, yz );             /* Z3 = (8Y^2)(YZ)                 */
  fd_bls_fp_reduce_wide_batch3( out, w2 );
}

/* out = [-z]P where -z = 0xd201000000010000 */
static void
g1_times_minus_z( fd_bls_fp_t *       out,
                  fd_bls_fp_t const * p ) {
  static uint const runs[5] = { 2U, 3U, 9U, 32U, 16U };
  fd_bls_fp_t r[3] = { p[0], p[1], p[2] };
  g1_double( r, r );
  for( int i=0; i<5; i++ ) {
    fd_bls_g1_add( r, p );
    for( uint j=0U; j<runs[i]; j++ ) g1_double( r, r );
  }
  out[0]=r[0]; out[1]=r[1]; out[2]=r[2];
}

/* Scott's G1 test. sigma^2(P) == -[z^2]P = [-z]([-z]P)
   compared projectively, sigma^2(x,y) = (beta^2 x, y), so with
   [z^2]P = (X:Y:Z) the test is X == beta^2*x*Z and Y == -y*Z (Z!=0).
   P is affine. */
int
fd_bls_g1_in_g1_affine( fd_bls_fp_t const * x,
                        fd_bls_fp_t const * y ) {
  fd_bls_fp_t p[3] = { *x, *y }, t[3];
  fd_bls_fp_one( &p[2] );
  g1_times_minus_z( t, p );
  g1_times_minus_z( t, t );                  /* t  = [z^2]P = (X:Y:Z) */
  fd_bls_fp_t bx, rx, ry;
  fd_bls_fp_mul( &bx, &fd_bls_g1_beta2, x ); /* bx = beta^2 x         */
  fd_bls_fp_mul( &rx, &bx, &t[2] );          /* rx = beta^2*x*Z       */
  fd_bls_fp_mul( &ry, y, &t[2] );
  fd_bls_fp_neg( &ry, &ry );                 /* ry = -y*Z             */
  fd_bls_fp_t zero; fd_bls_fp_zero( &zero );
  if( FD_UNLIKELY( fd_bls_fp_equal( &t[2], &zero ) ) ) return 0;
  return fd_bls_fp_equal( &t[0], &rx ) & fd_bls_fp_equal( &t[1], &ry );
}

/* (p+1)/4 */
static ulong const fd_bls_sqrt_e[6] = {
  0xee7fbfffffffeaabUL, 0x07aaffffac54ffffUL, 0xd9cc34a83dac3d89UL,
  0xd91dd2e13ce144afUL, 0x92c6e9ed90d2eb35UL, 0x0680447a8e5ff9a6UL
};

/* Performs square root on Fp. p = 3 mod 4, so x^((p+1)/4) is a root iff
   x is a square. The exponentiation uses a width-5 sliding window.
   Writes the candidate root to out and returns whether it squares to x. */
int
fd_bls_fp_sqrt_rns( fd_bls_fp_t *       out,
                    fd_bls_fp_t const * x ) {
  fd_bls_fp_t tbl[16], x2, r;                  /* tbl[i] = x^(2i+1). */
  tbl[0] = *x;
  fd_bls_fp_mul( &x2, x, x );
  for( int i=1; i<16; i++ ) fd_bls_fp_mul( &tbl[i], &tbl[i-1], &x2 );

# define EBIT(b) ((int)( (fd_bls_sqrt_e[(b)>>6] >> ((b)&63)) & 1UL ))
  int b = 378, first = 1;
  while( b>=0 ) {
    if( !EBIT( b ) ) { fd_bls_fp_mul( &r, &r, &r ); b--; continue; }
    int lo = b-4 < 0 ? 0 : b-4; /* Window [lo,b], trimmed to end on a set bit. */
    while( !EBIT( lo ) ) lo++;
    int w = 0;
    for( int i=b; i>=lo; i-- ) w = (w<<1) | EBIT( i );
    if( first ) {
      r = tbl[ w>>1 ];
      first = 0;
    } else {
      for( int i=b; i>=lo; i-- ) fd_bls_fp_mul( &r, &r, &r );
      fd_bls_fp_mul( &r, &r, &tbl[ w>>1 ] );
    }
    b = lo-1;
  }
# undef EBIT
  fd_bls_fp_t sq; fd_bls_fp_mul( &sq, &r, &r );
  *out = r;
  return fd_bls_fp_equal( &sq, x );
}
