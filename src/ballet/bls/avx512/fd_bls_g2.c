/* Shared projective G2 arithmetic used by subgroup validation, hash-to-curve,
   and the Miller loop. */

#include "fd_bls_g2.h"

#include "fd_bls_constants.h"

uint const fd_bls_miller_iterations[5] = { 2U, 3U, 9U, 32U, 16U };


/* Line-free complete homogeneous doubling (double_step minus the Miller
   tangent evaluation).  Pure EC work: X^2 and the two line products are
   never formed, so round 1 reduces four products and round 2 three. */
void
fd_bls_g2_double( fd_bls_p2_projective_t *       out,
                  fd_bls_p2_projective_t const * p,
                  int                            first ) {
  fd_bls_fp2_t round1[4];
  if( FD_UNLIKELY( first ) ) {
    fd_bls_fp2_wide_t wide1[2];
    fd_bls_fp2_t reduced[2];
    fd_bls_fp2_wide_set_mul( &wide1[0], &p->y, &p->y ); /* Y^2. */
    fd_bls_fp2_wide_set_mul( &wide1[1], &p->x, &p->y ); /* X*Y. */
    fd_bls_fp2_reduce_batch2( reduced, wide1 );
    round1[0]=reduced[0]; round1[1]=p->z;        /* yy=Y^2, zz=Z^2=1. */
    round1[2]=reduced[1]; round1[3]=p->y;        /* xy=X*Y, yz=Y*Z=Y. */
  } else {
    fd_bls_fp2_wide_t wide1[4];
    fd_bls_fp2_wide_set_mul( &wide1[0], &p->y, &p->y ); /* Y^2. */
    fd_bls_fp2_wide_set_mul( &wide1[1], &p->z, &p->z ); /* Z^2. */
    fd_bls_fp2_wide_set_mul( &wide1[2], &p->x, &p->y ); /* X*Y. */
    fd_bls_fp2_wide_set_mul( &wide1[3], &p->y, &p->z ); /* Y*Z. */
    fd_bls_fp_reduce_wide_batch8( &round1[0].c[0], &wide1[0].c[0] );
  }
  fd_bls_fp2_t const * yy=&round1[0], * zz=&round1[1];
  fd_bls_fp2_t const * xy=&round1[2], * yz=&round1[3];

  fd_bls_fp2_t eight_yy, b3_zz, yy_plus_b3, b9_zz, yy_minus_b9, two_xy;
  fd_bls_fp2_mul_small( &eight_yy, yy, 8U );            /* eight_yy  = 8Y^2.      */
  fd_bls_fp2_mul_3b( &b3_zz, zz );                      /* b3_zz     = 3bZ^2.     */
  fd_bls_fp2_add( &yy_plus_b3, yy, &b3_zz );     /* yy_plus_b3 = Y^2+3bZ^2. */
  fd_bls_fp2_mul_small( &b9_zz, &b3_zz, 3U );           /* b9ZZ     = 9bZ^2.     */
  fd_bls_fp2_sub( &yy_minus_b9, yy, &b9_zz );    /* yyMinusB9= Y^2-9bZ^2. */
  fd_bls_fp2_mul_small( &two_xy, xy, 2U );              /* twoXY    = 2XY.       */

  fd_bls_fp2_wide_t wide2[3];
  fd_bls_fp2_wide_set_mul( &wide2[0], &yy_minus_b9, &yy_plus_b3 ); /* Y3 = (Y^2-9bZ^2)(Y^2+3bZ^2) ... */
  fd_bls_fp2_wide_addmul( &wide2[0], &eight_yy, &b3_zz );          /* ...  + (8Y^2)(3bZ^2).            */
  fd_bls_fp2_wide_set_mul( &wide2[1], &yy_minus_b9, &two_xy );     /* X3 = (Y^2-9bZ^2)(2XY).            */
  fd_bls_fp2_wide_set_mul( &wide2[2], &eight_yy, yz );             /* Z3 = (8Y^2)(YZ).                  */
  fd_bls_fp2_t round2[3];
  fd_bls_fp2_reduce_batch3( round2, wide2 );
  fd_bls_fp2_copy( &out->x, &round2[1] ); fd_bls_fp2_copy( &out->y, &round2[0] ); fd_bls_fp2_copy( &out->z, &round2[2] );
}

/* Line-free complete mixed addition (add_step minus the secant
   evaluation): round 2 reduces three products instead of five. */
void
fd_bls_g2_add_affine( fd_bls_p2_projective_t *       out,
           fd_bls_p2_projective_t const * p,
           fd_bls_fp2_t const *           e2x,
           fd_bls_fp2_t const *           e2y ) {
  fd_bls_fp2_wide_t wide1[6];
  fd_bls_fp2_wide_set_mul( &wide1[0], e2x, &p->x ); /* xQ*X. */
  fd_bls_fp2_wide_set_mul( &wide1[1], e2x, &p->y ); /* xQ*Y. */
  fd_bls_fp2_wide_set_mul( &wide1[2], e2x, &p->z ); /* xQ*Z. */
  fd_bls_fp2_wide_set_mul( &wide1[3], e2y, &p->x ); /* yQ*X. */
  fd_bls_fp2_wide_set_mul( &wide1[4], e2y, &p->y ); /* yQ*Y. */
  fd_bls_fp2_wide_set_mul( &wide1[5], e2y, &p->z ); /* yQ*Z. */
  fd_bls_fp2_t round1[6];
  fd_bls_fp2_reduce_batch6( round1, wide1 );
  fd_bls_fp2_t const * x2x1=&round1[0], * x2y1=&round1[1], * x2z1=&round1[2];
  fd_bls_fp2_t const * y2x1=&round1[3], * y2y1=&round1[4], * y2z1=&round1[5];

  fd_bls_fp2_t x2y1_plus_y2x1, y2z1_plus_y1, x2z1_plus_x1, three_x2x1;
  fd_bls_fp2_t b3z1, y2y1_plus_b3, y2y1_minus_b3, b3_xsum;
  fd_bls_fp2_add( &x2y1_plus_y2x1, x2y1, y2x1 );  /* xysum   = xQ*Y+yQ*X. */
  fd_bls_fp2_add( &y2z1_plus_y1, y2z1, &p->y );   /* yzsum   = yQ*Z+Y.    */
  fd_bls_fp2_add( &x2z1_plus_x1, x2z1, &p->x );   /* xzsum   = xQ*Z+X.    */
  fd_bls_fp2_mul_small( &three_x2x1, x2x1, 3U );         /* threeXX = 3xQ*X.     */
  fd_bls_fp2_mul_3b( &b3z1, &p->z );                     /* b3Z     = 3bZ.       */
  fd_bls_fp2_add( &y2y1_plus_b3, y2y1, &b3z1 );   /* yp      = yQ*Y+3bZ.  */
  fd_bls_fp2_sub( &y2y1_minus_b3, y2y1, &b3z1 );  /* ym      = yQ*Y-3bZ.  */
  fd_bls_fp2_mul_3b( &b3_xsum, &x2z1_plus_x1 );          /* bx      = 3b*xzsum.  */

  fd_bls_fp2_wide_t wide2[3];
  fd_bls_fp2_wide_set_mul( &wide2[0], &x2y1_plus_y2x1, &y2y1_minus_b3 ); /* X3 = xysum*ym ...   */
  fd_bls_fp2_wide_submul( &wide2[0], &b3_xsum, &y2z1_plus_y1 );          /* ... - bx*yzsum.      */
  fd_bls_fp2_wide_set_mul( &wide2[1], &b3_xsum, &three_x2x1 );           /* Y3 = bx*threeXX ...  */
  fd_bls_fp2_wide_addmul( &wide2[1], &y2y1_plus_b3, &y2y1_minus_b3 );   /* ... + yp*ym.         */
  fd_bls_fp2_wide_set_mul( &wide2[2], &y2y1_plus_b3, &y2z1_plus_y1 );   /* Z3 = yp*yzsum ...    */
  fd_bls_fp2_wide_addmul( &wide2[2], &x2y1_plus_y2x1, &three_x2x1 );    /* ... + xysum*threeXX. */
  fd_bls_fp2_t round2[3];
  fd_bls_fp2_reduce_batch3( round2, wide2 );
  fd_bls_fp2_copy( &out->x, &round2[0] ); fd_bls_fp2_copy( &out->y, &round2[1] ); fd_bls_fp2_copy( &out->z, &round2[2] );
}

/* Complete homogeneous addition of two PROJECTIVE points (fd_bls_g2_add_affine
   generalized to Q = (Xq:Yq:Zq): substituting the affine xq=Xq/Zq,
   yq=Yq/Zq and clearing the Zq^2 denominator).  Costs 15 muls vs
   fd_bls_g2_add_affine's 11, but needs no affinization of the addend. */
void
fd_bls_g2_add_projective( fd_bls_p2_projective_t *       out,
                          fd_bls_p2_projective_t const * p,
                          fd_bls_p2_projective_t const * q ) {
  fd_bls_fp2_wide_t w1a[6], w1b[3];
  fd_bls_fp2_wide_set_mul( &w1a[0], &q->x, &p->x ); /* Xq*X. */
  fd_bls_fp2_wide_set_mul( &w1a[1], &q->x, &p->y ); /* Xq*Y. */
  fd_bls_fp2_wide_set_mul( &w1a[2], &q->x, &p->z ); /* Xq*Z. */
  fd_bls_fp2_wide_set_mul( &w1a[3], &q->y, &p->x ); /* Yq*X. */
  fd_bls_fp2_wide_set_mul( &w1a[4], &q->y, &p->y ); /* Yq*Y. */
  fd_bls_fp2_wide_set_mul( &w1a[5], &q->y, &p->z ); /* Yq*Z. */
  fd_bls_fp2_wide_set_mul( &w1b[0], &p->x, &q->z ); /* X*Zq. */
  fd_bls_fp2_wide_set_mul( &w1b[1], &p->y, &q->z ); /* Y*Zq. */
  fd_bls_fp2_wide_set_mul( &w1b[2], &p->z, &q->z ); /* Z*Zq. */
  fd_bls_fp2_t r1[6], r1b[3];
  fd_bls_fp2_reduce_batch6( r1, w1a );
  fd_bls_fp2_reduce_batch3( r1b, w1b );
  fd_bls_fp2_t const * xqx=&r1[0], * xqy=&r1[1], * xqz=&r1[2];
  fd_bls_fp2_t const * yqx=&r1[3], * yqy=&r1[4], * yqz=&r1[5];
  fd_bls_fp2_t const * xzq=&r1b[0], * yzq=&r1b[1], * zzq=&r1b[2];

  fd_bls_fp2_t xysum, ym, yp, xzsum, yzsum, three_xx, b3_zzq, bx;
  fd_bls_fp2_add( &xysum, xqy, yqx );              /* XqY+YqX.     */
  fd_bls_fp2_mul_3b( &b3_zzq, zzq );                      /* 3b*Z*Zq.     */
  fd_bls_fp2_sub( &ym, yqy, &b3_zzq );             /* YqY-3bZZq.   */
  fd_bls_fp2_add( &yp, yqy, &b3_zzq );             /* YqY+3bZZq.   */
  fd_bls_fp2_add( &xzsum, xqz, xzq );              /* XqZ+XZq.     */
  fd_bls_fp2_add( &yzsum, yqz, yzq );              /* YqZ+YZq.     */
  fd_bls_fp2_mul_small( &three_xx, xqx, 3U );            /* 3*Xq*X.      */
  fd_bls_fp2_mul_3b( &bx, &xzsum );                      /* 3b(XqZ+XZq). */

  fd_bls_fp2_wide_t w2[3];
  fd_bls_fp2_wide_set_mul( &w2[0], &xysum, &ym );          /* X3 = xysum*ym ...     */
  fd_bls_fp2_wide_submul( &w2[0], &bx, &yzsum );           /* ... - bx*yzsum.        */
  fd_bls_fp2_wide_set_mul( &w2[1], &bx, &three_xx );      /* Y3 = bx*threeXX ...    */
  fd_bls_fp2_wide_addmul( &w2[1], &yp, &ym );              /* ... + yp*ym.           */
  fd_bls_fp2_wide_set_mul( &w2[2], &yp, &yzsum );         /* Z3 = yp*yzsum ...      */
  fd_bls_fp2_wide_addmul( &w2[2], &xysum, &three_xx );     /* ... + xysum*threeXX.   */
  fd_bls_fp2_t r2[3];
  fd_bls_fp2_reduce_batch3( r2, w2 );
  fd_bls_fp2_copy( &out->x, &r2[0] ); fd_bls_fp2_copy( &out->y, &r2[1] ); fd_bls_fp2_copy( &out->z, &r2[2] );
}

/* [-z] ladder over an affine base, line-free: 2Q then the {2,3,9,32,16}
   add+double groups of -z = 0xd201000000010000. */
fd_bls_p2_projective_t
fd_bls_g2_ladder_minus_z_affine( fd_bls_fp2_t const * qx,
                       fd_bls_fp2_t const * qy ) {
  fd_bls_p2_projective_t r = { .x = *qx, .y = *qy };
  fd_bls_fp2_one( &r.z );
  fd_bls_g2_double( &r, &r, 1 );
  for( int i=0; i<5; i++ ) {
    fd_bls_g2_add_affine( &r, &r, qx, qy );
    for( uint j=0U; j<fd_bls_miller_iterations[i]; j++ )
      fd_bls_g2_double( &r, &r, 0 );
  }
  return r;
}


/* Scott subgroup relation for an affine point already in RNS form. */
int
fd_bls_g2_validate_affine( fd_bls_fp2_t const * ax,
                               fd_bls_fp2_t const * ay ) {
  /* [-z]Q via the line-free ladder (2Q, then add+double by {2,3,9,32,16}). */
  fd_bls_p2_projective_t r = fd_bls_g2_ladder_minus_z_affine( ax, ay );

  /* Scott's test as the ladder states it: the chain ends at [-z]Q, which
     must equal -psi(Q).  psi is linear over the affine coordinates:
     psi_x = conj(x)*xi^((1-p)/3), psi_y = conj(y)*xi^((1-p)/2). */
  fd_bls_fp2_t x_conj = *ax, y_conj = *ay;
  fd_bls_fp_neg( &x_conj.c[1], &x_conj.c[1] );
  fd_bls_fp_neg( &y_conj.c[1], &y_conj.c[1] );

  fd_bls_fp2_t frob_x, frob_y;
  fd_bls_fp_zero( &frob_x.c[0] );
  frob_x.c[1] = fd_bls_frob1_3;
  frob_y.c[0] = fd_bls_frob3_2;
  frob_y.c[1] = fd_bls_frob3_3;
  fd_bls_fp2_t psi_x, psi_y, rhs_x, rhs_y;
  fd_bls_fp2_mul( &psi_x, &x_conj, &frob_x );
  fd_bls_fp2_mul( &psi_y, &y_conj, &frob_y );
  fd_bls_fp2_mul( &rhs_x, &psi_x, &r.z );
  fd_bls_fp2_mul( &rhs_y, &psi_y, &r.z );
  fd_bls_fp2_neg( &rhs_y, &rhs_y );   /* rhs = -psi(Q) */
  return fd_bls_fp2_equal( &r.x, &rhs_x ) & fd_bls_fp2_equal( &r.y, &rhs_y );
}

int
fd_bls_g2_validate_affine_mont( ulong const * xy ) { /* 2*2*6 Montgomery limbs. */
  fd_bls_fp2_t q[2];
  fd_bls_fp_from_mont_batch( q->c, xy, 4 );
  return fd_bls_g2_validate_affine( q, q+1 );
}

/* Native G2 subgroup validation using Scott's subgroup relation.  Inputs
   outside the curve are outside the validated domain. */
int
fd_bls_g2_validate_mont( ulong const * xyz ) { /* 3*2*6 Montgomery limbs. */
  fd_bls_fp2_t q[3];
  fd_bls_fp_from_mont_batch( q->c, xyz, 6 );

  fd_bls_fp2_t ax, ay;
  static ulong const z_one[2][6] = { { 0x760900000002fffdUL, 0xebf4000bc40c0002UL,
                                       0x5f48985753c758baUL, 0x77ce585370525745UL,
                                       0x5c071a97a256ec6dUL, 0x15f65ec3fa80e493UL },
                                     { 0UL, 0UL, 0UL, 0UL, 0UL, 0UL } };
  if( FD_LIKELY( !memcmp( xyz + 2UL*2UL*6UL, z_one, sizeof(z_one) ) ) ) {
    ax = q[0]; ay = q[1];
  } else {
    fd_bls_fp2_t zinv, zinv2;
    fd_bls_fp2_inverse( &zinv, q+2 );
    fd_bls_fp2_mul( &zinv2, &zinv, &zinv );
    fd_bls_fp2_mul( &ax, q, &zinv2 );
    fd_bls_fp2_mul( &ay, q+1, &zinv2 );
    fd_bls_fp2_mul( &ay, &ay, &zinv );
  }
  return fd_bls_g2_validate_affine( &ax, &ay );
}
