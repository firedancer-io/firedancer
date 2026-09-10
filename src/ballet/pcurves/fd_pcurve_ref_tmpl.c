/* Portable C backend for a short Weierstrass prime curve with a=-3
   (secp256r1, secp384r1).  Provides the same static inline API as the
   s2n-bignum wrappers (fd_secp256r1_s2n.c, fd_secp384r1_s2n.c) so the
   ECDSA template (fd_pcurve_tmpl.c) and the unit tests are backend
   agnostic.

   Field and scalar arithmetic is fiat-crypto generated Montgomery
   arithmetic.  Inversion and square roots are Fermat exponentiations,
   the group law is complete Jacobian addition and scalar multiplication
   is a fixed 4-bit window.  Only public data flows through this code
   (signature verification), see fd_pcurve_ref_util.h.

   Expects, in addition to the macros below, the constants
   NAME_const_{zero,p,n,n_m1_half,one_mont,a_mont,b_mont} (fd_uintN_t)
   and NAME_const_g_mont (3*LIMBS ulong, Jacobian Montgomery generator)
   from the private header, plus NAME_const_{p_m2,p_p1_div4,n_m2}
   (LIMBS ulong, plain integers) from the including file.  Requires
   p = 3 mod 4. */

#ifndef PCURVE_REF_NAME
#error "Define PCURVE_REF_NAME"
#endif
#ifndef PCURVE_REF_LIMBS
#error "Define PCURVE_REF_LIMBS"
#endif
#ifndef PCURVE_REF_UINT
#error "Define PCURVE_REF_UINT"
#endif
#ifndef PCURVE_REF_FIAT_FP
#error "Define PCURVE_REF_FIAT_FP"
#endif
#ifndef PCURVE_REF_FIAT_SC
#error "Define PCURVE_REF_FIAT_SC"
#endif
#ifndef PCURVE_REF_SUCCESS
#error "Define PCURVE_REF_SUCCESS"
#endif
#ifndef PCURVE_REF_FAILURE
#error "Define PCURVE_REF_FAILURE"
#endif

#include "fd_pcurve_ref_util.h"

#define REF_(x)  FD_EXPAND_THEN_CONCAT3(PCURVE_REF_NAME,_,x)
#define UINT_(x) FD_EXPAND_THEN_CONCAT3(PCURVE_REF_UINT,_,x)
#define N        PCURVE_REF_LIMBS
#define SZ       (8UL*(N))

#define FP_T     REF_(fp_t)
#define SC_T     REF_(scalar_t)
#define PT_T     REF_(point_t)

/* fiat-crypto wrappers operating on fd types */

#define FP_MUL(r,a,b)  PCURVE_REF_FIAT_FP(mul)            ( (r)->limbs, (a)->limbs, (b)->limbs )
#define FP_SQR(r,a)    PCURVE_REF_FIAT_FP(square)         ( (r)->limbs, (a)->limbs )
#define FP_ADD(r,a,b)  PCURVE_REF_FIAT_FP(add)            ( (r)->limbs, (a)->limbs, (b)->limbs )
#define FP_SUB(r,a,b)  PCURVE_REF_FIAT_FP(sub)            ( (r)->limbs, (a)->limbs, (b)->limbs )
#define FP_OPP(r,a)    PCURVE_REF_FIAT_FP(opp)            ( (r)->limbs, (a)->limbs )
#define FP_TOMONT(r,a) PCURVE_REF_FIAT_FP(to_montgomery)  ( (r)->limbs, (a)->limbs )
#define FP_DEMONT(r,a) PCURVE_REF_FIAT_FP(from_montgomery)( (r)->limbs, (a)->limbs )

FD_PCURVE_REF_DEFINE_POW( REF_(fp_pow_limbs), PCURVE_REF_LIMBS,
                          PCURVE_REF_FIAT_FP(mul), PCURVE_REF_FIAT_FP(square), PCURVE_REF_FIAT_FP(set_one) )
FD_PCURVE_REF_DEFINE_POW( REF_(scalar_pow_limbs), PCURVE_REF_LIMBS,
                          PCURVE_REF_FIAT_SC(mul), PCURVE_REF_FIAT_SC(square), PCURVE_REF_FIAT_SC(set_one) )

/* Scalars */

static inline int
REF_(scalar_is_zero)( SC_T const * a ) {
  return UINT_(eq)( a, REF_(const_zero) );
}

static inline SC_T *
REF_(scalar_frombytes)( SC_T *      r,
                        uchar const in[ SZ ] ) {
  memcpy( r->buf, in, SZ );
  UINT_(bswap)( r, r );
  if( FD_LIKELY( UINT_(cmp)( r, REF_(const_n) )<0 ) ) return r;
  return NULL;
}

static inline SC_T *
REF_(scalar_frombytes_positive)( SC_T *      r,
                                 uchar const in[ SZ ] ) {
  memcpy( r->buf, in, SZ );
  UINT_(bswap)( r, r );
  if( FD_LIKELY( UINT_(cmp)( r, REF_(const_n_m1_half) )<=0 ) ) return r;
  return NULL;
}

/* r = in mod n.  in < 2^(64N) < 2n, so a single conditional subtraction
   fully reduces. */
static inline void
REF_(scalar_from_digest)( SC_T *      r,
                          uchar const in[ SZ ] ) {
  memcpy( r->buf, in, SZ );
  UINT_(bswap)( r, r );
  fd_pcurve_ref_reduce_once( r->limbs, r->limbs, REF_(const_n)->limbs, N );
}

/* r = a*b mod n, all plain (non Montgomery) residues.
   montmul(a,b) = a*b/R, then to_montgomery multiplies by R. */
static inline SC_T *
REF_(scalar_mul)( SC_T *       r,
                  SC_T const * a,
                  SC_T const * b ) {
  ulong t[ N ];
  PCURVE_REF_FIAT_SC(mul)( t, a->limbs, b->limbs );
  PCURVE_REF_FIAT_SC(to_montgomery)( r->limbs, t );
  return r;
}

/* r = 1/a mod n, plain residues.  a MUST not be 0. */
static inline SC_T *
REF_(scalar_inv)( SC_T *       r,
                  SC_T const * a ) {
  ulong t[ N ];
  PCURVE_REF_FIAT_SC(to_montgomery)( t, a->limbs );
  REF_(scalar_pow_limbs)( t, t, REF_(const_n_m2) );
  PCURVE_REF_FIAT_SC(from_montgomery)( r->limbs, t );
  return r;
}

/* Field.  Elements are in the Montgomery domain unless noted. */

static inline FP_T *
REF_(fp_set)( FP_T *       r,
              FP_T const * a ) {
  memcpy( r->limbs, a->limbs, SZ );
  return r;
}

static inline int
REF_(fp_eq)( FP_T const * a,
             FP_T const * b ) {
  return UINT_(eq)( a, b );
}

/* Parses a big endian plain residue, rejects values >= p.  Result is
   NOT in the Montgomery domain. */
static inline FP_T *
REF_(fp_frombytes)( FP_T *      r,
                    uchar const in[ SZ ] ) {
  memcpy( r->buf, in, SZ );
  UINT_(bswap)( r, r );
  if( FD_LIKELY( UINT_(cmp)( r, REF_(const_p) )<0 ) ) return r;
  return NULL;
}

static inline FP_T *
REF_(fp_neg)( FP_T *       r,
              FP_T const * a ) {
  FP_OPP( r, a );
  return r;
}

/* r = sqrt(a) = a^((p+1)/4) (p = 3 mod 4).  Returns NULL if a is not a
   square. */
static inline FP_T *
REF_(fp_sqrt)( FP_T *       r,
               FP_T const * a ) {
  FP_T t0[1], t1[1];
  REF_(fp_pow_limbs)( t0->limbs, a->limbs, REF_(const_p_p1_div4) );
  FP_SQR( t1, t0 );
  if( FD_UNLIKELY( !REF_(fp_eq)( t1, a ) ) ) return NULL;
  return REF_(fp_set)( r, t0 );
}

/* Points, Jacobian coordinates over Montgomery field elements.  The
   point at infinity is any point with Z=0. */

static inline int
REF_(point_is_inf)( PT_T const * a ) {
  return UINT_(eq)( a->z, REF_(const_zero) );
}

static inline void
REF_(point_set_inf)( PT_T * r ) {
  REF_(fp_set)( r->x, REF_(const_zero) );
  REF_(fp_set)( r->y, REF_(const_one_mont) );
  REF_(fp_set)( r->z, REF_(const_zero) );
}

static inline void
REF_(point_set)( PT_T *       r,
                 PT_T const * a ) {
  if( r!=a ) memcpy( r, a, sizeof(PT_T) );
}

/* r = 2a.  dbl-2001-b (a=-3).  Maps infinity to infinity.  r may
   alias a. */
static inline void
REF_(point_double)( PT_T *       r,
                    PT_T const * a ) {
  FP_T delta[1], gamma[1], beta[1], alpha[1], t[1], x3[1], y3[1], z3[1];

  FP_SQR( delta, a->z );
  FP_SQR( gamma, a->y );
  FP_MUL( beta,  a->x, gamma );

  /* alpha = 3*(X-delta)*(X+delta) */
  FP_SUB( t,     a->x,  delta );
  FP_ADD( alpha, a->x,  delta );
  FP_MUL( alpha, alpha, t     );
  FP_ADD( t,     alpha, alpha );
  FP_ADD( alpha, alpha, t     );

  /* X3 = alpha^2 - 8*beta */
  FP_SQR( x3, alpha );
  FP_ADD( t,  beta, beta );
  FP_ADD( t,  t,    t    );
  FP_ADD( t,  t,    t    );
  FP_SUB( x3, x3,   t    );

  /* Z3 = (Y+Z)^2 - gamma - delta */
  FP_ADD( z3, a->y, a->z  );
  FP_SQR( z3, z3          );
  FP_SUB( z3, z3,   gamma );
  FP_SUB( z3, z3,   delta );

  /* Y3 = alpha*(4*beta - X3) - 8*gamma^2 */
  FP_ADD( t,  beta,  beta );
  FP_ADD( t,  t,     t    );
  FP_SUB( t,  t,     x3   );
  FP_MUL( y3, alpha, t    );
  FP_SQR( t,  gamma       );
  FP_ADD( t,  t,     t    );
  FP_ADD( t,  t,     t    );
  FP_ADD( t,  t,     t    );
  FP_SUB( y3, y3,    t    );

  REF_(fp_set)( r->x, x3 );
  REF_(fp_set)( r->y, y3 );
  REF_(fp_set)( r->z, z3 );
}

/* r = a+b.  add-1998-cmo-2 with explicit handling of infinity, a==b
   (doubling) and a==-b (infinity).  r may alias a or b. */
static inline void
REF_(point_add)( PT_T *       r,
                 PT_T const * a,
                 PT_T const * b ) {
  if( FD_UNLIKELY( REF_(point_is_inf)( a ) ) ) { REF_(point_set)( r, b ); return; }
  if( FD_UNLIKELY( REF_(point_is_inf)( b ) ) ) { REF_(point_set)( r, a ); return; }

  FP_T z1z1[1], z2z2[1], u1[1], u2[1], s1[1], s2[1], h[1], rr[1];
  FP_SQR( z1z1, a->z );
  FP_SQR( z2z2, b->z );
  FP_MUL( u1, a->x, z2z2 );
  FP_MUL( u2, b->x, z1z1 );
  FP_MUL( s1, a->y, b->z ); FP_MUL( s1, s1, z2z2 );
  FP_MUL( s2, b->y, a->z ); FP_MUL( s2, s2, z1z1 );
  FP_SUB( h,  u2, u1 );
  FP_SUB( rr, s2, s1 );

  if( FD_UNLIKELY( REF_(fp_eq)( h, REF_(const_zero) ) ) ) {
    if( REF_(fp_eq)( rr, REF_(const_zero) ) ) REF_(point_double)( r, a );
    else                                      REF_(point_set_inf)( r );
    return;
  }

  FP_T hh[1], hhh[1], v[1], t[1], x3[1], y3[1], z3[1];
  FP_SQR( hh,  h );
  FP_MUL( hhh, h,  hh );
  FP_MUL( v,   u1, hh );

  /* X3 = R^2 - H^3 - 2V */
  FP_SQR( x3, rr );
  FP_SUB( x3, x3, hhh );
  FP_SUB( x3, x3, v   );
  FP_SUB( x3, x3, v   );

  /* Y3 = R*(V-X3) - S1*H^3 */
  FP_SUB( t,  v,  x3 );
  FP_MUL( y3, rr, t  );
  FP_MUL( t,  s1, hhh );
  FP_SUB( y3, y3, t  );

  /* Z3 = Z1*Z2*H */
  FP_MUL( z3, a->z, b->z );
  FP_MUL( z3, z3,   h    );

  REF_(fp_set)( r->x, x3 );
  REF_(fp_set)( r->y, y3 );
  REF_(fp_set)( r->z, z3 );
}

/* r = s*a, fixed 4-bit window.  s is a plain LE integer of N limbs. */
static inline void
REF_(point_scalarmul)( PT_T *       r,
                       ulong const  s[ N ],
                       PT_T const * a ) {
  PT_T tbl[ 16 ];
  REF_(point_set_inf)( &tbl[ 0 ] );
  REF_(point_set)( &tbl[ 1 ], a );
  for( ulong i=2UL; i<16UL; i++ ) REF_(point_add)( &tbl[ i ], &tbl[ i-1UL ], a );

  PT_T acc[1];
  REF_(point_set_inf)( acc );
  for( long i=(long)(64UL*N)-4L; i>=0L; i-=4L ) {
    REF_(point_double)( acc, acc );
    REF_(point_double)( acc, acc );
    REF_(point_double)( acc, acc );
    REF_(point_double)( acc, acc );
    ulong d = ( s[ i/64L ] >> (i%64L) ) & 15UL;
    REF_(point_add)( acc, acc, &tbl[ d ] );
  }
  REF_(point_set)( r, acc );
}

/* Validates a SEC1 uncompressed point (0x04 || x || y): canonical
   coordinates and the curve equation. */
static inline int
REF_(point_validate_uncompressed)( uchar const in[ 1+2*SZ ] ) {
  if( FD_UNLIKELY( in[ 0 ]!=0x04U ) ) return PCURVE_REF_FAILURE;

  FP_T x[1], y[1], lhs[1], rhs[1];
  if( FD_UNLIKELY( !REF_(fp_frombytes)( x, in+1    ) ) ) return PCURVE_REF_FAILURE;
  if( FD_UNLIKELY( !REF_(fp_frombytes)( y, in+1+SZ ) ) ) return PCURVE_REF_FAILURE;

  FP_TOMONT( x, x );
  FP_TOMONT( y, y );

  /* y^2 = x^3 + ax + b */
  FP_SQR( lhs, y );
  FP_SQR( rhs, x );
  FP_ADD( rhs, rhs, REF_(const_a_mont) );
  FP_MUL( rhs, rhs, x );
  FP_ADD( rhs, rhs, REF_(const_b_mont) );
  return REF_(fp_eq)( lhs, rhs );
}

/* Decompresses a SEC1 compressed point (0x02/0x03 || x). */
static inline PT_T *
REF_(point_frombytes)( PT_T *      r,
                       uchar const in[ 1+SZ ] ) {
  FP_T y2[1], demont_y[1];

  uchar sgn = in[0];
  if( FD_UNLIKELY( sgn!=2U && sgn!=3U ) ) return NULL;

  if( FD_UNLIKELY( !REF_(fp_frombytes)( r->x, in+1 ) ) ) return NULL;
  FP_TOMONT( r->x, r->x );

  /* y^2 = x^3 + ax + b */
  FP_SQR( y2, r->x );
  FP_ADD( y2, y2, REF_(const_a_mont) );
  FP_MUL( y2, y2, r->x );
  FP_ADD( y2, y2, REF_(const_b_mont) );

  if( FD_UNLIKELY( !REF_(fp_sqrt)( r->y, y2 ) ) ) return NULL;

  /* choose y or -y */
  FP_DEMONT( demont_y, r->y );
  if( ( demont_y->limbs[0] & 1UL ) != (ulong)( sgn==3U ) ) FP_OPP( r->y, r->y );

  REF_(fp_set)( r->z, REF_(const_one_mont) );
  return r;
}

/* Returns PCURVE_REF_SUCCESS if the affine x coordinate of p, reduced
   mod n, equals r.  Infinity never matches. */
static inline int
REF_(point_eq_x)( PT_T const * p,
                  SC_T const * r ) {
  FP_T x[1];

  if( FD_UNLIKELY( REF_(point_is_inf)( p ) ) ) return PCURVE_REF_FAILURE;

  /* x = demont(X / Z^2) mod n.  demont(X/Z^2) < p < 2n so one
     conditional subtraction reduces. */
  REF_(fp_pow_limbs)( x->limbs, p->z->limbs, REF_(const_p_m2) );
  FP_SQR( x, x );
  FP_MUL( x, x, p->x );
  FP_DEMONT( x, x );
  fd_pcurve_ref_reduce_once( x->limbs, x->limbs, REF_(const_n)->limbs, N );

  if( FD_LIKELY( UINT_(eq)( r, x ) ) ) return PCURVE_REF_SUCCESS;
  return PCURVE_REF_FAILURE;
}

/* Mixed helpers.  b is an affine point (x,y) in the Montgomery domain
   laid out as 2N limbs; (0,0) denotes infinity (s2n-bignum
   convention). */

static inline int
REF_(point_eq_mixed)( PT_T const * a,
                      ulong const  b[ 2*N ] ) {
  FP_T x[1], y[1];
  memcpy( x->limbs, b,   SZ );
  memcpy( y->limbs, b+N, SZ );
  int is_zero = REF_(fp_eq)( x, REF_(const_zero) ) & REF_(fp_eq)( y, REF_(const_zero) );

  if( FD_UNLIKELY( REF_(point_is_inf)( a ) ) ) return is_zero;
  if( FD_UNLIKELY( is_zero ) ) return 0;

  FP_T z1z1[1], t[1];
  FP_SQR( z1z1, a->z );
  FP_MUL( t, x, z1z1 );
  if( !REF_(fp_eq)( a->x, t ) ) return 0;
  FP_MUL( t, z1z1, a->z );
  FP_MUL( t, t, y );
  return REF_(fp_eq)( a->y, t );
}

static inline void
REF_(point_add_mixed)( PT_T *       r,
                       PT_T const * a,
                       ulong const  b[ 2*N ] ) {
  PT_T bp[1];
  memcpy( bp->x->limbs, b,   SZ );
  memcpy( bp->y->limbs, b+N, SZ );
  int is_zero = REF_(fp_eq)( bp->x, REF_(const_zero) ) & REF_(fp_eq)( bp->y, REF_(const_zero) );
  if( FD_UNLIKELY( is_zero ) ) { REF_(point_set)( r, a ); return; }
  REF_(fp_set)( bp->z, REF_(const_one_mont) );
  REF_(point_add)( r, a, bp );
}

/* r = u1*G + u2*a */
static inline void
REF_(double_scalar_mul_base)( PT_T *       r,
                              SC_T const * u1,
                              PT_T const * a,
                              SC_T const * u2 ) {
  PT_T g[1], t1[1], t2[1];
  memcpy( g->x->limbs, REF_(const_g_mont),     SZ );
  memcpy( g->y->limbs, REF_(const_g_mont)+N,   SZ );
  memcpy( g->z->limbs, REF_(const_g_mont)+2*N, SZ );

  REF_(point_scalarmul)( t1, u1->limbs, g );
  REF_(point_scalarmul)( t2, u2->limbs, a );
  REF_(point_add)( r, t1, t2 );
}

#undef FP_MUL
#undef FP_SQR
#undef FP_ADD
#undef FP_SUB
#undef FP_OPP
#undef FP_TOMONT
#undef FP_DEMONT
#undef FP_T
#undef SC_T
#undef PT_T
#undef SZ
#undef N
#undef UINT_
#undef REF_
#undef PCURVE_REF_NAME
#undef PCURVE_REF_LIMBS
#undef PCURVE_REF_UINT
#undef PCURVE_REF_FIAT_FP
#undef PCURVE_REF_FIAT_SC
#undef PCURVE_REF_SUCCESS
#undef PCURVE_REF_FAILURE
