/* Native AVX-512 hash-to-curve (hash_msg) for BLS12-381 G2, bit-exact
   with blst_hash_to_g2:

   - Phase 1 uses blst's public expand_message_xmd.
   - Phase 2 reduces the four 64-byte blocks modulo p (fd_bls_rns_reduce_512) and
     enters RNS directly.
   - Phase 3 runs the SSWU map, the E' point addition, and the 3-isogeny
     entirely in RNS.  The square root is RFC 9380 sqrt_ratio over Fp2
     (q = p^2 = 9 mod 16): one Frobenius-split 377-bit Fp2 exponentiation
     with the two independent u0/u1 map instances advancing together
     through shared batched reductions.
   - Phase 4 clears the cofactor with the Budroni-Pintore chain on the
     RNS Miller machinery (2x [-z] ladders + psi + complete additions),
     emitting the affine (x, y).

   The branch structure (QR select, zero-xd select, sign alignment) and
   isogeny Horner order follow blst's map_to_g2.c, so every select has the
   same semantics; sqrt_ratio yields the same square root up to sign, and
   the sign is then fixed by sgn0 exactly as in blst.  Hash inputs are
   public, so data-dependent branches are fine here. */

#include "fd_bls_hash.h"

#include "fd_bls_constants.h"

#include "../../../third_party/blst/bindings/blst.h"

/* sgn0 must be evaluated on the CANONICAL value (RFC 9380 sgn0 is parity
   of the canonical representative).  Direct port of blst's
   sgn0_pty_mod_384: bit0 = parity, bit1 = value > (p-1)/2. */
static int
sgn0_pty_canon( ulong const a[6] ) {
  ulong ret = a[0] & 1UL;              /* parity */
  ulong tmp[6], carry = 0UL, borrow = 0UL;
  for( int i=0; i<6; i++ ) { ulong ai = a[i]; tmp[i] = ai<<1 | carry; carry = ai>>63; }
  for( int i=0; i<6; i++ ) { ulong pi = fd_bls_field_modulus_limbs[i] + borrow; borrow = tmp[i] < pi; }
  ret |= ((carry - borrow) & 2UL) ^ 2UL;  /* pty bit */
  return (int)ret;
}

/* sgn0 of an RNS Fp2 element, blst sgn0_pty_mont_384x semantics. */
static int
sgn0_f2_rns( fd_bls_fp2_t const * a ) {
  ulong re[6], im[6];
  fd_bls_fp_to_uint64( re, &a->c[0] );
  fd_bls_fp_to_uint64( im, &a->c[1] );
  int re_s = sgn0_pty_canon( re ), im_s = sgn0_pty_canon( im );
  int im_nz = (int)( (im[0]|im[1]|im[2]|im[3]|im[4]|im[5]) != 0UL );
  int re_z  = (int)( (re[0]|re[1]|re[2]|re[3]|re[4]|re[5]) == 0UL );
  int sign = im_nz ? im_s : re_s;    /* a.im!=0 ? sgn0(a.im) : sgn0(a.re) */
  int prty = re_z  ? im_s : re_s;    /* a.re==0 ? pty(a.im) : pty(a.re)   */
  return (sign & 2) | (prty & 1);
}

/* --- native clear_cofactor helpers (Miller chain + psi) --- */

/* psi on affine coordinates: psi_x = conj(x)*xi^((1-p)/3),
   psi_y = conj(y)*xi^((1-p)/2).  Same constants as sig_validate (verified
   against blst_p2_in_g2 there). */
static void
psi_affine( fd_bls_fp2_t *       ox,
            fd_bls_fp2_t *       oy,
            fd_bls_fp2_t const * x,
            fd_bls_fp2_t const * y ) {
  /* frob constants are plain register writes; constructed per call so the
     function is stateless (fd_bls_verify paths may run on concurrent
     tiles, and a lazily-initialized static is a data race).  Same
     constants as sig_validate (verified against blst_p2_in_g2 there). */
  fd_bls_fp2_t frob_x, frob_y;
  fd_bls_fp_zero( &frob_x.c[0] );
  frob_x.c[1] = fd_bls_frob1_3;
  frob_y.c[0] = fd_bls_frob3_2;
  frob_y.c[1] = fd_bls_frob3_3;
  fd_bls_fp2_t xc = *x, yc = *y;
  fd_bls_fp_neg( &xc.c[1], &xc.c[1] );   /* conj: negate imag component ONLY */
  fd_bls_fp_neg( &yc.c[1], &yc.c[1] );   /* (fd_bls_fp2_neg would also negate
                                           the real part -> computes -psi) */
  fd_bls_fp2_mul( ox, &xc, &frob_x );
  fd_bls_fp2_mul( oy, &yc, &frob_y );
}

/* psi on homogeneous projective: (X:Y:Z) -> (psi_x(X) : psi_y(Y) : conj(Z)),
   which represents psi of the affine point without an inversion. */
static void
psi_projective( fd_bls_p2_projective_t * p ) {
  fd_bls_fp2_t ox, oy;
  psi_affine( &ox, &oy, &p->x, &p->y );
  p->x = ox; p->y = oy;
  fd_bls_fp_neg( &p->z.c[1], &p->z.c[1] );   /* conj(Z): imag only */
}

/* Shared line-free projective formulas live in fd_bls_g2.c. */

/* --- RNS small helpers for the SSWU domain parameters --- */

static inline fd_bls_fp2_t
fp2_const_hash( fd_bls_fp_t re,
                fd_bls_fp_t im ) {
  return (fd_bls_fp2_t){ .c = { re, im } };
}

static inline int
fp_is_zero_rns( fd_bls_fp_t const * a ) {
  fd_bls_fp_t z; fd_bls_fp_zero( &z );
  return fd_bls_fp_equal( a, &z );
}

static inline int
fp2_is_zero_rns( fd_bls_fp2_t const * a ) {
  return fp_is_zero_rns( &a->c[0] ) & fp_is_zero_rns( &a->c[1] );
}

/* Multiply by the SSWU Z = -(2+u): (a+bu)*Z = (b-2a) + (-(a+2b))u. */
static inline void
fp2_mul_sswu_z( fd_bls_fp2_t * out, fd_bls_fp2_t const * in ) {
  fd_bls_fp_t a2, b2, t;
  fd_bls_fp_add( &a2, &in->c[0], &in->c[0] );  /* 2a      */
  fd_bls_fp_add( &b2, &in->c[1], &in->c[1] );  /* 2b      */
  fd_bls_fp_sub( &t, &in->c[1], &a2 );         /* b-2a    */
  fd_bls_fp_add( &b2, &in->c[0], &b2 );        /* a+2b    */
  out->c[0] = t;
  fd_bls_fp_neg( &out->c[1], &b2 );            /* -(a+2b) */
}

/* Multiply by A' = 240u: (a+bu)*240u = -240b + 240a u.  240 is applied
   via a full fp_mul by its encoded constant: a raw small-multiple chain
   would scale the redundant RNS value 240x, far past the 2048p operand
   bound of the lazy wide products (and the 40p equality scan). */
static inline void
fp2_mul_sswu_a( fd_bls_fp2_t * out, fd_bls_fp2_t const * in ) {
  fd_bls_fp_t re, im;
  fd_bls_fp_t c240 = fd_bls_c240;
  fd_bls_fp_mul( &im, &in->c[0], &c240 );
  fd_bls_fp_mul( &re, &in->c[1], &c240 );
  fd_bls_fp_neg( &out->c[0], &re );
  out->c[1] = im;
}

/* Multiply by B' = 1012(1+u): 1012*((a-b) + (a+b)u), same bound note. */
static inline void
fp2_mul_sswu_b( fd_bls_fp2_t * out, fd_bls_fp2_t const * in ) {
  fd_bls_fp_t c1012 = fd_bls_c1012;
  fd_bls_fp2_t nonres;
  fd_bls_fp_sub( &nonres.c[0], &in->c[0], &in->c[1] );
  fd_bls_fp_add( &nonres.c[1], &in->c[0], &in->c[1] );
  fd_bls_fp_mul( &out->c[0], &nonres.c[0], &c1012 );
  fd_bls_fp_mul( &out->c[1], &nonres.c[1], &c1012 );
}

/* --- Fp2 sqrt_ratio for both u values in lockstep ---

   RFC 9380 F.2.1.1 sqrt_ratio specialized to q = p^2 = 9 (mod 16)
   (c1 = 3).  Its exponent c3 = (q-9)/16 splits through the Frobenius:
   with k = (p-11)/16, c3 = k*p + 11k + 7, so x^c3 = conj(x^k)*(x^k)^11*x^7
   (x^p is the Fp2 conjugate).  One 377-bit exponentiation over Fp2
   replaces the two sequential 381-bit Fp exponentiations of the
   norm-based complex method, and the two lanes advance together through
   batched reductions of their four base-field components. */

typedef struct { fd_bls_fp2_t l[2]; } fp2x2_t;

static inline void
fp2x2_mul( fp2x2_t *       o,
           fp2x2_t const * a,
           fp2x2_t const * b ) {
  fd_bls_fp2_wide_t w[2];
  fd_bls_fp2_wide_set_mul( &w[0], &a->l[0], &b->l[0] );
  fd_bls_fp2_wide_set_mul( &w[1], &a->l[1], &b->l[1] );
  fd_bls_fp_reduce_wide_batch4( &o->l[0].c[0], &w[0].c[0] );
}

static inline void
fp2x2_sqr( fp2x2_t *       o,
           fp2x2_t const * a ) {
  fp2x2_mul( o, a, a );
}

/* k = (p-11)/16, little-endian 64-bit limbs (377 bits). */
static ulong const fd_bls_sqrt_ratio_k[6] = {
  0xfb9feffffffffaaaUL, 0x41eabfffeb153fffUL, 0xf6730d2a0f6b0f62UL,
  0x764774b84f38512bUL, 0xa4b1ba7b6434bacdUL, 0x01a0111ea397fe69UL
};
#define FD_BLS_SQRT_RATIO_K_BITS (377)

/* o = x^k, sliding window of width 5 over the fixed public exponent. */
static void
fp2x2_pow_k( fp2x2_t *       o,
             fp2x2_t const * x ) {
  fp2x2_t tbl[16], x2;                         /* tbl[i] = x^(2i+1). */
  tbl[0] = *x;
  fp2x2_sqr( &x2, x );
  for( int i=1; i<16; i++ ) fp2x2_mul( &tbl[i], &tbl[i-1], &x2 );
# define KBIT(b) ((int)( (fd_bls_sqrt_ratio_k[(b)>>6] >> ((b)&63)) & 1UL ))
  int   b     = FD_BLS_SQRT_RATIO_K_BITS-1;
  int   first = 1;
  fp2x2_t r;
  while( b>=0 ) {
    if( !KBIT( b ) ) { fp2x2_sqr( &r, &r ); b--; continue; }
    int lo = b-4 < 0 ? 0 : b-4;                /* window [lo,b], trimmed to end on a set bit */
    while( !KBIT( lo ) ) lo++;
    int w = 0;
    for( int i=b; i>=lo; i-- ) w = (w<<1) | KBIT( i );
    if( first ) { r = tbl[ w>>1 ]; first = 0; }
    else {
      for( int i=b; i>=lo; i-- ) fp2x2_sqr( &r, &r );
      fp2x2_mul( &r, &r, &tbl[ w>>1 ] );
    }
    b = lo-1;
  }
# undef KBIT
  *o = r;
}

static inline int
fp2_is_one_rns( fd_bls_fp2_t const * a ) {
  fd_bls_fp2_t one; fd_bls_fp2_one( &one );
  return fd_bls_fp2_equal( a, &one );
}

/* Per lane L: if num/den is a square (or num is zero, matching blst's
   recip_sqrt convention) sets bit L of the return and y[L] =
   sqrt(num/den); otherwise y[L] = sqrt(Z*num/den).  den must be nonzero. */
static int
sqrt_ratio_x2( fp2x2_t *       y,
               fp2x2_t const * num,
               fp2x2_t const * den ) {
  fp2x2_t v2, v4, v7, v8, v15, t, x7, y11, yk;
  fp2x2_sqr( &v2, den );
  fp2x2_sqr( &v4, &v2 );
  fp2x2_mul( &t,  &v2, den );
  fp2x2_mul( &v7, &v4, &t );                   /* tv2 = v^7  */
  fp2x2_sqr( &v8, &v4 );
  fp2x2_mul( &v15, &v8, &v7 );                 /* tv3 = v^15 */
  fp2x2_mul( &t, num, &v15 );                  /* t = u*v^15 */

  /* t^c3 = conj(t^k) * (t^k)^11 * t^7 */
  fp2x2_t t2, t3, t6, y2, y4, y8, y10;
  fp2x2_pow_k( &yk, &t );
  fp2x2_sqr( &t2, &t );
  fp2x2_mul( &t3, &t2, &t );
  fp2x2_sqr( &t6, &t3 );
  fp2x2_mul( &x7, &t6, &t );                   /* t^7        */
  fp2x2_sqr( &y2, &yk );
  fp2x2_sqr( &y4, &y2 );
  fp2x2_sqr( &y8, &y4 );
  fp2x2_mul( &y10, &y8, &y2 );
  fp2x2_mul( &y11, &y10, &yk );                /* (t^k)^11   */
  fp2x2_t yc = yk;
  for( int l=0; l<2; l++ ) fd_bls_fp_neg( &yc.l[l].c[1], &yc.l[l].c[1] ); /* (t^k)^p */
  fp2x2_t tv5;
  fp2x2_mul( &tv5, &yc, &y11 );
  fp2x2_mul( &tv5, &tv5, &x7 );                /* tv5 = (u v^15)^c3 */

  fp2x2_t tv2, tv3, tv4, s1, s2;
  fp2x2_mul( &tv5, &tv5, &v7 );
  fp2x2_mul( &tv2, &tv5, den );
  fp2x2_mul( &tv3, &tv5, num );
  fp2x2_mul( &tv4, &tv3, &tv2 );
  fp2x2_sqr( &s1, &tv4 );
  fp2x2_sqr( &s2, &s1 );                       /* tv4^4 */

  fd_bls_fp2_t c6 = fp2_const_hash( fd_bls_frob3_3, fd_bls_frob3_3 );     /* Z^c2         */
  fd_bls_fp2_t c7 = fp2_const_hash( fd_bls_sswu_c7_re, fd_bls_sswu_c7_im ); /* Z^((c2+1)/2) */
  int is_qr = 0;
  for( int l=0; l<2; l++ ) {
    int qr = fp2_is_one_rns( &s2.l[l] );
    if( FD_UNLIKELY( fp2_is_zero_rns( &num->l[l] ) ) ) {   /* blst: zero is a square, root 0 */
      fd_bls_fp_zero( &y->l[l].c[0] ); fd_bls_fp_zero( &y->l[l].c[1] );
      is_qr |= 1<<l;
      continue;
    }
    fd_bls_fp2_t r3 = tv3.l[l], r4 = tv4.l[l], tv1 = c6;
    if( !qr ) {
      fd_bls_fp2_mul( &r3, &r3, &c7 );
      fd_bls_fp2_mul( &r4, &r4, &tv1 );
    }
    for( int i=3; i>=2; i-- ) {                /* i-2 squarings, then test == 1 */
      fd_bls_fp2_t e = r4;
      for( int j=0; j<i-2; j++ ) fd_bls_fp2_sqr( &e, &e );
      int e1 = fp2_is_one_rns( &e );
      fd_bls_fp2_t tv2l;
      fd_bls_fp2_mul( &tv2l, &r3, &tv1 );
      fd_bls_fp2_sqr( &tv1, &tv1 );
      if( !e1 ) { r3 = tv2l; fd_bls_fp2_mul( &r4, &r4, &tv1 ); }
    }
    y->l[l] = r3;
    is_qr |= qr<<l;
  }
  return is_qr;
}

/* sqrt over Fp2 for G2 decompression (q = 9 mod 16).  r0 = x^((q+7)/16)
   = x*x^c3 satisfies r0^2 = x*w with w a 4th root of unity when x is a
   square, so sqrt(x) is r0 times one of 1, u, c6, c6*u (c6^2 = -u).
   Returns 0 if x is not a square.  The root's sign is fixed later by the
   caller via sgn0, so the choice among the two roots does not matter. */
/* Single-lane x^k (same sliding window as fp2x2_pow_k). */
static void
fp2_pow_k( fd_bls_fp2_t *       o,
           fd_bls_fp2_t const * x ) {
  fd_bls_fp2_t tbl[16], x2;                    /* tbl[i] = x^(2i+1). */
  tbl[0] = *x;
  fd_bls_fp2_sqr( &x2, x );
  for( int i=1; i<16; i++ ) fd_bls_fp2_mul( &tbl[i], &tbl[i-1], &x2 );
# define KBIT(b) ((int)( (fd_bls_sqrt_ratio_k[(b)>>6] >> ((b)&63)) & 1UL ))
  int   b     = FD_BLS_SQRT_RATIO_K_BITS-1;
  int   first = 1;
  fd_bls_fp2_t r;
  while( b>=0 ) {
    if( !KBIT( b ) ) { fd_bls_fp2_sqr( &r, &r ); b--; continue; }
    int lo = b-4 < 0 ? 0 : b-4;
    while( !KBIT( lo ) ) lo++;
    int w = 0;
    for( int i=b; i>=lo; i-- ) w = (w<<1) | KBIT( i );
    if( first ) { r = tbl[ w>>1 ]; first = 0; }
    else {
      for( int i=b; i>=lo; i-- ) fd_bls_fp2_sqr( &r, &r );
      fd_bls_fp2_mul( &r, &r, &tbl[ w>>1 ] );
    }
    b = lo-1;
  }
# undef KBIT
  *o = r;
}

static inline void
fp2_mul_by_u( fd_bls_fp2_t * o, fd_bls_fp2_t const * a ) { /* (a0+a1 u)u = -a1 + a0 u */
  fd_bls_fp_t re = a->c[0];
  fd_bls_fp_neg( &o->c[0], &a->c[1] );
  o->c[1] = re;
}

int
fd_bls_fp2_sqrt_rns( fd_bls_fp2_t *       out,
                     fd_bls_fp2_t const * x ) {
  fd_bls_fp2_t y, y2, y4, y8, y11, x2, x3, x6, x7, t, r0, s;
  fp2_pow_k( &y, x );
  fd_bls_fp2_sqr( &y2, &y );
  fd_bls_fp2_sqr( &y4, &y2 );
  fd_bls_fp2_sqr( &y8, &y4 );
  fd_bls_fp2_mul( &y11, &y8, &y2 );
  fd_bls_fp2_mul( &y11, &y11, &y );            /* (x^k)^11 */
  fd_bls_fp2_sqr( &x2, x );
  fd_bls_fp2_mul( &x3, &x2, x );
  fd_bls_fp2_sqr( &x6, &x3 );
  fd_bls_fp2_mul( &x7, &x6, x );               /* x^7 */
  fd_bls_fp_neg( &y.c[1], &y.c[1] );           /* (x^k)^p */
  fd_bls_fp2_mul( &t, &y, &y11 );
  fd_bls_fp2_mul( &t, &t, &x7 );               /* x^c3 */
  fd_bls_fp2_mul( &r0, &t, x );                /* r0 = x^((q+7)/16) */
  fd_bls_fp2_sqr( &s, &r0 );                   /* s = r0^2 = x*w, w^4 = 1 if x is a square */

  /* (r0*u)^2 = -s, (r0*c6)^2 = -u*s, (r0*c6*u)^2 = u*s with c6^2 = -u. */
  fd_bls_fp2_t c6 = fp2_const_hash( fd_bls_frob3_3, fd_bls_frob3_3 );
  fd_bls_fp2_t ns, us, nus;
  fd_bls_fp2_neg( &ns, &s );
  fp2_mul_by_u( &us, &s );
  fd_bls_fp2_neg( &nus, &us );
  if( fd_bls_fp2_equal( &s,   x ) ) { *out = r0; return 1; }
  if( fd_bls_fp2_equal( &ns,  x ) ) { fp2_mul_by_u( out, &r0 ); return 1; }
  fd_bls_fp2_t rc; fd_bls_fp2_mul( &rc, &r0, &c6 );
  if( fd_bls_fp2_equal( &nus, x ) ) { *out = rc; return 1; }
  if( fd_bls_fp2_equal( &us,  x ) ) { fp2_mul_by_u( out, &rc ); return 1; }
  return 0;
}

/* Native G2 decompression with blst_p2_uncompress semantics on non-
   infinity encodings.  x arrives as canonical little-endian limbs (the
   caller has checked the range, flags and infinity cases).  Writes the
   affine point and returns 0 on success, -1 if x^3+b is not a square. */
int
fd_bls_g2_decompress_rns( fd_bls_fp2_t *    ox,
                          fd_bls_fp2_t *    oy,
                          ulong const       x_re[6],
                          ulong const       x_im[6],
                          int               sign_bit ) {
  fd_bls_fp2_t x, rhs, t, y;
  fd_bls_fp_from_uint64( &x.c[0], x_re );
  fd_bls_fp_from_uint64( &x.c[1], x_im );
  fd_bls_fp2_sqr( &t, &x );
  fd_bls_fp2_mul( &rhs, &t, &x );
  fd_bls_fp_t four; fd_bls_fp_mul_small( &four, &fd_bls_one, 4U );
  fd_bls_fp_add( &rhs.c[0], &rhs.c[0], &four );
  fd_bls_fp_add( &rhs.c[1], &rhs.c[1], &four );  /* x^3 + 4(1+u) */
  if( FD_UNLIKELY( !fd_bls_fp2_sqrt_rns( &y, &rhs ) ) ) return -1;
  int s = sgn0_f2_rns( &y );
  if( ((s>>1)&1) ^ sign_bit ) fd_bls_fp2_neg( &y, &y );
  /* Re-encode y from its canonical value so decoded points carry the same
     RNS representative as every other entry path (callers memcmp them). */
  for( int i=0; i<2; i++ ) {
    ulong c[6]; fd_bls_fp_to_uint64( c, &y.c[i] ); fd_bls_fp_from_uint64( &y.c[i], c );
  }
  *ox = x; *oy = y;
  return 0;
}

/* --- SSWU map to the isogenous curve E', both u values in lockstep ---
   RFC 9380 simplified SWU (same select/sign semantics as blst
   map_to_isogenous_E2); output is Jacobian on E' (reusing the projective
   struct for storage). */
static void
sswu_map2_rns( fd_bls_p2_projective_t out[2],
               fd_bls_fp2_t const     u  [2] ) {
  fd_bls_fp2_t xd[2], gxd[2], x1n[2], x2n[2], zuu[2];
  fp2x2_t      gx1v, gxdv, y1;

  for( int l=0; l<2; l++ ) {
    fd_bls_fp2_t uu, tv2, t;
    fd_bls_fp2_sqr( &uu, &u[l] );                     /* uu  = u^2                 */
    fp2_mul_sswu_z( &zuu[l], &uu );                   /* Zuu = Z*u^2               */
    fd_bls_fp2_sqr( &tv2, &zuu[l] );
    fd_bls_fp2_add( &tv2, &tv2, &zuu[l] );            /* tv2 = Zuu^2+Zuu           */
    fd_bls_fp2_t tv2p1 = tv2;
    fd_bls_fp_t one; fd_bls_fp_one( &one );
    fd_bls_fp_add( &tv2p1.c[0], &tv2p1.c[0], &one );
    fp2_mul_sswu_b( &x1n[l], &tv2p1 );                /* x1n = B'(tv2+1)           */
    fd_bls_fp2_mul( &x2n[l], &zuu[l], &x1n[l] );      /* x2n = Zuu*x1n             */

    fp2_mul_sswu_a( &xd[l], &tv2 );                   /* xd  = A'*tv2              */
    fd_bls_fp2_neg( &xd[l], &xd[l] );                 /* xd  = -A'*tv2             */
    if( FD_UNLIKELY( fp2_is_zero_rns( &xd[l] ) ) ) {
      /* xd==0: substitute Z*A' = 240-480u */
      xd[l].c[0] = fd_bls_c240;
      xd[l].c[1] = fd_bls_sswu_zxa_im;
    }

    fd_bls_fp2_sqr( &t, &xd[l] );                     /* t    = xd^2               */
    fd_bls_fp2_mul( &gxd[l], &xd[l], &t );            /* gxd  = xd^3               */
    fp2_mul_sswu_a( &t, &t );                         /* t    = A'*xd^2            */
    fd_bls_fp2_t gx1;
    fd_bls_fp2_sqr( &gx1, &x1n[l] );
    fd_bls_fp2_add( &gx1, &gx1, &t );                 /* gx1  = x1n^2+A'xd^2       */
    fd_bls_fp2_mul( &gx1, &gx1, &x1n[l] );            /* gx1 *= x1n                */
    fp2_mul_sswu_b( &t, &gxd[l] );                    /* t    = B'*gxd             */
    fd_bls_fp2_add( &gx1v.l[l], &gx1, &t );           /* gx1  = g(x1n/xd)*gxd      */
    gxdv.l[l] = gxd[l];
  }

  int e2 = sqrt_ratio_x2( &y1, &gx1v, &gxdv );        /* y1 = sqrt(gx1/gxd) or sqrt(Z*gx1/gxd) */

  for( int l=0; l<2; l++ ) {
    fd_bls_fp2_t x, y;
    if( (e2>>l) & 1 ) { x = x1n[l]; y = y1.l[l]; }
    else {
      x = x2n[l];
      fd_bls_fp2_mul( &y, &y1.l[l], &zuu[l] );
      fd_bls_fp2_mul( &y, &y, &u[l] );                /* y2 = Z*u^3*y1             */
    }

    /* blst sgn0_fp2 compares only the parity bit */
    int su = sgn0_f2_rns( &u[l] ), sy = sgn0_f2_rns( &y );
    if( (su ^ sy) & 1 ) fd_bls_fp2_neg( &y, &y );

    /* to Jacobian on E': X = xn*xd, Y = y*gxd, Z = xd */
    fd_bls_fp2_mul( &out[l].x, &x, &xd[l] );
    fd_bls_fp2_mul( &out[l].y, &y, &gxd[l] );
    out[l].z = xd[l];
  }
}

/* Complete Jacobian addition on E' (a4 = A' = 240u), blst POINTonE2_dadd
   port with public-input branches in place of the constant-time selects. */
static void
ec_dadd_eprime_rns( fd_bls_p2_projective_t *       p1,   /* updated in place */
                    fd_bls_p2_projective_t const * p2 ) {
  if( FD_UNLIKELY( fp2_is_zero_rns( &p2->z ) ) ) return;
  if( FD_UNLIKELY( fp2_is_zero_rns( &p1->z ) ) ) { *p1 = *p2; return; }

  fd_bls_fp2_t z1z1, z2z2, u1, u2, s1, s2, h, r, sx, zmul;
  fd_bls_fp2_sqr( &z1z1, &p1->z );                    /* Z1^2            */
  fd_bls_fp2_sqr( &z2z2, &p2->z );                    /* Z2^2            */
  fd_bls_fp2_mul( &u1, &p1->x, &z2z2 );               /* U1 = X1*Z2^2    */
  fd_bls_fp2_mul( &u2, &p2->x, &z1z1 );               /* U2 = X2*Z1^2    */
  fd_bls_fp2_mul( &s1, &p1->y, &p2->z );
  fd_bls_fp2_mul( &s1, &s1, &z2z2 );                  /* S1 = Y1*Z2^3    */
  fd_bls_fp2_mul( &s2, &p2->y, &p1->z );
  fd_bls_fp2_mul( &s2, &s2, &z1z1 );                  /* S2 = Y2*Z1^3    */
  fd_bls_fp2_sub( &h, &u2, &u1 );                     /* H  = U2-U1      */
  fd_bls_fp2_sub( &r, &s2, &s1 );                     /* R  = S2-S1      */
  fd_bls_fp2_add( &sx, &u1, &u2 );                    /* sx = U1+U2      */
  fd_bls_fp2_mul( &zmul, &p1->z, &p2->z );            /* Z1*Z2           */

  if( FD_UNLIKELY( fd_bls_fp2_equal( &u1, &u2 ) && fd_bls_fp2_equal( &s1, &s2 ) ) ) {
    /* doubling: H'=2Y1, R'=3X1^2+A'Z1^4, sx=2X1, U1=X1, S1=Y1, zz=Z1 */
    fd_bls_fp2_t z4;
    fd_bls_fp2_add( &h, &p1->y, &p1->y );
    fd_bls_fp2_sqr( &r, &p1->x );
    fd_bls_fp2_mul_small( &r, &r, 3U );
    fd_bls_fp2_sqr( &z4, &z1z1 );
    fp2_mul_sswu_a( &z4, &z4 );                       /* A'*Z1^4         */
    fd_bls_fp2_add( &r, &r, &z4 );
    fd_bls_fp2_add( &sx, &p1->x, &p1->x );
    u1 = p1->x; s1 = p1->y; zmul = p1->z;
  }

  fd_bls_fp2_t h2, h3s1, h2u1, x3, y3, z3;
  fd_bls_fp2_mul( &z3, &zmul, &h );                   /* Z3 = H*Z1*Z2    */
  fd_bls_fp2_sqr( &h2, &h );                          /* H^2             */
  fd_bls_fp2_mul( &h3s1, &h2, &h );
  fd_bls_fp2_mul( &h3s1, &h3s1, &s1 );                /* H^3*S1          */
  fd_bls_fp2_mul( &h2u1, &h2, &u1 );                  /* H^2*U1          */
  fd_bls_fp2_mul( &h2, &h2, &sx );                    /* H^2*sx          */
  fd_bls_fp2_sqr( &x3, &r );
  fd_bls_fp2_sub( &x3, &x3, &h2 );                    /* X3 = R^2-H^2*sx */
  fd_bls_fp2_sub( &y3, &h2u1, &x3 );
  fd_bls_fp2_mul( &y3, &y3, &r );
  fd_bls_fp2_sub( &y3, &y3, &h3s1 );                  /* Y3 = R(H^2U1-X3)-H^3S1 */
  p1->x = x3; p1->y = y3; p1->z = z3;
}

/* --- 3-isogeny map E' -> E2 in RNS (blst isogeny_map_to_E2 port) --- */
static void
isogeny_map_rns( fd_bls_p2_projective_t *       out,  /* Jacobian on E2 */
                 fd_bls_p2_projective_t const * p ) { /* Jacobian on E' */
#define C2(name_re,name_im) fp2_const_hash( name_re, name_im )
  fd_bls_fp2_t zz[3], map[3], xn, xd, yn, yd, t;
  fd_bls_fp2_sqr( &zz[2], &p->z );                     /* Z^2 */
  fd_bls_fp2_sqr( &zz[1], &zz[2] );                    /* Z^4 */
  fd_bls_fp2_mul( &zz[0], &zz[2], &zz[1] );            /* Z^6 */

  fd_bls_fp2_t iso_xn[4], iso_xd[2], iso_yn[4], iso_yd[3];
  iso_xn[0] = C2( fd_bls_iso_xn0, fd_bls_iso_xn0 );
  fd_bls_fp_zero( &iso_xn[1].c[0] );
  iso_xn[1].c[1] = fd_bls_iso_xn1_im;
  iso_xn[2] = C2( fd_bls_iso_xn2_re, fd_bls_iso_xn2_im );
  iso_xn[3].c[0] = fd_bls_iso_xn3_re;
  fd_bls_fp_zero( &iso_xn[3].c[1] );
  fd_bls_fp_zero( &iso_xd[0].c[0] );
  iso_xd[0].c[1] = fd_bls_iso_xd0_im;
  iso_xd[1] = C2( fd_bls_iso_xd1_re, fd_bls_iso_xd1_im );
  iso_yn[0] = C2( fd_bls_iso_yn0, fd_bls_iso_yn0 );
  fd_bls_fp_zero( &iso_yn[1].c[0] );
  iso_yn[1].c[1] = fd_bls_iso_yn1_im;
  iso_yn[2] = C2( fd_bls_iso_yn2_re, fd_bls_iso_yn2_im );
  iso_yn[3].c[0] = fd_bls_iso_yn3_re;
  fd_bls_fp_zero( &iso_yn[3].c[1] );
  iso_yd[0] = C2( fd_bls_iso_yd0, fd_bls_iso_yd0 );
  fd_bls_fp_zero( &iso_yd[1].c[0] );
  iso_yd[1].c[1] = fd_bls_iso_yd1_im;
  iso_yd[2] = C2( fd_bls_iso_yd2_re, fd_bls_iso_yd2_im );
#undef C2

  /* x numerator: Horner in X with coefficients scaled by Z powers */
  for( int i=0; i<3; i++ ) fd_bls_fp2_mul( &map[i], &iso_xn[i], &zz[i] );
  fd_bls_fp2_mul( &xn, &p->x, &iso_xn[3] );
  fd_bls_fp2_add( &xn, &xn, &map[2] );
  fd_bls_fp2_mul( &xn, &xn, &p->x );
  fd_bls_fp2_add( &xn, &xn, &map[1] );
  fd_bls_fp2_mul( &xn, &xn, &p->x );
  fd_bls_fp2_add( &xn, &xn, &map[0] );

  /* x denominator (monic degree 2) */
  for( int i=0; i<2; i++ ) fd_bls_fp2_mul( &map[i], &iso_xd[i], &zz[i+1] );
  fd_bls_fp2_add( &xd, &p->x, &map[1] );
  fd_bls_fp2_mul( &xd, &xd, &p->x );
  fd_bls_fp2_add( &xd, &xd, &map[0] );
  fd_bls_fp2_mul( &xd, &xd, &zz[2] );

  /* y numerator */
  for( int i=0; i<3; i++ ) fd_bls_fp2_mul( &map[i], &iso_yn[i], &zz[i] );
  fd_bls_fp2_mul( &yn, &p->x, &iso_yn[3] );
  fd_bls_fp2_add( &yn, &yn, &map[2] );
  fd_bls_fp2_mul( &yn, &yn, &p->x );
  fd_bls_fp2_add( &yn, &yn, &map[1] );
  fd_bls_fp2_mul( &yn, &yn, &p->x );
  fd_bls_fp2_add( &yn, &yn, &map[0] );
  fd_bls_fp2_mul( &yn, &yn, &p->y );

  /* y denominator (monic degree 3), scaled by Z^3 */
  for( int i=0; i<3; i++ ) fd_bls_fp2_mul( &map[i], &iso_yd[i], &zz[i] );
  fd_bls_fp2_add( &yd, &p->x, &map[2] );
  fd_bls_fp2_mul( &yd, &yd, &p->x );
  fd_bls_fp2_add( &yd, &yd, &map[1] );
  fd_bls_fp2_mul( &yd, &yd, &p->x );
  fd_bls_fp2_add( &yd, &yd, &map[0] );
  fd_bls_fp2_mul( &t, &zz[2], &p->z );                 /* Z^3 */
  fd_bls_fp2_mul( &yd, &yd, &t );

  /* to Jacobian */
  fd_bls_fp2_mul( &out->z, &xd, &yd );                 /* Z = xd*yd       */
  fd_bls_fp2_mul( &out->x, &xn, &yd );
  fd_bls_fp2_mul( &out->x, &out->x, &out->z );         /* X = xn*yd*Z     */
  fd_bls_fp2_sqr( &t, &out->z );
  fd_bls_fp2_mul( &out->y, &t, &xd );
  fd_bls_fp2_mul( &out->y, &out->y, &yn );             /* Y = Z^2*xd*yn   */
}

/* [-z] ladder over a PROJECTIVE base (complete proj x proj adds, so the
   base needs no affinization). */
static fd_bls_p2_projective_t
ladder_minus_z_proj( fd_bls_p2_projective_t const * q ) {
  fd_bls_p2_projective_t r = *q;
  fd_bls_g2_double( &r, &r, 0 );
  for( int i=0; i<5; i++ ) {
    fd_bls_g2_add_projective( &r, &r, q );
    for( uint j=0U; j<fd_bls_miller_iterations[i]; j++ )
      fd_bls_g2_double( &r, &r, 0 );
  }
  return r;
}

/* Clears the cofactor and writes an affine RNS point. */
static void
clear_cofactor_rns( fd_bls_hash_t *                 out,
                    fd_bls_p2_projective_t const * pj ) { /* Jacobian */
  /* Jacobian (Xj:Yj:Zj), x = Xj/Zj^2, y = Yj/Zj^3 -> homogeneous
     (Xh:Yh:Zh), x = Xh/Zh: Zh = Zj^3, Xh = Xj*Zj, Yh = Yj.  Three
     multiplies replace an affinize inversion; every chain op below
     accepts any homogeneous representative of the same affine point, so
     only the FINAL affinize inversion remains. */
  fd_bls_p2_projective_t Ph;
  fd_bls_fp2_t z2;
  fd_bls_fp2_sqr( &z2, &pj->z );
  fd_bls_fp2_mul( &Ph.z, &z2, &pj->z );
  fd_bls_fp2_mul( &Ph.x, &pj->x, &pj->z );
  Ph.y = pj->y;

  /* --- Budroni-Pintore chain (blst map_to_g2.c clear_cofactor) ---
     out = [z^2-z-1]P + [z-1]Psi(P) + Psi^2(2P)
       r  = Psi^2(2P) - P - Psi(P)
       t0 = [-z+1]P - Psi(P)
       t1 = [-z]t0 = [z^2-z]P + [z]Psi(P)
       r  = r + t1
     All EC work on the Miller chain's complete homogeneous formulas (same
     machinery as sig_validate's [-z]Q ladder); psi on homogeneous coords
     needs no inversion.  Inversions only at the final affine
     normalization. */
  fd_bls_p2_projective_t r = Ph;
  fd_bls_g2_double( &r, &r, 0 );                      /* r = 2P */
  psi_projective( &r );                        /* r = Psi(2P) */
  psi_projective( &r );                        /* r = Psi^2(2P) */

  fd_bls_p2_projective_t t1p = Ph;             /* t1p = -Psi(P) */
  psi_projective( &t1p );
  fd_bls_fp2_neg( &t1p.y, &t1p.y );
  fd_bls_p2_projective_t npp = Ph;             /* npp = -P */
  fd_bls_fp2_neg( &npp.y, &npp.y );

  /* r = Psi^2(2P) - P - Psi(P) */
  fd_bls_g2_add_projective( &r, &r, &npp );
  fd_bls_g2_add_projective( &r, &r, &t1p );

  /* t0 = [-z+1]P - Psi(P) */
  fd_bls_p2_projective_t t0 = ladder_minus_z_proj( &Ph );
  fd_bls_g2_add_projective( &t0, &t0, &Ph );
  fd_bls_g2_add_projective( &t0, &t0, &t1p );

  /* t1 = [-z]t0 via the projective-base ladder (complete proj x proj
     adds: the projective base needs no affinization), then the final
     complete projective addition r += t1 — together this drops the two
     inter-stage Fp2 inversions of the affine-add formulation. */
  fd_bls_p2_projective_t t1proj = ladder_minus_z_proj( &t0 );
  fd_bls_g2_add_projective( &r, &r, &t1proj );

  /* affinize r; emit the affine (x, y) */
  fd_bls_fp2_t fzinv, fx, fy;
  fd_bls_fp2_inverse( &fzinv, &r.z );
  fd_bls_fp2_mul( &fx, &r.x, &fzinv );
  fd_bls_fp2_mul( &fy, &r.y, &fzinv );
  out->x = fx;
  out->y = fy;
}

/* --- main entry: native hash_msg --- */

void
fd_bls_hash_to_g2_from_field( fd_bls_hash_t *      h,
                               fd_bls_fp2_t const   u[2] ) {
  /* Phase 3: SSWU both elements (pair-interleaved recip-sqrt chains),
     complete Jacobian add on E', 3-isogeny to E2 -- all in RNS */
  fd_bls_p2_projective_t pq[2], pre;
  sswu_map2_rns( pq, u );
  ec_dadd_eprime_rns( &pq[0], &pq[1] );
  isogeny_map_rns( &pre, &pq[0] );

  /* Phase 4: native cofactor clear; output remains in RNS. */
  clear_cofactor_rns( h, &pre );
}

void
fd_bls_hash_to_g2( uchar const *   msg,
                           ulong           msg_sz,
                           uchar const *   dst,
                           ulong           dst_len,
                           fd_bls_hash_t * h ) {
  /* Phase 1: expand_message_xmd (blst public API) */
  uchar pseudo[256];
  blst_expand_message_xmd( pseudo, 256, msg, msg_sz, dst, dst_len );

  /* Phase 2: reduce 64-byte blocks mod p and enter RNS */
  fd_bls_fp2_t u[2];
  for( int i=0; i<2; i++ ) {
    for( int j=0; j<2; j++ ) {
      ulong limbs[8];
      uchar const * b = pseudo + (i*2+j)*64;
      for( int k=0; k<8; k++ ) {
        /* fd_bls_rns_reduce_512 consumes little-endian limb order (in[0] = least
           significant limb); the hash block is big-endian bytes. */
        ulong v = 0;
        for( int m=0; m<8; m++ ) v = (v<<8) | b[(7-k)*8+m];
        limbs[k] = v;
      }
      ulong canon[6];
      fd_bls_rns_reduce_512( canon, limbs );
      fd_bls_fp_from_uint64( &u[i].c[j], canon );
    }
  }

  /* Phases 3 and 4: map_to_curve(u0) + map_to_curve(u1), cofactor clear */
  fd_bls_hash_to_g2_from_field( h, u );
}
