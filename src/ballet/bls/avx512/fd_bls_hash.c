/* Native AVX-512 hash-to-curve (hash_msg) for BLS12-381 G2, bit-exact
   with blst_hash_to_g2:

   - Phase 1 uses blst's public expand_message_xmd.
   - Phase 2 reduces the four 64-byte blocks modulo p (reduce_512) and
     enters RNS directly.
   - Phase 3 runs the SSWU map, the E' point addition, and the 3-isogeny
     entirely in RNS.  The two dominant (p-3)/4 reciprocal-sqrt addition
     chains are pair-interleaved across the two independent u0/u1 map
     instances, hiding most of the IFMA reduce latency.
   - Phase 4 clears the cofactor with the Budroni-Pintore chain on the
     RNS Miller machinery (2x [-z] ladders + psi + complete additions),
     emitting the affine (x, y).

   The recip-sqrt chain layout, branch structure (QR select, zero-xd
   select, sqrt alignment), and isogeny Horner order are direct ports of
   blst's sqrt.c/map_to_g2.c, so every select has the same semantics;
   hash inputs are public, so data-dependent branches are fine here. */

#include "fd_bls_rns.h"
#include "fd_bls_field.h"
#include "fd_bls_miller.h"

#if FD_HAS_AVX512

#include "../../../third_party/blst/bindings/blst.h"

/* sgn0 must be evaluated on the CANONICAL value (RFC 9380 sgn0 is parity
   of the canonical representative).  Direct port of blst's
   sgn0_pty_mod_384: bit0 = parity, bit1 = value > (p-1)/2. */
static int
sgn0_pty_canon( ulong const a[6] ) {
  ulong ret = a[0] & 1UL;              /* parity */
  ulong tmp[6], carry = 0UL, borrow = 0UL;
  for( int i=0; i<6; i++ ) { ulong ai = a[i]; tmp[i] = ai<<1 | carry; carry = ai>>63; }
  for( int i=0; i<6; i++ ) { ulong pi = fd_bls_field_modulus[i] + borrow; borrow = tmp[i] < pi; }
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
  /* frob constants cached on first use (3 psi calls per hash) */
  static fd_bls_fp2_t frob_x, frob_y; static int init = 0;
  if( FD_UNLIKELY( !init ) ) {
    fd_bls_fp_zero( &frob_x.c[0] );
    frob_x.c[1] = FD_BLS_FP_CONST( frob1_3 );
    frob_y.c[0] = FD_BLS_FP_CONST( frob3_2 );
    frob_y.c[1] = FD_BLS_FP_CONST( frob3_3 );
    init = 1;
  }
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

/* ec_double / ec_add_pa / ladder_minus_z_affine (line-free complete
   formulas) live in fd_bls_miller.c, same translation unit. */

/* --- RNS small helpers for the SSWU domain parameters --- */

static inline fd_bls_fp2_t
fp2_const_hash( ulong const re_m1[8], ulong const re_m2[8],
                ulong const im_m1[8], ulong const im_m2[8] ) {
  fd_bls_fp2_t r;
  r.c[0] = (fd_bls_fp_t){ .m1 = wwv_ld( re_m1 ), .m2 = wwv_ld( re_m2 ) };
  r.c[1] = (fd_bls_fp_t){ .m1 = wwv_ld( im_m1 ), .m2 = wwv_ld( im_m2 ) };
  return r;
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
  fd_bls_fp_t c240 = FD_BLS_FP_CONST( c240 );
  fd_bls_fp_mul( &im, &in->c[0], &c240 );
  fd_bls_fp_mul( &re, &in->c[1], &c240 );
  fd_bls_fp_neg( &out->c[0], &re );
  out->c[1] = im;
}

/* Multiply by B' = 1012(1+u): 1012*((a-b) + (a+b)u), same bound note. */
static inline void
fp2_mul_sswu_b( fd_bls_fp2_t * out, fd_bls_fp2_t const * in ) {
  fd_bls_fp_t c1012 = FD_BLS_FP_CONST( c1012 );
  fd_bls_fp2_t nonres;
  fd_bls_fp_sub( &nonres.c[0], &in->c[0], &in->c[1] );
  fd_bls_fp_add( &nonres.c[1], &in->c[0], &in->c[1] );
  fd_bls_fp_mul( &out->c[0], &nonres.c[0], &c1012 );
  fd_bls_fp_mul( &out->c[1], &nonres.c[1], &c1012 );
}

/* --- pair-interleaved (p-3)/4 reciprocal-sqrt chain ---

   blst's Bos-Coster win=4 chain for (p-3)/4 (sqrt-addchain.h), replayed
   from a fixed op table on TWO independent operands in lockstep.  Op
   encoding: {0,d,s,-}: t[d]=t[s]^2; {1,d,a,b}: t[d]=t[a]*t[b];
   {2,-,n,k}: t[0]=t[0]^(2^n)*t[k]; {3,d,-,-}: t[d]=inp; {4,-,-,-}:
   out=t[0]^2.  377 squarings + 80 multiplies per lane; extracted and
   exponent-verified against (p-3)/4 by symbolic execution. */
static uchar const fd_bls_rsqrt_chain[][4] = {
  {3,13,0,0}, {0,0,13,0}, {1,8,0,13}, {0,4,0,0}, {1,1,8,0}, {1,6,4,8}, {1,9,1,4}, {1,12,6,4}, {1,3,9,4}, {1,7,12,4},
  {1,15,3,4}, {1,10,7,4}, {1,2,15,4}, {1,11,10,4}, {0,0,3,0}, {1,14,11,4}, {1,5,0,8}, {1,4,0,1}, {2,0,12,15}, {2,0,7,7},
  {2,0,4,1}, {2,0,6,6}, {2,0,7,11}, {2,0,5,4}, {2,0,2,8}, {2,0,6,3}, {2,0,6,3}, {2,0,6,9}, {2,0,3,8}, {2,0,7,3},
  {2,0,4,3}, {2,0,6,7}, {2,0,6,14}, {2,0,3,13}, {2,0,8,3}, {2,0,7,11}, {2,0,5,12}, {2,0,6,3}, {2,0,6,5}, {2,0,4,9},
  {2,0,8,5}, {2,0,4,3}, {2,0,7,11}, {2,0,9,10}, {2,0,2,8}, {2,0,5,6}, {2,0,7,1}, {2,0,7,9}, {2,0,6,11}, {2,0,5,5},
  {2,0,5,10}, {2,0,5,10}, {2,0,8,3}, {2,0,7,2}, {2,0,9,7}, {2,0,5,3}, {2,0,3,8}, {2,0,8,7}, {2,0,3,8}, {2,0,7,9},
  {2,0,9,7}, {2,0,6,2}, {2,0,6,4}, {2,0,5,4}, {2,0,5,4}, {2,0,4,3}, {2,0,3,8}, {2,0,8,2}, {2,0,7,4}, {2,0,5,4},
  {2,0,5,4}, {2,0,4,7}, {2,0,4,6}, {2,0,7,4}, {2,0,5,5}, {2,0,5,4}, {2,0,5,4}, {2,0,5,4}, {2,0,5,4}, {2,0,5,4},
  {2,0,5,4}, {2,0,4,3}, {2,0,6,2}, {2,0,4,1}, {4,0,0,0},
};

/* out[L] = in[L]^((p-3)/4); ret bit L set iff in[L] is a nonzero QR
   (blst recip_sqrt_fp semantics: (out*in)^2 == in). */
static int
fp_rsqrt_pair( fd_bls_fp_t       out[2],
               fd_bls_fp_t const in [2] ) {
  fd_bls_fp_t t[2][16];
  for( ulong i=0; i<sizeof(fd_bls_rsqrt_chain)/sizeof(fd_bls_rsqrt_chain[0]); i++ ) {
    uchar const * op = fd_bls_rsqrt_chain[i];
    switch( op[0] ) {
    case 0:
      fd_bls_fp_mul( &t[0][op[1]], &t[0][op[2]], &t[0][op[2]] );
      fd_bls_fp_mul( &t[1][op[1]], &t[1][op[2]], &t[1][op[2]] );
      break;
    case 1:
      fd_bls_fp_mul( &t[0][op[1]], &t[0][op[2]], &t[0][op[3]] );
      fd_bls_fp_mul( &t[1][op[1]], &t[1][op[2]], &t[1][op[3]] );
      break;
    case 2:
      for( uint n=0; n<op[2]; n++ ) {
        fd_bls_fp_mul( &t[0][0], &t[0][0], &t[0][0] );
        fd_bls_fp_mul( &t[1][0], &t[1][0], &t[1][0] );
      }
      fd_bls_fp_mul( &t[0][0], &t[0][0], &t[0][op[3]] );
      fd_bls_fp_mul( &t[1][0], &t[1][0], &t[1][op[3]] );
      break;
    case 3:
      t[0][op[1]] = in[0];
      t[1][op[1]] = in[1];
      break;
    default:
      fd_bls_fp_mul( &out[0], &t[0][0], &t[0][0] );
      fd_bls_fp_mul( &out[1], &t[1][0], &t[1][0] );
      break;
    }
  }
  int ret = 0;
  for( int l=0; l<2; l++ ) {
    fd_bls_fp_t chk;
    fd_bls_fp_mul( &chk, &out[l], &in[l] );   /* chk = in^((p+1)/4).            */
    fd_bls_fp_mul( &chk, &chk, &chk );        /* chk = in^((p+1)/2) = in iff QR. */
    ret |= fd_bls_fp_equal( &chk, &in[l] ) << l;
  }
  return ret;
}

/* sqrt alignment (blst sqrt_align_fp2): sqrt^2 must be inp rotated by a
   multiple of 90 degrees; rotate ret back by the matching root of unity.
   Candidate coefficients: 1, u, sqrt(sqrt(-1)) = frob3_2+frob3_3*u,
   sqrt(-sqrt(-1)) = frob3_3+frob3_3*u (verified: the canonical forms of
   blst's sqrt.c rotation constants equal those Frobenius constants). */
static void
sqrt_align_rns( fd_bls_fp2_t *       out,
                fd_bls_fp2_t const * sqrt,
                fd_bls_fp2_t const * inp ) {
  fd_bls_fp2_t t0;
  fd_bls_fp2_sqr( &t0, sqrt );
  if( fd_bls_fp_equal( &t0.c[0], &inp->c[0] ) &&
      fd_bls_fp_equal( &t0.c[1], &inp->c[1] ) ) return;                  /* coeff = 1 */
  fd_bls_fp2_t neg;
  fd_bls_fp2_neg( &neg, inp );
  if( fd_bls_fp_equal( &t0.c[0], &neg.c[0] ) &&
      fd_bls_fp_equal( &t0.c[1], &neg.c[1] ) ) {                         /* coeff = u */
    fd_bls_fp_t re = out->c[0];
    fd_bls_fp_neg( &out->c[0], &out->c[1] );
    out->c[1] = re;
    return;
  }
  fd_bls_fp2_t coeff;
  if( fd_bls_fp_equal( &t0.c[0], &inp->c[1] ) &&
      fd_bls_fp_equal( &t0.c[1], &neg.c[0] ) ) {       /* coeff = sqrt(sqrt(-1))  */
    coeff.c[0] = FD_BLS_FP_CONST( frob3_2 );
    coeff.c[1] = FD_BLS_FP_CONST( frob3_3 );
  } else {                                             /* coeff = sqrt(-sqrt(-1)) */
    coeff.c[0] = FD_BLS_FP_CONST( frob3_3 );
    coeff.c[1] = FD_BLS_FP_CONST( frob3_3 );
  }
  fd_bls_fp2_mul( out, out, &coeff );
}

/* Pair recip-sqrt over Fp2 (blst recip_sqrt_fp2, complex method), both
   lanes in lockstep so the two (p-3)/4 chains interleave.  Returns the
   per-lane is_sqrt mask. */
static int
recip_sqrt_f2_pair( fd_bls_fp2_t       out[2],
                    fd_bls_fp2_t const in [2] ) {
  fd_bls_fp_t aa[2], cc[2], t;
  fd_bls_fp2_t inp_[2];
  for( int l=0; l<2; l++ ) {
    fd_bls_fp_mul( &aa[l], &in[l].c[0], &in[l].c[0] );
    fd_bls_fp_mul( &t, &in[l].c[1], &in[l].c[1] );
    fd_bls_fp_add( &aa[l], &aa[l], &t );               /* aa = norm(in) = a^2+b^2 */
  }
  int is_sqrt = fp_rsqrt_pair( cc, aa );               /* cc = aa^((p-3)/4)       */

  fd_bls_fp2_t recip_zzz = fp2_const_hash( fd_bls_sswu_recip_zzz_re_m1, fd_bls_sswu_recip_zzz_re_m2,
                                           fd_bls_sswu_recip_zzz_im_m1, fd_bls_sswu_recip_zzz_im_m2 );
  fd_bls_fp_t magic0 = FD_BLS_FP_CONST( sswu_magic_zzz_0 );
  fd_bls_fp_t magic1 = FD_BLS_FP_CONST( sswu_magic_zzz_1 );
  fd_bls_fp_t inv2   = FD_BLS_FP_CONST( inv2 );

  fd_bls_fp_t aa2[2];
  for( int l=0; l<2; l++ ) {
    if( (is_sqrt>>l) & 1 ) {
      inp_[l] = in[l];
    } else {
      /* no QR: shift the input by 1/Z^3 and fix aa, cc to match */
      fd_bls_fp2_mul( &inp_[l], &in[l], &recip_zzz );
      fd_bls_fp_mul( &aa[l], &aa[l], &magic0 );        /* aa *= (za^2+zb^2)            */
      fd_bls_fp_mul( &cc[l], &cc[l], &magic1 );        /* cc *= (za^2+zb^2)^((p-3)/4)  */
    }
    fd_bls_fp_mul( &t, &aa[l], &cc[l] );               /* t  = sqrt(a^2+b^2)           */
    fd_bls_fp_t am, ap;
    fd_bls_fp_sub( &am, &inp_[l].c[0], &t );           /* am = a - sqrt(a^2+b^2)        */
    fd_bls_fp_add( &ap, &inp_[l].c[0], &t );           /* ap = a + sqrt(a^2+b^2)        */
    if( FD_UNLIKELY( fp_is_zero_rns( &ap ) ) ) ap = am;
    fd_bls_fp_mul( &aa2[l], &ap, &inv2 );              /* aa2 = (a +- sqrt(a^2+b^2))/2  */
  }

  fd_bls_fp_t r0[2];
  (void)fp_rsqrt_pair( r0, aa2 );                      /* r0 = 1/sqrt(aa2) (if any)    */

  for( int l=0; l<2; l++ ) {
    fd_bls_fp_mul( &out[l].c[1], &inp_[l].c[1], &inv2 );
    fd_bls_fp_mul( &out[l].c[1], &out[l].c[1], &r0[l] );  /* b/(2 sqrt(aa2)) */
    fd_bls_fp_mul( &out[l].c[0], &r0[l], &aa2[l] );       /* sqrt(aa2)       */
    sqrt_align_rns( &out[l], &out[l], &inp_[l] );         /* fix 90-degree rotation */
    fd_bls_fp_mul( &out[l].c[0], &out[l].c[0], &cc[l] );  /* invert via 1/sqrt(norm) */
    fd_bls_fp_mul( &out[l].c[1], &out[l].c[1], &cc[l] );
    fd_bls_fp_neg( &out[l].c[1], &out[l].c[1] );
  }
  return is_sqrt;
}

/* --- SSWU map to the isogenous curve E', both u values in lockstep ---
   Direct port of blst map_to_isogenous_E2; output is Jacobian on E'
   (reusing the projective struct for storage). */
static void
sswu_map2_rns( fd_bls_p2_projective_t out[2],
               fd_bls_fp2_t const     u  [2] ) {
  fd_bls_fp2_t uu[2], xd[2], gxd[2], tv2m[2], x1n[2], x2n[2], tv4[2], y1[2];

  for( int l=0; l<2; l++ ) {
    fd_bls_fp2_t zuu, tv2, t;
    fd_bls_fp2_sqr( &uu[l], &u[l] );                  /* uu  = u^2                 */
    fp2_mul_sswu_z( &zuu, &uu[l] );                   /* Zuu = Z*u^2               */
    fd_bls_fp2_sqr( &tv2, &zuu );
    fd_bls_fp2_add( &tv2, &tv2, &zuu );               /* tv2 = Zuu^2+Zuu           */
    fd_bls_fp2_t tv2p1 = tv2;
    fd_bls_fp_t one; fd_bls_fp_one( &one );
    fd_bls_fp_add( &tv2p1.c[0], &tv2p1.c[0], &one );
    fp2_mul_sswu_b( &x1n[l], &tv2p1 );                /* x1n = B'(tv2+1)           */
    fd_bls_fp2_mul( &x2n[l], &zuu, &x1n[l] );         /* x2n = Zuu*x1n             */

    fp2_mul_sswu_a( &xd[l], &tv2 );                   /* xd  = A'*tv2              */
    fd_bls_fp2_neg( &xd[l], &xd[l] );                 /* xd  = -A'*tv2             */
    if( FD_UNLIKELY( fp2_is_zero_rns( &xd[l] ) ) ) {
      /* xd==0: substitute Z*A' = 240-480u */
      xd[l].c[0] = FD_BLS_FP_CONST( c240 );
      xd[l].c[1] = FD_BLS_FP_CONST( sswu_zxa_im );
    }

    fd_bls_fp2_sqr( &t, &xd[l] );                     /* t    = xd^2               */
    fd_bls_fp2_mul( &gxd[l], &xd[l], &t );            /* gxd  = xd^3               */
    fp2_mul_sswu_a( &t, &t );                         /* t    = A'*xd^2            */
    fd_bls_fp2_t gx1;
    fd_bls_fp2_sqr( &gx1, &x1n[l] );
    fd_bls_fp2_add( &gx1, &gx1, &t );                 /* gx1  = x1n^2+A'xd^2       */
    fd_bls_fp2_mul( &gx1, &gx1, &x1n[l] );            /* gx1 *= x1n                */
    fp2_mul_sswu_b( &t, &gxd[l] );                    /* t    = B'*gxd             */
    fd_bls_fp2_add( &gx1, &gx1, &t );                 /* gx1  = g(x1n/xd)*gxd      */
    fd_bls_fp2_sqr( &tv4[l], &gxd[l] );               /* tv4  = gxd^2              */
    fd_bls_fp2_mul( &tv2m[l], &gx1, &gxd[l] );        /* tv2m = gx1*gxd            */
    fd_bls_fp2_mul( &tv4[l], &tv4[l], &tv2m[l] );     /* tv4  = gx1*gxd^3          */
  }

  int e2 = recip_sqrt_f2_pair( y1, tv4 );             /* y1 = tv4^-1/2 (shifted)   */

  for( int l=0; l<2; l++ ) {
    fd_bls_fp2_t y2, x, y;
    fd_bls_fp2_mul( &y1[l], &y1[l], &tv2m[l] );       /* y1 = sqrt(gx1/gxd) if e2  */
    fd_bls_fp2_mul( &y2, &y1[l], &uu[l] );
    fd_bls_fp2_mul( &y2, &y2, &u[l] );                /* y2 = y1*u^3               */
    if( (e2>>l) & 1 ) { x = x1n[l]; y = y1[l]; }
    else              { x = x2n[l]; y = y2;     }

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

  if( FD_UNLIKELY( fp2_is_zero_rns( &h ) && fp2_is_zero_rns( &r ) ) ) {
    /* doubling: H'=2Y1, R'=3X1^2+A'Z1^4, sx=2X1, U1=X1, S1=Y1, zz=Z1 */
    fd_bls_fp2_t z4;
    fd_bls_fp2_add( &h, &p1->y, &p1->y );
    fd_bls_fp2_sqr( &r, &p1->x );
    fp2_mul_small( &r, &r, 3U );
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
#define C2(name_re_m1,name_re_m2,name_im_m1,name_im_m2) \
  fp2_const_hash( name_re_m1, name_re_m2, name_im_m1, name_im_m2 )
  fd_bls_fp2_t zz[3], map[3], xn, xd, yn, yd, t;
  fd_bls_fp2_sqr( &zz[2], &p->z );                     /* Z^2 */
  fd_bls_fp2_sqr( &zz[1], &zz[2] );                    /* Z^4 */
  fd_bls_fp2_mul( &zz[0], &zz[2], &zz[1] );            /* Z^6 */

  fd_bls_fp2_t iso_xn[4], iso_xd[2], iso_yn[4], iso_yd[3];
  iso_xn[0] = C2( fd_bls_iso_xn0_m1, fd_bls_iso_xn0_m2, fd_bls_iso_xn0_m1, fd_bls_iso_xn0_m2 );
  fd_bls_fp_zero( &iso_xn[1].c[0] );
  iso_xn[1].c[1] = FD_BLS_FP_CONST( iso_xn1_im );
  iso_xn[2] = C2( fd_bls_iso_xn2_re_m1, fd_bls_iso_xn2_re_m2, fd_bls_iso_xn2_im_m1, fd_bls_iso_xn2_im_m2 );
  iso_xn[3].c[0] = FD_BLS_FP_CONST( iso_xn3_re );
  fd_bls_fp_zero( &iso_xn[3].c[1] );
  fd_bls_fp_zero( &iso_xd[0].c[0] );
  iso_xd[0].c[1] = FD_BLS_FP_CONST( iso_xd0_im );
  iso_xd[1] = C2( fd_bls_iso_xd1_re_m1, fd_bls_iso_xd1_re_m2, fd_bls_iso_xd1_im_m1, fd_bls_iso_xd1_im_m2 );
  iso_yn[0] = C2( fd_bls_iso_yn0_m1, fd_bls_iso_yn0_m2, fd_bls_iso_yn0_m1, fd_bls_iso_yn0_m2 );
  fd_bls_fp_zero( &iso_yn[1].c[0] );
  iso_yn[1].c[1] = FD_BLS_FP_CONST( iso_yn1_im );
  iso_yn[2] = C2( fd_bls_iso_yn2_re_m1, fd_bls_iso_yn2_re_m2, fd_bls_iso_yn2_im_m1, fd_bls_iso_yn2_im_m2 );
  iso_yn[3].c[0] = FD_BLS_FP_CONST( iso_yn3_re );
  fd_bls_fp_zero( &iso_yn[3].c[1] );
  iso_yd[0] = C2( fd_bls_iso_yd0_m1, fd_bls_iso_yd0_m2, fd_bls_iso_yd0_m1, fd_bls_iso_yd0_m2 );
  fd_bls_fp_zero( &iso_yd[1].c[0] );
  iso_yd[1].c[1] = FD_BLS_FP_CONST( iso_yd1_im );
  iso_yd[2] = C2( fd_bls_iso_yd2_re_m1, fd_bls_iso_yd2_re_m2, fd_bls_iso_yd2_im_m1, fd_bls_iso_yd2_im_m2 );
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
  r = ec_double( &r, 0 );
  for( int i=0; i<5; i++ ) {
    r = ec_add_pp( &r, q );
    for( uint j=0U; j<fd_bls_miller_iterations[i]; j++ )
      r = ec_double( &r, 0 );
  }
  return r;
}

/* Clears the cofactor of the pre-cofactor Jacobian point (RNS) and writes
   the affine result into |out| — the same 192-byte affine shape
   fd_bls_ref_hash_msg produces, so the native path is a byte-for-byte
   drop-in replacement. */
static void
clear_cofactor_rns( blst_p2_affine *               out,
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
  r = ec_double( &r, 0 );                      /* r = 2P */
  psi_projective( &r );                        /* r = Psi(2P) */
  psi_projective( &r );                        /* r = Psi^2(2P) */

  fd_bls_p2_projective_t t1p = Ph;             /* t1p = -Psi(P) */
  psi_projective( &t1p );
  fd_bls_fp2_neg( &t1p.y, &t1p.y );
  fd_bls_p2_projective_t npp = Ph;             /* npp = -P */
  fd_bls_fp2_neg( &npp.y, &npp.y );

  /* r = Psi^2(2P) - P - Psi(P) */
  r = ec_add_pp( &r, &npp );
  r = ec_add_pp( &r, &t1p );

  /* t0 = [-z+1]P - Psi(P) */
  fd_bls_p2_projective_t t0 = ladder_minus_z_proj( &Ph );
  t0 = ec_add_pp( &t0, &Ph );
  t0 = ec_add_pp( &t0, &t1p );

  /* t1 = [-z]t0 via the projective-base ladder (complete proj x proj
     adds: the projective base needs no affinization), then the final
     complete projective addition r += t1 — together this drops the two
     inter-stage Fp2 inversions of the affine-add formulation. */
  fd_bls_p2_projective_t t1proj = ladder_minus_z_proj( &t0 );
  r = ec_add_pp( &r, &t1proj );

  /* affinize r; emit the affine (x, y) */
  fd_bls_fp2_t fzinv, fx, fy;
  fp2_inverse_final( &fzinv, &r.z );
  fd_bls_fp2_mul( &fx, &r.x, &fzinv );
  fd_bls_fp2_mul( &fy, &r.y, &fzinv );
  ulong o[2][2][6];
  fd_bls_fp_to_uint64( o[0][0], &fx.c[0] ); fd_bls_fp_to_uint64( o[0][1], &fx.c[1] );
  fd_bls_fp_to_uint64( o[1][0], &fy.c[0] ); fd_bls_fp_to_uint64( o[1][1], &fy.c[1] );
  blst_fp_from_uint64( &out->x.fp[0], o[0][0] );
  blst_fp_from_uint64( &out->x.fp[1], o[0][1] );
  blst_fp_from_uint64( &out->y.fp[0], o[1][0] );
  blst_fp_from_uint64( &out->y.fp[1], o[1][1] );
}

/* --- main entry: native hash_msg --- */

void
fd_bls_g2_hash_msg_avx512( uchar const *   msg,
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
        /* reduce_512 consumes little-endian limb order (in[0] = least
           significant limb); the hash block is big-endian bytes. */
        ulong v = 0;
        for( int m=0; m<8; m++ ) v = (v<<8) | b[(7-k)*8+m];
        limbs[k] = v;
      }
      ulong canon[6];
      reduce_512( canon, limbs );
      fd_bls_fp_from_uint64( &u[i].c[j], canon );
    }
  }

  /* Phase 3: SSWU both elements (pair-interleaved recip-sqrt chains),
     complete Jacobian add on E', 3-isogeny to E2 -- all in RNS */
  fd_bls_p2_projective_t pq[2], pre;
  sswu_map2_rns( pq, u );
  ec_dadd_eprime_rns( &pq[0], &pq[1] );
  isogeny_map_rns( &pre, &pq[0] );

  /* Phase 4: native cofactor clear on the RNS Miller chain.  The output
     is the affine (x, y) — byte-identical to fd_bls_ref_hash_msg's
     affinized blst_hash_to_g2 result. */
  clear_cofactor_rns( (blst_p2_affine *)h, &pre );
}

#endif
