#include "fd_r43x6_ge.h"

/* Direct quotes from RFC 8032 are indicated with '//' style comments. */

wv_t
fd_r43x6_ge_encode( wwl_t P03, wwl_t P14, wwl_t P25 ) {

  // 5.1.2.  Encoding
  //
  // All values are coded as octet strings, and integers are coded using
  // little-endian convention, i.e., a 32-octet string h h[0],...h[31]
  // represents the integer h[0] + 2^8 * h[1] + ... + 2^248 * h[31].
  //
  // A curve point (x,y), with coordinates in the range 0 <= x,y < p, is
  // coded as follows.

  /* The below computes x=mod(X/Z) and y=mod(Y/Z) but doesn't repack
     the results into fd_r43x6_t's since we need to tweak y's limbs with
     values from x0 in the next part. */

  fd_r43x6_t X,Y,Z,T; FD_R43X6_QUAD_UNPACK( X,Y,Z,T, P ); /* in u47/u47/u47/u47 */
  (void)T;

  fd_r43x6_t one_Z = fd_r43x6_invert( Z ); /* in u44 */

  /* TODO: Consider a FD_R43X6_MUL2_FAST_INL? */
  fd_r43x6_t x = fd_r43x6_mul_fast( X, one_Z ); /* in u63 */     fd_r43x6_t y = fd_r43x6_mul_fast( Y, one_Z ); /* in u63 */

  long x0,x1,x2,x3,x4,x5; fd_r43x6_extract_limbs( x, x );        long y0,y1,y2,y3,y4,y5; fd_r43x6_extract_limbs( y, y );

  fd_r43x6_biased_carry_propagate_limbs( x, x, 0L ); /* in nr */ fd_r43x6_biased_carry_propagate_limbs( y, y, 0L ); /* in nr */

  fd_r43x6_mod_nearly_reduced_limbs( x, x ); /* in [0,p) */      fd_r43x6_mod_nearly_reduced_limbs( y, y ); /* in [0,p) */

  // First, encode the y-coordinate as a little-endian string of 32
  // octets.  The most significant bit of the final octet is always
  // zero.  To form the encoding of the point, copy the least
  // significant bit of the x-coordinate to the most significant bit of
  // the final octet.

  /* Since the limbs of y are already in a packed form, we copy the
     least significant bit before we pack up the uint256 to save some
     memory operations. */

  return fd_r43x6_pack( fd_r43x6( y0, y1, y2, y3, y4, y5 | ((x0 & 1L)<<40) ) );
}

int
fd_r43x6_ge_decode( wwl_t * _P03, wwl_t * _P14, wwl_t * _P25,
                    void const * _vs ) {

  // 5.1.3.  Decoding
  //
  // Decoding a point, given as a 32-octet string, is a little more
  // complicated.
  //
  // 1.  First, interpret the string as an integer in little-endian
  //     representation.

  ulong _s[4] __attribute__((aligned(32)));
  memcpy( _s, _vs, 32UL );
  ulong y0 = _s[0]; /* Bits   0- 63 */
  ulong y1 = _s[1]; /* Bits  64-127 */
  ulong y2 = _s[2]; /* Bits 128-191 */
  ulong y3 = _s[3]; /* Bits 192-255 */

  // Bit 255 of this number is the least significant bit of the
  // x-coordinate and denote this value x_0.

  int x_0 = (int)(y3>>63);

  // The y-coordinate is recovered simply by clearing this bit.

  y3 &= ~(1UL<<63);

  // If the resulting value is >= p, decoding fails.

  /* To do this, we add 19 to y ( which yields a 256-bit result, since y
     is in [0,2^255) after clearing the most significant bit of y3 ) and
     see if bit 255 is set.  If so, then y+19>=2^255, which implies y>=p. */

  ulong c = 19UL;
  ulong t;
  t = y0 + c; c = (ulong)(t<c);
  t = y1 + c; c = (ulong)(t<c);
  t = y2 + c; c = (ulong)(t<c);
  t = y3 + c;
  if( FD_UNLIKELY( t>>63 ) ) goto fail;

  fd_r43x6_t y = fd_r43x6_unpack( wv( y0, y1, y2, y3 ) );

  // 2.  To recover the x-coordinate, the curve equation implies x^2 =
  //     (y^2 - 1) / (d y^2 + 1) (mod p).  The denominator is always
  //     non-zero mod p.  Let u = y^2 - 1 and v = d y^2 + 1.

  fd_r43x6_t const one = fd_r43x6_one();
  fd_r43x6_t const d   = fd_r43x6_d();

  fd_r43x6_t ysq = fd_r43x6_sqr( y );                                /*       y^2     in u44 */
  fd_r43x6_t u   = fd_r43x6_sub( ysq, one );                         /* u =   y^2 - 1 in u44 */
  fd_r43x6_t v   = fd_r43x6_add_fast( fd_r43x6_mul( d, ysq ), one ); /* v = d y^2 + 1 in u44 */

  // To compute the square root of (u/v), the first step is to compute
  // the candidate root x = (u/v)^((p+3)/8).  This can be done with the
  // following trick, using a single modular powering for both the
  // inversion of v and the square root:
  //
  //            (p+3)/8      3        (p-5)/8
  //   x = (u/v)        = u v  (u v^7)         (mod p)

  fd_r43x6_t v2  = fd_r43x6_sqr( v        ); /* v^2               in u44 */
  fd_r43x6_t v4  = fd_r43x6_sqr( v2       ); /* v^4               in u44 */
  fd_r43x6_t v3  = fd_r43x6_mul( v,   v2  ); /* v^3               in u44 */
  fd_r43x6_t uv3 = fd_r43x6_mul( u,   v3  ); /* u v^3             in u44 */
  fd_r43x6_t uv7 = fd_r43x6_mul( uv3, v4  ); /* u v^7             in u44 */
  fd_r43x6_t t0  = fd_r43x6_pow22523( uv7 ); /* (u v^7)^((p-5)/8) in u44 */
  fd_r43x6_t x   = fd_r43x6_mul( uv3, t0  ); /* x                 in u44 */

  // 3.  Again, there are three cases:
  //
  //     1.  If v x^2 = u (mod p), x is a square root.
  //
  //     2.  If v x^2 = -u (mod p), set x <-- x * 2^((p-1)/4), which is
  //         a square root.
  //
  //     3.  Otherwise, no square root exists for modulo p, and decoding
  //         fails

  /* The implementation below has flattened the above branches to make
     it more amenable to doing multiple decodes concurrently.  This also
     makes this essentially a constant time algorithm (but such isn't
     required here). */

  fd_r43x6_t x2  = fd_r43x6_sqr( x );           /* x^2       in u44 */
  fd_r43x6_t vx2 = fd_r43x6_mul( v, x2 );       /* v x^2     in u44 */
  fd_r43x6_t t1  = fd_r43x6_sub_fast( vx2, u ); /* v x^2 - u in s44 */
  fd_r43x6_t t2  = fd_r43x6_add_fast( vx2, u ); /* v x^2 + u in u45 */
  int t1nz = fd_r43x6_is_nonzero( t1 );
  int t2nz = fd_r43x6_is_nonzero( t2 );
  if( FD_UNLIKELY( t1nz & t2nz ) ) goto fail; /* case 3 */
  fd_r43x6_t t3  = fd_r43x6_if( t1nz, fd_r43x6_imag(), one ); /* in u43 */
  /**/       x   = fd_r43x6_mul( x, t3 );                     /* in u44 */

  // 4.  Finally, use the x_0 bit to select the right square root.  If x
  //     = 0, and x_0 = 1, decoding fails." */

  /* Note that we could merge this branch with the above for even
     more deterministic performance.

     WARNING!  This check seems to be missing from the OpenSSL
     implementation. */

  int x_mod_2 = fd_r43x6_diagnose( x );
  if( FD_UNLIKELY( (x_mod_2==-1) & (x_0==1) ) ) goto fail;

  // Otherwise, if x_0 != x mod 2, set x <-- p - x.

  x = fd_r43x6_if( x_0!=x_mod_2, fd_r43x6_neg( x ) /* in u44 */, x );

  // Return the decoded point (x,y).

  FD_R43X6_QUAD_PACK( *_P,
    x,                      /* in u44 */
    y,                      /* Reduced */
    one,                    /* Reduced */
    fd_r43x6_mul( x, y ) ); /* in u44 */
  return 0;

fail:
  *_P03 = fd_r43x6_zero();
  *_P14 = fd_r43x6_zero();
  *_P25 = fd_r43x6_zero();
  return -1;
}

int
fd_r43x6_ge_decode2( wwl_t * _Pa03, wwl_t * _Pa14, wwl_t * _Pa25,
                     void const * _vsa,
                     wwl_t * _Pb03, wwl_t * _Pb14, wwl_t * _Pb25,
                     void const * _vsb ) {

# if 0 /* Reference implementation */

  if( FD_UNLIKELY( fd_r43x6_ge_decode( _Pa03, _Pa14, _Pa25, _vsa ) ) ) {
    *_Pb03 = wwl_zero(); *_Pb14 = wwl_zero(); *_Pb25 = wwl_zero();
    return -1;
  }

  if( FD_UNLIKELY( fd_r43x6_ge_decode( _Pb03, _Pb14, _Pb25, _vsb ) ) ) {
    *_Pa03 = wwl_zero(); *_Pa14 = wwl_zero(); *_Pa25 = wwl_zero();
    return -2;
  }

  return 0;

# else /* HPC implementation */

  fd_r43x6_t const one     = fd_r43x6_one();
  fd_r43x6_t const d       = fd_r43x6_d();
  fd_r43x6_t const sqrt_m1 = fd_r43x6_imag();

  ulong _sa[4] __attribute__((aligned(32)));                       ulong _sb[4] __attribute__((aligned(32)));
  memcpy( _sa, _vsa, 32UL );                                       memcpy( _sb, _vsb, 32UL );
  ulong y0a = _sa[0];                                              ulong y0b = _sb[0];
  ulong y1a = _sa[1];                                              ulong y1b = _sb[1];
  ulong y2a = _sa[2];                                              ulong y2b = _sb[2];
  ulong y3a = _sa[3];                                              ulong y3b = _sb[3];

  int x_0a = (int)(y3a>>63);                                       int x_0b = (int)(y3b>>63);

  y3a &= ~(1UL<<63);                                               y3b &= ~(1UL<<63);

  ulong ca = 19UL;                                                 ulong cb = 19UL;
  ulong ta;                                                        ulong tb;
  ta = y0a + ca; ca = (ulong)(ta<ca);                              tb = y0b + cb; cb = (ulong)(tb<cb);
  ta = y1a + ca; ca = (ulong)(ta<ca);                              tb = y1b + cb; cb = (ulong)(tb<cb);
  ta = y2a + ca; ca = (ulong)(ta<ca);                              tb = y2b + cb; cb = (ulong)(tb<cb);
  ta = y3a + ca;                                                   tb = y3b + cb;
  if( FD_UNLIKELY( ta>>63 ) ) goto faila;
  /**/                                                             if( FD_UNLIKELY( tb>>63 ) ) goto failb;

  _sa[0] = y0a;                                                    _sb[0] = y0b;
  _sa[1] = y1a;                                                    _sb[1] = y1b;
  _sa[2] = y2a;                                                    _sb[2] = y2b;
  _sa[3] = y3a;                                                    _sb[3] = y3b;
  fd_r43x6_t ya = fd_r43x6_unpack( wv_ld( _sa ) );                 fd_r43x6_t yb = fd_r43x6_unpack( wv_ld( _sb ) );

  fd_r43x6_t ysqa, ysqb; FD_R43X6_SQR2_INL   ( ysqa, ya,           ysqb, yb       );
  fd_r43x6_t ua = fd_r43x6_sub( ysqa, one );                       fd_r43x6_t ub = fd_r43x6_sub( ysqb, one );
  fd_r43x6_t va = fd_r43x6_add_fast( fd_r43x6_mul(d,ysqa), one );  fd_r43x6_t vb = fd_r43x6_add_fast( fd_r43x6_mul(d,ysqb), one );

  fd_r43x6_t v2a,  v2b;  FD_R43X6_SQR2_INL      ( v2a,  va,        v2b,  vb       );
  fd_r43x6_t v4a,  v4b;  FD_R43X6_SQR2_INL      ( v4a,  v2a,       v4b,  v2b      );
  fd_r43x6_t v3a,  v3b;  FD_R43X6_MUL2_INL      ( v3a,  va,v2a,    v3b,  vb,v2b   );
  fd_r43x6_t uv3a, uv3b; FD_R43X6_MUL2_INL      ( uv3a, ua,v3a,    uv3b, ub,v3b   );
  fd_r43x6_t uv7a, uv7b; FD_R43X6_MUL2_INL      ( uv7a, uv3a,v4a,  uv7b, uv3b,v4b );
  fd_r43x6_t t0a,  t0b;  FD_R43X6_POW22523_2_INL( t0a,  uv7a,      t0b,  uv7b     );
  fd_r43x6_t xa,   xb;   FD_R43X6_MUL2_INL      ( xa,   uv3a,t0a,  xb,   uv3b,t0b );

  fd_r43x6_t x2a,  x2b;  FD_R43X6_SQR2_INL      ( x2a,  xa,        x2b,  xb       );
  fd_r43x6_t vx2a, vx2b; FD_R43X6_MUL2_INL      ( vx2a, va,x2a,    vx2b, vb,x2b   );
  fd_r43x6_t t1a = fd_r43x6_sub_fast( vx2a, ua );                  fd_r43x6_t t1b = fd_r43x6_sub_fast( vx2b, ub );
  fd_r43x6_t t2a = fd_r43x6_add_fast( vx2a, ua );                  fd_r43x6_t t2b = fd_r43x6_add_fast( vx2b, ub );
  int t1nza = fd_r43x6_is_nonzero( t1a );                          int t1nzb = fd_r43x6_is_nonzero( t1b );
  int t2nza = fd_r43x6_is_nonzero( t2a );                          int t2nzb = fd_r43x6_is_nonzero( t2b );
  if( FD_UNLIKELY( t1nza & t2nza ) ) goto faila;
  /**/                                                             if( FD_UNLIKELY( t1nzb & t2nzb ) ) goto failb;

  fd_r43x6_t t3a = fd_r43x6_if( t1nza, sqrt_m1, one );             fd_r43x6_t t3b = fd_r43x6_if( t1nzb, sqrt_m1, one );
  /**/                   FD_R43X6_MUL2_INL      ( xa,   xa,t3a,    xb,   xb,t3b   );

  int x_mod_2a = fd_r43x6_diagnose( xa );                          int x_mod_2b = fd_r43x6_diagnose( xb );
  if( FD_UNLIKELY( (x_mod_2a==-1) & (x_0a==1) ) ) goto faila;
  /**/                                                             if( FD_UNLIKELY( (x_mod_2b==-1) & (x_0b==1) ) ) goto failb;
  xa = fd_r43x6_if( x_0a!=x_mod_2a, fd_r43x6_neg( xa ), xa );      xb = fd_r43x6_if( x_0b!=x_mod_2b, fd_r43x6_neg( xb ), xb );

  fd_r43x6_t xya,  xyb;  FD_R43X6_MUL2_INL      ( xya,  xa,ya,     xyb,  xb,yb    );

  FD_R43X6_QUAD_PACK( *_Pa, xa,ya,one,xya );                       FD_R43X6_QUAD_PACK( *_Pb, xb,yb,one,xyb );
  return 0;

faila:
  *_Pa03 = wwl_zero();                                             *_Pb03 = wwl_zero();
  *_Pa14 = wwl_zero();                                             *_Pb14 = wwl_zero();
  *_Pa25 = wwl_zero();                                             *_Pb25 = wwl_zero();
  return -1;

failb:
  *_Pa03 = wwl_zero();                                             *_Pb03 = wwl_zero();
  *_Pa14 = wwl_zero();                                             *_Pb14 = wwl_zero();
  *_Pa25 = wwl_zero();                                             *_Pb25 = wwl_zero();
  return -2;

# endif
}
