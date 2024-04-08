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

void
fd_r43x6_ge_smul_base_ref( wwl_t * _R03, wwl_t * _R14, wwl_t * _R25,
                           void const * _vs ) {
  uchar const * _s = (uchar const *)_vs;

  // Section 6 "class EdwardsPoint" [page 51]
  //
  // def __mul__(self,x):
  //     r=self.zero_elem()
  //     s=self
  //     while x > 0:
  //         if (x%2)>0:
  //             r=r+s
  //         s=s.double()
  //         x=x//2
  //     return r

  FD_R43X6_QUAD_DECL( R ); FD_R43X6_GE_ZERO( R ); /* R = neutral point, in u44|u44|u44|u44 */
  FD_R43X6_QUAD_DECL( S ); FD_R43X6_GE_ONE ( S ); /* S = base point,    in u44|u44|u44|u44 */

  for( int b=0; b<255; b++ ) { /* Note: s_255 is zero */
    int sb = (((int)_s[ b>>3 ]) >> (b&7)) & 1;
    if( sb ) FD_R43X6_GE_ADD( R, R, S );          /* R += S,            in u44|u44|u44|u44 */
    FD_R43X6_GE_DBL( S, S );                      /* S *= 2,            in u44|u44|u44|u44 */
  }

  FD_R43X6_QUAD_MOV( *_R, R );                    /* return R,          in u44|u44|u44|u44 */
}

FD_IMPORT( fd_r43x6_ge_smul_base_large_table, "src/ballet/ed25519/table/fd_r43x6_ge_smul_base_large_table", wwl_t, 7, "" );
/* 384 KiB */

void
fd_r43x6_ge_smul_base_large( wwl_t * _R03, wwl_t * _R14, wwl_t * _R25,
                             void const * _vs ) {
  uchar const * _s = (uchar const *)_vs;

  /* 8-bit table lookup based with table precomp and table symmetry.
     Theory:

       R = sum_{i in [0,256)} s_i 2^i B

     Reshape the sum:

       R = sum_{i in [0,2)} sum_{j in [0,16)} sum_{k in [0,8)} s_l 2^l B

     where:

       l = 16 j + 8 i + k

     Factoring out the 2^(8*i), we have:

       R = sum_{i in [0,2)} 2^(8 i) sum_{j in [0,16)} sum_{k in [0,8)} s_l 2^(16 j + k) B

     The k sums can be precomputed into a table:

       table(j,w) = sum_{k in [0,8)} w_k 2^(16 j+k) B

     The table is indexed [0,16)x[0,256).  With this table, we have:

       R = sum_{i in [0,2)} 2^(8 i) sum_{j in [0,16)} table(j,s_{m+7:m})

     where m = 16*j + 8*i.  That is, when i=0 / i=1, we are summing
     table lookups over the even / odd bytes of s.  Expanding the i sum:

       R = (2^8) sum_{j in [0,16)} table(j,s[2j+1])
         +       sum_{j in [0,16)} table(j,s[2j  ])

     As such, we accumulate all the odd bytes, double the result 8 times
     and then finish accumulating the even bytes.  This yields the basic
     structure below.

     The original sum can be thought of as over bytes of s:

       R = sum_{i in [0,32)} s[i] 2^(8 i) B

     and we note that the s[i] can be thought of as arbitrary integers.
     As we result, if we do:

       t[i]   = s[i]   - 2^8 carry
       t[i+1] = s[i+1] +     carry

     for some integer valued carry, the sum above will not be changed.
     Using this, we can transform s[i] from the range [0,256) to the
     range [-128,128] quickly.  This yields:

       R = (2^8) sum_{j in [0,16)} (sgn s[2j+1]) table(j,|s[2j+1])|)
         +       sum_{j in [0,16)} (sgn s[2j  ]) table(j,|s[2j  ])|)

     where sgn x is -1,0,+1 if x is negative,zero,positive.  The benefit
     of this is that we now only need to index the table [0x16)x[1,128).
     This results in a table half the size.  The negating of the table
     entries is a very small amount of extra (branchless) work.

     The last optimization is to note that we can optimize the
     representation of the table entries to save some calculations in
     the accumulation.  Specifically, ADD_TABLE needs
     (Y-X,Y+X,2*Z,2*d*T) and we can normalize the table such that Z is
     1.  This allows us to store:

       (Y-X,Y+X,-2*d*T,2*d*T)

     as reduced fd_r43x6_t in a FD_R43X6_QUAD in the table.  When we
     load a table entry, if we need to negate it, we swap the lanes 0,1
     and lanes 2,3 and blend in 2*Z = 2 into FD_R43X6_QUAD lane 2 to get
     the desired ADD_TABLE input.

     This results in the below.

     The upshot is that the reference version does ~256 GE_DBL and ~128
     GE_ADD while this only does ~8 GE_DBL and ~32 (faster)
     GE_ADD_TABLE.

     This is the same algorithm used by OpenSSL scalarmult_base but,
     unlike that implementation, this actually documents how it works
     (which then enables one to much better optimize it) and this works
     8-bits at a time instead of a 4-bits at a time.  This plus the use
     of a faster fd_r43x6 representation (instead of the r25.5x10) and
     then an AVX-512 accelerated implementation of that faster
     representation are the main sources of speedups for this
     implementation.

     Working 8-bits at a time requires use of a significantly larger
     table than the OpenSSL implementation but modern cores have large
     caches and FD use cases expect that tiles will be specialized for
     operations like signing.  So using a larger fraction of those
     caches for larger tables is justified.

     We could work more than 8-bits at a time but the table size doubles
     for each additional bit such that the table rapidly becomes
     impractical to store.  Additionally, the number of GE_DBL scales
     linearly with this such that, at some point, it becomes
     counterproductive (i.e. the increased number of GE_DBL reduces the
     benefit of having fewer GE_ADD_TABLE).  That is, the costs grow
     exponentially while the benefits improve sublinearly.

     Other reshaping of the sum are possible but this above seems to
     result in the best result practically. */

  /* Transform s into a 32 signed 16-bit int limb representation.  At
     this point, _s[0:30] are in [0,256) and _s[31] is in [0,128). */

  short _t[32];

  int carry = 0;
  for( int i=0; i<31; i++ ) {

    /* At this point, carry in [0,1]  */

    int si = ((int)_s[i]) + carry;   /* In [   0,256] */
    carry = (si>=128);               /* In [   0,  1] (0 if ti in [0,127], 1 if ti in [128,256]) */
    _t[i] = (short)(si - 256*carry); /* In [-128,128) (0:127 map to 0:7, 8:16 map to -8:0) */
  }

  /* At this point, carry in [0,1]  */

  _t[31] = (short)(((int)_s[31]) + carry); /* In [0,128] */

  /* Accumulate the odd bytes, scale and then accumulate the even bytes
     as per the above.  At this point _t[0:30] in [-128,128) (fits into
     schar), _t[31] in [0,128] (almost fits into a schar), or, more
     generically, _t[*] in [-128,128]. */

  FD_R43X6_QUAD_DECL( R ); FD_R43X6_GE_ZERO( R );                     /* R = neutral point, in u44|u44|u44|u44 */

  FD_R43X6_QUAD_DECL( two );
  two03 = wwl( 2L,2L,2L,2L, 0L,0l,0L,0L );
  two14 = wwl_zero();
  two25 = wwl_zero();                                                 /* two = 2|2|2|2,     in u44|u44|u44|u44 */

  int i = 2;
  do {
    i--;

    for( int j=0; j<16; j++ ) {
      int w = (int)_t[2*j+i];

      FD_R43X6_QUAD_DECL( T );

      /* Direct table lookup might be vulnerable to timing attacks as
         performance can depend on the data cache state, branch
         prediction cache state, etc, all of which are affected by
         recently passed s (among other things).

         The OpenSSL style mitigation loads the entire table over the
         course of the calculation and branchlessly selects out the
         needed table entries to make the timing independent of the s
         passed.  This is much more expensive and can thrash the cache,
         especially if done as a one-off calculation in a thread that
         does lots of other unrelated stuff. */

#     if 1 /* No timing attack mitigations */

      if( FD_UNLIKELY( !w ) ) continue; /* Shortcut if nothing to do */
      int l = (3*128)*j + 3*((int)fd_int_abs( w ) - 1);
      wwl_t perm = wwl_if( w<0 ? 0xff : 0x00, wwl( 1L,0L,3L,2L,5L,4L,7L,6L ), wwl( 0L,1L,2L,3L,4L,5L,6L,7L ) );
      T03 = wwl_if( (1<<2)|(1<<6), two03, wwl_permute( perm, fd_r43x6_ge_smul_base_large_table[ l + 0 ] ) );
      T14 = wwl_if( (1<<2)|(1<<6), two14, wwl_permute( perm, fd_r43x6_ge_smul_base_large_table[ l + 1 ] ) );
      T25 = wwl_if( (1<<2)|(1<<6), two25, wwl_permute( perm, fd_r43x6_ge_smul_base_large_table[ l + 2 ] ) );

#     else /* OpenSSL style timing attack mitigations */

      int idx = (int)fd_int_abs( w ) - 1;
      T03 = wwl( 1L,1L,0L,0L, 0L,0L,0L,0L ); /* (1,1,0,0) */
      T14 = wwl_zero();
      T25 = wwl_zero();
      for( int k=0; k<128; k++ ) {
        int keep = (idx==k) ? 0xff : 0x00;
        int l    = (3*128)*j + 3*k;
        T03 = wwl_if( keep, fd_r43x6_ge_smul_base_large_table[ l + 0 ], T03 );
        T14 = wwl_if( keep, fd_r43x6_ge_smul_base_large_table[ l + 1 ], T14 );
        T25 = wwl_if( keep, fd_r43x6_ge_smul_base_large_table[ l + 2 ], T25 );
      }
      wwl_t perm = wwl_if( (w<0) ? 0xff : 0x00, wwl( 1L,0L,3L,2L,5L,4L,7L,6L ), wwl( 0L,1L,2L,3L,4L,5L,6L,7L ) );
      T03 = wwl_if( (1<<2)|(1<<6), two03, wwl_permute( perm, T03 ) );
      T14 = wwl_if( (1<<2)|(1<<6), two14, wwl_permute( perm, T14 ) );
      T25 = wwl_if( (1<<2)|(1<<6), two25, wwl_permute( perm, T25 ) );

#     endif

      /* At this point T in u44|u44|u44|u44 */

      FD_R43X6_GE_ADD_TABLE( R, T, R );                               /* R += T, R in u44|u44|u44|u44 */
    }

    if( i ) for( ulong rem=8UL; rem; rem-- ) FD_R43X6_GE_DBL( R, R ); /* R *= 2, R in u44|u44|u44|u44 */

  } while( i );

  FD_R43X6_QUAD_MOV( *_R, R );                                        /* return R, in u44|u44|u44|u44 */
}

FD_IMPORT( fd_r43x6_ge_smul_base_small_table, "src/ballet/ed25519/table/fd_r43x6_ge_smul_base_small_table", wwl_t, 7, "" );
/* 48 KiB */

void
fd_r43x6_ge_smul_base_small( wwl_t * _R03, wwl_t * _R14, wwl_t * _R25,
                             void const * _vs ) {
  uchar const * _s = (uchar const *)_vs;

  /* See ge_smul_base_large for details.  This operates 4-bits at time
     instead of 8-bits.  That is, this is the original OpenSSL algorithm
     converted to use AVX-512 accelerated curve operations. */

  /* Unpack s into a 64 signed 4-bit int limb representation. */

  schar _t[64];

  for( int i=0; i<32; i++ ) {
    int si = (int)_s[i];
    _t[2*i+0] = (schar)(si & 15);
    _t[2*i+1] = (schar)(si >> 4);
  }

  /* At this point _t[0:62] in [0,16), _t[63] in [0,8) */

  int carry = 0;
  for( int i=0; i<63; i++ ) {
    int ti = ((int)_t[i]) + carry;  /* In [ 0,16] */
    carry = (ti>=8);                /* In [ 0, 1] (0 if ti in [0,7], 1 if ti in [8,16]) */
    _t[i] = (schar)(ti - 16*carry); /* In [-8, 8) (0:7 map to 0:7, 8:16 map to -8:0) */
  }
  _t[63] = (schar)(((int)_t[63]) + carry); /* In [0,8] */

  /* At this point _t[0:62] in [-8,8), _t[63] in [0,8], or, more
     generically, _t[*] in [-8,8] */

  FD_R43X6_QUAD_DECL( R ); FD_R43X6_GE_ZERO( R );                     /* R = neutral point, in u44|u44|u44|u44 */

  FD_R43X6_QUAD_DECL( two );
  two03 = wwl( 2L,2L,2L,2L, 0L,0l,0L,0L );
  two14 = wwl_zero();
  two25 = wwl_zero();                                                 /* two = 2|2|2|2,     in u44|u44|u44|u44 */

  int i = 2;
  do {
    i--;

    for( int j=0; j<32; j++ ) {
      int w = (int)_t[2*j+i];

      FD_R43X6_QUAD_DECL( T );

      /* See details above re mitigations */

#     if 0 /* No timing attack mitigations */

      if( FD_UNLIKELY( !w ) ) continue; /* Shortcut if nothing to do */
      int l = (3*8)*j + 3*((int)fd_int_abs( w ) - 1);
      wwl_t perm = wwl_if( w<0 ? 0xff : 0x00, wwl( 1L,0L,3L,2L,5L,4L,7L,6L ), wwl( 0L,1L,2L,3L,4L,5L,6L,7L ) );
      T03 = wwl_if( (1<<2)|(1<<6), two03, wwl_permute( perm, fd_r43x6_ge_smul_base_small_table[ l + 0 ] ) );
      T14 = wwl_if( (1<<2)|(1<<6), two14, wwl_permute( perm, fd_r43x6_ge_smul_base_small_table[ l + 1 ] ) );
      T25 = wwl_if( (1<<2)|(1<<6), two25, wwl_permute( perm, fd_r43x6_ge_smul_base_small_table[ l + 2 ] ) );

#     else /* OpenSSL style timing attack mitigations */

      int idx = (int)fd_int_abs( w ) - 1;
      T03 = wwl( 1L,1L,0L,0L, 0L,0L,0L,0L ); /* (1,1,0,0) */
      T14 = wwl_zero();
      T25 = wwl_zero();
      for( int k=0; k<8; k++ ) {
        int keep = (idx==k) ? 0xff : 0x00;
        int l    = (3*8)*j + 3*k;
        T03 = wwl_if( keep, fd_r43x6_ge_smul_base_small_table[ l + 0 ], T03 );
        T14 = wwl_if( keep, fd_r43x6_ge_smul_base_small_table[ l + 1 ], T14 );
        T25 = wwl_if( keep, fd_r43x6_ge_smul_base_small_table[ l + 2 ], T25 );
      }
      wwl_t perm = wwl_if( (w<0) ? 0xff : 0x00, wwl( 1L,0L,3L,2L,5L,4L,7L,6L ), wwl( 0L,1L,2L,3L,4L,5L,6L,7L ) );
      T03 = wwl_if( (1<<2)|(1<<6), two03, wwl_permute( perm, T03 ) );
      T14 = wwl_if( (1<<2)|(1<<6), two14, wwl_permute( perm, T14 ) );
      T25 = wwl_if( (1<<2)|(1<<6), two25, wwl_permute( perm, T25 ) );

#     endif

      /* At this point T in u44|u44|u44|u44 */

      FD_R43X6_GE_ADD_TABLE( R, T, R );                               /* R += T, R in u44|u44|u44|u44 */
    }

    if( i ) for( ulong rem=4UL; rem; rem-- ) FD_R43X6_GE_DBL( R, R ); /* R *= 2, R in u44|u44|u44|u44 */

  } while( i );

  FD_R43X6_QUAD_MOV( *_R, R );                                        /* return R, in u44|u44|u44|u44 */
}

void
fd_r43x6_ge_fma_ref( wwl_t * _R03, wwl_t * _R14, wwl_t * _R25,
                     void const * _vs,
                     wwl_t    P03, wwl_t    P14, wwl_t    P25,
                     wwl_t    Q03, wwl_t    Q14, wwl_t    Q25 ) {

  /* See smul_base_ref above for details how this works */

  uchar const * _s = (uchar const *)_vs;
  for( int b=0; b<255; b++ ) {
    int sb = (((int)_s[ b>>3 ]) >> (b&7)) & 1;
    if( sb ) FD_R43X6_GE_ADD( Q, Q, P );       /* Q += P,   in u44|u44|u44|u44 */
    FD_R43X6_GE_DBL( P, P );                   /* P *= 2,   in u44|u44|u44|u44 */
  }

  FD_R43X6_QUAD_MOV( *_R, Q );                 /* return Q, in u44|u44|u44|u44 */
}

void
fd_r43x6_ge_sparse_table( wwl_t *    table,
                          wwl_t P03, wwl_t P14, wwl_t P25,
                          int        max ) {

  FD_R43X6_QUAD_DECL( P2 ); FD_R43X6_GE_DBL( P2, P );          /* P2 = 2*P,                  in u44|u44|u44|u44 */
  FD_R43X6_QUAD_DECL( wP ); FD_R43X6_QUAD_MOV( wP, P );        /* wP = P,                    in u44|u44|u44|u44 */

  for( int w=1; w<=max; w+=2 ) {
    if( FD_LIKELY( w>1 ) ) FD_R43X6_GE_ADD( wP, wP, P2 );      /* wP += 2*P,                 in u44|u44|u44|u44 */

    /* At this point wP = [w]P */

    fd_r43x6_t wPX, wPY, wPZ, wPT;
    FD_R43X6_QUAD_UNPACK( wPX, wPY, wPZ, wPT, wP );
    int l;

    fd_r43x6_t YmX  = fd_r43x6_sub_fast( wPY, wPX );           /* YmX  = Y-X,                in s44 */
    fd_r43x6_t YpX  = fd_r43x6_add_fast( wPY, wPX );           /* YpX  = Y+X,                in u45 */
    fd_r43x6_t Z2   = fd_r43x6_add_fast( wPZ, wPZ );           /* Z2   = 2*Z,                in u45 */
    fd_r43x6_t T2d  = fd_r43x6_mul_fast( wPT, fd_r43x6_2d() ); /* T2d  =  T*2*d,             in u62 */
    fd_r43x6_t nT2d = fd_r43x6_neg_fast( T2d );                /* nT2d = -T*2*d,             in s62 */

    FD_R43X6_QUAD_DECL( T );

    FD_R43X6_QUAD_PACK( T, YmX, YpX, Z2, T2d );                /* T    = Y-X|Y+X|2*Z| T*2*d, in s44|u45|u45|u62 */
    FD_R43X6_QUAD_FOLD_SIGNED( T, T );                         /* T    = Y-X|Y+X|2*Z| T*2*d, in u44|u44|u44|u44 */
    l = 3*((max+w)>>1);
    table[ l + 0 ] = T03;
    table[ l + 1 ] = T14;
    table[ l + 2 ] = T25;

    FD_R43X6_QUAD_PACK( T, YpX, YmX, Z2, nT2d );               /* T    = Y+X|Y-X|2*Z|-T*2*d, in u45|s44|u45|s62 */
    FD_R43X6_QUAD_FOLD_SIGNED( T, T );                         /* T    = Y+X|Y-X|2*Z|-T*2*d, in u44|u44|u44|u44 */
    l = 3*((max-w)>>1);
    table[ l + 0 ] = T03;
    table[ l + 1 ] = T14;
    table[ l + 2 ] = T25;
  }
}

/* fd_r43x6_ge_sparsen converts a little endian uint256 number in
   [0,2^255) into a sparse representation such that:

      s = sum(i=0:255) s_i 2^i
        = sum(i=0:256) t_i 2^i

   where t_i are mostly zero and the non-zero values are odd and in
   [-max,max]. */

static void
fd_r43x6_ge_sparsen( int *        _t,     /* 256-entry */
                     void const * _vs,    /* 32-byte, assumes bit 255 zero */
                     int          max ) { /* should be positive, odd and << INT_MAX */

  uchar const * _s = (uchar const *)_vs;

  /* Unpack s bits into _t */

  for( int i=0; i<255; i++ ) _t[i] = ((int)_s[i>>3] >> (i&7)) & 1;
  _t[255] = 0; /* Guarantee 0 termination even if bad data passed */

  /* At this point _t[*] in [0,1] */

  int i;

  for( i=0; i<256; i++ ) if( _t[i] ) break; /* Find first non-zero t */

  while( i<256 ) {

    /* At this point [0,i) have been made sparse and t[i] is 1.
       Absorb as many tj for j in (i,256) into ti as possible */

    int ti = 1;

    int j;
    for( j=i+1; j<256; j++ ) {
      int tj = _t[j];
      if( !tj ) continue;

      /* At this point, we've zeroed out (i,j) and we know tj is
         1.  We also know that ti is odd and in [-max,max].  Thus, if
         2^shift>(2*max), ti +/- 2^shift*tj is _not_ in [-max,max] and
         we can't merge this j and any following into i. */

      if( j-i > 30 ) break; /* make sure delta doesn't overflow */
      int delta = 1 << (j-i); /* even */
      if( delta>(2*max) ) break;

      /* See if we can add tj to ti.  If so, this implies we are
         subtracting 1 from tj, making it 0. */

      int tip = ti + delta; /* odd + even -> odd */
      if( tip<=max ) { /* Yep ... add it to ti and zero it out */
        ti    = tip; /* odd */
        _t[j] = 0;
        continue;
      }

      /* See if we can instead subtract tj from ti.  This implies we are
         adding 1 to tj, making it 2.  We carry-propagate this into tk
         for k>j, turning tj and possibly later tk to 0.  We note that
         delta for the next iteration will be so large that we can't
         possibly absorb it into ti so we can abort this inner loop.

         Note that if this carry propagates to _t[255] (which is
         strictly zero initially), we have _t[k]==0 for k in [j,254) and
         _t[255]==1.  The outer loop iteration will resume at i==255 and
         detect it is done when it can't scan further for additional j
         to absorb.  Hence we will never carry propagate off the end and
         the loop below is guaranteed to terminate. */

      int tim = ti - delta; /* odd + even -> odd */
      if( tim>=-max ) { /* Yep ... sub it from ti and carry propagate */
        ti    = tim; /* odd */
        _t[j] = 0;
        for(;;) {
          j++;
          if( !_t[j] ) { _t[j] = 1; break; }
          _t[j] = 0;
        }
        break;
      }

      /* We can't absorb tj into ti */

      break;
    }

    /* Finalize ti and advance */

    _t[i] = ti;
    i = j;
  }
}

void
fd_r43x6_ge_fma_sparse( wwl_t * _R03, wwl_t * _R14, wwl_t * _R25,
                        void const * _vs,
                        wwl_t    P03, wwl_t    P14, wwl_t    P25,
                        wwl_t    Q03, wwl_t    Q14, wwl_t    Q25 ) {

  /* We don't have the luxury of precomputing a large table for P
     off-line like we did above for B.  But, like above, we can treat
     the si as integer valued (not just binary valued).  Via the
     transformation:

       si + delta
       sj - delta 2^(j-i)

     where j>i, we can introduce sparsity to reduce the number of
     non-zero terms we have to compute.

     To do this usefully, we need to introduce this sparsity such that
     there are only a handful of values that need to be considered.
     This allows us to precompute on the fly a small table of the needed
     P multiples.

     The sparsen algorithm above can convert a binary array into a
     sparse array in fast O(N256 time where the non-zero values are odd
     and in [-MAX,+MAX].  We can compute a table with these multiplies
     (utilizing symmetry to only do expensive computations for half the
     table).

     The choice of MAX balances between increasing computation for the
     table computation nd decreasing work for the Horner's rule like
     accumulation loop.  Odd values in [-9,+9] empirically found to be
     good. */

# define MAX (9)

  wwl_t Ptable[3*(MAX+1)]; fd_r43x6_ge_sparse_table( Ptable, P03, P14, P25, MAX );

  /* Sparsen s into zero or odd values in [-MAX,+MAX] */

  int _w[256]; fd_r43x6_ge_sparsen( _w, _vs, MAX );

  /* Compute R = [s]P using the P multiple table and sparse s */

  FD_R43X6_QUAD_DECL( R ); FD_R43X6_GE_ZERO( R );              /* R    = neutral point,      in u44|u44|u44|u44 */

  int i;

  for( i=255; i>=0; i-- ) if( _w[i] ) break; /* Find highest index non-zero _w */

  for( ; i>=0; i-- ) {
    int w = _w[i];
    if( FD_UNLIKELY( w ) ) {
      int l = 3*((MAX+w)>>1);
      FD_R43X6_QUAD_DECL( T );
      T03 = Ptable[ l + 0 ];
      T14 = Ptable[ l + 1 ];
      T25 = Ptable[ l + 2 ];
      /* At this point, T in u44|u44|u44|u44 */
      FD_R43X6_GE_ADD_TABLE( R, T, R );                        /* R   += T,                  in u44|u44|u44|u44 */
    }
    if( FD_LIKELY( i ) ) FD_R43X6_GE_DBL( R, R );              /* R   *= 2,                  in u44|u44|u44|u44 */
  }

  /* Compute R = [s]P + Q */

  FD_R43X6_GE_ADD( R, R, Q );                                  /* R   += Q,                  in u44|u44|u44|u44 */
  FD_R43X6_QUAD_MOV( *_R, R );                                 /* return R,                  in u44|u44|u44|u44 */

# undef MAX
}

void
fd_r43x6_ge_dmul_ref( wwl_t * _R03, wwl_t * _R14, wwl_t * _R25,
                      void const * _vs,
                      void const * _vk,
                      wwl_t    A03, wwl_t    A14, wwl_t    A25 ) {
  uchar const * _s = (uchar const *)_vs;
  uchar const * _k = (uchar const *)_vk;

  /* See smul_base_ref above for details how this works */

  FD_R43X6_QUAD_DECL( B ); FD_R43X6_GE_ONE( B );               /* B   = base point,          in u44|u44|u44|u44 */
  FD_R43X6_QUAD_DECL( R ); FD_R43X6_GE_ZERO( R );              /* R   = neutral point,       in u44|u44|u44|u44 */

  for( int b=0; b<255; b++ ) { /* Note: s_255 and k_255 are zero */
    int sb = (((int)_s[ b>>3 ]) >> (b&7)) & 1;
    if( sb ) FD_R43X6_GE_ADD( R, R, B );                       /* R += B,                    in u44|u44|u44|u44 */
    FD_R43X6_GE_DBL( B, B );                                   /* B *= 2,                    in u44|u44|u44|u44 */

    int kb = (((int)_k[ b>>3 ]) >> (b&7)) & 1;
    if( kb ) FD_R43X6_GE_ADD( R, R, A );                       /* R += A,                    in u44|u44|u44|u44 */
    FD_R43X6_GE_DBL( A, A );                                   /* A *= 2,                    in u44|u44|u44|u44 */
  }

  FD_R43X6_QUAD_MOV( *_R, R );                                 /* return R,                  in u44|u44|u44|u44 */
}

FD_IMPORT( fd_r43x6_ge_dmul_sparse_table, "src/ballet/ed25519/table/fd_r43x6_ge_dmul_sparse_table", wwl_t, 7, "" ); /* 384 KiB */

void
fd_r43x6_ge_dmul_sparse( wwl_t * _R03, wwl_t * _R14, wwl_t * _R25,
                         void const * _vs,
                         void const * _vk,
                         wwl_t    A03, wwl_t    A14, wwl_t    A25 ) {

  /* This works very similar to fma_sparse above except it sparsens both
     s and k (and then with independently configurable max since we can
     precompute the B table off line.  Note: MAXK ~ 2047 such that this
     uses (almost) the same amount of memory as used by
     smul_base_large_table.  Ignoring memory costs, increasing MAXS
     increases performance, albeit by increasingly small amounts.  The
     table above will need to be recomputed if MAXS is changed. */

# define MAXS (2047)
# define MAXK (9)

  wwl_t Atable[3*(MAXK+1)]; fd_r43x6_ge_sparse_table( Atable, A03, A14, A25, MAXK );

  /* Sparsen s and k into a range of zero or odd values in [-MAXS,+MAXS], [-MAXK,+MAXK] */

  int _ws[256]; fd_r43x6_ge_sparsen( _ws, _vs, MAXS );
  int _wk[256]; fd_r43x6_ge_sparsen( _wk, _vk, MAXK );

  /* Compute R = [s]B + [k]A using the B and A multiple tables, sparse s
     and sparse k */

  FD_R43X6_QUAD_DECL( R ); FD_R43X6_GE_ZERO( R );              /* R    = neutral point,      in u44|u44|u44|u44 */

  int i;

  for( i=255; i>=0; i-- ) if( FD_UNLIKELY( _wk[i] | _ws[i] ) ) break; /* Find highest index non-zero _wk or _ws */

  for( ; i>=0; i-- ) {

    /* TODO: USE FN CALL OR LOOP TO MERGE COMMON CODE? */
    /* TODO: CONSIDER COMPUTING NEGATIVE ON THE FLY TO GET TWICE TABLE
       SIZE FOR SAME MEMORY FOOTPRINT FOR THE SPARSE TABLE */

    int ws = _ws[i];
    if( FD_UNLIKELY( ws ) ) {
      int l = 3*((MAXS+ws)>>1);
      FD_R43X6_QUAD_DECL( T );
      T03 = fd_r43x6_ge_dmul_sparse_table[ l + 0 ];
      T14 = fd_r43x6_ge_dmul_sparse_table[ l + 1 ];
      T25 = fd_r43x6_ge_dmul_sparse_table[ l + 2 ];
      /* At this point, T in u44|u44|u44|u44 */
      FD_R43X6_GE_ADD_TABLE( R, T, R );                        /* R   += T,                  in u44|u44|u44|u44 */

    }

    int wk = _wk[i];
    if( FD_UNLIKELY( wk ) ) {
      int l = 3*((MAXK+wk)>>1);
      FD_R43X6_QUAD_DECL( T );
      T03 = Atable[ l + 0 ];
      T14 = Atable[ l + 1 ];
      T25 = Atable[ l + 2 ];
      /* At this point, T in u44|u44|u44|u44 */
      FD_R43X6_GE_ADD_TABLE( R, T, R );                        /* R   += T,                  in u44|u44|u44|u44 */
    }

    if( FD_LIKELY( i ) ) FD_R43X6_GE_DBL( R, R );              /* R *= 2,                    in u44|u44|u44|u44 */

  }

  FD_R43X6_QUAD_MOV( *_R, R );                                 /* return R,                  in u44|u44|u44|u44 */

# undef MAXK
# undef MAXS
}
