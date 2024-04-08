#include "../fd_ed25519_private.h"
#include "../fd_ed25519_ge.h"

/* Internal use representations of a ed25519 group element:

   ge_p1p1    (completed): ((X:Z),(Y:T)) satisfying x=X/Z, y=Y/T
   ge_precomp (Duif):      (y+x,y-x,2dxy) */

struct fd_ed25519_ge_p1p1_private {
  fd_ed25519_fe_t X[1];
  fd_ed25519_fe_t Y[1];
  fd_ed25519_fe_t Z[1];
  fd_ed25519_fe_t T[1];
};

typedef struct fd_ed25519_ge_p1p1_private fd_ed25519_ge_p1p1_t;

struct fd_ed25519_ge_precomp_private {
  fd_ed25519_fe_t yplusx [1];
  fd_ed25519_fe_t yminusx[1];
  fd_ed25519_fe_t xy2d   [1];
};

typedef struct fd_ed25519_ge_precomp_private fd_ed25519_ge_precomp_t;

static inline fd_ed25519_ge_precomp_t *
fd_ed25519_ge_precomp_0( fd_ed25519_ge_precomp_t * h ) {
  fd_ed25519_fe_1( h->yplusx  );
  fd_ed25519_fe_1( h->yminusx );
  fd_ed25519_fe_0( h->xy2d    );
  return h;
}

struct fd_ed25519_ge_cached_private {
  fd_ed25519_fe_t YplusX [1];
  fd_ed25519_fe_t YminusX[1];
  fd_ed25519_fe_t Z      [1];
  fd_ed25519_fe_t T2d    [1];
};

typedef struct fd_ed25519_ge_cached_private fd_ed25519_ge_cached_t;

static inline fd_ed25519_ge_cached_t *
fd_ed25519_ge_p3_to_cached( fd_ed25519_ge_cached_t *   r,
                            fd_ed25519_ge_p3_t const * p ) {
  static const fd_ed25519_fe_t d2[1] = {{
    { -21827239, -5839606, -30745221, 13898782, 229458, 15978800, -12551817, -6495438,  29715968, 9444199 }
  }};

  fd_ed25519_fe_add ( r->YplusX,  p->Y, p->X );
  fd_ed25519_fe_sub ( r->YminusX, p->Y, p->X );
  fd_ed25519_fe_copy( r->Z,       p->Z       );
  fd_ed25519_fe_mul ( r->T2d,     p->T, d2   );
  return r;
}

/**********************************************************************/

/* FIXME: THIS SEEMS UNNECESSARILY BYZANTINE (AND, IF THE POINT IS
   DETERMINISTIC TIMING, THIS COULD BE ACHIEVED MUCH MORE CLEANLY AND
   WITH LESS OVERHEAD). */

static inline int /* In {0,1} */
fd_ed25519_ge_precomp_negative( int b ) {
  return (int)(((uint)b) >> 31);
}

static inline int /* In {0,1} */
fd_ed25519_ge_precomp_equal( int b,
                             int c ) {
  return (int)((((uint)(b ^ c))-1U) >> 31);
}

static inline fd_ed25519_ge_precomp_t *
fd_ed25519_ge_precomp_if( fd_ed25519_ge_precomp_t *       t,
                          int                             c,
                          fd_ed25519_ge_precomp_t const * u,
                          fd_ed25519_ge_precomp_t const * v ) {
  fd_ed25519_fe_if( t->yplusx,  c, u->yplusx,  v->yplusx  );
  fd_ed25519_fe_if( t->yminusx, c, u->yminusx, v->yminusx );
  fd_ed25519_fe_if( t->xy2d,    c, u->xy2d,    v->xy2d    );
  return t;
}

static fd_ed25519_ge_precomp_t *
fd_ed25519_ge_table_select( fd_ed25519_ge_precomp_t * t,
                            int                       pos,
                            int                       b ) { /* In -8:8 */

# include "../table/fd_ed25519_ge_k25519_precomp.c"

  int bnegative = fd_ed25519_ge_precomp_negative( b );
  int babs      = b - (int)((uint)((-bnegative) & b) << 1); /* b = b - (2*b) = -b = |b| if b<0, b - 2*0 = b = |b| o.w. */
  fd_ed25519_ge_precomp_0( t );
  fd_ed25519_ge_precomp_if( t, fd_ed25519_ge_precomp_equal( babs, 1 ), k25519_precomp[ pos ][ 0 ], t );
  fd_ed25519_ge_precomp_if( t, fd_ed25519_ge_precomp_equal( babs, 2 ), k25519_precomp[ pos ][ 1 ], t );
  fd_ed25519_ge_precomp_if( t, fd_ed25519_ge_precomp_equal( babs, 3 ), k25519_precomp[ pos ][ 2 ], t );
  fd_ed25519_ge_precomp_if( t, fd_ed25519_ge_precomp_equal( babs, 4 ), k25519_precomp[ pos ][ 3 ], t );
  fd_ed25519_ge_precomp_if( t, fd_ed25519_ge_precomp_equal( babs, 5 ), k25519_precomp[ pos ][ 4 ], t );
  fd_ed25519_ge_precomp_if( t, fd_ed25519_ge_precomp_equal( babs, 6 ), k25519_precomp[ pos ][ 5 ], t );
  fd_ed25519_ge_precomp_if( t, fd_ed25519_ge_precomp_equal( babs, 7 ), k25519_precomp[ pos ][ 6 ], t );
  fd_ed25519_ge_precomp_if( t, fd_ed25519_ge_precomp_equal( babs, 8 ), k25519_precomp[ pos ][ 7 ], t );
  fd_ed25519_ge_precomp_t minust[1];
  fd_ed25519_fe_copy( minust->yplusx,  t->yminusx );
  fd_ed25519_fe_copy( minust->yminusx, t->yplusx  );
  fd_ed25519_fe_neg ( minust->xy2d,    t->xy2d    );
  fd_ed25519_ge_precomp_if( t, bnegative, minust, t );
  return t;
}

/**********************************************************************/

static inline fd_ed25519_ge_p3_t *
fd_ed25519_ge_p2_to_p3( fd_ed25519_ge_p3_t *       r,
                        fd_ed25519_ge_p2_t const * p ) {
  fd_ed25519_fe_mul( r->X, p->X, p->Z );
  fd_ed25519_fe_mul( r->Y, p->Y, p->Z );
  fd_ed25519_fe_sq ( r->Z, p->Z );
  fd_ed25519_fe_mul( r->T, p->X, p->Y );
  return r;
}

static inline fd_ed25519_ge_p2_t *
fd_ed25519_ge_p3_to_p2( fd_ed25519_ge_p2_t *       r,
                        fd_ed25519_ge_p3_t const * p ) {
  fd_ed25519_fe_copy( r->X, p->X );
  fd_ed25519_fe_copy( r->Y, p->Y );
  fd_ed25519_fe_copy( r->Z, p->Z );
  return r;
}

static inline fd_ed25519_ge_p2_t *
fd_ed25519_ge_p1p1_to_p2( fd_ed25519_ge_p2_t *         r,
                          fd_ed25519_ge_p1p1_t * const p ) {
  fd_ed25519_fe_mul3( r->X, p->X, p->T,
                      r->Y, p->Y, p->Z,
                      r->Z, p->Z, p->T );
  return r;
}

static inline fd_ed25519_ge_p3_t *
fd_ed25519_ge_p1p1_to_p3( fd_ed25519_ge_p3_t *         r,
                          fd_ed25519_ge_p1p1_t const * p ) {
  fd_ed25519_fe_mul4( r->X, p->X, p->T,
                      r->Y, p->Y, p->Z,
                      r->Z, p->Z, p->T,
                      r->T, p->X, p->Y );
  return r;
}

static inline fd_ed25519_ge_p1p1_t *
fd_ed25519_ge_p2_dbl( fd_ed25519_ge_p1p1_t *     r,
                      fd_ed25519_ge_p2_t const * p ) {
  fd_ed25519_fe_t t0[1];
  fd_ed25519_fe_add ( r->Y, p->X, p->Y );
  fd_ed25519_fe_sqn4( r->X, p->X, 1L,
                      r->Z, p->Y, 1L,
                      r->T, p->Z, 2L,
                      t0,   r->Y, 1L   );
  fd_ed25519_fe_add ( r->Y, r->Z, r->X );
  fd_ed25519_fe_sub ( r->Z, r->Z, r->X );
  fd_ed25519_fe_sub ( r->X, t0,   r->Y );
  fd_ed25519_fe_sub ( r->T, r->T, r->Z );
  return r;
}

static inline fd_ed25519_ge_p1p1_t *
fd_ed25519_ge_p3_dbl( fd_ed25519_ge_p1p1_t *     r,
                      fd_ed25519_ge_p3_t const * p ) {
  fd_ed25519_ge_p2_t q[1];
  fd_ed25519_ge_p3_to_p2( q, p );
  fd_ed25519_ge_p2_dbl  ( r, q );
  return r;
}

FD_FN_UNUSED static fd_ed25519_ge_p1p1_t * /* Work around -Winline */
fd_ed25519_ge_add( fd_ed25519_ge_p1p1_t *         r,
                   fd_ed25519_ge_p3_t const *     p,
                   fd_ed25519_ge_cached_t const * q ) {
  fd_ed25519_fe_t t0[1];
  fd_ed25519_fe_add ( r->X, p->Y,   p->X       );
  fd_ed25519_fe_sub ( r->Y, p->Y,   p->X       );
  fd_ed25519_fe_mul4( r->Z, r->X,   q->YplusX,
                      r->Y, r->Y,   q->YminusX,
                      r->T, q->T2d, p->T,
                      r->X, p->Z,   q->Z       );
  fd_ed25519_fe_add ( t0,   r->X,   r->X       );
  fd_ed25519_fe_sub ( r->X, r->Z,   r->Y       );
  fd_ed25519_fe_add ( r->Y, r->Z,   r->Y       );
  fd_ed25519_fe_add ( r->Z, t0,     r->T       );
  fd_ed25519_fe_sub ( r->T, t0,     r->T       );
  return r;
}

static inline fd_ed25519_ge_p1p1_t *
fd_ed25519_ge_sub( fd_ed25519_ge_p1p1_t *         r,
                   fd_ed25519_ge_p3_t const *     p,
                   fd_ed25519_ge_cached_t const * q ) {
  fd_ed25519_fe_t t0[1];
  fd_ed25519_fe_add ( r->X, p->Y,   p->X       );
  fd_ed25519_fe_sub ( r->Y, p->Y,   p->X       );
  fd_ed25519_fe_mul4( r->Z, r->X,   q->YminusX,
                      r->Y, r->Y,   q->YplusX,
                      r->T, q->T2d, p->T,
                      r->X, p->Z,   q->Z       );
  fd_ed25519_fe_add ( t0,   r->X,   r->X       );
  fd_ed25519_fe_sub ( r->X, r->Z,   r->Y       );
  fd_ed25519_fe_add ( r->Y, r->Z,   r->Y       );
  fd_ed25519_fe_sub ( r->Z, t0,     r->T       );
  fd_ed25519_fe_add ( r->T, t0,     r->T       );
  return r;
}

static inline fd_ed25519_ge_p1p1_t *
fd_ed25519_ge_madd( fd_ed25519_ge_p1p1_t *          r,
                    fd_ed25519_ge_p3_t const *      p,
                    fd_ed25519_ge_precomp_t const * q ) {
  fd_ed25519_fe_t t0[1];
  fd_ed25519_fe_add ( r->X, p->Y,    p->X       );
  fd_ed25519_fe_sub ( r->Y, p->Y,    p->X       );
  fd_ed25519_fe_mul3( r->Z, r->X,    q->yplusx,
                      r->Y, r->Y,    q->yminusx,
                      r->T, q->xy2d, p->T       );
  fd_ed25519_fe_add ( t0,   p->Z,    p->Z       );
  fd_ed25519_fe_sub ( r->X, r->Z,    r->Y       );
  fd_ed25519_fe_add ( r->Y, r->Z,    r->Y       );
  fd_ed25519_fe_add ( r->Z, t0,      r->T       );
  fd_ed25519_fe_sub ( r->T, t0,      r->T       );
  return r;
}

static inline fd_ed25519_ge_p1p1_t *
fd_ed25519_ge_msub( fd_ed25519_ge_p1p1_t *          r,
                    fd_ed25519_ge_p3_t const *      p,
                    fd_ed25519_ge_precomp_t const * q ) {
  fd_ed25519_fe_t t0[1];
  fd_ed25519_fe_add ( r->X, p->Y,    p->X       );
  fd_ed25519_fe_sub ( r->Y, p->Y,    p->X       );
  fd_ed25519_fe_mul3( r->Z, r->X,    q->yminusx,
                      r->Y, r->Y,    q->yplusx,
                      r->T, q->xy2d, p->T       );
  fd_ed25519_fe_add ( t0,   p->Z,    p->Z       );
  fd_ed25519_fe_sub ( r->X, r->Z,    r->Y       );
  fd_ed25519_fe_add ( r->Y, r->Z,    r->Y       );
  fd_ed25519_fe_sub ( r->Z, t0,      r->T       );
  fd_ed25519_fe_add ( r->T, t0,      r->T       );
  return r;
}

/**********************************************************************/

int
fd_ed25519_ge_frombytes_vartime( fd_ed25519_ge_p3_t * h,
                                 uchar const *        s ) {

  static const fd_ed25519_fe_t d[1] = {{
    { -10913610, 13857413, -15372611, 6949391, 114729, -8787816, -6275908, -3247719, -18696448, -12055116 }
  }};

  static const fd_ed25519_fe_t sqrtm1[1] = {{
    { -32595792, -7943725, 9377950, 3500415, 12389472, -272473, -25146209, -2005654, 326686, 11406482 }
  }};

  fd_ed25519_fe_t u[1];
  fd_ed25519_fe_t v[1];
  fd_ed25519_fe_frombytes( h->Y, s    );
  fd_ed25519_fe_1        ( h->Z       );
  fd_ed25519_fe_sq       ( u, h->Y    );
  fd_ed25519_fe_mul      ( v, u, d    );
  fd_ed25519_fe_sub      ( u, u, h->Z );    /* u = y^2-1 */
  fd_ed25519_fe_add      ( v, v, h->Z );    /* v = dy^2+1 */

  fd_ed25519_fe_t v3[1];
  fd_ed25519_fe_sq ( v3,   v       );
  fd_ed25519_fe_mul( v3,   v3, v   );       /* v3 = v^3 */
  fd_ed25519_fe_sq ( h->X, v3      );
  fd_ed25519_fe_mul( h->X, h->X, v );
  fd_ed25519_fe_mul( h->X, h->X, u );       /* x = uv^7 */

  fd_ed25519_fe_pow22523( h->X, h->X     ); /* x = (uv^7)^((q-5)/8) */
  fd_ed25519_fe_mul     ( h->X, h->X, v3 );
  fd_ed25519_fe_mul     ( h->X, h->X, u  ); /* x = uv^3(uv^7)^((q-5)/8) */

  fd_ed25519_fe_t vxx  [1];
  fd_ed25519_fe_t check[1];
  fd_ed25519_fe_sq ( vxx,   h->X   );
  fd_ed25519_fe_mul( vxx,   vxx, v );
  fd_ed25519_fe_sub( check, vxx, u ); /* vx^2-u */
  if( fd_ed25519_fe_isnonzero( check ) ) { /* unclear prob */
    fd_ed25519_fe_add( check, vxx, u ); /* vx^2+u */
    if( FD_UNLIKELY( fd_ed25519_fe_isnonzero( check ) ) ) return FD_ED25519_ERR_PUBKEY;
    fd_ed25519_fe_mul( h->X, h->X, sqrtm1 );
  }

  if( fd_ed25519_fe_isnegative( h->X )!=(s[31] >> 7) ) fd_ed25519_fe_neg( h->X, h->X ); /* unclear prob */

  fd_ed25519_fe_mul( h->T, h->X, h->Y );
  return FD_ED25519_SUCCESS;
}

int
fd_ed25519_ge_frombytes_vartime_2( fd_ed25519_ge_p3_t * h0, uchar const * s0,
                                   fd_ed25519_ge_p3_t * h1, uchar const * s1 ) {

  static const fd_ed25519_fe_t d[1] = {{
    { -10913610, 13857413, -15372611, 6949391, 114729, -8787816, -6275908, -3247719, -18696448, -12055116 }
  }};

  static const fd_ed25519_fe_t sqrtm1[1] = {{
    { -32595792, -7943725, 9377950, 3500415, 12389472, -272473, -25146209, -2005654, 326686, 11406482 }
  }};

  fd_ed25519_fe_t u0[1];
  fd_ed25519_fe_t v0[1];
  fd_ed25519_fe_t u1[1];
  fd_ed25519_fe_t v1[1];
  fd_ed25519_fe_frombytes  ( h0->Y, s0       );
  fd_ed25519_fe_frombytes  ( h1->Y, s1       );
  fd_ed25519_fe_1          ( h0->Z           );
  fd_ed25519_fe_1          ( h1->Z           );
  fd_ed25519_fe_sqn2       ( u0, h0->Y, 1,
                             u1, h1->Y, 1    );
  fd_ed25519_fe_mul2       ( v0, u0, d,
                             v1, u1, d       );
  fd_ed25519_fe_sub        ( u0, u0, h0->Z   );     /* u = y^2-1 */
  fd_ed25519_fe_sub        ( u1, u1, h1->Z   );     /* u = y^2-1 */
  fd_ed25519_fe_add        ( v0, v0, h0->Z   );     /* v = dy^2+1 */
  fd_ed25519_fe_add        ( v1, v1, h1->Z   );     /* v = dy^2+1 */

  fd_ed25519_fe_t v30_0[1]; fd_ed25519_fe_t v30_1[1];
  fd_ed25519_fe_sqn2      ( v30_0, v0, 1,
                            v30_1, v1, 1     );
  fd_ed25519_fe_mul2      ( v30_0, v30_0, v0,       /* v3 = v^3 */
                            v30_1, v30_1, v1 );     /* v3 = v^3 */
  fd_ed25519_fe_sqn2      ( h0->X, v30_0, 1,
                            h1->X, v30_1, 1  );
  fd_ed25519_fe_mul2      ( h0->X, h0->X, v0,
                            h1->X, h1->X, v1 );
  fd_ed25519_fe_mul2      ( h0->X, h0->X, u0,       /* x = uv^7 */
                            h1->X, h1->X, u1 );     /* x = uv^7 */

  fd_ed25519_fe_pow22523_2( h0->X, h0->X,           /* x = (uv^7)^((q-5)/8) */
                            h1->X, h1->X        );  /* x = (uv^7)^((q-5)/8) */
  fd_ed25519_fe_mul2      ( h0->X, h0->X, v30_0,
                            h1->X, h1->X, v30_1 );
  fd_ed25519_fe_mul2      ( h0->X, h0->X, u0,       /* x = uv^3(uv^7)^((q-5)/8) */
                            h1->X, h1->X, u1    );  /* x = uv^3(uv^7)^((q-5)/8) */

  fd_ed25519_fe_t vxx0[1]; fd_ed25519_fe_t check0[1];
  fd_ed25519_fe_t vxx1[1]; fd_ed25519_fe_t check1[1];
  fd_ed25519_fe_sqn2      ( vxx0,   h0->X, 1,
                            vxx1,   h1->X, 1 );
  fd_ed25519_fe_mul2      ( vxx0,   vxx0, v0,
                            vxx1,   vxx1, v1 );
  fd_ed25519_fe_sub       ( check0, vxx0, u0 ); /* vx^2-u */
  fd_ed25519_fe_sub       ( check1, vxx1, u1 ); /* vx^2-u */

  if( fd_ed25519_fe_isnonzero( check0 ) ) { /* unclear prob */
    fd_ed25519_fe_add( check0, vxx0, u0 );  /* vx^2+u */
    if( FD_UNLIKELY( fd_ed25519_fe_isnonzero( check0 ) ) ) return FD_ED25519_ERR_PUBKEY;
    fd_ed25519_fe_mul( h0->X, h0->X, sqrtm1 );
  }
  if( fd_ed25519_fe_isnegative( h0->X )!=(s0[31] >> 7) ) fd_ed25519_fe_neg( h0->X, h0->X ); /* unclear prob */
  fd_ed25519_fe_mul( h0->T, h0->X, h0->Y );

  if( fd_ed25519_fe_isnonzero( check1 ) ) { /* unclear prob */
    fd_ed25519_fe_add( check1, vxx1, u1 );  /* vx^2+u */
    if( FD_UNLIKELY( fd_ed25519_fe_isnonzero( check1 ) ) ) return FD_ED25519_ERR_SIG;
    fd_ed25519_fe_mul( h1->X, h1->X, sqrtm1 );
  }
  if( fd_ed25519_fe_isnegative( h1->X )!=(s1[31] >> 7) ) fd_ed25519_fe_neg( h1->X, h1->X ); /* unclear prob */
  fd_ed25519_fe_mul( h1->T, h1->X, h1->Y );

  return FD_ED25519_SUCCESS;
}

uchar *
fd_ed25519_ge_tobytes( uchar *                    s,
                       fd_ed25519_ge_p2_t const * h ) {
  fd_ed25519_fe_t recip[1]; fd_ed25519_fe_invert( recip, h->Z );
  fd_ed25519_fe_t x[1];
  fd_ed25519_fe_t y[1];     fd_ed25519_fe_mul2( x, h->X, recip, y, h->Y, recip );
  fd_ed25519_fe_tobytes( s, y );
  s[31] ^= (uchar)(fd_ed25519_fe_isnegative( x ) << 7);
  return s;
}

uchar *
fd_ed25519_ge_p3_tobytes( uchar *                    s,
                          fd_ed25519_ge_p3_t const * h ) {
  fd_ed25519_fe_t recip[1]; fd_ed25519_fe_invert( recip,  h->Z  );
  fd_ed25519_fe_t x[1];
  fd_ed25519_fe_t y[1];     fd_ed25519_fe_mul2( x, h->X, recip, y, h->Y, recip );
  fd_ed25519_fe_tobytes( s, y );
  s[31] ^= (uchar)(fd_ed25519_fe_isnegative( x ) << 7);
  return s;
}

fd_ed25519_ge_p3_t *
fd_ed25519_ge_scalarmult_base( fd_ed25519_ge_p3_t * h,
                               uchar const *        a ) {
  fd_ed25519_ge_p1p1_t    r[1];
  fd_ed25519_ge_p2_t      s[1];
  fd_ed25519_ge_precomp_t t[1];

  int e[64];
  for( int i=0; i<32; i++ ) {
    e[2*i+0] = (int)(( (uint)a[i]      ) & 15U);
    e[2*i+1] = (int)((((uint)a[i]) >> 4) & 15U);
  }

  /* At this point, e[0:62] are in [0:15], e[63] is in [0:7] */

  int carry = 0;
  for( int i=0; i<63; i++ ) {
    e[i] += carry;
    carry = e[i] + 8;
    carry >>= 4;
    e[i] -= carry << 4;
  }
  e[63] += carry;

  /* At this point, e[*] are in [-8,8] */

  fd_ed25519_ge_p3_0( h );
  for( int i=1; i<64; i+=2 ) {
    fd_ed25519_ge_table_select( t, i/2, e[i] );
    fd_ed25519_ge_madd        ( r, h, t );
    fd_ed25519_ge_p1p1_to_p3  ( h, r );
  }

  fd_ed25519_ge_p3_dbl    ( r, h );
  fd_ed25519_ge_p1p1_to_p2( s, r );
  fd_ed25519_ge_p2_dbl    ( r, s );
  fd_ed25519_ge_p1p1_to_p2( s, r );
  fd_ed25519_ge_p2_dbl    ( r, s );
  fd_ed25519_ge_p1p1_to_p2( s, r );
  fd_ed25519_ge_p2_dbl    ( r, s );
  fd_ed25519_ge_p1p1_to_p3( h, r );

  for( int i=0; i<64; i+=2 ) {
    fd_ed25519_ge_table_select( t, i/2, e[i] );
    fd_ed25519_ge_madd        ( r, h, t );
    fd_ed25519_ge_p1p1_to_p3  ( h, r    );
  }

  /* Sanitize */

  fd_memset( e, 0, 64UL*sizeof(int) );

  return h;
}

static int *
fd_ed25519_ge_slide( int *         r,
                     uchar const * a ) {

  for( int i=0; i<256; i++ ) r[i] = (int)(1U & (((uint)a[i >> 3]) >> (i & 7)));

  for( int i=0; i<256; i++ ) {
    if( !r[i] ) continue;
    for( int b=1; (b<=6) && ((i+b)<256); b++ ) {
      if( !r[i+b] ) continue;
      if     ( r[i] + (r[i+b] << b) <=  15 ) { r[i] += r[i+b] << b; r[i+b] = 0; }
      else if( r[i] - (r[i+b] << b) >= -15 ) {
        r[i] -= r[i+b] << b;
        for( int k=i+b; k<256; k++ ) {
          if( !r[k] ) { r[k] = 1; break; }
          r[k] = 0;
        }
      } else break;
    }
  }

  return r;
}

fd_ed25519_ge_p2_t *
fd_ed25519_ge_double_scalarmult_vartime( fd_ed25519_ge_p2_t *       r,
                                         uchar const *              a,
                                         fd_ed25519_ge_p3_t const * A,
                                         uchar const *              b ) {

# include "../table/fd_ed25519_ge_bi_precomp.c"

  int aslide[256]; fd_ed25519_ge_slide( aslide, a );
  int bslide[256]; fd_ed25519_ge_slide( bslide, b );

  fd_ed25519_ge_cached_t Ai[8][1]; /* A,3A,5A,7A,9A,11A,13A,15A */
  fd_ed25519_ge_p3_t     A2[1];
  fd_ed25519_ge_p1p1_t   t[1];
  fd_ed25519_ge_p3_t     u[1];

  fd_ed25519_ge_p3_to_cached( Ai[0], A         );
  fd_ed25519_ge_p3_dbl      ( t,     A         );
  fd_ed25519_ge_p1p1_to_p3  ( A2,    t         );
  for( int i=0; i<7; i++ ) {
    fd_ed25519_ge_add         ( t,       A2, Ai[i] );
    fd_ed25519_ge_p1p1_to_p3  ( u,       t         );
    fd_ed25519_ge_p3_to_cached( Ai[i+1], u         );
  }

  fd_ed25519_ge_p2_0( r );

  int i;
  for( i=255; i>=0; i-- ) if( aslide[i] || bslide[i] ) break;
  for(      ; i>=0; i-- ) {
    fd_ed25519_ge_p2_dbl( t, r );
    if(      aslide[i] > 0 ) { fd_ed25519_ge_p1p1_to_p3( u, t ); fd_ed25519_ge_add ( t, u, Ai        [  aslide[i]  / 2] ); }
    else if( aslide[i] < 0 ) { fd_ed25519_ge_p1p1_to_p3( u, t ); fd_ed25519_ge_sub ( t, u, Ai        [(-aslide[i]) / 2] ); }
    if(      bslide[i] > 0 ) { fd_ed25519_ge_p1p1_to_p3( u, t ); fd_ed25519_ge_madd( t, u, bi_precomp[  bslide[i]  / 2] ); }
    else if( bslide[i] < 0 ) { fd_ed25519_ge_p1p1_to_p3( u, t ); fd_ed25519_ge_msub( t, u, bi_precomp[(-bslide[i]) / 2] ); }
    fd_ed25519_ge_p1p1_to_p2( r, t );
  }

  return r;
}

/**********************************************************************/

fd_ed25519_point_t *
fd_ed25519_point_decompress( fd_ed25519_point_t * h_,
                             uchar const          s[ static 32 ] ) {
  fd_ed25519_ge_p3_t * h = fd_type_pun( h_ );
  return fd_ed25519_ge_frombytes_vartime( h, s )==FD_ED25519_SUCCESS ? h_ : NULL;
}

uchar *
fd_ed25519_point_compress( uchar                      s[ static 32 ],
                           fd_ed25519_point_t const * f_ ) {
  fd_ed25519_ge_p3_t const * f = fd_type_pun_const( f_ );
  return fd_ed25519_ge_p3_tobytes( s, f );
}

fd_ed25519_point_t *
fd_ed25519_point_0( fd_ed25519_point_t * h ) {
  fd_ed25519_ge_p3_0( fd_type_pun( h ) );
  return h;
}

fd_ed25519_point_t *
fd_ed25519_point_add( fd_ed25519_point_t *       h_,
                      fd_ed25519_point_t const * f_,
                      fd_ed25519_point_t const * g_ ) {
  fd_ed25519_ge_p3_t * h = (fd_ed25519_ge_p3_t *)h_;
  fd_ed25519_ge_p3_t * f = (fd_ed25519_ge_p3_t *)f_;
  fd_ed25519_ge_p3_t * g = (fd_ed25519_ge_p3_t *)g_;

  fd_ed25519_ge_p1p1_t   r [1];
  fd_ed25519_ge_cached_t gc[1];
  fd_ed25519_ge_p3_to_cached( gc, g );
  fd_ed25519_ge_add( r, f, gc );
  /* Consider converting to p2 instead of p3 */
  fd_ed25519_ge_p1p1_to_p3( h, r );
  return h_;
}

fd_ed25519_point_t *
fd_ed25519_point_sub( fd_ed25519_point_t *       h_,
                      fd_ed25519_point_t const * f_,
                      fd_ed25519_point_t const * g_ ) {
  fd_ed25519_ge_p3_t * h = (fd_ed25519_ge_p3_t *)h_;
  fd_ed25519_ge_p3_t * f = (fd_ed25519_ge_p3_t *)f_;
  fd_ed25519_ge_p3_t * g = (fd_ed25519_ge_p3_t *)g_;

  fd_ed25519_ge_p1p1_t   r [1];
  fd_ed25519_ge_cached_t gc[1];
  fd_ed25519_ge_p3_to_cached( gc, g );
  fd_ed25519_ge_sub( r, f, gc );
  /* Consider converting to p2 instead of p3 */
  fd_ed25519_ge_p1p1_to_p3( h, r );
  return h_;
}

fd_ed25519_point_t *
fd_ed25519_point_scalarmult( fd_ed25519_point_t *       h_,
                             uchar const                a[ static 32 ],
                             fd_ed25519_point_t const * A_ ) {

  fd_ed25519_ge_p3_t *       h = fd_type_pun      ( h_ );
  fd_ed25519_ge_p3_t const * A = fd_type_pun_const( A_ );

  /* TODO validate scalar */

  int aslide[256]; fd_ed25519_ge_slide( aslide, a );

  fd_ed25519_ge_cached_t Ai[8][1]; /* A,3A,5A,7A,9A,11A,13A,15A */
  fd_ed25519_ge_p3_t     A2[1];
  fd_ed25519_ge_p1p1_t   t[1];
  fd_ed25519_ge_p3_t     u[1];

  fd_ed25519_ge_p3_to_cached( Ai[0], A         );
  fd_ed25519_ge_p3_dbl      ( t,     A         );
  fd_ed25519_ge_p1p1_to_p3  ( A2,    t         );
  for( int i=0; i<7; i++ ) {
    fd_ed25519_ge_add         ( t,       A2, Ai[i] );
    fd_ed25519_ge_p1p1_to_p3  ( u,       t         );
    fd_ed25519_ge_p3_to_cached( Ai[i+1], u         );
  }

  fd_ed25519_ge_p2_t r[1];
  fd_ed25519_ge_p2_0( r );

  int i;
  for( i=255; i>=0; i-- ) if( aslide[i] ) break;
  for(      ; i>=0; i-- ) {
    fd_ed25519_ge_p2_dbl( t, r );
    if(      aslide[i] > 0 ) { fd_ed25519_ge_p1p1_to_p3( u, t ); fd_ed25519_ge_add ( t, u, Ai[  aslide[i]  / 2] ); }
    else if( aslide[i] < 0 ) { fd_ed25519_ge_p1p1_to_p3( u, t ); fd_ed25519_ge_sub ( t, u, Ai[(-aslide[i]) / 2] ); }
    fd_ed25519_ge_p1p1_to_p2( r, t );
  }

  fd_ed25519_ge_p2_to_p3( h, r );
  return h_;
}
