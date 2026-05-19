#ifndef HEADER_fd_src_ballet_ed25519_avx512_fd_r52x5_ge_h
#define HEADER_fd_src_ballet_ed25519_avx512_fd_r52x5_ge_h

/* A curve point is represented by a FD_R52X5_QUAD (X,Y,Z,T) in normal
   homogeneous coordinates where X, Y, Z and T hold r52x5 field elements
   and X Y = T Z. */

#include "fd_r52x5_inl.h"

FD_PROTOTYPES_BEGIN

/* FD_R52X5_GE_ZERO(P) sets P to the curve neutral point (0,1,1,0). */
#define FD_R52X5_GE_ZERO( P ) do { \
    P##0 = wl( 0, 1, 1, 0 );       \
    P##1 = wl( 0, 0, 0, 0 );       \
    P##2 = wl( 0, 0, 0, 0 );       \
    P##3 = wl( 0, 0, 0, 0 );       \
    P##4 = wl( 0, 0, 0, 0 );       \
  } while(0)

/* fd_r52x5_ge_decode decodes a compressed Edwards point.  Returns 0 on
   success and -1 if no square root exists. */
FD_FN_UNUSED static int
fd_r52x5_ge_decode( wl_t * _P0, wl_t * _P1, wl_t * _P2, wl_t * _P3, wl_t * _P4,
                    uchar const buf[ 32 ] ) {
  fd_f25519_t  y[1],  u[1],   v[1], ysq[1];
  fd_f25519_t v2[1], v3[1],  v4[1], uv3[1], uv7[1];
  fd_f25519_t  x[1], x2[1], vx2[1],  t1[1],  t2[1], t3[1], xy[1];

  /* Decode y and save bit 255 as the x-coordinate sign bit. */

  int x_0 = buf[31] >> 7;

  uchar buf2[32];
  fd_memcpy( buf2, buf, 32UL );
  buf2[31] &= 0x7f;
  fd_f25519_frombytes( y, buf2 );

  /* Recover x from x^2 = (y^2 - 1) / (d y^2 + 1). */

  fd_f25519_sqr( ysq, y );
  fd_f25519_sub( u, ysq, fd_f25519_one );
  fd_f25519_mul( v, fd_f25519_d, ysq );
  fd_f25519_add( v, v, fd_f25519_one );

  /* Compute the candidate root x = u v^3 (u v^7)^((p-5)/8). */

  fd_f25519_sqr( v2,  v );
  fd_f25519_sqr( v4,  v2 );
  fd_f25519_mul( v3,  v, v2 );
  fd_f25519_mul( uv3, u, v3 );
  fd_f25519_mul( uv7, uv3, v4 );
  fd_f25519_pow22523( x, uv7 );
  fd_f25519_mul( x, x, uv3 );

  /* Check v x^2 = u.  If v x^2 = -u, multiply by sqrt(-1). */

  fd_f25519_sqr( x2,  x );
  fd_f25519_mul( vx2, v, x2 );
  fd_f25519_sub( t1, vx2, u );
  fd_f25519_add( t2, vx2, u );
  int t1nz = fd_f25519_is_nonzero( t1 );
  int t2nz = fd_f25519_is_nonzero( t2 );
  if( FD_UNLIKELY( t1nz & t2nz ) ) return -1;

  fd_f25519_if( t3, t1nz, fd_f25519_sqrtm1, fd_f25519_one );
  fd_f25519_mul( x, x, t3 );

  /* Select the root with the requested sign bit. */

  int x_mod_2 = fd_f25519_sgn( x );
  fd_f25519_t neg_x[1];
  fd_f25519_neg( neg_x, x );
  fd_f25519_if( x, x_0 != x_mod_2, neg_x, x );

  /* Return the decoded point (x,y). */

  fd_f25519_mul( xy, x, y );

  FD_R52X5_QUAD_DECL( _r );
  FD_R52X5_QUAD_PACK( _r, x->el, y->el, fd_f25519_one->el, xy->el );
  *_P0 = _r0; *_P1 = _r1; *_P2 = _r2; *_P3 = _r3; *_P4 = _r4;
  return 0;
}

/* FD_R52X5_GE_DECODE2(Pa,sa,Pb,sb) decodes two compressed points. */
#define FD_R52X5_GE_DECODE2( Pa, sa, Pb, sb ) (__extension__({ \
    int _erra = fd_r52x5_ge_decode( &Pa##0, &Pa##1, &Pa##2,    \
                                    &Pa##3, &Pa##4, (sa) );    \
    int _errb = fd_r52x5_ge_decode( &Pb##0, &Pb##1, &Pb##2,    \
                                    &Pb##3, &Pb##4, (sb) );    \
    int _err = 0;                                              \
    if( FD_UNLIKELY( _erra ) ) {                               \
      FD_R52X5_GE_ZERO( Pb );                                  \
      _err = -1;                                               \
    } else if( FD_UNLIKELY( _errb ) ) {                        \
      FD_R52X5_GE_ZERO( Pa );                                  \
      _err = -2;                                               \
    }                                                          \
    _err;                                                      \
  }))

/* FD_R52X5_TO_TABLE converts a normal point S = [X, Y, Z, T] into the
   precomputed form:

    D = 121666 * [Y-X, X+Y, 2*Z, 2*d*T]
      = [121666*(Y-X), 121666*(X+Y), 2*121666*Z, -2*121665*T]

    Given that d = -121665/121666, multiplying the usual 2*d*T lane
    by the common factor 121666 gives -2*121665*T.
    In-place operation fine. */
#define FD_R52X5_TO_TABLE( D, S ) do {                                                       \
    FD_R52X5_QUAD_DECL( _ta );                                                               \
    FD_R52X5_QUAD_DECL( _tb );                                                               \
    FD_R52X5_QUAD_DIFF_SUM( _ta, S );                       /* _ta = [Y-X, X+Y, T-Z, Z+T] */ \
    FD_R52X5_QUAD_LANE_IF( _ta, 1,1,0,0, _ta, S );          /* _ta = [Y-X, X+Y, Z,   T  ] */ \
    FD_R52X5_QUAD_REDUCE( _ta, _ta );                       /* _ta = [Y-X, X+Y, Z,   T  ] */ \
    wv_t _1122d = wv( 121666, 121666, 2*121666, 2*121665 );                                  \
    FD_R52X5_QUAD_MUL_CONSTANT( _ta, _ta, _1122d );         /* _ta = [121666*(Y-X), 121666*(X+Y), 2*121666*Z, 2*121665*T] */  \
    FD_R52X5_QUAD_NEGATE_LAZY( _tb, _ta );                  /* _tb = each lane of _ta negated */                              \
    FD_R52X5_QUAD_LANE_IF( _ta, 0,0,0,1, _tb, _ta );        /* _ta = [121666*(Y-X), 121666*(X+Y), 2*121666*Z, -2*121665*T] */ \
    FD_R52X5_QUAD_REDUCE( D, _ta );                         /*   D = 121666*[Y-X, X+Y, 2*Z, 2*d*T] */                         \
  } while(0)

/* FD_R52X5_GE_ADD(P3,P1,P2) computes P3 = P1 + P2.  P1 and P2 are
   normal points. P3 is a normal point.  In-place operation fine. */
#define FD_R52X5_GE_ADD( P3, P1, P2 ) do {             \
    FD_R52X5_QUAD_DECL( _table );                      \
    FD_R52X5_TO_TABLE( _table, P2 );                   \
    FD_R52X5_QUAD_DECL( _ta );                         \
    FD_R52X5_QUAD_DECL( _tb );                         \
    FD_R52X5_GE_ADD_TABLE( P3, P1, _table, _ta, _tb ); \
  } while(0)

/* FD_R52X5_GE_ADD_TABLE computes P3 = P1 + T2 where P1 is a normal
   point and T2 is in the precomputed form produced by
   FD_R52X5_TO_TABLE.
     A = (Y1-X1)*(Y2-X2)
     B = (Y1+X1)*(Y2+X2)
     C = T1*2*d*T2
     D = Z1*2*Z2
     E = B-A
     F = D-C
     G = D+C
     H = B+A
     P3 = [ E*F, G*H, F*G, E*H ] */
#define FD_R52X5_GE_ADD_TABLE( P3, P1, T2, _ta, _tb ) do {    \
    FD_R52X5_QUAD_DIFF_SUM( _ta, P1 );              /* _ta = [Y1-X1, X1+Y1, T1-Z1, Z1+T1] */            \
    FD_R52X5_QUAD_LANE_IF( _ta, 1,1,0,0, _ta, P1 ); /* _ta = [Y1-X1, X1+Y1, Z1,    T1   ] */            \
    FD_R52X5_QUAD_REDUCE( _ta, _ta );               /* _ta = [Y1-X1, X1+Y1, Z1,    T1   ] */            \
    FD_R52X5_QUAD_MUL_FAST( _ta, _ta, T2 );         /* _ta = 121666*[A, B, D, C] */                     \
    FD_R52X5_QUAD_PERMUTE( _ta, 0,1,3,2, _ta );     /* _ta = 121666*[A, B, C, D] */                     \
    FD_R52X5_QUAD_DIFF_SUM( _ta, _ta );             /* _ta = 121666*[E=B-A, H=A+B, F=D-C, G=C+D] */     \
    FD_R52X5_QUAD_REDUCE( _ta, _ta );               /* _ta = 121666*[E=B-A, H=A+B, F=D-C, G=C+D] */     \
    FD_R52X5_QUAD_PERMUTE( _tb, 0,3,3,0, _ta );     /* _tb = 121666*[E, G, G, E] */                     \
    FD_R52X5_QUAD_PERMUTE( _ta, 2,1,2,1, _ta );     /* _ta = 121666*[F, H, F, H] */                     \
    FD_R52X5_QUAD_MUL_FAST( P3, _tb, _ta );         /*  P3 = 121666^2*[E*F, G*H, G*F, E*H] */           \
    FD_R52X5_QUAD_REDUCE( P3, P3 );                 /* Common scaling represent an equivalent point. */ \
  } while(0)

/* FD_R52X5_GE_DBL computes P2 = 2*P1 where P1 and P2 are normal points.
   In-place operation fine.
     A = X1^2
     B = Y1^2
     C = 2*Z1^2
     D = -A
     E = (X1+Y1)^2 - A - B
     G = D + B = B-A
     F = G - C
     H = D - B = -(A+B)
     P2 = [ E*F, G*H, F*G, E*H ] */
#define FD_R52X5_GE_DBL( P2, P1 ) do {                        \
    FD_R52X5_QUAD_DECL( _ta );                                \
    FD_R52X5_QUAD_DECL( _tb );                                \
    FD_R52X5_QUAD_DECL( _1111 );                              \
    FD_R52X5_QUAD_DECL( _2222 );                              \
    FD_R52X5_QUAD_DECL( _2224 );                              \
    FD_R52X5_QUAD_DECL( _zero ); FD_R52X5_QUAD_ZERO( _zero ); \
    FD_R52X5_QUAD_PERMUTE( _ta, 1,0,3,2, P1 );           /* _ta = [Y1, X1, T1, Z1] */                  \
    FD_R52X5_QUAD_ADD_FAST( _ta, _ta, P1 );              /* _ta = [X1+Y1,  X1+Y1,  Z1+T1, Z1+T1] */    \
    FD_R52X5_QUAD_PERMUTE( _ta, 0,1,0,1, _ta );          /* _ta = [X1+Y1,  X1+Y1,  X1+Y1, X1+Y1] */    \
    FD_R52X5_QUAD_LANE_IF( _ta, 0,0,0,1, _ta, P1 );      /* _ta = [X1      Y2,     Z1,    X1+Y1] */    \
    FD_R52X5_QUAD_REDUCE( _ta, _ta );                    /* _ta = [X1      Y2,     Z1,    X1+Y1] */    \
    FD_R52X5_QUAD_SQR_FAST( _ta, _ta );                  /* _ta = [A=X1^2, B=Y1^2, Z1^2, (X1+Y1)^2] */ \
                                                                                                       \
    FD_R52X5_QUAD_PERMUTE( _1111, 0,0,0,0, _ta );        /* _1111 = [A,   A,  A,  A        ] */ \
    FD_R52X5_QUAD_PERMUTE( _2222, 1,1,1,1, _ta );        /* _2222 = [B,   B,  B,  B        ] */ \
    FD_R52X5_QUAD_LANE_IF( _2224, 0,0,0,1, _ta, _2222 ); /* _2224 = [B,   B,  B,  (X1+Y1)^2] */ \
    FD_R52X5_QUAD_NEGATE_LAZY( _2224, _2224 );           /* _2224 = [-B, -B, -B, -(X1+Y1)^2] */ \
                                                                                                \
    FD_R52X5_QUAD_ADD_FAST( _ta, _ta, _ta );             /* _ta = [2A, 2B, C=2*Z1^2, 2*(X1+Y1)^2] */ \
    FD_R52X5_QUAD_LANE_IF( _ta, 0,0,1,0, _ta, _zero );   /* _ta = [0, 0, C,   0] */                  \
    FD_R52X5_QUAD_ADD_FAST( _ta, _1111, _ta );           /* _ta = [A, A, A+C, A] */                  \
    FD_R52X5_QUAD_LANE_IF( _tb, 1,0,0,1, _2222, _zero ); /* _tb = [B, 0, 0,   B] */                  \
                                                                                                     \
    FD_R52X5_QUAD_ADD_FAST( _ta, _ta, _tb );             /* _ta = [A+B, A, A+C,  A+B      ] */                    \
    FD_R52X5_QUAD_LANE_IF( _tb, 0,1,1,1, _2224, _zero ); /* _tb = [0,  -B,  -B, -(X1+Y1)^2] */                    \
    FD_R52X5_QUAD_ADD_FAST( _ta, _ta, _tb );             /* _ta = [-H=A+B, -G=A-B, -F=A+C-B, -E=A+B-(X1+Y1)^2] */ \
    FD_R52X5_QUAD_REDUCE( _ta, _ta );                    /* _ta = [-H=A+B, -G=A-B, -F=A+C-B, -E=A+B-(X1+Y1)^2] */ \
    FD_R52X5_QUAD_PERMUTE( _tb, 3,1,1,3, _ta );          /* _tb = [-E, -G, -G, -E] */                             \
    FD_R52X5_QUAD_PERMUTE( _ta, 2,0,2,0, _ta );          /* _ta = [-F, -H, -F, -H] */                             \
    FD_R52X5_QUAD_MUL_FAST( P2, _ta, _tb );              /*  P2 = [E*F, G*H, F*G, E*H] */                         \
    FD_R52X5_QUAD_REDUCE( P2, P2 );                                                                               \
  } while(0)

/* FD_R52X5_GE_IS_EQ(X,Y) returns 1 if X and Y represent the same curve
   point and 0 otherwise. */
#define FD_R52X5_GE_IS_EQ( X, Y ) fd_r52x5_ge_is_eq( X##0, X##1, X##2, X##3, X##4, Y##0, Y##1, Y##2, Y##3, Y##4 )

static inline void
fd_r52x5_reduce( ulong x[ 5 ] ) {
  ulong q = (x[0] + 19) >> 51;
  q = (x[1] + q) >> 51; q = (x[2] + q) >> 51;
  q = (x[3] + q) >> 51; q = (x[4] + q) >> 51;
  x[0] += 19 * q;
  ulong c;
  c = x[0] >> 51; x[0] &= FD_F25519_LIMB_MASK;
  x[1] += c; c = x[1] >> 51; x[1] &= FD_F25519_LIMB_MASK;
  x[2] += c; c = x[2] >> 51; x[2] &= FD_F25519_LIMB_MASK;
  x[3] += c; c = x[3] >> 51; x[3] &= FD_F25519_LIMB_MASK;
  x[4] += c; x[4] &= FD_F25519_LIMB_MASK;
}

FD_FN_UNUSED static int
fd_r52x5_ge_is_eq( wl_t A0, wl_t A1, wl_t A2, wl_t A3, wl_t A4,
                   wl_t B0, wl_t B1, wl_t B2, wl_t B3, wl_t B4 ) {
  FD_R52X5_QUAD_PERMUTE( A, 2,0,2,1, A ); /* A = [Az,    Ax,    Az,    Ay] */
  FD_R52X5_QUAD_PERMUTE( B, 0,2,1,2, B ); /* B = [Bx,    Bz,    By,    Bz] */
  FD_R52X5_QUAD_MUL_FAST( A, A, B );      /* A = [Az*Bx, Ax*Bz, Az*By, Ay*Bz] */
  FD_R52X5_QUAD_REDUCE( A, A );

  FD_R52X5_QUAD_DECL( D );
  FD_R52X5_QUAD_PERMUTE( D, 1,0,3,2, A ); /* D = [ Ax*Bz,       Az*Bx,       Ay*Bz,       Az*By] */
  FD_R52X5_QUAD_NEGATE_LAZY( A, A );      /* A = [-Az*Bx,      -Ax*Bz,      -Az*By,      -Ay*Bz] */
  FD_R52X5_QUAD_ADD_FAST( D, D, A );      /* D = [ Ax*Bz-Az*Bx, Az*Bx-Ax*Bz, Ay*Bz-Az*By, Az*By-Ay*Bz] */
  FD_R52X5_QUAD_REDUCE( D, D );

  ulong dx[5], dy[5];
  dx[0] = (ulong)wl_extract( D0, 0 ); dy[0] = (ulong)wl_extract( D0, 2 );
  dx[1] = (ulong)wl_extract( D1, 0 ); dy[1] = (ulong)wl_extract( D1, 2 );
  dx[2] = (ulong)wl_extract( D2, 0 ); dy[2] = (ulong)wl_extract( D2, 2 );
  dx[3] = (ulong)wl_extract( D3, 0 ); dy[3] = (ulong)wl_extract( D3, 2 );
  dx[4] = (ulong)wl_extract( D4, 0 ); dy[4] = (ulong)wl_extract( D4, 2 );

  /* Canonical reduction for dx,dy */
  fd_r52x5_reduce( dx );
  fd_r52x5_reduce( dy );

  /* Check for zero */
  return ((dx[0]|dx[1]|dx[2]|dx[3]|dx[4]) == 0) &
         ((dy[0]|dy[1]|dy[2]|dy[3]|dy[4]) == 0);
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_ed25519_avx512_fd_r52x5_ge_h */
