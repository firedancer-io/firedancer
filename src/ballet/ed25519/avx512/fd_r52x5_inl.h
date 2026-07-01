#ifndef HEADER_fd_src_ballet_ed25519_avx512_fd_r52x5_inl_h
#define HEADER_fd_src_ballet_ed25519_avx512_fd_r52x5_inl_h

#include "../../../util/simd/fd_avx.h"
#include "../../../util/simd/fd_avx512.h"

FD_PROTOTYPES_BEGIN

/* FD_R52X5_QUAD_DECL(Q) declares wl_t Q0..Q4 in the local scope to
   represent four GF(p) elements, usually an Edwards point (X,Y,Z,T),
   where p = 2^255-19.  Organization:

    Q0 = [ X0, Y0, Z0, T0 ]
    Q1 = [ X1, Y1, Z1, T1 ]
    Q2 = [ X2, Y2, Z2, T2 ]
    Q3 = [ X3, Y3, Z3, T3 ]
    Q4 = [ X4, Y4, Z4, T4 ]

   Each field element is represented as 5 radix-2^51 limbs:
     ele = l0 + l1*2^51 + l2*2^102 + l3*2^153 + l4*2^204  (mod p) */

#define FD_R52X5_QUAD_DECL( Q ) wl_t Q##0, Q##1, Q##2, Q##3, Q##4

#define FD_R52X5_QUAD_ZERO( Q ) do { \
    Q##0 = wl_zero();                \
    Q##1 = wl_zero();                \
    Q##2 = wl_zero();                \
    Q##3 = wl_zero();                \
    Q##4 = wl_zero();                \
  } while(0)

#define FD_R52X5_QUAD_MOV( D, S ) do { \
    D##0 = S##0;                       \
    D##1 = S##1;                       \
    D##2 = S##2;                       \
    D##3 = S##3;                       \
    D##4 = S##4;                       \
  } while(0)

/* Pack four scalar field elements into lane-wise r52x5 form. */
#define FD_R52X5_QUAD_PACK( Q, x, y, z, t ) do {                  \
    long _x[8] __attribute__((aligned(64))); wwl_st( _x, (x) );   \
    long _y[8] __attribute__((aligned(64))); wwl_st( _y, (y) );   \
    long _z[8] __attribute__((aligned(64))); wwl_st( _z, (z) );   \
    long _t[8] __attribute__((aligned(64))); wwl_st( _t, (t) );   \
    Q##0 = wl( _x[0], _y[0], _z[0], _t[0] );                      \
    Q##1 = wl( _x[1], _y[1], _z[1], _t[1] );                      \
    Q##2 = wl( _x[2], _y[2], _z[2], _t[2] );                      \
    Q##3 = wl( _x[3], _y[3], _z[3], _t[3] );                      \
    Q##4 = wl( _x[4], _y[4], _z[4], _t[4] );                      \
  } while(0)

/* Unpack lane-wise r52x5 form into four scalar field elements. */
#define FD_R52X5_QUAD_UNPACK( x, y, z, t, Q ) do {                \
    wl_t _r0 = Q##0;                                              \
    wl_t _r1 = Q##1;                                              \
    wl_t _r2 = Q##2;                                              \
    wl_t _r3 = Q##3;                                              \
    wl_t _r4 = Q##4;                                              \
    (x) = wwl( wl_extract( _r0, 0 ), wl_extract( _r1, 0 ),        \
               wl_extract( _r2, 0 ), wl_extract( _r3, 0 ),        \
               wl_extract( _r4, 0 ), 0L, 0L, 0L );                \
    (y) = wwl( wl_extract( _r0, 1 ), wl_extract( _r1, 1 ),        \
               wl_extract( _r2, 1 ), wl_extract( _r3, 1 ),        \
               wl_extract( _r4, 1 ), 0L, 0L, 0L );                \
    (z) = wwl( wl_extract( _r0, 2 ), wl_extract( _r1, 2 ),        \
               wl_extract( _r2, 2 ), wl_extract( _r3, 2 ),        \
               wl_extract( _r4, 2 ), 0L, 0L, 0L );                \
    (t) = wwl( wl_extract( _r0, 3 ), wl_extract( _r1, 3 ),        \
               wl_extract( _r2, 3 ), wl_extract( _r3, 3 ),        \
               wl_extract( _r4, 3 ), 0L, 0L, 0L );                \
  } while(0)

/* Lane permutation: D = [ S(imm0), S(imm1), S(imm2), S(imm3) ]
   where imm* in [0,3] map to X,Y,Z,T */
#define FD_R52X5_QUAD_PERMUTE( D, imm0, imm1, imm2, imm3, S ) do { \
    D##0 = wl_permute( S##0, imm0, imm1, imm2, imm3 );             \
    D##1 = wl_permute( S##1, imm0, imm1, imm2, imm3 );             \
    D##2 = wl_permute( S##2, imm0, imm1, imm2, imm3 );             \
    D##3 = wl_permute( S##3, imm0, imm1, imm2, imm3 );             \
    D##4 = wl_permute( S##4, imm0, imm1, imm2, imm3 );             \
  } while(0)

/* Lane select: D[i] = imm_i ? S[i] : T[i] */
#define FD_R52X5_QUAD_LANE_IF( D, imm0, imm1, imm2, imm3, S, T ) do { \
    wc_t _c = wc_bcast_wide( imm0, imm1, imm2, imm3 );                \
    D##0 = wl_if( _c, S##0, T##0 );                                   \
    D##1 = wl_if( _c, S##1, T##1 );                                   \
    D##2 = wl_if( _c, S##2, T##2 );                                   \
    D##3 = wl_if( _c, S##3, T##3 );                                   \
    D##4 = wl_if( _c, S##4, T##4 );                                   \
  } while(0)

/* Component-wise addition.  No carry propagation is performed. */
#define FD_R52X5_QUAD_ADD_FAST( R, P, Q ) do { \
    R##0 = wl_add( P##0, Q##0 );               \
    R##1 = wl_add( P##1, Q##1 );               \
    R##2 = wl_add( P##2, Q##2 );               \
    R##3 = wl_add( P##3, Q##3 );               \
    R##4 = wl_add( P##4, Q##4 );               \
  } while(0)

/* Lazy negation: D = 16*p - S.  The 16*p bias keeps all limbs positive
   for inputs under the usual <2^54 bound. */
#define FD_R52X5_QUAD_NEGATE_LAZY( D, S ) do { \
    wl_t _lo = wl_bcast( 0x7FFFFFFFFFFED0 );   \
    wl_t _hi = wl_bcast( 0x7FFFFFFFFFFFF0 );   \
    D##0 = wl_sub( _lo, S##0 );                \
    D##1 = wl_sub( _hi, S##1 );                \
    D##2 = wl_sub( _hi, S##2 );                \
    D##3 = wl_sub( _hi, S##3 );                \
    D##4 = wl_sub( _hi, S##4 );                \
  } while(0)

/* For input S = [X, Y, Z, T], computes D = [Y-X, X+Y, T-Z, Z+T].
   Subtractions are expressed with lazy negation so the result stays in
   unsigned limb space. */
#define FD_R52X5_QUAD_DIFF_SUM( D, S ) do {            \
    FD_R52X5_QUAD_DECL( _tmp1 );                       \
    FD_R52X5_QUAD_DECL( _tmp2 );                       \
    FD_R52X5_QUAD_PERMUTE( _tmp1, 1,0,3,2, S );        \
    FD_R52X5_QUAD_NEGATE_LAZY( _tmp2, S );             \
    FD_R52X5_QUAD_LANE_IF( _tmp2, 1,0,1,0, _tmp2, S ); \
    FD_R52X5_QUAD_ADD_FAST( D, _tmp1, _tmp2 );         \
  } while(0)

/* Weak carry propagation modulo p.  Carries flow forward through limbs
   0..4, and limb 4's carry wraps into limb 0 multiplied by 19 because
   2^255 = 19 mod p. */
#define FD_R52X5_QUAD_REDUCE( D, S ) do {                  \
    wl_t _s0 = S##0;                                       \
    wl_t _s1 = S##1;                                       \
    wl_t _s2 = S##2;                                       \
    wl_t _s3 = S##3;                                       \
    wl_t _s4 = S##4;                                       \
                                                           \
    wl_t _mask = wl_bcast( (1LL << 51) - 1 );              \
    wl_t _r19  = wl_bcast( 19 );                           \
                                                           \
    wl_t _c0 = wl_shru( _s0, 51 );                         \
    wl_t _c1 = wl_shru( _s1, 51 );                         \
    wl_t _c2 = wl_shru( _s2, 51 );                         \
    wl_t _c3 = wl_shru( _s3, 51 );                         \
    wl_t _c4 = wl_shru( _s4, 51 );                         \
                                                           \
    D##0 = wl_madd52lo( wl_and( _s0, _mask ), _c4, _r19 ); \
    D##1 = wl_add( wl_and( _s1, _mask ), _c0 );            \
    D##2 = wl_add( wl_and( _s2, _mask ), _c1 );            \
    D##3 = wl_add( wl_and( _s3, _mask ), _c2 );            \
    D##4 = wl_add( wl_and( _s4, _mask ), _c3 );            \
  } while(0)

/* Multiply each lane by its corresponding 32-bit scalar in y.
   The output is unreduced. */
#define FD_R52X5_QUAD_MUL_CONSTANT( D, S, y ) do {                    \
    wl_t _s0 = S##0;                                                  \
    wl_t _s1 = S##1;                                                  \
    wl_t _s2 = S##2;                                                  \
    wl_t _s3 = S##3;                                                  \
    wl_t _s4 = S##4;                                                  \
    wl_t _y  = (y);                                                   \
                                                                      \
    wl_t _r19  = wl_bcast( 19 );                                      \
    wl_t _z0_1 = wl_zero();                                           \
    wl_t _z1_1 = wl_zero();  wl_t _z1_2 = wl_zero();                  \
    wl_t _z2_1 = wl_zero();  wl_t _z2_2 = wl_zero();                  \
    wl_t _z3_1 = wl_zero();  wl_t _z3_2 = wl_zero();                  \
    wl_t _z4_1 = wl_zero();  wl_t _z4_2 = wl_zero();                  \
                             wl_t _z5_2 = wl_zero();                  \
                                                                      \
    _z0_1 = wl_madd52lo( _z0_1, _y, _s0 ); _z1_2 = wl_madd52hi( _z1_2, _y, _s0 ); \
    _z1_1 = wl_madd52lo( _z1_1, _y, _s1 ); _z2_2 = wl_madd52hi( _z2_2, _y, _s1 ); \
    _z2_1 = wl_madd52lo( _z2_1, _y, _s2 ); _z3_2 = wl_madd52hi( _z3_2, _y, _s2 ); \
    _z3_1 = wl_madd52lo( _z3_1, _y, _s3 ); _z4_2 = wl_madd52hi( _z4_2, _y, _s3 ); \
    _z4_1 = wl_madd52lo( _z4_1, _y, _s4 ); _z5_2 = wl_madd52hi( _z5_2, _y, _s4 ); \
    _z0_1 = wl_madd52lo( _z0_1, wl_add( _z5_2, _z5_2 ), _r19 );       \
                                                                      \
    D##0 = _z0_1;                                                     \
    D##1 = wl_add( wl_add( _z1_1, _z1_2 ), _z1_2 );                   \
    D##2 = wl_add( wl_add( _z2_1, _z2_2 ), _z2_2 );                   \
    D##3 = wl_add( wl_add( _z3_1, _z3_2 ), _z3_2 );                   \
    D##4 = wl_add( wl_add( _z4_1, _z4_2 ), _z4_2 );                   \
  } while(0)

/* FD_R52X5_QUAD_MUL_FAST(R,P,Q) does:
     [ fd_f25519_mul(PX,QX) fd_f25519_mul(PY,QY) fd_f25519_mul(PZ,QZ) fd_f25519_mul(PT,QT) ]
   Written this way so that pointer escapes don't inhibit optimizations. */
#define FD_R52X5_QUAD_MUL_FAST( R, P, Q ) do {              \
    FD_R52X5_QUAD_DECL( _R );                               \
    fd_r52x5_quad_mul_fast( &_R0, &_R1, &_R2, &_R3, &_R4,   \
                            P##0, P##1, P##2, P##3, P##4,   \
                            Q##0, Q##1, Q##2, Q##3, Q##4 ); \
    FD_R52X5_QUAD_MOV( R, _R );                             \
  } while(0)

FD_FN_UNUSED static void
fd_r52x5_quad_mul_fast( wl_t * _z0, wl_t * _z1, wl_t * _z2, wl_t * _z3, wl_t * _z4,
                        wl_t    x0, wl_t    x1, wl_t    x2, wl_t    x3, wl_t    x4,
                        wl_t    y0, wl_t    y1, wl_t    y2, wl_t    y3, wl_t    y4 ) {

  /* Grade school-ish:

                                      x4    x3    x2    x1    x0
                                 x    y4    y3    y2    y1    y0
                                 -------------------------------
                                      p40   p30   p20   p10   p00
                                p41   p31   p21   p11   p01
                          p42   p32   p22   p12   p02
                    p43   p33   p23   p13   p03
              p44   p34   p24   p14   p04
              -----------------------------------------------
               d8    d7    d6    d5    d4    d3    d2    d1    d0

     The madd52{lo,hi} give each p_ij in low and high 52-bit parts.  The
     low parts accumulate into z{k}_1, and the high parts accumulate into
     z{k+1}_2.
     Recombining as z{k}_1 + 2*z{k}_2 accounts for the 52-bit split in
     a radix-2^51 representation. */

  wl_t const _zz = wl_zero();

  wl_t z0_1 =                           wl_madd52lo( _zz,                     x0, y0 );
  wl_t z1_1 =              wl_madd52lo( wl_madd52lo( _zz,           x1, y0 ), x0, y1 );
  wl_t z2_1 = wl_madd52lo( wl_madd52lo( wl_madd52lo( _zz, x2, y0 ), x1, y1 ), x0, y2 );
  wl_t z3_1 = wl_madd52lo( wl_madd52lo( wl_madd52lo( _zz, x3, y0 ), x2, y1 ), x1, y2 );
  /**/ z3_1 =              wl_madd52lo(               z3_1,                   x0, y3 );
  wl_t z4_1 = wl_madd52lo( wl_madd52lo( wl_madd52lo( _zz, x4, y0 ), x3, y1 ), x2, y2 );
  /**/ z4_1 = wl_madd52lo( wl_madd52lo(               z4_1,         x1, y3 ), x0, y4 );
  wl_t z5_1 = wl_madd52lo( wl_madd52lo( wl_madd52lo( _zz, x4, y1 ), x3, y2 ), x2, y3 );
  /**/ z5_1 =              wl_madd52lo(               z5_1,                   x1, y4 );
  wl_t z6_1 = wl_madd52lo( wl_madd52lo( wl_madd52lo( _zz, x4, y2 ), x3, y3 ), x2, y4 );
  wl_t z7_1 =              wl_madd52lo( wl_madd52lo( _zz,           x4, y3 ), x3, y4 );
  wl_t z8_1 =                           wl_madd52lo( _zz,                     x4, y4 );

  wl_t z0_2 = _zz;
  wl_t z1_2 =                           wl_madd52hi( _zz,                     x0, y0 );
  wl_t z2_2 =              wl_madd52hi( wl_madd52hi( _zz,           x1, y0 ), x0, y1 );
  wl_t z3_2 = wl_madd52hi( wl_madd52hi( wl_madd52hi( _zz, x2, y0 ), x1, y1 ), x0, y2 );
  wl_t z4_2 = wl_madd52hi( wl_madd52hi( wl_madd52hi( _zz, x3, y0 ), x2, y1 ), x1, y2 );
  /**/ z4_2 =              wl_madd52hi(               z4_2,                   x0, y3 );
  wl_t z5_2 = wl_madd52hi( wl_madd52hi( wl_madd52hi( _zz, x4, y0 ), x3, y1 ), x2, y2 );
  /**/ z5_2 = wl_madd52hi( wl_madd52hi(               z5_2,         x1, y3 ), x0, y4 );
  wl_t z6_2 = wl_madd52hi( wl_madd52hi( wl_madd52hi( _zz, x4, y1 ), x3, y2 ), x2, y3 );
  /**/ z6_2 =              wl_madd52hi(               z6_2,                   x1, y4 );
  wl_t z7_2 = wl_madd52hi( wl_madd52hi( wl_madd52hi( _zz, x4, y2 ), x3, y3 ), x2, y4 );
  wl_t z8_2 =              wl_madd52hi( wl_madd52hi( _zz,           x4, y3 ), x3, y4 );
  wl_t z9_2 =                           wl_madd52hi( _zz,                     x4, y4 );

  wl_t z5 = wl_add( wl_add( z5_1, z5_2 ), z5_2 );
  wl_t z6 = wl_add( wl_add( z6_1, z6_2 ), z6_2 );
  wl_t z7 = wl_add( wl_add( z7_1, z7_2 ), z7_2 );
  wl_t z8 = wl_add( wl_add( z8_1, z8_2 ), z8_2 );
  wl_t z9 = wl_add(         z9_2, z9_2 );

  wl_t t0  = wl_zero();
  wl_t t1  = wl_zero();
  wl_t r19 = wl_bcast( 19 );

  t1   = wl_madd52lo( t1,   r19, wl_shru( z9, 52 ) );
  z1_2 = wl_madd52lo( z1_2, r19, wl_shru( z5, 52 ) );
  z2_2 = wl_madd52lo( z2_2, r19, wl_shru( z6, 52 ) );
  z3_2 = wl_madd52lo( z3_2, r19, wl_shru( z7, 52 ) );

  z0_1 = wl_madd52lo( z0_1, r19, z5 ); z1_2 = wl_madd52hi( z1_2, r19, z5 );
  z1_1 = wl_madd52lo( z1_1, r19, z6 ); z2_2 = wl_madd52hi( z2_2, r19, z6 );
  z2_1 = wl_madd52lo( z2_1, r19, z7 ); z3_2 = wl_madd52hi( z3_2, r19, z7 );
  z4_2 = wl_madd52hi( z4_2, r19, z8 ); z3_1 = wl_madd52lo( z3_1, r19, z8 );
  z4_1 = wl_madd52lo( z4_1, r19, z9 ); t0   = wl_madd52hi( t0,   r19, z9 );

  z0_2 = wl_madd52lo( z0_2, r19, wl_add(  t0, t1 ) );
  z4_2 = wl_madd52lo( z4_2, r19, wl_shru( z8, 52 ) );

  wl_t r0 = wl_add( wl_add( z0_1, z0_2 ), z0_2 );
  wl_t r1 = wl_add( wl_add( z1_1, z1_2 ), z1_2 );
  wl_t r2 = wl_add( wl_add( z2_1, z2_2 ), z2_2 );
  wl_t r3 = wl_add( wl_add( z3_1, z3_2 ), z3_2 );
  wl_t r4 = wl_add( wl_add( z4_1, z4_2 ), z4_2 );

  FD_R52X5_QUAD_MOV( *_z, r );
}

/* FD_R52X5_QUAD_SQR_FAST(R,P) does:
     [ fd_f25519_sqr(PX) fd_f25519_sqr(PY) fd_f25519_sqr(PZ) fd_f25519_sqr(PT) ]
   Written this way so that pointer escapes don't inhibit optimizations. */
#define FD_R52X5_QUAD_SQR_FAST( R, P ) do {                 \
    FD_R52X5_QUAD_DECL( _R );                               \
    fd_r52x5_quad_sqr_fast( &_R0, &_R1, &_R2, &_R3, &_R4,   \
                            P##0, P##1, P##2, P##3, P##4 ); \
    FD_R52X5_QUAD_MOV( R, _R );                             \
  } while(0)

FD_FN_UNUSED static void
fd_r52x5_quad_sqr_fast( wl_t * _z0, wl_t * _z1, wl_t * _z2, wl_t * _z3, wl_t * _z4,
                        wl_t    x0, wl_t    x1, wl_t    x2, wl_t    x3, wl_t    x4 ) {

  /* Grade school-ish:

                                      x4    x3    x2    x1    x0
                                 x    x4    x3    x2    x1    x0
                                 -------------------------------
                                      p40   p30   p20   p10   p00
                                p41   p31   p21   p11   p01
                          p42   p32   p22   p12   p02
                    p43   p33   p23   p13   p03
              p44   p34   p24   p14   p04
              -----------------------------------------------
               d8    d7    d6    d5    d4    d3    d2    d1    d0

     When squaring, p_ij=p_ji, so the partial reduction becomes:

               p44  2*p34  2*p24  2*p14  2*p04   p33  2*p23  2*p13  2*p03   p22  2*p12  2*p02   p11  2*p01   p00
              --------------------------------------------------------------------------------------------------------
                d8     d7     d6     d5     d4    d6     d5     d4     d3    d4     d3     d2    d2     d1    d0

     The high halves are computed first into q{k}_{2,4}, where the suffix
     is the scale that high half has after the 52-to-51 bit split:

       q1_2 = p00h
       q2_4 = p01h
       q3_2 = p11h,         q3_4 = p02h
       q4_4 = p12h + p03h
       q5_2 = p22h,         q5_4 = p13h + p04h
       q6_4 = p23h + p14h
       q7_2 = p33h,         q7_4 = p24h
       q8_4 = p34h
       q9_2 = p44h

     The low-half block then forms z{k}_1 and z{k}_2.  Limbs 0..4 are left
     split for the final z{k}_1 + 2*z{k}_2 re-combine.  Limbs 5..9 are
     immediately recombined into z{k}_1 because they are only used for the
     wraparound fold by 2^255 = 19. */

  wl_t const _zz = wl_zero();

  wl_t q1_2 =              wl_madd52hi( _zz,           x0, x0 );
  wl_t q2_4 =              wl_madd52hi( _zz,           x0, x1 );
  wl_t q3_2 =              wl_madd52hi( _zz,           x1, x1 );
  wl_t q3_4 =              wl_madd52hi( _zz,           x0, x2 );
  wl_t q4_4 = wl_madd52hi( wl_madd52hi( _zz, x1, x2 ), x0, x3 );
  wl_t q5_2 =              wl_madd52hi( _zz,           x2, x2 );
  wl_t q5_4 = wl_madd52hi( wl_madd52hi( _zz, x1, x3 ), x0, x4 );
  wl_t q6_4 = wl_madd52hi( wl_madd52hi( _zz, x2, x3 ), x1, x4 );
  wl_t q7_2 =              wl_madd52hi( _zz,           x3, x3 );
  wl_t q7_4 =              wl_madd52hi( _zz,           x2, x4 );
  wl_t q8_4 =              wl_madd52hi( _zz,           x3, x4 );
  wl_t q9_2 =              wl_madd52hi( _zz,           x4, x4 );

  wl_t z0_1 =              wl_madd52lo( _zz,               x0, x0 );
  wl_t z0_2 = _zz;
  wl_t z1_1 = _zz;
  wl_t z1_2 =              wl_madd52lo(         q1_2,      x0, x1 );
  wl_t z2_1 =              wl_madd52lo( wl_shl( q2_4, 2 ), x1, x1 );
  wl_t z2_2 =              wl_madd52lo( _zz,               x0, x2 );
  wl_t z3_1 =              wl_shl     (         q3_4, 2 );
  wl_t z3_2 = wl_madd52lo( wl_madd52lo(         q3_2,      x1, x2 ), x0, x3 );
  wl_t z4_1 =              wl_madd52lo( wl_shl( q4_4, 2 ), x2, x2 );
  wl_t z4_2 = wl_madd52lo( wl_madd52lo( _zz,               x1, x3 ), x0, x4 );
  wl_t z5_1 =              wl_shl     (         q5_4, 2 );
  wl_t z5_2 = wl_madd52lo( wl_madd52lo(         q5_2,      x2, x3 ), x1, x4 );
  wl_t z6_1 =              wl_madd52lo( wl_shl( q6_4, 2 ), x3, x3 );
  wl_t z6_2 =              wl_madd52lo( _zz,               x2, x4 );
  wl_t z7_1 =              wl_shl     (         q7_4, 2 );
  wl_t z7_2 =              wl_madd52lo(         q7_2,      x3, x4 );
  wl_t z8_1 =              wl_madd52lo( wl_shl( q8_4, 2 ), x4, x4 );
  wl_t z9_1 =              wl_shl     (         q9_2, 1 );

  /**/ z5_1 = wl_add( z5_1, wl_shl( z5_2, 1 ) );
  /**/ z6_1 = wl_add( z6_1, wl_shl( z6_2, 1 ) );
  /**/ z7_1 = wl_add( z7_1, wl_shl( z7_2, 1 ) );

  wl_t t0  = _zz;
  wl_t t1  = _zz;
  wl_t r19 = wl_bcast( 19 );

  t0   = wl_madd52hi( t0,   r19,          z9_1 );
  t1   = wl_madd52lo( t1,   r19, wl_shru( z9_1, 52 ) );
  z4_2 = wl_madd52lo( z4_2, r19, wl_shru( z8_1, 52 ) );
  z3_2 = wl_madd52lo( z3_2, r19, wl_shru( z7_1, 52 ) );
  z2_2 = wl_madd52lo( z2_2, r19, wl_shru( z6_1, 52 ) );
  z1_2 = wl_madd52lo( z1_2, r19, wl_shru( z5_1, 52 ) );

  z0_2 = wl_madd52lo( z0_2, r19, wl_add( t0, t1 ) );
  z1_2 = wl_madd52hi( z1_2, r19, z5_1 );
  z2_2 = wl_madd52hi( z2_2, r19, z6_1 );
  z3_2 = wl_madd52hi( z3_2, r19, z7_1 );
  z4_2 = wl_madd52hi( z4_2, r19, z8_1 );

  z0_1 = wl_madd52lo( z0_1, r19, z5_1 );
  z1_1 = wl_madd52lo( z1_1, r19, z6_1 );
  z2_1 = wl_madd52lo( z2_1, r19, z7_1 );
  z3_1 = wl_madd52lo( z3_1, r19, z8_1 );
  z4_1 = wl_madd52lo( z4_1, r19, z9_1 );

  wl_t r0 = wl_add( wl_add( z0_1, z0_2 ), z0_2 );
  wl_t r1 = wl_add( wl_add( z1_1, z1_2 ), z1_2 );
  wl_t r2 = wl_add( wl_add( z2_1, z2_2 ), z2_2 );
  wl_t r3 = wl_add( wl_add( z3_1, z3_2 ), z3_2 );
  wl_t r4 = wl_add( wl_add( z4_1, z4_2 ), z4_2 );

  FD_R52X5_QUAD_MOV( *_z, r );
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_ed25519_avx512_fd_r52x5_inl_h */
