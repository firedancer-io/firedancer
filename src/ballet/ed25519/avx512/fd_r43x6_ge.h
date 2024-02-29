#ifndef HEADER_fd_src_ballet_ed25519_avx512_fd_r43x6_ge_h
#define HEADER_fd_src_ballet_ed25519_avx512_fd_r43x6_ge_h

/* This header provides APIs for manipulating group elements / curve
   points in ED25519.  Direct quotes from RFC 8032 are indicated with
   '//' style comments. */

/* A curve point will be represented by a FD_R43X6_QUAD (X,Y,Z,T) in
   extended homogeneous coordinates where X, Y, Z and T hold fd_r43x6_t
   u44 representations typically and X Y = T Z. */

// Section 5.1.4 (page 11)
//
// A point (x,y) is represented in extended homogeneous coordinates
// (X, Y, Z, T), with x = X/Z, y = Y/Z, x * y = T/Z.

#include "fd_r43x6.h"

FD_PROTOTYPES_BEGIN

/* FD_R43X6_GE_ZERO(P) does P = the curve neutral point (0,1,1,0).
   (X,Y,Z,T) will be reduced representations. */

// Section 5.1.4 (page 11):
//
// The neutral point is (0,1), or equivalently in extended homogeneous
// coordinates (0, Z, Z, 0) for any non-zero Z.

#define FD_R43X6_GE_ZERO(P) do { P##03 = wwl( 0L,1L,1L,0L, 0L,0L,0L,0L ); P##14 = wwl_zero(); P##25 = wwl_zero(); } while(0)

/* FD_R43X6_GE_ONE(P) does P = the curve "base" point.  (X,Y,Z,T) are all
   reduced representations with Z==1.  Section 5.1 (page 9):

     B = (15112221349535400772501151409588531511454012693041857206046113283949847762202,
          46316835694926478169428394003475163141307993866256225615783033603165251855960)

   The below limbs for a reduced fd_r43x6_t representation were computed
   from the above using Python. */

#define FD_R43X6_GE_ONE(P) do {                                                                                            \
    P##03 = wwl( 5912276620570L, 7036874417752L, 1L, 2970602692003L, 1206867684910L, 3518437208883L, 0L, 8002368565694L ); \
    P##14 = wwl( 5175273663173L, 5277655813324L, 0L, 2381000326097L, 7581689711182L, 7036874417766L, 0L,  787695955620L ); \
    P##25 = wwl( 1806891319892L, 1759218604441L, 0L, 4963950264797L,  286998243226L,  879609302220L, 0L,  889305571247L ); \
  } while(0)

/* FD_R43X6_GE_IS_EQ(X,Y) returns 1 if X and Y represent the same curve
   point and 0 otherwise.  X and Y should be FD_R43X6_QUAD holding u46
   representations. */

#define FD_R43X6_GE_IS_EQ( X, Y ) fd_r43x6_ge_is_eq( X##03,X##14,X##25, Y##03,Y##14,Y##25 )

FD_FN_UNUSED static int /* let compiler decide if worth inlining */
fd_r43x6_ge_is_eq( wwl_t X03, wwl_t X14, wwl_t X25,
                   wwl_t Y03, wwl_t Y14, wwl_t Y25 ) {

  /* We use the same method from the spec to test equality.  It is worth
     noting that the standard itself specifies using a two point check
     to avoid doing an unnecessary inversion.  E.g. It is somewhat odd
     that OpenSSL implementation chooses instead to encode R' to r'
     (slow) compare the encoded r and r' for its equality check in
     verify. */

  // Section 6 classEdwardsPoint (page 51)
  //
  // #Check that two points are equal.
  // def __eq__(self,y):
  //     #Need to check x1/z1 == x2/z2 and similarly for y, so cross
  //     #multiply to eliminate divisions.
  //     xn1=self.x*y.z
  //     xn2=y.x*self.z
  //     yn1=self.y*y.z
  //     yn2=y.y*self.z
  //     return xn1==xn2 and yn1==yn2

  fd_r43x6_t xn1, xn2, yn1, yn2;
  FD_R43X6_QUAD_PERMUTE ( X, 2,0,2,1, X );         /* X = XZ |XX |XZ |XY,  in u46|u46|u46|u46 */
  FD_R43X6_QUAD_PERMUTE ( Y, 0,2,1,2, Y );         /* Y = YX |YZ |YY |YZ , in u46|u46|u46|u46 */
  FD_R43X6_QUAD_MUL_FAST( X, X, Y );               /* X = xn2|xn1|yn2|yn1, in u62|u62|u62|u62 */
  FD_R43X6_QUAD_UNPACK  ( xn2, xn1, yn2, yn1, X );
  return (int)(!fd_r43x6_is_nonzero( fd_r43x6_sub_fast( xn1, xn2 ) /* in s62 */ )) &
         (int)(!fd_r43x6_is_nonzero( fd_r43x6_sub_fast( yn1, yn2 ) /* in s62 */ ));
}

/* FD_R43X6_QUAD_1112d(Q) does Q = (1,1,2,2*d).  (X,Y,Z,T) will be
   reduced fd_r43x6_t. */

#define FD_R43X6_QUAD_1112d( Q ) do {                                      \
    Q##03 = wwl( 1L, 1L, 1L, 3934839304537L, 0L, 0L, 0L,  521695520920L ); \
    Q##14 = wwl( 0L, 0L, 0L,  507525298899L, 0L, 0L, 0L, 6596238350568L ); \
    Q##25 = wwl( 0L, 0L, 0L,   15037786634L, 0L, 0L, 0L,  309467527341L ); \
  } while(0)

/* FD_R43X6_GE_ADD(P3,P1,P2) computes P3 = P1 + P2 where P1, P2 and P3
   are FD_R43X6_QUAD.  P1 and P2 should hold s61 representations.  P3
   will hold u44 representations on return.  In place operation fine. */

// Section 5.1.4 (page 12):
//
// The following formulas for adding two points, (x3,y3) =
// (x1,y1)+(x2,y2), on twisted Edwards curves with a=-1, square a, and
// non-square d are described in Section 3.1 of [Edwards-revisited] and
// in [EFD-TWISTED-ADD].  They are complete, i.e., they work for any
// pair of valid input points.
//
//   A = (Y1-X1)*(Y2-X2)
//   B = (Y1+X1)*(Y2+X2)
//   C = T1*2*d*T2
//   D = Z1*2*Z2
//   E = B-A
//   F = D-C
//   G = D+C
//   H = B+A
//   X3 = E*F
//   Y3 = G*H
//   T3 = E*H
//   Z3 = F*G

#if 1 /* Seems very slightly faster than the below */
#define FD_R43X6_GE_ADD( P3, P1, P2 ) do {                                                                             \
    FD_R43X6_QUAD_DECL         ( _1112d );                                                                             \
    FD_R43X6_QUAD_DECL         ( _ta );                                                                                \
    FD_R43X6_QUAD_DECL         ( _tb );                                                                                \
    FD_R43X6_QUAD_1112d        ( _1112d );                      /*       (1,    1,    1,    2*d  ), u43|u43|u43|u43 */ \
    FD_R43X6_QUAD_PERMUTE      ( _ta, 1,0,2,3, P1 );            /* _ta = (Y1,   X1,   Z1,   T1   ), s61|s61|s61|s61 */ \
    FD_R43X6_QUAD_PERMUTE      ( _tb, 1,0,2,3, P2 );            /* _tb = (Y2,   X2,   Z2,   T2   ), s61|s61|s61|s61 */ \
    FD_R43X6_QUAD_LANE_SUB_FAST( _ta, _ta, 1,0,0,0, _ta, P1 );  /* _ta = (Y1-X1,X1,   Z1,   T1   ), s62|s61|s61|s61 */ \
    FD_R43X6_QUAD_LANE_SUB_FAST( _tb, _tb, 1,0,0,0, _tb, P2 );  /* _tb = (Y2-X2,X2,   Z2,   T2   ), s62|s61|s61|s61 */ \
    FD_R43X6_QUAD_LANE_ADD_FAST( _ta, _ta, 0,1,1,0, _ta, P1 );  /* _ta = (Y1-X1,Y1+X1,Z1*2, T1   ), s62|s62|s61|s61 */ \
    FD_R43X6_QUAD_LANE_ADD_FAST( _tb, _tb, 0,1,0,0, _tb, P2 );  /* _tb = (Y2-X2,Y2+X2,Z2,   T2   ), s62|s62|s61|s61 */ \
    FD_R43X6_QUAD_MUL_FAST     ( _ta, _ta, _1112d );            /* _ta = (Y1-X1,Y1+X1,Z1*2, T1*2d), u62|u62|u62|u62 */ \
    FD_R43X6_QUAD_FOLD_UNSIGNED( _ta, _ta );                    /* _ta = (Y1-X1,Y1+X1,Z1*2, T1*2d), u44|u44|u44|u44 */ \
    FD_R43X6_QUAD_MUL_FAST     ( _ta, _ta, _tb );               /* _ta = (A,    B,    D,    C    ), u62|u62|u62|u62 */ \
    FD_R43X6_QUAD_FOLD_UNSIGNED( _ta, _ta );                    /* _ta = (A,    B,    D,    C    ), u44|u44|u44|u44 */ \
    FD_R43X6_QUAD_PERMUTE      ( _tb, 1,0,3,2, _ta );           /* _tb = (B,    A,    C,    D    ), u62|u62|u62|u62 */ \
    FD_R43X6_QUAD_LANE_SUB_FAST( _tb, _tb, 1,0,0,1, _tb, _ta ); /* _tb = (E,    A,    C,    F    ), s62|u62|u62|s62 */ \
    FD_R43X6_QUAD_LANE_ADD_FAST( _tb, _tb, 0,1,1,0, _tb, _ta ); /* _tb = (E,    H,    G,    F    ), s62|u63|u63|s62 */ \
    FD_R43X6_QUAD_PERMUTE      ( _ta, 0,2,2,0, _tb );           /* _ta = (E,    G,    G,    E    ), u44|u44|u44|u44 */ \
    FD_R43X6_QUAD_PERMUTE      ( _tb, 3,1,3,1, _tb );           /* _tb = (F,    H,    F,    H    ), u44|u44|u44|u44 */ \
    FD_R43X6_QUAD_MUL_FAST     ( _ta, _ta, _tb );               /* _ta = (X3,   Y3,   Z3,   T3   ), u62|u62|u62|u62 */ \
    FD_R43X6_QUAD_FOLD_UNSIGNED( P3, _ta );                     /* P3  = (X3,   Y3,   Z3,   T3   ), u44|u44|u44|u44 */ \
  } while(0)
#else /* Seems very slightly slower than the above */
#define FD_R43X6_GE_ADD( P3, P1, P2 ) do {                                                                          \
    FD_R43X6_QUAD_DECL         ( _ta );                                                                             \
    FD_R43X6_QUAD_DECL         ( _tb );                                                                             \
    FD_R43X6_QUAD_PERMUTE      ( _ta, 1,0,2,3, P1 );            /* _ta = (Y1,   X1,   Z1,   T1), s61|s61|s61|s61 */ \
    FD_R43X6_QUAD_PERMUTE      ( _tb, 1,0,2,3, P2 );            /* _tb = (Y2,   X2,   Z2,   T2), s61|s61|s61|s61 */ \
    FD_R43X6_QUAD_LANE_SUB_FAST( _ta, _ta, 1,0,0,0, _ta, P1 );  /* _ta = (Y1-X1,X1,   Z1,   T1), s62|s61|s61|s61 */ \
    FD_R43X6_QUAD_LANE_SUB_FAST( _tb, _tb, 1,0,0,0, _tb, P2 );  /* _tb = (Y2-X2,X2,   Z2,   T2), s62|s61|s61|s61 */ \
    FD_R43X6_QUAD_LANE_ADD_FAST( _ta, _ta, 0,1,1,0, _ta, P1 );  /* _ta = (Y1-X1,Y1+X1,2*Z1, T1), s62|s62|s62|s61 */ \
    FD_R43X6_QUAD_LANE_ADD_FAST( _tb, _tb, 0,1,0,0, _tb, P2 );  /* _tb = (Y2-X2,Y2+X2,Z2,   T2), s62|s62|s61|s61 */ \
    FD_R43X6_QUAD_FOLD_SIGNED  ( _ta, _ta );                    /* _ta = (Y1-X1,Y1+X1,2*Z1, T1), u44|u44|u44|u44 */ \
    FD_R43X6_QUAD_FOLD_SIGNED  ( _tb, _tb );                    /* _tb = (Y2-X2,Y2+X2,Z2,   T2), u44|u44|u44|u44 */ \
    fd_r43x6_t _YmX1, _YpX1, _2Z1, _T1;                                                                             \
    FD_R43X6_QUAD_UNPACK( _YmX1, _YpX1, _2Z1, _T1, _ta );                                                           \
    FD_R43X6_QUAD_PACK( _ta, _YmX1, _YpX1, _2Z1, fd_r43x6_mul( _T1, fd_r43x6_2d() ) );                              \
    FD_R43X6_QUAD_MUL_FAST     ( _ta, _ta, _tb );               /* _ta = (A,    B,    D,    C ), u62|u62|u62|u62 */ \
    FD_R43X6_QUAD_PERMUTE      ( _tb, 1,0,3,2, _ta );           /* _tb = (B,    A,    C,    D ), u62|u62|u62|u62 */ \
    FD_R43X6_QUAD_LANE_SUB_FAST( _tb, _tb, 1,0,0,1, _tb, _ta ); /* _tb = (E,    A,    C,    F ), s62|u62|u62|s62 */ \
    FD_R43X6_QUAD_LANE_ADD_FAST( _tb, _tb, 0,1,1,0, _tb, _ta ); /* _tb = (E,    H,    G,    F ), s62|u63|u63|s62 */ \
    FD_R43X6_QUAD_FOLD_SIGNED  ( _tb, _tb );                    /* _tb = (E,    H,    G,    F ), u44|u44|u44|u44 */ \
    FD_R43X6_QUAD_PERMUTE      ( _ta, 0,2,2,0, _tb );           /* _ta = (E,    G,    G,    E ), u44|u44|u44|u44 */ \
    FD_R43X6_QUAD_PERMUTE      ( _tb, 3,1,3,1, _tb );           /* _tb = (F,    H,    F,    H ), u44|u44|u44|u44 */ \
    FD_R43X6_QUAD_MUL_FAST     ( _ta, _ta, _tb );               /* _ta = (X3,   Y3,   Z3,   T3), u62|u62|u62|u62 */ \
    FD_R43X6_QUAD_FOLD_UNSIGNED( P3, _ta );                     /* P3  = (X3,   Y3,   Z3,   T3), u44|u44|u44|u44 */ \
  } while(0)
#endif

/* FD_R43X6_GE_ADD_TABLE does the same thing as FD_R43X6_GE_ADD where T1
   holds (Y1-X1,Y1+X1,Z1*2,T1*2d).  T1 and P2 should be in s61
   representations.  P3 will hold u44 representations. */

#define FD_R43X6_GE_ADD_TABLE( P3, T1, P2 ) do {                                                                      \
    FD_R43X6_QUAD_DECL         ( _ta );                                                                               \
    FD_R43X6_QUAD_DECL         ( _tb );                                                                               \
    FD_R43X6_QUAD_MOV          ( _ta, T1 );                     /* _ta = (Y1-X1,Y1+X1,Z1*2,T1*2d), s61|s61|s61|s61 */ \
    FD_R43X6_QUAD_PERMUTE      ( _tb, 1,0,2,3, P2 );            /* _tb = (Y2,   X2,   Z2,  T2   ), s61|s61|s61|s61 */ \
    FD_R43X6_QUAD_LANE_SUB_FAST( _tb, _tb, 1,0,0,0, _tb, P2 );  /* _tb = (Y2-X2,X2,   Z2,  T2   ), s62|s61|s61|s61 */ \
    FD_R43X6_QUAD_LANE_ADD_FAST( _tb, _tb, 0,1,0,0, _tb, P2 );  /* _tb = (Y2-X2,Y2+X2,Z2,  T2   ), s62|s62|s61|s61 */ \
    FD_R43X6_QUAD_MUL_FAST     ( _ta, _ta, _tb );               /* _ta = (A,    B,    D,   C    ), u62|u62|u62|u62 */ \
    FD_R43X6_QUAD_FOLD_UNSIGNED( _ta, _ta );                    /* _ta = (A,    B,    D,   C    ), u44|u44|u44|u44 */ \
    FD_R43X6_QUAD_PERMUTE      ( _tb, 1,0,3,2, _ta );           /* _tb = (B,    A,    C,   D    ), u62|u62|u62|u62 */ \
    FD_R43X6_QUAD_LANE_SUB_FAST( _tb, _tb, 1,0,0,1, _tb, _ta ); /* _tb = (E,    A,    C,   F    ), s62|u62|u62|s62 */ \
    FD_R43X6_QUAD_LANE_ADD_FAST( _tb, _tb, 0,1,1,0, _tb, _ta ); /* _tb = (E,    H,    G,   F    ), s62|u63|u63|s62 */ \
    FD_R43X6_QUAD_PERMUTE      ( _ta, 0,2,2,0, _tb );           /* _ta = (E,    G,    G,   E    ), u44|u44|u44|u44 */ \
    FD_R43X6_QUAD_PERMUTE      ( _tb, 3,1,3,1, _tb );           /* _tb = (F,    H,    F,   H    ), u44|u44|u44|u44 */ \
    FD_R43X6_QUAD_MUL_FAST     ( _ta, _ta, _tb );               /* _ta = (X3,   Y3,   Z3,  T3   ), u62|u62|u62|u62 */ \
    FD_R43X6_QUAD_FOLD_UNSIGNED( P3, _ta );                     /* P3  = (X3,   Y3,   Z3,  T3   ), u44|u44|u44|u44 */ \
  } while(0)

/* FD_R43X6_GE_DBL(P3,P1) computes P3 = 2*P1 where P1 and P3 are
   FD_R43X6_GE.  P1 should hold u44 representations.  P3 will hold u44
   representations on return.  In place operation fine. */

// Section 5.1.4 (page 12):
//
// For point doubling, (x3,y3) = (x1,y1)+(x1,y1), one could just
// substitute equal points in the above (because of completeness, such
// substitution is valid) and observe that four multiplications turn
// into squares.  However, using the formulas described in Section 3.2
// of [Edwards-revisited] and in [EFD-TWISTED-DBL] saves a few smaller
// operations.
//
//   A = X1^2
//   B = Y1^2
//   C = 2*Z1^2
//   H = A+B
//   E = H-(X1+Y1)^2
//   G = A-B
//   F = C+G
//   X3 = E*F
//   Y3 = G*H
//   T3 = E*H
//   Z3 = F*G

/* TODO: CONSIDER MUL INSTEAD OF SQR TO GET THE 2* AT THE SAME TIME? */
#define FD_R43X6_GE_DBL( P3, P1 ) do {                                                                              \
    FD_R43X6_QUAD_DECL         ( _ta );                                                                             \
    FD_R43X6_QUAD_DECL         ( _tb );                                                                             \
    FD_R43X6_QUAD_DECL         ( _BB );                                                                             \
    FD_R43X6_QUAD_PERMUTE      ( _ta, 1,1,2,0, P1 );            /* _ta = (Y1,       Y1,Z1,  X1), u44/u44/u44/u44 */ \
    FD_R43X6_QUAD_LANE_ADD_FAST( _ta, _ta, 1,0,0,0, _ta, P1 );  /* _ta = (X1+Y1,    Y1,Z1,  X1), u45/u44/u44/u44 */ \
    FD_R43X6_QUAD_SQR_FAST     ( _ta, _ta );                    /* _ta = ((X1+Y1)^2,B, Z1^2,A ), u61/u61/u61/u61 */ \
    FD_R43X6_QUAD_FOLD_UNSIGNED( _ta, _ta );                    /* _ta = ((X1+Y1)^2,B, Z1^2,A ), u44|u44|u44|u44 */ \
    FD_R43X6_QUAD_LANE_ADD_FAST( _ta, _ta, 0,0,1,0, _ta, _ta ); /* _ta = ((X1+Y1)^2,B, C,   A ), u61/u61/u62/u61 */ \
    FD_R43X6_QUAD_PERMUTE      ( _tb, 3,3,3,3, _ta );           /* _tb = (A,        A, A,   A ), u61/u61/u61/u61 */ \
    FD_R43X6_QUAD_PERMUTE      ( _BB, 1,1,1,1, _ta );           /* _BB = (B,        B, B,   B ), u61/u61/u61/u61 */ \
    FD_R43X6_QUAD_LANE_ADD_FAST( _tb, _tb, 1,0,0,1, _tb, _BB ); /* _tb = (H,        A, A,   H ), u62/u61/u61/u62 */ \
    FD_R43X6_QUAD_LANE_SUB_FAST( _tb, _tb, 0,1,1,0, _tb, _BB ); /* _tb = (H,        G, G,   H ), u62/s61/s61/u62 */ \
    FD_R43X6_QUAD_LANE_ADD_FAST( _tb, _tb, 0,0,1,0, _tb, _ta ); /* _tb = (H,        G, F,   H ), u62/s61/s63/u62 */ \
    FD_R43X6_QUAD_LANE_SUB_FAST( _tb, _tb, 1,0,0,0, _tb, _ta ); /* _tb = (E,        G, F,   H ), s62/s61/s63/u62 */ \
    FD_R43X6_QUAD_FOLD_UNSIGNED( _tb, _tb );                    /* _tb = (E,        G, F,   H ), u44/u44/u44/u44 */ \
    FD_R43X6_QUAD_PERMUTE      ( _ta, 0,1,1,0, _tb );           /* _tb = (E,        G, G,   E ), u44/u44/u44/u44 */ \
    FD_R43X6_QUAD_PERMUTE      ( _tb, 2,3,2,3, _tb );           /* _tb = (F,        H, F,   H ), u44/u44/u44/u44 */ \
    FD_R43X6_QUAD_MUL_FAST     ( _ta, _ta, _tb );               /* _ta = (X3,       Y3,Z3,  T3), u62|u62|u62|u62 */ \
    FD_R43X6_QUAD_FOLD_UNSIGNED( P3, _ta );                     /* P3  = (X3,       Y3,Z3,  T3), u44|u44|u44|u44 */ \
  } while(0)

/* FD_R43X6_GE_IS_SMALL_ORDER(P) returns 1 if [8]P is the curve neutral
   point and 0 otherwise.  P should be a FD_R43X6_QUAD holding u44
   representations of a valid curve point. */

#define FD_R43X6_GE_IS_SMALL_ORDER( P ) fd_r43x6_ge_is_small_order( P##03,P##14,P##25 )

FD_FN_UNUSED static int /* let compiler decide if worth inlining */
fd_r43x6_ge_is_small_order( wwl_t P03, wwl_t P14, wwl_t P25 ) {
  for( int i=0; i<3; i++ ) FD_R43X6_GE_DBL( P, P ); /* P = [8]P, in u44|u44|u44|u44 */

  /* We do a faster check than is_eq above by propagating the 0 and 1
     values of the curve neutral point into the multiplication and
     simplifying it.  This is equivalent to checking that the result has
     the form (0|Z|Z|0).  Note that if x is a representation of field
     element 0, t is also a representation 0 as t = x*y. */

  fd_r43x6_t x, y, z, t;
  FD_R43X6_QUAD_UNPACK( x, y, z, t, P ); (void)t;
  return (int)(!fd_r43x6_is_nonzero( x )) & (int)(!fd_r43x6_is_nonzero( fd_r43x6_sub_fast( y, z ) /* in s44 */ ));
}

/* FD_R43X6_GE_ENCODE(h,P) encodes a curve point P stored in the
   FD_R43X6_QUAD P into a unique compressed representation and writes it
   to the 32-byte memory region whose first byte in the callers address
   space is h.  P should hold u47 representations. */

#define FD_R43X6_GE_ENCODE(h,P) wv_stu( (h), fd_r43x6_ge_encode( P##03, P##14, P##25 ) )

FD_FN_CONST wv_t
fd_r43x6_ge_encode( wwl_t P03, wwl_t P14, wwl_t P25 );

/* FD_R43X6_GE_DECODE(P,s) decodes a encoded curve point stored at the
   32-byte region whose first byte in the caller's address space is
   pointed to by s into the curve point P.  Returns 0 on success (P will
   hold the decoded curve point on return in u44 representations) and a
   negative error code on failure (P will hold reduced 0 for X,Y,Z,T).
   The below implementation avoids pointer escapes to help the
   optimizer. */

#define FD_R43X6_GE_DECODE( P,s ) (__extension__({             \
    FD_R43X6_QUAD_DECL( _P );                                  \
    int _err = fd_r43x6_ge_decode( &_P03, &_P14, &_P25, (s) ); \
    FD_R43X6_QUAD_MOV( P, _P );                                \
    _err;                                                      \
  }))

int
fd_r43x6_ge_decode( wwl_t * _P03, wwl_t * _P14, wwl_t * _P25,
                    void const * _vs );

/* FD_R43X6_GE_DECODE2( Pa,sa, Pb,sb ) does:

     if(      GE_DECODE( Pa,sa ) ) { (PbX,PbY,PbZ,PbT) = 0; return -1; }
     else if( GE_DECODE( Pb,sb ) ) { (PaX,PaY,PaZ,PaT) = 0; return -2; }
     return 0;

   but faster. */

#define FD_R43X6_GE_DECODE2( Pa,sa, Pb,sb ) (__extension__({                                      \
    FD_R43X6_QUAD_DECL( _Pa );    FD_R43X6_QUAD_DECL( _Pb );                                      \
    int _err = fd_r43x6_ge_decode2( &_Pa03, &_Pa14, &_Pa25, (sa), &_Pb03, &_Pb14, &_Pb25, (sb) ); \
    FD_R43X6_QUAD_MOV( Pa, _Pa ); FD_R43X6_QUAD_MOV( Pb, _Pb );                                   \
    _err;                                                                                         \
  }))

int
fd_r43x6_ge_decode2( wwl_t * _Pa03, wwl_t * _Pa14, wwl_t * _Pa25,
                     void const * _vsa,
                     wwl_t * _Pb03, wwl_t * _Pb14, wwl_t * _Pb25,
                     void const * _vsb );

/* FD_R43X6_GE_SMUL_BASE(R,s) computes R = [s]B where B is the base
   curve point.  s points to a 32-byte memory region holding a little
   endian uint256 scalar in [0,2^255).  In-place operation fine.  The
   implementation has OpenSSL style timing attack mitigations.  The
   returned R will hold u44 representations.

   FD_R43X6_GE_SMUL_BASE_VARTIME does the same thing but uses a faster
   variable time algorithm.

   Written this funny way to prevent pointer escapes from interfering
   the optimizer and allow for easy testing of different implementations
   as this one of this most performance critical operations in the code
   base.

   Performance of fd_ed25519_public_from_private (this is almost just a
   pure smul_base so it is a good indicator of practical end-to-end
   performance of smul_base ... sign for small messages will show
   similar results) on a single 2.3 GHz icelake-server core under gcc-12
   circa 2023 Sep:

     ref:   ~37.0 us ("vartime" style)
     large:  ~9.2 us ("vartime" style)
     small: ~11.3 us (w/timing attack mitigations)

   For reference:

     scalar: ~46.0 us ("small" style w/timing attack mitigations)
     AVX-2:  ~24.9 us ("small" style w/timing attack mitigations)

   In the large implementation, if table symmetry is not exploited, it
   gets slightly faster (~9.0 us) but the table footprint roughly
   doubles (to ~765KiB) such that it has double the cache pressure.  If
   table symmetry and GE_ADD precomputation is omitted (i.e. GE_ADD is
   used instead of GE_ADD_TABLE), it runs at ~10.0 us.

   If the large implementation is modified to use OpenSSL-style timing
   attack mitigations, it runs at ~11.5 us because the mitigations are
   so expensive (these scan the whole table every time such that the
   table lookup timing should be independent of the input s, which is a
   blunt and portable if naive way of doing it).

   In the small implementation, by using a 4-bit at-a-time
   implementation, the table footprint can be reduced to 48KiB.
   OpenSSL-style timing attack mitigations are then much less expensive
   but more computation is required.  The result has virtually identical
   performance but much less cache pressure than the large
   implementation with timing attack mitigations.  If timing attack
   mitigations are removed from small, it runs at ~11.1 us.

   TL;DR This is ~4-5x faster than the original scalar implementation
   and ~2.2-2.7x faster than the original AVX-2 accelerated
   implementation.  Performance should roughly scale with core clock
   speed for these operations. */

#define FD_R43X6_GE_SMUL_BASE(R,s) do {                                                \
    FD_R43X6_QUAD_DECL( _R ); fd_r43x6_ge_smul_base_small( &_R03, &_R14, &_R25, (s) ); \
    FD_R43X6_QUAD_MOV( R, _R );                                                        \
  } while(0)

#define FD_R43X6_GE_SMUL_BASE_VARTIME(R,s) do {                                        \
    FD_R43X6_QUAD_DECL( _R ); fd_r43x6_ge_smul_base_large( &_R03, &_R14, &_R25, (s) ); \
    FD_R43X6_QUAD_MOV( R, _R );                                                        \
  } while(0)

void
fd_r43x6_ge_smul_base_ref( wwl_t * _R03, wwl_t * _R14, wwl_t * _R25,
                           void const * _vs ); /* vartime */

void
fd_r43x6_ge_smul_base_large( wwl_t * _R03, wwl_t * _R14, wwl_t * _R25,
                             void const * _vs ); /* vartime */

void
fd_r43x6_ge_smul_base_small( wwl_t * _R03, wwl_t * _R14, wwl_t * _R25,
                             void const * _vs ); /* has timing attack mitigations */

/* FD_R43X6_GE_FMA_VARTIME computes R = [s]P + Q where s points to a
   32-bit memory region holding a little endian uint256 scalar in
   [0,2^255).  P and Q are FD_R43X6_QUADs holding curve points in a u44
   representation.  R is a FD_R43X6_QUAD that will hold the result in a
   u44 representation on return.  Uses a variable time algorithm.
   In-place operation fine. */

#define FD_R43X6_GE_FMA_VARTIME(R,s,P,Q) do {                                                                         \
    FD_R43X6_QUAD_DECL( _R ); fd_r43x6_ge_fma_sparse( &_R03,&_R14,&_R25, (s), P##03,P##14,P##25, Q##03,Q##14,Q##25 ); \
    FD_R43X6_QUAD_MOV( R, _R );                                                                                       \
  } while(0)

void
fd_r43x6_ge_fma_ref( wwl_t * _R03, wwl_t * _R14, wwl_t * _R25,
                     void const * _vs,
                     wwl_t    P03, wwl_t    P14, wwl_t    P25,
                     wwl_t    Q03, wwl_t    Q14, wwl_t    Q25 ); /* vartime */

void
fd_r43x6_ge_fma_sparse( wwl_t * _R03, wwl_t * _R14, wwl_t * _R25,
                        void const * _vs,
                        wwl_t    P03, wwl_t    P14, wwl_t    P25,
                        wwl_t    Q03, wwl_t    Q14, wwl_t    Q25 ); /* vartime */

/* FD_R43X6_GE_DMUL_VARTIME(R,s,k,A) computes R = [s]B + [k]A where s
   and k point to 32-byte memory regions holding little endian uint256
   scalars in [0,2^255) and A is a FD_R43X6_QUAD holding a curve point
   in a u44 representation.  B is the base curve point.  R is a
   FD_R43X6_QUAD that will hold the result in a u44 representation on
   return.  Uses a variable time algorithm.  In-place operation fine. */

#define FD_R43X6_GE_DMUL_VARTIME(R,s,k,A) do {                                                           \
    FD_R43X6_QUAD_DECL( _R ); fd_r43x6_ge_dmul_sparse( &_R03,&_R14,&_R25, (s), (k), A##03,A##14,A##25 ); \
    FD_R43X6_QUAD_MOV( R, _R );                                                                          \
  } while(0)

void
fd_r43x6_ge_dmul_ref( wwl_t * _R03, wwl_t * _R14, wwl_t * _R25,
                      void const * _vs,
                      void const * _vk,
                      wwl_t    A03, wwl_t    A14, wwl_t    A25 ); /* vartime */

void
fd_r43x6_ge_dmul_sparse( wwl_t * _R03, wwl_t * _R14, wwl_t * _R25,
                         void const * _vs,
                         void const * _vk,
                         wwl_t    A03, wwl_t    A14, wwl_t    A25 ); /* vartime */

/* fd_r43x6_ge_sparse_table computes a table of odd scalar multiples of
   P stores them in table.  Given a w in [-max,max], the 3 wwl_t's
   holding the FD_R43X6_QUAD for [w]P will start at table index:
   3*((max+w)/2).  This quad will hold Y-X|Y+X|2*Z|T*2*d in a u44
   representation.  max should be positive and odd and table should have
   space for 3*(max+1) entries.  This is mostly for internal use. */

void
fd_r43x6_ge_sparse_table( wwl_t *    table,
                          wwl_t P03, wwl_t P14, wwl_t P25,
                          int        max );

/* TODO: Consider pure for multi-return functions? */

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_ed25519_avx512_fd_r43x6_ge_h */
