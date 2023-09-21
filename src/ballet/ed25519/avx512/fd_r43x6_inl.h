#ifndef HEADER_fd_src_ballet_ed25519_avx512_fd_r43x6_inl_h
#define HEADER_fd_src_ballet_ed25519_avx512_fd_r43x6_inl_h

#ifndef HEADER_fd_src_ballet_ed25519_avx512_fd_r43x6_h
#error "Do not include this directly; use fd_r43x6.h"
#endif

/* Protocols like ED25519 do many GF(p) operations that can be run
   in parallel in principle.  But, because of the complexity of the
   individual operations, optimizers struggle with extracting the ILP
   (e.g. to get at the ILP in, for example, 3 independent fd_r43x6_mul,
   it has to decide to inline all 3 when its heuristics usually indicate
   is each mul is too expensive in code footprint to justify inlining
   even one and then do a very long range reorganization of the assembly
   instructions when its heuristics usually indicate to avoid such to
   keep compile time computational complexity reasonable.

   Further, when there are enough operations that can be run in
   parallel, it is often a net win to swizzle / deswizzle the data
   layout to make use of otherwise unused vector lanes.  The optimizer's
   ability to do such radical code transformations, is limited at best
   and practically impossible for transformations could generate a
   different but mathematically equivalent representation of the result,
   akin to fd_r43x6_mul(x,x) vs fd_r43x6_sqr(x).

   It is also useful to annotate such parallelism in the protocol
   implementations such that they can be upgraded with no change to take
   advantage of newer hardware, better compilers, etc by updating these
   implementations as appropriate.

   The below makes a low to mid tens of percent performance improvement
   for things like ED25519 verify on gcc-12 and icelake-server. */

FD_PROTOTYPES_BEGIN

/* FD_R43X6_QUAD_DECL(Q) declares the wwl_t's Q03, Q14 and Q25 in the
   local scope to represent fd_r43x6_t X, Y, Z and T, but in a more
   efficient way for data parallel GF(p) operations under the hood.
   Organization:

     Q03 = [ X0 Y0 Z0 T0 | X3 Y3 Z3 T3 ]
     Q14 = [ X1 Y1 Z1 T1 | X4 Y4 Z4 T4 ]
     Q25 = [ X2 Y2 Z2 T2 | X5 Y5 Z5 T5 ]

   where Xi is the i-th limb of X. */

#define FD_R43X6_QUAD_DECL( Q ) wwl_t Q##03, Q##14, Q##25

/* FD_R43X6_QUAD_MOV( D, S ) does D = S.  D and S are FD_R43X6_QUAD
   declarations in the local scope. */

#define FD_R43X6_QUAD_MOV( D, S ) do { D##03 = S##03; D##14 = S##14; D##25 = S##25; } while(0)

/* FD_R43X6_QUAD_PACK(Q,x,y,z,t) does Q = (x,y,z,t) where Q is a
   FD_R43X6_QUAD declared in the local scope, x, y, z and t are
   arbitrary fd_r43x6_t. */

#define FD_R43X6_QUAD_PACK( Q, x,y,z,t ) do {                           \
    wwl_t _r0 = (x);                                                    \
    wwl_t _r1 = (y);                                                    \
    wwl_t _r2 = (z);                                                    \
    wwl_t _r3 = (t);                                                    \
    /* At this point _r0 = x0 x1 x2 x3 x4 x5 -- -- */                   \
    /*               _r1 = y0 y1 y2 y3 y4 y5 -- -- */                   \
    /*               _r2 = z0 z1 z2 z3 z4 z5 -- -- */                   \
    /*               _r3 = t0 t1 t2 t3 t4 t5 -- -- */                   \
    /* Transpose 2x2 blocks                        */                   \
    /* No _mm256_permute2f128_si256 equivalent? Sigh ... */             \
    wwl_t _t0 = wwl_select( wwl(  0, 1, 8, 9, 4, 5,12,13 ), _r0, _r2 ); \
    wwl_t _t1 = wwl_select( wwl(  0, 1, 8, 9, 4, 5,12,13 ), _r1, _r3 ); \
    wwl_t _t2 = wwl_select( wwl(  2, 3,10,11, 6, 7,12,13 ), _r0, _r2 ); \
    wwl_t _t3 = wwl_select( wwl(  2, 3,10,11, 6, 7,12,13 ), _r1, _r3 ); \
    /* At this point _t0 = x0 x1 z0 z1 x4 x5 z4 z5 */                   \
    /*               _t1 = y0 y1 t0 t1 y4 y5 t4 t5 */                   \
    /*               _t2 = x2 x3 z2 z3 -- -- -- -- */                   \
    /*               _t3 = y2 y3 t2 t3 -- -- -- -- */                   \
    /* Transpose 1x1 blocks                        */                   \
    wwl_t _c04 = _mm512_unpacklo_epi64( _t0, _t1 );                     \
    wwl_t _c15 = _mm512_unpackhi_epi64( _t0, _t1 );                     \
    wwl_t _c26 = _mm512_unpacklo_epi64( _t2, _t3 );                     \
    wwl_t _c37 = _mm512_unpackhi_epi64( _t2, _t3 );                     \
    /* At this point _c04 = x0 y0 z0 t0 x4 y4 z4 t4 */                  \
    /*               _c15 = x1 y1 t1 t1 x5 y5 z4 t5 */                  \
    /*               _c26 = x2 y2 z2 t2 -- -- -- -- */                  \
    /*               _c37 = x3 y3 z2 t3 -- -- -- -- */                  \
    Q##03 = wwl_pack_halves( _c04,0, _c37,0 );                          \
    Q##14 = wwl_pack_h0_h1 ( _c15,   _c04   );                          \
    Q##25 = wwl_pack_h0_h1 ( _c26,   _c15   );                          \
  } while(0)

/* FD_R43X6_QUAD_UNPACK(x,y,z,t,Q) does (x,y,z,t) = Q where x, y, z and
   t are arbitrary fd_r43x6_t and Q is a FD_R43X6_QUAD declared in the
   local scope. */

#define FD_R43X6_QUAD_UNPACK( x,y,z,t, Q ) do {               \
    wwl_t _r0 = Q##03;                                        \
    wwl_t _r1 = Q##14;                                        \
    wwl_t _r2 = Q##25;                                        \
    wwl_t _r3 = wwl_zero();                                   \
    /* At this point _r0 = x0 y0 z0 t0 x3 y3 z3 t3 */         \
    /*               _r1 = x1 y1 z1 t1 x4 y4 z4 t4 */         \
    /*               _r2 = x2 y2 z2 t2 x5 y5 z5 t5 */         \
    /*               _r3 =  0  0  0  0  0  0  0  0 */         \
    /* Transpose 1x1 blocks */                                \
    wwl_t _c0 = _mm512_unpacklo_epi64( _r0, _r1 );            \
    wwl_t _c1 = _mm512_unpackhi_epi64( _r0, _r1 );            \
    wwl_t _c2 = _mm512_unpacklo_epi64( _r2, _r3 );            \
    wwl_t _c3 = _mm512_unpackhi_epi64( _r2, _r3 );            \
    /* At this point _c0 = x0 x1 z0 z1 x3 x4 z3 z4 */         \
    /*               _c1 = y0 y1 t0 t1 y3 y4 t3 t4 */         \
    /*               _c2 = x2  0 z2  0 x5  0 z5  0 */         \
    /*               _c3 = y2  0 t2  0 y5  0 t5  0 */         \
    (x) = wwl_select( wwl(  0,1, 8, 4,5,12, 9,9 ), _c0,_c2 ); \
    (y) = wwl_select( wwl(  0,1, 8, 4,5,12, 9,9 ), _c1,_c3 ); \
    (z) = wwl_select( wwl(  2,3,10, 6,7,14, 9,9 ), _c0,_c2 ); \
    (t) = wwl_select( wwl(  2,3,10, 6,7,14, 9,9 ), _c1,_c3 ); \
  } while(0)

/* FD_R43X6_QUAD_PERMUTE(D,S) does:
     D = [ S(imm0) S(imm1) S(imm2) S(imm3) ]
   where imm* are in [0,3] (0/1/2/3->X/Y/Z/T) */

#define FD_R43X6_QUAD_PERMUTE( D, imm0,imm1,imm2,imm3, S ) do {                                  \
    wwl_t const _perm = wwl( (imm0),(imm1),(imm2),(imm3), 4+(imm0),4+(imm1),4+(imm2),4+(imm3) ); \
    D##03 = wwl_permute( _perm, S##03 );                                                         \
    D##14 = wwl_permute( _perm, S##14 );                                                         \
    D##25 = wwl_permute( _perm, S##25 );                                                         \
  } while(0)

/* FD_R43X6_QUAD_LANE_BLEND does:
     D = [ imm0 ? SX : TX, imm1 ? SY : TY, imm2 ? SZ : TZ, imm3 ? ST : TT ]
   imm* should be in [0,1]. */

#define FD_R43X6_QUAD_LANE_BLEND( D, imm0,imm1,imm2,imm3, S, T ) do {                  \
    __mmask8 const _mask = (__mmask8)(17*(imm0) + 34*(imm1) + 68*(imm2) + 136*(imm3)); \
    D##03 = wwl_blend( _mask, S##03, T##03 );                                          \
    D##14 = wwl_blend( _mask, S##14, T##14 );                                          \
    D##25 = wwl_blend( _mask, S##25, T##25 );                                          \
  } while(0)

/* FD_R43X6_QUAD_LANE_ADD_FAST does:
     D = [ (imm0 ? (PX+QX) : SX) (imm1 ? (PY+QY) : SY) (imm2 ? (PZ+QZ) : SZ) (imm3 ? (PT+QT) : ST) ]
   imm* should be in [0,1]. */

#define FD_R43X6_QUAD_LANE_ADD_FAST( D, S, imm0,imm1,imm2,imm3, P, Q ) do {            \
    __mmask8 const _mask = (__mmask8)(17*(imm0) + 34*(imm1) + 68*(imm2) + 136*(imm3)); \
    D##03 = _mm512_mask_add_epi64( S##03, _mask, P##03, Q##03 );                       \
    D##14 = _mm512_mask_add_epi64( S##14, _mask, P##14, Q##14 );                       \
    D##25 = _mm512_mask_add_epi64( S##25, _mask, P##25, Q##25 );                       \
  } while(0)

/* FD_R43X6_QUAD_LANE_SUB_FAST does:
     D = [ (imm0 ? (PX-QX) : SX) (imm1 ? (PY-QY) : SY) (imm2 ? (PZ-QZ) : SZ) (imm3 ? (PT-QT) : ST) ]
   imm* should be in [0,1]. */

#define FD_R43X6_QUAD_LANE_SUB_FAST( D, S, imm0,imm1,imm2,imm3, P, Q ) do {            \
    __mmask8 const _mask = (__mmask8)(17*(imm0) + 34*(imm1) + 68*(imm2) + 136*(imm3)); \
    D##03 = _mm512_mask_sub_epi64( S##03, _mask, P##03, Q##03 );                       \
    D##14 = _mm512_mask_sub_epi64( S##14, _mask, P##14, Q##14 );                       \
    D##25 = _mm512_mask_sub_epi64( S##25, _mask, P##25, Q##25 );                       \
  } while(0)

/* FD_R43X6_QUAD_FOLD_UNSIGNED(R,P) does:
     R = [ fd_r43x6_fold_unsigned(PX) fd_r43x6_fold_unsigned(PY) fd_r43x6_fold_unsigned(PZ) fd_r43x6_fold_unsigned(PT) ] */

#define FD_R43X6_QUAD_FOLD_UNSIGNED( R, P ) do {                                            \
    long const _m43 = (1L<<43) - 1L;                                                        \
    long const _m40 = (1L<<40) - 1L;                                                        \
                                                                                            \
    wwl_t const _m43_m43 = wwl_bcast( _m43 );                                               \
    wwl_t const _m43_m40 = wwl( _m43,_m43,_m43,_m43, _m40,_m40,_m40,_m40 );                 \
    wwl_t const _s43_s40 = wwl(  43L, 43L, 43L, 43L,  40L, 40L, 40L, 40L );                 \
                                                                                            \
    wwl_t _Ph03    = wwl_shru       ( P##03, 43      );                                     \
    wwl_t _Ph14    = wwl_shru       ( P##14, 43      );                                     \
    wwl_t _Ph25    = wwl_shru_vector( P##25, _s43_s40 );                                    \
    wwl_t _19_Ph25 = wwl_add( _Ph25, wwl_add( wwl_shl( _Ph25, 1 ), wwl_shl( _Ph25, 4 ) ) ); \
                                                                                            \
    R##03 = wwl_add( wwl_and( P##03, _m43_m43 ), wwl_pack_halves( _19_Ph25,1, _Ph25,0 ) );  \
    R##14 = wwl_add( wwl_and( P##14, _m43_m43 ), _Ph03 );                                   \
    R##25 = wwl_add( wwl_and( P##25, _m43_m40 ), _Ph14 );                                   \
  } while(0)

/* FD_R43X6_QUAD_FOLD_SIGNED(R,P) does:
     R = [ fd_r43x6_fold_signed(PX) fd_r43x6_fold_signed(PY) fd_r43x6_fold_signed(PZ) fd_r43x6_fold_signed(PT) ] */

#define FD_R43X6_QUAD_FOLD_SIGNED( R, P ) do {                                                                \
    long const _b0  = 19L<<23;                                                                                \
    long const _bb  =  1L<<20;                                                                                \
    long const _m43 = (1L<<43) - 1L;                                                                          \
    long const _m40 = (1L<<40) - 1L;                                                                          \
                                                                                                              \
    wwl_t const _bias03  = wwl(  _b0, _b0, _b0, _b0,  _bb, _bb, _bb, _bb );                                   \
    wwl_t const _bias    = wwl_bcast( _bb );                                                                  \
    wwl_t const _m43_m43 = wwl_bcast( _m43 );                                                                 \
    wwl_t const _m43_m40 = wwl( _m43,_m43,_m43,_m43, _m40,_m40,_m40,_m40 );                                   \
    wwl_t const _s43_s40 = wwl(  43L, 43L, 43L, 43L,  40L, 40L, 40L, 40L );                                   \
                                                                                                              \
    wwl_t _P03 = wwl_sub( P##03, _bias03 );                                                                   \
    wwl_t _P14 = wwl_sub( P##14, _bias   );                                                                   \
    wwl_t _P25 = wwl_sub( P##25, _bias   );                                                                   \
                                                                                                              \
    wwl_t _Ph03    = wwl_shr       ( _P03, 43       );                                                        \
    wwl_t _Ph14    = wwl_shr       ( _P14, 43       );                                                        \
    wwl_t _Ph25    = wwl_shr_vector( _P25, _s43_s40 );                                                        \
    wwl_t _19_Ph25 = wwl_add( _Ph25, wwl_add( wwl_shl( _Ph25, 1 ), wwl_shl( _Ph25, 4 ) ) );                   \
                                                                                                              \
    R##03 = wwl_add( wwl_and( _P03, _m43_m43 ), wwl_add( wwl_pack_halves( _19_Ph25,1, _Ph25,0 ), _bias03 ) ); \
    R##14 = wwl_add( wwl_and( _P14, _m43_m43 ), wwl_add( _Ph03,                                  _bias   ) ); \
    R##25 = wwl_add( wwl_and( _P25, _m43_m40 ), wwl_add( _Ph14,                                  _bias   ) ); \
  } while(0)

/* FD_R43X6_QUAD_MUL_FAST(R,P,Q) does (
     [ fd_r43x6_mul_fast(PX,QX) fd_r43x6_mul_fast(PY,QY) fd_r43x6_mul_fast(PZ,QZ) fd_r43x6_mul_fast(PT,QT) ]
   Written this way so that pointer escapes don't inhibit optimizations. */

#define FD_R43X6_QUAD_MUL_FAST( R, P, Q ) do {                                                                   \
    FD_R43X6_QUAD_DECL( _R ); fd_r43x6_quad_mul_fast( &_R03,&_R14,&_R25, P##03,P##14,P##25, Q##03,Q##14,Q##25 ); \
    FD_R43X6_QUAD_MOV( R, _R );                                                                                  \
  } while(0)

FD_FN_UNUSED static void /* let compiler decide if worth inlining */
fd_r43x6_quad_mul_fast( fd_r43x6_t * _z03, fd_r43x6_t * _z14, fd_r43x6_t * _z25,
                        fd_r43x6_t    x03, fd_r43x6_t    x14, fd_r43x6_t    x25,
                        fd_r43x6_t    y03, fd_r43x6_t    y14, fd_r43x6_t    y25 ) {

  /* Grade school-ish from the original mul:

                                       x5   x4   x3   x2   x1   x0
                                  x    y5   y4   y3   y2   y1   y0
                                  --------------------------------
                                     p50l p40l p30l p20l p10l p00l
                                p50h p40h p30h p20h p10h p00h
                                p51l p41l p31l p21l p11l p01l
                           p51h p41h p31h p21h p11h p01h
                           p52l p42l p32l p22l p12l p02l
                      p52h p42h p32h p22h p12h p02h
                      p53l p43l p33l p23l p13l p03l
                 p53h p43h p33h p23h p13h p03h
                 p54l p44l p34l p24l p14l p04l
            p54h p44h p34h p24h p14h p04h
            p55l p45l p35l p25l p15l p05l
       p55h p45h p35h p25h p15h p05h
       -----------------------------------------------------------
        zb5  zb4  zb3  zb2  zb1  zb0  za5  za4  za3  za2  za1  za0

     Reorganize the partials into low and high parts:

                                     p50l p40l p30l p20l p10l p00l
                                p51l p41l p31l p21l p11l p01l
                           p52l p42l p32l p22l p12l p02l
                      p53l p43l p33l p23l p13l p03l
                 p54l p44l p34l p24l p14l p04l
            p55l p45l p35l p25l p15l p05l

                                p50h p40h p30h p20h p10h p00h
                           p51h p41h p31h p21h p11h p01h
                      p52h p42h p32h p22h p12h p02h
                 p53h p43h p33h p23h p13h p03h
            p54h p44h p34h p24h p14h p04h
       p55h p45h p35h p25h p15h p05h

     We start with 3 8-lane vectors per input.  These hold 4 fd_r43x6_t
     organized as:

       x03 = [ X0 X3 ], y03 = [ Y0 Y3 ],
       x14 = [ X1 X4 ], y14 = [ Y1 Y4 ],
       x25 = [ X2 X5 ], y25 = [ Y2 Y5 ]

     Above, Xi indicates limb i for the 4 input.  We can quickly form
     "xii = [ Xi Xi ]" by packing halves of the x inputs.  And then
     doing madd52lo of this on a similarly packed yjk we get:

       LO( xii * yjk ) = [ pijl pikl ]

     Doing x00, x11, x22, x33, x44, x55 against y03, y14, y25 yields all
     the low partials, organized:

       [ p00l p03l ], [ p01l p04l ], [ p02l p05l ],
       [ p10l p03l ], [ p11l p14l ], [ p12l p15l ],
       [ p20l p03l ], [ p21l p24l ], [ p22l p25l ],
       [ p30l p03l ], [ p31l p34l ], [ p32l p35l ],
       [ p40l p03l ], [ p41l p44l ], [ p42l p45l ],
       [ p50l p03l ], [ p51l p54l ], [ p52l p55l ]

     If we use the lower half of these results to accumulate the
     partials for the first 3 rows, we have:

       p0_q3 = [ p00l p03l ]
       p1_q4 = [ p10l p04l ] + [ p01l p04l ]
       p2_q5 = [ p20l p05l ] + [ p11l p15l ] + [ p02l p05l ]
       p3_q6 = [ p30l p06l ] + [ p21l p26l ] + [ p12l p15l ]
       p4_q7 = [ p40l p07l ] + [ p31l p37l ] + [ p22l p25l ]
       p5_q8 = [ p50l p08l ] + [ p41l p48l ] + [ p32l p35l ]
       p6_q9 =                 [ p51l p59l ] + [ p42l p45l ]
       p7_qa =                                 [ p52l p55l ]

     We also see that doing this implicitly accumulates the last 3 rows
     of partials at the same time.  Note also that we can use the
     accumulate features of MADD to do these accumulations and we have
     lots of independent MADD chains.

     The exact same applies for the HI partials.  When we sum the LO and
     HI partials, we need to shift the HI parts left by 9 for the
     reasons described in the scalar version.  When we sum the lower and
     upper halves to finish the partial accumulation, we repack them
     into two FD_R43X6_QUAD representations at the same time.

     This yields the below.  This has massive ILP with utilization of
     all lanes with no wasted or redundant multiplications and very
     minimal fast shuffling. */

  wwl_t const _zz = wwl_zero();

  wwl_t x00   = wwl_pack_halves( x03,0, x03,0 );
  wwl_t x11   = wwl_pack_halves( x14,0, x14,0 );
  wwl_t x22   = wwl_pack_halves( x25,0, x25,0 );
  wwl_t x33   = wwl_pack_halves( x03,1, x03,1 );
  wwl_t x44   = wwl_pack_halves( x14,1, x14,1 );
  wwl_t x55   = wwl_pack_halves( x25,1, x25,1 );

# if 1 /* This version is faster even though it has more adds due to higher ILP */
  wwl_t p0_q3 = wwl_madd52lo(                             _zz, x00, y03 );
  wwl_t p1_q4 = wwl_madd52lo( wwl_madd52lo(               _zz, x11, y03 ), x00, y14 );
  wwl_t p2_q5 = wwl_madd52lo( wwl_madd52lo( wwl_madd52lo( _zz, x22, y03 ), x11, y14 ), x00, y25 );
  wwl_t p3_q6 = wwl_madd52lo( wwl_madd52lo( wwl_madd52lo( _zz, x33, y03 ), x22, y14 ), x11, y25 );
  wwl_t p4_q7 = wwl_madd52lo( wwl_madd52lo( wwl_madd52lo( _zz, x44, y03 ), x33, y14 ), x22, y25 );
  wwl_t p5_q8 = wwl_madd52lo( wwl_madd52lo( wwl_madd52lo( _zz, x55, y03 ), x44, y14 ), x33, y25 );
  wwl_t p6_q9 =               wwl_madd52lo( wwl_madd52lo( _zz,             x55, y14 ), x44, y25 );
  wwl_t p7_qa =                             wwl_madd52lo( _zz,                         x55, y25 );

  /**/  p1_q4 = wwl_add( p1_q4, wwl_shl( wwl_madd52hi(                             _zz, x00, y03 ),                         9 ) );
  /**/  p2_q5 = wwl_add( p2_q5, wwl_shl( wwl_madd52hi( wwl_madd52hi(               _zz, x11, y03 ), x00, y14 ),             9 ) );
  /**/  p3_q6 = wwl_add( p3_q6, wwl_shl( wwl_madd52hi( wwl_madd52hi( wwl_madd52hi( _zz, x22, y03 ), x11, y14 ), x00, y25 ), 9 ) );
  /**/  p4_q7 = wwl_add( p4_q7, wwl_shl( wwl_madd52hi( wwl_madd52hi( wwl_madd52hi( _zz, x33, y03 ), x22, y14 ), x11, y25 ), 9 ) );
  /**/  p5_q8 = wwl_add( p5_q8, wwl_shl( wwl_madd52hi( wwl_madd52hi( wwl_madd52hi( _zz, x44, y03 ), x33, y14 ), x22, y25 ), 9 ) );
  /**/  p6_q9 = wwl_add( p6_q9, wwl_shl( wwl_madd52hi( wwl_madd52hi( wwl_madd52hi( _zz, x55, y03 ), x44, y14 ), x33, y25 ), 9 ) );
  /**/  p7_qa = wwl_add( p7_qa, wwl_shl(               wwl_madd52hi( wwl_madd52hi( _zz,             x55, y14 ), x44, y25 ), 9 ) );
  wwl_t p8_qb =                 wwl_shl(                             wwl_madd52hi( _zz,                         x55, y25 ), 9 );
# else
  wwl_t p1_q4 = wwl_shl( wwl_madd52hi(                             _zz,   x00, y03 ),                         9 );
  wwl_t p2_q5 = wwl_shl( wwl_madd52hi( wwl_madd52hi(               _zz,   x11, y03 ), x00, y14 ),             9 );
  wwl_t p3_q6 = wwl_shl( wwl_madd52hi( wwl_madd52hi( wwl_madd52hi( _zz,   x22, y03 ), x11, y14 ), x00, y25 ), 9 );
  wwl_t p4_q7 = wwl_shl( wwl_madd52hi( wwl_madd52hi( wwl_madd52hi( _zz,   x33, y03 ), x22, y14 ), x11, y25 ), 9 );
  wwl_t p5_q8 = wwl_shl( wwl_madd52hi( wwl_madd52hi( wwl_madd52hi( _zz,   x44, y03 ), x33, y14 ), x22, y25 ), 9 );
  wwl_t p6_q9 = wwl_shl( wwl_madd52hi( wwl_madd52hi( wwl_madd52hi( _zz,   x55, y03 ), x44, y14 ), x33, y25 ), 9 );
  wwl_t p7_qa = wwl_shl(               wwl_madd52hi( wwl_madd52hi( _zz,               x55, y14 ), x44, y25 ), 9 );
  wwl_t p8_qb = wwl_shl(                             wwl_madd52hi( _zz,                           x55, y25 ), 9 );

  wwl_t p0_q3 =          wwl_madd52lo(                             _zz,   x00, y03 );
  /**/  p1_q4 =          wwl_madd52lo( wwl_madd52lo(               p1_q4, x11, y03 ), x00, y14 );
  /**/  p2_q5 =          wwl_madd52lo( wwl_madd52lo( wwl_madd52lo( p2_q5, x22, y03 ), x11, y14 ), x00, y25 );
  /**/  p3_q6 =          wwl_madd52lo( wwl_madd52lo( wwl_madd52lo( p3_q6, x33, y03 ), x22, y14 ), x11, y25 );
  /**/  p4_q7 =          wwl_madd52lo( wwl_madd52lo( wwl_madd52lo( p4_q7, x44, y03 ), x33, y14 ), x22, y25 );
  /**/  p5_q8 =          wwl_madd52lo( wwl_madd52lo( wwl_madd52lo( p5_q8, x55, y03 ), x44, y14 ), x33, y25 );
  /**/  p6_q9 =                        wwl_madd52lo( wwl_madd52lo( p6_q9,             x55, y14 ), x44, y25 );
  /**/  p7_qa =                                      wwl_madd52lo( p7_qa,                         x55, y25 );
# endif

  wwl_t q6_p3 = wwl_pack_halves( p3_q6,1, p3_q6,0 );
  wwl_t q7_p4 = wwl_pack_halves( p4_q7,1, p4_q7,0 );
  wwl_t q8_p5 = wwl_pack_halves( p5_q8,1, p5_q8,0 );

  wwl_t za03  = _mm512_mask_add_epi64( p0_q3, (__mmask8)0xF0, p0_q3, q6_p3 );
  wwl_t za14  = _mm512_mask_add_epi64( p1_q4, (__mmask8)0xF0, p1_q4, q7_p4 );
  wwl_t za25  = _mm512_mask_add_epi64( p2_q5, (__mmask8)0xF0, p2_q5, q8_p5 );

  wwl_t zb03  = _mm512_mask_add_epi64( p6_q9, (__mmask8)0x0F, p6_q9, q6_p3 );
  wwl_t zb14  = _mm512_mask_add_epi64( p7_qa, (__mmask8)0x0F, p7_qa, q7_p4 );
  wwl_t zb25  = _mm512_mask_add_epi64( p8_qb, (__mmask8)0x0F, p8_qb, q8_p5 );

  /* At this point:

       z = <za0,za1,za2,za3,za4,za5> + 2^258 <zb0,zb1,zb2,zb3,zb4,zb5>
         = <za0,za1,za2,za3,za4,za5> +   152 <zb0,zb1,zb2,zb3,zb4,zb5>

     and we can sum this directly (see scalar version for proof).  Like
     the scalar version, we do the multiplication via shift-and-add
     techniques because mullo is slow. */

  wwl_t z03 = wwl_add( wwl_add( za03, wwl_shl( zb03, 7 ) ), wwl_add( wwl_shl( zb03, 4 ), wwl_shl( zb03, 3 ) ) );
  wwl_t z14 = wwl_add( wwl_add( za14, wwl_shl( zb14, 7 ) ), wwl_add( wwl_shl( zb14, 4 ), wwl_shl( zb14, 3 ) ) );
  wwl_t z25 = wwl_add( wwl_add( za25, wwl_shl( zb25, 7 ) ), wwl_add( wwl_shl( zb25, 4 ), wwl_shl( zb25, 3 ) ) );

  FD_R43X6_QUAD_MOV( *_z, z );
}

/* FD_R43X6_QUAD_SQR_FAST(R,P) does:
     [ fd_r43x6_sqr_fast(PX) fd_r43x6_sqr_fast(PY) fd_r43x6_sqr_fast(PZ) fd_r43x6_sqr_fast(PT) ]
   Written this way so that pointer escapes don't inhibit optimizations. */

#define FD_R43X6_QUAD_SQR_FAST( R, P ) do {                                                   \
    FD_R43X6_QUAD_DECL( _R ); fd_r43x6_quad_sqr_fast( &_R03,&_R14,&_R25, P##03,P##14,P##25 ); \
    FD_R43X6_QUAD_MOV( R, _R );                                                               \
  } while(0)

FD_FN_UNUSED static void /* let compiler decide if worth inlining */
fd_r43x6_quad_sqr_fast( fd_r43x6_t * _z03, fd_r43x6_t * _z14, fd_r43x6_t * _z25,
                        fd_r43x6_t    x03, fd_r43x6_t    x14, fd_r43x6_t    x25 ) {

  /* Grade school-ish from the original mul:

                                       x5   x4   x3   x2   x1   x0
                                  x    x5   x4   x3   x2   x1   x0
                                  --------------------------------
                                     p50l p40l p30l p20l p10l p00l
                                p50h p40h p30h p20h p10h p00h
                                p51l p41l p31l p21l p11l p01l
                           p51h p41h p31h p21h p11h p01h
                           p52l p42l p32l p22l p12l p02l
                      p52h p42h p32h p22h p12h p02h
                      p53l p43l p33l p23l p13l p03l
                 p53h p43h p33h p23h p13h p03h
                 p54l p44l p34l p24l p14l p04l
            p54h p44h p34h p24h p14h p04h
            p55l p45l p35l p25l p15l p05l
       p55h p45h p35h p25h p15h p05h
       -----------------------------------------------------------
         zb   za   z9   z8   z7   z6   z5   z4   z3   z2   z1   z0

     Consider only the low partial rows and note that pijl=pjil here.
     This portion of the reduction can be simplified:

                                          2*p50l 2*p40l 2*p30l 2*p20l 2*p10l   p00l
                                   2*p51l 2*p41l 2*p31l 2*p21l   p11l
                            2*p52l 2*p42l 2*p32l   p22l
                     2*p53l 2*p43l   p33l
              2*p54l   p44l
         p55l
       ----------------------------------------------------------------------------
           pa     p9     p8     p7     p6     p5     p4     p3     p2     p1     p0

     The number of adds and the partials that need to be doubled have a
     mirror symmetry about p5.  Exploiting this yields:

       2*p50l|2*p32l 2*p40l|2*p51l 2*p30l|2*p52l 2*p20l|2*p53l 2*p10l|2*p54l  p00l|p55l
       2*p41l|2*zero 2*p31l|2*p42l 2*p21l|2*p43l   p11l|  p44l
                       p22l|  p33l
       --------------------------------------------------------------------------------
            p55           p46           p37           p28           p19          p0a

     Above a|b means make an 8-lane vector by concatenating the 4 a's
     (one for each square in progress) and the 4 b's.  Above we have
     split the reduction of p5 to get some extra vector multiplier
     utilization.  Other splits are possible and maybe could usefully
     trade some extra computation for less swizzling.

     Similar holds for the high partials:

       2*p50h|2*p32h 2*p40h|2*p51h 2*p30h|2*p52h 2*p20h|2*p53h 2*p10h|2*p54h  p00h|p55h
       2*p41h|2*zero 2*p31h|2*p42h 2*p21h|2*p43h   p11h|  p44h
                       p22h|  p33h
       --------------------------------------------------------------------------------
            q66           q57           q48           q39           q2a          q1b

     For the reasons described in the scalar implementation, we need to
     shift the high partials left by 9 before we can reduce them into
     the low partials.  As we do this reduction, we repack them into the
     FD_R43X6_QUAD's za and zb.

     In doing these reductions, we exploit i<>j symmetry and pair terms
     on the left and right halves to minimize input shuffling.  For
     example, for p1b, we need to form x05=x0|x5 and then compute
     p1b=x05*x05.  Instead of forming x15 and x04 to compute
     p2a=2*x15*x04, we can do p2a=2*p01h|2*p54h and use the x14 we were
     passed direclty and reuse the x05 formed for p1b.

     This yields the below.  Theoretical minimum number of multiplies,
     tons of ILP, low swizzling overhead. */

  wwl_t _zz     = wwl_zero();

  wwl_t x05     = wwl_pack_h0_h1 ( x03,   x25   );
  wwl_t x12     = wwl_pack_halves( x14,0, x25,0 );
  wwl_t x34     = wwl_pack_halves( x03,1, x14,1 );
  wwl_t x41     = wwl_pack_halves( x14,1, x14,0 );
  wwl_t x23     = wwl_pack_h0_h1 ( x25,   x03   );

  wwl_t x52     = wwl_pack_halves( x25,1, x25,0 );
  wwl_t x4z     = wwl_pack_halves( x14,1, _zz,0 );

  wwl_t two_x03 = wwl_shl( x03, 1 );
  wwl_t two_x14 = wwl_shl( x14, 1 );
  wwl_t two_x05 = wwl_shl( x05, 1 );
  wwl_t two_x12 = wwl_shl( x12, 1 );

# if 1 /* This version is faster even though it has more adds due to better ILP */
  wwl_t p0a     =          wwl_madd52lo(                             _zz,     x05, x05 );
  wwl_t p19     =          wwl_madd52lo(                             _zz, two_x05, x14 );
  wwl_t p28     =          wwl_madd52lo( wwl_madd52lo(               _zz,     x14, x14 ), two_x03, x25 );
  wwl_t p37     =          wwl_madd52lo( wwl_madd52lo(               _zz, two_x03, x34 ), two_x12, x25 );
  wwl_t p46     =          wwl_madd52lo( wwl_madd52lo( wwl_madd52lo( _zz,     x23, x23 ), two_x05, x41 ), two_x12, x34 );
  wwl_t p55     =          wwl_madd52lo( wwl_madd52lo(               _zz, two_x03, x52 ), two_x14, x4z );

  wwl_t q1b     = wwl_shl( wwl_madd52hi(                             _zz,     x05, x05 ),                                 9 );
  wwl_t q2a     = wwl_shl( wwl_madd52hi(                             _zz, two_x05, x14 ),                                 9 );
  wwl_t q39     = wwl_shl( wwl_madd52hi( wwl_madd52hi(               _zz,     x14, x14 ), two_x03, x25 ),                 9 );
  wwl_t q48     = wwl_shl( wwl_madd52hi( wwl_madd52hi(               _zz, two_x03, x34 ), two_x12, x25 ),                 9 );
  wwl_t q57     = wwl_shl( wwl_madd52hi( wwl_madd52hi( wwl_madd52hi( _zz,     x23, x23 ), two_x05, x41 ), two_x12, x34 ), 9 );
  wwl_t q66     = wwl_shl( wwl_madd52hi( wwl_madd52hi(               _zz, two_x03, x52 ), two_x14, x4z ),                 9 );

  wwl_t za03    =          wwl_add( wwl_pack_halves( p0a,0, p37,0 ), wwl_pack_halves( _zz,0, q39,0 ) );
  wwl_t za14    =          wwl_add( wwl_pack_halves( p19,0, p46,0 ), wwl_pack_halves( q1b,0, q48,0 ) );
  wwl_t za25    = wwl_add( wwl_add( wwl_pack_halves( p28,0, p55,0 ), wwl_pack_halves( q2a,0, q57,0 ) ), wwl_pack_h0_h1( _zz, p55 ) );

  wwl_t zb03    = wwl_add( wwl_add( wwl_pack_halves( p46,1, p19,1 ), wwl_pack_halves( q66,1, q39,1 ) ), wwl_pack_h0_h1( q66, _zz ) );
  wwl_t zb14    =          wwl_add( wwl_pack_halves( p37,1, p0a,1 ), wwl_pack_halves( q57,1, q2a,1 ) );
  wwl_t zb25    =          wwl_add( wwl_pack_halves( p28,1, _zz,1 ), wwl_pack_halves( q48,1, q1b,1 ) );
# else
  wwl_t q1b     = wwl_shl( wwl_madd52hi(                             _zz,     x05, x05 ),                                 9 );
  wwl_t q2a     = wwl_shl( wwl_madd52hi(                             _zz, two_x05, x14 ),                                 9 );
  wwl_t q39     = wwl_shl( wwl_madd52hi( wwl_madd52hi(               _zz,     x14, x14 ), two_x03, x25 ),                 9 );
  wwl_t q48     = wwl_shl( wwl_madd52hi( wwl_madd52hi(               _zz, two_x03, x34 ), two_x12, x25 ),                 9 );
  wwl_t q57     = wwl_shl( wwl_madd52hi( wwl_madd52hi( wwl_madd52hi( _zz,     x23, x23 ), two_x05, x41 ), two_x12, x34 ), 9 );
  wwl_t q66     = wwl_shl( wwl_madd52hi( wwl_madd52hi(               _zz, two_x03, x52 ), two_x14, x4z ),                 9 );

  wwl_t p0a     =          wwl_madd52lo(                             wwl_pack_h0_h1( _zz, q2a ),     x05, x05 );
  wwl_t p19     =          wwl_madd52lo(                             wwl_pack_h0_h1( q1b, q39 ), two_x05, x14 );
  wwl_t p28     =          wwl_madd52lo( wwl_madd52lo(               wwl_pack_h0_h1( q2a, q48 ),     x14, x14 ), two_x03, x25 );
  wwl_t p37     =          wwl_madd52lo( wwl_madd52lo(               wwl_pack_h0_h1( q39, q57 ), two_x03, x34 ), two_x12, x25 );
  wwl_t p46     =          wwl_madd52lo( wwl_madd52lo( wwl_madd52lo( wwl_pack_h0_h1( q48, q66 ),     x23, x23 ), two_x05, x41 ), two_x12, x34 );
  wwl_t p55     =          wwl_madd52lo( wwl_madd52lo(               wwl_pack_h0_h1( q57, _zz ), two_x03, x52 ), two_x14, x4z );

  wwl_t za03    =          wwl_pack_halves( p0a,0, p37,0 );
  wwl_t za14    =          wwl_pack_halves( p19,0, p46,0 );
  wwl_t za25    = wwl_add( wwl_pack_halves( p28,0, p55,0 ), wwl_pack_h0_h1( _zz, p55 ) );

  wwl_t zb03    = wwl_add( wwl_pack_halves( p46,1, p19,1 ), wwl_pack_h0_h1( q66, _zz ) );
  wwl_t zb14    =          wwl_pack_halves( p37,1, p0a,1 );
  wwl_t zb25    =          wwl_pack_halves( p28,1, q1b,1 );
# endif

  /* At this point:

       z = <za0,za1,za2,za3,za4,za5> + 2^258 <zb0,zb1,zb2,zb3,zb4,zb5>

     We complete the calc exactly like FD_R43X6_QUAD_MUL above. */

  wwl_t z03 = wwl_add( wwl_add( za03, wwl_shl( zb03, 7 ) ), wwl_add( wwl_shl( zb03, 4 ), wwl_shl( zb03, 3 ) ) );
  wwl_t z14 = wwl_add( wwl_add( za14, wwl_shl( zb14, 7 ) ), wwl_add( wwl_shl( zb14, 4 ), wwl_shl( zb14, 3 ) ) );
  wwl_t z25 = wwl_add( wwl_add( za25, wwl_shl( zb25, 7 ) ), wwl_add( wwl_shl( zb25, 4 ), wwl_shl( zb25, 3 ) ) );

  FD_R43X6_QUAD_MOV( *_z, z );
}

/* Below, FD_R43X6_MUL4_INL( za,xa,ya, zb,xb,yb, zc,xc,yc, zd,xd,yd )
   exactly does:

     za = fd_r43x6_mul( xa, ya );
     zb = fd_r43x6_mul( xb, yb );
     zc = fd_r43x6_mul( xc, yc );
     zd = fd_r43x6_mul( xd, yd );

   Likewise, FD_R43X6_SQR4_INL( za,xa, zb,xb, zc,xc, zd,xd ) exactly does:

     za = fd_r43x6_sqr( xa );
     zb = fd_r43x6_sqr( xb );
     zc = fd_r43x6_sqr( xc );
     zd = fd_r43x6_sqr( xd );

   And, FD_R43X6_POW25223_2_INL( za,xa, zb,xb ) exactly does:

     za = fd_r43x6_pow25223( xa );
     zb = fd_r43x6_pow25223( xb );

   Similarly for FD_R43X6_MUL{1,2,3}_INL, FD_R43X6_SQR{1,2,3}_INL and
   FD_R43X6_POW25223_1_INL( za ).

   These macros are robust (e.g. these evaluate their arguments once and
   they linguistically behave as a single statement) and have the
   resulting ILP very exposed to the optimizer and CPU.  In-place
   operation okay.

   Future implementations might allow these to produce different
   mathematically equivalent representations of the result if such
   allows higher performance akin to what was done for fd_r43x6_sqr.

   TODO: SUB2_INL to accelerate the folds there?

   TODO: Consider pure for various multi-return function prototypes? */

#if 0 /* Reference implementation */

#define FD_R43X6_MUL1_INL( za,xa,ya ) do { \
    (za) = fd_r43x6_mul( (xa), (ya) );     \
  } while(0)

#define FD_R43X6_MUL2_INL( za,xa,ya, zb,xb,yb ) do { \
    (za) = fd_r43x6_mul( (xa), (ya) );               \
    (zb) = fd_r43x6_mul( (xb), (yb) );               \
  } while(0)

#define FD_R43X6_MUL3_INL( za,xa,ya, zb,xb,yb, zc,xc,yc ) do { \
    (za) = fd_r43x6_mul( (xa), (ya) );                         \
    (zb) = fd_r43x6_mul( (xb), (yb) );                         \
    (zc) = fd_r43x6_mul( (xc), (yc) );                         \
  } while(0)

#define FD_R43X6_MUL4_INL( za,xa,ya, zb,xb,yb, zc,xc,yc, zd,xd,yd ) do { \
    (za) = fd_r43x6_mul( (xa), (ya) );                                   \
    (zb) = fd_r43x6_mul( (xb), (yb) );                                   \
    (zc) = fd_r43x6_mul( (xc), (yc) );                                   \
    (zd) = fd_r43x6_mul( (xd), (yd) );                                   \
  } while(0)

#define FD_R43X6_SQR1_INL( za,xa ) do { \
    (za) = fd_r43x6_sqr( (xa) );        \
  } while(0)

#define FD_R43X6_SQR2_INL( za,xa, zb,xb ) do { \
    (za) = fd_r43x6_sqr( (xa) );               \
    (zb) = fd_r43x6_sqr( (xb) );               \
  } while(0)

#define FD_R43X6_SQR3_INL( za,xa, zb,xb, zc,xc ) do { \
    (za) = fd_r43x6_sqr( (xa) );                      \
    (zb) = fd_r43x6_sqr( (xb) );                      \
    (zc) = fd_r43x6_sqr( (xc) );                      \
  } while(0)

#define FD_R43X6_SQR4_INL( za,xa, zb,xb, zc,xc, zd,xd ) do { \
    (za) = fd_r43x6_sqr( (xa) );                             \
    (zb) = fd_r43x6_sqr( (xb) );                             \
    (zc) = fd_r43x6_sqr( (xc) );                             \
    (zd) = fd_r43x6_sqr( (xd) );                             \
  } while(0)

#define FD_R43X6_POW22523_1_INL( za,xa ) do { \
    (za) = fd_r43x6_pow22523( (xa) );         \
  } while(0)

#define FD_R43X6_POW22523_2_INL( za,xa, zb,xb ) do { \
    (za) = fd_r43x6_pow22523( (xa) );                \
    (zb) = fd_r43x6_pow22523( (xb) );                \
  } while(0)

#else /* HPC implementation */

/* Nothing to interleave so let compiler decide */

#define FD_R43X6_MUL1_INL( z,x,y ) do { \
    (z) = fd_r43x6_mul( (x), (y) );     \
  } while(0)

/* Seems to be slightly faster to let compiler decide */

#define FD_R43X6_MUL2_INL( za,xa,ya, zb,xb,yb ) do { \
    (za) = fd_r43x6_mul( (xa), (ya) );               \
    (zb) = fd_r43x6_mul( (xb), (yb) );               \
  } while(0)

/* Slightly faster to pack / pack / mul / fold / unpack */

#define FD_R43X6_MUL3_INL( za,xa,ya, zb,xb,yb, zc,xc,yc ) do {                                   \
    FD_R43X6_QUAD_DECL( _X ); FD_R43X6_QUAD_PACK         ( _X, (xa),(xb),(xc),fd_r43x6_zero() ); \
    FD_R43X6_QUAD_DECL( _Y ); FD_R43X6_QUAD_PACK         ( _Y, (ya),(yb),(yc),fd_r43x6_zero() ); \
    FD_R43X6_QUAD_DECL( _Z ); FD_R43X6_QUAD_MUL_FAST     (  _Z, _X, _Y );                        \
    /**/                      FD_R43X6_QUAD_FOLD_UNSIGNED( _Z, _Z );                             \
    fd_r43x6_t _zd;           FD_R43X6_QUAD_UNPACK       ( (za),(zb),(zc),_zd, _Z );             \
    (void)_zd;                                                                                   \
  } while(0)

/* Substantially faster to pack / pack / mul / fold / unpack */

#define FD_R43X6_MUL4_INL( za,xa,ya, zb,xb,yb, zc,xc,yc, zd,xd,yd ) do {              \
    FD_R43X6_QUAD_DECL( _X ); FD_R43X6_QUAD_PACK         ( _X, (xa),(xb),(xc),(xd) ); \
    FD_R43X6_QUAD_DECL( _Y ); FD_R43X6_QUAD_PACK         ( _Y, (ya),(yb),(yc),(yd) ); \
    FD_R43X6_QUAD_DECL( _Z ); FD_R43X6_QUAD_MUL_FAST     (  _Z, _X, _Y );             \
    /**/                      FD_R43X6_QUAD_FOLD_UNSIGNED( _Z, _Z );                  \
    /**/                      FD_R43X6_QUAD_UNPACK       ( (za),(zb),(zc),(zd), _Z ); \
  } while(0)

/* Nothing to interleave so let compiler decide */

#define FD_R43X6_SQR1_INL( z,x ) do { (z) = fd_r43x6_sqr( (x) ); } while(0)

/* Seems to be slightly faster to let compiler decide */

#define FD_R43X6_SQR2_INL( za,xa, zb,xb ) do { \
    (za) = fd_r43x6_sqr( (xa) );               \
    (zb) = fd_r43x6_sqr( (xb) );               \
  } while(0)

/* Seems to be slightly faster to let compiler decide */

#define FD_R43X6_SQR3_INL( za,xa, zb,xb, zc,xc ) do { \
    (za) = fd_r43x6_sqr( (xa) );                      \
    (zb) = fd_r43x6_sqr( (xb) );                      \
    (zc) = fd_r43x6_sqr( (xc) );                      \
  } while(0)

/* Substantially faster to pack / pack / sqr / fold / unpack */

#define FD_R43X6_SQR4_INL( za,xa, zb,xb, zc,xc, zd,xd ) do {                          \
    FD_R43X6_QUAD_DECL( _X ); FD_R43X6_QUAD_PACK         ( _X, (xa),(xb),(xc),(xd) ); \
    FD_R43X6_QUAD_DECL( _Z ); FD_R43X6_QUAD_SQR_FAST     ( _Z, _X );                  \
    /**/                      FD_R43X6_QUAD_FOLD_UNSIGNED( _Z, _Z );                  \
    /**/                      FD_R43X6_QUAD_UNPACK       ( (za),(zb),(zc),(zd), _Z ); \
  } while(0)

/* Nothing to interleave so let compiler decide */

#define FD_R43X6_POW22523_1_INL( za,xa ) do { \
    (za) = fd_r43x6_pow22523( (xa) );         \
  } while(0)

/* This is very expensive with a huge instruction footprint.  So we just
   wrap to avoid pointer escapes from inhibiting optimization and call a
   separately compiled version. */

#define FD_R43X6_POW22523_2_INL( za,xa, zb,xb ) do { \
    fd_r43x6_t _za; fd_r43x6_t _zb;                  \
    fd_r43x6_pow22523_2( &_za,(xa), &_zb,(xb) );     \
    (za) = _za; (zb) = _zb;                          \
  } while(0)

void
fd_r43x6_pow22523_2( fd_r43x6_t * _za, fd_r43x6_t za,
                     fd_r43x6_t * _zb, fd_r43x6_t zb );

#endif /* HPC implementation */

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_ed25519_avx512_fd_r43x6_inl_h */
