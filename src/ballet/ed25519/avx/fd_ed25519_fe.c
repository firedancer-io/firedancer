#include "../fd_ed25519_private.h"

#define SWIZZLE_IN( v0,v1,v2,v3,v4,v5,v6,v7,v8,v9, a,b,c,d ) do {                                                         \
    /* Load in limbs 0:7 */                                                                                               \
    fd_ed25519_fe_t const * _a = (a); wi_t _r0 = wi_ld( _a->limb ); wi_t _r1 = wi_zero();                                 \
    fd_ed25519_fe_t const * _b = (b); wi_t _r2 = wi_ld( _b->limb ); wi_t _r3 = wi_zero();                                 \
    fd_ed25519_fe_t const * _c = (c); wi_t _r4 = wi_ld( _c->limb ); wi_t _r5 = wi_zero();                                 \
    fd_ed25519_fe_t const * _d = (d); wi_t _r6 = wi_ld( _d->limb ); wi_t _r7 = wi_zero();                                 \
    /* At this point r0...r7 are the 8x8 int matrix */                                                                    \
    /* r0 = a0 a1 a2 a3 a4 a5 a6 a7 */                                                                                    \
    /* r1 =  0  0  0  0  0  0  0  0 */                                                                                    \
    /* r2 = b0 b1 b2 b3 b4 b5 b6 b7 */                                                                                    \
    /* r3 =  0  0  0  0  0  0  0  0 */                                                                                    \
    /* r4 = c0 c1 c2 c3 c4 c5 c6 c7 */                                                                                    \
    /* r5 =  0  0  0  0  0  0  0  0 */                                                                                    \
    /* r6 = d0 d1 d2 d3 d4 d5 d6 d7 */                                                                                    \
    /* r7 =  0  0  0  0  0  0  0  0 */                                                                                    \
    /* Transpose this matrix */                                                                                           \
    wi_t _ta = _r0; _r0 = _mm256_permute2f128_si256( _ta, _r4, 0x20 ); _r4 = _mm256_permute2f128_si256( _ta, _r4, 0x31 ); \
    wi_t _tb = _r1; _r1 = _mm256_permute2f128_si256( _tb, _r5, 0x20 ); _r5 = _mm256_permute2f128_si256( _tb, _r5, 0x31 ); \
    wi_t _tc = _r2; _r2 = _mm256_permute2f128_si256( _tc, _r6, 0x20 ); _r6 = _mm256_permute2f128_si256( _tc, _r6, 0x31 ); \
    wi_t _td = _r3; _r3 = _mm256_permute2f128_si256( _td, _r7, 0x20 ); _r7 = _mm256_permute2f128_si256( _td, _r7, 0x31 ); \
    wi_t _te = _r0; _r0 = _mm256_unpacklo_epi32    ( _te, _r2       ); _r2 = _mm256_unpackhi_epi32    ( _te, _r2       ); \
    wi_t _tf = _r1; _r1 = _mm256_unpacklo_epi32    ( _tf, _r3       ); _r3 = _mm256_unpackhi_epi32    ( _tf, _r3       ); \
    wi_t _tg = _r4; _r4 = _mm256_unpacklo_epi32    ( _tg, _r6       ); _r6 = _mm256_unpackhi_epi32    ( _tg, _r6       ); \
    wi_t _th = _r5; _r5 = _mm256_unpacklo_epi32    ( _th, _r7       ); _r7 = _mm256_unpackhi_epi32    ( _th, _r7       ); \
    /**/ _ta = _r0; _r0 = _mm256_unpacklo_epi32    ( _ta, _r1       ); _r1 = _mm256_unpackhi_epi32    ( _ta, _r1       ); \
    /**/ _tb = _r2; _r2 = _mm256_unpacklo_epi32    ( _tb, _r3       ); _r3 = _mm256_unpackhi_epi32    ( _tb, _r3       ); \
    /**/ _tc = _r4; _r4 = _mm256_unpacklo_epi32    ( _tc, _r5       ); _r5 = _mm256_unpackhi_epi32    ( _tc, _r5       ); \
    /**/ _td = _r6; _r6 = _mm256_unpacklo_epi32    ( _td, _r7       ); _r7 = _mm256_unpackhi_epi32    ( _td, _r7       ); \
    /* At this point, r0...r7 are the 8x8 int matrix */                                                                   \
    /* r0 = a0 0 b0 0 c0 0 d0 0 */                                                                                        \
    /* r1 = a1 0 b1 0 c1 0 d1 0 */                                                                                        \
    /* r2 = a2 0 b2 0 c2 0 d2 0 */                                                                                        \
    /* r3 = a3 0 b3 0 c3 0 d3 0 */                                                                                        \
    /* r4 = a4 0 b4 0 c4 0 d4 0 */                                                                                        \
    /* r5 = a5 0 b5 0 c5 0 d5 0 */                                                                                        \
    /* r6 = a6 0 b6 0 c6 0 d6 0 */                                                                                        \
    /* r7 = a7 0 b7 0 c7 0 d7 0 */                                                                                        \
    /* This can be treated as a 8x4 long matrix with no further manipulations */                                          \
    /* r0 = a0 b0 c0 d0 */                                                                                                \
    /* r1 = a1 b1 c1 d1 */                                                                                                \
    /* r2 = a2 b2 c2 d2 */                                                                                                \
    /* r3 = a3 b3 c3 d3 */                                                                                                \
    /* r4 = a4 b4 c4 d4 */                                                                                                \
    /* r5 = a5 b5 c5 d5 */                                                                                                \
    /* r6 = a6 b6 c6 d6 */                                                                                                \
    /* r7 = a7 b7 c7 d7 */                                                                                                \
    (v0) = (wl_t)_r0;                                                                                                     \
    (v1) = (wl_t)_r1;                                                                                                     \
    (v2) = (wl_t)_r2;                                                                                                     \
    (v3) = (wl_t)_r3;                                                                                                     \
    (v4) = (wl_t)_r4;                                                                                                     \
    (v5) = (wl_t)_r5;                                                                                                     \
    (v6) = (wl_t)_r6;                                                                                                     \
    (v7) = (wl_t)_r7;                                                                                                     \
    /* Handle stragglers (FIXME: PROBABLY CAN BE OPT FURTHER) */                                                          \
    (v8) = wl( (long)_a->limb[8], (long)_b->limb[8], (long)_c->limb[8], (long)_d->limb[8] );                              \
    (v9) = wl( (long)_a->limb[9], (long)_b->limb[9], (long)_c->limb[9], (long)_d->limb[9] );                              \
  } while(0)

#define SWIZZLE_OUT( a,b,c,d, v0,v1,v2,v3,v4,v5,v6,v7,v8,v9 ) do {                                                           \
    /* At this point v0:v7 are the 8x4 long matrix where all components fit in 32-bits */                                    \
    /* v0 = a0 b0 c0 d0 */                                                                                                   \
    /* v1 = a1 b1 c1 d1 */                                                                                                   \
    /* v2 = a2 b2 c2 d2 */                                                                                                   \
    /* v3 = a3 b3 c3 d3 */                                                                                                   \
    /* v4 = a4 b4 c4 d4 */                                                                                                   \
    /* v5 = a5 b5 c5 d5 */                                                                                                   \
    /* v6 = a6 b6 c6 d6 */                                                                                                   \
    /* v7 = a7 b7 c7 d7 */                                                                                                   \
    wi_t _r0 = (wi_t)(v0); wi_t _r1 = (wi_t)(v1);                                                                            \
    wi_t _r2 = (wi_t)(v2); wi_t _r3 = (wi_t)(v3);                                                                            \
    wi_t _r4 = (wi_t)(v4); wi_t _r5 = (wi_t)(v5);                                                                            \
    wi_t _r6 = (wi_t)(v6); wi_t _r7 = (wi_t)(v7);                                                                            \
    /* At this point r0...r7 are the 8x8 int matrix */                                                                       \
    /* v0 = a0 0 b0 0 c0 0 d0 0 */                                                                                           \
    /* v1 = a1 0 b1 0 c1 0 d1 0 */                                                                                           \
    /* v2 = a2 0 b2 0 c2 0 d2 0 */                                                                                           \
    /* v3 = a3 0 b3 0 c3 0 d3 0 */                                                                                           \
    /* v4 = a4 0 b4 0 c4 0 d4 0 */                                                                                           \
    /* v5 = a5 0 b5 0 c5 0 d5 0 */                                                                                           \
    /* v6 = a6 0 b6 0 c6 0 d6 0 */                                                                                           \
    /* v7 = a7 0 b7 0 c7 0 d7 0 */                                                                                           \
    /* Transpose this matrix */                                                                                              \
    /* We can skip doing the final formulation of the zero rows */                                                           \
    wi_t _ta = _r0; _r0 = _mm256_permute2f128_si256( _ta, _r4, 0x20 );  _r4 = _mm256_permute2f128_si256( _ta, _r4, 0x31 );   \
    wi_t _tb = _r1; _r1 = _mm256_permute2f128_si256( _tb, _r5, 0x20 );  _r5 = _mm256_permute2f128_si256( _tb, _r5, 0x31 );   \
    wi_t _tc = _r2; _r2 = _mm256_permute2f128_si256( _tc, _r6, 0x20 );  _r6 = _mm256_permute2f128_si256( _tc, _r6, 0x31 );   \
    wi_t _td = _r3; _r3 = _mm256_permute2f128_si256( _td, _r7, 0x20 );  _r7 = _mm256_permute2f128_si256( _td, _r7, 0x31 );   \
    wi_t _te = _r0; _r0 = _mm256_unpacklo_epi32    ( _te, _r2       );  _r2 = _mm256_unpackhi_epi32    ( _te, _r2       );   \
    wi_t _tf = _r1; _r1 = _mm256_unpacklo_epi32    ( _tf, _r3       );  _r3 = _mm256_unpackhi_epi32    ( _tf, _r3       );   \
    wi_t _tg = _r4; _r4 = _mm256_unpacklo_epi32    ( _tg, _r6       );  _r6 = _mm256_unpackhi_epi32    ( _tg, _r6       );   \
    wi_t _th = _r5; _r5 = _mm256_unpacklo_epi32    ( _th, _r7       );  _r7 = _mm256_unpackhi_epi32    ( _th, _r7       );   \
    /**/ _ta = _r0; _r0 = _mm256_unpacklo_epi32    ( _ta, _r1       );/*_r1 = _mm256_unpackhi_epi32    ( _ta, _r1       );*/ \
    /**/ _tb = _r2; _r2 = _mm256_unpacklo_epi32    ( _tb, _r3       );/*_r3 = _mm256_unpackhi_epi32    ( _tb, _r3       );*/ \
    /**/ _tc = _r4; _r4 = _mm256_unpacklo_epi32    ( _tc, _r5       );/*_r5 = _mm256_unpackhi_epi32    ( _tc, _r5       );*/ \
    /**/ _td = _r6; _r6 = _mm256_unpacklo_epi32    ( _td, _r7       );/*_r7 = _mm256_unpackhi_epi32    ( _td, _r7       );*/ \
    /* Store out limbs 0:7 */                                                                                                \
    fd_ed25519_fe_t * _a = (a);                                                                                              \
    fd_ed25519_fe_t * _b = (b);                                                                                              \
    fd_ed25519_fe_t * _c = (c);                                                                                              \
    fd_ed25519_fe_t * _d = (d);                                                                                              \
    wi_st( _a->limb, _r0 );                                                                                                  \
    wi_st( _b->limb, _r2 );                                                                                                  \
    wi_st( _c->limb, _r4 );                                                                                                  \
    wi_st( _d->limb, _r6 );                                                                                                  \
    /* Scatter stragglers (MIGHT BE ABLE TO OPT FURTHER) */                                                                  \
    wi_t _r8    = (wi_t)(v8);           wi_t _r9    = (wi_t)(v9);                                                            \
    _a->limb[8] = wi_extract( _r8, 0 ); _a->limb[9] = wi_extract( _r9, 0 );                                                  \
    _b->limb[8] = wi_extract( _r8, 2 ); _b->limb[9] = wi_extract( _r9, 2 );                                                  \
    _c->limb[8] = wi_extract( _r8, 4 ); _c->limb[9] = wi_extract( _r9, 4 );                                                  \
    _d->limb[8] = wi_extract( _r8, 6 ); _d->limb[9] = wi_extract( _r9, 6 );                                                  \
  } while(0)

#define REDUCE_0()                       wl_zero()
#define REDUCE_1(  a                   ) (a)
#define REDUCE_2(  a,b                 ) wl_add( (a), (b) )
#define REDUCE_3(  a,b,c               ) REDUCE_2( REDUCE_2( (a),(b) ),             (c) )
#define REDUCE_4(  a,b,c,d             ) REDUCE_2( REDUCE_2( (a),(b) ),             REDUCE_2( (c),(d) ) )
#define REDUCE_5(  a,b,c,d,e           ) REDUCE_2( REDUCE_3( (a),(b),(c) ),         REDUCE_2( (d),(e) ) )
#define REDUCE_6(  a,b,c,d,e,f         ) REDUCE_2( REDUCE_3( (a),(b),(c) ),         REDUCE_3( (d),(e),(f) ) )
#define REDUCE_7(  a,b,c,d,e,f,g       ) REDUCE_2( REDUCE_4( (a),(b),(c),(d) ),     REDUCE_3( (e),(f),(g) ) )
#define REDUCE_8(  a,b,c,d,e,f,g,h     ) REDUCE_2( REDUCE_4( (a),(b),(c),(d) ),     REDUCE_4( (e),(f),(g),(h) ) )
#define REDUCE_9(  a,b,c,d,e,f,g,h,i   ) REDUCE_2( REDUCE_5( (a),(b),(c),(d),(e) ), REDUCE_4( (f),(g),(h),(i) ) )
#define REDUCE_10( a,b,c,d,e,f,g,h,i,j ) REDUCE_2( REDUCE_5( (a),(b),(c),(d),(e) ), REDUCE_5( (f),(g),(h),(i),(j) ) )

fd_ed25519_fe_t *
fd_ed25519_fe_frombytes( fd_ed25519_fe_t * h,
                         uchar const *     s ) {

  /* FIXME: THIS CAN PROBABLY BE ACCELERATED BY DOING 4 64-BIT LOADS AND
     THEN UNPACKING FOR HIGH ILP.  UNCLEAR IF BELOW DOES A FULL
     REDUCTION THOUGH SO THIS ALTERNATIVE MIGHT YIELD ONLY AN EQUIVALENT
     INTERMEDIATE REPRESENTATION (AND FOR SANITY WE ARE KEEPING
     INTERMEDIATES BIT LEVEL EXACT TOO).  CHECK FD_LOADS ELSEWHERE TO
     MAKE SURE THIS IS THE CASE IN GENERAL. */

  long h0 = (long)  fd_load_4_fast( s      );
  long h1 = (long)  fd_load_3_fast( s +  4 ) << 6;
  long h2 = (long)  fd_load_3_fast( s +  7 ) << 5;
  long h3 = (long)  fd_load_3_fast( s + 10 ) << 3;
  long h4 = (long)  fd_load_3_fast( s + 13 ) << 2;
  long h5 = (long)  fd_load_4_fast( s + 16 );
  long h6 = (long)  fd_load_3_fast( s + 20 ) << 7;
  long h7 = (long)  fd_load_3_fast( s + 23 ) << 5;
  long h8 = (long)  fd_load_3_fast( s + 26 ) << 4;
  long h9 = (long)((fd_load_3     ( s + 29 ) & 0x7fffffUL) << 2); /* Ignores top bit of h. */

  long m39u = (long)FD_MASK_MSB(39);
  long carry9 = h9 + (1 << 24); h0 += (carry9 >> 25)*19L; h9 -= carry9 & m39u;
  long carry1 = h1 + (1 << 24); h2 +=  carry1 >> 25;      h1 -= carry1 & m39u;
  long carry3 = h3 + (1 << 24); h4 +=  carry3 >> 25;      h3 -= carry3 & m39u;
  long carry5 = h5 + (1 << 24); h6 +=  carry5 >> 25;      h5 -= carry5 & m39u;
  long carry7 = h7 + (1 << 24); h8 +=  carry7 >> 25;      h7 -= carry7 & m39u;

  long m38u = (long)FD_MASK_MSB(38);
  long carry0 = h0 + (1 << 25); h1 +=  carry0 >> 26;      h0 -= carry0 & m38u;
  long carry2 = h2 + (1 << 25); h3 +=  carry2 >> 26;      h2 -= carry2 & m38u;
  long carry4 = h4 + (1 << 25); h5 +=  carry4 >> 26;      h4 -= carry4 & m38u;
  long carry6 = h6 + (1 << 25); h7 +=  carry6 >> 26;      h6 -= carry6 & m38u;
  long carry8 = h8 + (1 << 25); h9 +=  carry8 >> 26;      h8 -= carry8 & m38u;

  h->limb[0] = (int)h0; h->limb[1] = (int)h1;
  h->limb[2] = (int)h2; h->limb[3] = (int)h3;
  h->limb[4] = (int)h4; h->limb[5] = (int)h5;
  h->limb[6] = (int)h6; h->limb[7] = (int)h7;
  h->limb[8] = (int)h8; h->limb[9] = (int)h9;
  return h;
}

uchar *
fd_ed25519_fe_tobytes( uchar *                 s,
                       fd_ed25519_fe_t const * h ) {

  /* Load limbs of h */

  int h0 = h->limb[0]; int h1 = h->limb[1];
  int h2 = h->limb[2]; int h3 = h->limb[3];
  int h4 = h->limb[4]; int h5 = h->limb[5];
  int h6 = h->limb[6]; int h7 = h->limb[7];
  int h8 = h->limb[8]; int h9 = h->limb[9];

  /* Write p=2^255-19; q=floor(h/p).
     Basic claim: q = floor(2^(-255)(h + 19 2^(-25)h9 + 2^(-1))).
    
     Proof:
       Have |h|<=p so |q|<=1 so |19^2 2^(-255) q|<1/4.
       Also have |h-2^230 h9|<2^231 so |19 2^(-255)(h-2^230 h9)|<1/4.
    
       Write y=2^(-1)-19^2 2^(-255)q-19 2^(-255)(h-2^230 h9).
       Then 0<y<1.
    
       Write r=h-pq.
       Have 0<=r<=p-1=2^255-20.
       Thus 0<=r+19(2^-255)r<r+19(2^-255)2^255<=2^255-1.
    
       Write x=r+19(2^-255)r+y.
       Then 0<x<2^255 so floor(2^(-255)x) = 0 so floor(q+2^(-255)x) = q.
    
       Have q+2^(-255)x = 2^(-255)(h + 19 2^(-25) h9 + 2^(-1))
       so floor(2^(-255)(h + 19 2^(-25) h9 + 2^(-1))) = q.  */

  int q = (19*h9 + (1<<24)) >> 25;
  q = (h0 + q) >> 26; q = (h1 + q) >> 25;
  q = (h2 + q) >> 26; q = (h3 + q) >> 25;
  q = (h4 + q) >> 26; q = (h5 + q) >> 25;
  q = (h6 + q) >> 26; q = (h7 + q) >> 25;
  q = (h8 + q) >> 26; q = (h9 + q) >> 25;

  /* Goal: Output h-(2^255-19)q, which is between 0 and 2^255-20. */

  h0 += 19*q;

  /* Goal: Output h-2^255 q, which is between 0 and 2^255-20. */

  int m26 = (int)FD_MASK_LSB(26);
  int m25 = (int)FD_MASK_LSB(25);

  h1 += h0 >> 26; h0 &= m26; h2 += h1 >> 25; h1 &= m25;
  h3 += h2 >> 26; h2 &= m26; h4 += h3 >> 25; h3 &= m25;
  h5 += h4 >> 26; h4 &= m26; h6 += h5 >> 25; h5 &= m25;
  h7 += h6 >> 26; h6 &= m26; h8 += h7 >> 25; h7 &= m25;
  h9 += h8 >> 26; h8 &= m26; /*h10=carry9*/  h9 &= m25;

  /* Pack the results into s */

  *(ulong *) s     = (((ulong)(uint)h0)    ) | (((ulong)(uint)h1)<<26) | (((ulong)(uint)h2)<<51);
  *(ulong *)(s+ 8) = (((ulong)(uint)h2)>>13) | (((ulong)(uint)h3)<<13) | (((ulong)(uint)h4)<<38);
  *(ulong *)(s+16) = (((ulong)(uint)h5)    ) | (((ulong)(uint)h6)<<25) | (((ulong)(uint)h7)<<51);
  *(ulong *)(s+24) = (((ulong)(uint)h7)>>13) | (((ulong)(uint)h8)<<12) | (((ulong)(uint)h9)<<38);

  return s;
}

fd_ed25519_fe_t *
fd_ed25519_fe_mul( fd_ed25519_fe_t *       h,
                   fd_ed25519_fe_t const * f,
                   fd_ed25519_fe_t const * g ) {

  /* Notes on implementation strategy:
    
     Using schoolbook multiplication.
     Karatsuba would save a little in some cost models.
    
     Most multiplications by 2 and 19 are 32-bit precomputations;
     cheaper than 64-bit postcomputations.
    
     There is one remaining multiplication by 19 in the carry chain;
     one *19 precomputation can be merged into this,
     but the resulting data flow is considerably less clean.
    
     There are 12 carries below.
     10 of them are 2-way parallelizable and vectorizable.
     Can get away with 11 carries, but then data flow is much deeper.
    
     With tighter constraints on inputs can squeeze carries into int. */

  long f0 = (long)f->limb[0]; long f1 = (long)f->limb[1];
  long f2 = (long)f->limb[2]; long f3 = (long)f->limb[3];
  long f4 = (long)f->limb[4]; long f5 = (long)f->limb[5];
  long f6 = (long)f->limb[6]; long f7 = (long)f->limb[7];
  long f8 = (long)f->limb[8]; long f9 = (long)f->limb[9];

  long g0 = (long)g->limb[0]; long g1 = (long)g->limb[1];
  long g2 = (long)g->limb[2]; long g3 = (long)g->limb[3];
  long g4 = (long)g->limb[4]; long g5 = (long)g->limb[5];
  long g6 = (long)g->limb[6]; long g7 = (long)g->limb[7];
  long g8 = (long)g->limb[8]; long g9 = (long)g->limb[9];

  long g1_19 = 19L*g1; /* 1.959375*2^29 */
  long g2_19 = 19L*g2; /* 1.959375*2^30; still ok */
  long g3_19 = 19L*g3;
  long g4_19 = 19L*g4;
  long g5_19 = 19L*g5;
  long g6_19 = 19L*g6;
  long g7_19 = 19L*g7;
  long g8_19 = 19L*g8;
  long g9_19 = 19L*g9;

  long f1_2 = 2L*f1;
  long f3_2 = 2L*f3;
  long f5_2 = 2L*f5;
  long f7_2 = 2L*f7;
  long f9_2 = 2L*f9;

  long f0g0    = f0*g0   ; long f0g1    = f0  *g1   ;
  long f0g2    = f0*g2   ; long f0g3    = f0  *g3   ;
  long f0g4    = f0*g4   ; long f0g5    = f0  *g5   ;
  long f0g6    = f0*g6   ; long f0g7    = f0  *g7   ;
  long f0g8    = f0*g8   ; long f0g9    = f0  *g9   ;

  long f1g0    = f1*g0   ; long f1g1_2  = f1_2*g1   ;
  long f1g2    = f1*g2   ; long f1g3_2  = f1_2*g3   ;
  long f1g4    = f1*g4   ; long f1g5_2  = f1_2*g5   ;
  long f1g6    = f1*g6   ; long f1g7_2  = f1_2*g7   ;
  long f1g8    = f1*g8   ; long f1g9_38 = f1_2*g9_19;

  long f2g0    = f2*g0   ; long f2g1    = f2  *g1   ;
  long f2g2    = f2*g2   ; long f2g3    = f2  *g3   ;
  long f2g4    = f2*g4   ; long f2g5    = f2  *g5   ;
  long f2g6    = f2*g6   ; long f2g7    = f2  *g7   ;
  long f2g8_19 = f2*g8_19; long f2g9_19 = f2  *g9_19;

  long f3g0    = f3*g0   ; long f3g1_2  = f3_2*g1   ;
  long f3g2    = f3*g2   ; long f3g3_2  = f3_2*g3   ;
  long f3g4    = f3*g4   ; long f3g5_2  = f3_2*g5   ;
  long f3g6    = f3*g6   ; long f3g7_38 = f3_2*g7_19;
  long f3g8_19 = f3*g8_19; long f3g9_38 = f3_2*g9_19;

  long f4g0    = f4*g0   ; long f4g1    = f4  *g1   ;
  long f4g2    = f4*g2   ; long f4g3    = f4  *g3   ;
  long f4g4    = f4*g4   ; long f4g5    = f4  *g5   ;
  long f4g6_19 = f4*g6_19; long f4g7_19 = f4  *g7_19;
  long f4g8_19 = f4*g8_19; long f4g9_19 = f4  *g9_19;

  long f5g0    = f5*g0   ; long f5g1_2  = f5_2*g1   ;
  long f5g2    = f5*g2   ; long f5g3_2  = f5_2*g3   ;
  long f5g4    = f5*g4   ; long f5g5_38 = f5_2*g5_19;
  long f5g6_19 = f5*g6_19; long f5g7_38 = f5_2*g7_19;
  long f5g8_19 = f5*g8_19; long f5g9_38 = f5_2*g9_19;

  long f6g0    = f6*g0   ; long f6g1    = f6  *g1   ;
  long f6g2    = f6*g2   ; long f6g3    = f6  *g3   ;
  long f6g4_19 = f6*g4_19; long f6g5_19 = f6  *g5_19;
  long f6g6_19 = f6*g6_19; long f6g7_19 = f6  *g7_19;
  long f6g8_19 = f6*g8_19; long f6g9_19 = f6  *g9_19;

  long f7g0    = f7*g0   ; long f7g1_2  = f7_2*g1   ;
  long f7g2    = f7*g2   ; long f7g3_38 = f7_2*g3_19;
  long f7g4_19 = f7*g4_19; long f7g5_38 = f7_2*g5_19;
  long f7g6_19 = f7*g6_19; long f7g7_38 = f7_2*g7_19;
  long f7g8_19 = f7*g8_19; long f7g9_38 = f7_2*g9_19;

  long f8g0    = f8*g0   ; long f8g1    = f8  *g1   ;
  long f8g2_19 = f8*g2_19; long f8g3_19 = f8  *g3_19;
  long f8g4_19 = f8*g4_19; long f8g5_19 = f8  *g5_19;
  long f8g6_19 = f8*g6_19; long f8g7_19 = f8  *g7_19;
  long f8g8_19 = f8*g8_19; long f8g9_19 = f8  *g9_19;

  long f9g0    = f9*g0   ; long f9g1_38 = f9_2*g1_19;
  long f9g2_19 = f9*g2_19; long f9g3_38 = f9_2*g3_19;
  long f9g4_19 = f9*g4_19; long f9g5_38 = f9_2*g5_19;
  long f9g6_19 = f9*g6_19; long f9g7_38 = f9_2*g7_19;
  long f9g8_19 = f9*g8_19; long f9g9_38 = f9_2*g9_19;

  long h0 = f0g0 + f1g9_38 + f2g8_19 + f3g7_38 + f4g6_19 + f5g5_38 + f6g4_19 + f7g3_38 + f8g2_19 + f9g1_38;
  long h1 = f0g1 + f1g0    + f2g9_19 + f3g8_19 + f4g7_19 + f5g6_19 + f6g5_19 + f7g4_19 + f8g3_19 + f9g2_19;
  long h2 = f0g2 + f1g1_2  + f2g0    + f3g9_38 + f4g8_19 + f5g7_38 + f6g6_19 + f7g5_38 + f8g4_19 + f9g3_38;
  long h3 = f0g3 + f1g2    + f2g1    + f3g0    + f4g9_19 + f5g8_19 + f6g7_19 + f7g6_19 + f8g5_19 + f9g4_19;
  long h4 = f0g4 + f1g3_2  + f2g2    + f3g1_2  + f4g0    + f5g9_38 + f6g8_19 + f7g7_38 + f8g6_19 + f9g5_38;
  long h5 = f0g5 + f1g4    + f2g3    + f3g2    + f4g1    + f5g0    + f6g9_19 + f7g8_19 + f8g7_19 + f9g6_19;
  long h6 = f0g6 + f1g5_2  + f2g4    + f3g3_2  + f4g2    + f5g1_2  + f6g0    + f7g9_38 + f8g8_19 + f9g7_38;
  long h7 = f0g7 + f1g6    + f2g5    + f3g4    + f4g3    + f5g2    + f6g1    + f7g0    + f8g9_19 + f9g8_19;
  long h8 = f0g8 + f1g7_2  + f2g6    + f3g5_2  + f4g4    + f5g3_2  + f6g2    + f7g1_2  + f8g0    + f9g9_38;
  long h9 = f0g9 + f1g8    + f2g7    + f3g6    + f4g5    + f5g4    + f6g3    + f7g2    + f8g1    + f9g0   ;

  /* |h0| <= (1.65*1.65*2^52*(1+19+19+19+19)+1.65*1.65*2^50*(38+38+38+38+38))
       i.e. |h0| <= 1.4*2^60; narrower ranges for h2, h4, h6, h8
     |h1| <= (1.65*1.65*2^51*(1+1+19+19+19+19+19+19+19+19))
       i.e. |h1| <= 1.7*2^59; narrower ranges for h3, h5, h7, h9 */

  long m38u = (long)FD_MASK_MSB(38);
  long m39u = (long)FD_MASK_MSB(39);

  long carry0 = h0 + (1L << 25); h1 += carry0 >> 26; h0 -= carry0 & m38u;
  long carry4 = h4 + (1L << 25); h5 += carry4 >> 26; h4 -= carry4 & m38u;
  /* |h0| <= 2^25 */
  /* |h4| <= 2^25 */
  /* |h1| <= 1.71*2^59 */
  /* |h5| <= 1.71*2^59 */

  long carry1 = h1 + (1L << 24); h2 += carry1 >> 25; h1 -= carry1 & m39u;
  long carry5 = h5 + (1L << 24); h6 += carry5 >> 25; h5 -= carry5 & m39u;
  /* |h1| <= 2^24; from now on fits into int */
  /* |h5| <= 2^24; from now on fits into int */
  /* |h2| <= 1.41*2^60 */
  /* |h6| <= 1.41*2^60 */

  long carry2 = h2 + (1L << 25); h3 += carry2 >> 26; h2 -= carry2 & m38u;
  long carry6 = h6 + (1L << 25); h7 += carry6 >> 26; h6 -= carry6 & m38u;
  /* |h2| <= 2^25; from now on fits into int unchanged */
  /* |h6| <= 2^25; from now on fits into int unchanged */
  /* |h3| <= 1.71*2^59 */
  /* |h7| <= 1.71*2^59 */

  long carry3 = h3 + (1L << 24); h4 += carry3 >> 25; h3 -= carry3 & m39u;
  long carry7 = h7 + (1L << 24); h8 += carry7 >> 25; h7 -= carry7 & m39u;
  /* |h3| <= 2^24; from now on fits into int unchanged */
  /* |h7| <= 2^24; from now on fits into int unchanged */
  /* |h4| <= 1.72*2^34 */
  /* |h8| <= 1.41*2^60 */

  /**/ carry4 = h4 + (1L << 25); h5 += carry4 >> 26; h4 -= carry4 & m38u;
  long carry8 = h8 + (1L << 25); h9 += carry8 >> 26; h8 -= carry8 & m38u;
  /* |h4| <= 2^25; from now on fits into int unchanged */
  /* |h8| <= 2^25; from now on fits into int unchanged */
  /* |h5| <= 1.01*2^24 */
  /* |h9| <= 1.71*2^59 */

  long carry9 = h9 + (1L << 24); h0 += (carry9 >> 25)*19L; h9 -= carry9 & m39u;
  /* |h9| <= 2^24; from now on fits into int unchanged */
  /* |h0| <= 1.1*2^39 */

  /**/ carry0 = h0 + (1L << 25); h1 += carry0 >> 26; h0 -= carry0 & m38u;
  /* |h0| <= 2^25; from now on fits into int unchanged */
  /* |h1| <= 1.01*2^24 */

  h->limb[0] = (int)h0; h->limb[1] = (int)h1;
  h->limb[2] = (int)h2; h->limb[3] = (int)h3;
  h->limb[4] = (int)h4; h->limb[5] = (int)h5;
  h->limb[6] = (int)h6; h->limb[7] = (int)h7;
  h->limb[8] = (int)h8; h->limb[9] = (int)h9;
  return h;
}

fd_ed25519_fe_t *
fd_ed25519_fe_sq( fd_ed25519_fe_t *       h,
                  fd_ed25519_fe_t const * f ) {

  /* See fd_ed25519_fe_mul for discussion of implementation strategy. */

  long f0 = f->limb[0]; long f1 = f->limb[1];
  long f2 = f->limb[2]; long f3 = f->limb[3];
  long f4 = f->limb[4]; long f5 = f->limb[5];
  long f6 = f->limb[6]; long f7 = f->limb[7];
  long f8 = f->limb[8]; long f9 = f->limb[9];

  long f0_2 = 2L*f0; long f1_2 = 2L*f1;
  long f2_2 = 2L*f2; long f3_2 = 2L*f3;
  long f4_2 = 2L*f4; long f5_2 = 2L*f5;
  long f6_2 = 2L*f6; long f7_2 = 2L*f7;

  long f5_38 = 38L*f5; /* 1.959375*2^30 */ long f6_19 = 19L*f6; /* 1.959375*2^30 */
  long f7_38 = 38L*f7; /* 1.959375*2^30 */ long f8_19 = 19L*f8; /* 1.959375*2^30 */
  long f9_38 = 38L*f9; /* 1.959375*2^30 */

  long f0f0    = f0  *f0   ; long f0f1_2  = f0_2*f1   ;
  long f0f2_2  = f0_2*f2   ; long f0f3_2  = f0_2*f3   ;
  long f0f4_2  = f0_2*f4   ; long f0f5_2  = f0_2*f5   ;
  long f0f6_2  = f0_2*f6   ; long f0f7_2  = f0_2*f7   ;
  long f0f8_2  = f0_2*f8   ; long f0f9_2  = f0_2*f9   ;

  long f1f1_2  = f1_2*f1   ; long f1f2_2  = f1_2*f2   ;
  long f1f3_4  = f1_2*f3_2 ; long f1f4_2  = f1_2*f4   ;
  long f1f5_4  = f1_2*f5_2 ; long f1f6_2  = f1_2*f6   ;
  long f1f7_4  = f1_2*f7_2 ; long f1f8_2  = f1_2*f8   ;
  long f1f9_76 = f1_2*f9_38; 

  long f2f2    = f2  *f2   ; long f2f3_2  = f2_2*f3   ;
  long f2f4_2  = f2_2*f4   ; long f2f5_2  = f2_2*f5   ;
  long f2f6_2  = f2_2*f6   ; long f2f7_2  = f2_2*f7   ;
  long f2f8_38 = f2_2*f8_19; long f2f9_38 = f2  *f9_38;

  long f3f3_2  = f3_2*f3   ; long f3f4_2  = f3_2*f4   ;
  long f3f5_4  = f3_2*f5_2 ; long f3f6_2  = f3_2*f6   ;
  long f3f7_76 = f3_2*f7_38; long f3f8_38 = f3_2*f8_19;
  long f3f9_76 = f3_2*f9_38;

  long f4f4    = f4  *f4   ; long f4f5_2  = f4_2*f5   ;
  long f4f6_38 = f4_2*f6_19; long f4f7_38 = f4  *f7_38;
  long f4f8_38 = f4_2*f8_19; long f4f9_38 = f4  *f9_38;

  long f5f5_38 = f5  *f5_38; long f5f6_38 = f5_2*f6_19;
  long f5f7_76 = f5_2*f7_38; long f5f8_38 = f5_2*f8_19;
  long f5f9_76 = f5_2*f9_38;

  long f6f6_19 = f6  *f6_19; long f6f7_38 = f6  *f7_38;
  long f6f8_38 = f6_2*f8_19; long f6f9_38 = f6  *f9_38;

  long f7f7_38 = f7  *f7_38; long f7f8_38 = f7_2*f8_19;
  long f7f9_76 = f7_2*f9_38;

  long f8f8_19 = f8  *f8_19; long f8f9_38 = f8  *f9_38;

  long f9f9_38 = f9  *f9_38;

  long h0 = f0f0   + f1f9_76 + f2f8_38 + f3f7_76 + f4f6_38 + f5f5_38;
  long h1 = f0f1_2 + f2f9_38 + f3f8_38 + f4f7_38 + f5f6_38;
  long h2 = f0f2_2 + f1f1_2  + f3f9_76 + f4f8_38 + f5f7_76 + f6f6_19;
  long h3 = f0f3_2 + f1f2_2  + f4f9_38 + f5f8_38 + f6f7_38;
  long h4 = f0f4_2 + f1f3_4  + f2f2    + f5f9_76 + f6f8_38 + f7f7_38;
  long h5 = f0f5_2 + f1f4_2  + f2f3_2  + f6f9_38 + f7f8_38;
  long h6 = f0f6_2 + f1f5_4  + f2f4_2  + f3f3_2  + f7f9_76 + f8f8_19;
  long h7 = f0f7_2 + f1f6_2  + f2f5_2  + f3f4_2  + f8f9_38;
  long h8 = f0f8_2 + f1f7_4  + f2f6_2  + f3f5_4  + f4f4    + f9f9_38;
  long h9 = f0f9_2 + f1f8_2  + f2f7_2  + f3f6_2  + f4f5_2;

  long m38u = (long)FD_MASK_MSB(38);
  long m39u = (long)FD_MASK_MSB(39);

  long carry0 = h0 + (1 << 25); h1 +=  carry0 >> 26;      h0 -= carry0 & m38u;
  long carry4 = h4 + (1 << 25); h5 +=  carry4 >> 26;      h4 -= carry4 & m38u;

  long carry1 = h1 + (1 << 24); h2 +=  carry1 >> 25;      h1 -= carry1 & m39u;
  long carry5 = h5 + (1 << 24); h6 +=  carry5 >> 25;      h5 -= carry5 & m39u;

  long carry2 = h2 + (1 << 25); h3 +=  carry2 >> 26;      h2 -= carry2 & m38u;
  long carry6 = h6 + (1 << 25); h7 +=  carry6 >> 26;      h6 -= carry6 & m38u;

  long carry3 = h3 + (1 << 24); h4 +=  carry3 >> 25;      h3 -= carry3 & m39u;
  long carry7 = h7 + (1 << 24); h8 +=  carry7 >> 25;      h7 -= carry7 & m39u;

  /**/ carry4 = h4 + (1 << 25); h5 +=  carry4 >> 26;      h4 -= carry4 & m38u;
  long carry8 = h8 + (1 << 25); h9 +=  carry8 >> 26;      h8 -= carry8 & m38u;

  long carry9 = h9 + (1 << 24); h0 += (carry9 >> 25)*19L; h9 -= carry9 & m39u;

  /**/ carry0 = h0 + (1 << 25); h1 +=  carry0 >> 26;      h0 -= carry0 & m38u;

  h->limb[0] = (int)h0; h->limb[1] = (int)h1;
  h->limb[2] = (int)h2; h->limb[3] = (int)h3;
  h->limb[4] = (int)h4; h->limb[5] = (int)h5;
  h->limb[6] = (int)h6; h->limb[7] = (int)h7;
  h->limb[8] = (int)h8; h->limb[9] = (int)h9;
  return h;
}

fd_ed25519_fe_t *
fd_ed25519_fe_sq2( fd_ed25519_fe_t *       h,
                   fd_ed25519_fe_t const * f ) {

  /* See fd_ed25519_fe_mul for discussion of implementation strategy. */

  long f0 = f->limb[0]; long f1 = f->limb[1];
  long f2 = f->limb[2]; long f3 = f->limb[3];
  long f4 = f->limb[4]; long f5 = f->limb[5];
  long f6 = f->limb[6]; long f7 = f->limb[7];
  long f8 = f->limb[8]; long f9 = f->limb[9];

  long f0_2  = 2L*f0; long f1_2 = 2L*f1;
  long f2_2  = 2L*f2; long f3_2 = 2L*f3;
  long f4_2  = 2L*f4; long f5_2 = 2L*f5;
  long f6_2  = 2L*f6; long f7_2 = 2L*f7;

  long f5_38 = 38L*f5; /* 1.959375*2^30 */ long f6_19 = 19L*f6; /* 1.959375*2^30 */
  long f7_38 = 38L*f7; /* 1.959375*2^30 */ long f8_19 = 19L*f8; /* 1.959375*2^30 */
  long f9_38 = 38L*f9; /* 1.959375*2^30 */

  long f0f0    = ((long)f0  )*((long)f0   ); long f0f1_2  = ((long)f0_2)*((long)f1   );
  long f0f2_2  = ((long)f0_2)*((long)f2   ); long f0f3_2  = ((long)f0_2)*((long)f3   );
  long f0f4_2  = ((long)f0_2)*((long)f4   ); long f0f5_2  = ((long)f0_2)*((long)f5   );
  long f0f6_2  = ((long)f0_2)*((long)f6   ); long f0f7_2  = ((long)f0_2)*((long)f7   );
  long f0f8_2  = ((long)f0_2)*((long)f8   ); long f0f9_2  = ((long)f0_2)*((long)f9   );

  long f1f1_2  = ((long)f1_2)*((long)f1   ); long f1f2_2  = ((long)f1_2)*((long)f2   );
  long f1f3_4  = ((long)f1_2)*((long)f3_2 ); long f1f4_2  = ((long)f1_2)*((long)f4   );
  long f1f5_4  = ((long)f1_2)*((long)f5_2 ); long f1f6_2  = ((long)f1_2)*((long)f6   );
  long f1f7_4  = ((long)f1_2)*((long)f7_2 ); long f1f8_2  = ((long)f1_2)*((long)f8   );
  long f1f9_76 = ((long)f1_2)*((long)f9_38);

  long f2f2    = ((long)f2  )*((long)f2   ); long f2f3_2  = ((long)f2_2)*((long)f3   );
  long f2f4_2  = ((long)f2_2)*((long)f4   ); long f2f5_2  = ((long)f2_2)*((long)f5   );
  long f2f6_2  = ((long)f2_2)*((long)f6   ); long f2f7_2  = ((long)f2_2)*((long)f7   );
  long f2f8_38 = ((long)f2_2)*((long)f8_19); long f2f9_38 = ((long)f2  )*((long)f9_38);

  long f3f3_2  = ((long)f3_2)*((long)f3   ); long f3f4_2  = ((long)f3_2)*((long)f4   );
  long f3f5_4  = ((long)f3_2)*((long)f5_2 ); long f3f6_2  = ((long)f3_2)*((long)f6   );
  long f3f7_76 = ((long)f3_2)*((long)f7_38); long f3f8_38 = ((long)f3_2)*((long)f8_19);
  long f3f9_76 = ((long)f3_2)*((long)f9_38);

  long f4f4    = ((long)f4  )*((long)f4   ); long f4f5_2  = ((long)f4_2)*((long)f5   );
  long f4f6_38 = ((long)f4_2)*((long)f6_19); long f4f7_38 = ((long)f4  )*((long)f7_38);
  long f4f8_38 = ((long)f4_2)*((long)f8_19); long f4f9_38 = ((long)f4  )*((long)f9_38);

  long f5f5_38 = ((long)f5  )*((long)f5_38); long f5f6_38 = ((long)f5_2)*((long)f6_19);
  long f5f7_76 = ((long)f5_2)*((long)f7_38); long f5f8_38 = ((long)f5_2)*((long)f8_19);
  long f5f9_76 = ((long)f5_2)*((long)f9_38);

  long f6f6_19 = ((long)f6  )*((long)f6_19); long f6f7_38 = ((long)f6  )*((long)f7_38);
  long f6f8_38 = ((long)f6_2)*((long)f8_19); long f6f9_38 = ((long)f6  )*((long)f9_38);

  long f7f7_38 = ((long)f7  )*((long)f7_38); long f7f8_38 = ((long)f7_2)*((long)f8_19);
  long f7f9_76 = ((long)f7_2)*((long)f9_38);

  long f8f8_19 = ((long)f8  )*((long)f8_19); long f8f9_38 = ((long)f8  )*((long)f9_38);

  long f9f9_38 = ((long)f9  )*((long)f9_38);

  long h0 = f0f0   + f1f9_76 + f2f8_38 + f3f7_76 + f4f6_38 + f5f5_38; h0 += h0;
  long h1 = f0f1_2 + f2f9_38 + f3f8_38 + f4f7_38 + f5f6_38;           h1 += h1;
  long h2 = f0f2_2 + f1f1_2  + f3f9_76 + f4f8_38 + f5f7_76 + f6f6_19; h2 += h2;
  long h3 = f0f3_2 + f1f2_2  + f4f9_38 + f5f8_38 + f6f7_38;           h3 += h3;
  long h4 = f0f4_2 + f1f3_4  + f2f2    + f5f9_76 + f6f8_38 + f7f7_38; h4 += h4;
  long h5 = f0f5_2 + f1f4_2  + f2f3_2  + f6f9_38 + f7f8_38;           h5 += h5;
  long h6 = f0f6_2 + f1f5_4  + f2f4_2  + f3f3_2  + f7f9_76 + f8f8_19; h6 += h6;
  long h7 = f0f7_2 + f1f6_2  + f2f5_2  + f3f4_2  + f8f9_38;           h7 += h7;
  long h8 = f0f8_2 + f1f7_4  + f2f6_2  + f3f5_4  + f4f4    + f9f9_38; h8 += h8;
  long h9 = f0f9_2 + f1f8_2  + f2f7_2  + f3f6_2  + f4f5_2;            h9 += h9;

  long m38u = (long)FD_MASK_MSB(38);
  long m39u = (long)FD_MASK_MSB(39);

  long carry0 = h0 + (1 << 25); h1 +=  carry0 >> 26;      h0 -= carry0 & m38u;
  long carry4 = h4 + (1 << 25); h5 +=  carry4 >> 26;      h4 -= carry4 & m38u;

  long carry1 = h1 + (1 << 24); h2 +=  carry1 >> 25;      h1 -= carry1 & m39u;
  long carry5 = h5 + (1 << 24); h6 +=  carry5 >> 25;      h5 -= carry5 & m39u;

  long carry2 = h2 + (1 << 25); h3 +=  carry2 >> 26;      h2 -= carry2 & m38u;
  long carry6 = h6 + (1 << 25); h7 +=  carry6 >> 26;      h6 -= carry6 & m38u;

  long carry3 = h3 + (1 << 24); h4 +=  carry3 >> 25;      h3 -= carry3 & m39u;
  long carry7 = h7 + (1 << 24); h8 +=  carry7 >> 25;      h7 -= carry7 & m39u;

  /**/ carry4 = h4 + (1 << 25); h5 +=  carry4 >> 26;      h4 -= carry4 & m38u;
  long carry8 = h8 + (1 << 25); h9 +=  carry8 >> 26;      h8 -= carry8 & m38u;

  long carry9 = h9 + (1 << 24); h0 += (carry9 >> 25)*19L; h9 -= carry9 & m39u;

  /**/ carry0 = h0 + (1 << 25); h1 +=  carry0 >> 26;      h0 -= carry0 & m38u;

  h->limb[0] = (int)h0; h->limb[1] = (int)h1;
  h->limb[2] = (int)h2; h->limb[3] = (int)h3;
  h->limb[4] = (int)h4; h->limb[5] = (int)h5;
  h->limb[6] = (int)h6; h->limb[7] = (int)h7;
  h->limb[8] = (int)h8; h->limb[9] = (int)h9;
  return h;
}

fd_ed25519_fe_t *
fd_ed25519_fe_invert( fd_ed25519_fe_t * out,
                      fd_ed25519_fe_t const * z ) {
  fd_ed25519_fe_t t0[1];
  fd_ed25519_fe_t t1[1];
  fd_ed25519_fe_t t2[1];
  fd_ed25519_fe_t t3[1];

  /* Compute z**-1 = z**(2**255 - 19 - 2) with the exponent as
     2**255 - 21 = (2**5) * (2**250 - 1) + 11. */

  fd_ed25519_fe_sq ( t0,  z     );                       /* t0 = z**2 */
  fd_ed25519_fe_sq ( t1, t0     );
  fd_ed25519_fe_sq ( t1, t1     );                       /* t1 = t0**(2**2) = z**8 */
  fd_ed25519_fe_mul( t1,  z, t1 );                       /* t1 = z * t1 = z**9 */
  fd_ed25519_fe_mul( t0, t0, t1 );                       /* t0 = t0 * t1 = z**11 -- stash t0 away for the end. */
  fd_ed25519_fe_sq ( t2, t0     );                       /* t2 = t0**2 = z**22 */
  fd_ed25519_fe_mul( t1, t1, t2 );                       /* t1 = t1 * t2 = z**(2**5 - 1) */
  fd_ed25519_fe_sq ( t2, t1     );
  for( int i=1; i<  5; i++ ) fd_ed25519_fe_sq( t2, t2 ); /* t2 = t1**(2**5) = z**((2**5) * (2**5 - 1)) */
  fd_ed25519_fe_mul( t1, t2, t1 );                       /* t1 = t1 * t2 = z**((2**5 + 1) * (2**5 - 1)) = z**(2**10 - 1) */
  fd_ed25519_fe_sq ( t2, t1     );
  for( int i=1; i< 10; i++ ) fd_ed25519_fe_sq( t2, t2 );
  fd_ed25519_fe_mul( t2, t2, t1 );                       /* t2 = z**(2**20 - 1) */
  fd_ed25519_fe_sq ( t3, t2     );
  for( int i=1; i< 20; i++ ) fd_ed25519_fe_sq( t3, t3 );
  fd_ed25519_fe_mul( t2, t3, t2 );                       /* t2 = z**(2**40 - 1) */
  for( int i=0; i< 10; i++ ) fd_ed25519_fe_sq( t2, t2 ); /* t2 = z**(2**10) * (2**40 - 1) */
  fd_ed25519_fe_mul( t1, t2, t1 );                       /* t1 = z**(2**50 - 1) */
  fd_ed25519_fe_sq ( t2, t1     );
  for( int i=1; i< 50; i++ ) fd_ed25519_fe_sq( t2, t2 );
  fd_ed25519_fe_mul( t2, t2, t1 );                       /* t2 = z**(2**100 - 1) */
  fd_ed25519_fe_sq ( t3, t2     );
  for( int i=1; i<100; i++ ) fd_ed25519_fe_sq( t3, t3 );
  fd_ed25519_fe_mul( t2, t3, t2 );                       /* t2 = z**(2**200 - 1) */
  fd_ed25519_fe_sq ( t2, t2     );
  for( int i=1; i< 50; i++ ) fd_ed25519_fe_sq( t2, t2 ); /* t2 = z**((2**50) * (2**200 - 1) */
  fd_ed25519_fe_mul( t1, t2, t1 );                       /* t1 = z**(2**250 - 1) */
  fd_ed25519_fe_sq ( t1, t1     );
  for( int i=1; i<  5; i++ ) fd_ed25519_fe_sq( t1, t1 ); /* t1 = z**((2**5) * (2**250 - 1)) */
  return fd_ed25519_fe_mul( out, t1, t0 );               /* Recall t0 = z**11; out = z**(2**255 - 21) */
}

fd_ed25519_fe_t *
fd_ed25519_fe_pow22523( fd_ed25519_fe_t *       out,
                        fd_ed25519_fe_t const * z ) {
  fd_ed25519_fe_t t0[1];
  fd_ed25519_fe_t t1[1];
  fd_ed25519_fe_t t2[1];

  fd_ed25519_fe_sq ( t0, z      );
  fd_ed25519_fe_sq ( t1, t0     );
  for( int i=1; i<  2; i++ ) fd_ed25519_fe_sq( t1, t1 );

  fd_ed25519_fe_mul( t1, z,  t1 );
  fd_ed25519_fe_mul( t0, t0, t1 );
  fd_ed25519_fe_sq ( t0, t0     );
  fd_ed25519_fe_mul( t0, t1, t0 );
  fd_ed25519_fe_sq ( t1, t0     );
  for( int i=1; i<  5; i++ ) fd_ed25519_fe_sq( t1, t1 );

  fd_ed25519_fe_mul( t0, t1, t0 );
  fd_ed25519_fe_sq ( t1, t0     );
  for( int i=1; i< 10; i++ ) fd_ed25519_fe_sq( t1, t1 );

  fd_ed25519_fe_mul( t1, t1, t0 );
  fd_ed25519_fe_sq ( t2, t1     );
  for( int i=1; i< 20; i++ ) fd_ed25519_fe_sq( t2, t2 );

  fd_ed25519_fe_mul( t1, t2, t1 );
  fd_ed25519_fe_sq ( t1, t1     );
  for( int i=1; i< 10; i++ ) fd_ed25519_fe_sq( t1, t1 );

  fd_ed25519_fe_mul( t0, t1, t0 );
  fd_ed25519_fe_sq ( t1, t0     );
  for( int i=1; i< 50; i++ ) fd_ed25519_fe_sq( t1, t1 );

  fd_ed25519_fe_mul( t1, t1, t0 );
  fd_ed25519_fe_sq ( t2, t1     );
  for( int i=1; i<100; i++ ) fd_ed25519_fe_sq( t2, t2 );

  fd_ed25519_fe_mul( t1, t2, t1 );
  fd_ed25519_fe_sq ( t1, t1     );
  for( int i=1; i< 50; i++ ) fd_ed25519_fe_sq( t1, t1 );

  fd_ed25519_fe_mul( t0, t1, t0 );
  fd_ed25519_fe_sq ( t0, t0     );
  for( int i=1; i<  2; i++ ) fd_ed25519_fe_sq( t0, t0 );

  fd_ed25519_fe_mul(out, t0, z  );
  return out;
}

static inline wl_t wl_shr_scale( wl_t x, int n, long scale ) {
  long l[4] __attribute__((aligned(32)));
  wl_st( l, x );
  l[0] = (l[0] >> n)*scale;
  l[1] = (l[1] >> n)*scale;
  l[2] = (l[2] >> n)*scale;
  l[3] = (l[3] >> n)*scale;
  return wl_ld( l );
}

void
fd_ed25519_fe_vmul( fd_ed25519_fe_t * ha, fd_ed25519_fe_t const * fa, fd_ed25519_fe_t const * ga,
                    fd_ed25519_fe_t * hb, fd_ed25519_fe_t const * fb, fd_ed25519_fe_t const * gb,
                    fd_ed25519_fe_t * hc, fd_ed25519_fe_t const * fc, fd_ed25519_fe_t const * gc,
                    fd_ed25519_fe_t * hd, fd_ed25519_fe_t const * fd, fd_ed25519_fe_t const * gd ) {
  wl_t f0; wl_t f1; wl_t f2; wl_t f3; wl_t f4; wl_t f5; wl_t f6; wl_t f7; wl_t f8; wl_t f9;
  SWIZZLE_IN( f0,f1,f2,f3,f4,f5,f6,f7,f8,f9, fa,fb,fc,fd );

  wl_t g0; wl_t g1; wl_t g2; wl_t g3; wl_t g4; wl_t g5; wl_t g6; wl_t g7; wl_t g8; wl_t g9;
  SWIZZLE_IN( g0,g1,g2,g3,g4,g5,g6,g7,g8,g9, ga,gb,gc,gd );

  wl_t _19     = wl_bcast( 19L );

  wl_t g1_19   = wl_mul_ll( _19, g1 );
  wl_t g2_19   = wl_mul_ll( _19, g2 );
  wl_t g3_19   = wl_mul_ll( _19, g3 );
  wl_t g4_19   = wl_mul_ll( _19, g4 );
  wl_t g5_19   = wl_mul_ll( _19, g5 );
  wl_t g6_19   = wl_mul_ll( _19, g6 );
  wl_t g7_19   = wl_mul_ll( _19, g7 );
  wl_t g8_19   = wl_mul_ll( _19, g8 );
  wl_t g9_19   = wl_mul_ll( _19, g9 );

  wl_t f1_2    = wl_add( f1, f1 );
  wl_t f3_2    = wl_add( f3, f3 );
  wl_t f5_2    = wl_add( f5, f5 );
  wl_t f7_2    = wl_add( f7, f7 );
  wl_t f9_2    = wl_add( f9, f9 );

  wl_t f0g0    = wl_mul_ll( f0, g0    ); wl_t f0g1    = wl_mul_ll( f0,   g1    );
  wl_t f0g2    = wl_mul_ll( f0, g2    ); wl_t f0g3    = wl_mul_ll( f0,   g3    );
  wl_t f0g4    = wl_mul_ll( f0, g4    ); wl_t f0g5    = wl_mul_ll( f0,   g5    );
  wl_t f0g6    = wl_mul_ll( f0, g6    ); wl_t f0g7    = wl_mul_ll( f0,   g7    );
  wl_t f0g8    = wl_mul_ll( f0, g8    ); wl_t f0g9    = wl_mul_ll( f0,   g9    );

  wl_t f1g0    = wl_mul_ll( f1, g0    ); wl_t f1g1_2  = wl_mul_ll( f1_2, g1    );
  wl_t f1g2    = wl_mul_ll( f1, g2    ); wl_t f1g3_2  = wl_mul_ll( f1_2, g3    );
  wl_t f1g4    = wl_mul_ll( f1, g4    ); wl_t f1g5_2  = wl_mul_ll( f1_2, g5    );
  wl_t f1g6    = wl_mul_ll( f1, g6    ); wl_t f1g7_2  = wl_mul_ll( f1_2, g7    );
  wl_t f1g8    = wl_mul_ll( f1, g8    ); wl_t f1g9_38 = wl_mul_ll( f1_2, g9_19 );

  wl_t f2g0    = wl_mul_ll( f2, g0    ); wl_t f2g1    = wl_mul_ll( f2,   g1    );
  wl_t f2g2    = wl_mul_ll( f2, g2    ); wl_t f2g3    = wl_mul_ll( f2,   g3    );
  wl_t f2g4    = wl_mul_ll( f2, g4    ); wl_t f2g5    = wl_mul_ll( f2,   g5    );
  wl_t f2g6    = wl_mul_ll( f2, g6    ); wl_t f2g7    = wl_mul_ll( f2,   g7    );
  wl_t f2g8_19 = wl_mul_ll( f2, g8_19 ); wl_t f2g9_19 = wl_mul_ll( f2,   g9_19 );

  wl_t f3g0    = wl_mul_ll( f3, g0    ); wl_t f3g1_2  = wl_mul_ll( f3_2, g1    );
  wl_t f3g2    = wl_mul_ll( f3, g2    ); wl_t f3g3_2  = wl_mul_ll( f3_2, g3    );
  wl_t f3g4    = wl_mul_ll( f3, g4    ); wl_t f3g5_2  = wl_mul_ll( f3_2, g5    );
  wl_t f3g6    = wl_mul_ll( f3, g6    ); wl_t f3g7_38 = wl_mul_ll( f3_2, g7_19 );
  wl_t f3g8_19 = wl_mul_ll( f3, g8_19 ); wl_t f3g9_38 = wl_mul_ll( f3_2, g9_19 );

  wl_t f4g0    = wl_mul_ll( f4, g0    ); wl_t f4g1    = wl_mul_ll( f4,   g1    );
  wl_t f4g2    = wl_mul_ll( f4, g2    ); wl_t f4g3    = wl_mul_ll( f4,   g3    );
  wl_t f4g4    = wl_mul_ll( f4, g4    ); wl_t f4g5    = wl_mul_ll( f4,   g5    );
  wl_t f4g6_19 = wl_mul_ll( f4, g6_19 ); wl_t f4g7_19 = wl_mul_ll( f4,   g7_19 );
  wl_t f4g8_19 = wl_mul_ll( f4, g8_19 ); wl_t f4g9_19 = wl_mul_ll( f4,   g9_19 );

  wl_t f5g0    = wl_mul_ll( f5, g0    ); wl_t f5g1_2  = wl_mul_ll( f5_2, g1    );
  wl_t f5g2    = wl_mul_ll( f5, g2    ); wl_t f5g3_2  = wl_mul_ll( f5_2, g3    );
  wl_t f5g4    = wl_mul_ll( f5, g4    ); wl_t f5g5_38 = wl_mul_ll( f5_2, g5_19 );
  wl_t f5g6_19 = wl_mul_ll( f5, g6_19 ); wl_t f5g7_38 = wl_mul_ll( f5_2, g7_19 );
  wl_t f5g8_19 = wl_mul_ll( f5, g8_19 ); wl_t f5g9_38 = wl_mul_ll( f5_2, g9_19 );

  wl_t f6g0    = wl_mul_ll( f6, g0    ); wl_t f6g1    = wl_mul_ll( f6,   g1    );
  wl_t f6g2    = wl_mul_ll( f6, g2    ); wl_t f6g3    = wl_mul_ll( f6,   g3    );
  wl_t f6g4_19 = wl_mul_ll( f6, g4_19 ); wl_t f6g5_19 = wl_mul_ll( f6,   g5_19 );
  wl_t f6g6_19 = wl_mul_ll( f6, g6_19 ); wl_t f6g7_19 = wl_mul_ll( f6,   g7_19 );
  wl_t f6g8_19 = wl_mul_ll( f6, g8_19 ); wl_t f6g9_19 = wl_mul_ll( f6,   g9_19 );

  wl_t f7g0    = wl_mul_ll( f7, g0    ); wl_t f7g1_2  = wl_mul_ll( f7_2, g1    );
  wl_t f7g2    = wl_mul_ll( f7, g2    ); wl_t f7g3_38 = wl_mul_ll( f7_2, g3_19 );
  wl_t f7g4_19 = wl_mul_ll( f7, g4_19 ); wl_t f7g5_38 = wl_mul_ll( f7_2, g5_19 );
  wl_t f7g6_19 = wl_mul_ll( f7, g6_19 ); wl_t f7g7_38 = wl_mul_ll( f7_2, g7_19 );
  wl_t f7g8_19 = wl_mul_ll( f7, g8_19 ); wl_t f7g9_38 = wl_mul_ll( f7_2, g9_19 );

  wl_t f8g0    = wl_mul_ll( f8, g0    ); wl_t f8g1    = wl_mul_ll( f8,   g1    );
  wl_t f8g2_19 = wl_mul_ll( f8, g2_19 ); wl_t f8g3_19 = wl_mul_ll( f8,   g3_19 );
  wl_t f8g4_19 = wl_mul_ll( f8, g4_19 ); wl_t f8g5_19 = wl_mul_ll( f8,   g5_19 );
  wl_t f8g6_19 = wl_mul_ll( f8, g6_19 ); wl_t f8g7_19 = wl_mul_ll( f8,   g7_19 );
  wl_t f8g8_19 = wl_mul_ll( f8, g8_19 ); wl_t f8g9_19 = wl_mul_ll( f8,   g9_19 );

  wl_t f9g0    = wl_mul_ll( f9, g0    ); wl_t f9g1_38 = wl_mul_ll( f9_2, g1_19 );
  wl_t f9g2_19 = wl_mul_ll( f9, g2_19 ); wl_t f9g3_38 = wl_mul_ll( f9_2, g3_19 );
  wl_t f9g4_19 = wl_mul_ll( f9, g4_19 ); wl_t f9g5_38 = wl_mul_ll( f9_2, g5_19 );
  wl_t f9g6_19 = wl_mul_ll( f9, g6_19 ); wl_t f9g7_38 = wl_mul_ll( f9_2, g7_19 );
  wl_t f9g8_19 = wl_mul_ll( f9, g8_19 ); wl_t f9g9_38 = wl_mul_ll( f9_2, g9_19 );

  wl_t h0      = REDUCE_10( f0g0, f1g9_38, f2g8_19, f3g7_38, f4g6_19, f5g5_38, f6g4_19, f7g3_38, f8g2_19, f9g1_38 );
  wl_t h1      = REDUCE_10( f0g1, f1g0   , f2g9_19, f3g8_19, f4g7_19, f5g6_19, f6g5_19, f7g4_19, f8g3_19, f9g2_19 );
  wl_t h2      = REDUCE_10( f0g2, f1g1_2 , f2g0   , f3g9_38, f4g8_19, f5g7_38, f6g6_19, f7g5_38, f8g4_19, f9g3_38 );
  wl_t h3      = REDUCE_10( f0g3, f1g2   , f2g1   , f3g0   , f4g9_19, f5g8_19, f6g7_19, f7g6_19, f8g5_19, f9g4_19 );
  wl_t h4      = REDUCE_10( f0g4, f1g3_2 , f2g2   , f3g1_2 , f4g0   , f5g9_38, f6g8_19, f7g7_38, f8g6_19, f9g5_38 );
  wl_t h5      = REDUCE_10( f0g5, f1g4   , f2g3   , f3g2   , f4g1   , f5g0   , f6g9_19, f7g8_19, f8g7_19, f9g6_19 );
  wl_t h6      = REDUCE_10( f0g6, f1g5_2 , f2g4   , f3g3_2 , f4g2   , f5g1_2 , f6g0   , f7g9_38, f8g8_19, f9g7_38 );
  wl_t h7      = REDUCE_10( f0g7, f1g6   , f2g5   , f3g4   , f4g3   , f5g2   , f6g1   , f7g0   , f8g9_19, f9g8_19 );
  wl_t h8      = REDUCE_10( f0g8, f1g7_2 , f2g6   , f3g5_2 , f4g4   , f5g3_2 , f6g2   , f7g1_2 , f8g0   , f9g9_38 );
  wl_t h9      = REDUCE_10( f0g9, f1g8   , f2g7   , f3g6   , f4g5   , f5g4   , f6g3   , f7g2   , f8g1   , f9g0    );

  wl_t m38u    = wl_bcast( (long)FD_MASK_MSB(38) );
  wl_t m39u    = wl_bcast( (long)FD_MASK_MSB(39) );
  wl_t b24     = wl_bcast( 1L << 24 );
  wl_t b25     = wl_bcast( 1L << 25 );

  wl_t carry0 = wl_add( h0, b25 ); h1 = wl_add( h1, wl_shr      ( carry0, 26 ) );      h0 = wl_sub( h0, wl_and( carry0, m38u ) );
  wl_t carry4 = wl_add( h4, b25 ); h5 = wl_add( h5, wl_shr      ( carry4, 26 ) );      h4 = wl_sub( h4, wl_and( carry4, m38u ) );
  wl_t carry1 = wl_add( h1, b24 ); h2 = wl_add( h2, wl_shr      ( carry1, 25 ) );      h1 = wl_sub( h1, wl_and( carry1, m39u ) );
  wl_t carry5 = wl_add( h5, b24 ); h6 = wl_add( h6, wl_shr      ( carry5, 25 ) );      h5 = wl_sub( h5, wl_and( carry5, m39u ) );
  wl_t carry2 = wl_add( h2, b25 ); h3 = wl_add( h3, wl_shr      ( carry2, 26 ) );      h2 = wl_sub( h2, wl_and( carry2, m38u ) );
  wl_t carry6 = wl_add( h6, b25 ); h7 = wl_add( h7, wl_shr      ( carry6, 26 ) );      h6 = wl_sub( h6, wl_and( carry6, m38u ) );
  wl_t carry3 = wl_add( h3, b24 ); h4 = wl_add( h4, wl_shr      ( carry3, 25 ) );      h3 = wl_sub( h3, wl_and( carry3, m39u ) );
  wl_t carry7 = wl_add( h7, b24 ); h8 = wl_add( h8, wl_shr      ( carry7, 25 ) );      h7 = wl_sub( h7, wl_and( carry7, m39u ) );
  /**/ carry4 = wl_add( h4, b25 ); h5 = wl_add( h5, wl_shr      ( carry4, 26 ) );      h4 = wl_sub( h4, wl_and( carry4, m38u ) );
  wl_t carry8 = wl_add( h8, b25 ); h9 = wl_add( h9, wl_shr      ( carry8, 26 ) );      h8 = wl_sub( h8, wl_and( carry8, m38u ) );
  wl_t carry9 = wl_add( h9, b24 ); h0 = wl_add( h0, wl_shr_scale( carry9, 25, 19L ) ); h9 = wl_sub( h9, wl_and( carry9, m39u ) );
  /**/ carry0 = wl_add( h0, b25 ); h1 = wl_add( h1, wl_shr      ( carry0, 26 ) );      h0 = wl_sub( h0, wl_and( carry0, m38u ) );

  SWIZZLE_OUT( ha,hb,hc,hd, h0,h1,h2,h3,h4,h5,h6,h7,h8,h9 );
}

void
fd_ed25519_fe_vsqn( fd_ed25519_fe_t * ha, fd_ed25519_fe_t const * fa, long na,
                    fd_ed25519_fe_t * hb, fd_ed25519_fe_t const * fb, long nb,
                    fd_ed25519_fe_t * hc, fd_ed25519_fe_t const * fc, long nc,
                    fd_ed25519_fe_t * hd, fd_ed25519_fe_t const * fd, long nd ) {

  wl_t f0; wl_t f1; wl_t f2; wl_t f3; wl_t f4; wl_t f5; wl_t f6; wl_t f7; wl_t f8; wl_t f9;
  SWIZZLE_IN( f0,f1,f2,f3,f4,f5,f6,f7,f8,f9, fa,fb,fc,fd );

  wl_t f0_2  = wl_add( f0, f0 );     wl_t f1_2  = wl_add( f1, f1 );
  wl_t f2_2  = wl_add( f2, f2 );     wl_t f3_2  = wl_add( f3, f3 );
  wl_t f4_2  = wl_add( f4, f4 );     wl_t f5_2  = wl_add( f5, f5 );
  wl_t f6_2  = wl_add( f6, f6 );     wl_t f7_2  = wl_add( f7, f7 );

  wl_t _38   = wl_bcast( 38L );      wl_t _19   = wl_bcast( 19L );

  wl_t f5_38 = wl_mul_ll( _38, f5 ); wl_t f6_19 = wl_mul_ll( _19, f6 );
  wl_t f7_38 = wl_mul_ll( _38, f7 ); wl_t f8_19 = wl_mul_ll( _19, f8 );
  wl_t f9_38 = wl_mul_ll( _38, f9 );

  wl_t f0f0    = wl_mul_ll( f0  , f0    ); wl_t f0f1_2  = wl_mul_ll( f0_2, f1    );
  wl_t f0f2_2  = wl_mul_ll( f0_2, f2    ); wl_t f0f3_2  = wl_mul_ll( f0_2, f3    );
  wl_t f0f4_2  = wl_mul_ll( f0_2, f4    ); wl_t f0f5_2  = wl_mul_ll( f0_2, f5    );
  wl_t f0f6_2  = wl_mul_ll( f0_2, f6    ); wl_t f0f7_2  = wl_mul_ll( f0_2, f7    );
  wl_t f0f8_2  = wl_mul_ll( f0_2, f8    ); wl_t f0f9_2  = wl_mul_ll( f0_2, f9    );

  wl_t f1f1_2  = wl_mul_ll( f1_2, f1    ); wl_t f1f2_2  = wl_mul_ll( f1_2, f2    );
  wl_t f1f3_4  = wl_mul_ll( f1_2, f3_2  ); wl_t f1f4_2  = wl_mul_ll( f1_2, f4    );
  wl_t f1f5_4  = wl_mul_ll( f1_2, f5_2  ); wl_t f1f6_2  = wl_mul_ll( f1_2, f6    );
  wl_t f1f7_4  = wl_mul_ll( f1_2, f7_2  ); wl_t f1f8_2  = wl_mul_ll( f1_2, f8    );
  wl_t f1f9_76 = wl_mul_ll( f1_2, f9_38 );

  wl_t f2f2    = wl_mul_ll( f2  , f2    ); wl_t f2f3_2  = wl_mul_ll( f2_2, f3    );
  wl_t f2f4_2  = wl_mul_ll( f2_2, f4    ); wl_t f2f5_2  = wl_mul_ll( f2_2, f5    );
  wl_t f2f6_2  = wl_mul_ll( f2_2, f6    ); wl_t f2f7_2  = wl_mul_ll( f2_2, f7    );
  wl_t f2f8_38 = wl_mul_ll( f2_2, f8_19 ); wl_t f2f9_38 = wl_mul_ll( f2  , f9_38 );

  wl_t f3f3_2  = wl_mul_ll( f3_2, f3    ); wl_t f3f4_2  = wl_mul_ll( f3_2, f4    );
  wl_t f3f5_4  = wl_mul_ll( f3_2, f5_2  ); wl_t f3f6_2  = wl_mul_ll( f3_2, f6    );
  wl_t f3f7_76 = wl_mul_ll( f3_2, f7_38 ); wl_t f3f8_38 = wl_mul_ll( f3_2, f8_19 );
  wl_t f3f9_76 = wl_mul_ll( f3_2, f9_38 );

  wl_t f4f4    = wl_mul_ll( f4  , f4    ); wl_t f4f5_2  = wl_mul_ll( f4_2, f5    );
  wl_t f4f6_38 = wl_mul_ll( f4_2, f6_19 ); wl_t f4f7_38 = wl_mul_ll( f4  , f7_38 );
  wl_t f4f8_38 = wl_mul_ll( f4_2, f8_19 ); wl_t f4f9_38 = wl_mul_ll( f4  , f9_38 );

  wl_t f5f5_38 = wl_mul_ll( f5  , f5_38 ); wl_t f5f6_38 = wl_mul_ll( f5_2, f6_19 );
  wl_t f5f7_76 = wl_mul_ll( f5_2, f7_38 ); wl_t f5f8_38 = wl_mul_ll( f5_2, f8_19 );
  wl_t f5f9_76 = wl_mul_ll( f5_2, f9_38 );

  wl_t f6f6_19 = wl_mul_ll( f6  , f6_19 ); wl_t f6f7_38 = wl_mul_ll( f6  , f7_38 );
  wl_t f6f8_38 = wl_mul_ll( f6_2, f8_19 ); wl_t f6f9_38 = wl_mul_ll( f6  , f9_38 );

  wl_t f7f7_38 = wl_mul_ll( f7  , f7_38 ); wl_t f7f8_38 = wl_mul_ll( f7_2, f8_19 );
  wl_t f7f9_76 = wl_mul_ll( f7_2, f9_38 );

  wl_t f8f8_19 = wl_mul_ll( f8  , f8_19 ); wl_t f8f9_38 = wl_mul_ll( f8  , f9_38 );

  wl_t f9f9_38 = wl_mul_ll( f9  , f9_38 );

  wl_t m  = wl( 1L-na, 1L-nb, 1L-nc, 1L-nd );

  wl_t h0 = REDUCE_6( f0f0  , f1f9_76, f2f8_38, f3f7_76, f4f6_38, f5f5_38 ); h0 = wl_add( h0, wl_and( h0, m ) );
  wl_t h1 = REDUCE_5( f0f1_2, f2f9_38, f3f8_38, f4f7_38, f5f6_38          ); h1 = wl_add( h1, wl_and( h1, m ) );
  wl_t h2 = REDUCE_6( f0f2_2, f1f1_2 , f3f9_76, f4f8_38, f5f7_76, f6f6_19 ); h2 = wl_add( h2, wl_and( h2, m ) );
  wl_t h3 = REDUCE_5( f0f3_2, f1f2_2 , f4f9_38, f5f8_38, f6f7_38          ); h3 = wl_add( h3, wl_and( h3, m ) );
  wl_t h4 = REDUCE_6( f0f4_2, f1f3_4 , f2f2   , f5f9_76, f6f8_38, f7f7_38 ); h4 = wl_add( h4, wl_and( h4, m ) );
  wl_t h5 = REDUCE_5( f0f5_2, f1f4_2 , f2f3_2 , f6f9_38, f7f8_38          ); h5 = wl_add( h5, wl_and( h5, m ) );
  wl_t h6 = REDUCE_6( f0f6_2, f1f5_4 , f2f4_2 , f3f3_2 , f7f9_76, f8f8_19 ); h6 = wl_add( h6, wl_and( h6, m ) );
  wl_t h7 = REDUCE_5( f0f7_2, f1f6_2 , f2f5_2 , f3f4_2 , f8f9_38          ); h7 = wl_add( h7, wl_and( h7, m ) );
  wl_t h8 = REDUCE_6( f0f8_2, f1f7_4 , f2f6_2 , f3f5_4 , f4f4   , f9f9_38 ); h8 = wl_add( h8, wl_and( h8, m ) );
  wl_t h9 = REDUCE_5( f0f9_2, f1f8_2 , f2f7_2 , f3f6_2 , f4f5_2           ); h9 = wl_add( h9, wl_and( h9, m ) );

  wl_t m38u = wl_bcast( (long)FD_MASK_MSB(38) );
  wl_t m39u = wl_bcast( (long)FD_MASK_MSB(39) );
  wl_t b24  = wl_bcast( 1L << 24 );
  wl_t b25  = wl_bcast( 1L << 25 );

  wl_t carry0 = wl_add( h0, b25 ); h1 = wl_add( h1, wl_shr      ( carry0, 26 ) );      h0 = wl_sub( h0, wl_and( carry0, m38u ) );
  wl_t carry4 = wl_add( h4, b25 ); h5 = wl_add( h5, wl_shr      ( carry4, 26 ) );      h4 = wl_sub( h4, wl_and( carry4, m38u ) );
  wl_t carry1 = wl_add( h1, b24 ); h2 = wl_add( h2, wl_shr      ( carry1, 25 ) );      h1 = wl_sub( h1, wl_and( carry1, m39u ) );
  wl_t carry5 = wl_add( h5, b24 ); h6 = wl_add( h6, wl_shr      ( carry5, 25 ) );      h5 = wl_sub( h5, wl_and( carry5, m39u ) );
  wl_t carry2 = wl_add( h2, b25 ); h3 = wl_add( h3, wl_shr      ( carry2, 26 ) );      h2 = wl_sub( h2, wl_and( carry2, m38u ) );
  wl_t carry6 = wl_add( h6, b25 ); h7 = wl_add( h7, wl_shr      ( carry6, 26 ) );      h6 = wl_sub( h6, wl_and( carry6, m38u ) );
  wl_t carry3 = wl_add( h3, b24 ); h4 = wl_add( h4, wl_shr      ( carry3, 25 ) );      h3 = wl_sub( h3, wl_and( carry3, m39u ) );
  wl_t carry7 = wl_add( h7, b24 ); h8 = wl_add( h8, wl_shr      ( carry7, 25 ) );      h7 = wl_sub( h7, wl_and( carry7, m39u ) );
  /**/ carry4 = wl_add( h4, b25 ); h5 = wl_add( h5, wl_shr      ( carry4, 26 ) );      h4 = wl_sub( h4, wl_and( carry4, m38u ) );
  wl_t carry8 = wl_add( h8, b25 ); h9 = wl_add( h9, wl_shr      ( carry8, 26 ) );      h8 = wl_sub( h8, wl_and( carry8, m38u ) );
  wl_t carry9 = wl_add( h9, b24 ); h0 = wl_add( h0, wl_shr_scale( carry9, 25, 19L ) ); h9 = wl_sub( h9, wl_and( carry9, m39u ) );
  /**/ carry0 = wl_add( h0, b25 ); h1 = wl_add( h1, wl_shr      ( carry0, 26 ) );      h0 = wl_sub( h0, wl_and( carry0, m38u ) );

  SWIZZLE_OUT( ha,hb,hc,hd, h0,h1,h2,h3,h4,h5,h6,h7,h8,h9 );
}
