#include "fd_bench_sign8.h"
#include "../../../../ballet/ed25519/fd_ed25519.h"
#include "../../../../ballet/ed25519/fd_curve25519.h"
#include "../../../../ballet/sha512/fd_sha512.h"

#if FD_HAS_AVX512
#include "../../../../ballet/ed25519/avx512/fd_ed25519_lane.h"

/* table[w][k] = k*256^w*B, k in [0,128], as affine Niels coordinates
   (y-x, y+x, 2dt) in radix 2^51 limbs, one 128 byte entry per point so
   a lane gathers one point.  A signed radix-256 digit d picks entry |d|
   and, when negative, swaps y-x with y+x and negates 2dt (done by
   swapping f and g in the addition). */

#define WINDOWS (32)
#define ENTRIES (129)
#define STRIDE  (16) /* qwords: ymx[5] ypx[5] kt[5] pad */

struct __attribute__((aligned(64))) fd_bench_sign8 {
  ulong                table[ WINDOWS ][ ENTRIES ][ STRIDE ];
  fd_ed25519_lane_fe_t curve_k; /* 2d */
};

ulong fd_bench_sign8_align    ( void ) { return alignof(fd_bench_sign8_t); }
ulong fd_bench_sign8_footprint( void ) { return sizeof (fd_bench_sign8_t); }

fd_bench_sign8_t *
fd_bench_sign8_new( void * mem ) {
  fd_bench_sign8_t * s8 = (fd_bench_sign8_t *)mem;

  fd_f25519_t ks[ 8 ];
  for( ulong j=0UL; j<8UL; j++ ) fd_f25519_set( &ks[ j ], fd_f25519_k );
  fd_ed25519_lane_pack_fe( &s8->curve_k, ks );

  /* Entry k is entry k-1 plus the window base; the lane decoder turns
     the encodings back into affine coordinates, eight at a time. */
  for( ulong w=0UL; w<WINDOWS; w++ ) {
    uchar scalar[ 32 ] = {0};
    scalar[ w ] = 1;
    fd_ed25519_point_t base[1], cur[1];
    fd_ed25519_scalar_mul_base_const_time( base, scalar );
    fd_ed25519_point_set_zero( cur );
    uchar enc[ ENTRIES+7 ][ 32 ];
    for( ulong k=0UL; k<ENTRIES; k++ ) {
      fd_ed25519_point_tobytes( enc[ k ], cur );
      fd_ed25519_point_add( cur, cur, base );
    }
    for( ulong k=ENTRIES; k<ENTRIES+7UL; k++ ) fd_memcpy( enc[ k ], enc[ 0 ], 32UL );
    for( ulong k=0UL; k<ENTRIES; k+=8UL ) {
      uchar const * bufs[ 8 ];
      for( ulong j=0UL; j<8UL; j++ ) bufs[ j ] = enc[ k+j ];
      fd_ed25519_lane_point_t lp;
      FD_TEST( fd_ed25519_lane_decode( &lp, bufs )==0xFF );
      fd_ed25519_lane_fe_t ymx, ypx, kt;
      fd_ed25519_lane_sub( &ymx, &lp.y, &lp.x );
      fd_ed25519_lane_add( &ypx, &lp.y, &lp.x );
      fd_ed25519_lane_mul( &kt,  &lp.t, &s8->curve_k );
      fd_ed25519_lane_fe_t const * fe[ 3 ] = { &ymx, &ypx, &kt };
      for( ulong f=0UL; f<3UL; f++ ) {
        for( ulong l=0UL; l<5UL; l++ ) {
          ulong tmp[ 8 ] __attribute__((aligned(64)));
          wwv_st( tmp, fe[ f ]->limb[ l ] );
          for( ulong j=0UL; j<8UL && k+j<ENTRIES; j++ ) s8->table[ w ][ k+j ][ 5UL*f+l ] = tmp[ j ];
        }
      }
    }
  }
  return s8;
}

/* One fully reduced 32 byte encoding per lane */
static void
lane_fe_tobytes( uchar                out[ 8 ][ 32 ],
                 fd_ed25519_lane_fe_t a ) {
  a = fd_ed25519_lane_normalize( a );
  ulong l[ 5 ][ 8 ] __attribute__((aligned(64)));
  for( ulong i=0UL; i<5UL; i++ ) wwv_st( l[ i ], a.limb[ i ] );
  for( ulong j=0UL; j<8UL; j++ ) {
    ulong u0 =  l[0][j]      | (l[1][j]<<51);
    ulong u1 = (l[1][j]>>13) | (l[2][j]<<38);
    ulong u2 = (l[2][j]>>26) | (l[3][j]<<25);
    ulong u3 = (l[3][j]>>39) | (l[4][j]<<12);
    /* normalize leaves [0,2^255); fold [p,2^255) down */
    if( FD_UNLIKELY( (u3==0x7FFFFFFFFFFFFFFFUL) & (u2==ULONG_MAX) & (u1==ULONG_MAX) & (u0>=0xFFFFFFFFFFFFFFEDUL) ) ) {
      u0 += 19UL; u1 = 0UL; u2 = 0UL; u3 = 0UL;
    }
    FD_STORE( ulong, out[ j ],    u0 );
    FD_STORE( ulong, out[ j ]+8,  u1 );
    FD_STORE( ulong, out[ j ]+16, u2 );
    FD_STORE( ulong, out[ j ]+24, u3 );
  }
}

/* p += q for affine Niels q=(ymx,ypx,kt); lanes in neg add -q instead
   (their ymx/ypx are already swapped, negating kt swaps f and g). */
static inline void
lane_point_add_niels( fd_ed25519_lane_point_t *    p,
                      fd_ed25519_lane_fe_t const * ymx,
                      fd_ed25519_lane_fe_t const * ypx,
                      fd_ed25519_lane_fe_t const * kt,
                      int                          neg ) {
  fd_ed25519_lane_fe_t a, b, c, d, e, f, g, h;
  fd_ed25519_lane_sub( &a, &p->y, &p->x );
  fd_ed25519_lane_mul( &a, &a, ymx );
  fd_ed25519_lane_add( &b, &p->y, &p->x );
  fd_ed25519_lane_mul( &b, &b, ypx );
  fd_ed25519_lane_mul( &c, &p->t, kt );
  fd_ed25519_lane_add( &d, &p->z, &p->z );
  fd_ed25519_lane_sub( &e, &b, &a );
  fd_ed25519_lane_sub( &f, &d, &c );
  fd_ed25519_lane_add( &g, &d, &c );
  fd_ed25519_lane_add( &h, &b, &a );
  for( int i=0; i<5; i++ ) {
    wwv_t t = f.limb[i];
    f.limb[i] = wwv_if( neg, g.limb[i], f.limb[i] );
    g.limb[i] = wwv_if( neg, t,         g.limb[i] );
  }
  fd_ed25519_lane_mul( &p->x, &e, &f );
  fd_ed25519_lane_mul( &p->y, &g, &h );
  fd_ed25519_lane_mul( &p->z, &f, &g );
  fd_ed25519_lane_mul( &p->t, &e, &h );
}

/* R = [r]B for one lane batch; leaves acc projective.  r < L < 2^253,
   so the top byte is at most 0x10 and the last digit never carries. */
static void
lane_scalar_mul_base( fd_bench_sign8_t const *  s8,
                      fd_ed25519_lane_point_t * acc,
                      uchar const               r[ 8 ][ 32 ] ) {
  ulong off[ WINDOWS ][ 8 ] __attribute__((aligned(64)));
  int   neg[ WINDOWS ];
  for( ulong w=0UL; w<WINDOWS; w++ ) neg[ w ] = 0;
  for( ulong j=0UL; j<8UL; j++ ) {
    int carry = 0;
    for( ulong w=0UL; w<WINDOWS; w++ ) {
      int d = (int)r[ j ][ w ] + carry;
      carry = d>=128;
      d -= carry<<8;
      neg[ w ] |= (d<0)<<j;
      off[ w ][ j ] = (w*ENTRIES + (ulong)(d<0 ? -d : d))*(STRIDE*sizeof(ulong));
    }
  }

  uchar const * base = (uchar const *)s8->table;
  fd_ed25519_lane_zero( acc );
  for( ulong w=0UL; w<WINDOWS; w++ ) {
    if( FD_LIKELY( w+1UL<WINDOWS ) ) {
      for( ulong j=0UL; j<8UL; j++ ) {
        _mm_prefetch( base + off[ w+1UL ][ j ],      _MM_HINT_T0 );
        _mm_prefetch( base + off[ w+1UL ][ j ] + 64, _MM_HINT_T0 );
      }
    }
    wwv_t offsets = wwv_ld( off[ w ] );
    fd_ed25519_lane_fe_t ymx, ypx, kt;
    for( ulong l=0UL; l<5UL; l++ ) {
      wwv_t m = _mm512_i64gather_epi64( offsets, base + ( 0UL+l)*sizeof(ulong), 1 );
      wwv_t p = _mm512_i64gather_epi64( offsets, base + ( 5UL+l)*sizeof(ulong), 1 );
      kt.limb[ l ]  = _mm512_i64gather_epi64( offsets, base + (10UL+l)*sizeof(ulong), 1 );
      ymx.limb[ l ] = wwv_if( neg[ w ], p, m );
      ypx.limb[ l ] = wwv_if( neg[ w ], m, p );
    }
    lane_point_add_niels( acc, &ymx, &ypx, &kt, neg[ w ] );
  }
}

void
fd_bench_sign8_mul_base( fd_bench_sign8_t const * s8,
                         uchar                    out[ 8 ][ 32 ],
                         uchar const              r[ 8 ][ 32 ] ) {
  fd_ed25519_lane_point_t acc;
  lane_scalar_mul_base( s8, &acc, r );
  fd_ed25519_lane_fe_t zinv, z3;
  fd_ed25519_lane_pow22523( &zinv, &acc.z );
  fd_ed25519_lane_sqrn( &zinv, &zinv, 3 );
  fd_ed25519_lane_sqr ( &z3, &acc.z );
  fd_ed25519_lane_mul ( &z3, &z3, &acc.z );
  fd_ed25519_lane_mul ( &zinv, &zinv, &z3 );
  fd_ed25519_lane_mul( &acc.x, &acc.x, &zinv );
  fd_ed25519_lane_mul( &acc.y, &acc.y, &zinv );
  uchar xb[ 8 ][ 32 ];
  lane_fe_tobytes( xb,  acc.x );
  lane_fe_tobytes( out, acc.y );
  for( ulong j=0UL; j<8UL; j++ ) out[ j ][ 31 ] |= (uchar)( (xb[ j ][ 0 ]&1)<<7 );
}

void
fd_bench_sign8_n( fd_bench_sign8_t const * s8,
                  ulong                    n,
                  uchar * const *          sigs,
                  uchar const * const *    msgs,
                  ulong const *            msg_szs,
                  uchar const * const *    pubs,
                  uchar const * const *    privs ) {
  fd_sha512_batch_t batch[ 1 ];
  uchar az [ FD_BENCH_SIGN8_N_MAX*8 ][ 64 ];
  uchar r64[ 8 ][ 64 ], r[ FD_BENCH_SIGN8_N_MAX*8 ][ 32 ];
  uchar k64[ 8 ][ 64 ], k[ 32 ];
  uchar buf[ 8 ][ 64+FD_BENCH_SIGN8_MSG_MAX ];
  uchar R  [ FD_BENCH_SIGN8_N_MAX*8 ][ 32 ];
  fd_ed25519_lane_point_t acc [ FD_BENCH_SIGN8_N_MAX ];
  fd_ed25519_lane_fe_t    pref[ FD_BENCH_SIGN8_N_MAX ]; /* pref[i] = z_0 * ... * z_i */

  for( ulong i=0UL; i<n; i++ ) {
    ulong o = 8UL*i;

    /* 1. secret scalar and prefix: az = SHA-512( private key ) */
    fd_sha512_batch_init( batch );
    for( ulong j=0UL; j<8UL; j++ ) fd_sha512_batch_add( batch, privs[ o+j ], 32UL, az[ o+j ] );
    fd_sha512_batch_fini( batch );
    for( ulong j=0UL; j<8UL; j++ ) {
      az[ o+j ][ 0] &= (uchar)0xF8;
      az[ o+j ][31] &= (uchar)0x7F;
      az[ o+j ][31] |= (uchar)0x40;
    }

    /* 2. r = SHA-512( prefix || msg ) mod L */
    fd_sha512_batch_init( batch );
    for( ulong j=0UL; j<8UL; j++ ) {
      fd_memcpy( buf[ j ],    az[ o+j ]+32, 32UL           );
      fd_memcpy( buf[ j ]+32, msgs[ o+j ],  msg_szs[ o+j ] );
      fd_sha512_batch_add( batch, buf[ j ], 32UL+msg_szs[ o+j ], r64[ j ] );
    }
    fd_sha512_batch_fini( batch );
    for( ulong j=0UL; j<8UL; j++ ) fd_curve25519_scalar_reduce( r[ o+j ], r64[ j ] );

    /* 3. R = [r]B, one signed 8 bit window per table row, no doublings */
    lane_scalar_mul_base( s8, &acc[ i ], (uchar const (*)[ 32 ])(r+o) );
    if( i ) fd_ed25519_lane_mul( &pref[ i ], &pref[ i-1UL ], &acc[ i ].z );
    else    pref[ 0 ] = acc[ 0 ].z;
  }

  /* 4. one inversion for all batches: z^(p-2) = pow22523(z)^8 * z^3 */
  fd_ed25519_lane_fe_t inv, z3;
  fd_ed25519_lane_pow22523( &inv, &pref[ n-1UL ] );
  fd_ed25519_lane_sqrn( &inv, &inv, 3 );
  fd_ed25519_lane_sqr ( &z3, &pref[ n-1UL ] );
  fd_ed25519_lane_mul ( &z3, &z3, &pref[ n-1UL ] );
  fd_ed25519_lane_mul ( &inv, &inv, &z3 );

  for( ulong i=n; i--; ) {
    ulong o = 8UL*i;
    fd_ed25519_lane_fe_t zinv;
    if( i ) { fd_ed25519_lane_mul( &zinv, &inv, &pref[ i-1UL ] ); fd_ed25519_lane_mul( &inv, &inv, &acc[ i ].z ); }
    else    zinv = inv;
    fd_ed25519_lane_mul( &acc[ i ].x, &acc[ i ].x, &zinv );
    fd_ed25519_lane_mul( &acc[ i ].y, &acc[ i ].y, &zinv );
    uchar xb[ 8 ][ 32 ];
    lane_fe_tobytes( xb,  acc[ i ].x );
    lane_fe_tobytes( R+o, acc[ i ].y );
    for( ulong j=0UL; j<8UL; j++ ) R[ o+j ][ 31 ] |= (uchar)( (xb[ j ][ 0 ]&1)<<7 );
  }

  for( ulong i=0UL; i<n; i++ ) {
    ulong o = 8UL*i;

    /* 5. k = SHA-512( R || A || msg ) mod L */
    fd_sha512_batch_init( batch );
    for( ulong j=0UL; j<8UL; j++ ) {
      fd_memcpy( buf[ j ],    R[ o+j ],    32UL           );
      fd_memcpy( buf[ j ]+32, pubs[ o+j ], 32UL           );
      fd_memcpy( buf[ j ]+64, msgs[ o+j ], msg_szs[ o+j ] );
      fd_sha512_batch_add( batch, buf[ j ], 64UL+msg_szs[ o+j ], k64[ j ] );
    }
    fd_sha512_batch_fini( batch );

    /* 6. S = r + k*a mod L */
    for( ulong j=0UL; j<8UL; j++ ) {
      fd_curve25519_scalar_reduce( k, k64[ j ] );
      fd_memcpy( sigs[ o+j ], R[ o+j ], 32UL );
      fd_curve25519_scalar_muladd( sigs[ o+j ]+32, k, az[ o+j ], r[ o+j ] );
    }
  }
}

#else /* !FD_HAS_AVX512 */

struct fd_bench_sign8 { fd_sha512_t sha[ 1 ]; };

ulong fd_bench_sign8_align    ( void ) { return alignof(fd_bench_sign8_t); }
ulong fd_bench_sign8_footprint( void ) { return sizeof (fd_bench_sign8_t); }

fd_bench_sign8_t *
fd_bench_sign8_new( void * mem ) {
  fd_bench_sign8_t * s8 = (fd_bench_sign8_t *)mem;
  FD_TEST( fd_sha512_join( fd_sha512_new( s8->sha ) ) );
  return s8;
}

void
fd_bench_sign8_mul_base( fd_bench_sign8_t const * s8,
                         uchar                    out[ 8 ][ 32 ],
                         uchar const              r[ 8 ][ 32 ] ) {
  (void)s8;
  for( ulong j=0UL; j<8UL; j++ ) {
    fd_ed25519_point_t P[1];
    fd_ed25519_scalar_mul_base_const_time( P, r[ j ] );
    fd_ed25519_point_tobytes( out[ j ], P );
  }
}

void
fd_bench_sign8_n( fd_bench_sign8_t const * s8,
                  ulong                    n,
                  uchar * const *          sigs,
                  uchar const * const *    msgs,
                  ulong const *            msg_szs,
                  uchar const * const *    pubs,
                  uchar const * const *    privs ) {
  for( ulong j=0UL; j<8UL*n; j++ )
    fd_ed25519_sign( sigs[ j ], msgs[ j ], msg_szs[ j ], pubs[ j ], privs[ j ], (fd_sha512_t *)s8->sha );
}

#endif
