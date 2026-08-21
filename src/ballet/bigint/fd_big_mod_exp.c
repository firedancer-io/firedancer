#include "fd_big_mod_exp.h"

#if FD_HAS_S2NBIGNUM

#include <stdint.h>
#include <s2n-bignum.h>

/* s2n-bignum has ADX variants for various sizes, and generic non-ADX
   bignum_amontmul, bignum_amontsqr.
   ADX code is ~2x faster than non-ADX, so worth the extra complexity. */
#if defined(__ADX__)
#define FD_BIG_MOD_EXP_ADX 1
#else
#define FD_BIG_MOD_EXP_ADX 0
#endif

/* Max operand size in 64-bit words (512 bytes / 8). */
#define FD_BIG_MOD_EXP_MAX_WORDS (FD_BIG_MOD_EXP_MAX_BYTES/8UL)

/* Largest exponent window, in bits. */

#define FD_BIG_MOD_EXP_MAX_WINDOW (4UL)
#define FD_BIG_MOD_EXP_TBL_CNT    (1UL<<FD_BIG_MOD_EXP_MAX_WINDOW)

/* largest k{sqr,mul} temp (kmul_32_64) */
#define FD_BIG_MOD_EXP_KT_WORDS (96UL)

int
fd_big_mod_exp_modulus_is_valid( uchar const * mod,
                                 ulong         mod_len ) {
  if( FD_UNLIKELY( mod_len==0UL ) ) return 0;        /* zero */
  if( FD_UNLIKELY( !(mod[0] & 1U) ) ) return 0;      /* even (includes zero) */
  /* odd: the only remaining value <= 1 is exactly 1 */
  if( FD_UNLIKELY( mod[0]==1U ) ) {
    int is_one = 1;
    for( ulong i=1UL; i<mod_len; i++ ) if( mod[i] ) { is_one = 0; break; }
    if( is_one ) return 0;                           /* one */
  }
  return 1;
}

FD_FN_PURE static inline ulong
fd_big_mod_exp_bits( ulong const * x,
                     ulong         pos,
                     ulong         n ) {
  ulong i  = pos>>6;
  ulong sh = pos & 63UL;
  ulong v  = x[i]>>sh;
  if( sh+n>64UL ) v |= x[i+1]<<(64UL-sh);
  return v & ((1UL<<n)-1UL);
}

/* Montgomery domain parameters plus the fast path's scratch. */

struct fd_big_mod_exp_mont {
  ulong const * m;    /* modulus, k words     */
  ulong         k;
  ulong         w;    /* -1/m[0] mod 2^64     */
  int           fast;
  ulong *       prod; /* 2k words             */
  ulong *       kt;   /* k{sqr,mul} temporary */
};

typedef struct fd_big_mod_exp_mont fd_big_mod_exp_mont_t;

static inline void
fd_big_mod_exp_mont_sqr( fd_big_mod_exp_mont_t const * mt,
                         ulong *                       out,
                         ulong const *                 x ) {
  ulong k = mt->k;
#if FD_BIG_MOD_EXP_ADX
  if( FD_LIKELY( mt->fast ) ) {
    if     ( k== 8UL ) bignum_sqr_8_16  ( mt->prod, x );
    else if( k==16UL ) bignum_ksqr_16_32( mt->prod, x, mt->kt );
    else if( k==32UL ) bignum_ksqr_32_64( mt->prod, x, mt->kt );
    else               bignum_sqr( 2UL*k, mt->prod, k, x );
    ulong cy = bignum_emontredc_8n( k, mt->prod, mt->m, mt->w );
    bignum_optsub( k, out, mt->prod+k, cy, mt->m );
    return;
  }
#endif
  bignum_amontsqr( k, out, x, mt->m );
}

static inline void
fd_big_mod_exp_mont_mul( fd_big_mod_exp_mont_t const * mt,
                         ulong *                       out,
                         ulong const *                 x,
                         ulong const *                 y ) {
  ulong k = mt->k;
#if FD_BIG_MOD_EXP_ADX
  if( FD_LIKELY( mt->fast ) ) {
    if     ( k== 8UL ) bignum_mul_8_16  ( mt->prod, x, y );
    else if( k==16UL ) bignum_kmul_16_32( mt->prod, x, y, mt->kt );
    else if( k==32UL ) bignum_kmul_32_64( mt->prod, x, y, mt->kt );
    else               bignum_mul( 2UL*k, mt->prod, k, x, k, y );
    ulong cy = bignum_emontredc_8n( k, mt->prod, mt->m, mt->w );
    bignum_optsub( k, out, mt->prod+k, cy, mt->m );
    return;
  }
#endif
  bignum_amontmul( k, out, x, y, mt->m );
}

int
fd_big_mod_exp( uchar *       out,
                uchar const * base, ulong base_len,
                uchar const * exp,  ulong exp_len,
                uchar const * mod,  ulong mod_len ) {

  if( FD_UNLIKELY( !fd_big_mod_exp_modulus_is_valid( mod, mod_len ) ) )
    return FD_BIG_MOD_EXP_ERR_MODULUS;

  ulong k = ( fd_ulong_max( base_len, mod_len ) + 7UL )/8UL;  /* [1,MAX_WORDS] */
  ulong e = ( exp_len                           + 7UL )/8UL;  /* [0,MAX_WORDS] */

  ulong a  [ FD_BIG_MOD_EXP_MAX_WORDS ]; /* base,     zero extended to k */
  ulong p  [ FD_BIG_MOD_EXP_MAX_WORDS ]; /* exponent, zero extended to e */
  ulong m  [ FD_BIG_MOD_EXP_MAX_WORDS ]; /* modulus,  zero extended to k */
  ulong r2 [ FD_BIG_MOD_EXP_MAX_WORDS ]; /* 2^{128k} mod m               */
  ulong u  [ FD_BIG_MOD_EXP_MAX_WORDS ]; /* accumulator, ping            */
  ulong v  [ FD_BIG_MOD_EXP_MAX_WORDS ]; /* accumulator, pong            */
  ulong tbl[ FD_BIG_MOD_EXP_TBL_CNT ][ FD_BIG_MOD_EXP_MAX_WORDS ]; /* mont(base^i) */
  ulong prd[ 2UL*FD_BIG_MOD_EXP_MAX_WORDS ]; /* fast path: product          */
  ulong kt [ FD_BIG_MOD_EXP_KT_WORDS ];      /* fast path: k{sqr,mul} temp  */

  fd_memset( a, 0, k*sizeof(ulong) );
  fd_memset( m, 0, k*sizeof(ulong) );
  fd_memcpy( (uchar *)a, base, base_len );
  fd_memcpy( (uchar *)m, mod,  mod_len  );
  if( FD_LIKELY( e ) ) {
    fd_memset( p, 0, e*sizeof(ulong) );
    fd_memcpy( (uchar *)p, exp, exp_len );
  }

  ulong nbits = e ? bignum_bitsize( e, p ) : 0UL;

  /* base^0 == 1 for every base, 0 included. m>1, so 1 mod m == 1. */
  if( FD_UNLIKELY( !nbits ) ) {
    fd_memset( out, 0, mod_len );
    out[0] = (uchar)1;
    return FD_BIG_MOD_EXP_SUCCESS;
  }

  /* Fixed window. */
  ulong w    = 1UL;
  ulong best = nbits + nbits; /* cost at w==1 */
  for( ulong t=2UL; t<=FD_BIG_MOD_EXP_MAX_WINDOW; t++ ) {
    ulong cost = ((1UL<<t)-2UL) + nbits + (nbits+t-1UL)/t;
    if( cost<best ) { best = cost; w = t; }
  }

  fd_big_mod_exp_mont_t mt[1];
  mt->m    = m;
  mt->k    = k;
  mt->prod = prd;
  mt->kt   = kt;
  mt->fast = FD_BIG_MOD_EXP_ADX && k>=8UL && !(k & 7UL);
  mt->w    = mt->fast ? word_negmodinv( m[0] ) : 0UL;

  bignum_amontifier( k, r2, m, v /* scratch, >=k words */ );
  fd_big_mod_exp_mont_mul( mt, tbl[1], r2, a );
  for( ulong i=2UL; i<(1UL<<w); i++ ) {
    fd_big_mod_exp_mont_mul( mt, tbl[i], tbl[i-1], tbl[1] );
  }

  ulong top = nbits % w;
  if( !top ) top = w;
  ulong pos = nbits - top; /* a multiple of w */

  ulong * cur = u;
  ulong * nxt = v;
  fd_memcpy( cur, tbl[ fd_big_mod_exp_bits( p, pos, top ) ], k*sizeof(ulong) );

  while( pos ) {
    pos -= w;
    for( ulong j=0UL; j<w; j++ ) {
      fd_big_mod_exp_mont_sqr( mt, nxt, cur );
      ulong * s = cur; cur = nxt; nxt = s;
    }
    ulong d = fd_big_mod_exp_bits( p, pos, w );
    if( d ) {
      fd_big_mod_exp_mont_mul( mt, nxt, cur, tbl[d] );
      ulong * s = cur; cur = nxt; nxt = s;
    }
  }

  bignum_demont( k, nxt, cur, m );
  fd_memcpy( out, (uchar const *)nxt, mod_len );

  return FD_BIG_MOD_EXP_SUCCESS;
}

#endif /* FD_HAS_S2NBIGNUM */
