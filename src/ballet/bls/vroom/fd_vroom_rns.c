#include "fd_vroom_rns.h"

#if FD_HAS_AVX512

#include "fd_vroom_constants.h"

#define FD_VROOM_MASK50 ((ulong)((1UL<<50)-1UL))

static ulong const fd_vroom_field_modulus[6] = {
  0xb9feffffffffaaabUL, 0x1eabfffeb153ffffUL,
  0x6730d2a0f6b0f624UL, 0x64774b84f38512bfUL,
  0x4b1ba7b6434bacd7UL, 0x1a0111ea397fe69aUL
};

static inline int
uint384_ge( ulong const a[6],
            ulong const b[6] ) {
  for( int i=5; i>=0; i-- ) {
    if( a[i]>b[i] ) return 1;
    if( a[i]<b[i] ) return 0;
  }
  return 1;
}

static inline void
uint384_sub( ulong       a[6],
             ulong const b[6] ) {
  ulong borrow = 0UL;
  for( int i=0; i<6; i++ ) {
    ulong bi = b[i] + borrow;
    ulong carry = bi<b[i];
    ulong ai = a[i];
    a[i] = ai-bi;
    borrow = carry | (ai<bi);
  }
}

/* Canonical reduction for the conversion/export boundary.  This deliberately
   simple fixed 512-bit long division replaces the former use of BLST's
   private fields.h internals.  It is not on the pairing hot path. */
static void
reduce_512_c( ulong       out[6],
              ulong const in[8] ) {
  ulong r[6] = {0UL};
  for( int bit=511; bit>=0; bit-- ) {
    ulong carry = (in[(uint)bit>>6] >> ((uint)bit&63U)) & 1UL;
    for( int i=0; i<6; i++ ) {
      ulong next = r[i]>>63;
      r[i] = (r[i]<<1) | carry;
      carry = next;
    }
    if( uint384_ge( r, fd_vroom_field_modulus ) ) uint384_sub( r, fd_vroom_field_modulus );
  }
  for( int i=0; i<6; i++ ) out[i] = r[i];
}

static inline __m512i
vload( ulong const p[8] ) {
  return _mm512_load_si512( (__m512i const *)p );
}

static inline __m512i
normalize( __m512i x,
           __m512i t ) {
  __m512i lo = _mm512_and_si512( x, _mm512_set1_epi64( (long long)FD_VROOM_MASK50 ) );
  __m512i hi = _mm512_srli_epi64( x, 50 );
  return _mm512_madd52lo_epu64( lo, hi, t );
}

/* Montgomery reduction with R=2^52 and 50-bit moduli.  The redundant two-bit
   headroom makes the final normalization branchless. */
static inline __m512i
mont_reduce_wide_raw( __m512i hi,
                      __m512i lo,
                      __m512i moduli,
                      __m512i mont ) {
  hi = _mm512_add_epi64( hi, _mm512_srli_epi64( lo, 52 ) );
  __m512i q   = _mm512_madd52lo_epu64( _mm512_setzero_si512(), lo, mont );
  __m512i neg = _mm512_sub_epi64( _mm512_setzero_si512(), moduli );
  __m512i hn  = _mm512_madd52hi_epu64( neg, q, moduli );
  return _mm512_sub_epi64( hi, hn );
}

static inline __m512i
mont_reduce_wide_normalized( __m512i hi,
                             __m512i lo,
                             __m512i moduli,
                             __m512i mont,
                             __m512i t ) {
  return normalize( mont_reduce_wide_raw( hi, lo, moduli, mont ), t );
}

static inline void
matrix_accumulate( __m512i                residues,
                   ulong const            mat[8][8],
                   ulong const            sqe[8],
                   ulong const            correction[8],
                   ulong const *          correction_shift,
                   __m512i *              hi,
                   __m512i *              lo ) {
  ulong s[8] __attribute__((aligned(64)));
  _mm512_store_si512( (__m512i *)s, residues );
  uint128 k_raw = (uint128)0;
  for( int i=0; i<8; i++ ) {
    __m512i row    = vload( mat[i] );
    __m512i scalar = _mm512_set1_epi64( (long long)s[i] );
    *hi = _mm512_madd52hi_epu64( *hi, row, scalar );
    *lo = _mm512_madd52lo_epu64( *lo, row, scalar );
    k_raw += (uint128)s[i] * (uint128)sqe[i];
  }

  ulong k = (ulong)(k_raw >> 64);
  __m512i corr = vload( correction );
  __m512i ks   = _mm512_set1_epi64( (long long)k );
  *hi = _mm512_madd52hi_epu64( *hi, corr, ks );
  *lo = _mm512_madd52lo_epu64( *lo, corr, ks );

  /* k can be wider than an IFMA digit.  Accumulate its remaining high digit
     without scalarizing the output lanes.  The r2->r1 path uses constants
     with the 2^52 shift folded in; generic conversions apply it here. */
  ks = _mm512_srli_epi64( ks, 52 );
  if( correction_shift ) {
    __m512i corr_shift = vload( correction_shift );
    *hi = _mm512_madd52hi_epu64( *hi, corr_shift, ks );
    *lo = _mm512_madd52lo_epu64( *lo, corr_shift, ks );
  } else {
    *hi = _mm512_madd52lo_epu64( *hi, corr, ks );
    __m512i carry = _mm512_madd52hi_epu64( _mm512_setzero_si512(), corr, ks );
    *hi = _mm512_add_epi64( *hi, _mm512_slli_epi64( carry, 52 ) );
  }
}

static inline __m512i
expand_m2_to_m1( __m512i m2 ) {
  __m512i hi = _mm512_setzero_si512();
  __m512i lo = _mm512_setzero_si512();
  matrix_accumulate( m2, fd_vroom_r2_mat, fd_vroom_r2_sqe, fd_vroom_r2_correction,
                     fd_vroom_r2_correction_shift, &hi, &lo );
  return mont_reduce_wide_normalized( hi, lo, vload( fd_vroom_m1 ), vload( fd_vroom_m1_mont ), vload( fd_vroom_m1_t ) );
}

static inline __m512i
reduce_wide_m2( fd_vroom_fp_wide_t const * in,
                int                        normalize_m1 ) {
  /* ready<MAX_ADD> sees a product of two standard (bound-2) inputs.  Its
     first reduction deliberately keeps the [0,2m) result.  Reducing it once
     more would alter the no-k quotient estimate in the following r1 step. */
  __m512i m1 = mont_reduce_wide_raw( in->m1_hi, in->m1_lo,
                                    vload( fd_vroom_m1 ), vload( fd_vroom_m1_mont ) );
  if( normalize_m1 ) m1 = normalize( m1, vload( fd_vroom_m1_t ) );

  /* MatrixNoK: cyclic diagonal matmul changes the reduced m1 base into m2
     and accumulates it directly into the unreduced m2 expression. */
  __m512i hi = in->m2_hi;
  __m512i lo = in->m2_lo;
  __m512i cur = m1;
  __m512i shift = _mm512_set_epi64( 6, 5, 4, 3, 2, 1, 0, 7 );
  for( int d=0; d<8; d++ ) {
    if( d ) cur = _mm512_permutexvar_epi64( shift, cur );
    __m512i row = vload( fd_vroom_r1_perm[d] );
    hi = _mm512_madd52hi_epu64( hi, row, cur );
    lo = _mm512_madd52lo_epu64( lo, row, cur );
  }
  return mont_reduce_wide_normalized( hi, lo,
                                     vload( fd_vroom_m2 ), vload( fd_vroom_m2_mont ), vload( fd_vroom_m2_t ) );
}

static inline void
reduce_wide_inner( fd_vroom_fp_t *            out,
                   fd_vroom_fp_wide_t const * in,
                   int                        normalize_m1 ) {
  out->m2 = reduce_wide_m2( in, normalize_m1 );
  out->m1 = expand_m2_to_m1( out->m2 );
}

/* Cyclotomic squaring produces six independent expressions with the same
   post-reduction scale.  Keep the six base conversions interleaved so the
   eight fixed matrix rows are loaded once per half-Fp12, matching VROOM's
   batch-of-six schedule. */
static __attribute__((always_inline)) inline void
fd_vroom_fp_reduce_wide_scaled_batch6( fd_vroom_fp_t             out[6],
                                       fd_vroom_fp_wide_t const   in[6],
                                       uint                       scale ) {
  __m512i cur[6], hi[6], lo[6];
  __m512i mod1  = vload( fd_vroom_m1 );
  __m512i mod2  = vload( fd_vroom_m2 );
  __m512i mont1 = vload( fd_vroom_m1_mont );
  __m512i mont2 = vload( fd_vroom_m2_mont );
  __m512i t1    = vload( fd_vroom_m1_t );
  __m512i t2    = vload( fd_vroom_m2_t );
  __m512i shift = _mm512_set_epi64( 6, 5, 4, 3, 2, 1, 0, 7 );

  for( int j=0; j<6; j++ ) {
    cur[j] = normalize( mont_reduce_wide_raw( in[j].m1_hi, in[j].m1_lo, mod1, mont1 ), t1 );
    hi[j]  = in[j].m2_hi;
    lo[j]  = in[j].m2_lo;
  }
  for( int d=0; d<8; d++ ) {
    __m512i row = vload( fd_vroom_r1_perm[d] );
    for( int j=0; j<6; j++ ) {
      if( d ) cur[j] = _mm512_permutexvar_epi64( shift, cur[j] );
      hi[j] = _mm512_madd52hi_epu64( hi[j], row, cur[j] );
      lo[j] = _mm512_madd52lo_epu64( lo[j], row, cur[j] );
    }
  }
  for( int j=0; j<6; j++ ) {
    __m512i x  = mont_reduce_wide_normalized( hi[j], lo[j], mod2, mont2, t2 );
    __m512i x2 = _mm512_add_epi64( x, x );
    __m512i x3 = _mm512_add_epi64( x2, x );
    __m512i xs = scale==3U ? x3 : _mm512_add_epi64( x3, x3 );
    out[j].m2 = normalize( xs, t2 );
  }

  ulong scalar[6][8] __attribute__((aligned(64)));
  uint128 k_raw[6] = {0};
  for( int j=0; j<6; j++ ) {
    _mm512_store_si512( (__m512i *)scalar[j], out[j].m2 );
    hi[j] = _mm512_setzero_si512();
    lo[j] = _mm512_setzero_si512();
  }
  for( int i=0; i<8; i++ ) {
    __m512i row = vload( fd_vroom_r2_mat[i] );
    for( int j=0; j<6; j++ ) {
      __m512i s = _mm512_set1_epi64( (long long)scalar[j][i] );
      hi[j] = _mm512_madd52hi_epu64( hi[j], row, s );
      lo[j] = _mm512_madd52lo_epu64( lo[j], row, s );
      k_raw[j] += (uint128)scalar[j][i] * (uint128)fd_vroom_r2_sqe[i];
    }
  }
  __m512i corr       = vload( fd_vroom_r2_correction );
  __m512i corr_shift = vload( fd_vroom_r2_correction_shift );
  for( int j=0; j<6; j++ ) {
    __m512i k = _mm512_set1_epi64( (long long)(ulong)(k_raw[j] >> 64) );
    hi[j] = _mm512_madd52hi_epu64( hi[j], corr, k );
    lo[j] = _mm512_madd52lo_epu64( lo[j], corr, k );
    k = _mm512_srli_epi64( k, 52 );
    hi[j] = _mm512_madd52hi_epu64( hi[j], corr_shift, k );
    lo[j] = _mm512_madd52lo_epu64( lo[j], corr_shift, k );
    out[j].m1 = mont_reduce_wide_normalized( hi[j], lo[j], mod1, mont1, t1 );
  }
}

void
fd_vroom_fp_from_uint64( fd_vroom_fp_t * out,
                         ulong const      in[6] ) {
  ulong d[8] __attribute__((aligned(64)));
  d[0] = in[0] & FD_VROOM_MASK50;
  d[1] = ((in[0] >> 50) | (in[1] << 14)) & FD_VROOM_MASK50;
  d[2] = ((in[1] >> 36) | (in[2] << 28)) & FD_VROOM_MASK50;
  d[3] = ((in[2] >> 22) | (in[3] << 42)) & FD_VROOM_MASK50;
  d[4] = (in[3] >> 8) & FD_VROOM_MASK50;
  d[5] = ((in[3] >> 58) | (in[4] << 6)) & FD_VROOM_MASK50;
  d[6] = ((in[4] >> 44) | (in[5] << 20)) & FD_VROOM_MASK50;
  d[7] = (in[5] >> 30) & FD_VROOM_MASK50;

  __m512i hi = _mm512_setzero_si512();
  __m512i lo = _mm512_setzero_si512();
  matrix_accumulate( vload( d ), fd_vroom_to_mat, fd_vroom_to_sqe, fd_vroom_to_correction,
                     NULL, &hi, &lo );
  out->m2 = mont_reduce_wide_normalized( hi, lo,
                                        vload( fd_vroom_m2 ), vload( fd_vroom_m2_mont ), vload( fd_vroom_m2_t ) );
  out->m1 = expand_m2_to_m1( out->m2 );
}

void
fd_vroom_fp_to_uint64( ulong                 out[6],
                       fd_vroom_fp_t const * in ) {
  __m512i hi = _mm512_setzero_si512();
  __m512i lo = _mm512_setzero_si512();
  matrix_accumulate( in->m2, fd_vroom_from_mat, fd_vroom_from_sqe, fd_vroom_from_correction,
                     NULL, &hi, &lo );

  ulong h[8] __attribute__((aligned(64)));
  ulong l[8] __attribute__((aligned(64)));
  ulong digit[9];
  ulong sum[8] = {0UL};
  _mm512_store_si512( (__m512i *)h, hi );
  _mm512_store_si512( (__m512i *)l, lo );
  digit[0] = l[0];
  for( int i=1; i<8; i++ ) digit[i] = h[i-1] + l[i];
  digit[8] = h[7];

  for( int i=0; i<9; i++ ) {
    int word = (52*i) >> 6;
    int bit  = (52*i) & 63;
    uint128 x = (uint128)sum[word] + ((uint128)digit[i] << bit);
    sum[word]   = (ulong)x;
    sum[word+1] = (ulong)(x >> 64);
  }

  reduce_512_c( out, sum );
}

void
fd_vroom_fp_reduce_wide( fd_vroom_fp_t *            out,
                         fd_vroom_fp_wide_t const * in ) {
  reduce_wide_inner( out, in, 1 );
}

static __attribute__((always_inline)) inline void
reduce_wide_batch_impl( fd_vroom_fp_t *            out,
                        fd_vroom_fp_wide_t const * in,
                        int                        cnt ) {
  __m512i cur[6], hi[6], lo[6];
  __m512i mod1  = vload( fd_vroom_m1 );
  __m512i mod2  = vload( fd_vroom_m2 );
  __m512i mont1 = vload( fd_vroom_m1_mont );
  __m512i mont2 = vload( fd_vroom_m2_mont );
  __m512i t1    = vload( fd_vroom_m1_t );
  __m512i t2    = vload( fd_vroom_m2_t );
  __m512i shift = _mm512_set_epi64( 6, 5, 4, 3, 2, 1, 0, 7 );

  for( int j=0; j<cnt; j++ ) {
    cur[j] = normalize( mont_reduce_wide_raw( in[j].m1_hi, in[j].m1_lo, mod1, mont1 ), t1 );
    hi[j]  = in[j].m2_hi;
    lo[j]  = in[j].m2_lo;
  }
  for( int d=0; d<8; d++ ) {
    __m512i row = vload( fd_vroom_r1_perm[d] );
    for( int j=0; j<cnt; j++ ) {
      if( d ) cur[j] = _mm512_permutexvar_epi64( shift, cur[j] );
      hi[j] = _mm512_madd52hi_epu64( hi[j], row, cur[j] );
      lo[j] = _mm512_madd52lo_epu64( lo[j], row, cur[j] );
    }
  }
  for( int j=0; j<cnt; j++ )
    out[j].m2 = mont_reduce_wide_normalized( hi[j], lo[j], mod2, mont2, t2 );

  ulong scalar[6][8] __attribute__((aligned(64)));
  uint128 k_raw[6] = {0};
  for( int j=0; j<cnt; j++ ) {
    _mm512_store_si512( (__m512i *)scalar[j], out[j].m2 );
    hi[j] = _mm512_setzero_si512();
    lo[j] = _mm512_setzero_si512();
  }
  for( int i=0; i<8; i++ ) {
    __m512i row = vload( fd_vroom_r2_mat[i] );
    for( int j=0; j<cnt; j++ ) {
      __m512i s = _mm512_set1_epi64( (long long)scalar[j][i] );
      hi[j] = _mm512_madd52hi_epu64( hi[j], row, s );
      lo[j] = _mm512_madd52lo_epu64( lo[j], row, s );
      k_raw[j] += (uint128)scalar[j][i] * (uint128)fd_vroom_r2_sqe[i];
    }
  }
  __m512i corr       = vload( fd_vroom_r2_correction );
  __m512i corr_shift = vload( fd_vroom_r2_correction_shift );
  for( int j=0; j<cnt; j++ ) {
    __m512i k = _mm512_set1_epi64( (long long)(ulong)(k_raw[j] >> 64) );
    hi[j] = _mm512_madd52hi_epu64( hi[j], corr, k );
    lo[j] = _mm512_madd52lo_epu64( lo[j], corr, k );
    k = _mm512_srli_epi64( k, 52 );
    hi[j] = _mm512_madd52hi_epu64( hi[j], corr_shift, k );
    lo[j] = _mm512_madd52lo_epu64( lo[j], corr_shift, k );
    out[j].m1 = mont_reduce_wide_normalized( hi[j], lo[j], mod1, mont1, t1 );
  }
}

static __attribute__((always_inline)) inline void
fd_vroom_fp_reduce_wide_batch2( fd_vroom_fp_t             out[2],
                                fd_vroom_fp_wide_t const   in[2] ) {
  reduce_wide_batch_impl( out, in, 2 );
}

static __attribute__((always_inline)) inline void
fd_vroom_fp_reduce_wide_batch4( fd_vroom_fp_t             out[4],
                                fd_vroom_fp_wide_t const   in[4] ) {
  reduce_wide_batch_impl( out, in, 4 );
}

static __attribute__((always_inline)) inline void
fd_vroom_fp_reduce_wide_batch6( fd_vroom_fp_t             out[6],
                                fd_vroom_fp_wide_t const   in[6] ) {
  reduce_wide_batch_impl( out, in, 6 );
}

void
fd_vroom_fp_mul( fd_vroom_fp_t *       out,
                 fd_vroom_fp_t const * a,
                 fd_vroom_fp_t const * b ) {
  fd_vroom_fp_wide_t w;
  w.m1_hi = _mm512_madd52hi_epu64( _mm512_setzero_si512(), a->m1, b->m1 );
  w.m1_lo = _mm512_madd52lo_epu64( _mm512_setzero_si512(), a->m1, b->m1 );
  w.m2_hi = _mm512_madd52hi_epu64( _mm512_setzero_si512(), a->m2, b->m2 );
  w.m2_lo = _mm512_madd52lo_epu64( _mm512_setzero_si512(), a->m2, b->m2 );
  reduce_wide_inner( out, &w, 0 );
}

void
fd_vroom_fp_sqr( fd_vroom_fp_t *       out,
                 fd_vroom_fp_t const * a ) {
  fd_vroom_fp_mul( out, a, a );
}

void
fd_vroom_fp_add( fd_vroom_fp_t *       out,
                 fd_vroom_fp_t const * a,
                 fd_vroom_fp_t const * b ) {
  out->m1 = normalize( _mm512_add_epi64( a->m1, b->m1 ), vload( fd_vroom_m1_t ) );
  out->m2 = normalize( _mm512_add_epi64( a->m2, b->m2 ), vload( fd_vroom_m2_t ) );
}

void
fd_vroom_fp_neg( fd_vroom_fp_t *       out,
                 fd_vroom_fp_t const * a ) {
  __m512i m1 = vload( fd_vroom_m1 );
  __m512i m2 = vload( fd_vroom_m2 );
  __m512i x1 = _mm512_add_epi64( _mm512_sub_epi64( _mm512_slli_epi64( m1, 1 ), a->m1 ),
                                vload( fd_vroom_modulus_m1 ) );
  __m512i x2 = _mm512_add_epi64( _mm512_sub_epi64( _mm512_slli_epi64( m2, 1 ), a->m2 ),
                                vload( fd_vroom_modulus_m2 ) );
  out->m1 = _mm512_min_epu64( x1, _mm512_sub_epi64( x1, m1 ) );
  out->m2 = _mm512_min_epu64( x2, _mm512_sub_epi64( x2, m2 ) );
}

void
fd_vroom_fp_sub( fd_vroom_fp_t *       out,
                 fd_vroom_fp_t const * a,
                 fd_vroom_fp_t const * b ) {
  fd_vroom_fp_t neg_b;
  fd_vroom_fp_neg( &neg_b, b );
  fd_vroom_fp_add( out, a, &neg_b );
}

void
fd_vroom_fp_wide_offset( fd_vroom_fp_wide_t * out ) {
  out->m1_hi = vload( fd_vroom_wide_offset_m1_hi );
  out->m1_lo = vload( fd_vroom_wide_offset_m1_lo );
  out->m2_hi = vload( fd_vroom_wide_offset_m2_hi );
  out->m2_lo = vload( fd_vroom_wide_offset_m2_lo );
}

void
fd_vroom_fp_wide_addmul( fd_vroom_fp_wide_t * out,
                         fd_vroom_fp_t const * a,
                         fd_vroom_fp_t const * b ) {
  out->m1_hi = _mm512_madd52hi_epu64( out->m1_hi, a->m1, b->m1 );
  out->m1_lo = _mm512_madd52lo_epu64( out->m1_lo, a->m1, b->m1 );
  out->m2_hi = _mm512_madd52hi_epu64( out->m2_hi, a->m2, b->m2 );
  out->m2_lo = _mm512_madd52lo_epu64( out->m2_lo, a->m2, b->m2 );
}

void
fd_vroom_fp_wide_submul( fd_vroom_fp_wide_t * out,
                         fd_vroom_fp_t const * a,
                         fd_vroom_fp_t const * b ) {
  __m512i z = _mm512_setzero_si512();
  out->m1_hi = _mm512_sub_epi64( out->m1_hi, _mm512_madd52hi_epu64( z, a->m1, b->m1 ) );
  out->m1_lo = _mm512_sub_epi64( out->m1_lo, _mm512_madd52lo_epu64( z, a->m1, b->m1 ) );
  out->m2_hi = _mm512_sub_epi64( out->m2_hi, _mm512_madd52hi_epu64( z, a->m2, b->m2 ) );
  out->m2_lo = _mm512_sub_epi64( out->m2_lo, _mm512_madd52lo_epu64( z, a->m2, b->m2 ) );
}

void
fd_vroom_fp_one( fd_vroom_fp_t * out ) {
  out->m1 = vload( fd_vroom_one_m1 );
  out->m2 = vload( fd_vroom_one_m2 );
}

void
fd_vroom_fp_zero( fd_vroom_fp_t * out ) {
  out->m1 = _mm512_setzero_si512();
  out->m2 = _mm512_setzero_si512();
}

static inline __m512i
canonical_residue( __m512i x,
                   __m512i modulus ) {
  return _mm512_min_epu64( x, _mm512_sub_epi64( x, modulus ) );
}

int
fd_vroom_fp_equal( fd_vroom_fp_t const * a,
                   fd_vroom_fp_t const * b ) {
  __m512i mod1 = vload( fd_vroom_m1 );
  __m512i mod2 = vload( fd_vroom_m2 );
  __m512i p1   = canonical_residue( vload( fd_vroom_field_modulus_m1 ), mod1 );
  __m512i p2   = canonical_residue( vload( fd_vroom_field_modulus_m2 ), mod2 );
  __m512i a1   = canonical_residue( a->m1, mod1 );
  __m512i a2   = canonical_residue( a->m2, mod2 );
  __m512i b1   = canonical_residue( b->m1, mod1 );
  __m512i b2   = canonical_residue( b->m2, mod2 );
  __m512i ca1 = a1, ca2 = a2, cb1 = b1, cb2 = b2;

  /* A standard reduced VROOM value occupies less than 40*p of redundant
     RNS range.  Equal field values can therefore differ by at most 40
     copies of p in either direction.  Compare in both directions without
     converting either operand out of its native RNS form. */
  for( int k=0; k<=40; k++ ) {
    int ab = _mm512_cmpeq_epu64_mask( ca1, b1 )==(__mmask8)0xff &&
             _mm512_cmpeq_epu64_mask( ca2, b2 )==(__mmask8)0xff;
    int ba = _mm512_cmpeq_epu64_mask( cb1, a1 )==(__mmask8)0xff &&
             _mm512_cmpeq_epu64_mask( cb2, a2 )==(__mmask8)0xff;
    if( FD_LIKELY( ab | ba ) ) return 1;
    ca1 = canonical_residue( _mm512_add_epi64( ca1, p1 ), mod1 );
    ca2 = canonical_residue( _mm512_add_epi64( ca2, p2 ), mod2 );
    cb1 = canonical_residue( _mm512_add_epi64( cb1, p1 ), mod1 );
    cb2 = canonical_residue( _mm512_add_epi64( cb2, p2 ), mod2 );
  }
  return 0;
}

#endif
