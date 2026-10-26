/* BLS12-381 base-field arithmetic in rotated-RNS Montgomery form on
   AVX-512 IFMA (8x50-bit residue bases M and N; see fd_bls_rns.h and
   gen_bls_constants.py for the representation). */

#include "fd_bls_rns.h"

#include "fd_bls_constants.h"

ulong const fd_bls_field_modulus_limbs[6] = {
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

/* Canonical reduction for the conversion/export boundary: scalar
   Montgomery arithmetic, hot through fd_bls_fp_to_uint64 and the
   hash-to-field path. */

#define FD_BLS_P0 (0x89f3fffcfffcfffdUL) /* -p^-1 mod 2^64. */
#define FD_BLS_BARRETT_MU (0x2760d74bcf327917UL) /* floor(2^442/p). */

/* 2^768 mod p: redc(y*RR2) = y*2^384 mod p undoes one redc pass. */
static ulong const fd_bls_rr2[6] = {
  0xf4df1f341c341746UL, 0x0a76e6a609d104f1UL, 0x8de5476c4c95b6d5UL,
  0x67eb88a9939d83c0UL, 0x9a793e85b519952dUL, 0x11988fe592cae3aaUL
};

/* One Montgomery round on a sliding window: t <- (t + (t0*p0 mod 2^64)*p)/2^64.
   t has cnt live limbs on entry and cnt-1 on exit (the caller shrinks cnt). */
static inline void
redc_round( ulong * t,
            int     cnt ) {
  ulong   m     = t[0]*FD_BLS_P0;                 /* m makes t+m*p divisible by 2^64. */
  uint128 acc   = (uint128)t[0] + (uint128)m*(uint128)fd_bls_field_modulus_limbs[0];
  ulong   carry = (ulong)(acc>>64);               /* Low limb is zero by construction. */
  for( int i=1; i<6; i++ ) {
    acc    = (uint128)t[i] + (uint128)m*(uint128)fd_bls_field_modulus_limbs[i] + (uint128)carry;
    t[i-1] = (ulong)acc;                          /* Shift down while accumulating.    */
    carry  = (ulong)(acc>>64);
  }
  for( int i=6; i<cnt; i++ ) {
    acc    = (uint128)t[i] + (uint128)carry;
    t[i-1] = (ulong)acc;
    carry  = (ulong)(acc>>64);
  }
  t[cnt-1] = carry;                               /* t < t_in/2^64 + p always fits.    */
}

/* out = in*2^-384 mod p for in < 2^768, out < p + in/2^384 (not canonical). */
static void
redc_768( ulong       out[6],
          ulong const in[12] ) {
  ulong t[12];
  for( int i=0; i<12; i++ ) t[i] = in[i];
  for( int r=0; r<6; r++ ) redc_round( t, 12-r );
  for( int i=0; i<6; i++ ) out[i] = t[i];
}

void
fd_bls_rns_reduce_512( ulong       out[6],
            ulong const in[8] ) {
  /* out = redc(redc(in)*RR2) = in*2^-384*2^768*2^-384 = in mod p. */
  ulong t[12] = {0UL};
  for( int i=0; i<8; i++ ) t[i] = in[i];
  ulong y[6];
  redc_768( y, t );                               /* y = in*2^-384 mod p, y < p+2^128. */

  for( int i=0; i<12; i++ ) t[i] = 0UL;           /* t = y*RR2 < 2^382*2^381 = 2^763.  */
  for( int i=0; i<6; i++ ) {
    ulong carry = 0UL;
    for( int j=0; j<6; j++ ) {
      uint128 acc = (uint128)y[i]*(uint128)fd_bls_rr2[j] + (uint128)t[i+j] + (uint128)carry;
      t[i+j] = (ulong)acc;
      carry  = (ulong)(acc>>64);
    }
    t[i+6] = carry;
  }
  redc_768( out, t );                             /* out = y*2^384 = in mod p, < 2p.   */
  if( uint384_ge( out, fd_bls_field_modulus_limbs ) ) uint384_sub( out, fd_bls_field_modulus_limbs );
}

static inline void
matrix_accumulate( wwv_t                  residues,
                   ulong const            mat[8][8],
                   ulong const            sqe[8],
                   ulong const            correction[8],
                   ulong const *          correction_shift,
                   wwv_t *                hi,
                   wwv_t *                lo ) {
  /* Appendix A CRNS: sum_i r_i*A_ij + k*c_j.  The fixed-point estimate k
     removes the hidden multiple of the input-base product in CRT recovery. */
  ulong s[8] __attribute__((aligned(64)));
  wwv_st( s, residues );                             /* s_i = input residue in source-base lane i. */
  uint128 k_raw = (uint128)0;                        /* k_raw starts the fixed-point CRT quotient. */
  for( int i=0; i<8; i++ ) {
    wwv_t row    = wwv_ld( mat[i] );                              /* row_j = A_ij.                  */
    wwv_t scalar = wwv_bcast( (ulong)s[i] );                      /* scalar_j = s_i.                */
    *hi = wwv_madd52hi( *hi, row, scalar );                       /* hi_j += floor(s_i*A_ij/R).     */
    *lo = wwv_madd52lo( *lo, row, scalar );                       /* lo_j += s_i*A_ij mod R.        */
    k_raw += (uint128)s[i] * (uint128)sqe[i];                      /* k_raw += s_i*f_i, Appendix A's fixed-point term. */
  }

  ulong k = (ulong)(k_raw >> 64);                         /* k=floor(dot(s,f)/2^64), the CRT quotient estimate. */
  wwv_t corr = wwv_ld( correction );                      /* corr_j cancels k times source base.  */
  wwv_t ks   = wwv_bcast( (ulong)k );                     /* ks_j=k for all destination lanes.    */
  *hi = wwv_madd52hi( *hi, corr, ks );                    /* hi_j += floor(k*corr_j/R).            */
  *lo = wwv_madd52lo( *lo, corr, ks );                    /* lo_j += k*corr_j mod R.               */

  /* k can be wider than an IFMA digit.  Accumulate its remaining high digit
     without scalarizing the output lanes.  The r2->r1 path uses constants
     with the 2^52 shift folded in; generic conversions apply it here. */
  ks = wwv_shr( ks, 52 );                                 /* ks=floor(k/R), the second IFMA digit. */
  if( correction_shift ) {
    wwv_t corr_shift = wwv_ld( correction_shift );
    *hi = wwv_madd52hi( *hi, corr_shift, ks );            /* acc += floor(k/R)*shiftedCorrection. */
    *lo = wwv_madd52lo( *lo, corr_shift, ks );            /* Low half of the same correction.    */
  } else {
    *hi = wwv_madd52lo( *hi, corr, ks );                  /* High X digit gets low(corr*floor(k/R)). */
    wwv_t carry = wwv_madd52hi( wwv_zero(), corr, ks );   /* carry=high(corr*floor(k/R)).             */
    *hi = wwv_add( *hi, wwv_shl( carry, 52 ) );           /* Restore carry at the next radix-R place. */
  }
}

wwv_t
fd_bls_rns_expand_m2_to_m1( wwv_t m2 ) {
  /* Algorithm 2, line 4: CRNS from N back to M, with its scale folded in. */
  wwv_t hi = wwv_zero();                                  /* hi:lo = 0 before CRT reconstruction. */
  wwv_t lo = wwv_zero();
  matrix_accumulate( m2, fd_bls_r2_mat, fd_bls_r2_sqe, fd_bls_r2_correction,
                     fd_bls_r2_correction_shift, &hi, &lo );
  return fd_bls_rns_mont_reduce_wide_normalized( hi, lo, wwv_ld( fd_bls_m1 ), wwv_ld( fd_bls_m1_mont ), wwv_ld( fd_bls_m1_t ) ); /* N residues -> M residues. */
}

/* Latency-optimized single-element reduction (Algorithm 2 for one value).
   The standalone multiply is a serial dependency in exponentiation chains
   (sqrt, inversion-free exponents), so every step is arranged to shorten
   the critical path rather than to minimize uops:
   - M->N: the seven lane rotations of the M residues are independent
     permutes of one register (no rotate-of-rotate chain), accumulated as a
     4-way tree.
   - N->M: lane broadcasts are register permutes, the CRT quotient k is two
     independent 128-bit dot-product halves over a stored copy, and the high
     digit of k selects a precomputed lane-sum correction.
   Bit-identical to the batch kernels. */
static ulong const __attribute__((aligned(64))) fd_bls_rot_idx[8][8] = {
  { 0,1,2,3,4,5,6,7 }, { 7,0,1,2,3,4,5,6 }, { 6,7,0,1,2,3,4,5 }, { 5,6,7,0,1,2,3,4 },
  { 4,5,6,7,0,1,2,3 }, { 3,4,5,6,7,0,1,2 }, { 2,3,4,5,6,7,0,1 }, { 1,2,3,4,5,6,7,0 }
};

static __attribute__((always_inline)) inline void
reduce_wide_lat( fd_bls_fp_t * out,
                 wwv_t         m1_hi,
                 wwv_t         m1_lo,
                 wwv_t         m2_hi,
                 wwv_t         m2_lo,
                 int           normalize_m1 ) {
  /* ready<MAX_ADD> sees a product of two standard (bound-2) inputs.  Its
     first reduction deliberately keeps the [0,2m) result.  Reducing it once
     more would alter the no-k quotient estimate in the following r1 step. */
  wwv_t z    = wwv_zero();
  wwv_t mod1 = wwv_ld( fd_bls_m1 );
  wwv_t cur  = fd_bls_rns_mont_reduce_wide_raw( m1_hi, m1_lo, mod1, wwv_ld( fd_bls_m1_mont ) ); /* X/R in base M. */
  if( normalize_m1 ) cur = fd_bls_rns_normalize( cur, wwv_ld( fd_bls_m1_t ) );

  wwv_t h[4], l[4];
  for( int a=0; a<4; a++ ) {                      /* X_N += sum_d rot_d(cur)*r1_perm[d]. */
    wwv_t c0 = a ? wwv_permute( wwv_ld( fd_bls_rot_idx[2*a] ), cur ) : cur;
    wwv_t c1 = wwv_permute( wwv_ld( fd_bls_rot_idx[2*a+1] ), cur );
    wwv_t r0 = wwv_ld( fd_bls_r1_perm[2*a] ), r1 = wwv_ld( fd_bls_r1_perm[2*a+1] );
    wwv_t hh = a ? z : m2_hi;
    wwv_t ll = a ? z : m2_lo;
    hh = wwv_madd52hi( hh, r0, c0 ); ll = wwv_madd52lo( ll, r0, c0 );
    hh = wwv_madd52hi( hh, r1, c1 ); ll = wwv_madd52lo( ll, r1, c1 );
    h[a] = hh; l[a] = ll;
  }
  wwv_t hi = wwv_add( wwv_add( h[0], h[1] ), wwv_add( h[2], h[3] ) );
  wwv_t lo = wwv_add( wwv_add( l[0], l[1] ), wwv_add( l[2], l[3] ) );
  wwv_t n  = fd_bls_rns_mont_reduce_wide_normalized( hi, lo, wwv_ld( fd_bls_m2 ),
                                                     wwv_ld( fd_bls_m2_mont ), wwv_ld( fd_bls_m2_t ) ); /* reduced X/R in N. */
  out->m2 = n;

  ulong sc[8] __attribute__((aligned(64)));
  wwv_st( sc, n );
  ulong * volatile sc_launder = sc;
  ulong *          sl         = sc_launder;
  uint128 k0 = 0, k1 = 0;                        /* k = floor(dot(n,sqe)/2^64), two chains. */
  for( int i=0; i<8; i+=2 ) {
    k0 += (uint128)sl[i  ] * (uint128)fd_bls_r2_sqe[i  ];
    k1 += (uint128)sl[i+1] * (uint128)fd_bls_r2_sqe[i+1];
  }
  ulong kk = (ulong)( (k0+k1) >> 64 );

  for( int a=0; a<4; a++ ) {                      /* X_M = sum_i n_i*r2_mat[i] + k*corr. */
    wwv_t r0 = wwv_ld( fd_bls_r2_mat[2*a] ), r1 = wwv_ld( fd_bls_r2_mat[2*a+1] );
    wwv_t s0 = wwv_permute( wwv_bcast( (ulong)(2*a)   ), n );
    wwv_t s1 = wwv_permute( wwv_bcast( (ulong)(2*a+1) ), n );
    wwv_t hh = wwv_madd52hi( z, r0, s0 ), ll = wwv_madd52lo( z, r0, s0 );
    hh = wwv_madd52hi( hh, r1, s1 ); ll = wwv_madd52lo( ll, r1, s1 );
    h[a] = hh; l[a] = ll;
  }
  hi = wwv_add( wwv_add( h[0], h[1] ), wwv_add( h[2], h[3] ) );
  lo = wwv_add( wwv_add( l[0], l[1] ), wwv_add( l[2], l[3] ) );
  wwv_t k    = wwv_bcast( kk );
  wwv_t corr = wwv_ld( fd_bls_r2_correction );
  hi = wwv_madd52hi( hi, corr, k );
  lo = wwv_add( wwv_madd52lo( lo, corr, k ), wwv_ld( fd_bls_r2_khi[ kk>>52 ] ) );
  out->m1 = fd_bls_rns_mont_reduce_wide_normalized( hi, lo, mod1, wwv_ld( fd_bls_m1_mont ), wwv_ld( fd_bls_m1_t ) );
}

static inline void
reduce_wide_inner( fd_bls_fp_t *            out,
                   fd_bls_fp_wide_t const * in,
                   int                      normalize_m1 ) {
  reduce_wide_lat( out, in->m1_hi, in->m1_lo, in->m2_hi, in->m2_lo, normalize_m1 );
}

void
fd_bls_fp_from_uint64( fd_bls_fp_t * out,
                       ulong const   in[6] ) {
  /* Appendix F: regard the radix input as eight 50-bit digits, convert it to
     the rotated N representation, then expand N to M. */
  ulong d[8] __attribute__((aligned(64)));
  d[0] = in[0] & FD_BLS_MASK50;                                /* d0 = floor(in/2^(50*0)) mod 2^50. */
  d[1] = ((in[0] >> 50) | (in[1] << 14)) & FD_BLS_MASK50;      /* d1 = floor(in/2^(50*1)) mod 2^50. */
  d[2] = ((in[1] >> 36) | (in[2] << 28)) & FD_BLS_MASK50;      /* d2 = floor(in/2^(50*2)) mod 2^50. */
  d[3] = ((in[2] >> 22) | (in[3] << 42)) & FD_BLS_MASK50;      /* d3 = floor(in/2^(50*3)) mod 2^50. */
  d[4] = (in[3] >> 8) & FD_BLS_MASK50;                         /* d4 = floor(in/2^(50*4)) mod 2^50. */
  d[5] = ((in[3] >> 58) | (in[4] << 6)) & FD_BLS_MASK50;       /* d5 = floor(in/2^(50*5)) mod 2^50. */
  d[6] = ((in[4] >> 44) | (in[5] << 20)) & FD_BLS_MASK50;      /* d6 = floor(in/2^(50*6)) mod 2^50. */
  d[7] = (in[5] >> 30) & FD_BLS_MASK50;                        /* d7 = floor(in/2^(50*7)) mod 2^50. */

  wwv_t hi = wwv_zero();
  wwv_t lo = wwv_zero();
  matrix_accumulate( wwv_ld( d ), fd_bls_to_mat, fd_bls_to_sqe, fd_bls_to_correction,
                     NULL, &hi, &lo );
  out->m2 = fd_bls_rns_mont_reduce_wide_normalized( hi, lo,
                                        wwv_ld( fd_bls_m2 ), wwv_ld( fd_bls_m2_mont ), wwv_ld( fd_bls_m2_t ) ); /* radix digits -> N residues. */
  out->m1 = fd_bls_rns_expand_m2_to_m1( out->m2 ); /* Complete the redundant representation with matching M residues. */
}

void
fd_bls_fp_to_uint64( ulong               out[6],
                     fd_bls_fp_t const * in ) {
  /* Appendix F in reverse: CRNS from N to radix-2^52 digits, then remove the
     remaining redundant multiple of p at this cold conversion boundary. */
  wwv_t hi = wwv_zero();
  wwv_t lo = wwv_zero();
  matrix_accumulate( in->m2, fd_bls_from_mat, fd_bls_from_sqe, fd_bls_from_correction,
                     NULL, &hi, &lo );

  ulong h[8] __attribute__((aligned(64)));
  ulong l[8] __attribute__((aligned(64)));
  ulong digit[9];
  ulong sum[8] = {0UL};
  wwv_st( h, hi );
  wwv_st( l, lo );
  digit[0] = l[0];                                      /* digit0 = low limb 0.                    */
  for( int i=1; i<8; i++ ) digit[i] = h[i-1] + l[i];    /* digit_i = carry_{i-1}+low_i in radix R. */
  digit[8] = h[7];                                      /* digit8 = final radix-R carry.            */

  for( int i=0; i<9; i++ ) {
    int word = (52*i) >> 6;                                                /* word=floor(52i/64).     */
    int bit  = (52*i) & 63;                                                /* bit =52i mod 64.        */
    uint128 x = (uint128)sum[word] + ((uint128)digit[i] << bit);           /* x accumulates digit_i*R^i. */
    sum[word]   = (ulong)x;                                                /* Store low 64 bits.      */
    sum[word+1] = (ulong)(x >> 64);                                        /* Propagate high 64 bits. */
  }

  /* sum < 2^436 (eight residues below 2^51 times rows below p, plus
     k*correction with k < 2^54 and correction < p), so a single-word
     Barrett step suffices: with A=floor(sum/2^378) < 2^58 and
     mu=floor(2^442/p), q=floor(A*mu/2^64) underestimates floor(sum/p) by
     at most one (error < 2^378/p + A/2^64 + 1 < 1.2), leaving
     sum-q*p < 2p < 2^382, so its low six limbs are exact. */
  ulong   a  = (sum[5]>>58) | (sum[6]<<6);                 /* A = floor(sum/2^378), sum[7]==0. */
  ulong   q  = (ulong)( ( (uint128)a * (uint128)FD_BLS_BARRETT_MU ) >> 64 );
  uint128 c  = 0;                                          /* r = sum - q*p over 7 limbs.      */
  ulong   borrow = 0UL;
  for( int i=0; i<6; i++ ) {
    c = (uint128)q * (uint128)fd_bls_field_modulus_limbs[i] + (c>>64);
    ulong t  = (ulong)c;
    ulong si = sum[i];
    ulong d  = si - t - borrow;
    borrow   = (ulong)( (si < t) | ((si - t) < borrow) );
    out[i]   = d;
  }
  /* The top limb of sum - q*p is zero (result < 2p < 2^382). */
  if( uint384_ge( out, fd_bls_field_modulus_limbs ) ) uint384_sub( out, fd_bls_field_modulus_limbs );
}

void
fd_bls_fp_reduce_wide( fd_bls_fp_t *            out,
                       fd_bls_fp_wide_t const * in ) {
  reduce_wide_inner( out, in, 1 );
}

/* This is reduce_wide_inner interleaved across cnt values: reduce X/R in
   M, use that quotient to finish the N reduction, then reconstruct M.

   Both 8x8 CRNS matrix products are evaluated with one operand broadcast
   from memory (a vpbroadcastq m64 folds into the load ports on Zen 4,
   leaving the IFMA pipe as the only busy vector port).  The residue rows
   are stored once and reloaded through a laundered pointer so the compiler
   cannot "forward" the store into lane extractions (vpermq/vpextrq), which
   would compete with IFMA for the vector ALUs.  For small batches the
   cyclic register-only form of the M->N map is used instead: there the
   loop is latency bound and the store/reload round trip is exposed. */
static __attribute__((always_inline)) inline void
reduce_wide_batch_impl( fd_bls_fp_t *            out,
                        fd_bls_fp_wide_t const * in,
                        int                      cnt,
                        uint                     scale ) {
  wwv_t hi[12], lo[12];
  wwv_t mod1  = wwv_ld( fd_bls_m1 );
  wwv_t mod2  = wwv_ld( fd_bls_m2 );
  wwv_t mont1 = wwv_ld( fd_bls_m1_mont );
  wwv_t mont2 = wwv_ld( fd_bls_m2_mont );
  wwv_t t1    = wwv_ld( fd_bls_m1_t );
  wwv_t t2    = wwv_ld( fd_bls_m2_t );

  if( cnt<=4 ) {
    wwv_t cur[12];
    wwv_t shift = wwv( 7UL, 0UL, 1UL, 2UL, 3UL, 4UL, 5UL, 6UL );
    for( int j=0; j<cnt; j++ ) {
      cur[j] = fd_bls_rns_normalize( fd_bls_rns_mont_reduce_wide_raw( in[j].m1_hi, in[j].m1_lo, mod1, mont1 ), t1 ); /* cur_j=X_j/R in M. */
      hi[j]  = in[j].m2_hi; /* hi_j:lo_j starts as X_j in N. */
      lo[j]  = in[j].m2_lo;
    }
    for( int d=0; d<8; d++ ) {
      wwv_t row = wwv_ld( fd_bls_r1_perm[d] );
      for( int j=0; j<cnt; j++ ) {
        if( d ) cur[j] = wwv_permute( shift, cur[j] ); /* Rotate to M residue j-d.             */
        hi[j] = wwv_madd52hi( hi[j], row, cur[j] );   /* Add cyclic M->N correction, high half. */
        lo[j] = wwv_madd52lo( lo[j], row, cur[j] );   /* Add cyclic M->N correction, low half.  */
      }
    }
  } else {
    ulong cur[12][8] __attribute__((aligned(64)));
    for( int j=0; j<cnt; j++ ) {
      wwv_st( cur[j], fd_bls_rns_normalize( fd_bls_rns_mont_reduce_wide_raw( in[j].m1_hi, in[j].m1_lo, mod1, mont1 ), t1 ) ); /* cur_j=X_j/R in M. */
      hi[j] = in[j].m2_hi; /* hi_j:lo_j starts as X_j in N. */
      lo[j] = in[j].m2_lo;
    }
    ulong (* volatile cur_launder)[8] = cur;
    ulong (* curl)[8] = cur_launder;
    for( int i=0; i<8; i++ ) {
      wwv_t row = wwv_ld( fd_bls_r1_mat[i] );
      for( int j=0; j<cnt; j++ ) {
        wwv_t s = wwv_bcast( curl[j][i] );          /* s lanes = M residue i.                 */
        hi[j] = wwv_madd52hi( hi[j], row, s );      /* Add M->N correction, high half.        */
        lo[j] = wwv_madd52lo( lo[j], row, s );      /* Add M->N correction, low half.         */
      }
    }
  }

  ulong scalar[12][8] __attribute__((aligned(64)));
  for( int j=0; j<cnt; j++ ) {
    wwv_t x = fd_bls_rns_mont_reduce_wide_normalized( hi[j], lo[j], mod2, mont2, t2 ); /* Reduced X_j/R in N. */
    wwv_st( scalar[j], x );         /* scalar_j,i = N residue i (unscaled; the M map applies any scale). */
    if( scale!=1U ) {               /* Cyclotomic squaring post-scales by 3 or 6. */
      wwv_t x3 = wwv_add( wwv_add( x, x ), x );
      x = fd_bls_rns_normalize( scale==3U ? x3 : wwv_add( x3, x3 ), t2 );
    }
    out[j].m2 = x;
    hi[j] = wwv_zero();             /* hi_j:lo_j = 0 before N->M CRNS.   */
    lo[j] = wwv_zero();
  }
  ulong (* volatile scalar_launder)[8] = scalar;
  ulong (* sl)[8] = scalar_launder;
  ulong const (* r2_mat)[8]   = scale==1U ? fd_bls_r2_mat              : scale==3U ? fd_bls_r2_mat3              : fd_bls_r2_mat6;
  ulong const * r2_corr       = scale==1U ? fd_bls_r2_correction       : scale==3U ? fd_bls_r2_correction3       : fd_bls_r2_correction6;
  ulong const (* r2_khi)[8]   = scale==1U ? fd_bls_r2_khi              : scale==3U ? fd_bls_r2_khi3              : fd_bls_r2_khi6;
  uint128 k_raw[12] = {0};
  for( int i=0; i<8; i++ ) {
    wwv_t row = wwv_ld( r2_mat[i] );
    for( int j=0; j<cnt; j++ ) {
      wwv_t s = wwv_bcast( sl[j][i] );                                   /* s lanes = N residue i.           */
      hi[j] = wwv_madd52hi( hi[j], row, s );                            /* CRT sum += s*A_i, high half.     */
      lo[j] = wwv_madd52lo( lo[j], row, s );                            /* CRT sum += s*A_i, low half.      */
      k_raw[j] += (uint128)((ulong volatile const *)scalar[j])[i] * (uint128)fd_bls_r2_sqe[i]; /* Fixed-point quotient numerator. */
    }
  }
  wwv_t corr       = wwv_ld( r2_corr );
  for( int j=0; j<cnt; j++ ) {
    ulong kk = (ulong)(k_raw[j] >> 64);                                /* k=floor(dot(s,f)/2^64) < 2^54.      */
    wwv_t k  = wwv_bcast( kk );
    hi[j] = wwv_madd52hi( hi[j], corr, k );                          /* Add low digit of k*correction.      */
    lo[j] = wwv_madd52lo( lo[j], corr, k );
    lo[j] = wwv_add( lo[j], wwv_ld( r2_khi[ kk>>52 ] ) );            /* Add floor(k/R)*shifted correction (< R, no high digit). */
    out[j].m1 = fd_bls_rns_mont_reduce_wide_normalized( hi[j], lo[j], mod1, mont1, t1 ); /* Matching M residues. */
  }
}

void
fd_bls_fp_reduce_wide_batch2( fd_bls_fp_t *            out,
                              fd_bls_fp_wide_t const * in ) {
  reduce_wide_batch_impl( out, in, 2, 1U );
}

void
fd_bls_fp_reduce_wide_batch3( fd_bls_fp_t *            out,
                              fd_bls_fp_wide_t const * in ) {
  reduce_wide_batch_impl( out, in, 3, 1U );
}

void
fd_bls_fp_reduce_wide_batch4( fd_bls_fp_t *            out,
                              fd_bls_fp_wide_t const * in ) {
  reduce_wide_batch_impl( out, in, 4, 1U );
}

void
fd_bls_fp_reduce_wide_batch5( fd_bls_fp_t *            out,
                              fd_bls_fp_wide_t const * in ) {
  reduce_wide_batch_impl( out, in, 5, 1U );
}

void
fd_bls_fp_reduce_wide_batch6( fd_bls_fp_t *            out,
                              fd_bls_fp_wide_t const * in ) {
  reduce_wide_batch_impl( out, in, 6, 1U );
}

void
fd_bls_fp_reduce_wide_batch8( fd_bls_fp_t *            out,
                              fd_bls_fp_wide_t const * in ) {
  reduce_wide_batch_impl( out, in, 8, 1U );
}

void
fd_bls_fp_reduce_wide_batch9( fd_bls_fp_t *            out,
                              fd_bls_fp_wide_t const * in ) {
  reduce_wide_batch_impl( out, in, 9, 1U );
}

void
fd_bls_fp_reduce_wide_scaled_batch6( fd_bls_fp_t *            out,
                                     fd_bls_fp_wide_t const * in,
                                     uint                     scale ) {
  /* Cyclotomic squaring produces independent expressions whose
     post-reduction scale is 3 for the first half-Fp12 and 6 for the
     second; the scale is applied to the reduced N residues before the
     N->M reconstruction. */
  if( scale==3U ) reduce_wide_batch_impl( out, in, 6, 3U );
  else            reduce_wide_batch_impl( out, in, 6, 6U );
}

void
fd_bls_fp_reduce_wide_batch10( fd_bls_fp_t *            out,
                               fd_bls_fp_wide_t const * in ) {
  reduce_wide_batch_impl( out, in, 10, 1U );
}

void
fd_bls_fp_mul( fd_bls_fp_t *       out,
               fd_bls_fp_t const * a,
               fd_bls_fp_t const * b ) {
  fd_bls_fp_wide_t w;
  w.m1_hi = wwv_madd52hi( wwv_zero(), a->m1, b->m1 ); /* w_M = a_M*b_M, high radix-R half. */
  w.m1_lo = wwv_madd52lo( wwv_zero(), a->m1, b->m1 ); /* w_M = a_M*b_M, low radix-R half.  */
  w.m2_hi = wwv_madd52hi( wwv_zero(), a->m2, b->m2 ); /* w_N = a_N*b_N, high radix-R half. */
  w.m2_lo = wwv_madd52lo( wwv_zero(), a->m2, b->m2 ); /* w_N = a_N*b_N, low radix-R half.  */
  reduce_wide_inner( out, &w, 0 );                    /* out = a*b in rotated RNS Montgomery form. */
}

void
fd_bls_fp_sqr( fd_bls_fp_t *       out,
               fd_bls_fp_t const * a ) {
  fd_bls_fp_mul( out, a, a );
}

static inline wwv_t
canonical_residue( wwv_t x,
                   wwv_t modulus ) {
  return wwv_min( x, wwv_sub( x, modulus ) );
}

/* A standard reduced RNS value occupies less than 40*p of redundant RNS
   range, so equal field values differ by k*p with |k|<=40.  The residue
   difference a-b is compared against the canonical residues of the 81
   encodings of k*p: lane 0 of base M selects the single candidate k (the
   generator asserts these lane values are distinct), and one full-row
   comparison in both bases confirms it.  This accepts exactly the pairs the
   former bidirectional +p stepping scan accepted. */
int
fd_bls_fp_equal( fd_bls_fp_t const * a,
                 fd_bls_fp_t const * b ) {
  wwv_t mod1 = wwv_ld( fd_bls_m1 );
  wwv_t mod2 = wwv_ld( fd_bls_m2 );
  wwv_t a1   = canonical_residue( a->m1, mod1 );
  wwv_t a2   = canonical_residue( a->m2, mod2 );
  wwv_t b1   = canonical_residue( b->m1, mod1 );
  wwv_t b2   = canonical_residue( b->m2, mod2 );
  wwv_t d1   = canonical_residue( wwv_sub( wwv_add( a1, mod1 ), b1 ), mod1 ); /* (a-b) mod m1_i in [0,m1_i) */
  wwv_t d2   = canonical_residue( wwv_sub( wwv_add( a2, mod2 ), b2 ), mod2 ); /* (a-b) mod m2_i in [0,m2_i) */

  wwv_t lane0 = wwv_permute( wwv_zero(), d1 ); /* broadcast d1 lane 0 */
  int   idx   = -1;
  for( int r=0; r<(int)(sizeof(fd_bls_zero_lane0)/sizeof(fd_bls_zero_lane0[0])); r++ ) {
    int hit = wwv_eq( lane0, wwv_ld( fd_bls_zero_lane0[r] ) );
    if( hit ) { idx = 8*r + fd_uint_find_lsb( (uint)hit ); break; }
  }
  if( FD_LIKELY( idx<0 ) ) return 0;
  return ( wwv_eq( d1, wwv_ld( fd_bls_zero_m1[idx] ) )==0xff ) &
         ( wwv_eq( d2, wwv_ld( fd_bls_zero_m2[idx] ) )==0xff );
}


/* Split one 6-limb/64-bit blst Montgomery value into 8 50-bit digits. */
void
fd_bls_fp_digits50( ulong dst[8], ulong const v[6] ) {
  dst[0] = v[0] & FD_BLS_MASK50;
  dst[1] = ((v[0] >> 50) | (v[1] << 14)) & FD_BLS_MASK50;
  dst[2] = ((v[1] >> 36) | (v[2] << 28)) & FD_BLS_MASK50;
  dst[3] = ((v[2] >> 22) | (v[3] << 42)) & FD_BLS_MASK50;
  dst[4] = (v[3] >> 8) & FD_BLS_MASK50;
  dst[5] = ((v[3] >> 58) | (v[4] << 6)) & FD_BLS_MASK50;
  dst[6] = ((v[4] >> 44) | (v[5] << 20)) & FD_BLS_MASK50;
  dst[7] = (v[5] >> 30) & FD_BLS_MASK50;
}

/* Shared fused-entry core: consumes cnt pre-split 50-bit digit rows. */
void
fd_bls_fp_from_mont_core( fd_bls_fp_t * out,
                          ulong const * d,
                          int           cnt ) {
  wwv_t hi[ FD_BLS_G1_ENTRY_MAX ], lo[ FD_BLS_G1_ENTRY_MAX ];
  uint128 k_raw[ FD_BLS_G1_ENTRY_MAX ] = { 0 };
  for( int e=0; e<cnt; e++ ) { hi[e]=wwv_zero(); lo[e]=wwv_zero(); }

  for( int i=0; i<8; i++ ) {
    wwv_t row = wwv_ld( fd_bls_to_mont_mat[i] );
    for( int e=0; e<cnt; e++ ) {
      wwv_t s = wwv_bcast( d[ 8*e + i ] );
      hi[e] = wwv_madd52hi( hi[e], row, s );
      lo[e] = wwv_madd52lo( lo[e], row, s );
      k_raw[e] += (uint128)d[ 8*e + i ] * (uint128)fd_bls_to_mont_sqe[i];
    }
  }
  wwv_t corr = wwv_ld( fd_bls_to_mont_correction );
  for( int e=0; e<cnt; e++ ) {
    /* second-digit correction, as in matrix_accumulate */
    wwv_t ks = wwv_bcast( (ulong)(k_raw[e] >> 64) );
    hi[e] = wwv_madd52hi( hi[e], corr, ks );
    lo[e] = wwv_madd52lo( lo[e], corr, ks );
    ks = wwv_shr( ks, 52 );
    hi[e] = wwv_madd52lo( hi[e], corr, ks );
    wwv_t carry = wwv_madd52hi( wwv_zero(), corr, ks );
    hi[e] = wwv_add( hi[e], wwv_shl( carry, 52 ) );
    out[e].m2 = fd_bls_rns_mont_reduce_wide_normalized( hi[e], lo[e],
                    wwv_ld( fd_bls_m2 ), wwv_ld( fd_bls_m2_mont ), wwv_ld( fd_bls_m2_t ) );
    out[e].m1 = fd_bls_rns_expand_m2_to_m1( out[e].m2 );
  }
}

void
fd_bls_fp_from_mont_batch( fd_bls_fp_t * out,
                    ulong const * in,
                    int            cnt ) {
  ulong d[ FD_BLS_G1_ENTRY_MAX ][ 8 ] __attribute__((aligned(64)));
  for( int e=0; e<cnt; e++ ) fd_bls_fp_digits50( d[e], &in[ 6*e ] );
  fd_bls_fp_from_mont_core( out, &d[0][0], cnt );
}

/* --- variable-time base-field inversion ---

   Bernstein-Yang safegcd with 62-step variable-time divstep batches over
   signed 62-bit limbs (the libsecp256k1 modinv64_var design, specialized
   to the BLS12-381 base field).  Only public data (point coordinates,
   pairing values) is ever inverted here, so data-dependent timing is
   acceptable.  About 1.7us versus ~3us for the blst round trip. */

#define M62 ((ulong)(-1) >> 2)
typedef struct { long v[7]; } fd_bls_s62_t;      /* sum v[i]*2^(62i), v[0..5] in [0,2^62), v[6] signed (top) */

static const fd_bls_s62_t P62 = {{ 0x39feffffffffaaabL, 0x3aaffffac54ffffeL, 0x330d2a0f6b0f6241L, 0x1dd2e13ce144afd9L,
                            0x1ba7b6434bacd764L, 0x0447a8e5ff9a692cL, 0x1a0L }};
#define PINV62 (0x360c000300030003UL)

typedef struct { long u, v, q, r; } fd_bls_trans_t;

static inline int ctz64( ulong x ) { return __builtin_ctzl( x ); }

static long
divsteps_62_var( long eta, ulong f0, ulong g0, fd_bls_trans_t * t ) {
  ulong u = 1, v = 0, q = 0, r = 1;
  ulong f = f0, g = g0, m;
  uint w;
  int i = 62, limit, zeros;
  for(;;) {
    zeros = ctz64( g | ((~0UL) << i) );
    g >>= zeros; u <<= zeros; v <<= zeros; eta -= zeros; i -= zeros;
    if( i==0 ) break;
    if( eta<0 ) {
      ulong tmp;
      eta = -eta;
      tmp = f; f = g; g = -tmp;
      tmp = u; u = q; q = -tmp;
      tmp = v; v = r; r = -tmp;
      limit = ((int)eta + 1) > i ? i : ((int)eta + 1);
      m = ((~0UL) >> (64 - limit)) & 63U;
      w = (uint)((f * g * (f * f - 2)) & m);
    } else {
      limit = ((int)eta + 1) > i ? i : ((int)eta + 1);
      m = ((~0UL) >> (64 - limit)) & 15U;
      w = (uint)(f + (((f + 1) & 4) << 1));
      w = (uint)((-(ulong)w * g) & m);
    }
    g += f * w; q += u * w; r += v * w;
  }
  t->u = (long)u; t->v = (long)v; t->q = (long)q; t->r = (long)r;
  return eta;
}

/* f,g <- (t*[f,g]) / 2^62, len limbs (len<=7). */
static void
update_fg_var( int len, fd_bls_s62_t * f, fd_bls_s62_t * g, fd_bls_trans_t const * t ) {
  long u = t->u, v = t->v, q = t->q, r = t->r;
  int128 cf, cg;
  long fi = f->v[0], gi = g->v[0];
  cf = (int128)u * fi + (int128)v * gi;
  cg = (int128)q * fi + (int128)r * gi;
  cf >>= 62; cg >>= 62;
  for( int i=1; i<len; i++ ) {
    fi = f->v[i]; gi = g->v[i];
    cf += (int128)u * fi + (int128)v * gi;
    cg += (int128)q * fi + (int128)r * gi;
    f->v[i-1] = (long)((ulong)cf & M62); cf >>= 62;
    g->v[i-1] = (long)((ulong)cg & M62); cg >>= 62;
  }
  f->v[len-1] = (long)cf;
  g->v[len-1] = (long)cg;
}

/* d,e <- (t*[d,e] + [md,me]*p) / 2^62, keeping d,e in (-2p, p). */
static void
update_de( fd_bls_s62_t * d, fd_bls_s62_t * e, fd_bls_trans_t const * t ) {
  long u = t->u, v = t->v, q = t->q, r = t->r;
  long sd = d->v[6] >> 63, se = e->v[6] >> 63;
  long md = (u & sd) + (v & se), me = (q & sd) + (r & se);
  long di = d->v[0], ei = e->v[0];
  int128 cd = (int128)u * di + (int128)v * ei;
  int128 ce = (int128)q * di + (int128)r * ei;
  md -= (long)((PINV62 * (ulong)cd + (ulong)md) & M62);
  me -= (long)((PINV62 * (ulong)ce + (ulong)me) & M62);
  cd += (int128)P62.v[0] * md;
  ce += (int128)P62.v[0] * me;
  cd >>= 62; ce >>= 62;
  for( int i=1; i<7; i++ ) {
    di = d->v[i]; ei = e->v[i];
    cd += (int128)u * di + (int128)v * ei + (int128)P62.v[i] * md;
    ce += (int128)q * di + (int128)r * ei + (int128)P62.v[i] * me;
    d->v[i-1] = (long)((ulong)cd & M62); cd >>= 62;
    e->v[i-1] = (long)((ulong)ce & M62); ce >>= 62;
  }
  d->v[6] = (long)cd;
  e->v[6] = (long)ce;
}

/* Reduce a (in (-2p,p)) times sign to [0,p). */
static void
normalize( fd_bls_s62_t * r, long sign ) {
  long r0=r->v[0], r1=r->v[1], r2=r->v[2], r3=r->v[3], r4=r->v[4], r5=r->v[5], r6=r->v[6];
  long cond_add, cond_negate;
  cond_add = r6 >> 63;
  r0 += P62.v[0] & cond_add; r1 += P62.v[1] & cond_add; r2 += P62.v[2] & cond_add; r3 += P62.v[3] & cond_add;
  r4 += P62.v[4] & cond_add; r5 += P62.v[5] & cond_add; r6 += P62.v[6] & cond_add;
  cond_negate = sign >> 63;
  r0 = (r0 ^ cond_negate) - cond_negate; r1 = (r1 ^ cond_negate) - cond_negate; r2 = (r2 ^ cond_negate) - cond_negate;
  r3 = (r3 ^ cond_negate) - cond_negate; r4 = (r4 ^ cond_negate) - cond_negate; r5 = (r5 ^ cond_negate) - cond_negate;
  r6 = (r6 ^ cond_negate) - cond_negate;
  r1 += r0 >> 62; r0 &= (long)M62; r2 += r1 >> 62; r1 &= (long)M62; r3 += r2 >> 62; r2 &= (long)M62;
  r4 += r3 >> 62; r3 &= (long)M62; r5 += r4 >> 62; r4 &= (long)M62; r6 += r5 >> 62; r5 &= (long)M62;
  cond_add = r6 >> 63;
  r0 += P62.v[0] & cond_add; r1 += P62.v[1] & cond_add; r2 += P62.v[2] & cond_add; r3 += P62.v[3] & cond_add;
  r4 += P62.v[4] & cond_add; r5 += P62.v[5] & cond_add; r6 += P62.v[6] & cond_add;
  r1 += r0 >> 62; r0 &= (long)M62; r2 += r1 >> 62; r1 &= (long)M62; r3 += r2 >> 62; r2 &= (long)M62;
  r4 += r3 >> 62; r3 &= (long)M62; r5 += r4 >> 62; r4 &= (long)M62; r6 += r5 >> 62; r5 &= (long)M62;
  r->v[0]=r0; r->v[1]=r1; r->v[2]=r2; r->v[3]=r3; r->v[4]=r4; r->v[5]=r5; r->v[6]=r6;
}

static void
to_s62( fd_bls_s62_t * r, ulong const a[6] ) {
  r->v[0] = (long)( a[0] & M62 );
  r->v[1] = (long)( ((a[0] >> 62) | (a[1] <<  2)) & M62 );
  r->v[2] = (long)( ((a[1] >> 60) | (a[2] <<  4)) & M62 );
  r->v[3] = (long)( ((a[2] >> 58) | (a[3] <<  6)) & M62 );
  r->v[4] = (long)( ((a[3] >> 56) | (a[4] <<  8)) & M62 );
  r->v[5] = (long)( ((a[4] >> 54) | (a[5] << 10)) & M62 );
  r->v[6] = (long)(   a[5] >> 52 );
}

static void
from_s62( ulong r[6], fd_bls_s62_t const * a ) {
  ulong const * v = (ulong const *)a->v;
  r[0] =  v[0]        | (v[1] << 62);
  r[1] = (v[1] >>  2) | (v[2] << 60);
  r[2] = (v[2] >>  4) | (v[3] << 58);
  r[3] = (v[3] >>  6) | (v[4] << 56);
  r[4] = (v[4] >>  8) | (v[5] << 54);
  r[5] = (v[5] >> 10) | (v[6] << 52);
}

/* out = x^-1 mod p (x canonical, nonzero).  out=0 for x=0. */
void
fd_bls_fp_inv_canon( ulong out[6], ulong const x[6] ) {
  fd_bls_s62_t d = {{0}}, e = {{1}}, f = P62, g;
  to_s62( &g, x );
  long eta = -1;
  int len = 7;
  for(;;) {
    fd_bls_trans_t t;
    eta = divsteps_62_var( eta, (ulong)f.v[0], (ulong)g.v[0], &t );
    update_de( &d, &e, &t );
    update_fg_var( len, &f, &g, &t );
    if( g.v[0]==0 ) {
      long cond = 0;
      for( int j=1; j<len; j++ ) cond |= g.v[j];
      if( cond==0 ) break;
    }
    long fn = f.v[len-1], gn = g.v[len-1];
    long cond = ((long)len - 2) >> 63;
    cond |= fn ^ (fn >> 63);
    cond |= gn ^ (gn >> 63);
    if( cond==0 ) {
      f.v[len-2] |= (long)((ulong)fn << 62);
      g.v[len-2] |= (long)((ulong)gn << 62);
      --len;
    }
  }
  normalize( &d, f.v[len-1] );
  from_s62( out, &d );
}
