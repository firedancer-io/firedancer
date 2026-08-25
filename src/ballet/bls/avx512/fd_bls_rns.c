#include "fd_bls_rns.h"

#if FD_HAS_AVX512

#include "fd_bls_constants.h"

#define FD_BLS_MASK50 ((ulong)((1UL<<50)-1UL))

static ulong const fd_bls_field_modulus[6] = {
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
reduce_512( ulong       out[6],
              ulong const in[8] ) {
  /* Bitwise Horner reduction: after bit b, r is the processed high prefix
     modulo p, so the next step is r<-(2r+in_b) mod p. */
  ulong r[6] = {0UL};
  for( int bit=511; bit>=0; bit-- ) {
    ulong carry = (in[(uint)bit>>6] >> ((uint)bit&63U)) & 1UL; /* carry=in_b. */
    for( int i=0; i<6; i++ ) {
      ulong next = r[i]>>63;       /* next is the carry into limb i+1. */
      r[i] = (r[i]<<1) | carry;    /* r<-2r+in_b, limb i.              */
      carry = next;
    }
    if( uint384_ge( r, fd_bls_field_modulus ) ) uint384_sub( r, fd_bls_field_modulus ); /* r<-(2r+in_b) mod p. */
  }
  for( int i=0; i<6; i++ ) out[i] = r[i]; /* out=in mod p. */
}

static inline wwv_t
normalize( wwv_t x,
           wwv_t t ) {
  /* For m_i=2^50-t_i, fold x=x_lo+2^50*x_hi to x_lo+t_i*x_hi (mod m_i). */
  wwv_t lo = wwv_and( x, wwv_bcast( (ulong)FD_BLS_MASK50 ) ); /* lo  = x mod 2^50.             */
  wwv_t hi = wwv_shr( x, 50 );                               /* hi  = floor(x/2^50).          */
  return wwv_madd52lo( lo, hi, t );                           /* out = lo+hi*t = x (mod m_i). */
}

/* Montgomery reduction with R=2^52 and 50-bit moduli.  With
   q=lo*m^-1 (mod R), the result hi+m-floor(q*m/R) is X/R (mod m).
   The redundant two-bit headroom makes the final normalization branchless. */
static inline wwv_t
mont_reduce_wide_raw( wwv_t hi,
                      wwv_t lo,
                      wwv_t moduli,
                      wwv_t mont ) {
  hi = wwv_add( hi, wwv_shr( lo, 52 ) );             /* hi = floor(X/R), including carry from lo. */
  wwv_t q   = wwv_madd52lo( wwv_zero(), lo, mont );  /* q  = lo*m^-1 mod R.                        */
  wwv_t neg = wwv_neg( moduli );                     /* neg= -m.                                   */
  wwv_t hn  = wwv_madd52hi( neg, q, moduli );        /* hn = -m+floor(q*m/R).                      */
  return wwv_sub( hi, hn );                          /* out= hi+m-floor(q*m/R) = X/R (mod m).      */
}

static inline wwv_t
mont_reduce_wide_normalized( wwv_t hi,
                             wwv_t lo,
                             wwv_t moduli,
                             wwv_t mont,
                             wwv_t t ) {
  return normalize( mont_reduce_wide_raw( hi, lo, moduli, mont ), t );
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
  uint128 k_raw = (uint128)0;                        /* kRaw starts the fixed-point CRT quotient.  */
  for( int i=0; i<8; i++ ) {
    wwv_t row    = wwv_ld( mat[i] );                              /* row_j = A_ij.                  */
    wwv_t scalar = wwv_bcast( (ulong)s[i] );                      /* scalar_j = s_i.                */
    *hi = wwv_madd52hi( *hi, row, scalar );                       /* accHi_j += floor(s_i*A_ij/R).  */
    *lo = wwv_madd52lo( *lo, row, scalar );                       /* accLo_j += s_i*A_ij mod R.     */
    k_raw += (uint128)s[i] * (uint128)sqe[i];                      /* kRaw += s_i*f_i, Appendix A's fixed-point term. */
  }

  ulong k = (ulong)(k_raw >> 64);                         /* k=floor(dot(s,f)/2^64), the CRT quotient estimate. */
  wwv_t corr = wwv_ld( correction );                      /* corr_j cancels k times source base.  */
  wwv_t ks   = wwv_bcast( (ulong)k );                     /* ks_j=k for all destination lanes.    */
  *hi = wwv_madd52hi( *hi, corr, ks );                    /* accHi_j += floor(k*corr_j/R).         */
  *lo = wwv_madd52lo( *lo, corr, ks );                    /* accLo_j += k*corr_j mod R.            */

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

static inline wwv_t
expand_m2_to_m1( wwv_t m2 ) {
  /* Algorithm 2, line 4: CRNS from N back to M, with its scale folded in. */
  wwv_t hi = wwv_zero();                                  /* hi:lo = 0 before CRT reconstruction. */
  wwv_t lo = wwv_zero();
  matrix_accumulate( m2, fd_bls_r2_mat, fd_bls_r2_sqe, fd_bls_r2_correction,
                     fd_bls_r2_correction_shift, &hi, &lo );
  return mont_reduce_wide_normalized( hi, lo, wwv_ld( fd_bls_m1 ), wwv_ld( fd_bls_m1_mont ), wwv_ld( fd_bls_m1_t ) ); /* N residues -> M residues. */
}

static inline wwv_t
reduce_wide_m2( fd_bls_fp_wide_t const * in,
                int                        normalize_m1 ) {
  /* ready<MAX_ADD> sees a product of two standard (bound-2) inputs.  Its
     first reduction deliberately keeps the [0,2m) result.  Reducing it once
     more would alter the no-k quotient estimate in the following r1 step. */
  wwv_t m1 = mont_reduce_wide_raw( in->m1_hi, in->m1_lo,
                                  wwv_ld( fd_bls_m1 ), wwv_ld( fd_bls_m1_mont ) ); /* m1 = X/R in base M. */
  if( normalize_m1 ) m1 = normalize( m1, wwv_ld( fd_bls_m1_t ) );                 /* m1 <- m1 mod each M_i. */

  /* Algorithm 2, line 3: the cyclic CRNS map changes M to N and accumulates
     the Montgomery quotient term directly into the unreduced N product. */
  wwv_t hi    = in->m2_hi;                          /* Start with X represented in base N. */
  wwv_t lo    = in->m2_lo;
  wwv_t cur   = m1;                                 /* cur_j supplies cyclic M residues.  */
  wwv_t shift = wwv( 7UL, 0UL, 1UL, 2UL, 3UL, 4UL, 5UL, 6UL );
  for( int d=0; d<8; d++ ) {
    if( d ) cur = wwv_permute( shift, cur );         /* cur_j = m1_{j-d mod 8}.             */
    wwv_t row = wwv_ld( fd_bls_r1_perm[d] );         /* row_j = cyclic CRNS coefficient.   */
    hi = wwv_madd52hi( hi, row, cur );               /* X_N += row_j*cur_j, high IFMA half. */
    lo = wwv_madd52lo( lo, row, cur );               /* X_N += row_j*cur_j, low IFMA half.  */
  }
  return mont_reduce_wide_normalized( hi, lo,
                                     wwv_ld( fd_bls_m2 ), wwv_ld( fd_bls_m2_mont ), wwv_ld( fd_bls_m2_t ) );
}

static inline void
reduce_wide_inner( fd_bls_fp_t *            out,
                   fd_bls_fp_wide_t const * in,
                   int                        normalize_m1 ) {
  out->m2 = reduce_wide_m2( in, normalize_m1 ); /* First obtain reduced residues in N. */
  out->m1 = expand_m2_to_m1( out->m2 );        /* Reconstruct the matching M residues. */
}

/* Cyclotomic squaring produces six independent expressions with the same
   post-reduction scale.  Keep the six base conversions interleaved so the
   eight fixed matrix rows are loaded once per half-Fp12, matching the
   batch-of-six schedule. */
static __attribute__((always_inline)) inline void
fd_bls_fp_reduce_wide_scaled_batch6( fd_bls_fp_t             out[6],
                                       fd_bls_fp_wide_t const   in[6],
                                       uint                       scale ) {
  wwv_t cur[6], hi[6], lo[6];
  wwv_t mod1  = wwv_ld( fd_bls_m1 );
  wwv_t mod2  = wwv_ld( fd_bls_m2 );
  wwv_t mont1 = wwv_ld( fd_bls_m1_mont );
  wwv_t mont2 = wwv_ld( fd_bls_m2_mont );
  wwv_t t1    = wwv_ld( fd_bls_m1_t );
  wwv_t t2    = wwv_ld( fd_bls_m2_t );
  wwv_t shift = wwv( 7UL, 0UL, 1UL, 2UL, 3UL, 4UL, 5UL, 6UL );

  for( int j=0; j<6; j++ ) {
    cur[j] = normalize( mont_reduce_wide_raw( in[j].m1_hi, in[j].m1_lo, mod1, mont1 ), t1 ); /* cur_j = X_j/R in M. */
    hi[j]  = in[j].m2_hi; /* hi_j:lo_j starts as the same X_j in N. */
    lo[j]  = in[j].m2_lo;
  }
  for( int d=0; d<8; d++ ) {
    wwv_t row = wwv_ld( fd_bls_r1_perm[d] );
    for( int j=0; j<6; j++ ) {
      if( d ) cur[j] = wwv_permute( shift, cur[j] ); /* cur lane rotates to the next cyclic M residue. */
      hi[j] = wwv_madd52hi( hi[j], row, cur[j] );   /* Add CRNS correction, high IFMA half.           */
      lo[j] = wwv_madd52lo( lo[j], row, cur[j] );   /* Add CRNS correction, low IFMA half.            */
    }
  }
  for( int j=0; j<6; j++ ) {
    wwv_t x  = mont_reduce_wide_normalized( hi[j], lo[j], mod2, mont2, t2 ); /* x  = reduced X_j/R in N. */
    wwv_t x2 = wwv_add( x, x );                                             /* x2 = 2x.                  */
    wwv_t x3 = wwv_add( x2, x );                                            /* x3 = 3x.                  */
    wwv_t xs = scale==3U ? x3 : wwv_add( x3, x3 );                          /* xs = scale*x, scale=3 or 6. */
    out[j].m2 = normalize( xs, t2 );                                        /* Store scale*x modulo N_i.  */
  }

  ulong scalar[6][8] __attribute__((aligned(64)));
  uint128 k_raw[6] = {0};
  for( int j=0; j<6; j++ ) {
    wwv_st( scalar[j], out[j].m2 ); /* scalar_j,i = scaled N residue i. */
    hi[j] = wwv_zero();             /* hi_j:lo_j = 0 before N->M CRT.   */
    lo[j] = wwv_zero();
  }
  for( int i=0; i<8; i++ ) {
    wwv_t row = wwv_ld( fd_bls_r2_mat[i] );
    for( int j=0; j<6; j++ ) {
      wwv_t s = wwv_bcast( (ulong)scalar[j][i] );                         /* s lanes = N residue i.              */
      hi[j] = wwv_madd52hi( hi[j], row, s );                             /* CRT sum += s*A_i, high IFMA half.   */
      lo[j] = wwv_madd52lo( lo[j], row, s );                             /* CRT sum += s*A_i, low IFMA half.    */
      k_raw[j] += (uint128)scalar[j][i] * (uint128)fd_bls_r2_sqe[i];      /* Fixed-point quotient numerator.    */
    }
  }
  wwv_t corr       = wwv_ld( fd_bls_r2_correction );
  wwv_t corr_shift = wwv_ld( fd_bls_r2_correction_shift );
  for( int j=0; j<6; j++ ) {
    wwv_t k = wwv_bcast( (ulong)(k_raw[j] >> 64) );                  /* k=floor(dot(s,f)/2^64).             */
    hi[j] = wwv_madd52hi( hi[j], corr, k );                          /* Add low digit of k*correction.      */
    lo[j] = wwv_madd52lo( lo[j], corr, k );
    k = wwv_shr( k, 52 );                                           /* k=floor(k/R), remaining high digit. */
    hi[j] = wwv_madd52hi( hi[j], corr_shift, k );                    /* Add high digit of k*correction.     */
    lo[j] = wwv_madd52lo( lo[j], corr_shift, k );
    out[j].m1 = mont_reduce_wide_normalized( hi[j], lo[j], mod1, mont1, t1 ); /* Complete N->M conversion. */
  }
}

void
fd_bls_fp_from_uint64( fd_bls_fp_t * out,
                         ulong const      in[6] ) {
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
  out->m2 = mont_reduce_wide_normalized( hi, lo,
                                        wwv_ld( fd_bls_m2 ), wwv_ld( fd_bls_m2_mont ), wwv_ld( fd_bls_m2_t ) ); /* radix digits -> N residues. */
  out->m1 = expand_m2_to_m1( out->m2 ); /* Complete the redundant representation with matching M residues. */
}

void
fd_bls_fp_to_uint64( ulong                 out[6],
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

  reduce_512( out, sum );
}

void
fd_bls_fp_reduce_wide( fd_bls_fp_t *            out,
                         fd_bls_fp_wide_t const * in ) {
  reduce_wide_inner( out, in, 1 );
}

static __attribute__((always_inline)) inline void
reduce_wide_batch_impl( fd_bls_fp_t *            out,
                        fd_bls_fp_wide_t const * in,
                        int                        cnt ) {
  /* This is reduce_wide_inner interleaved across cnt values: reduce X/R in
     M, use that quotient to finish the N reduction, then reconstruct M. */
  wwv_t cur[6], hi[6], lo[6];
  wwv_t mod1  = wwv_ld( fd_bls_m1 );
  wwv_t mod2  = wwv_ld( fd_bls_m2 );
  wwv_t mont1 = wwv_ld( fd_bls_m1_mont );
  wwv_t mont2 = wwv_ld( fd_bls_m2_mont );
  wwv_t t1    = wwv_ld( fd_bls_m1_t );
  wwv_t t2    = wwv_ld( fd_bls_m2_t );
  wwv_t shift = wwv( 7UL, 0UL, 1UL, 2UL, 3UL, 4UL, 5UL, 6UL );

  for( int j=0; j<cnt; j++ ) {
    cur[j] = normalize( mont_reduce_wide_raw( in[j].m1_hi, in[j].m1_lo, mod1, mont1 ), t1 ); /* cur_j=X_j/R in M. */
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
  for( int j=0; j<cnt; j++ )
    out[j].m2 = mont_reduce_wide_normalized( hi[j], lo[j], mod2, mont2, t2 ); /* Reduced X_j/R in N. */

  ulong scalar[6][8] __attribute__((aligned(64)));
  uint128 k_raw[6] = {0};
  for( int j=0; j<cnt; j++ ) {
    wwv_st( scalar[j], out[j].m2 ); /* scalar_j,i = N residue i.          */
    hi[j] = wwv_zero();             /* hi_j:lo_j = 0 before N->M CRNS.   */
    lo[j] = wwv_zero();
  }
  for( int i=0; i<8; i++ ) {
    wwv_t row = wwv_ld( fd_bls_r2_mat[i] );
    for( int j=0; j<cnt; j++ ) {
      wwv_t s = wwv_bcast( (ulong)scalar[j][i] );                    /* s lanes = N residue i.            */
      hi[j] = wwv_madd52hi( hi[j], row, s );                        /* CRT sum += s*A_i, high half.      */
      lo[j] = wwv_madd52lo( lo[j], row, s );                        /* CRT sum += s*A_i, low half.       */
      k_raw[j] += (uint128)scalar[j][i] * (uint128)fd_bls_r2_sqe[i]; /* Fixed-point quotient numerator.  */
    }
  }
  wwv_t corr       = wwv_ld( fd_bls_r2_correction );
  wwv_t corr_shift = wwv_ld( fd_bls_r2_correction_shift );
  for( int j=0; j<cnt; j++ ) {
    wwv_t k = wwv_bcast( (ulong)(k_raw[j] >> 64) );                  /* k=floor(dot(s,f)/2^64).             */
    hi[j] = wwv_madd52hi( hi[j], corr, k );                          /* Add low digit of k*correction.      */
    lo[j] = wwv_madd52lo( lo[j], corr, k );
    k = wwv_shr( k, 52 );                                           /* k=floor(k/R), remaining high digit. */
    hi[j] = wwv_madd52hi( hi[j], corr_shift, k );                    /* Add high digit of k*correction.     */
    lo[j] = wwv_madd52lo( lo[j], corr_shift, k );
    out[j].m1 = mont_reduce_wide_normalized( hi[j], lo[j], mod1, mont1, t1 ); /* Matching M residues. */
  }
}

static __attribute__((always_inline)) inline void
fd_bls_fp_reduce_wide_batch2( fd_bls_fp_t             out[2],
                                fd_bls_fp_wide_t const   in[2] ) {
  reduce_wide_batch_impl( out, in, 2 );
}

static __attribute__((always_inline)) inline void
fd_bls_fp_reduce_wide_batch4( fd_bls_fp_t             out[4],
                                fd_bls_fp_wide_t const   in[4] ) {
  reduce_wide_batch_impl( out, in, 4 );
}

static __attribute__((always_inline)) inline void
fd_bls_fp_reduce_wide_batch6( fd_bls_fp_t             out[6],
                                fd_bls_fp_wide_t const   in[6] ) {
  reduce_wide_batch_impl( out, in, 6 );
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

void
fd_bls_fp_add( fd_bls_fp_t *       out,
                 fd_bls_fp_t const * a,
                 fd_bls_fp_t const * b ) {
  out->m1 = normalize( wwv_add( a->m1, b->m1 ), wwv_ld( fd_bls_m1_t ) );
  out->m2 = normalize( wwv_add( a->m2, b->m2 ), wwv_ld( fd_bls_m2_t ) );
}

void
fd_bls_fp_neg( fd_bls_fp_t *       out,
                 fd_bls_fp_t const * a ) {
  /* The encoded p is zero in Fp; adding it makes p-a nonnegative per lane. */
  wwv_t m1 = wwv_ld( fd_bls_m1 );
  wwv_t m2 = wwv_ld( fd_bls_m2 );
  wwv_t x1 = wwv_add( wwv_sub( wwv_shl( m1, 1 ), a->m1 ),
                      wwv_ld( fd_bls_modulus_m1 ) );
  wwv_t x2 = wwv_add( wwv_sub( wwv_shl( m2, 1 ), a->m2 ),
                      wwv_ld( fd_bls_modulus_m2 ) );
  out->m1 = wwv_min( x1, wwv_sub( x1, m1 ) );
  out->m2 = wwv_min( x2, wwv_sub( x2, m2 ) );
}

void
fd_bls_fp_sub( fd_bls_fp_t *       out,
                 fd_bls_fp_t const * a,
                 fd_bls_fp_t const * b ) {
  fd_bls_fp_t neg_b;
  fd_bls_fp_neg( &neg_b, b );
  fd_bls_fp_add( out, a, &neg_b );
}

void
fd_bls_fp_wide_offset( fd_bls_fp_wide_t * out ) {
  out->m1_hi = wwv_ld( fd_bls_wide_offset_m1_hi );
  out->m1_lo = wwv_ld( fd_bls_wide_offset_m1_lo );
  out->m2_hi = wwv_ld( fd_bls_wide_offset_m2_hi );
  out->m2_lo = wwv_ld( fd_bls_wide_offset_m2_lo );
}

void
fd_bls_fp_wide_addmul( fd_bls_fp_wide_t * out,
                         fd_bls_fp_t const * a,
                         fd_bls_fp_t const * b ) {
  out->m1_hi = wwv_madd52hi( out->m1_hi, a->m1, b->m1 );
  out->m1_lo = wwv_madd52lo( out->m1_lo, a->m1, b->m1 );
  out->m2_hi = wwv_madd52hi( out->m2_hi, a->m2, b->m2 );
  out->m2_lo = wwv_madd52lo( out->m2_lo, a->m2, b->m2 );
}

void
fd_bls_fp_wide_submul( fd_bls_fp_wide_t * out,
                         fd_bls_fp_t const * a,
                         fd_bls_fp_t const * b ) {
  wwv_t z = wwv_zero();
  out->m1_hi = wwv_sub( out->m1_hi, wwv_madd52hi( z, a->m1, b->m1 ) );
  out->m1_lo = wwv_sub( out->m1_lo, wwv_madd52lo( z, a->m1, b->m1 ) );
  out->m2_hi = wwv_sub( out->m2_hi, wwv_madd52hi( z, a->m2, b->m2 ) );
  out->m2_lo = wwv_sub( out->m2_lo, wwv_madd52lo( z, a->m2, b->m2 ) );
}

void
fd_bls_fp_one( fd_bls_fp_t * out ) {
  out->m1 = wwv_ld( fd_bls_one_m1 );
  out->m2 = wwv_ld( fd_bls_one_m2 );
}

void
fd_bls_fp_zero( fd_bls_fp_t * out ) {
  out->m1 = wwv_zero();
  out->m2 = wwv_zero();
}

static inline wwv_t
canonical_residue( wwv_t x,
                   wwv_t modulus ) {
  return wwv_min( x, wwv_sub( x, modulus ) );
}

int
fd_bls_fp_equal( fd_bls_fp_t const * a,
                   fd_bls_fp_t const * b ) {
  wwv_t mod1 = wwv_ld( fd_bls_m1 );
  wwv_t mod2 = wwv_ld( fd_bls_m2 );
  wwv_t p1   = canonical_residue( wwv_ld( fd_bls_field_modulus_m1 ), mod1 );
  wwv_t p2   = canonical_residue( wwv_ld( fd_bls_field_modulus_m2 ), mod2 );
  wwv_t a1   = canonical_residue( a->m1, mod1 );
  wwv_t a2   = canonical_residue( a->m2, mod2 );
  wwv_t b1   = canonical_residue( b->m1, mod1 );
  wwv_t b2   = canonical_residue( b->m2, mod2 );
  wwv_t ca1 = a1, ca2 = a2, cb1 = b1, cb2 = b2;

  /* A standard reduced RNS value occupies less than 40*p of redundant
     RNS range.  Equal field values can therefore differ by at most 40
     copies of p in either direction.  Compare in both directions without
     converting either operand out of its native RNS form. */
  for( int k=0; k<=40; k++ ) {
    int ab = wwv_eq( ca1, b1 )==0xff && wwv_eq( ca2, b2 )==0xff;
    int ba = wwv_eq( cb1, a1 )==0xff && wwv_eq( cb2, a2 )==0xff;
    if( FD_LIKELY( ab | ba ) ) return 1;
    ca1 = canonical_residue( wwv_add( ca1, p1 ), mod1 );
    ca2 = canonical_residue( wwv_add( ca2, p2 ), mod2 );
    cb1 = canonical_residue( wwv_add( cb1, p1 ), mod1 );
    cb2 = canonical_residue( wwv_add( cb2, p2 ), mod2 );
  }
  return 0;
}

#endif
