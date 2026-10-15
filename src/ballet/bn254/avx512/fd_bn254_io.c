/* BN254 <-> VROOM boundary: convert fd_bn254's 4x64 Montgomery (R=2^256)
   field elements into rotated-RNS form and back.  Entry uses the fused
   foreign-Montgomery tables (premult scaled by 2^-256) so raw Montgomery
   limbs load with zero de-Montgomery cost; export goes through canonical
   limbs and the scalar fd_bn254_fp_to_mont.  Part of the BN254 unity TU. */

#if FD_HAS_AVX512

/* Split one 4x64 Montgomery value (zero-padded to 6 limbs) into 8 50-bit
   digits. */
static inline void
bn254_digits50( ulong dst[8], ulong const v[4] ) {
  dst[0] = v[0] & VROOM_MASK50;
  dst[1] = ((v[0] >> 50) | (v[1] << 14)) & VROOM_MASK50;
  dst[2] = ((v[1] >> 36) | (v[2] << 28)) & VROOM_MASK50;
  dst[3] = ((v[2] >> 22) | (v[3] << 42)) & VROOM_MASK50;
  dst[4] = (v[3] >> 8) & VROOM_MASK50;
  dst[5] = (v[3] >> 58) & VROOM_MASK50;
  dst[6] = 0UL;
  dst[7] = 0UL;
}

#define BN254_ENTRY_MAX (12)

/* Fused-entry core: consumes cnt pre-split 50-bit digit rows (same
   shape as the BLS g1_from_mont_core; digits 6,7 are always zero for a
   254-bit input but the row loads are shared so the loop stays 8-deep). */
static void
bn254_from_mont_core( vroom_fp_t  out[ BN254_ENTRY_MAX ],
                      ulong const d  [ BN254_ENTRY_MAX ][ 8 ],
                      int         cnt ) {
  wwv_t hi[ BN254_ENTRY_MAX ], lo[ BN254_ENTRY_MAX ];
  uint128 k_raw[ BN254_ENTRY_MAX ] = { 0 };
  for( int e=0; e<cnt; e++ ) { hi[e]=wwv_zero(); lo[e]=wwv_zero(); }

  for( int i=0; i<6; i++ ) { /* digits 6,7 are zero for 254-bit inputs */
    wwv_t row = wwv_ld( vroom_to_mont_mat[i] );
    for( int e=0; e<cnt; e++ ) {
      wwv_t s = wwv_bcast( d[e][i] );
      hi[e] = wwv_madd52hi( hi[e], row, s );
      lo[e] = wwv_madd52lo( lo[e], row, s );
      k_raw[e] += (uint128)d[e][i] * (uint128)vroom_to_mont_sqe[i];
    }
  }
  wwv_t corr = wwv_ld( vroom_to_mont_correction );
  for( int e=0; e<cnt; e++ ) {
    /* second-digit correction, as in matrix_accumulate */
    wwv_t ks = wwv_bcast( (ulong)(k_raw[e] >> 64) );
    hi[e] = wwv_madd52hi( hi[e], corr, ks );
    lo[e] = wwv_madd52lo( lo[e], corr, ks );
    ks = wwv_shr( ks, 52 );
    hi[e] = wwv_madd52lo( hi[e], corr, ks );
    wwv_t carry = wwv_madd52hi( wwv_zero(), corr, ks );
    hi[e] = wwv_add( hi[e], wwv_shl( carry, 52 ) );
    out[e].m2 = mont_reduce_wide_normalized( hi[e], lo[e],
                    wwv_ld( vroom_m2 ), wwv_ld( vroom_m2_mont ), wwv_ld( vroom_m2_t ) );
    out[e].m1 = expand_m2_to_m1( out[e].m2 );
  }
}

static void
bn254_fp_batch_enter( vroom_fp_t          out[ BN254_ENTRY_MAX ],
                      fd_bn254_fp_t const in[],
                      int                 cnt ) {
  ulong d[ BN254_ENTRY_MAX ][ 8 ] __attribute__((aligned(64)));
  for( int e=0; e<cnt; e++ ) bn254_digits50( d[e], in[e].limbs );
  bn254_from_mont_core( out, d, cnt );
}

static inline void
bn254_fp_enter( vroom_fp_t *          out,
                fd_bn254_fp_t const * in ) {
  bn254_fp_batch_enter( out, in, 1 );
}

static inline void
bn254_fp2_enter( vroom_fp2_t *          out,
                 fd_bn254_fp2_t const * in ) {
  bn254_fp_batch_enter( &out->c[0], in->el, 2 );
}

/* Export an RNS value as fd_bn254 Montgomery limbs. */
static void
bn254_fp_exit( fd_bn254_fp_t *    out,
               vroom_fp_t const * in ) {
  ulong canon[6];
  vroom_fp_to_uint64( canon, in );
  out->limbs[0]=canon[0]; out->limbs[1]=canon[1];
  out->limbs[2]=canon[2]; out->limbs[3]=canon[3];
  fd_bn254_fp_to_mont( out, out );
}

static inline void
bn254_fp2_exit( fd_bn254_fp2_t *    out,
                vroom_fp2_t const * in ) {
  bn254_fp_exit( &out->el[0], &in->c[0] );
  bn254_fp_exit( &out->el[1], &in->c[1] );
}

#endif /* FD_HAS_AVX512 */
