/* Native AVX-512 G1 aggregation and G2 subgroup validation over the
   rotated-RNS backend.  Same translation unit as the Miller machinery
   (fd_bls_miller.c) so the complete-formula pairing arithmetic and psi
   constants can be reused directly. */

#if FD_HAS_AVX512

/* Fused blst-Montgomery -> RNS batched entry.  The fd_bls_to_mont_*
   tables (gen_bls_constants.py) are the radix-entry tables with the
   premult scaled by 2^-384, so raw blst_fp Montgomery limbs (x*2^384
   mod p) load as the same RNS value the canonical entry produces for
   x -- zero per-coordinate blst_uint64_from_fp cost.  The row loads
   amortize across up to 12 coordinates per call. */

#define FD_BLS_G1_ENTRY_MAX (12)

/* Split one 6-limb/64-bit blst Montgomery value into 8 50-bit digits. */
static inline void
g1_digits50( ulong dst[8], ulong const v[6] ) {
  dst[0] = v[0] & VROOM_MASK50;
  dst[1] = ((v[0] >> 50) | (v[1] << 14)) & VROOM_MASK50;
  dst[2] = ((v[1] >> 36) | (v[2] << 28)) & VROOM_MASK50;
  dst[3] = ((v[2] >> 22) | (v[3] << 42)) & VROOM_MASK50;
  dst[4] = (v[3] >> 8) & VROOM_MASK50;
  dst[5] = ((v[3] >> 58) | (v[4] << 6)) & VROOM_MASK50;
  dst[6] = ((v[4] >> 44) | (v[5] << 20)) & VROOM_MASK50;
  dst[7] = (v[5] >> 30) & VROOM_MASK50;
}

/* Shared fused-entry core: consumes cnt pre-split 50-bit digit rows. */
static void
g1_from_mont_core( vroom_fp_t out[ FD_BLS_G1_ENTRY_MAX ],
                   ulong const d  [ FD_BLS_G1_ENTRY_MAX ][ 8 ],
                   int         cnt ) {
  wwv_t hi[ FD_BLS_G1_ENTRY_MAX ], lo[ FD_BLS_G1_ENTRY_MAX ];
  uint128 k_raw[ FD_BLS_G1_ENTRY_MAX ] = { 0 };
  for( int e=0; e<cnt; e++ ) { hi[e]=wwv_zero(); lo[e]=wwv_zero(); }

  for( int i=0; i<8; i++ ) {
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
g1_from_mont_batch( vroom_fp_t out[ FD_BLS_G1_ENTRY_MAX ],
                    ulong const in [ FD_BLS_G1_ENTRY_MAX ][ 6 ],
                    int         cnt ) {
  ulong d[ FD_BLS_G1_ENTRY_MAX ][ 8 ] __attribute__((aligned(64)));
  for( int e=0; e<cnt; e++ ) g1_digits50( d[e], in[e] );
  g1_from_mont_core( out, d, cnt );
}

/* Direct-from-keys fused entry: splits each key's x,y Montgomery limbs
   into digits in place of a caller-side gather memcpy, so the walk
   streams pubs once. */
static void
g1_from_mont_batch_keys( vroom_fp_t          out[ FD_BLS_G1_ENTRY_MAX ],
                         fd_bls_pub_t const * pubs,
                         ulong const *        ranks,
                         ulong                n ) {
  ulong d[ FD_BLS_G1_ENTRY_MAX ][ 8 ] __attribute__((aligned(64)));
  for( ulong i=0; i<n; i++ ) {
    g1_digits50( d[2*i+0], (ulong const *)&pubs[ ranks[i] ].x );
    g1_digits50( d[2*i+1], (ulong const *)&pubs[ ranks[i] ].y );
  }
  g1_from_mont_core( out, d, (int)(2*n) );
}

/* Export an RNS value as raw blst Montgomery limbs (blst_pN fields are
   Montgomery form; vroom_fp_to_uint64 gives canonical limbs, so remont-
   gomeryize through the public blst entry). */
static void
vroom_fp_to_mont_limbs( ulong               out[ 6 ],
                         vroom_fp_t const * in ) {
  ulong canon[ 6 ];
  vroom_fp_to_uint64( canon, in );
  blst_fp t;
  blst_fp_from_uint64( &t, canon );
  fd_memcpy( out, &t, 48 );
}

/* Rescale projective (X:Y:Z) to blst_p1 Jacobian (X*Z : Y*Z^2 : Z) and
   export.  A sum whose value is infinity rescales to the all-zero limbs
   blst uses for infinity (Z == 0 zeroes every output). */
static void
g1_rescale_out( fd_bls_pub_t *      out,
                vroom_fp_t const * acc ) {
  vroom_fp_t xj, yj, zj, zs;
  vroom_fp_mul( &xj, &acc[0], &acc[2] );
  vroom_fp_mul( &zs, &acc[2], &acc[2] );
  vroom_fp_mul( &yj, &acc[1], &zs );
  zj = acc[2];

  vroom_fp_to_mont_limbs( (ulong *)&out->x, &xj );
  vroom_fp_to_mont_limbs( (ulong *)&out->y, &yj );
  vroom_fp_to_mont_limbs( (ulong *)&out->z, &zj );
}

void
fd_bls_g1_pub_sum_avx512( fd_bls_pub_t *       out,
                          fd_bls_pub_t const * pubs,
                          fd_bls_set_t const * set ) {
  ulong r = fd_bls_set_const_iter_init( set );
  if( FD_UNLIKELY( fd_bls_set_const_iter_done( r ) ) ) return;

  vroom_fp_t acc0[3], acc1[3];
  vroom_fp_t q[ FD_BLS_G1_ENTRY_MAX ];

  /* first key seeds chain 0 */
  g1_from_mont_batch_keys( q, pubs, &r, 1 );
  acc0[0]=q[0]; acc0[1]=q[1]; vroom_fp_one( &acc0[2] );
  r = fd_bls_set_const_iter_next( set, r );
  if( FD_UNLIKELY( fd_bls_set_const_iter_done( r ) ) ) {
    g1_rescale_out( out, acc0 );
    return;
  }

  /* second key seeds chain 1 */
  g1_from_mont_batch_keys( q, pubs, &r, 1 );
  acc1[0]=q[0]; acc1[1]=q[1]; vroom_fp_one( &acc1[2] );
  r = fd_bls_set_const_iter_next( set, r );

  /* dual-accumulator walk: batch up to 6 keys (12 coords) per fused-entry
     call so the 8 row loads amortize, then interleave the paired adds. */
  while( !fd_bls_set_const_iter_done( r ) ) {
    ulong ranks[6]; ulong n = 0;
    while( n<6UL && !fd_bls_set_const_iter_done( r ) ) {
      ranks[n++] = r;
      r = fd_bls_set_const_iter_next( set, r );
    }
    g1_from_mont_batch_keys( q, pubs, ranks, n );
    for( ulong i=0; i+1<n; i+=2 )
      vroom_g1_mixed_add2( acc0, acc1, q + 2*i, q + 2*i + 2 );
    if( n & 1UL )
      vroom_g1_mixed_add( acc0, q + 2*(n-1UL) );
  }

  /* complete projective merge of the two chains */
  vroom_g1_proj_add( acc0, acc1 );
  g1_rescale_out( out, acc0 );
}

/* Native G2 subgroup validation (Scott ePrint 2021/1130): Q is in the
   order-r subgroup iff [z]Q == psi(Q).  The [-z]Q ladder reuses the
   Miller loop's complete projective twist arithmetic, and psi(Q) is
   applied to the projective coordinates directly so no inversion is
   needed.  Inputs are the raw blst Montgomery limbs of a Jacobian
   (X:Y:Z) G2 point; infinity (Z == 0) is rejected up front by the
   caller.  Matches blst_p2_in_g2 on every on-curve input; off-curve
   inputs are outside the validated domain. */
int
fd_bls_g2_validate_mont_avx512( ulong const xyz[ 3 ][ 2 ][ 6 ] ) {
  vroom_fp_t q[ 6 ][ 2 ];  /* X, Y, Z as converted Fp2 coordinates */
  g1_from_mont_batch( (vroom_fp_t *)q, (ulong const (*)[6])xyz, 6 );

  vroom_fp2_t * X = (vroom_fp2_t *)q[0];
  vroom_fp2_t * Y = (vroom_fp2_t *)q[1];
  vroom_fp2_t * Z = (vroom_fp2_t *)q[2];

  /* The ladder adds Q in affine form.  blst_p2 is Jacobian
     (affine = X/Z^2, Y/Z^3): Z == Montgomery-one is the affine shape
     sig_de always produces, and any other Z (an aggregated signature)
     is affinized with a single Fp2 inversion before the ladder. */
  vroom_fp2_t ax, ay;
  /* blst's affine shape carries Z = 1 in Fp2, i.e. (ONE_MONT_P, zero). */
  static ulong const z_one[2][6] = { { 0x760900000002fffdUL, 0xebf4000bc40c0002UL,
                                       0x5f48985753c758baUL, 0x77ce585370525745UL,
                                       0x5c071a97a256ec6dUL, 0x15f65ec3fa80e493UL },
                                     { 0UL, 0UL, 0UL, 0UL, 0UL, 0UL } };
  if( FD_LIKELY( !memcmp( xyz[2], z_one, sizeof(z_one) ) ) ) {
    ax = *X; ay = *Y;
  } else {
    vroom_fp2_t zinv, zinv2;
    vroom_fp2_inverse( &zinv, Z );
    vroom_fp2_mul( &zinv2, &zinv, &zinv );
    vroom_fp2_mul( &ax, X, &zinv2 );       /* x = X/Z^2 */
    vroom_fp2_mul( &ay, Y, &zinv2 );
    vroom_fp2_mul( &ay, &ay, &zinv );      /* y = Y/Z^3 */
  }

  /* [-z]Q via the line-free ladder (2Q, then add+double by {2,3,9,32,16}). */
  vroom_p2_projective_t r = ladder_minus_z_affine( &ax, &ay );

  /* Scott's test as the ladder states it: the chain ends at [-z]Q, which
     must equal -psi(Q).  psi is linear over the affine coordinates:
     psi_x = conj(x)*xi^((1-p)/3), psi_y = conj(y)*xi^((1-p)/2). */
  vroom_fp2_t x_conj = ax, y_conj = ay;
  vroom_fp_neg( &x_conj.c[1], &x_conj.c[1] );
  vroom_fp_neg( &y_conj.c[1], &y_conj.c[1] );

  vroom_fp2_t frob_x, frob_y;
  vroom_fp_zero( &frob_x.c[0] );
  frob_x.c[1] = VROOM_FP_CONST( frob1_3 );
  frob_y.c[0] = VROOM_FP_CONST( frob3_2 );
  frob_y.c[1] = VROOM_FP_CONST( frob3_3 );
  vroom_fp2_t psi_x, psi_y, rhs_x, rhs_y;
  vroom_fp2_mul( &psi_x, &x_conj, &frob_x );
  vroom_fp2_mul( &psi_y, &y_conj, &frob_y );
  vroom_fp2_mul( &rhs_x, &psi_x, &r.z );
  vroom_fp2_mul( &rhs_y, &psi_y, &r.z );
  vroom_fp2_neg( &rhs_y, &rhs_y );   /* rhs = -psi(Q) */
  return vroom_fp2_equal( &r.x, &rhs_x ) & vroom_fp2_equal( &r.y, &rhs_y );
}

#endif
