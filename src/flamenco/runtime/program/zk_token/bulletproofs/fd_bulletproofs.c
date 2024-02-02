#include "fd_bulletproofs.h"

static inline int
batched_range_proof_validate_bits( ulong bit_length ) {
  if ( FD_LIKELY(
    bit_length==1  || bit_length==2  || bit_length==4  || bit_length==8 ||
    bit_length==16 || bit_length==32 || bit_length==64 || bit_length==128
  ) ) {
    return FD_BULLETPROOFS_SUCCESS;
  }
  return FD_BULLETPROOFS_ERROR;
}

void
fd_bulletproofs_delta(
  uchar delta[ static 32 ],
  ulong const nm,
  uchar const y[ static 32 ],
  uchar const z[ static 32 ],
  uchar const zz[ static 32 ],
  uchar const bit_lengths[ static 1 ],
  uchar const batch_len
) {
  uchar exp_y[ 32 ];
  uchar sum_of_powers_y[ 32 ];
  fd_memcpy( exp_y, y, 32 );
  fd_ed25519_sc_add( sum_of_powers_y, y, fd_ed25519_scalar_one );
  for( ulong i=nm; i>2; i/=2 ) {
    fd_ed25519_sc_mul   ( exp_y, exp_y, exp_y );
    fd_ed25519_sc_muladd( sum_of_powers_y, exp_y, sum_of_powers_y, sum_of_powers_y );
  }
  fd_ed25519_sc_sub( delta, z, zz );
  fd_ed25519_sc_mul( delta, delta, sum_of_powers_y );

  uchar neg_exp_z[ 32 ];
  uchar sum_2[ 32 ];
  fd_ed25519_sc_neg( neg_exp_z, zz );
  for( ulong i=0; i<batch_len; i++ ) {
    fd_memset( sum_2, 0, 32 );
    //TODO currently assuming that bit_length[i] is multiple of 8 - need to fix cases: 1, 2, 4
    fd_memset( sum_2, 0xFF, bit_lengths[i] / 8 );
    fd_ed25519_sc_mul   ( neg_exp_z, neg_exp_z, z );
    fd_ed25519_sc_muladd( delta, neg_exp_z, sum_2, delta );
  }
}

int
fd_bulletproofs_range_proof_verify(
  fd_bulletproofs_range_proof_t const * range_proof,
  fd_bulletproofs_ipp_proof_t const *   ipp_proof,
  uchar const                           commitments [ static 32 ],
  uchar const                           bit_lengths [ static 1 ],
  uchar const                           batch_len,
  fd_merlin_transcript_t *              transcript ) {

  /* https://github.com/solana-labs/solana/blob/v1.17.15/zk-token-sdk/src/range_proof/mod.rs#L223

    We need to verify a range proof, by computing a large MSM.

    We store points in the following array.
    Indexes are the common example of u128 batch range proof with batch_len==4,
    used in SPL confidential transfers.

           points
      0    G
      1    H
      2    S
      3    T_1
      4    T_2
      5    commitments[ 0 ]
           ...
      8    commitments[ 3 ]    // 4 == batch_len (example)
      9    L_vec[ 0 ]
           ...
     15    L_vec[ 6 ]          // 7 == log2( 128 )
     16    R_vec[ 0 ]
           ...
     22    R_vec[ 6 ]          // 7 == log2( 128 )
     23    generators_H[ 0 ]
           ...
    150    generators_H[ 127 ] // 128 generators
    151    generators_G[ 0 ]
           ...
    278    generators_G[ 127 ] // 128 generators
    ------------------------------------------------------ MSM
           A

    As final check we test that the result of the MSM == -A.
    We could negate all scalars, but that'd make it more complex to debug
    against Rust bulletproofs / Solana, in case of issues, and the marginal
    cost of negating A is negligible.

    This implementation has a few differences compared to the Rust implementation.

    - We need to support batched range proofs for u64, u128 and u256.
      Rust does dynamic allocations. This implementation statically allocates
      for u256 (a total of <64kB) and dynamically handles u64 and u128.

    - This implementation limits memory copies.
      Input data arrives from the Solana tx in a certain order and essentially
      includes compressed points and scalars.
      We allocate enough scalars and (uncompressed) points for the MSM.
      As we parse input data, we compute scalars and decompress points
      directly into the memory region used by MSM (layout shown above).

    - Points and scalars are in a different order compared to Rust,
      but their value is the same. The order has no particular meaning,
      it just seemed more convenient.

    - Range proof depends interally on innerproduct proof (ipp).
      ipp needs to invert logn elements (called u_i).
      range proof, in addition, needs to invert y.
      Rust uses batch inversion to invert all u_i more efficiently.
      We also include y in the batch, to save 1 inversion (~300 mul).

    - ipp generates n scalars s_i, from which range proof derives 2n scalars
      for generators_G and generators_H.
      The scalars for generators_G are just a rescaling of s_i,
      while the scalars for generators_H are a bit more complex.
      We store s_i in the same memory region of generators_G scalars,
      then use them to compute generators_H scalars, and finally we do
      the rescaling. This saves 8kB of stack.
  */

  /* Capital LOGN, N are used to allocate memory.
     Lowercase logn, n are used at runtime.
     This implementation allocates memory to support u256, and
     at runtime can verify u64, u128 and u256 range proofs. */
#define LOGN 8
#define N (1 << LOGN)
#define MAX (2*N + 2*LOGN + 5 + FD_BULLETPROOFS_MAX_COMMITMENTS)

  const ulong logn = ipp_proof->logn;
  const ulong n = 1UL << logn;

  /* https://github.com/solana-labs/solana/blob/v1.17.15/zk-token-sdk/src/range_proof/mod.rs#L234C47-L239
     total bit length (nm) should be a power of 2, and <= 256 == size of our generators table. */
  ulong nm = 0;
  for( uchar i=0; i<batch_len; i++ ) {
    if( FD_UNLIKELY( batched_range_proof_validate_bits( bit_lengths[i] ) != FD_BULLETPROOFS_SUCCESS ) ) {
      return FD_BULLETPROOFS_ERROR;
    }
    nm += bit_lengths[i];
  }
  if( FD_UNLIKELY( nm != n ) ) {
    return FD_BULLETPROOFS_ERROR;
  }

  /* Validate all inputs */
  uchar scalars[ MAX*32 ];
  fd_ristretto255_point_t points[ MAX ];
  fd_ristretto255_point_t a_res[ 1 ];
  fd_ristretto255_point_t res[ 1 ];
  fd_ristretto255_point_copy( &points[0], fd_bulletproofs_basepoint_G );
  fd_ristretto255_point_copy( &points[1], fd_bulletproofs_basepoint_H );
  if( FD_UNLIKELY( fd_ristretto255_point_decompress( a_res, range_proof->a )==NULL ) ) {
    return FD_BULLETPROOFS_ERROR;
  }
  if( FD_UNLIKELY( fd_ristretto255_point_decompress( &points[2], range_proof->s )==NULL ) ) {
    return FD_BULLETPROOFS_ERROR;
  }
  if( FD_UNLIKELY( fd_ristretto255_point_decompress( &points[3], range_proof->t1 )==NULL ) ) {
    return FD_BULLETPROOFS_ERROR;
  }
  if( FD_UNLIKELY( fd_ristretto255_point_decompress( &points[4], range_proof->t2 )==NULL ) ) {
    return FD_BULLETPROOFS_ERROR;
  }
  ulong idx = 5;
  for( ulong i=0; i<batch_len; i++, idx++ ) {
    if( FD_UNLIKELY( fd_ristretto255_point_decompress( &points[ idx ], &commitments[ i*32 ] )==NULL ) ) {
      return FD_BULLETPROOFS_ERROR;
    }
  }
  for( ulong i=0; i<logn; i++, idx++ ) {
    if( FD_UNLIKELY( fd_ristretto255_point_decompress( &points[ idx ], ipp_proof->vecs[ i ].l )==NULL ) ) {
      return FD_BULLETPROOFS_ERROR;
    }
  }
  for( ulong i=0; i<logn; i++, idx++ ) {
    if( FD_UNLIKELY( fd_ristretto255_point_decompress( &points[ idx ], ipp_proof->vecs[ i ].r )==NULL ) ) {
      return FD_BULLETPROOFS_ERROR;
    }
  }
  fd_memcpy( &points[ idx ],   fd_bulletproofs_generators_H, n*sizeof(fd_ristretto255_point_t) );
  fd_memcpy( &points[ idx+n ], fd_bulletproofs_generators_G, n*sizeof(fd_ristretto255_point_t) );

  if( FD_UNLIKELY( fd_ed25519_scalar_validate( range_proof->tx )==NULL ) ) {
    return FD_BULLETPROOFS_ERROR;
  }
  if( FD_UNLIKELY( fd_ed25519_scalar_validate( range_proof->tx_blinding )==NULL ) ) {
    return FD_BULLETPROOFS_ERROR;
  }
  if( FD_UNLIKELY( fd_ed25519_scalar_validate( range_proof->e_blinding )==NULL ) ) {
    return FD_BULLETPROOFS_ERROR;
  }
  if( FD_UNLIKELY( fd_ed25519_scalar_validate( ipp_proof->a )==NULL ) ) {
    return FD_BULLETPROOFS_ERROR;
  }
  if( FD_UNLIKELY( fd_ed25519_scalar_validate( ipp_proof->b )==NULL ) ) {
    return FD_BULLETPROOFS_ERROR;
  }

  /* Finalize transcript and extract challenges */
  int val = FD_TRANSCRIPT_SUCCESS;
  val |= fd_bulletproofs_transcript_validate_and_append_point( transcript, FD_TRANSCRIPT_LITERAL("A"), range_proof->a);
  val |= fd_bulletproofs_transcript_validate_and_append_point( transcript, FD_TRANSCRIPT_LITERAL("S"), range_proof->s);

  uchar batchinv_in [ 32*(1+LOGN) ];
  uchar batchinv_out[ 32*(1+LOGN) ];
  uchar allinv[ 32 ];
  uchar *y = batchinv_in;
  uchar *y_inv = batchinv_out;
  uchar z[ 32 ];
  fd_bulletproofs_transcript_challenge_scalar( y, transcript, FD_TRANSCRIPT_LITERAL("y") );
  fd_bulletproofs_transcript_challenge_scalar( z, transcript, FD_TRANSCRIPT_LITERAL("z") );
  // printf("y = "); for(ulong i=0; i<32; i++) { printf("%02x", y[i]); } printf("\n");

  val |= fd_bulletproofs_transcript_validate_and_append_point( transcript, FD_TRANSCRIPT_LITERAL("T_1"), range_proof->t1);
  val |= fd_bulletproofs_transcript_validate_and_append_point( transcript, FD_TRANSCRIPT_LITERAL("T_2"), range_proof->t2);
  if( FD_UNLIKELY( val != FD_TRANSCRIPT_SUCCESS ) ) {
    return FD_BULLETPROOFS_ERROR;
  }

  uchar x[ 32 ];
  fd_bulletproofs_transcript_challenge_scalar( x, transcript, FD_TRANSCRIPT_LITERAL("x") );

  fd_bulletproofs_transcript_append_scalar( transcript, FD_TRANSCRIPT_LITERAL("t_x"), range_proof->tx);
  fd_bulletproofs_transcript_append_scalar( transcript, FD_TRANSCRIPT_LITERAL("t_x_blinding"), range_proof->tx_blinding);
  fd_bulletproofs_transcript_append_scalar( transcript, FD_TRANSCRIPT_LITERAL("e_blinding"), range_proof->e_blinding);

  uchar w[ 32 ];
  uchar c[ 32 ];
  fd_bulletproofs_transcript_challenge_scalar( w, transcript, FD_TRANSCRIPT_LITERAL("w") );
  fd_bulletproofs_transcript_challenge_scalar( c, transcript, FD_TRANSCRIPT_LITERAL("c") );

  /* Inner Product (sub)Proof */
  fd_bulletproofs_transcript_domsep_innerproduct( transcript, nm );

  uchar *u =     &batchinv_in [ 32 ]; // skip y
  uchar *u_inv = &batchinv_out[ 32 ]; // skip y_inv
  for( ulong i=0; i<logn; i++ ) {
    val |= fd_bulletproofs_transcript_validate_and_append_point( transcript, FD_TRANSCRIPT_LITERAL("L"), ipp_proof->vecs[ i ].l);
    val |= fd_bulletproofs_transcript_validate_and_append_point( transcript, FD_TRANSCRIPT_LITERAL("R"), ipp_proof->vecs[ i ].r);
    if( FD_UNLIKELY( val != FD_TRANSCRIPT_SUCCESS ) ) {
      return FD_BULLETPROOFS_ERROR;
    }
    fd_bulletproofs_transcript_challenge_scalar( &u[ i*32 ], transcript, FD_TRANSCRIPT_LITERAL("u") );
  }
  fd_ed25519_sc_batch_inv( batchinv_out, allinv, batchinv_in, logn+1 );

  /* Compute scalars */

  // H: - ( eb + c t_xb )
  uchar const *eb = range_proof->e_blinding;
  uchar const *txb = range_proof->tx_blinding;
  fd_ed25519_sc_muladd( &scalars[ 1*32 ], c, txb, eb );
  fd_ed25519_sc_neg(    &scalars[ 1*32 ], &scalars[ 1*32 ] );

  // S:   x
  // T_1: c x
  // T_2: c x^2
  fd_memcpy(            &scalars[ 2*32 ], x, 32 );
  fd_ed25519_sc_mul(    &scalars[ 3*32 ], c, x );
  fd_ed25519_sc_mul(    &scalars[ 4*32 ], &scalars[ 3*32 ], x );

  // commitments: c z^2, c z^3 ...
  uchar zz[ 32 ];
  fd_ed25519_sc_mul(    zz, z, z );
  fd_ed25519_sc_mul(    &scalars[ 5*32 ], zz, c );
  idx = 6;
  for( ulong i=1; i<batch_len; i++, idx++ ) {
    fd_ed25519_sc_mul(  &scalars[ idx*32 ], &scalars[ (idx-1)*32 ], z );
  }

  // L_vec: u0^2, u1^2...
  // R_vec: 1/u0^2, 1/u1^2...
  uchar *u_sq = &scalars[ idx*32 ];
  for( ulong i=0; i<logn; i++, idx++ ) {
    fd_ed25519_sc_mul(  &scalars[ idx*32 ], &u[ i*32 ], &u[ i*32 ] );
  }
  for( ulong i=0; i<logn; i++, idx++ ) {
    fd_ed25519_sc_mul(  &scalars[ idx*32 ], &u_inv[ i*32 ], &u_inv[ i*32 ] );
  }

  // s_i for generators_G, generators_H
  uchar *s = &scalars[ (idx+n)*32 ];
  fd_ed25519_sc_mul( &s[ 0*32 ], allinv, y ); // allinv also contains 1/y
  // s[i] = s[ i-k ] * u[ k+1 ]^2   (k the "next power of 2" wrt i)
  for( ulong k=0; k<logn; k++ ) {
    ulong powk = (1UL << k);
    for( ulong j=0; j<powk; j++ ) {
      ulong i = powk + j;
      fd_ed25519_sc_mul( &s[ i*32 ], &s[ j*32 ], &u_sq[ (logn-1-k)*32 ] );
    }
  }

  // generators_H: (-a * s_i) + (-z)
  uchar const *a = ipp_proof->a;
  uchar const *b = ipp_proof->b;
  uchar minus_b[ 32 ];
  uchar exp_z[ 32 ];
  uchar exp_y_inv[ 32 ];
  uchar z_and_2[ 32 ];
  fd_ed25519_sc_neg( minus_b, b );
  fd_memcpy( exp_z, zz, 32 );
  fd_memcpy( z_and_2, exp_z, 32 );
  fd_memcpy( exp_y_inv, y, 32 ); //TODO: remove 2 unnecessary muls
  for( ulong i=0, j=0, m=0; i<n; i++, j++, idx++ ) {
    if( j == bit_lengths[m] ) {
      j = 0;
      m++;
      fd_ed25519_sc_mul ( exp_z, exp_z, z );
      fd_memcpy( z_and_2, exp_z, 32 );
    }
    if( j != 0 ) {
      fd_ed25519_sc_add ( z_and_2, z_and_2, z_and_2 );
    }
    fd_ed25519_sc_mul   ( exp_y_inv, exp_y_inv, y_inv );
    fd_ed25519_sc_muladd( &scalars[ idx*32 ], &s[ (n-1-i)*32 ], minus_b, z_and_2 );
    fd_ed25519_sc_muladd( &scalars[ idx*32 ], &scalars[ idx*32 ], exp_y_inv, z );
  }

  // generators_G: (-a * s_i) + (-z)
  uchar minus_z[ 32 ];
  uchar minus_a[ 32 ];
  fd_ed25519_sc_neg( minus_z, z );
  fd_ed25519_sc_neg( minus_a, a );
  for( ulong i=0; i<n; i++, idx++ ) {
    fd_ed25519_sc_muladd( &scalars[ idx*32 ], &s[ i*32 ], minus_a, minus_z );
  }

  // G
  // w * (self.t_x - a * b) + c * (delta(&bit_lengths, &y, &z) - self.t_x)
  uchar delta[ 32 ];
  fd_bulletproofs_delta( delta, nm, y, z, zz, bit_lengths, batch_len );
  fd_ed25519_sc_muladd(  &scalars[ 0 ], minus_a, b, range_proof->tx );
  fd_ed25519_sc_sub(     delta, delta, range_proof->tx );
  fd_ed25519_sc_mul(     delta, delta, c );
  fd_ed25519_sc_muladd(  &scalars[ 0 ], &scalars[ 0 ], w, delta );

  /* Compute the final MSM */
  fd_ristretto255_multiscalar_mul( res, scalars, points, idx );

  if( FD_LIKELY( fd_ristretto255_point_eq_neg( res, a_res ) ) ) {
    return FD_BULLETPROOFS_SUCCESS;
  }

#undef LOGN
#undef N
#undef MAX
  return FD_BULLETPROOFS_ERROR;
}
