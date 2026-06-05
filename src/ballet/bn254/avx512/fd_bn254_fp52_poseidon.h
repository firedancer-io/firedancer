#ifndef HEADER_fd_src_ballet_bn254_avx512_fd_bn254_fp52_poseidon_h
#define HEADER_fd_src_ballet_bn254_avx512_fd_bn254_fp52_poseidon_h

#if FD_HAS_AVX512

/* fd_bn254_fp52_poseidon.h provides an AVX-512-accelerated
   implementation of the Poseidon hash function over the BN254 scalar
   field.  This is a drop-in replacement for fd_poseidon.h with
   identical semantics and output.

   The implementation uses radix-2^52 Montgomery form with R = 2^260
   for the internal state, and leverages 8-way batched CIOS
   multiplication for S-box and MDS operations when width <= 8.

   For widths > 8 (i.e. more than 7 input elements), scalar CIOS
   operations are used instead.

   Reference: fd_poseidon.c (existing scalar implementation). */

#include "fd_bn254_fp52_scalar.h"
#include "../fd_poseidon_params.c"

/* Maximum Poseidon width: state size = cnt+1, cnt in [1,12],
   so width in [2,13]. */

#define FD_BN254_FP52_POSEIDON_MAX_WIDTH (13UL)

FD_PROTOTYPES_BEGIN

/* fd_bn254_fp52_poseidon_convert_scalar converts a fd_bn254_scalar_t
   in R_256 Montgomery form to radix-2^52 R_260 Montgomery form. */

FD_FN_UNUSED static inline void
fd_bn254_fp52_poseidon_convert_scalar( ulong                     r52[5],
                                       fd_bn254_scalar_t const * s ) {
  fd_bn254_fr52_from_scalar( r52, s );
}

/* fd_bn254_fp52_poseidon_ark adds round constants to the state.
   state is an array of width elements, each a ulong[5] in radix-2^52
   R_260 Montgomery form.  ark points to the round constants for
   round `round` (width consecutive fd_bn254_scalar_t values in R_256
   Montgomery form). */

FD_FN_UNUSED static inline void
fd_bn254_fp52_poseidon_ark( ulong                     state[][5],
                            fd_bn254_scalar_t const * ark,
                            ulong                     width,
                            ulong                     round ) {
  for( ulong i=0; i<width; i++ ) {
    ulong ark_r52[5];
    fd_bn254_fr52_from_scalar( ark_r52, &ark[ round * width + i ] );
    fd_bn254_fr52_add_scalar( state[i], state[i], ark_r52 );
  }
}

/* fd_bn254_fp52_poseidon_sbox_full applies the S-box (x^5) to all
   width state elements.

   For width <= 8, all elements are packed into 8-wide AVX-512 lanes
   and the three multiplications (sqr, sqr, mul) are batched:
     t = s^2  (batched sqr)
     t = t^2  (batched sqr)
     s = s*t  (batched mul)

   For width > 8, scalar CIOS is used. */

FD_FN_UNUSED static inline void
fd_bn254_fp52_poseidon_sbox_full( ulong state[][5],
                                  ulong width ) {
  if( width<=8UL ) {
    /* Pack state into batched representation */
    fd_bn254_fp52x8_t s;
    fd_bn254_fp52x8_zero( &s );
    for( ulong i=0; i<width; i++ ) {
      fd_bn254_fp52x8_set_lane( &s, (int)i, state[i] );
    }

    /* s^2 */
    fd_bn254_fp52x8_t t = fd_bn254_fr52x8_sqr( &s );
    /* s^4 */
    t = fd_bn254_fr52x8_sqr( &t );
    /* s^5 = s * s^4 */
    s = fd_bn254_fr52x8_mul( &s, &t );

    /* Unpack back to state */
    for( ulong i=0; i<width; i++ ) {
      fd_bn254_fp52x8_get_lane( state[i], &s, (int)i );
    }
  } else {
    /* Scalar fallback for width > 8 */
    for( ulong i=0; i<width; i++ ) {
      ulong t[5];
      fd_bn254_fr52_sqr_scalar( t, state[i] );         /* t = s^2 */
      fd_bn254_fr52_sqr_scalar( t, t );                 /* t = s^4 */
      fd_bn254_fr52_mul_scalar( state[i], state[i], t ); /* s = s^5 */
    }
  }
}

/* fd_bn254_fp52_poseidon_sbox_partial applies the S-box (x^5) only
   to state[0].  This is the partial round S-box. */

FD_FN_UNUSED static inline void
fd_bn254_fp52_poseidon_sbox_partial( ulong state[][5] ) {
  ulong t[5];
  fd_bn254_fr52_sqr_scalar( t, state[0] );         /* t = s^2 */
  fd_bn254_fr52_sqr_scalar( t, t );                 /* t = s^4 */
  fd_bn254_fr52_mul_scalar( state[0], state[0], t ); /* s = s^5 */
}

/* fd_bn254_fp52_poseidon_mds applies the MDS matrix-vector multiply:
     out[i] = sum_j( mds[i*width+j] * state[j] )

   For width <= 8, each row of products is computed using batched
   multiply:
     - Pack state[0..width-1] and mds[i*width+0..width-1] into lanes
     - One batched multiply yields all width products
     - Extract and sum the products using scalar addition

   For width > 8, scalar CIOS is used for all multiplications. */

FD_FN_UNUSED static inline void
fd_bn254_fp52_poseidon_mds( ulong                     state[][5],
                            fd_bn254_scalar_t const * mds,
                            ulong                     width ) {
  ulong out[FD_BN254_FP52_POSEIDON_MAX_WIDTH][5];

  if( width<=8UL ) {
    /* Pack state into batched representation (reused for all rows) */
    fd_bn254_fp52x8_t sv;
    fd_bn254_fp52x8_zero( &sv );
    for( ulong j=0; j<width; j++ ) {
      fd_bn254_fp52x8_set_lane( &sv, (int)j, state[j] );
    }

    for( ulong i=0; i<width; i++ ) {
      /* Pack MDS row i into batched representation */
      fd_bn254_fp52x8_t mv;
      fd_bn254_fp52x8_zero( &mv );
      for( ulong j=0; j<width; j++ ) {
        ulong mds_r52[5];
        fd_bn254_fr52_from_scalar( mds_r52, &mds[ i * width + j ] );
        fd_bn254_fp52x8_set_lane( &mv, (int)j, mds_r52 );
      }

      /* Batched multiply: products[j] = state[j] * mds[i*w+j] */
      fd_bn254_fp52x8_t products = fd_bn254_fr52x8_mul( &sv, &mv );

      /* Sum all width products using scalar addition */
      ulong acc[5] = { 0, 0, 0, 0, 0 };
      for( ulong j=0; j<width; j++ ) {
        ulong lane[5];
        fd_bn254_fp52x8_get_lane( lane, &products, (int)j );
        fd_bn254_fr52_add_scalar( acc, acc, lane );
      }

      out[i][0] = acc[0]; out[i][1] = acc[1]; out[i][2] = acc[2];
      out[i][3] = acc[3]; out[i][4] = acc[4];
    }
  } else {
    /* Scalar fallback for width > 8 */
    for( ulong i=0; i<width; i++ ) {
      ulong acc[5] = { 0, 0, 0, 0, 0 };
      for( ulong j=0; j<width; j++ ) {
        ulong mds_r52[5];
        fd_bn254_fr52_from_scalar( mds_r52, &mds[ i * width + j ] );
        ulong prod[5];
        fd_bn254_fr52_mul_scalar( prod, state[j], mds_r52 );
        fd_bn254_fr52_add_scalar( acc, acc, prod );
      }
      out[i][0] = acc[0]; out[i][1] = acc[1]; out[i][2] = acc[2];
      out[i][3] = acc[3]; out[i][4] = acc[4];
    }
  }

  /* Copy output back to state */
  for( ulong i=0; i<width; i++ ) {
    state[i][0] = out[i][0]; state[i][1] = out[i][1]; state[i][2] = out[i][2];
    state[i][3] = out[i][3]; state[i][4] = out[i][4];
  }
}

/* fd_bn254_fp52_poseidon_hash computes the Poseidon hash.
   This is the top-level API matching fd_poseidon_hash.

   Input: in is a buffer of in_sz bytes, where in_sz must be a
   multiple of 32.  Each 32-byte chunk is a little-endian scalar
   field element (must be < r).  At most 12 elements are supported.

   Output: out is a 32-byte buffer receiving the hash result as a
   little-endian scalar field element.

   Returns 0 on success, non-zero on error. */

FD_FN_UNUSED static int
fd_bn254_fp52_poseidon_hash( uchar       out[32],
                             uchar const in[],
                             ulong       in_sz ) {
  if( FD_UNLIKELY( in_sz==0 || in_sz>32*12 || (in_sz & 31) ) ) {
    return -1;
  }

  ulong cnt = in_sz / 32;
  ulong width = cnt + 1;

  /* Validate all input scalars and convert to radix-2^52 R_260
     Montgomery form. */

  ulong state[FD_BN254_FP52_POSEIDON_MAX_WIDTH][5];

  /* state[0] = 0 (capacity element, zero in Montgomery is zero) */
  state[0][0] = 0; state[0][1] = 0; state[0][2] = 0;
  state[0][3] = 0; state[0][4] = 0;

  for( ulong i=0; i<cnt; i++ ) {
    /* Validate: load as fd_bn254_scalar_t and check < r */
    fd_bn254_scalar_t cur[1] = { 0 };
    fd_memcpy( cur->buf, &in[i*32], 32 );

    if( FD_UNLIKELY( !fd_bn254_scalar_validate( cur ) ) ) {
      return -1;
    }

    /* Convert to R_256 Montgomery form, then to R_260 radix-2^52 */
    fd_bn254_scalar_t mont[1];
    fd_bn254_scalar_to_mont( mont, cur );
    fd_bn254_fr52_from_scalar( state[i+1], mont );
  }

  /* Get Poseidon parameters (ARK and MDS in R_256 Montgomery) */
  fd_bn254_scalar_t const * ark = NULL;
  fd_bn254_scalar_t const * mds = NULL;

# define FD_BN254_FP52_POSEIDON_GET_PARAMS(w) case (w):                \
    ark = fd_poseidon_ark_## w;                                         \
    mds = fd_poseidon_mds_## w;                                         \
    break

  switch( width ) {
  FD_BN254_FP52_POSEIDON_GET_PARAMS(2);
  FD_BN254_FP52_POSEIDON_GET_PARAMS(3);
  FD_BN254_FP52_POSEIDON_GET_PARAMS(4);
  FD_BN254_FP52_POSEIDON_GET_PARAMS(5);
  FD_BN254_FP52_POSEIDON_GET_PARAMS(6);
  FD_BN254_FP52_POSEIDON_GET_PARAMS(7);
  FD_BN254_FP52_POSEIDON_GET_PARAMS(8);
  FD_BN254_FP52_POSEIDON_GET_PARAMS(9);
  FD_BN254_FP52_POSEIDON_GET_PARAMS(10);
  FD_BN254_FP52_POSEIDON_GET_PARAMS(11);
  FD_BN254_FP52_POSEIDON_GET_PARAMS(12);
  FD_BN254_FP52_POSEIDON_GET_PARAMS(13);
  default: return -1;
  }

# undef FD_BN254_FP52_POSEIDON_GET_PARAMS

  if( FD_UNLIKELY( !ark || !mds ) ) {
    return -1;
  }

  /* Round counts (matches fd_poseidon.c exactly) */
  static const ulong PARTIAL_ROUNDS[] = {
    56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65, 70, 60, 64, 68
  };
  ulong partial_rounds = PARTIAL_ROUNDS[ cnt-1 ];
  ulong full_rounds    = 8;
  ulong half_rounds    = full_rounds / 2;
  ulong all_rounds     = full_rounds + partial_rounds;

  /* First half of full rounds */
  ulong round = 0;
  for( ; round<half_rounds; round++ ) {
    fd_bn254_fp52_poseidon_ark( state, ark, width, round );
    fd_bn254_fp52_poseidon_sbox_full( state, width );
    fd_bn254_fp52_poseidon_mds( state, mds, width );
  }

  /* Partial rounds */
  for( ; round<half_rounds+partial_rounds; round++ ) {
    fd_bn254_fp52_poseidon_ark( state, ark, width, round );
    fd_bn254_fp52_poseidon_sbox_partial( state );
    fd_bn254_fp52_poseidon_mds( state, mds, width );
  }

  /* Second half of full rounds */
  for( ; round<all_rounds; round++ ) {
    fd_bn254_fp52_poseidon_ark( state, ark, width, round );
    fd_bn254_fp52_poseidon_sbox_full( state, width );
    fd_bn254_fp52_poseidon_mds( state, mds, width );
  }

  /* Convert state[0] from R_260 radix-2^52 back to R_256 radix-2^64
     Montgomery, then de-Montgomery to get the raw scalar, and write
     it out as little-endian bytes. */
  fd_bn254_scalar_t result[1];
  fd_bn254_fr52_to_scalar( result, state[0] );
  fd_bn254_scalar_from_mont( result, result );
  fd_memcpy( out, result->buf, 32 );

  return 0;
}

/* fd_bn254_fp52_poseidon_hash_be is the big-endian variant.
   Input and output are in big-endian byte order. */

FD_FN_UNUSED static int
fd_bn254_fp52_poseidon_hash_be( uchar       out[32],
                                uchar const in[],
                                ulong       in_sz ) {
  if( FD_UNLIKELY( in_sz==0 || in_sz>32*12 || (in_sz & 31) ) ) {
    return -1;
  }

  ulong cnt = in_sz / 32;

  /* Convert big-endian inputs to little-endian, then hash */
  uchar le_in[32*12];
  for( ulong i=0; i<cnt; i++ ) {
    for( ulong j=0; j<32; j++ ) {
      le_in[i*32 + j] = in[i*32 + 31 - j];
    }
  }

  int err = fd_bn254_fp52_poseidon_hash( out, le_in, in_sz );
  if( FD_UNLIKELY( err ) ) return err;

  /* Swap output to big-endian */
  for( ulong j=0; j<16; j++ ) {
    uchar tmp = out[j];
    out[j]     = out[31-j];
    out[31-j]  = tmp;
  }

  return 0;
}

FD_PROTOTYPES_END

#endif /* FD_HAS_AVX512 */

#endif /* HEADER_fd_src_ballet_bn254_avx512_fd_bn254_fp52_poseidon_h */
