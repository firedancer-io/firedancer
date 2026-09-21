/* Instantiate with FD_POSEIDON_WIDTH and FD_POSEIDON_IMPL defined.  The
   width-specific translation units keep these loops specialized without
   making one optimizer job contain all widths. */

#ifndef FD_POSEIDON_WIDTH
#error "FD_POSEIDON_WIDTH must be defined"
#endif

#ifndef FD_POSEIDON_IMPL
#error "FD_POSEIDON_IMPL must be defined"
#endif

#include "./fd_poseidon_private.h"
#include "fd_poseidon_params.c"

static inline __attribute__((always_inline)) void
fd_poseidon_apply_ark( fd_bn254_scalar_t         state[],
                       ulong const               width,
                       fd_bn254_scalar_t const * ark ) {
  for( ulong i=0; i<width; i++ ) {
    fd_bn254_scalar_add( &state[i], &state[i], &ark[i] );
  }
}

static inline __attribute__((always_inline)) void
fd_poseidon_apply_sbox_full( fd_bn254_scalar_t state[],
                             ulong const       width ) {
  /* Compute s[i]^5 */
  for( ulong i=0; i<width; i++ ) {
    fd_bn254_scalar_t t[1];
    fd_bn254_scalar_sqr( t, &state[i] );            /* t = s^2 */
    fd_bn254_scalar_sqr( t, t );                    /* t = s^4 */
    fd_bn254_scalar_mul( &state[i], &state[i], t ); /* s = s^5 */
  }
}

static inline __attribute__((always_inline)) void
fd_poseidon_apply_sbox_partial( fd_bn254_scalar_t state[] ) {
  /* Compute s[0]^5 */
  fd_poseidon_apply_sbox_full( state, 1 );
}

static inline __attribute__((always_inline)) void
fd_poseidon_apply_mds_row0( fd_bn254_scalar_t         state[],
                            ulong const               width,
                            fd_bn254_scalar_t const * mds ) {
  fd_bn254_scalar_t new_s0[1] = { 0 };

  for( ulong j=0; j<width; j++ ) {
    fd_bn254_scalar_t t[1];
    fd_bn254_scalar_mul( t, &state[j], &mds[j] );
    fd_bn254_scalar_add( new_s0, new_s0, t );
  }

  state[0] = new_s0[0];
}

static inline __attribute__((always_inline)) void
fd_poseidon_permute( fd_bn254_scalar_t state[] ) {
  ulong const width          = FD_POSEIDON_WIDTH;
  ulong const partial_rounds = FD_POSEIDON_PARTIAL_ROUNDS;
  ulong const half_rounds    = 4UL;

  fd_poseidon_apply_ark       ( state, width, fd_poseidon_ark_start );
  fd_poseidon_apply_sbox_full ( state, width );

  for( ulong round=1; round<half_rounds; round++ ) {
    fd_poseidon_apply_ark       ( state, width, fd_poseidon_ark_start + round*width );
    fd_poseidon_private_apply_mds( state, width, fd_poseidon_mds );
    fd_poseidon_apply_sbox_full ( state, width );
  }

  fd_poseidon_apply_ark ( state, width, fd_poseidon_ark_start + half_rounds*width );
  fd_poseidon_private_apply_mds( state, width, fd_poseidon_pre_sparse_mds );

  for( ulong round=0; round<partial_rounds; round++ ) {
    fd_poseidon_apply_sbox_partial( state );
    fd_bn254_scalar_add( &state[0], &state[0], &fd_poseidon_ark_partial[ round ] );
    fd_poseidon_private_apply_sparse_mds( state,
                                          width,
                                          fd_poseidon_sparse_mds_row + round*width,
                                          fd_poseidon_sparse_mds_col + round*(width-1UL) );
  }

  fd_poseidon_apply_sbox_full( state, width );
  for( ulong round=0; round<half_rounds-1UL; round++ ) {
    fd_poseidon_apply_ark       ( state, width, fd_poseidon_ark_end + round*width );
    fd_poseidon_private_apply_mds( state, width, fd_poseidon_mds );
    fd_poseidon_apply_sbox_full ( state, width );
  }
  fd_poseidon_apply_mds_row0( state, width, fd_poseidon_mds );
}

uchar *
FD_POSEIDON_IMPL( fd_poseidon_t * pos,
                  uchar           hash[ FD_POSEIDON_HASH_SZ ] ) {
  fd_poseidon_permute( pos->state );

  /* Convert through a local scalar: hash only needs to be byte aligned. */
  fd_bn254_scalar_t scalar_hash[1];
  fd_bn254_scalar_from_mont( scalar_hash, &pos->state[0] );
  if( pos->big_endian ) {
    fd_uint256_bswap( scalar_hash, scalar_hash );
  }
  fd_memcpy( hash, scalar_hash, 32UL );
  return hash;
}
