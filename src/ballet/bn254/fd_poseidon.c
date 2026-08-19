#include "./fd_poseidon.h"
#include "fd_poseidon_params.c"

/* Poseidon internals */

static inline void
fd_poseidon_apply_ark( fd_bn254_scalar_t         state[],
                       ulong const               width,
                       fd_bn254_scalar_t const * ark ) {
  for( ulong i=0; i<width; i++ ) {
    fd_bn254_scalar_add( &state[i], &state[i], &ark[i] );
  }
}

static inline void
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

static inline void
fd_poseidon_apply_sbox_partial( fd_bn254_scalar_t state[] ) {
  /* Compute s[0]^5 */
  fd_poseidon_apply_sbox_full( state, 1 );
}

static inline void
fd_poseidon_apply_mds( fd_bn254_scalar_t         state[],
                       ulong const               width,
                       fd_bn254_scalar_t const * mds ) {
  fd_bn254_scalar_t x[FD_POSEIDON_MAX_WIDTH+1] = { 0 };
  /* Vector-matrix multiplication (state vector times mds matrix) */
  for( ulong i=0; i<width; i++ ) {
    for( ulong j=0; j<width; j++ ) {
      fd_bn254_scalar_t t[1];
      fd_bn254_scalar_mul( t, &state[j], &mds[ i * width + j ] );
      fd_bn254_scalar_add( &x[i], &x[i], t );
    }
  }
  for( ulong i=0; i<width; i++ ) {
    state[i] = x[i];
  }
}

static inline void
fd_poseidon_apply_sparse_mds( fd_bn254_scalar_t         state[],
                              ulong const               width,
                              fd_bn254_scalar_t const * row,
                              fd_bn254_scalar_t const * col ) {
  fd_bn254_scalar_t old_s0 = state[0];
  fd_bn254_scalar_t new_s0[1] = { 0 };

  for( ulong j=0; j<width; j++ ) {
    fd_bn254_scalar_t t[1];
    fd_bn254_scalar_mul( t, &state[j], &row[j] );
    fd_bn254_scalar_add( new_s0, new_s0, t );
  }

  for( ulong i=1; i<width; i++ ) {
    fd_bn254_scalar_t t[1];
    fd_bn254_scalar_mul( t, &old_s0, &col[i-1] );
    fd_bn254_scalar_add( &state[i], &state[i], t );
  }

  state[0] = new_s0[0];
}

static inline void
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
fd_poseidon_permute( fd_bn254_scalar_t         state[],
                     ulong const               width,
                     fd_poseidon_par_t const * params,
                     ulong const               partial_rounds ) {
  const ulong half_rounds = 4UL;

  fd_poseidon_apply_ark       ( state, width, params->ark_start );
  fd_poseidon_apply_sbox_full ( state, width );

  for( ulong round=1; round<half_rounds; round++ ) {
    fd_poseidon_apply_ark       ( state, width, params->ark_start + round*width );
    fd_poseidon_apply_mds       ( state, width, params->mds );
    fd_poseidon_apply_sbox_full ( state, width );
  }

  fd_poseidon_apply_ark ( state, width, params->ark_start + half_rounds*width );
  fd_poseidon_apply_mds ( state, width, params->pre_sparse_mds );

  for( ulong round=0; round<partial_rounds; round++ ) {
    fd_poseidon_apply_sbox_partial( state );
    fd_bn254_scalar_add( &state[0], &state[0], &params->ark_partial[ round ] );
    fd_poseidon_apply_sparse_mds( state,
                                  width,
                                  params->sparse_mds_row + round*width,
                                  params->sparse_mds_col + round*(width-1UL) );
  }

  fd_poseidon_apply_sbox_full( state, width );
  for( ulong round=0; round<half_rounds-1UL; round++ ) {
    fd_poseidon_apply_ark       ( state, width, params->ark_end + round*width );
    fd_poseidon_apply_mds       ( state, width, params->mds );
    fd_poseidon_apply_sbox_full ( state, width );
  }
  fd_poseidon_apply_mds_row0( state, width, params->mds );
}

static inline void
fd_poseidon_get_params( fd_poseidon_par_t * params,
                        ulong const         width ) {
#define FD_POSEIDON_GET_PARAMS(w) case (w):                       \
  params->ark            = fd_poseidon_ark_## w;                  \
  params->mds            = fd_poseidon_mds_## w;                  \
  params->ark_start      = fd_poseidon_ark_start_## w;            \
  params->ark_partial    = fd_poseidon_ark_partial_## w;          \
  params->ark_end        = fd_poseidon_ark_end_## w;              \
  params->pre_sparse_mds = fd_poseidon_pre_sparse_mds_## w;       \
  params->sparse_mds_row = fd_poseidon_sparse_mds_row_## w;       \
  params->sparse_mds_col = fd_poseidon_sparse_mds_col_## w;       \
  break

  switch( width ) {
  FD_POSEIDON_GET_PARAMS(2);
  FD_POSEIDON_GET_PARAMS(3);
  FD_POSEIDON_GET_PARAMS(4);
  FD_POSEIDON_GET_PARAMS(5);
  FD_POSEIDON_GET_PARAMS(6);
  FD_POSEIDON_GET_PARAMS(7);
  FD_POSEIDON_GET_PARAMS(8);
  FD_POSEIDON_GET_PARAMS(9);
  FD_POSEIDON_GET_PARAMS(10);
  FD_POSEIDON_GET_PARAMS(11);
  FD_POSEIDON_GET_PARAMS(12);
  FD_POSEIDON_GET_PARAMS(13);
  }
#undef FD_POSEIDON_GET_PARAMS
}

/* Poseidon interface */

fd_poseidon_t *
fd_poseidon_init( fd_poseidon_t * pos,
                  int const       big_endian ) {
  if( FD_UNLIKELY( pos==NULL ) ) {
    return NULL;
  }
  pos->big_endian = big_endian;
  pos->cnt = 0UL;
  fd_memset( pos->state, 0, sizeof(pos->state) );
  return pos;
}

fd_poseidon_t *
fd_poseidon_append( fd_poseidon_t * pos,
                    uchar const *   data,
                    ulong           sz ) {
  if( FD_UNLIKELY( pos==NULL ) ) {
    return NULL;
  }
  if( FD_UNLIKELY( pos->cnt >= FD_POSEIDON_MAX_WIDTH ) ) {
    return NULL;
  }
  if( FD_UNLIKELY( sz!=32UL ) ) {
    return NULL;
  }

  /* Handle endianness */
  fd_bn254_scalar_t cur[1] = { 0 };
  fd_memcpy( cur->buf, data, 32UL );
  if( pos->big_endian ) {
    fd_uint256_bswap( cur, cur );
  }

  if( FD_UNLIKELY( !fd_bn254_scalar_validate( cur ) ) ) {
    return NULL;
  }
  pos->cnt++;
  fd_bn254_scalar_to_mont( &pos->state[ pos->cnt ], cur );

  return pos;
}

uchar *
fd_poseidon_fini( fd_poseidon_t * pos,
                  uchar           hash[ FD_POSEIDON_HASH_SZ ] ) {
  if( FD_UNLIKELY( pos==NULL ) ) {
    return NULL;
  }
  if( FD_UNLIKELY( !pos->cnt ) ) {
    return NULL;
  }
  const ulong width = pos->cnt+1;
  fd_poseidon_par_t params[1] = { 0 };
  fd_poseidon_get_params( params, width );
  if( FD_UNLIKELY( !params->ark            ||
                   !params->mds            ||
                   !params->ark_start      ||
                   !params->ark_partial    ||
                   !params->ark_end        ||
                   !params->pre_sparse_mds ||
                   !params->sparse_mds_row ||
                   !params->sparse_mds_col ) ) {
    return NULL;
  }

#define FD_POSEIDON_PERMUTE_CASE(w,p) case (w): fd_poseidon_permute( pos->state, (w), params, (p) ); break
  switch( width ) {
  FD_POSEIDON_PERMUTE_CASE( 2UL,  56UL );
  FD_POSEIDON_PERMUTE_CASE( 3UL,  57UL );
  FD_POSEIDON_PERMUTE_CASE( 4UL,  56UL );
  FD_POSEIDON_PERMUTE_CASE( 5UL,  60UL );
  FD_POSEIDON_PERMUTE_CASE( 6UL,  60UL );
  FD_POSEIDON_PERMUTE_CASE( 7UL,  63UL );
  FD_POSEIDON_PERMUTE_CASE( 8UL,  64UL );
  FD_POSEIDON_PERMUTE_CASE( 9UL,  63UL );
  FD_POSEIDON_PERMUTE_CASE( 10UL, 60UL );
  FD_POSEIDON_PERMUTE_CASE( 11UL, 66UL );
  FD_POSEIDON_PERMUTE_CASE( 12UL, 60UL );
  FD_POSEIDON_PERMUTE_CASE( 13UL, 65UL );
  default: return NULL;
  }
#undef FD_POSEIDON_PERMUTE_CASE

  /* Convert through a local scalar: hash only needs to be byte aligned. */
  fd_bn254_scalar_t scalar_hash[1];
  fd_bn254_scalar_from_mont( scalar_hash, &pos->state[0] );
  if( pos->big_endian ) {
    fd_uint256_bswap( scalar_hash, scalar_hash );
  }
  fd_memcpy( hash, scalar_hash, 32 );
  return hash;
}
