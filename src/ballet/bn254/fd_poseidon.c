#include "./fd_poseidon.h"
#include "fd_poseidon_params.c"

/* Poseidon internals */

static inline void
fd_poseidon_apply_ark( fd_bn254_scalar_t         state[],
                       ulong const               width,
                       fd_poseidon_par_t const * params,
                       ulong                     round ) {
  for( ulong i=0; i<width; i++ ) {
    fd_bn254_scalar_add( &state[i], &state[i], &params->ark[ round * width + i ] );
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
fd_poseidon_apply_mds( FD_FN_UNUSED fd_bn254_scalar_t   state[],
                       FD_FN_UNUSED ulong const       width,
                       FD_FN_UNUSED fd_poseidon_par_t const * params ) {
  fd_bn254_scalar_t x[FD_POSEIDON_MAX_WIDTH+1] = { 0 };
  /* Vector-matrix multiplication (state vector times mds matrix) */
  for( ulong i=0; i<width; i++ ) {
    for( ulong j=0; j<width; j++ ) {
      fd_bn254_scalar_t t[1];
      fd_bn254_scalar_mul( t, &state[j], &params->mds[ i * width + j ] );
      fd_bn254_scalar_add( &x[i], &x[i], t );
    }
  }
  for( ulong i=0; i<width; i++ ) {
    state[i] = x[i];
  }
}

static inline void
fd_poseidon_get_params( fd_poseidon_par_t * params,
                        ulong const         width ) {
#define FD_POSEIDON_GET_PARAMS(w) case (w):                \
  params->ark = (fd_bn254_scalar_t *)fd_poseidon_ark_## w; \
  params->mds = (fd_bn254_scalar_t *)fd_poseidon_mds_## w; \
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
  if( FD_UNLIKELY( sz>32UL ) ) {
    return NULL;
  }

  /* Handle endianness */
  fd_bn254_scalar_t cur[1] = { 0 };
  fd_memcpy( cur->buf + (32-sz)*(pos->big_endian?1:0), data, sz );
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
  if( FD_UNLIKELY( !params->ark || !params->mds ) ) {
    return NULL;
  }

  const ulong PARTIAL_ROUNDS[] = { 56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65, 70, 60, 64, 68 };
  const ulong partial_rounds = PARTIAL_ROUNDS[ pos->cnt-1 ];
  const ulong full_rounds = 8;
  const ulong half_rounds = full_rounds / 2;
  const ulong all_rounds = full_rounds + partial_rounds;

  ulong round=0;
  for (; round<half_rounds; round++ ) {
    fd_poseidon_apply_ark         ( pos->state, width, params, round );
    fd_poseidon_apply_sbox_full   ( pos->state, width );
    fd_poseidon_apply_mds         ( pos->state, width, params );
  }

  for (; round<half_rounds+partial_rounds; round++ ) {
    fd_poseidon_apply_ark         ( pos->state, width, params, round );
    fd_poseidon_apply_sbox_partial( pos->state );
    fd_poseidon_apply_mds         ( pos->state, width, params );
  }

  for (; round<all_rounds; round++ ) {
    fd_poseidon_apply_ark         ( pos->state, width, params, round );
    fd_poseidon_apply_sbox_full   ( pos->state, width );
    fd_poseidon_apply_mds         ( pos->state, width, params );
  }

  /* Directly convert scalar into return hash buffer - hash MUST be FD_UINT256_ALIGNED */
  fd_bn254_scalar_t scalar_hash[1];
  fd_bn254_scalar_from_mont( scalar_hash, &pos->state[0] );
  if( pos->big_endian ) {
    fd_uint256_bswap( scalar_hash, scalar_hash );
  }
  fd_memcpy( hash, scalar_hash, 32 );
  return hash;
}
