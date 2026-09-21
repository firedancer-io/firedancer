#include "./fd_poseidon_private.h"

void
fd_poseidon_private_apply_mds( fd_bn254_scalar_t         state[],
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

void
fd_poseidon_private_apply_sparse_mds( fd_bn254_scalar_t         state[],
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

#define FD_POSEIDON_FINI_CASE(n) case (n)-1UL: return fd_poseidon_private_fini_##n( pos, hash )
  switch( pos->cnt ) {
  FD_POSEIDON_FINI_CASE( 2 );
  FD_POSEIDON_FINI_CASE( 3 );
  FD_POSEIDON_FINI_CASE( 4 );
  FD_POSEIDON_FINI_CASE( 5 );
  FD_POSEIDON_FINI_CASE( 6 );
  FD_POSEIDON_FINI_CASE( 7 );
  FD_POSEIDON_FINI_CASE( 8 );
  FD_POSEIDON_FINI_CASE( 9 );
  FD_POSEIDON_FINI_CASE( 10 );
  FD_POSEIDON_FINI_CASE( 11 );
  FD_POSEIDON_FINI_CASE( 12 );
  FD_POSEIDON_FINI_CASE( 13 );
  default: return NULL;
  }
#undef FD_POSEIDON_FINI_CASE
}
