#include "fd_keccak256.h"
#include "fd_keccak256_private.h"

fd_keccak256_t *
fd_keccak256_init( fd_keccak256_t * sha ) {
  fd_memset( sha->state, 0, sizeof( sha->state ) );

  sha->padding_start = 0;

  return sha;
}

fd_keccak256_t *
fd_keccak256_append( fd_keccak256_t * sha,
                     void const *     _data,
                     ulong            sz ) {

  /* If no data to append, we are done */

  if( FD_UNLIKELY( !sz ) ) return sha; /* optimize for non-trivial append */

  /* Unpack inputs */

  ulong * state         = sha->state;
  uchar * state_bytes   = (uchar*) sha->state;
  ulong   padding_start = sha->padding_start;

  uchar const * data = (uchar const *)_data;

  ulong state_idx = padding_start;
  for( ulong i = 0; i < sz; i++ ) {
    state_bytes[state_idx] ^= data[i];
    state_idx++;
    if( state_idx >= FD_KECCAK256_RATE ) {
      fd_keccak256_core(state);
      state_idx = 0;
    }
  }

  sha->padding_start = state_idx;

  return sha;
}

void *
fd_keccak256_fini( fd_keccak256_t * sha,
                   void *           hash ) {

  /* Unpack inputs */

  ulong * state         = sha->state;
  uchar * state_bytes   = (uchar*) sha->state;
  ulong   padding_start = sha->padding_start;


  /* Append the terminating message byte */

  state_bytes[padding_start] ^= (uchar)0x01;
  state_bytes[FD_KECCAK256_RATE-1] ^= (uchar)0x80;
  fd_keccak256_core(state);

  /* Copy the result into hash */

  fd_memcpy(hash, state, FD_KECCAK256_OUT_SZ);
  return hash;
}

void *
fd_keccak256_hash( void const * _data,
                ulong        sz,
                void *       _hash ) {
  fd_keccak256_t sha;
  fd_keccak256_init( &sha );
  fd_keccak256_append( &sha, _data, sz );
  fd_keccak256_fini( &sha, _hash );


  return _hash;
}
