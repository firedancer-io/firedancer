#include "fd_hmac.h"

#include "../sha256/fd_sha256.h"

void *
fd_hmac_sha256( void const * data,
                ulong        data_sz,
                void const * _key,
                ulong        key_sz,
                void *       hash ) {

  /* https://tools.ietf.org/html/rfc2104 */
  /* https://en.wikipedia.org/wiki/HMAC */

  /* Compress key */

  uchar key[ FD_SHA256_BLOCK_SZ ] __attribute__((aligned(32))) = {0};
  if( key_sz>FD_SHA256_BLOCK_SZ ) {
    fd_sha256_hash( _key, key_sz, key );
    key_sz = FD_SHA256_HASH_SZ;
  } else {
    fd_memcpy( key, _key, key_sz );
  }

  /* Pad key */

  uchar key_ipad[ FD_SHA256_BLOCK_SZ ];
  uchar key_opad[ FD_SHA256_BLOCK_SZ ];
  memset( key_ipad, 0x36, FD_SHA256_BLOCK_SZ );
  memset( key_opad, 0x5c, FD_SHA256_BLOCK_SZ );
  for( ulong i=0; i<FD_SHA256_BLOCK_SZ; i++ ) {
    key_ipad[ i ] = (uchar)( key_ipad[ i ] ^ key[ i ] );
    key_opad[ i ] = (uchar)( key_opad[ i ] ^ key[ i ] );
  }

  /* Inner SHA calculation */

  fd_sha256_t _sha[ 1 ];
  fd_sha256_t * sha = fd_sha256_join( fd_sha256_new( _sha ) );
  fd_sha256_init( sha );
  fd_sha256_append( sha, key_ipad, FD_SHA256_BLOCK_SZ );
  fd_sha256_append( sha, data, data_sz );
  fd_sha256_fini( sha, hash );

  /* Outer SHA calculation */

  fd_sha256_init( sha );
  fd_sha256_append( sha, key_opad, FD_SHA256_BLOCK_SZ );
  fd_sha256_append( sha, hash, FD_SHA256_HASH_SZ );
  fd_sha256_fini( sha, hash );

  return hash;
}
