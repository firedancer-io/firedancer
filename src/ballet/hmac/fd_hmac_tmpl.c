/* Defines a family of functions implementing HMAC over a single hash
   function.  See fd_hmac.c for example usage.

     #define HASH_ALG       sha256
     #define HASH_SZ        32UL
     #define HASH_BLOCK_SZ  64UL

   HASH_ALG is used to resolve names of the hash algorithm functions
   following fd_sha256 conventions (fd_{HASH_ALG}_{init,append,fini}).
   HASH_SZ is the byte count of the hash function's output value, and
   HASH_BLOCK_SZ is the hash function's internal block size (used by
   HMAC for key expansion). */

#ifndef HASH_ALG
#error "Define HASH_ALG"
#endif

#ifndef HASH_SZ
#error "Define HASH_SZ"
#endif

#ifndef HASH_BLOCK_SZ
#error "Define HASH_BLOCK_SZ"
#endif

#define HMAC_FN  FD_EXPAND_THEN_CONCAT2(fd_hmac_,HASH_ALG)
#define HASH_(x) FD_EXPAND_THEN_CONCAT4(fd_,HASH_ALG,_,x)

void *
HMAC_FN( void const * data,
         ulong        data_sz,
         void const * _key,
         ulong        key_sz,
         void *       hash ) {

  /* https://tools.ietf.org/html/rfc2104 */
  /* https://en.wikipedia.org/wiki/HMAC */

  /* Compress key */

  uchar key[ HASH_BLOCK_SZ ] __attribute__((aligned(32))) = {0};
  if( key_sz>HASH_BLOCK_SZ ) {
    HASH_(hash)( _key, key_sz, key );
    key_sz = HASH_SZ;
  } else {
    fd_memcpy( key, _key, key_sz );
  }

  /* Pad key */

  uchar key_ipad[ HASH_BLOCK_SZ ];
  uchar key_opad[ HASH_BLOCK_SZ ];
  memset( key_ipad, 0x36, HASH_BLOCK_SZ );
  memset( key_opad, 0x5c, HASH_BLOCK_SZ );
  for( ulong i=0; i<HASH_BLOCK_SZ; i++ ) {
    key_ipad[ i ] = (uchar)( key_ipad[ i ] ^ key[ i ] );
    key_opad[ i ] = (uchar)( key_opad[ i ] ^ key[ i ] );
  }

  /* Inner SHA calculation */

  HASH_(t) _sha[ 1 ];
  HASH_(t) * sha = HASH_(join)( HASH_(new)( _sha ) );
  HASH_(init)( sha );
  HASH_(append)( sha, key_ipad, HASH_BLOCK_SZ );
  HASH_(append)( sha, data, data_sz );
  HASH_(fini)( sha, hash );

  /* Outer SHA calculation */

  HASH_(init)( sha );
  HASH_(append)( sha, key_opad, HASH_BLOCK_SZ );
  HASH_(append)( sha, hash,     HASH_SZ       );
  HASH_(fini)( sha, hash );

  return hash;
}

#undef HMAC_FN
#undef HASH_

#undef HASH_ALG
#undef HASH_SZ
#undef HASH_BLOCK_SZ
