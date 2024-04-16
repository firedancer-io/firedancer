#ifndef HEADER_fd_src_app_fddev_genesis_hash_h
#define HEADER_fd_src_app_fddev_genesis_hash_h


#include "../../ballet/sha256/fd_sha256.h"

static inline ushort
compute_shred_version( char const * genesis_path,
                       uchar      * opt_gen_hash  ) {
  /* Compute the shred version and the genesis hash */
  fd_sha256_t _sha[ 1 ];  fd_sha256_t * sha = fd_sha256_join( fd_sha256_new( _sha ) );
  fd_sha256_init( sha );
  uchar buffer[ 4096 ];

  FILE * genesis_file = fopen( genesis_path, "r" );
  if( FD_UNLIKELY( !genesis_file ) ) {
    if( FD_LIKELY( errno==ENOENT ) ) return (ushort)0;

    FD_LOG_ERR(( "Opening genesis file (%s) failed (%i-%s)", genesis_path, errno, fd_io_strerror( errno ) ));
  }

  while( !feof( genesis_file ) ) {
    ulong read = fread( buffer, 1UL, sizeof(buffer), genesis_file );
    if( FD_UNLIKELY( ferror( genesis_file ) ) )
      FD_LOG_ERR(( "fread failed `%s` (%i-%s)", genesis_path, errno, fd_io_strerror( errno ) ));

    fd_sha256_append( sha, buffer, read );
  }

  if( FD_UNLIKELY( fclose( genesis_file ) ) )
    FD_LOG_ERR(( "fclose failed `%s` (%i-%s)", genesis_path, errno, fd_io_strerror( errno ) ));

  union {
    uchar  c[ 32 ];
    ushort s[ 16 ];
  } hash;
  fd_sha256_fini( sha, hash.c );
  fd_sha256_delete( fd_sha256_leave( sha ) );

  if( FD_LIKELY( opt_gen_hash ) ) memcpy( opt_gen_hash, hash.c, 32UL );

  ushort xor = 0;
  for( ulong i=0UL; i<16UL; i++ ) xor ^= hash.s[ i ];

  xor = fd_ushort_bswap( xor );
  return fd_ushort_if( xor<USHORT_MAX, (ushort)(xor + 1), USHORT_MAX );
}

#endif /* HEADER_fd_src_app_fddev_genesis_hash_h */
