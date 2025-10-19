#ifndef HEADER_fd_src_discof_genesis_genesis_hash_h
#define HEADER_fd_src_discof_genesis_genesis_hash_h

#include "../../ballet/sha256/fd_sha256.h"

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

static inline int
compute_shred_version( char const * genesis_path,
                       ushort *     opt_shred_version,
                       uchar *      opt_gen_hash  ) {
  fd_sha256_t _sha[ 1 ];  fd_sha256_t * sha = fd_sha256_join( fd_sha256_new( _sha ) );
  fd_sha256_init( sha );
  uchar buffer[ 4096 ];

  int fd = open( genesis_path, O_RDONLY );
  if( FD_UNLIKELY( -1==fd ) ) return -1;

  for(;;) {
    long result = read( fd, buffer, sizeof(buffer) );
    if( FD_UNLIKELY( -1==result ) ) {
      if( FD_UNLIKELY( -1==close( fd ) ) ) FD_LOG_ERR(( "close failed `%s` (%i-%s)", genesis_path, errno, fd_io_strerror( errno ) ));
      return -1;
    } else if( FD_UNLIKELY( !result ) ) break;

    fd_sha256_append( sha, buffer, (ulong)result );
  }

  if( FD_UNLIKELY( -1==close( fd ) ) ) FD_LOG_ERR(( "close failed `%s` (%i-%s)", genesis_path, errno, fd_io_strerror( errno ) ));

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
  xor = fd_ushort_if( xor<USHORT_MAX, (ushort)(xor + 1), USHORT_MAX );

  if( FD_LIKELY( opt_shred_version ) ) *opt_shred_version = xor;

  return 0;
}

#endif /* HEADER_fd_src_discof_genesis_genesis_hash_h */
