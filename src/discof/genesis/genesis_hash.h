#ifndef HEADER_fd_src_discof_genesis_genesis_hash_h
#define HEADER_fd_src_discof_genesis_genesis_hash_h

#include "../../ballet/sha256/fd_sha256.h"

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

static inline ushort
compute_shred_version( uchar const * genesis_hash,
                       ulong const * hard_forks,
                       ulong const * hard_forks_cnts,
                       ulong         hard_forks_cnt ) {
  union {
    uchar  c[ 32 ];
    ushort s[ 16 ];
  } running_hash;
  fd_memcpy( running_hash.c, genesis_hash, 32UL );

  for( ulong i=0UL; i<hard_forks_cnt; i++ ) {
    ulong slot = hard_forks[ i ];
    ulong count = hard_forks_cnts[ i ];

    uchar data[ 48UL ];
    fd_memcpy( data, running_hash.c, 32UL );
    fd_memcpy( data+32UL, &slot, sizeof(ulong) );
    fd_memcpy( data+40UL, &count, sizeof(ulong) );
    FD_TEST( fd_sha256_hash( data, 48UL, running_hash.c ) );
  }

  ushort xor = 0;
  for( ulong i=0UL; i<16UL; i++ ) xor ^= running_hash.s[ i ];

  xor = fd_ushort_bswap( xor );
  xor = fd_ushort_if( xor<USHORT_MAX, (ushort)(xor + 1), USHORT_MAX );

  return xor;
}

static inline int
read_genesis_bin( char const * genesis_path,
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
  if( FD_LIKELY( opt_shred_version ) ) *opt_shred_version = compute_shred_version( hash.c, NULL, NULL, 0UL );

  return 0;
}

#endif /* HEADER_fd_src_discof_genesis_genesis_hash_h */
