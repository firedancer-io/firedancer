#include "../fd_ballet.h"

#include "fd_sha1.h"

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  char const * inputs[] = {
    "abc",
    "",
    "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
    "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
    "The quick brown fox jumps over the lazy dog",
  };

  char const * outputs[] = {
    "a9993e364706816aba3e25717850c26c9cd0d89d",
    "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    "84983e441c3bd26ebaae4aa1f95129e5e54670f1",
    "a49b2446a02c645bf419f995b67091253a04a259",
    "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12",
  };

  for( ulong i=0UL; i<sizeof(inputs)/sizeof(inputs[0]); i++ ) {
    uint digest[ 5 ] __attribute__((aligned(4)));
    fd_sha1_hash( (uchar const *)inputs[ i ], strlen( inputs[ i ] ), (uchar *)digest );
    char hexdigest[ 41 ];
    FD_TEST( fd_cstr_printf_check( hexdigest, 41, NULL, "%08x%08x%08x%08x%08x", fd_uint_bswap( digest[ 0 ] ), fd_uint_bswap( digest[ 1 ] ), fd_uint_bswap( digest[ 2 ] ), fd_uint_bswap( digest[ 3 ] ), fd_uint_bswap( digest[ 4 ] ) ) );
    FD_TEST( 0==strcmp( hexdigest, outputs[ i ] ) );
  }

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
