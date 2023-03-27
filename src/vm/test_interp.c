#include "../fd_ballet.h"

FD_STATIC_ASSERT( FD_SHA256_ALIGN    ==128UL, unit_test );
FD_STATIC_ASSERT( FD_SHA256_FOOTPRINT==128UL, unit_test );

FD_STATIC_ASSERT( FD_SHA256_ALIGN    ==alignof(fd_sha256_t), unit_test );
FD_STATIC_ASSERT( FD_SHA256_FOOTPRINT==sizeof (fd_sha256_t), unit_test );

FD_STATIC_ASSERT( FD_SHA256_LG_HASH_SZ==5,    unit_test );
FD_STATIC_ASSERT( FD_SHA256_HASH_SZ   ==32UL, unit_test );

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_halt();
  return 0;
}

