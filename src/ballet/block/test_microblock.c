#include "fd_microblock.h"
#include <stddef.h>

FD_STATIC_ASSERT( sizeof( fd_microblock_hdr_t ) == 0x30UL, layout );
FD_STATIC_ASSERT( offsetof( fd_microblock_hdr_t, hash_cnt ) == 0x00UL, layout );
FD_STATIC_ASSERT( offsetof( fd_microblock_hdr_t, hash     ) == 0x08UL, layout );
FD_STATIC_ASSERT( offsetof( fd_microblock_hdr_t, txn_cnt  ) == 0x28UL, layout );

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  /* Add more checks here */

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
