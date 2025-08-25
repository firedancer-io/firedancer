#include "../../util/fd_util.h"
#include "fd_lookup.h"

#include <stdlib.h>

/* This function is hidden by default */
int
fd_lookup_ipliteral( struct address buf[static 1],
                     const char *name,
                     int family );

int
LLVMFuzzerInitialize( int *argc,
                      char ***argv ) {
  putenv( "FD_LOG_BACKTRACE=0" );
  fd_boot( argc, argv );
  (void) atexit( fd_halt );
  fd_log_level_core_set( 1 );
  return 0;
}


int
LLVMFuzzerTestOneInput( uchar const *data,
                        ulong        size ) {
  struct address addr = {0};
  char name[0x1000];

  if( FD_UNLIKELY( size<2UL )) {
    return -1;
  }

  uint8_t family_sel = data[ 0 ] & 0x3u;
  int family;
  switch ( family_sel ) {
    case 0:
      family = AF_UNSPEC;
      break;
    case 1:
      family = AF_INET;
      break;
    case 2:
      family = AF_INET6;
      break;
    default:
      family = AF_UNSPEC;
      break;
  }

  ulong name_len = fd_ulong_min( size-1UL, sizeof(name)-1UL );
  fd_memcpy( name, data+1, name_len );
  name[ name_len ] = '\0';

  int ret = fd_lookup_ipliteral( &addr, name, family );

  if( ret > 0 ) {
    FD_TEST((addr.family==AF_INET) | (addr.family==AF_INET6));
  }

  return 0;
}
