#include "../../util/fd_util.h"
#include "fd_lookup.h"

#include <assert.h>
#include <stdlib.h>

/* This function is hidden by default */
int
fd_dn_expand( uchar const *base,
              uchar const *end,
              uchar const *src,
              char *dest,
              int space );

int
LLVMFuzzerInitialize( int *argc,
                      char ***argv ) {
  /* Set up shell without signal handlers */
  putenv( "FD_LOG_BACKTRACE=0" );
  fd_boot( argc, argv );
  (void) atexit( fd_halt );
  fd_log_level_core_set( 1 ); /* crash on info log */
  return 0;
}


int
LLVMFuzzerTestOneInput( uchar const *data,
                        ulong        size ) {
  char tmp[256] = {0};

  /* Need at least two bytes for the offset plus one byte of data */
  if( FD_UNLIKELY( size<3 )) {
    return 1;
  }

  /* First two bytes pick an offset inside the packet to start
     expansion from.  The modulo arithmetic ensures we never read past
     the end of the provided buffer. */
  ushort offset = (ushort) (((ushort) data[ 0 ] | (ushort) (data[ 1 ] << 8)) % (ushort) (size-2UL));

  int ret = fd_dn_expand( data+2, data+size, /* base/end */
                          data+offset,       /* src      */
                          tmp, sizeof(tmp));

  FD_TEST((ret == -1) || (ret > 0 && ret <= (int) size));
  if( ret>0 ) {
    FD_TEST( tmp[ sizeof(tmp)-1 ]=='\0' );
    FD_TEST( strlen( tmp )<sizeof(tmp));
  }

  return 0;
}
