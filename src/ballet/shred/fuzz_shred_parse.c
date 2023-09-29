#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <stdio.h>
#include <stdlib.h>

#include "../../util/fd_util.h"
#include "fd_shred.h"

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  /* Set up shell without signal handlers */
  putenv( "FD_LOG_BACKTRACE=0" );
  fd_boot( argc, argv );
  atexit( fd_halt );
  return 0;
}

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         size ) {

  fd_shred_t const * shred = fd_shred_parse( data, size );
  if( shred==NULL ) return 0;

  if( fd_shred_merkle_cnt( shred->variant ) ) {
    if( (ulong)(fd_shred_merkle_nodes( shred )+fd_shred_merkle_cnt( shred->variant )) > (ulong)(data+size) ) __builtin_trap();
  }
  switch( fd_shred_type( shred->variant ) ) {
    case FD_SHRED_TYPE_LEGACY_CODE:
    case FD_SHRED_TYPE_MERKLE_CODE:
      if( fd_shred_code_payload( shred )+fd_shred_payload_sz( shred ) > data+size ) __builtin_trap();
      break;
    case FD_SHRED_TYPE_LEGACY_DATA:
    case FD_SHRED_TYPE_MERKLE_DATA:
      if( fd_shred_data_payload( shred )+fd_shred_payload_sz( shred ) > data+size ) __builtin_trap();
      break;
    default:
      __builtin_trap();
      break;
  }

  return 0;
}
