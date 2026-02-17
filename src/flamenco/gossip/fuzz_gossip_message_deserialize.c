#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <stdlib.h>

#include "../../util/fd_util.h"
#include "../../util/sanitize/fd_fuzz.h"
#include "fd_gossip_message.h"

extern int
gossip_agave_deserialize( uchar const * data,
                          ulong         len );

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  putenv( "FD_LOG_BACKTRACE=0" );
  fd_boot( argc, argv );
  atexit( fd_halt );
  fd_log_level_core_set( 3 );

  return 0;
}

static fd_gossip_message_t msg;

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         size ) {
  if( FD_UNLIKELY( size>1232UL ) ) return -1;

  int fd_ok = fd_gossip_message_deserialize( &msg, data, size );
  int agave_ok = gossip_agave_deserialize( data, size )==0;

  if( FD_UNLIKELY( fd_ok!=agave_ok ) ) FD_LOG_ERR(( "MISMATCH: fd=%d agave=%d size=%lu", fd_ok, agave_ok, size ));

  FD_FUZZ_MUST_BE_COVERED;
  return 0;
}
