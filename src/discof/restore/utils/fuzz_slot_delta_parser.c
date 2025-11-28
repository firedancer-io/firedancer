#include "fd_slot_delta_parser.h"

#include "../../../util/fd_util.h"

#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <stdlib.h>
#include <assert.h>

fd_slot_delta_parser_t * parser;

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  putenv( "FD_LOG_BACKTRACE=0" );
  fd_boot( argc, argv );
  atexit( fd_halt );

  void * parser_mem = aligned_alloc( fd_slot_delta_parser_align(), fd_slot_delta_parser_footprint() );
  parser = fd_slot_delta_parser_join( fd_slot_delta_parser_new( parser_mem ) );
  assert( parser );

  /* Disable parsing error logging */
  fd_log_level_stderr_set(4);
  fd_log_level_logfile_set(4);
  return 0;
}

int
LLVMFuzzerTestOneInput( uchar const * data_,
                        ulong         size ) {
  ulong bytes_remaining = size;
  fd_slot_delta_parser_init( parser );

  fd_slot_delta_parser_advance_result_t result[1];
  while( bytes_remaining ) {
    int res = fd_slot_delta_parser_consume( parser, data_, bytes_remaining, result );

    if( res==FD_SLOT_DELTA_PARSER_ADVANCE_DONE || res<0 ) break;

    data_           += result->bytes_consumed;
    bytes_remaining -= result->bytes_consumed;
  }
  return 0;
}
