#include "fd_ssmsg.h"
#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <stdlib.h>
#include <unistd.h>
#include <assert.h>

#include "../../../util/fd_util.h"
#include "fd_ssmanifest_parser.h"

fd_snapshot_manifest_t * output_mem;
fd_ssmanifest_parser_t * parser;

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  /* Set up shell without signal handlers */
  putenv( "FD_LOG_BACKTRACE=0" );
  fd_boot( argc, argv );
  atexit( fd_halt );

  output_mem = aligned_alloc( alignof(fd_snapshot_manifest_t), sizeof(fd_snapshot_manifest_t) );
  assert( output_mem );
  void * parser_mem = aligned_alloc( fd_ssmanifest_parser_align(), fd_ssmanifest_parser_footprint() );
  assert( parser_mem  );
  parser = fd_ssmanifest_parser_join( fd_ssmanifest_parser_new( parser_mem ) );
  assert( parser );

  /* Disable parsing error logging */
  fd_log_level_stderr_set(4);
  fd_log_level_logfile_set(4);
  return 0;
}

int
LLVMFuzzerTestOneInput( uchar const * data_,
                        ulong         size ) {
  // FD_LOG_WARNING(( "Fuzzing fd_ssmanifest_parser with %lu bytes", size ));
  fd_ssmanifest_parser_init( parser, output_mem );
  fd_ssmanifest_parser_consume( parser, data_, size );
  return 0;
}
