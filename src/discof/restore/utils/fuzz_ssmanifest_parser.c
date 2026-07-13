#include "fd_ssmsg.h"
#include "fd_ssmanifest_parser.h"

#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <stdlib.h>
#include <assert.h>

fd_snapshot_manifest_t * output_mem;
fd_ssmanifest_parser_t * parser;

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  putenv( "FD_LOG_BACKTRACE=0" );
  setenv( "FD_LOG_PATH", "", 0 );
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
  fd_ssmanifest_parser_init( parser, output_mem );
  uchar const * mbuf  = data_;
  ulong         mrem  = size;
  int           error = 0;
  for(;;) {
    fd_ssmanifest_parser_advance_result_t mres[1];
    int res = fd_ssmanifest_parser_consume( parser, mbuf, mrem, mres );
    if( res==FD_SSMANIFEST_PARSER_ADVANCE_ERROR ) { error = 1; break; }
    if( res==FD_SSMANIFEST_PARSER_ADVANCE_AGAIN || res==FD_SSMANIFEST_PARSER_ADVANCE_DONE ) break;
    mbuf += mres->consumed;
    mrem -= mres->consumed;
  }
  if( !error ) {
    fd_ssmanifest_parser_fini( parser );
  }
  return 0;
}
