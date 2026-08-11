#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <stdio.h>
#include <stdlib.h>

#include "../../util/fd_util.h"
#include "../../util/sanitize/fd_fuzz.h"
#include "fd_zstd.h"

#define MAX_DATA_SZ (1UL<<20)

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  putenv( "FD_LOG_BACKTRACE=0" );
  setenv( "FD_LOG_PATH", "", 0 );
  fd_boot( argc, argv );
  atexit( fd_halt );
  fd_log_level_core_set( 3 );
  return 0;
}

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         data_sz ) {
  if( FD_UNLIKELY( data_sz>MAX_DATA_SZ ) ) return -1;

  ulong             frame_max = fd_ulong_max( data_sz, 1UL );
  fd_zstd_frame_t * frame     = malloc( frame_max*sizeof(fd_zstd_frame_t) );
  FD_TEST( frame );

  ulong frame_cnt = fd_zstd_find_frame_boundaries( (ulong const *)data, data_sz, frame, frame_max*sizeof(fd_zstd_frame_t) );
  FD_TEST( frame_cnt<=frame_max );

  for( ulong i=0UL; i<frame_cnt; i++ ) {
    FD_TEST( frame[i].offset<=data_sz );
    FD_TEST( frame[i].sz<=data_sz-frame[i].offset );
  }

  free( frame );
  FD_FUZZ_MUST_BE_COVERED;
  return 0;
}
