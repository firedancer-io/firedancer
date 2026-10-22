#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "../../util/fd_util.h"
#include "../../util/sanitize/fd_fuzz.h"
#include "../../flamenco/runtime/program/vote/fd_vote_codec_tmpl.h"
#include "fd_tower_serdes.h"

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  /* Set up shell without signal handlers */
  putenv( "FD_LOG_BACKTRACE=0" );
  setenv( "FD_LOG_PATH", "", 0 );
  fd_boot( argc, argv );
  atexit( fd_halt );
  fd_log_level_core_set(3); /* crash on warning log */
  return 0;
}

static void
fuzz_vote_instruction( uchar const * data,
                       ulong         data_sz ) {
  fd_compact_tower_sync_serde_t serde[1];
  memset( serde, 0, sizeof(fd_compact_tower_sync_serde_t) );
  int de_err = fd_compact_tower_sync_de( serde, data, data_sz );
  if( de_err ) {
    FD_FUZZ_MUST_BE_COVERED;
    return;
  }
  FD_FUZZ_MUST_BE_COVERED;
}

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         data_sz ) {
  fuzz_vote_instruction( data, data_sz );
  return 0;
}
