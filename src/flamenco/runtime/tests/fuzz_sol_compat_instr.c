#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

/* Single-target harness for sol_compat_instr_execute_v1.  Runs in-process so it
   can build under MSAN, which the dlopen'd differential .so cannot host. */

#include <stdlib.h>

#include "../../../util/fd_util.h"
#include "../../../util/sanitize/fd_fuzz.h"
#include "fd_sol_compat.h"

#define OUT_BUFSZ ( 64UL<<20 )
static uchar * g_out_buf;

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  putenv( "FD_LOG_BACKTRACE=0" );
  setenv( "FD_LOG_PATH", "", 0 );
  fd_boot( argc, argv );
  /* sol_compat is globals-based and single-session: init once, single core. */
  sol_compat_init( 0 );
  g_out_buf = malloc( OUT_BUFSZ );
  if( FD_UNLIKELY( !g_out_buf ) ) FD_LOG_ERR(( "out of memory" ));
  atexit( fd_halt );
  return 0;
}

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         size ) {
  ulong out_sz = OUT_BUFSZ;
  if( FD_LIKELY( sol_compat_instr_execute_v1( g_out_buf, &out_sz, data, size ) ) ) {
    FD_FUZZ_MUST_BE_COVERED;
  }
  FD_COMPILER_UNPREDICTABLE( out_sz );
  return 0;
}
