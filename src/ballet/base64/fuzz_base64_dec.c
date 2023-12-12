#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include "../../util/fd_util.h"
#include "../../util/sanitize/fd_fuzz.h"
#include "fd_base64.h"

/* fuzz_base64_dec verifies that Base64 decoding is safe against
   untrusted inputs. */

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
                        ulong         data_sz ) {

  ulong dec_sz = FD_BASE64_DEC_SZ( data_sz );
  assert( dec_sz < data_sz+4UL );

  uchar * dec = malloc( data_sz );
  assert( dec );

  long dec_res = fd_base64_decode( dec, (char const *)data, data_sz );
  if ( dec_res>=0L ) {
    FD_FUZZ_MUST_BE_COVERED;
  } else if ( dec_res==-1L ) {
    FD_FUZZ_MUST_BE_COVERED;
  } else {
    abort();
  }

  free( dec );
  FD_FUZZ_MUST_BE_COVERED;
  return 0;
}
