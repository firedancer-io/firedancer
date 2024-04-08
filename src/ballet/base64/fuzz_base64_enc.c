#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include "../../util/fd_util.h"
#include "../../util/sanitize/fd_fuzz.h"

#include "fd_base64.h"

/* fuzz_base64_enc verifies that decode(encode(x)) is the identity
   function. */

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

  ulong  enc_sz = FD_BASE64_ENC_SZ( data_sz );
  char * enc    = malloc( enc_sz );
  assert( enc );

  ulong enc_res = fd_base64_encode( enc, data, data_sz );
  assert( enc_res==enc_sz );

  ulong dec_sz = FD_BASE64_DEC_SZ( enc_sz );
  assert( dec_sz <= data_sz+3UL );

  uchar * dec = malloc( dec_sz );
  assert( dec );

  long dec_res = fd_base64_decode( dec, enc, enc_sz );
  assert(        dec_res>=     0L );
  assert( (ulong)dec_res<= dec_sz );
  assert( (ulong)dec_res==data_sz );

  assert( 0==memcmp( dec, data, data_sz ) );

  free( enc );
  free( dec );
  FD_FUZZ_MUST_BE_COVERED;
  return 0;
}
