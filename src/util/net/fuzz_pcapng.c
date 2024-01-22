#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "../fd_util.h"
#include "../../util/sanitize/fd_fuzz.h"
#include "./fd_pcapng_private.h"

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  /* Set up shell without signal handlers */
  putenv( "FD_LOG_BACKTRACE=0" );
  putenv( "FD_LOG_PATH=" );
  fd_boot( argc, argv );
  atexit( fd_halt );

  /* Disable parsing error logging */
  fd_log_level_stderr_set(4);
  return 0;
}

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         data_sz ) {

  FILE * file;
  if( FD_UNLIKELY( data_sz==0UL ) )
    file = fopen( "/dev/null", "rb" );
  else
    file = fmemopen( (void *)data, data_sz, "rb" );
  FD_TEST( file );

  /* Construct fake pcapng state */
  fd_pcapng_iter_t iter = {
    .stream    = file,
    .iface_cnt = 1UL,
    .iface     = {
      { .link_type = FD_PCAPNG_LINKTYPE_ETHERNET,
        .opts = {
          .name     = "eth0",
          .ip4_addr = {(uchar)127, (uchar)0, (uchar)0, (uchar)1},
          .mac_addr = "\x06\x00\xde\xad\xbe\xef",
          .tsresol  = FD_PCAPNG_TSRESOL_NS,
          .hardware = "fake interface"
        } }
    }
  };

  for(;;) {
    FD_FUZZ_MUST_BE_COVERED;
    fd_pcapng_frame_t const * frame = fd_pcapng_iter_next( &iter );
    if( !frame ) break;

    /* Read all fields */
    ulong value;
    value = (ulong)frame->type;    FD_COMPILER_FORGET( value );
    value = (ulong)frame->ts;      FD_COMPILER_FORGET( value );
    value = (ulong)frame->orig_sz; FD_COMPILER_FORGET( value );
    value = (ulong)frame->if_idx;  FD_COMPILER_FORGET( value );
    FD_TEST( frame->data_sz <= FD_PCAPNG_FRAME_SZ );

    uchar x=0;
    for( uint i=0; i<frame->data_sz; i++ ) x ^= frame->data[ i ];
    FD_COMPILER_FORGET( x );
  }

  FD_TEST( 0==fclose( file ) );

  FD_FUZZ_MUST_BE_COVERED;
  return 0;
}

