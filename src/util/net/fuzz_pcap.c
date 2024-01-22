#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "../fd_util.h"
#include "../../util/sanitize/fd_fuzz.h"
#include "./fd_pcap.h"

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  /* Set up shell without signal handlers */
  putenv( "FD_LOG_BACKTRACE=0" );
  fd_boot( argc, argv );
  atexit( fd_halt );

  /* Disable parsing error logging */
  fd_log_level_stderr_set(4);
  return 0;
}

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         size ) {

/* > Before glibc 2.22, if size is specified as zero, fmemopen() fails with the error EINVAL.
   - https://man7.org/linux/man-pages/man3/fmemopen.3.html */
if( FD_UNLIKELY( size==0UL ) ) return 0;

  FILE * file = fmemopen( (void *)data, size, "rb" );
  FD_TEST( file );

  /* Open "pcap". */
  fd_pcap_iter_t * pcap = fd_pcap_iter_new( file );
  if ( FD_LIKELY( pcap ) ) {
    FD_FUZZ_MUST_BE_COVERED;
    /* Loop over all packets */
    uchar buf[128];
    long  pkt_ts;
    while( fd_pcap_iter_next(pcap, &buf, sizeof(buf), &pkt_ts) > 0 ) {}

    /* Release pcap */
    FD_TEST( fd_pcap_iter_delete( pcap ) != NULL );
  }

  FD_TEST( 0==fclose( file ) );

  FD_FUZZ_MUST_BE_COVERED;
  return 0;
}
