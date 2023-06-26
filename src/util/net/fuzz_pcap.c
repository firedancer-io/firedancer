#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "../fd_util.h"
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

  FILE * file = fmemopen( (void *)data, size, "r+b" );
  FD_TEST( file );

  /* Open "pcap". */
  fd_pcap_iter_t * pcap = fd_pcap_iter_new( file );
  if ( FD_LIKELY( pcap ) ) {
    /* Loop over all packets */
    uchar buf[128];
    long  pkt_ts;
    while( fd_pcap_iter_next(pcap, &buf, sizeof(buf), &pkt_ts) > 0 ) {}

    /* Release pcap */
    FD_TEST( fd_pcap_iter_delete( pcap ) != NULL );
  }

  FD_TEST( 0==fclose( file ) );
  return 0;
}
