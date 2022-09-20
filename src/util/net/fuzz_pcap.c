#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
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
  /* Write fuzz input to a memfd.
   * The fd_pcap interface presently only takes input via FILEs.
   * This setup can be simplified once/if fd_pcap accepts raw byte streams. */
  int fd;
  FD_TEST( (fd = memfd_create( "fuzz input", MFD_CLOEXEC )) != -1 );
  FD_TEST( write( fd, data, size  ) != -1 );
  FD_TEST( lseek( fd, SEEK_SET, 0 ) != -1 );

  /* Promote to file handle. */
  FILE * file = fdopen( fd, "r+b" );
  FD_TEST( file != NULL );

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

  /* Release memfd */
  FD_TEST( fclose( file ) == 0 );
  return 0;
}
