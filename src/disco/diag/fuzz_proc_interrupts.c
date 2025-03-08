#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#define _GNU_SOURCE
#include <sys/mman.h> /* memfd_create */
#include <errno.h>
#include <fcntl.h> /* open */
#include <assert.h> /* assert */
#include <stdlib.h> /* atexit */
#include <unistd.h> /* close */

#include "../../util/fd_util.h" /* fd_boot */
#include "fd_proc_interrupts.h"

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  /* Set up shell without signal handlers */
  putenv( "FD_LOG_BACKTRACE=0" );
  fd_boot( argc, argv );
  atexit( fd_halt );
  fd_log_level_logfile_set(4); /* ignore warning log */
  fd_log_level_core_set(4); /* crash on error log */
  return 0;
}

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         size ) {
  int memfd = memfd_create( "fuzz_proc_interrupts", 0 );
  if( FD_UNLIKELY( memfd<0 ) ) FD_LOG_ERR(( "memfd_create failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  ulong write_sz;
  FD_TEST( 0==fd_io_write( memfd, data, size, size, &write_sz ) );
  FD_TEST( write_sz==size );
  FD_TEST( 0==lseek( memfd, 0, SEEK_SET ) );

  static ulong per_cpu[ 3 ][ FD_TILE_MAX ];
  (void)fd_proc_interrupts_colwise( memfd, per_cpu[0] );
  (void)fd_proc_softirqs_sum( memfd, per_cpu );

  FD_TEST( 0==close( memfd ) );
  return 0;
}
