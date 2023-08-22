#include "fd_sbpf_loader.h"
#include "../../util/fd_util.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  /* Parse command line arguments */

  char const * bin_path = fd_env_strip_cmdline_cstr( &argc, &argv, "--bin", NULL, NULL );

  /* Validate command line arguments */

  if( FD_UNLIKELY( !bin_path ) )
    FD_LOG_ERR(( "--bin not specified" ));

  /* Open file */

  FILE * bin_file = fopen( bin_path, "rb" );
  if( FD_UNLIKELY( !bin_file ) )
    FD_LOG_ERR(( "Failed to open \"%s\" (%i-%s)", bin_path, errno, fd_io_strerror( errno ) ));

  /* Check file content */

  struct stat bin_stat;
  if( FD_UNLIKELY( 0!=fstat( fileno( bin_file ), &bin_stat ) ) )
    FD_LOG_ERR(( "fstat() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( !S_ISREG( bin_stat.st_mode ) ) )
    FD_LOG_ERR(( "File \"%s\" not a regular file", bin_path ));
  if( FD_UNLIKELY( bin_stat.st_size<0L ) )
    FD_LOG_ERR(( "File \"%s\" has invalid size %ld", bin_path, bin_stat.st_size ));

  /* Allocate file */

  long t_pre_read = fd_log_wallclock();

  ulong  bin_sz  = (ulong)bin_stat.st_size;
  void * bin_buf = malloc( bin_sz );
  if( FD_UNLIKELY( !bin_buf ) ) FD_LOG_ERR(( "malloc() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  /* Read file into memory */

  FD_LOG_NOTICE(( "Loading sBPF program: %s", bin_path ));

  if( FD_UNLIKELY( fread( bin_buf, bin_sz, 1UL, bin_file )!=1UL ) )
    FD_LOG_ERR(( "fread() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  long t_post_read = fd_log_wallclock();
  long dt_read = t_post_read-t_pre_read;
  FD_LOG_INFO(( "test_sbpf_loader: Read ELF into memory in %g ns", (double)dt_read ));

  /* Load and reloc program */

  long t_pre_load = fd_log_wallclock();

  fd_sbpf_program_t prog;
  int load_err = fd_sbpf_program_load( &prog, bin_buf, bin_sz );

  long t_post_load = fd_log_wallclock();
  long dt_load = t_post_load-t_pre_load;
  FD_LOG_INFO(( "test_sbpf_loader: Loaded and relocated ELF in %g ns", (double)dt_load ));

  /* Clean up */

  free( bin_buf );

  if( FD_UNLIKELY( 0!=fclose( bin_file ) ) ) FD_LOG_WARNING(( "fclose() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  /* Yield result */

  if( FD_UNLIKELY( load_err!=0 ) ) FD_LOG_ERR(( "FAIL: %s", fd_sbpf_strerror() ));

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
