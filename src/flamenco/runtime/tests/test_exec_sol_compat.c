#define FD_SCRATCH_USE_HANDHOLDING 1
#include "../../fd_flamenco_base.h"
#include "fd_exec_sol_compat.h"
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "../../nanopb/pb_firedancer.h"

/* run_test runs a test.
   Return 1 on success, 0 on failure. */
static int
run_test( fd_exec_instr_test_runner_t * runner,
          char const *                  path ) {

  /* Read file content to memory */

  int file = open( path, O_RDONLY );
  struct stat st;
  if( FD_UNLIKELY( 0!=fstat( file, &st ) ) ) {
    FD_LOG_WARNING(( "fstat(%s): %s", path, fd_io_strerror( errno ) ));
    return 0;
  }
  ulong file_sz = (ulong)st.st_size;
  uchar * buf = fd_scratch_alloc( 1, file_sz );
  FD_TEST( 0==fd_io_read( file, buf, file_sz, file_sz, &file_sz ) );
  FD_TEST( 0==close( file ) );

  /* Execute test */
  int ok = 0;

  FD_LOG_DEBUG(( "Running test %s", path ));

  if( strstr( path, "/instr/" ) != NULL ) {
    ok = sol_compat_instr_fixture( runner, buf, file_sz );
  } else if( strstr( path, "/precompile/" ) != NULL ) {
    ok = sol_compat_precompile_fixture( runner, buf, file_sz );
  } else if( strstr( path, "/syscall/" ) != NULL ) {
    ok = sol_compat_syscall_fixture( runner, buf, file_sz );
  }

  if( ok ) FD_LOG_INFO   (( "OK   %s", path ));
  else     FD_LOG_WARNING(( "FAIL %s", path ));

  return ok;
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  sol_compat_wksp_init();

  ulong fmem[ 64 ];
  fd_exec_instr_test_runner_t * runner = sol_compat_setup_scratch_and_runner( fmem );

  ulong fail_cnt = 0UL;
  for( int j=1; j<argc; j++ ) {
    FD_TEST( fd_scratch_frame_used()==0UL );
    fd_scratch_push();
    fail_cnt += !run_test( runner, argv[j] );
    fd_scratch_pop();
  }

  /* TODO verify that there are no leaked libc allocs and vallocs */

  FD_TEST( fd_scratch_frame_used()==0UL );
  sol_compat_cleanup_scratch_and_runner( runner );
  sol_compat_fini();
  fd_halt();
  return fail_cnt>0UL;
}
