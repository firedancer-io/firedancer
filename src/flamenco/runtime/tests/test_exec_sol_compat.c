#define FD_SCRATCH_USE_HANDHOLDING 1
#include "../../fd_flamenco.h"
#include "harness/fd_exec_sol_compat.h"
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "../../../ballet/nanopb/pb_firedancer.h"

/* run_test runs a test.
   Return 1 on success, 0 on failure. */
static int
run_test( fd_runtime_fuzz_runner_t * runner,
          char const *               path ) {

  /* Read file content to memory */

  int file = open( path, O_RDONLY );
  struct stat st;
  if( FD_UNLIKELY( 0!=fstat( file, &st ) ) ) {
    FD_LOG_WARNING(( "fstat(%s): %s", path, fd_io_strerror( errno ) ));
    return 0;
  }
  ulong file_sz = (ulong)st.st_size;
  uchar * buf = fd_spad_alloc( runner->spad, 1, file_sz );
  FD_TEST( 0==fd_io_read( file, buf, file_sz, file_sz, &file_sz ) );
  FD_TEST( 0==close( file ) );

  /* Execute test */
  int ok = 0;

  FD_LOG_DEBUG(( "Running test %s", path ));

  if( strstr( path, "/instr/" ) != NULL ) {
    ok = sol_compat_instr_fixture( runner, buf, file_sz );
  } else if( strstr( path, "/txn/" ) != NULL ) {
    ok = sol_compat_txn_fixture( runner, buf, file_sz );
  } else if( strstr( path, "/elf_loader/" ) != NULL ) {
    ok = sol_compat_elf_loader_fixture( runner, buf, file_sz );
  } else if( strstr( path, "/syscall/" ) != NULL ) {
    ok = sol_compat_syscall_fixture( runner, buf, file_sz );
  } else if( strstr( path, "/vm_interp/" ) != NULL ){
    ok = sol_compat_vm_interp_fixture( runner, buf, file_sz );
  } else if( strstr( path, "/block/" ) != NULL ){
    ok = sol_compat_block_fixture( runner, buf, file_sz );
  } else {
    FD_LOG_WARNING(( "Unknown test type: %s", path ));
  }

  if( ok ) FD_LOG_INFO   (( "OK   %s", path ));
  else     FD_LOG_WARNING(( "FAIL %s", path ));

  return ok;
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  ulong wksp_page_sz = fd_env_strip_cmdline_ulong( &argc, &argv, "--wksp-page-sz", "SOL_COMPAT_WKSP_PAGE_SZ", ULONG_MAX );
  if( wksp_page_sz == ULONG_MAX ) {
    wksp_page_sz = FD_SHMEM_NORMAL_PAGE_SZ;
  }

  sol_compat_wksp_init( wksp_page_sz );

  ulong fail_cnt = 0UL;
  for( int j=1; j<argc; j++ ) {
    // Init runner
    fd_runtime_fuzz_runner_t * runner = sol_compat_setup_runner();

    ulong frames_used_pre_test = runner->spad->frame_free;
    ulong mem_used_pre_test    = runner->spad->mem_used;

    FD_SPAD_FRAME_BEGIN( runner->spad ) {

    fail_cnt += !run_test( runner, argv[j] );

    } FD_SPAD_FRAME_END;

    ulong frames_used_post_test = runner->spad->frame_free;
    ulong mem_used_post_test    = runner->spad->mem_used;

    FD_TEST( frames_used_pre_test == frames_used_post_test );
    FD_TEST( mem_used_pre_test    == mem_used_post_test    );

    // Free runner
    sol_compat_cleanup_runner( runner );

    // Check usage
    sol_compat_check_wksp_usage();

  }

  /* TODO: verify that there are no leaked libc allocs and vallocs */
  sol_compat_fini();
  fd_halt();
  return fail_cnt>0UL;
}
