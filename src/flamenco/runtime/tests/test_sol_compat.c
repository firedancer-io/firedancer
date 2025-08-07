#include "fd_solfuzz.h"
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "../fd_runtime.h"
#include "../../../ballet/nanopb/pb_firedancer.h"

/* run_test runs a test.
   Return 1 on success, 0 on failure. */
static int
run_test( fd_solfuzz_runner_t * runner,
          char const *          path ) {

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
    ok = fd_solfuzz_instr_fixture( runner, buf, file_sz );
  } else if( strstr( path, "/txn/" ) != NULL ) {
    ok = fd_solfuzz_txn_fixture( runner, buf, file_sz );
  } else if( strstr( path, "/elf_loader/" ) != NULL ) {
    ok = fd_solfuzz_elf_loader_fixture( runner, buf, file_sz );
  } else if( strstr( path, "/syscall/" ) != NULL ) {
    ok = fd_solfuzz_syscall_fixture( runner, buf, file_sz );
  } else if( strstr( path, "/vm_interp/" ) != NULL ){
    ok = fd_solfuzz_vm_interp_fixture( runner, buf, file_sz );
  } else if( strstr( path, "/block/" ) != NULL ){
    ok = fd_solfuzz_block_fixture( runner, buf, file_sz );
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

  char const * wksp_name = fd_env_strip_cmdline_cstr ( &argc, &argv, "--wksp",      NULL,    NULL );
  uint         wksp_seed = fd_env_strip_cmdline_uint ( &argc, &argv, "--wksp-seed", NULL,      0U );
  ulong        wksp_tag  = fd_env_strip_cmdline_ulong( &argc, &argv, "--wksp-tag",  NULL,     1UL );
  ulong        data_max  = fd_env_strip_cmdline_ulong( &argc, &argv, "--data-max",  NULL, 6UL<<30 ); /* 6 GiB */
  ulong        part_max  = fd_env_strip_cmdline_ulong( &argc, &argv, "--part-max",  NULL, fd_wksp_part_max_est( data_max, 64UL<<10 ) );

  fd_wksp_t * wksp;
  if( wksp_name ) {
    FD_LOG_INFO(( "Attaching to --wksp %s", wksp_name ));
    wksp = fd_wksp_attach( wksp_name );
  } else {
    FD_LOG_INFO(( "--wksp not specified, using anonymous demand-paged memory --part-max %lu --data-max %lu", part_max, data_max ));
    wksp = fd_wksp_demand_paged_new( "solfuzz", wksp_seed, part_max, data_max );
  }
  if( FD_UNLIKELY( !wksp ) ) return 255;

  fd_solfuzz_runner_t * runner = fd_solfuzz_runner_new( wksp, wksp_tag );
  FD_TEST( runner );

  ulong fail_cnt = 0UL;
  for( int j=1; j<argc; j++ ) {
    ulong frames_used_pre_test = runner->spad->frame_free;
    ulong mem_used_pre_test    = runner->spad->mem_used;

    fd_spad_push( runner->spad );
    fail_cnt += !run_test( runner, argv[j] );
    fd_spad_pop( runner->spad );

    ulong frames_used_post_test = runner->spad->frame_free;
    ulong mem_used_post_test    = runner->spad->mem_used;

    FD_TEST( frames_used_pre_test == frames_used_post_test );
    FD_TEST( mem_used_pre_test    == mem_used_post_test    );
  }

  fd_solfuzz_runner_delete( runner );
  if( wksp_name ) fd_wksp_detach( wksp );
  else            fd_wksp_demand_paged_delete( wksp );

  fd_halt();
  return fail_cnt>0UL;
}
