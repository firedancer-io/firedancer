/* 
  Run test fixtures for the elf loader. The executable takes in a list of ELFLoaderFixture 
  message files, executes them and compares the effects with the expected output contained
  in the fixture.
*/
#include "../../../util/fd_util.h"
#include "fd_exec_test.pb.h"
#include "fd_exec_instr_test.h"
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include "../../nanopb/pb_decode.h"
#include <assert.h>

static int
diff_effects( fd_exec_test_elf_loader_effects_t const * expected,
              fd_exec_test_elf_loader_effects_t const * actual ) {
  int diff = 0;
  // TODO: Report differences at the field level
  if( expected->rodata_sz != actual->rodata_sz ) {
    diff = 1;
    FD_LOG_WARNING(( "ro data size: expected %lu, actual %lu", expected->rodata_sz, actual->rodata_sz ));
  };
  if( expected->text_cnt != actual->text_cnt ) {
    diff = 1;
    FD_LOG_WARNING(( "Instruction count: expected %lu, actual %lu", expected->text_cnt, actual->text_cnt ));
  }
  if( expected->entry_pc != actual->entry_pc ) {
    diff = 1;
    FD_LOG_WARNING(( "Entry PC: expected %lu, actual %lu", expected->entry_pc, actual->entry_pc ));
  }
  if( expected->calldests_count != actual->calldests_count ) {
    diff = 1;
    FD_LOG_WARNING(( "calldests count: expected %d, actual %d", expected->calldests_count, actual->calldests_count ));
  }
  if( memcmp( expected->calldests, actual->calldests, expected->calldests_count*sizeof(ulong) ) != 0 ){
    diff = 1;
    FD_LOG_WARNING(( "calldests differ" ));
  }
    
  if( memcmp( expected->rodata, actual->rodata, expected->rodata_sz ) != 0 ){
    diff = 1;
    FD_LOG_WARNING(( "rodata differ" ));
  }
  
  return diff;
}

static int
run_test( char const * path ) {
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

  pb_istream_t istream = pb_istream_from_buffer( buf, file_sz );
  fd_exec_test_elf_loader_fixture_t fixture[1] = {0};
  int decode_ok = pb_decode_ex( &istream, &fd_exec_test_elf_loader_fixture_t_msg, fixture, PB_DECODE_NOINIT );

  if( FD_UNLIKELY( !decode_ok ) ) {
    FD_LOG_WARNING(( "%s: failed to decode (%s)", path, PB_GET_ERROR(&istream) ));
    pb_release( &fd_exec_test_elf_loader_fixture_t_msg, fixture );
    return 0;
  }

  /* Run test */
  fd_exec_test_elf_loader_effects_t * output = NULL;
  int diff = 0;
  do {
    ulong out_bufsz = 50000000; /* 50MB */
    void * out0 = fd_scratch_prepare( 1UL );
    FD_TEST( out_bufsz < fd_scratch_free() );
    fd_scratch_publish( (void *)( (ulong)out0 + out_bufsz ) );
    ulong out_used = fd_sbpf_program_load_test_run( &fixture->input, &output, out0, out_bufsz );
    if( FD_UNLIKELY( !out_used ) ) {
      FD_LOG_WARNING(( "Failed to load from fixture %s", path ));
      output = NULL;
      break;
    }
    /* Compare effects */
    diff = diff_effects( &fixture->output, output );
    if( diff ) {
      /* Need "FAIL" for run_test_vectors script to pickup failure */
      FD_LOG_WARNING(( "FAIL: Elf loader effects differ for fixture %s", path ));
    }

  } while(0);

  pb_release( &fd_exec_test_elf_loader_fixture_t_msg, fixture );
  return diff; 

}



int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  static uchar scratch_mem [ 1<<28 ];  /* 256MB */
  static ulong scratch_fmem[ 4UL ] __attribute((aligned(FD_SCRATCH_FMEM_ALIGN)));
  fd_scratch_attach( scratch_mem, scratch_fmem, 1UL<<28, 4UL );

  ulong fail_cnt = 0UL;
  for( int j=1; j<argc; j++ ) {
    assert( fd_scratch_frame_used()==0UL );
    fd_scratch_push();
    fail_cnt += !run_test( argv[j] );
    fd_scratch_pop();
  }
  FD_TEST( fd_scratch_frame_used()==0UL );
  fd_scratch_detach( NULL );
  return fail_cnt>0UL;
}
