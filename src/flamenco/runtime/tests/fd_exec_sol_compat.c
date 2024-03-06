#include "fd_exec_instr_test.h"
#include "../../nanopb/pb_decode.h"
#include "../../nanopb/pb_encode.h"
#include <assert.h>
#include <stdlib.h>

/* This file defines stable APIs for compatibility testing.

   For the "compat" shared library used by the differential fuzzer,
   ideally the symbols defined in this file would be the only visible
   globals.  Unfortunately, we currently export all symbols, which leads
   to great symbol table bloat from fd_types.c. */

int
sol_compat_instr_execute_v1( uchar *       out,
                             ulong *       out_sz,
                             uchar const * in,
                             ulong         in_sz ) {

  static       uchar *     smem;
  static const ulong       smax = 1UL<<30;
  static       fd_wksp_t * wksp = NULL;
  FD_ONCE_BEGIN {
    int argc = 1;
    char * argv[1] = { strdup( "fd_exec_sol_compat" ) };
    char ** argv_ = argv;
    fd_boot( &argc, &argv_ );
    fd_log_level_logfile_set(5);

    ulong cpu_idx = fd_tile_cpu_id( fd_tile_idx() );
    if( cpu_idx>=fd_shmem_cpu_cnt() ) cpu_idx = 0UL;
    wksp = fd_wksp_new_anonymous( FD_SHMEM_NORMAL_PAGE_SZ, 65536, fd_shmem_cpu_idx( fd_shmem_numa_idx( cpu_idx ) ), "wksp", 0UL );
    assert( wksp );

    smem = malloc( smax );  /* 1 GiB */
    assert( smem );
  } FD_ONCE_END;

  ulong fmem[ 64 ];
  fd_scratch_attach( smem, fmem, smax, 64UL );
  fd_scratch_push();

  pb_istream_t istream = pb_istream_from_buffer( in, in_sz );
  fd_exec_test_instr_context_t input[1] = {0};
  int decode_ok = pb_decode_ex( &istream, &fd_exec_test_instr_context_t_msg, input, PB_DECODE_NOINIT );
  if( !decode_ok ) {
    pb_release( &fd_exec_test_instr_context_t_msg, input );
    return 0;
  }

  void * runner_mem = fd_wksp_alloc_laddr( wksp, fd_exec_instr_test_runner_align(), fd_exec_instr_test_runner_footprint(), 2 );
  fd_exec_instr_test_runner_t * runner = fd_exec_instr_test_runner_new( runner_mem, 3 );

  fd_exec_test_instr_effects_t * output = NULL;
  do {
    void * out0 = fd_scratch_prepare( 1UL );
    ulong out_bufsz = fd_scratch_free();
    ulong out_used = fd_exec_instr_test_run( runner, input, &output, out0, out_bufsz );
    if( FD_UNLIKELY( !out_used ) ) {
      output = NULL;
      fd_scratch_cancel();
      break;
    }

    fd_scratch_publish( (void *)( (ulong)out + out_used ) );
  } while(0);

  int ok = 0;
  if( output ) {
    pb_ostream_t ostream = pb_ostream_from_buffer( out, *out_sz );
    int encode_ok = pb_encode( &ostream, &fd_exec_test_instr_effects_t_msg, output );
    if( encode_ok ) {
      *out_sz = ostream.bytes_written;
      ok = 1;
    }
  }

  fd_wksp_free_laddr( fd_exec_instr_test_runner_delete( runner ) );
  pb_release( &fd_exec_test_instr_context_t_msg, input );
  fd_scratch_pop();
  fd_scratch_detach( NULL );
  return ok;
}
