#include "fd_exec_instr_test.h"
#include "../../nanopb/pb_decode.h"
#include "../../nanopb/pb_encode.h"
#include <assert.h>
#include <stdlib.h>

typedef struct {
  ulong   struct_size;
  ulong * hardcoded_features;
  ulong   hardcoded_feature_cnt;
  ulong * supported_features;
  ulong   supported_feature_cnt;
} sol_compat_features_t;

static sol_compat_features_t features;
static ulong hardcoded_features[] =
  { 0xd924059c5749c4c1,  // secp256k1_program_enabled
    0x8f688d4e3ab17a60,  // enable_early_verification_of_account_modifications
  };

static ulong supported_features[] =
  { 0xe8f97382b03240a1,  // system_transfer_zero_check
  };

static       uchar *     smem;
static const ulong       smax = 1UL<<30;
static       fd_wksp_t * wksp = NULL;

void
sol_compat_init( void ) {
  assert( !smem );

  int argc = 1;
  char * argv[2] = { (char *)"fd_exec_sol_compat", NULL };
  char ** argv_ = argv;
  setenv( "FD_LOG_PATH", "", 1 );
  fd_boot( &argc, &argv_ );
  fd_log_level_logfile_set(5);
  fd_log_level_core_set(4);  /* abort on FD_LOG_ERR */

  ulong cpu_idx = fd_tile_cpu_id( fd_tile_idx() );
  if( cpu_idx>=fd_shmem_cpu_cnt() ) cpu_idx = 0UL;
  wksp = fd_wksp_new_anonymous( FD_SHMEM_NORMAL_PAGE_SZ, 65536, fd_shmem_cpu_idx( fd_shmem_numa_idx( cpu_idx ) ), "wksp", 0UL );
  assert( wksp );

  smem = malloc( smax );  /* 1 GiB */
  assert( smem );

  features.struct_size           = sizeof(sol_compat_features_t);
  features.hardcoded_features    = hardcoded_features;
  features.hardcoded_feature_cnt = sizeof(hardcoded_features)/sizeof(ulong);
  features.supported_features    = supported_features;
  features.supported_feature_cnt = sizeof(supported_features)/sizeof(ulong);
}

void
sol_compat_fini( void ) {
  fd_wksp_delete_anonymous( wksp );
  free( smem );
  wksp = NULL;
  smem = NULL;
}

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
    ulong out_bufsz = 100000000;  /* 100 MB */
    void * out0 = fd_scratch_prepare( 1UL );
    assert( out_bufsz < fd_scratch_free() );
    fd_scratch_publish( (void *)( (ulong)out0 + out_bufsz ) );
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

sol_compat_features_t const *
sol_compat_get_features_v1( void ) {
  return &features;
}
