#include "fd_solfuzz.h"
#include "fd_solfuzz_private.h"
#define _GNU_SOURCE
#include "fd_sol_compat.h"

#include "../fd_executor_err.h"
#include "../../../ballet/shred/fd_shred.h"

#include "generated/block.pb.h"
#include "generated/elf.pb.h"
#include "generated/invoke.pb.h"
#include "generated/shred.pb.h"
#include "generated/vm.pb.h"
#include "generated/txn.pb.h"

#if FD_HAS_FLATCC
#include "flatbuffers/generated/elf_reader.h"
#include "flatbuffers/generated/flatbuffers_common_reader.h"
#endif

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

static fd_wksp_t *           wksp   = NULL;
static fd_solfuzz_runner_t * runner = NULL;

static fd_solfuzz_runner_t *
sol_compat_setup_runner( fd_solfuzz_runner_options_t const * options ) {
  runner = fd_solfuzz_runner_new( wksp, 3UL, options );
  if( FD_UNLIKELY( !runner ) ) {
    FD_LOG_ERR(( "fd_solfuzz_runner_new() failed" ));
    return NULL;
  }

  return runner;
}

static void
sol_compat_cleanup_runner( fd_solfuzz_runner_t * runner ) {
  fd_solfuzz_runner_delete( runner );
}

void
sol_compat_init( int log_level ) {
  int argc = 1;
  char * argv[2] = { (char *)"fd_exec_sol_compat", NULL };
  char ** argv_ = argv;
  if( !getenv( "FD_LOG_PATH" ) ) {
    setenv( "FD_LOG_PATH", "", 1 );
  }

  char const * enable_vm_tracing_env  = getenv( "ENABLE_VM_TRACING");
  int enable_vm_tracing               = enable_vm_tracing_env!=NULL;
  fd_solfuzz_runner_options_t options = {
    .enable_vm_tracing = enable_vm_tracing
  };

  fd_log_enable_unclean_exit();
  fd_boot( &argc, &argv_ );

  if( FD_UNLIKELY( wksp || runner ) ) {
    FD_LOG_ERR(( "sol_compat_init() called multiple times" ));
  }

  ulong footprint = 7UL<<30;
  ulong part_max  = fd_wksp_part_max_est( footprint, 64UL<<10 );
  ulong data_max  = fd_wksp_data_max_est( footprint, part_max );
  wksp = fd_wksp_demand_paged_new( "sol_compat", 42U, part_max, data_max );
  if( FD_UNLIKELY( !wksp ) ) FD_LOG_ERR(( "fd_wksp_demand_paged_new() failed" ));

  runner = sol_compat_setup_runner( &options );
  if( FD_UNLIKELY( !runner ) ) FD_LOG_ERR(( "sol_compat_setup_runner() failed" ));

  fd_log_level_logfile_set( log_level );
  fd_log_level_core_set(4);  /* abort on FD_LOG_ERR */
}

void
sol_compat_fini( void ) {
  sol_compat_cleanup_runner( runner );
  fd_wksp_delete_anonymous( wksp );
  wksp   = NULL;
  runner = NULL;
  fd_halt();
}

sol_compat_features_t const *
sol_compat_get_features_v1( void ) {
  static sol_compat_features_t features;
  static ulong hardcoded_features[ FD_FEATURE_ID_CNT ];
  static ulong supported_features[ FD_FEATURE_ID_CNT ];

  FD_ONCE_BEGIN {
    features.struct_size = sizeof(sol_compat_features_t);
    features.hardcoded_features = hardcoded_features;
    features.supported_features = supported_features;
    for( fd_feature_id_t const * iter = fd_feature_iter_init();
         !fd_feature_iter_done( iter );
         iter = fd_feature_iter_next( iter ) ) {
      if( iter->reverted ) continue; /* skip reverted features */

      /* Pretend that features activated on all clusters are hardcoded */
      if( iter->hardcode_for_fuzzing ) {
        hardcoded_features[ features.hardcoded_features_cnt++ ] = iter->id.ul[0];
      } else {
        supported_features[ features.supported_feature_cnt++  ] = iter->id.ul[0];
      }
    }
  }
  FD_ONCE_END;

  return &features;
}

/*
 * execute_v1
 */

int
sol_compat_instr_execute_v1( uchar *       out,
                             ulong *       out_sz,
                             uchar const * in,
                             ulong         in_sz ) {
  fd_exec_test_instr_context_t input[1] = {0};
  void * res = sol_compat_decode_lenient( &input, in, in_sz, &fd_exec_test_instr_context_t_msg );
  if( FD_UNLIKELY( !res ) ) return 0;

  int ok = 0;
  fd_spad_push( runner->spad );
  void * output = NULL;
  fd_solfuzz_pb_execute_wrapper( runner, input, &output, fd_solfuzz_pb_instr_run );
  if( output ) {
    ok = !!sol_compat_encode( out, out_sz, output, &fd_exec_test_instr_effects_t_msg );
  }
  fd_spad_pop( runner->spad );

  pb_release( &fd_exec_test_instr_context_t_msg, input );
  fd_solfuzz_runner_leak_check( runner );
  return ok;
}

int
sol_compat_txn_execute_v1( uchar *       out,
                           ulong *       out_sz,
                           uchar const * in,
                           ulong         in_sz ) {
  fd_exec_test_txn_context_t input[1] = {0};
  void * res = sol_compat_decode_lenient( &input, in, in_sz, &fd_exec_test_txn_context_t_msg );
  if( FD_UNLIKELY( !res ) ) return 0;

  int ok = 0;
  fd_spad_push( runner->spad );
  void * output = NULL;
  fd_solfuzz_pb_execute_wrapper( runner, input, &output, fd_solfuzz_pb_txn_run );
  if( output ) {
    ok = !!sol_compat_encode( out, out_sz, output, &fd_exec_test_txn_result_t_msg );
  }
  fd_spad_pop( runner->spad );

  pb_release( &fd_exec_test_txn_context_t_msg, input );
  fd_solfuzz_runner_leak_check( runner );
  return ok;
}

int
sol_compat_block_execute_v1( uchar *       out,
                             ulong *       out_sz,
                             uchar const * in,
                             ulong         in_sz ) {
  fd_exec_test_block_context_t input[1] = {0};
  void * res = sol_compat_decode_lenient( &input, in, in_sz, &fd_exec_test_block_context_t_msg );
  if( FD_UNLIKELY( !res ) ) return 0;

  fd_spad_push( runner->spad );
  int ok = 0;
  void * output = NULL;
  fd_solfuzz_pb_execute_wrapper( runner, input, &output, fd_solfuzz_pb_block_run );
  if( output ) {
    ok = !!sol_compat_encode( out, out_sz, output, &fd_exec_test_block_effects_t_msg );
  }
  fd_spad_pop( runner->spad );

  pb_release( &fd_exec_test_block_context_t_msg, input );
  fd_solfuzz_runner_leak_check( runner );
  return ok;
}

int
sol_compat_elf_loader_v1( uchar *       out,
                          ulong *       out_sz,
                          uchar const * in,
                          ulong         in_sz ) {
  fd_exec_test_elf_loader_ctx_t input[1] = {0};
  void * res = sol_compat_decode( &input, in, in_sz, &fd_exec_test_elf_loader_ctx_t_msg );
  if( FD_UNLIKELY( !res ) ) return 0;

  fd_spad_push( runner->spad );
  int ok = 0;
  void * output = NULL;
  fd_solfuzz_pb_execute_wrapper( runner, input, &output, fd_solfuzz_pb_elf_loader_run );
  if( output ) {
    ok = !!sol_compat_encode( out, out_sz, output, &fd_exec_test_elf_loader_effects_t_msg );
  }
  fd_spad_pop( runner->spad );

  pb_release( &fd_exec_test_elf_loader_ctx_t_msg, input );
  fd_solfuzz_runner_leak_check( runner );
  return ok;
}

int
sol_compat_vm_syscall_execute_v1( uchar *       out,
                                  ulong *       out_sz,
                                  uchar const * in,
                                  ulong         in_sz ) {
  fd_exec_test_syscall_context_t input[1] = {0};
  void * res = sol_compat_decode_lenient( &input, in, in_sz, &fd_exec_test_syscall_context_t_msg );
  if( FD_UNLIKELY( !res ) ) return 0;

  fd_spad_push( runner->spad );
  int ok = 0;
  void * output = NULL;
  fd_solfuzz_pb_execute_wrapper( runner, input, &output, fd_solfuzz_pb_syscall_run );
  if( output ) {
    ok = !!sol_compat_encode( out, out_sz, output, &fd_exec_test_syscall_effects_t_msg );
  }
  fd_spad_pop( runner->spad );

  pb_release( &fd_exec_test_syscall_context_t_msg, input );
  fd_solfuzz_runner_leak_check( runner );
  return ok;
}

int
sol_compat_vm_interp_v1( uchar *       out,
                         ulong *       out_sz,
                         uchar const * in,
                         ulong         in_sz ) {
  fd_exec_test_syscall_context_t input[1] = {0};
  void * res = sol_compat_decode_lenient( &input, in, in_sz, &fd_exec_test_syscall_context_t_msg );
  if( FD_UNLIKELY( !res ) ) return 0;

  fd_spad_push( runner->spad );
  int ok = 0;
  void * output = NULL;
  fd_solfuzz_pb_execute_wrapper( runner, input, &output, fd_solfuzz_pb_vm_interp_run );
  if( output ) {
    ok = !!sol_compat_encode( out, out_sz, output, &fd_exec_test_syscall_effects_t_msg );
  }
  fd_spad_pop( runner->spad );

  pb_release( &fd_exec_test_syscall_context_t_msg, input );
  fd_solfuzz_runner_leak_check( runner );
  return ok;
}

int
sol_compat_shred_parse_v1( uchar *       out,
                           ulong *       out_sz,
                           uchar const * in,
                           ulong         in_sz ) {
    fd_exec_test_shred_binary_t input[1] = {0};
    void                      * res      = sol_compat_decode_lenient( &input, in, in_sz, &fd_exec_test_shred_binary_t_msg );
    if( FD_UNLIKELY( res==NULL ) ) {
        return 0;
    }
    if( FD_UNLIKELY( input[0].data==NULL ) ) {
        pb_release( &fd_exec_test_shred_binary_t_msg, input );
        return 0;
    }
    fd_exec_test_accepts_shred_t output[1] = {0};
    output[0].valid                        = !!fd_shred_parse( input[0].data->bytes, input[0].data->size );
    pb_release( &fd_exec_test_shred_binary_t_msg, input );
    return !!sol_compat_encode( out, out_sz, output, &fd_exec_test_accepts_shred_t_msg );
}

/*
 * execute_v2
   Unlike sol_compat_execute_v1 APIs, v2 APIs use flatbuffers for
   zero-copy decoding. Returns SOL_COMPAT_V2_SUCCESS on success and
   SOL_COMPAT_V2_FAILURE on failure.

   out: output buffer
   out_sz: output buffer size
   in: input buffer
   in_sz: input buffer size (unused)

   Since flatbuffers utilizes zero-copy decoding, the v2 API does not
   require an input buffer size. Therefore, it is the caller's
   responsibility to ensure the input buffer is well-formed (preferably
   using a call to _verify_as_root) to avoid any OOB reads.

   TODO: Make sol_compat_v2 APIs infallible???
 */

#if FD_HAS_FLATCC

int
sol_compat_elf_loader_v2( uchar *            out,
                          ulong *            out_sz,
                          uchar const *      in,
                          ulong FD_FN_UNUSED in_sz ) {
  SOL_COMPAT_NS(ELFLoaderCtx_table_t) input = SOL_COMPAT_NS(ELFLoaderCtx_as_root( in ));
  if( FD_UNLIKELY( !input ) ) return 0;

  int err = fd_solfuzz_fb_execute_wrapper( runner, input, fd_solfuzz_fb_elf_loader_run );
  if( FD_UNLIKELY( err==SOL_COMPAT_V2_FAILURE ) ) return err;

  ulong buffer_sz = flatcc_builder_get_buffer_size( runner->fb_builder );
  flatcc_builder_copy_buffer( runner->fb_builder, out, buffer_sz );
  *out_sz = buffer_sz;

  return SOL_COMPAT_V2_SUCCESS;
}

#endif /* FD_HAS_FLATCC */
