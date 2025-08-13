#include "fd_solfuzz_private.h"
#define _GNU_SOURCE
#include "fd_sol_compat.h"

#include "../fd_executor_err.h"
#include "../../capture/fd_solcap_writer.h"
#include "../../../ballet/shred/fd_shred.h"

#include "generated/block.pb.h"
#include "generated/elf.pb.h"
#include "generated/invoke.pb.h"
#include "generated/shred.pb.h"
#include "generated/vm.pb.h"
#include "generated/txn.pb.h"
#include "generated/type.pb.h"

#include <assert.h>
#include <errno.h>
#include <stdio.h>

/* FIXME: Spad isn't properly sized out or cleaned up */

static fd_wksp_t *           wksp   = NULL;
static fd_solfuzz_runner_t * runner = NULL;

#define WKSP_EXECUTE_ALLOC_TAG (2UL)
#define WKSP_DATA_MAX          (6UL<<30) /* 6 GiB */

void
sol_compat_init( int log_level ) {
  int argc = 1;
  char * argv[2] = { (char *)"fd_exec_sol_compat", NULL };
  char ** argv_ = argv;
  if( !getenv( "FD_LOG_PATH" ) ) {
    setenv( "FD_LOG_PATH", "", 1 );
  }
  fd_log_enable_unclean_exit();
  fd_boot( &argc, &argv_ );
  fd_log_level_logfile_set( log_level );
  fd_log_level_core_set(4);  /* abort on FD_LOG_ERR */

  wksp = fd_wksp_demand_paged_new( "solfuzz", 42UL, fd_wksp_part_max_est( WKSP_DATA_MAX, 64UL<<10 ), WKSP_DATA_MAX );
  FD_TEST( wksp );
}

void
sol_compat_fini( void ) {
  fd_wksp_delete_anonymous( wksp );
  wksp   = NULL;
  runner = NULL;
}

sol_compat_features_t const *
sol_compat_get_features_v1( void ) {
  static sol_compat_features_t features;
  static ulong hardcoded_features[ FD_FEATURE_ID_CNT ];
  static ulong supported_features[ FD_FEATURE_ID_CNT ];

  FD_ONCE_BEGIN {
    features.hardcoded_features = hardcoded_features;
    features.supported_features = supported_features;
    for( fd_feature_id_t const * iter = fd_feature_iter_init();
         !fd_feature_iter_done( iter );
         iter = fd_feature_iter_next( iter ) ) {
      if( iter->reverted ) continue; /* skip reverted features */

      /* Pretend that features activated on all clusters are hardcoded */
      if( iter->activated_on_all_clusters ) {
        hardcoded_features[ features.hardcoded_features_cnt++ ] = iter->id.ul[0];
      } else {
        supported_features[ features.supported_feature_cnt++  ] = iter->id.ul[0];
      }
    }
  }
  FD_ONCE_END;

  return &features;
}

static fd_solfuzz_runner_t *
sol_compat_setup_runner( void ) {
  runner = fd_solfuzz_runner_new( wksp, WKSP_EXECUTE_ALLOC_TAG );

  char const * solcap_path = getenv( "FD_SOLCAP" );
  if( solcap_path ) {
    runner->solcap_file = fopen( solcap_path, "w" );
    if( FD_UNLIKELY( !runner->solcap_file ) ) {
      FD_LOG_ERR(( "fopen($FD_SOLCAP=%s) failed (%i-%s)", solcap_path, errno, fd_io_strerror( errno ) ));
    }
    FD_LOG_NOTICE(( "Logging to solcap file %s", solcap_path ));

    void * solcap_mem = fd_wksp_alloc_laddr( runner->wksp, fd_solcap_writer_align(), fd_solcap_writer_footprint(), 1UL );
    runner->solcap = fd_solcap_writer_new( solcap_mem );
    FD_TEST( runner->solcap );
    FD_TEST( fd_solcap_writer_init( solcap_mem, runner->solcap_file ) );
  }

  return runner;
}

static void
sol_compat_cleanup_runner( fd_solfuzz_runner_t * runner ) {
  /* Cleanup test runner */
  if( runner->solcap ) {
    fd_solcap_writer_flush( runner->solcap );
    fd_wksp_free_laddr( fd_solcap_writer_delete( runner->solcap ) );
    runner->solcap = NULL;
    fclose( runner->solcap_file );
    runner->solcap_file = NULL;
  }
  fd_solfuzz_runner_delete( runner );
}

/*
 * execute_v1
 */

int
sol_compat_instr_execute_v1( uchar *       out,
                             ulong *       out_sz,
                             uchar const * in,
                             ulong         in_sz ) {
  // Setup
  fd_solfuzz_runner_t * runner = sol_compat_setup_runner();

  // Decode context
  fd_exec_test_instr_context_t input[1] = {0};
  void * res = sol_compat_decode( &input, in, in_sz, &fd_exec_test_instr_context_t_msg );
  if( !res ) {
    sol_compat_cleanup_runner( runner );
    return 0;
  }

  int ok = 0;
  fd_spad_push( runner->spad );
  void * output = NULL;
  fd_solfuzz_execute_wrapper( runner, input, &output, fd_solfuzz_instr_run );
  if( output ) {
    ok = !!sol_compat_encode( out, out_sz, output, &fd_exec_test_instr_effects_t_msg );
  }
  fd_spad_pop( runner->spad );

  // Cleanup
  pb_release( &fd_exec_test_instr_context_t_msg, input );
  sol_compat_cleanup_runner( runner );

  // Check wksp usage
  FD_TEST( !fd_wksp_check_usage( wksp, WKSP_EXECUTE_ALLOC_TAG ) );

  return ok;
}

int
sol_compat_txn_execute_v1( uchar *       out,
                           ulong *       out_sz,
                           uchar const * in,
                           ulong         in_sz ) {
  // Setup
  fd_solfuzz_runner_t * runner = sol_compat_setup_runner();

  // Decode context
  fd_exec_test_txn_context_t input[1] = {0};
  void * res = sol_compat_decode( &input, in, in_sz, &fd_exec_test_txn_context_t_msg );
  if( FD_UNLIKELY( !res ) ) {
    sol_compat_cleanup_runner( runner );
    return 0;
  }

  int ok = 0;
  fd_spad_push( runner->spad );
  void * output = NULL;
  fd_solfuzz_execute_wrapper( runner, input, &output, fd_solfuzz_txn_run );
  if( output ) {
    ok = !!sol_compat_encode( out, out_sz, output, &fd_exec_test_txn_result_t_msg );
  }
  fd_spad_pop( runner->spad );

  // Cleanup
  pb_release( &fd_exec_test_txn_context_t_msg, input );
  sol_compat_cleanup_runner( runner );

  // Check wksp usage
  FD_TEST( !fd_wksp_check_usage( wksp, WKSP_EXECUTE_ALLOC_TAG ) );

  return ok;
}

int
sol_compat_block_execute_v1( uchar *       out,
                             ulong *       out_sz,
                             uchar const * in,
                             ulong         in_sz ) {
  // Setup
  fd_solfuzz_runner_t * runner = sol_compat_setup_runner();

  // Decode context
  fd_exec_test_block_context_t input[1] = {0};
  void * res = sol_compat_decode( &input, in, in_sz, &fd_exec_test_block_context_t_msg );
  if( FD_UNLIKELY( !res ) ) {
    sol_compat_cleanup_runner( runner );
    return 0;
  }

  fd_spad_push( runner->spad );
  int ok = 0;
  void * output = NULL;
  fd_solfuzz_execute_wrapper( runner, input, &output, fd_solfuzz_block_run );
  if( output ) {
    ok = !!sol_compat_encode( out, out_sz, output, &fd_exec_test_block_effects_t_msg );
  }
  fd_spad_pop( runner->spad );

  // Cleanup
  pb_release( &fd_exec_test_block_context_t_msg, input );
  sol_compat_cleanup_runner( runner );

  // Check wksp usage
  FD_TEST( !fd_wksp_check_usage( wksp, WKSP_EXECUTE_ALLOC_TAG ) );

  return ok;
}

int
sol_compat_elf_loader_v1( uchar *       out,
                          ulong *       out_sz,
                          uchar const * in,
                          ulong         in_sz ) {
  // Setup
  fd_solfuzz_runner_t * runner = sol_compat_setup_runner();

  // Decode context
  fd_exec_test_elf_loader_ctx_t input[1] = {0};
  void * res = sol_compat_decode( &input, in, in_sz, &fd_exec_test_elf_loader_ctx_t_msg );
  if( FD_UNLIKELY( !res ) ) {
    sol_compat_cleanup_runner( runner );
    return 0;
  }

  fd_spad_push( runner->spad );
  int ok = 0;
  void * output = NULL;
  fd_solfuzz_execute_wrapper( runner, input, &output, fd_solfuzz_elf_loader_run );
  if( output ) {
    ok = !!sol_compat_encode( out, out_sz, output, &fd_exec_test_elf_loader_effects_t_msg );
  }
  fd_spad_pop( runner->spad );

  // Cleanup
  pb_release( &fd_exec_test_elf_loader_ctx_t_msg, input );
  sol_compat_cleanup_runner( runner );

  // Check wksp usage
  FD_TEST( !fd_wksp_check_usage( wksp, WKSP_EXECUTE_ALLOC_TAG ) );

  return ok;
}

int
sol_compat_vm_syscall_execute_v1( uchar *       out,
                                  ulong *       out_sz,
                                  uchar const * in,
                                  ulong         in_sz ) {
  // Setup
  fd_solfuzz_runner_t * runner = sol_compat_setup_runner();

  // Decode context
  fd_exec_test_syscall_context_t input[1] = {0};
  void * res = sol_compat_decode( &input, in, in_sz, &fd_exec_test_syscall_context_t_msg );
  if( FD_UNLIKELY( !res ) ) {
    sol_compat_cleanup_runner( runner );
    return 0;
  }

  fd_spad_push( runner->spad );
  int ok = 0;
  void * output = NULL;
  fd_solfuzz_execute_wrapper( runner, input, &output, fd_solfuzz_syscall_run );
  if( output ) {
    ok = !!sol_compat_encode( out, out_sz, output, &fd_exec_test_syscall_effects_t_msg );
  }
  fd_spad_pop( runner->spad );

  // Cleanup
  pb_release( &fd_exec_test_syscall_context_t_msg, input );
  sol_compat_cleanup_runner( runner );

  // Check wksp usage
  FD_TEST( !fd_wksp_check_usage( wksp, WKSP_EXECUTE_ALLOC_TAG ) );

  return ok;
}

int
sol_compat_vm_interp_v1( uchar *       out,
                         ulong *       out_sz,
                         uchar const * in,
                         ulong         in_sz ) {
  // Setup
  fd_solfuzz_runner_t * runner = sol_compat_setup_runner();

  // Decode context
  fd_exec_test_syscall_context_t input[1] = {0};
  void * res = sol_compat_decode( &input, in, in_sz, &fd_exec_test_syscall_context_t_msg );
  if( FD_UNLIKELY( !res ) ) {
    sol_compat_cleanup_runner( runner );
    return 0;
  }

  fd_spad_push( runner->spad );
  int ok = 0;
  void * output = NULL;
  fd_solfuzz_execute_wrapper( runner, input, &output, fd_solfuzz_vm_interp_run );
  if( output ) {
    ok = !!sol_compat_encode( out, out_sz, output, &fd_exec_test_syscall_effects_t_msg );
  }
  fd_spad_pop( runner->spad );

  // Cleanup
  pb_release( &fd_exec_test_syscall_context_t_msg, input );
  sol_compat_cleanup_runner( runner );

  // Check wksp usage
  FD_TEST( !fd_wksp_check_usage( wksp, WKSP_EXECUTE_ALLOC_TAG ) );

  return ok;
}

int
sol_compat_shred_parse_v1( uchar *       out,
                           ulong *       out_sz,
                           uchar const * in,
                           ulong         in_sz ) {
    fd_exec_test_shred_binary_t input[1] = {0};
    void                      * res      = sol_compat_decode( &input, in, in_sz, &fd_exec_test_shred_binary_t_msg );
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

int
sol_compat_type_execute_v1( uchar *       out,
                            ulong *       out_sz,
                            uchar const * in,
                            ulong         in_sz ) {
  // Setup
  fd_solfuzz_runner_t * runner = sol_compat_setup_runner();

  // Decode context
  fd_exec_test_type_context_t input[1] = {0};
  void * res = sol_compat_decode( &input, in, in_sz, &fd_exec_test_type_context_t_msg );
  if( res==NULL ) {
    sol_compat_cleanup_runner( runner );
    return 0;
  }

  fd_spad_push( runner->spad );
  int ok = 0;
  void * output = NULL;
  fd_solfuzz_execute_wrapper( runner, input, &output, fd_solfuzz_type_run );
  if( output ) {
    ok = !!sol_compat_encode( out, out_sz, output, &fd_exec_test_type_effects_t_msg );
  }
  fd_spad_pop( runner->spad );

  pb_release( &fd_exec_test_type_context_t_msg, input );
  sol_compat_cleanup_runner( runner );

  // Check wksp usage
  FD_TEST( !fd_wksp_check_usage( wksp, WKSP_EXECUTE_ALLOC_TAG ) );

  return ok;
}
