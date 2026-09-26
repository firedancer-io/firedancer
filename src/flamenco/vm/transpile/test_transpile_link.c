/* test_transpile_link runs a transpiled program that was linked into
   this executable via libfd_transpiled.a (see test_transpile_link.sh)
   and checks that it behaves like the interpreter.  Requires
   --prog PATH pointing to the sBPF ELF the archive was built from. */

#include "fd_transpile.h"
#include "../fd_vm_private.h"
#include "../../runtime/fd_runtime.h"
#include "../../runtime/fd_system_ids.h"
#include "../../runtime/sysvar/fd_sysvar_cache.h"
#include "../../log_collector/fd_log_collector.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
  fd_runtime_t *      runtime;
  fd_txn_out_t *      txn_out;
  fd_bank_t *         bank;
  fd_sysvar_cache_t * sysvar_cache;
  fd_log_collector_t  log[1];
  fd_instr_info_t     instr[1];
  fd_exec_instr_ctx_t instr_ctx[1];
} test_env_t;

static void
test_env_init( test_env_t * env ) {
  env->runtime = calloc( 1UL, sizeof(fd_runtime_t) );
  env->txn_out = calloc( 1UL, sizeof(fd_txn_out_t) );
  env->bank    = calloc( 1UL, sizeof(fd_bank_t)    );
  FD_TEST( env->runtime && env->txn_out && env->bank );
  static fd_sysvar_cache_t cache_mem[1];
  env->sysvar_cache = fd_sysvar_cache_join( fd_sysvar_cache_new( cache_mem ) );
  FD_TEST( env->sysvar_cache );

  fd_sol_sysvar_clock_t clock = {
    .slot                  = 1234UL,
    .epoch_start_timestamp = 1700000000L,
    .epoch                 = 5UL,
    .leader_schedule_epoch = 6UL,
    .unix_timestamp        = 1700000400L
  };
  fd_sysvar_cache_restore_one( env->sysvar_cache, &fd_sysvar_clock_id, 1UL, (uchar const *)&clock, sizeof(clock) );

  fd_features_disable_all( &env->bank->f.features );
  env->runtime->log.log_collector = env->log;
  env->runtime->instr.stack_sz    = 1;
  env->txn_out->accounts.cnt      = 1;

  memset( env->instr, 0, sizeof(fd_instr_info_t) );
  env->instr->stack_height = 1;

  memset( env->instr_ctx, 0, sizeof(fd_exec_instr_ctx_t) );
  env->instr_ctx->instr        = env->instr;
  env->instr_ctx->runtime      = env->runtime;
  env->instr_ctx->txn_out      = env->txn_out;
  env->instr_ctx->bank         = env->bank;
  env->instr_ctx->sysvar_cache = env->sysvar_cache;
  strcpy( env->instr_ctx->program_id_base58, "11111111111111111111111111111111" );
}

typedef struct {
  int   err;
  int   bailed;
  ulong r0;
  long  cu;
  ulong log_sz;
  uchar log[ FD_LOG_COLLECTOR_MAX + FD_LOG_COLLECTOR_EXTRA ];
} test_result_t;

/* Serialized input (no accounts): u64 account_cnt, u64 data_sz, data,
   32 byte program id */

static void
run( test_env_t *                 env,
     fd_sbpf_program_t const *    prog,
     fd_sbpf_syscalls_t *         syscalls,
     fd_vm_transpiled_exec_func_t fn,
     uchar const *                data,
     ulong                        data_sz,
     test_result_t *              out ) {
  fd_log_collector_init( env->log, 1 );
  memset( &env->txn_out->err, 0, sizeof(env->txn_out->err) );
  memset( &env->txn_out->details.return_data, 0, sizeof(env->txn_out->details.return_data) );

  static uchar input[ 4096 ] __attribute__((aligned(16)));
  ulong input_sz = 16UL + data_sz + 32UL;
  FD_TEST( input_sz<=sizeof(input) );
  memset( input, 0, sizeof(input) );
  FD_STORE( ulong, input+8, data_sz );
  memcpy( input+16, data, data_sz );
  fd_vm_input_region_t region = {
    .haddr                  = (ulong)input,
    .region_sz              = (uint)input_sz,
    .address_space_reserved = input_sz,
    .is_writable            = 1
  };

  fd_sha256_t _sha[1];
  fd_sha256_t * sha = fd_sha256_join( fd_sha256_new( _sha ) );
  static fd_vm_t _vm[1];
  fd_vm_t * vm = fd_vm_join( fd_vm_new( _vm ) );
  FD_TEST( vm );
  FD_TEST( fd_vm_init( vm, env->instr_ctx, FD_VM_HEAP_DEFAULT, FD_VM_COMPUTE_UNIT_LIMIT,
                       prog->rodata, prog->rodata_sz, prog->text, prog->info.text_cnt, prog->info.text_off, prog->info.text_sz,
                       prog->entry_pc, prog->calldests, prog->info.sbpf_version, syscalls, NULL, sha,
                       &region, 1UL, NULL, 0, 0, 0, 0, 0, 0UL ) );
  FD_TEST( fd_vm_validate( vm )==FD_VM_SUCCESS );

  out->bailed = 0;
  if( fn ) {
    out->err = fn( vm );
    if( out->err==FD_VM_ERR_EBPF_BAIL ) {
      out->bailed = 1;
      out->err = fd_vm_exec( vm );
    }
  } else {
    out->err = fd_vm_exec( vm );
  }
  out->r0     = vm->reg[0];
  out->cu     = vm->cu;
  out->log_sz = env->log->buf_sz;
  memcpy( out->log, env->log->buf, out->log_sz );

  fd_vm_delete( fd_vm_leave( vm ) );
  fd_sha256_delete( fd_sha256_leave( sha ) );
}

static uchar *
read_file( char const * path,
           ulong *      sz ) {
  FILE * f = fopen( path, "rb" );
  if( FD_UNLIKELY( !f ) ) FD_LOG_ERR(( "fopen(%s) failed", path ));
  FD_TEST( !fseek( f, 0L, SEEK_END ) );
  long n = ftell( f );
  FD_TEST( n>0L );
  FD_TEST( !fseek( f, 0L, SEEK_SET ) );
  uchar * buf = malloc( (ulong)n );
  FD_TEST( buf );
  FD_TEST( fread( buf, 1UL, (ulong)n, f )==(ulong)n );
  FD_TEST( !fclose( f ) );
  *sz = (ulong)n;
  return buf;
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  char const * prog_path = fd_env_strip_cmdline_cstr( &argc, &argv, "--prog", NULL, NULL );
  if( FD_UNLIKELY( !prog_path ) ) FD_LOG_ERR(( "--prog PATH required" ));

  /* Exactly one program is linked in */

  fd_transpile_export_t const * ext = fd_transpiled_ext[0];
  if( FD_UNLIKELY( !ext ) ) FD_LOG_ERR(( "fd_transpiled_ext is empty (weak fallback linked?)" ));
  FD_TEST( !fd_transpiled_ext[1] );
  FD_TEST( ext->abi_version==FD_TRANSPILE_ABI_VERSION );
  FD_TEST( ext->struct_size==sizeof(fd_transpile_export_t) );
  FD_TEST( ext->exec );

  /* Load the program the same way fd_transpile did */

  ulong bin_sz;
  uchar * bin = read_file( prog_path, &bin_sz );

  static fd_sbpf_syscalls_t _syscalls[ FD_SBPF_SYSCALLS_SLOT_CNT ];
  fd_sbpf_syscalls_t * syscalls = fd_sbpf_syscalls_join( fd_sbpf_syscalls_new( _syscalls ) );
  FD_TEST( syscalls );
  FD_TEST( !fd_vm_syscall_register_all( syscalls, 0 ) );

  fd_sbpf_loader_config_t config = {
    .elf_deploy_checks = 1,
    .sbpf_min_version  = FD_SBPF_V0,
    .sbpf_max_version  = FD_SBPF_V3
  };
  fd_sbpf_elf_info_t info;
  FD_TEST( !fd_sbpf_elf_peek( &info, bin, bin_sz, &config ) );
  void * rodata   = aligned_alloc( FD_SBPF_PROG_RODATA_ALIGN, fd_ulong_align_up( fd_ulong_max( info.bin_sz, 1UL ), FD_SBPF_PROG_RODATA_ALIGN ) );
  void * prog_mem = aligned_alloc( fd_sbpf_program_align(), fd_sbpf_program_footprint( &info ) );
  void * scratch  = malloc( bin_sz );
  FD_TEST( rodata && prog_mem && scratch );
  fd_sbpf_program_t * prog = fd_sbpf_program_new( prog_mem, &info, rodata );
  FD_TEST( prog );
  FD_TEST( !fd_sbpf_program_load( prog, bin, bin_sz, syscalls, &config, scratch, bin_sz ) );

  /* Export metadata survived relocation */

  FD_TEST( ext->meta.text_cnt    ==prog->info.text_cnt     );
  FD_TEST( ext->meta.text_sz     ==prog->info.text_sz      );
  FD_TEST( ext->meta.entry_pc    ==prog->entry_pc          );
  FD_TEST( ext->meta.sbpf_version==prog->info.sbpf_version );

  /* Run over a set of instruction inputs.  With no accounts each
     instruction fails early but the failure path (parsing, logging,
     error return) must match the interpreter exactly. */

  test_env_t env[1];
  test_env_init( env );
  static test_result_t res_interp[1];
  static test_result_t res_link  [1];

  ulong case_cnt = 0UL;
  ulong bail_cnt = 0UL;
  for( ulong disc=0UL; disc<=64UL; disc++ ) {
    for( ulong data_sz=0UL; data_sz<=40UL; data_sz+=8UL ) {
      uchar data[ 48 ];
      for( ulong i=0UL; i<sizeof(data); i++ ) data[ i ] = (uchar)( 0x5aU ^ (uint)( disc*7UL + i*13UL ) );
      data[ 0 ] = (uchar)disc;
      ulong sz = disc==64UL ? 0UL : data_sz+1UL;

      run( env, prog, syscalls, NULL,      data, sz, res_interp );
      run( env, prog, syscalls, ext->exec, data, sz, res_link   );
      case_cnt++;
      bail_cnt += (ulong)res_link->bailed;

      if( FD_UNLIKELY( res_interp->err   !=res_link->err    ||
                       res_interp->r0    !=res_link->r0     ||
                       res_interp->cu    !=res_link->cu     ||
                       res_interp->log_sz!=res_link->log_sz ||
                       memcmp( res_interp->log, res_link->log, res_interp->log_sz ) ) ) {
        FD_LOG_ERR(( "disc %lu data_sz %lu: mismatch (interp err %d r0 %#lx cu %ld log_sz %lu) (linked err %d r0 %#lx cu %ld log_sz %lu)",
                     disc, sz,
                     res_interp->err, res_interp->r0, res_interp->cu, res_interp->log_sz,
                     res_link->err,   res_link->r0,   res_link->cu,   res_link->log_sz ));
      }
      if( disc==64UL ) break;
    }
  }
  if( FD_UNLIKELY( bail_cnt==case_cnt ) ) FD_LOG_ERR(( "transpiled code bailed on every input" ));
  FD_LOG_NOTICE(( "%lu inputs match the interpreter (%lu bailed)", case_cnt, bail_cnt ));

  free( scratch );
  free( prog_mem );
  free( rodata );
  free( bin );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
