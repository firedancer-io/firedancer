#include "fd_bpf_loader_program.h"
#include "../fd_bank.h"
#include "../fd_runtime.h"
#include "../fd_executor_err.h"
#include "../../features/fd_features.h"
#include "../../../ballet/sbpf/fd_sbpf_loader.h"
#include "../../../ballet/elf/fd_elf64.h"
#include "../../../ballet/elf/fd_elf.h"

/* SBPF v0 ELF (e_flags=0). */
FD_IMPORT_BINARY( elf_v0, "src/ballet/sbpf/fixtures/hello_solana_program.so" );

/* Build a minimal valid SBPF-V3 ELF with one rodata phdr and one
   bytecode phdr, where the bytecode is a single EXIT instruction.
   Mirrors the layout used by test_sbpf_strict_elf.c. */

#define MM_RODATA_START   (0x0UL)
#define MM_BYTECODE_START (0x100000000UL)
#define ELF_V3_MAX        (256UL)
#define PF_X              (1U)
#define PF_R              (4U)

static ulong
build_v3_elf( uchar buf[ ELF_V3_MAX ] ) {
  fd_memset( buf, 0, ELF_V3_MAX );

  ulong phdr_end    = sizeof(fd_elf64_ehdr) + 2UL*sizeof(fd_elf64_phdr);
  ulong rodata_sz   = 8UL;
  ulong bytecode_sz = 8UL;

  fd_elf64_ehdr ehdr;
  fd_memset( &ehdr, 0, sizeof(ehdr) );
  ehdr.e_ident[0] = 0x7f;
  ehdr.e_ident[1] = 'E';
  ehdr.e_ident[2] = 'L';
  ehdr.e_ident[3] = 'F';
  ehdr.e_ident[ FD_ELF_EI_CLASS   ] = FD_ELF_CLASS_64;
  ehdr.e_ident[ FD_ELF_EI_DATA    ] = FD_ELF_DATA_LE;
  ehdr.e_ident[ FD_ELF_EI_VERSION ] = 1;
  ehdr.e_machine   = FD_ELF_EM_BPF;
  ehdr.e_version   = 1;
  ehdr.e_entry     = MM_BYTECODE_START;
  ehdr.e_phoff     = sizeof(fd_elf64_ehdr);
  ehdr.e_flags     = FD_SBPF_V3;
  ehdr.e_ehsize    = sizeof(fd_elf64_ehdr);
  ehdr.e_phentsize = sizeof(fd_elf64_phdr);
  ehdr.e_phnum     = 2;
  fd_memcpy( buf, &ehdr, sizeof(ehdr) );

  fd_elf64_phdr ph0 = {0};
  ph0.p_type   = FD_ELF_PT_LOAD;
  ph0.p_flags  = PF_R;
  ph0.p_offset = phdr_end;
  ph0.p_vaddr  = MM_RODATA_START;
  ph0.p_paddr  = MM_RODATA_START;
  ph0.p_filesz = rodata_sz;
  ph0.p_memsz  = rodata_sz;
  fd_memcpy( buf + sizeof(fd_elf64_ehdr), &ph0, sizeof(ph0) );

  fd_elf64_phdr ph1 = {0};
  ph1.p_type   = FD_ELF_PT_LOAD;
  ph1.p_flags  = PF_X;
  ph1.p_offset = phdr_end + rodata_sz;
  ph1.p_vaddr  = MM_BYTECODE_START;
  ph1.p_paddr  = MM_BYTECODE_START;
  ph1.p_filesz = bytecode_sz;
  ph1.p_memsz  = bytecode_sz;
  fd_memcpy( buf + sizeof(fd_elf64_ehdr) + sizeof(fd_elf64_phdr), &ph1, sizeof(ph1) );

  /* Single EXIT instruction (opcode 0x95) terminates execution.
     This passes fd_vm_validate which would otherwise reject the
     all-zero bytecode used by test_sbpf_strict_elf. */
  buf[ phdr_end + rodata_sz ] = 0x95;

  return phdr_end + rodata_sz + bytecode_sz;
}

struct deploy_env {
  fd_banks_t *        banks;
  fd_bank_t *         bank;
  fd_runtime_t *      runtime;
  fd_txn_out_t *      txn_out;
  fd_instr_info_t     instr[1];
  fd_exec_instr_ctx_t ctx[1];
};
typedef struct deploy_env deploy_env_t;

static void
deploy_env_init( deploy_env_t * env,
                 fd_wksp_t *    wksp ) {
  ulong tag = 1UL;

  ulong banks_footprint = fd_banks_footprint( 1UL, 1UL, 2048UL, 2048UL );
  void * banks_mem = fd_wksp_alloc_laddr( wksp, fd_banks_align(), banks_footprint, tag++ );
  FD_TEST( banks_mem );
  env->banks = fd_banks_join( fd_banks_new( banks_mem, 1UL, 1UL, 2048UL, 2048UL, 0, 42UL ) );
  FD_TEST( env->banks );

  env->bank = fd_banks_init_bank( env->banks );
  FD_TEST( env->bank );
  env->bank->f.slot = 100UL;

  env->runtime = fd_wksp_alloc_laddr( wksp, alignof(fd_runtime_t), sizeof(fd_runtime_t), tag++ );
  FD_TEST( env->runtime );
  fd_memset( env->runtime, 0, sizeof(fd_runtime_t) );
  env->runtime->instr.stack_sz = 1;

  env->txn_out = fd_wksp_alloc_laddr( wksp, alignof(fd_txn_out_t), sizeof(fd_txn_out_t), tag++ );
  FD_TEST( env->txn_out );
  fd_memset( env->txn_out, 0, sizeof(fd_txn_out_t) );
  env->txn_out->details.compute_budget.heap_size     = 32UL*1024UL;
  env->txn_out->details.compute_budget.compute_meter = 200000UL;

  fd_memset( env->instr, 0, sizeof(env->instr) );

  fd_memset( env->ctx, 0, sizeof(env->ctx) );
  env->ctx->instr   = env->instr;
  env->ctx->txn_out = env->txn_out;
  env->ctx->bank    = env->bank;
  env->ctx->runtime = env->runtime;

  /* Enable all features so syscall registration is permissive, then
     disable the version-related features the deploy gate cares about
     so the version envelope is fully under test control. */
  fd_features_t * f = &env->bank->f.features;
  fd_features_enable_all( f );
  FD_FEATURE_SET_ACTIVE( f, disable_sbpf_v0_execution,        FD_FEATURE_DISABLED );
  FD_FEATURE_SET_ACTIVE( f, reenable_sbpf_v0_execution,       FD_FEATURE_DISABLED );
  FD_FEATURE_SET_ACTIVE( f, disable_sbpf_v0_v1_v2_deployment, FD_FEATURE_DISABLED );
}

static void
deploy_env_destroy( deploy_env_t * env ) {
  fd_wksp_free_laddr( env->txn_out );
  fd_wksp_free_laddr( env->runtime );
  fd_wksp_free_laddr( env->banks );
}

static void
test_deploy_v0_succeeds( fd_wksp_t * wksp ) {
  deploy_env_t env[1];
  deploy_env_init( env, wksp );

  int err = fd_deploy_program( env->ctx, elf_v0, elf_v0_sz,
                               /* disable_sbpf_v0_v1_v2_deployment */ 0 );
  FD_TEST( err==FD_EXECUTOR_INSTR_SUCCESS );

  deploy_env_destroy( env );
}

static void
test_deploy_v3_succeeds( fd_wksp_t * wksp ) {
  deploy_env_t env[1];
  deploy_env_init( env, wksp );

  uchar elf[ ELF_V3_MAX ];
  ulong elf_sz = build_v3_elf( elf );

  int err = fd_deploy_program( env->ctx, elf, elf_sz,
                               /* disable_sbpf_v0_v1_v2_deployment */ 0 );
  FD_TEST( err==FD_EXECUTOR_INSTR_SUCCESS );

  /* The gate must NOT block a v3 deploy. */
  err = fd_deploy_program( env->ctx, elf, elf_sz,
                           /* disable_sbpf_v0_v1_v2_deployment */ 1 );
  FD_TEST( err==FD_EXECUTOR_INSTR_SUCCESS );

  deploy_env_destroy( env );
}

/* SIMD-0500: with the gate active, deploying a v0 ELF must fail
   because the loader's accepted version range is restricted to
   [V3, max] for deployment.  Mirrors the agave PR-12410 test
   "Case: Deploy SBPFv0". */
static void
test_deploy_v0_rejected_when_gated( fd_wksp_t * wksp ) {
  deploy_env_t env[1];
  deploy_env_init( env, wksp );

  int err = fd_deploy_program( env->ctx, elf_v0, elf_v0_sz,
                               /* disable_sbpf_v0_v1_v2_deployment */ 1 );
  FD_TEST( err==FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA );

  deploy_env_destroy( env );
}

/* SIMD-0500 finalize gate: full Cartesian product of {v0, v3} ELF
   payload x {feature off, feature on}.  v0 with the feature on is
   the only case that should reject (matches agave PR-12410 "Case:
   Finalize a SBPFv0 program"); the other three are no-ops. */

static ulong
build_programdata_with_sbpf_version( uchar buf[ PROGRAMDATA_METADATA_SIZE + 64UL ],
                                     uint  sbpf_version ) {
  fd_memset( buf, 0, PROGRAMDATA_METADATA_SIZE + 64UL );
  /* e_flags lives at offset 48 of the ELF64 header. */
  FD_STORE( uint, buf + PROGRAMDATA_METADATA_SIZE + 48UL, sbpf_version );
  return PROGRAMDATA_METADATA_SIZE + 64UL;
}

static void
test_finalize_v0_feature_off( void ) {
  uchar buf[ PROGRAMDATA_METADATA_SIZE + 64UL ];
  ulong sz  = build_programdata_with_sbpf_version( buf, FD_SBPF_V0 );
  int   err = fd_bpf_loader_finalize_v3_check( 0, buf, sz );
  FD_TEST( err==FD_EXECUTOR_INSTR_SUCCESS );
}

static void
test_finalize_v0_feature_on( void ) {
  uchar buf[ PROGRAMDATA_METADATA_SIZE + 64UL ];
  ulong sz  = build_programdata_with_sbpf_version( buf, FD_SBPF_V0 );
  int   err = fd_bpf_loader_finalize_v3_check( 1, buf, sz );
  FD_TEST( err==FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA );
}

static void
test_finalize_v3_feature_off( void ) {
  uchar buf[ PROGRAMDATA_METADATA_SIZE + 64UL ];
  ulong sz  = build_programdata_with_sbpf_version( buf, FD_SBPF_V3 );
  int   err = fd_bpf_loader_finalize_v3_check( 0, buf, sz );
  FD_TEST( err==FD_EXECUTOR_INSTR_SUCCESS );
}

static void
test_finalize_v3_feature_on( void ) {
  uchar buf[ PROGRAMDATA_METADATA_SIZE + 64UL ];
  ulong sz  = build_programdata_with_sbpf_version( buf, FD_SBPF_V3 );
  int   err = fd_bpf_loader_finalize_v3_check( 1, buf, sz );
  FD_TEST( err==FD_EXECUTOR_INSTR_SUCCESS );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong cpu_idx = fd_tile_cpu_id( fd_tile_idx() );
  if( cpu_idx>fd_shmem_cpu_cnt() ) cpu_idx = 0UL;

  char const * _page_sz = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",  NULL, "normal" );
  ulong        page_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt", NULL, 1100000UL );
  ulong        numa_idx = fd_env_strip_cmdline_ulong( &argc, &argv, "--numa-idx", NULL, fd_shmem_numa_idx( cpu_idx ) );

  ulong page_sz = fd_cstr_to_shmem_page_sz( _page_sz );
  FD_TEST( page_sz );

  fd_wksp_t * wksp = fd_wksp_new_anonymous( page_sz, page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  test_deploy_v0_succeeds( wksp );
  test_deploy_v3_succeeds( wksp );
  test_deploy_v0_rejected_when_gated( wksp );

  test_finalize_v0_feature_off( );
  test_finalize_v0_feature_on ( );
  test_finalize_v3_feature_off( );
  test_finalize_v3_feature_on ( );

  fd_wksp_delete_anonymous( wksp );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
