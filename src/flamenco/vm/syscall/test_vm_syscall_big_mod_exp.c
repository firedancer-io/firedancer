#include "fd_vm_syscall.h"
#include "../test_vm_util.h"
#include "../../runtime/fd_bank.h"
#include "../../../ballet/murmur3/fd_murmur3.h"

/* Two tests for the sol_big_mod_exp syscall (SIMD-0529):
     1. feature disabled -> syscall is not registered
     2. feature enabled  -> syscall is registered and computes correctly
   The math itself is covered exhaustively by ballet's test_big_mod_exp. */

static int
syscall_registered( fd_sbpf_syscalls_t * syscalls,
                    char const *         name ) {
  ulong key = (ulong)fd_murmur3_32( name, strlen( name ), 0U );
  return fd_sbpf_syscalls_query( syscalls, key, NULL )!=NULL;
}

static void
test_feature_disabled( void ) {
  fd_sbpf_syscalls_t _syscalls[ 1UL<<FD_SBPF_SYSCALLS_LG_SLOT_CNT ] = {0};
  fd_sbpf_syscalls_t * syscalls = fd_sbpf_syscalls_join( fd_sbpf_syscalls_new( _syscalls ) );
  FD_TEST( syscalls );

  fd_features_t features[1];
  memset( features, 0, sizeof(fd_features_t) );          /* all features active at slot>=0 ... */
  features->enable_big_mod_exp_syscall = ULONG_MAX;      /* ... except this one (disabled) */

  FD_TEST( fd_vm_syscall_register_slot( syscalls, 1UL, features, 0 )==FD_VM_SUCCESS );
  FD_TEST( !syscall_registered( syscalls, "sol_big_mod_exp" ) );

  FD_LOG_NOTICE(( "ok: feature disabled -> sol_big_mod_exp NOT registered" ));
}

static void
test_feature_enabled( fd_vm_t * vm ) {
  /* (a) gate on -> registered */
  fd_sbpf_syscalls_t _syscalls[ 1UL<<FD_SBPF_SYSCALLS_LG_SLOT_CNT ] = {0};
  fd_sbpf_syscalls_t * syscalls = fd_sbpf_syscalls_join( fd_sbpf_syscalls_new( _syscalls ) );
  FD_TEST( syscalls );

  fd_features_t features[1];
  memset( features, 0, sizeof(fd_features_t) );          /* enable_big_mod_exp_syscall = 0 -> active */
  FD_TEST( fd_vm_syscall_register_slot( syscalls, 1UL, features, 0 )==FD_VM_SUCCESS );
  FD_TEST( syscall_registered( syscalls, "sol_big_mod_exp" ) );

  /* (b) end-to-end: 5^2 mod 7 = 4 (little-endian, 1-byte operands).
     BigModExpParams (6 little-endian u64): base ptr, base_len, exp ptr,
     exp_len, mod ptr, mod_len. */
  ulong const PARAMS_OFF = 0UL;
  ulong const BASE_OFF   = 64UL;
  ulong const EXP_OFF    = 128UL;
  ulong const MOD_OFF    = 192UL;
  ulong const RES_OFF    = 256UL;

  ulong * params = (ulong *)( vm->heap + PARAMS_OFF );
  params[0] = FD_VM_MEM_MAP_HEAP_REGION_START + BASE_OFF; params[1] = 1UL; /* base */
  params[2] = FD_VM_MEM_MAP_HEAP_REGION_START + EXP_OFF;  params[3] = 1UL; /* exponent */
  params[4] = FD_VM_MEM_MAP_HEAP_REGION_START + MOD_OFF;  params[5] = 1UL; /* modulus */
  vm->heap[ BASE_OFF ] = 5;
  vm->heap[ EXP_OFF  ] = 2;
  vm->heap[ MOD_OFF  ] = 7;
  vm->heap[ RES_OFF  ] = 0xcc;

  vm->cu = FD_VM_COMPUTE_UNIT_LIMIT;
  ulong ret = 123UL;
  int err = fd_vm_syscall_sol_big_mod_exp(
      vm,
      FD_VM_MEM_MAP_HEAP_REGION_START + PARAMS_OFF,
      FD_VM_MEM_MAP_HEAP_REGION_START + RES_OFF,
      0UL, 0UL, 0UL, &ret );

  FD_TEST( err==FD_VM_SUCCESS );
  FD_TEST( ret==0UL );
  FD_TEST( vm->heap[ RES_OFF ]==4 );                 /* 5^2 mod 7 = 4 */

  /* cost: exp!=1, max_operand_len=1, mult_complexity(1)=1, adjusted exp
     length=1 -> effective=max(1,75)=75, complexity=75, cu=422+ceil(75/189)=423 */
  FD_TEST( vm->cu==FD_VM_COMPUTE_UNIT_LIMIT-423UL );

  FD_LOG_NOTICE(( "ok: feature enabled -> sol_big_mod_exp registered & 5^2 mod 7 = %u (charged %lu CU)",
                  (uint)vm->heap[ RES_OFF ], FD_VM_COMPUTE_UNIT_LIMIT-vm->cu ));
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  char const * _page_sz = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",  NULL, "gigantic"      );
  ulong        page_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt", NULL, 5UL             );
  ulong        near_cpu = fd_env_strip_cmdline_ulong( &argc, &argv, "--near-cpu", NULL, fd_log_cpu_id() );
  ulong        wksp_tag = fd_env_strip_cmdline_ulong( &argc, &argv, "--wksp-tag", NULL, 1234UL          );

  fd_wksp_t * wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, near_cpu, "wksp", 0UL );
  FD_TEST( wksp );

  fd_runtime_t * runtime = fd_wksp_alloc_laddr( wksp, alignof(fd_runtime_t), sizeof(fd_runtime_t), wksp_tag );
  FD_TEST( runtime );

  fd_sha256_t _sha[1];
  fd_sha256_t * sha = fd_sha256_join( fd_sha256_new( _sha ) );

  fd_vm_t _vm[1];
  fd_vm_t * vm = fd_vm_join( fd_vm_new( _vm ) );
  FD_TEST( vm );

  ulong const rodata_sz = 64UL;
  uchar rodata[ rodata_sz ];
  memset( rodata, 0, rodata_sz );

  static fd_exec_instr_ctx_t instr_ctx[1];
  static fd_bank_t           bank[1];
  static fd_txn_out_t        txn_out[1];
  static fd_log_collector_t  log_collector[1];
  runtime->log.log_collector = log_collector;
  test_vm_minimal_exec_instr_ctx( instr_ctx, runtime, bank, txn_out );

  int vm_ok = !!fd_vm_init(
      vm, instr_ctx, FD_VM_HEAP_DEFAULT, FD_VM_COMPUTE_UNIT_LIMIT,
      rodata, rodata_sz, NULL, 0UL, 0UL, 0UL, 0UL, NULL,
      TEST_VM_DEFAULT_SBPF_VERSION, NULL, NULL, sha,
      NULL, 0U, NULL, 0,
      FD_FEATURE_ACTIVE_BANK( bank, account_data_direct_mapping ),
      FD_FEATURE_ACTIVE_BANK( bank, syscall_parameter_address_restrictions ),
      FD_FEATURE_ACTIVE_BANK( bank, virtual_address_space_adjustments ),
      0, 0UL );
  FD_TEST( vm_ok );

  test_feature_disabled();
  test_feature_enabled( vm );

  fd_vm_delete( fd_vm_leave( vm ) );
  fd_sha256_delete( fd_sha256_leave( sha ) );
  fd_wksp_free_laddr( runtime );
  fd_wksp_delete_anonymous( wksp );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
