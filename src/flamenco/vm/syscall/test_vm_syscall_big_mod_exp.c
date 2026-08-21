#include "fd_vm_syscall.h"
#include "../test_vm_util.h"
#include "../../runtime/fd_bank.h"
#include "../../../ballet/bigint/fd_big_mod_exp.h"
#include "../../../ballet/murmur3/fd_murmur3.h"

/* Mirrors FD_BIG_MOD_EXP_BASE_CU in fd_vm_syscall_big_mod_exp.c, which is
   private to that translation unit. */
#define TEST_BIG_MOD_EXP_BASE_CU (422UL)

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

  /* (c) charge/validation ORDER, which is consensus visible.  agave charges the
     base cost before translating params, charges the operation cost after
     translating only the exponent, and treats an empty or otherwise invalid
     modulus as an invalid-attribute abort after charging -- not as a length
     error before it.  Each case below pins one of those. */

  ulong const OP_CU = 1UL;   /* mult_complexity(1)*max(1,75)=75 -> ceil(75/189) */

# define RUN( pv, rv ) (__extension__({                                    \
    vm->cu = FD_VM_COMPUTE_UNIT_LIMIT;                                     \
    FD_VM_PREPARE_ERR_OVERWRITE( vm );                                     \
    ulong _r = 123UL;                                                      \
    int _e = fd_vm_syscall_sol_big_mod_exp( vm, (pv), (rv), 0UL,0UL,0UL, &_r ); \
    _e; }))
# define CHARGED() ( FD_VM_COMPUTE_UNIT_LIMIT - vm->cu )

  ulong const PV = FD_VM_MEM_MAP_HEAP_REGION_START + PARAMS_OFF;
  ulong const RV = FD_VM_MEM_MAP_HEAP_REGION_START + RES_OFF;

  /* empty modulus: not a length error, and charged in full */
  params[5] = 0UL;
  FD_TEST( RUN( PV, RV )==FD_VM_SYSCALL_ERR_INVALID_ATTRIBUTE );
  FD_TEST( CHARGED()==TEST_BIG_MOD_EXP_BASE_CU+OP_CU );
  params[5] = 1UL;

  /* even modulus: same abort, also charged in full */
  vm->heap[ MOD_OFF ] = 8;
  FD_TEST( RUN( PV, RV )==FD_VM_SYSCALL_ERR_INVALID_ATTRIBUTE );
  FD_TEST( CHARGED()==TEST_BIG_MOD_EXP_BASE_CU+OP_CU );
  vm->heap[ MOD_OFF ] = 7;

  /* modulus of one: likewise */
  vm->heap[ MOD_OFF ] = 1;
  FD_TEST( RUN( PV, RV )==FD_VM_SYSCALL_ERR_INVALID_ATTRIBUTE );
  FD_TEST( CHARGED()==TEST_BIG_MOD_EXP_BASE_CU+OP_CU );
  vm->heap[ MOD_OFF ] = 7;

  /* oversized operand: length error, but the base cost is already spent */
  params[1] = FD_BIG_MOD_EXP_MAX_BYTES+1UL;
  FD_TEST( RUN( PV, RV )==FD_VM_SYSCALL_ERR_INVALID_LENGTH );
  FD_TEST( CHARGED()==TEST_BIG_MOD_EXP_BASE_CU );
  params[1] = 1UL;

  /* unmapped params: base cost is charged before params are translated */
  FD_TEST( RUN( 0UL, RV )==FD_VM_SYSCALL_ERR_SEGFAULT );
  FD_TEST( CHARGED()==TEST_BIG_MOD_EXP_BASE_CU );

  /* unmapped base: charged base + operation cost, since the operation cost is
     charged after the exponent but before the base */
  params[0] = 0UL;
  FD_TEST( RUN( PV, RV )==FD_VM_SYSCALL_ERR_SEGFAULT );
  FD_TEST( CHARGED()==TEST_BIG_MOD_EXP_BASE_CU+OP_CU );
  params[0] = FD_VM_MEM_MAP_HEAP_REGION_START + BASE_OFF;

  /* unmapped exponent: charged the base cost only, the exponent is needed to
     compute the operation cost */
  params[2] = 0UL;
  FD_TEST( RUN( PV, RV )==FD_VM_SYSCALL_ERR_SEGFAULT );
  FD_TEST( CHARGED()==TEST_BIG_MOD_EXP_BASE_CU );
  params[2] = FD_VM_MEM_MAP_HEAP_REGION_START + EXP_OFF;

  /* insufficient CU for the operation cost, with an unmapped base: the budget
     error must win, because the charge happens first */
  params[0] = 0UL;
  vm->cu = TEST_BIG_MOD_EXP_BASE_CU;                    /* enough for base only */
  FD_VM_PREPARE_ERR_OVERWRITE( vm );
  ulong ret_c = 123UL;
  FD_TEST( fd_vm_syscall_sol_big_mod_exp( vm, PV, RV, 0UL,0UL,0UL, &ret_c )
           ==FD_VM_SYSCALL_ERR_COMPUTE_BUDGET_EXCEEDED );
  params[0] = FD_VM_MEM_MAP_HEAP_REGION_START + BASE_OFF;

  /* empty exponent: base^0 == 1, zero padded to mod_len */
  vm->heap[ MOD_OFF   ] = 7;
  vm->heap[ MOD_OFF+1 ] = 0;
  vm->heap[ RES_OFF   ] = 0xcc;
  vm->heap[ RES_OFF+1 ] = 0xcc;
  params[3] = 0UL;                                    /* exponent_len */
  params[5] = 2UL;                                    /* modulus_len  */
  FD_TEST( RUN( PV, RV )==FD_VM_SUCCESS );
  FD_TEST( vm->heap[ RES_OFF ]==1 && vm->heap[ RES_OFF+1 ]==0 );
  params[3] = 1UL;
  params[5] = 1UL;

  /* output aliasing an input is permitted */
  vm->heap[ BASE_OFF ] = 5;
  FD_TEST( RUN( PV, FD_VM_MEM_MAP_HEAP_REGION_START + BASE_OFF )==FD_VM_SUCCESS );
  FD_TEST( vm->heap[ BASE_OFF ]==4 );                 /* 5^2 mod 7 = 4 */
  vm->heap[ BASE_OFF ] = 5;

# undef CHARGED
# undef RUN

  FD_LOG_NOTICE(( "ok: charge and validation order matches agave" ));
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
