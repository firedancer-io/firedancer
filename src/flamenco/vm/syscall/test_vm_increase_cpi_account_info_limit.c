/* Test for SIMD-0339 increase_cpi_account_info_limit

   This test makes a CPI call (a simple system program transfer) with
   all permuatations of the increase_cpi_account_info_limit and
   increase_tx_account_lock_limit features.

   Each test asserts that the error code is correct and the correct amount
   of CUs have been charged. */

#include "fd_vm_syscall.h"
#include "../test_vm_util.h"
#include "../../runtime/fd_bank.h"
#include "../../runtime/fd_runtime.h"
#include "../../runtime/fd_system_ids.h"
#include "../../log_collector/fd_log_collector.h"

#define TEST_SYSTEM_PROGRAM_TRANSFER_DISCRIMINANT (2U)
#define TEST_VM_ACCOUNT_INFO_BYTE_SIZE            (80UL)
#define TEST_VM_CPI_BYTES_PER_UNIT                (250UL)
#define TEST_SYSTEM_PROGRAM_EXECUTE_CU            (150UL)
#define TEST_WKSP_TAG                             (1234UL)

static fd_pubkey_t const test_transfer_from_pubkey = {{
  0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
  0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
  0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
  0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11
}};

static fd_pubkey_t const test_transfer_to_pubkey = {{
  0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
  0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
  0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
  0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22
}};

struct test_env {
  fd_wksp_t *             wksp;
  fd_runtime_t *          runtime;
  fd_sha256_t             sha[1];
  fd_vm_t                 vm[1];
  fd_exec_instr_ctx_t     instr_ctx[1];
  fd_bank_t               bank[1];
  fd_txn_out_t            txn_out[1];
  fd_instr_info_t         instr[1];
  uchar                   rodata[100];
  fd_account_meta_t *     source_meta;
  fd_account_meta_t *     dest_meta;
  fd_account_meta_t *     sysprog_meta;
  fd_vm_acc_region_meta_t acc_region_metas[3];
  fd_log_collector_t      log_collector[1];
};
typedef struct test_env test_env_t;

static inline ulong
expected_account_info_cu( ulong num_acct_infos ) {
  return (num_acct_infos * TEST_VM_ACCOUNT_INFO_BYTE_SIZE) / TEST_VM_CPI_BYTES_PER_UNIT;
}

static void
setup_cpi_memory( fd_vm_t * vm,
                  ulong     num_acct_infos,
                  ulong *   out_instr_va,
                  ulong *   out_acct_infos_va ) {

  ulong heap_offset = 0UL;

  fd_vm_c_instruction_t * instr = (fd_vm_c_instruction_t *)&vm->heap[heap_offset];
  *out_instr_va = FD_VM_MEM_MAP_HEAP_REGION_START + heap_offset;
  heap_offset += sizeof(fd_vm_c_instruction_t);

  ulong program_id_offset = heap_offset;
  fd_pubkey_t * program_id = (fd_pubkey_t *)&vm->heap[heap_offset];
  memcpy( program_id, &fd_solana_system_program_id, sizeof(fd_pubkey_t) );
  heap_offset += sizeof(fd_pubkey_t);

  ulong acct_metas_offset = heap_offset;
  fd_vm_c_account_meta_t * meta0 = (fd_vm_c_account_meta_t *)&vm->heap[heap_offset];
  heap_offset += sizeof(fd_vm_c_account_meta_t);
  fd_vm_c_account_meta_t * meta1 = (fd_vm_c_account_meta_t *)&vm->heap[heap_offset];
  heap_offset += sizeof(fd_vm_c_account_meta_t);

  ulong meta_pubkey0_offset = heap_offset;
  fd_pubkey_t * meta_pubkey0 = (fd_pubkey_t *)&vm->heap[heap_offset];
  memcpy( meta_pubkey0, &test_transfer_from_pubkey, sizeof(fd_pubkey_t) );
  heap_offset += sizeof(fd_pubkey_t);

  ulong meta_pubkey1_offset = heap_offset;
  fd_pubkey_t * meta_pubkey1 = (fd_pubkey_t *)&vm->heap[heap_offset];
  memcpy( meta_pubkey1, &test_transfer_to_pubkey, sizeof(fd_pubkey_t) );
  heap_offset += sizeof(fd_pubkey_t);

  meta0->pubkey_addr = FD_VM_MEM_MAP_HEAP_REGION_START + meta_pubkey0_offset;
  meta0->is_signer   = 1;
  meta0->is_writable = 1;

  meta1->pubkey_addr = FD_VM_MEM_MAP_HEAP_REGION_START + meta_pubkey1_offset;
  meta1->is_signer   = 0;
  meta1->is_writable = 1;

  ulong instr_data_offset = heap_offset;
  uint * discriminant = (uint *)&vm->heap[heap_offset];
  *discriminant = TEST_SYSTEM_PROGRAM_TRANSFER_DISCRIMINANT;
  heap_offset += sizeof(uint);

  ulong * lamports = (ulong *)&vm->heap[heap_offset];
  *lamports = 0UL;
  heap_offset += sizeof(ulong);

  heap_offset = fd_ulong_align_up( heap_offset, 8UL );

  ulong acct_infos_offset = heap_offset;
  *out_acct_infos_va = FD_VM_MEM_MAP_HEAP_REGION_START + acct_infos_offset;

  ulong acc_info_data_offset = heap_offset + num_acct_infos * sizeof(fd_vm_c_account_info_t);

  for( ulong i = 0; i < num_acct_infos; i++ ) {
    fd_vm_c_account_info_t * info = (fd_vm_c_account_info_t *)&vm->heap[heap_offset];

    ulong pubkey_offset   = acc_info_data_offset + i * (sizeof(fd_pubkey_t) + sizeof(ulong));
    ulong lamports_offset = pubkey_offset + sizeof(fd_pubkey_t);

    fd_pubkey_t * pubkey = (fd_pubkey_t *)&vm->heap[pubkey_offset];
    if( i == 0 ) {
      memcpy( pubkey, &test_transfer_from_pubkey, sizeof(fd_pubkey_t) );
    } else if( i == 1 ) {
      memcpy( pubkey, &test_transfer_to_pubkey, sizeof(fd_pubkey_t) );
    } else {
      memset( pubkey->uc, (int)(0x30 + i), sizeof(fd_pubkey_t) );
    }

    ulong * info_lamports = (ulong *)&vm->heap[lamports_offset];
    *info_lamports = (i == 0) ? 1000000UL : 0UL;

    info->pubkey_addr   = FD_VM_MEM_MAP_HEAP_REGION_START + pubkey_offset;
    info->lamports_addr = FD_VM_MEM_MAP_HEAP_REGION_START + lamports_offset;
    info->data_sz       = 0UL;
    info->data_addr     = 0UL;
    info->owner_addr    = FD_VM_MEM_MAP_HEAP_REGION_START + program_id_offset;
    info->rent_epoch    = 0UL;
    info->is_signer     = (i == 0) ? 1 : 0;
    info->is_writable   = (i < 2) ? 1 : 0;
    info->executable    = 0;
    heap_offset += sizeof(fd_vm_c_account_info_t);
  }

  instr->program_id_addr = FD_VM_MEM_MAP_HEAP_REGION_START + program_id_offset;
  instr->accounts_addr   = FD_VM_MEM_MAP_HEAP_REGION_START + acct_metas_offset;
  instr->accounts_len    = 2UL;
  instr->data_addr       = FD_VM_MEM_MAP_HEAP_REGION_START + instr_data_offset;
  instr->data_len        = sizeof(uint) + sizeof(ulong);
}

static void
test_env_create( test_env_t * env,
                 fd_wksp_t *  wksp,
                 int          enable_increase_cpi_account_info_limit,
                 int          enable_increase_tx_account_lock_limit ) {

  memset( env, 0, sizeof(test_env_t) );
  env->wksp = wksp;

  env->runtime = fd_wksp_alloc_laddr( wksp, alignof(fd_runtime_t), sizeof(fd_runtime_t), TEST_WKSP_TAG );
  FD_TEST( env->runtime );

  fd_log_collector_init( env->log_collector, 0 );
  env->runtime->log.log_collector = env->log_collector;

  fd_sha256_t * sha = fd_sha256_join( fd_sha256_new( env->sha ) );
  FD_TEST( sha );

  fd_vm_t * vm = fd_vm_join( fd_vm_new( env->vm ) );
  FD_TEST( vm );

  test_vm_minimal_exec_instr_ctx( env->instr_ctx, env->runtime, env->bank, env->txn_out );

  fd_features_t * features = fd_bank_features_modify( env->bank );
  fd_features_disable_all( features );
  fd_bank_slot_set( env->bank, 1UL );

  if( enable_increase_cpi_account_info_limit ) features->increase_cpi_account_info_limit = 0UL;
  if( enable_increase_tx_account_lock_limit )  features->increase_tx_account_lock_limit  = 0UL;
  features->loosen_cpi_size_restriction = 0UL;

  env->txn_out->accounts.cnt = 3;

  memcpy( &env->txn_out->accounts.keys[0], &fd_solana_system_program_id, sizeof(fd_pubkey_t) );
  env->sysprog_meta = fd_wksp_alloc_laddr( wksp, alignof(fd_account_meta_t), sizeof(fd_account_meta_t), TEST_WKSP_TAG );
  memset( env->sysprog_meta, 0, sizeof(fd_account_meta_t) );
  memcpy( env->sysprog_meta->owner, &fd_solana_native_loader_id, sizeof(fd_pubkey_t) );
  env->sysprog_meta->executable = 1;
  env->txn_out->accounts.metas[0] = env->sysprog_meta;

  memcpy( &env->txn_out->accounts.keys[1], &test_transfer_from_pubkey, sizeof(fd_pubkey_t) );
  env->source_meta = fd_wksp_alloc_laddr( wksp, alignof(fd_account_meta_t), sizeof(fd_account_meta_t), TEST_WKSP_TAG );
  memset( env->source_meta, 0, sizeof(fd_account_meta_t) );
  memcpy( env->source_meta->owner, &fd_solana_system_program_id, sizeof(fd_pubkey_t) );
  env->source_meta->lamports = 1000000UL;
  env->txn_out->accounts.metas[1] = env->source_meta;

  memcpy( &env->txn_out->accounts.keys[2], &test_transfer_to_pubkey, sizeof(fd_pubkey_t) );
  env->dest_meta = fd_wksp_alloc_laddr( wksp, alignof(fd_account_meta_t), sizeof(fd_account_meta_t), TEST_WKSP_TAG );
  memset( env->dest_meta, 0, sizeof(fd_account_meta_t) );
  memcpy( env->dest_meta->owner, &fd_solana_system_program_id, sizeof(fd_pubkey_t) );
  env->dest_meta->lamports = 0UL;
  env->txn_out->accounts.metas[2] = env->dest_meta;

  env->runtime->accounts.refcnt[0] = 0UL;
  env->runtime->accounts.refcnt[1] = 0UL;
  env->runtime->accounts.refcnt[2] = 0UL;

  memset( env->instr, 0, sizeof(fd_instr_info_t) );
  env->instr->program_id  = 0;
  env->instr->acct_cnt    = 3;
  env->instr->accounts[0] = fd_instruction_account_init( 0, 0, 0, 0, 0 );
  env->instr->accounts[1] = fd_instruction_account_init( 1, 1, 1, 1, 1 );
  env->instr->accounts[2] = fd_instruction_account_init( 2, 2, 2, 1, 0 );
  env->instr_ctx->instr   = env->instr;

  memset( env->acc_region_metas, 0, sizeof(env->acc_region_metas) );
  env->acc_region_metas[0].region_idx        = 0;
  env->acc_region_metas[0].original_data_len = 0UL;
  env->acc_region_metas[0].meta              = env->sysprog_meta;
  env->acc_region_metas[1].region_idx        = 0;
  env->acc_region_metas[1].original_data_len = 0UL;
  env->acc_region_metas[1].meta              = env->source_meta;
  env->acc_region_metas[2].region_idx        = 0;
  env->acc_region_metas[2].original_data_len = 0UL;
  env->acc_region_metas[2].meta              = env->dest_meta;

  memset( env->rodata, 0, sizeof(env->rodata) );
  int vm_ok = !!fd_vm_init(
      vm,
      env->instr_ctx,
      FD_VM_HEAP_DEFAULT,
      FD_VM_COMPUTE_UNIT_LIMIT,
      env->rodata,
      sizeof(env->rodata),
      NULL,
      0UL,
      0UL,
      0UL,
      0UL,
      NULL,
      TEST_VM_DEFAULT_SBPF_VERSION,
      NULL,
      NULL,
      sha,
      NULL,
      0U,
      env->acc_region_metas,
      0,
      FD_FEATURE_ACTIVE_BANK( env->bank, account_data_direct_mapping ),
      FD_FEATURE_ACTIVE_BANK( env->bank, stricter_abi_and_runtime_constraints ),
      0, 0UL
  );
  FD_TEST( vm_ok );
}

static void
test_env_destroy( test_env_t * env ) {
  test_vm_clear_txn_ctx_err( env->instr_ctx->txn_out );
  fd_vm_delete( fd_vm_leave( env->vm ) );
  fd_sha256_delete( fd_sha256_leave( env->sha ) );
  fd_wksp_free_laddr( env->sysprog_meta );
  fd_wksp_free_laddr( env->source_meta );
  fd_wksp_free_laddr( env->dest_meta );
  fd_wksp_free_laddr( env->runtime );

  ulong           tag = TEST_WKSP_TAG;
  fd_wksp_usage_t usage[1];
  fd_wksp_usage( env->wksp, &tag, 1UL, usage );
  FD_TEST( usage->used_cnt == 0UL );
  FD_TEST( usage->used_sz  == 0UL );
}

static void
run_test( fd_wksp_t * wksp,
          int         increase_cpi_account_info_limit,
          int         increase_tx_account_lock_limit,
          ulong       num_infos,
          int         expected_err,
          ulong       expected_cus ) {
  test_env_t env[1];
  test_env_create( env, wksp, increase_cpi_account_info_limit, increase_tx_account_lock_limit );

  ulong initial_cu = env->vm->cu;
  ulong instr_va, acct_infos_va;
  setup_cpi_memory( env->vm, num_infos, &instr_va, &acct_infos_va );

  ulong ret = 0UL;
  int err = fd_vm_syscall_cpi_c( env->vm, instr_va, acct_infos_va, num_infos, 0UL, 0UL, &ret );

  FD_TEST( err == expected_err );
  FD_TEST( (initial_cu - env->vm->cu) == expected_cus );

  test_env_destroy( env );
}

static void
test_both_enabled_exceeds_limit( fd_wksp_t * wksp ) {
  int   increase_cpi_account_info_limit = 1;
  int   increase_tx_account_lock_limit  = 1;
  ulong num_infos                       = 256UL;
  ulong expected_cus                    = FD_VM_INVOKE_UNITS_SIMD_0339;
  run_test( wksp,
            increase_cpi_account_info_limit,
            increase_tx_account_lock_limit,
            num_infos,
            FD_VM_SYSCALL_ERR_MAX_INSTRUCTION_ACCOUNT_INFOS_EXCEEDED,
            expected_cus );
}

static void
test_increase_cpi_account_info_limit_enabled_exceeds_limit( fd_wksp_t * wksp ) {
  int   increase_cpi_account_info_limit = 1;
  int   increase_tx_account_lock_limit  = 0;
  ulong num_infos                       = 256UL;
  ulong expected_cus                    = FD_VM_INVOKE_UNITS_SIMD_0339;
  run_test( wksp,
            increase_cpi_account_info_limit,
            increase_tx_account_lock_limit,
            num_infos,
            FD_VM_SYSCALL_ERR_MAX_INSTRUCTION_ACCOUNT_INFOS_EXCEEDED,
            expected_cus );
}

static void
test_increase_tx_account_lock_limit_enabled_exceeds_limit( fd_wksp_t * wksp ) {
  int   increase_cpi_account_info_limit = 0;
  int   increase_tx_account_lock_limit  = 1;
  ulong num_infos                       = 129UL;
  ulong expected_cus                    = FD_VM_INVOKE_UNITS;
  run_test( wksp,
            increase_cpi_account_info_limit,
            increase_tx_account_lock_limit,
            num_infos,
            FD_VM_SYSCALL_ERR_MAX_INSTRUCTION_ACCOUNT_INFOS_EXCEEDED,
            expected_cus );
}

static void
test_neither_enabled_exceeds_limit( fd_wksp_t * wksp ) {
  int   increase_cpi_account_info_limit = 0;
  int   increase_tx_account_lock_limit  = 0;
  ulong num_infos                       = 65UL;
  ulong expected_cus                    = FD_VM_INVOKE_UNITS;
  run_test( wksp,
            increase_cpi_account_info_limit,
            increase_tx_account_lock_limit,
            num_infos,
            FD_VM_SYSCALL_ERR_MAX_INSTRUCTION_ACCOUNT_INFOS_EXCEEDED,
            expected_cus );
}

static void
test_both_enabled_at_limit( fd_wksp_t * wksp ) {
  int   increase_cpi_account_info_limit = 1;
  int   increase_tx_account_lock_limit  = 1;
  ulong num_infos                       = 255UL;
  ulong expected_cus                    = FD_VM_INVOKE_UNITS_SIMD_0339
                                        + expected_account_info_cu( num_infos )
                                        + TEST_SYSTEM_PROGRAM_EXECUTE_CU;
  run_test( wksp,
            increase_cpi_account_info_limit,
            increase_tx_account_lock_limit,
            num_infos,
            FD_VM_SUCCESS,
            expected_cus );
}

static void
test_increase_cpi_account_info_limit_enabled_at_limit( fd_wksp_t * wksp ) {
  int   increase_cpi_account_info_limit = 1;
  int   increase_tx_account_lock_limit  = 0;
  ulong num_infos                       = 255UL;
  ulong expected_cus                    = FD_VM_INVOKE_UNITS_SIMD_0339
                                        + expected_account_info_cu( num_infos )
                                        + TEST_SYSTEM_PROGRAM_EXECUTE_CU;
  run_test( wksp,
            increase_cpi_account_info_limit,
            increase_tx_account_lock_limit,
            num_infos,
            FD_VM_SUCCESS,
            expected_cus );
}

static void
test_increase_tx_account_lock_limit_enabled_at_limit( fd_wksp_t * wksp ) {
  int   increase_cpi_account_info_limit = 0;
  int   increase_tx_account_lock_limit  = 1;
  ulong num_infos                       = 128UL;
  ulong expected_cus                    = FD_VM_INVOKE_UNITS + TEST_SYSTEM_PROGRAM_EXECUTE_CU;
  run_test( wksp,
            increase_cpi_account_info_limit,
            increase_tx_account_lock_limit,
            num_infos,
            FD_VM_SUCCESS,
            expected_cus );
}

static void
test_neither_enabled_at_limit( fd_wksp_t * wksp ) {
  int   increase_cpi_account_info_limit = 0;
  int   increase_tx_account_lock_limit  = 0;
  ulong num_infos                       = 64UL;
  ulong expected_cus                    = FD_VM_INVOKE_UNITS + TEST_SYSTEM_PROGRAM_EXECUTE_CU;
  run_test( wksp,
            increase_cpi_account_info_limit,
            increase_tx_account_lock_limit,
            num_infos,
            FD_VM_SUCCESS,
            expected_cus );
}

static void
test_both_enabled_below_limit( fd_wksp_t * wksp ) {
  int   increase_cpi_account_info_limit = 1;
  int   increase_tx_account_lock_limit  = 1;
  ulong num_infos                       = 10UL;
  ulong expected_cus                    = FD_VM_INVOKE_UNITS_SIMD_0339
                                        + expected_account_info_cu( num_infos )
                                        + TEST_SYSTEM_PROGRAM_EXECUTE_CU;
  run_test( wksp,
            increase_cpi_account_info_limit,
            increase_tx_account_lock_limit,
            num_infos,
            FD_VM_SUCCESS,
            expected_cus );
}

static void
test_increase_cpi_account_info_limit_enabled_below_limit( fd_wksp_t * wksp ) {
  int   increase_cpi_account_info_limit = 1;
  int   increase_tx_account_lock_limit  = 0;
  ulong num_infos                       = 10UL;
  ulong expected_cus                    = FD_VM_INVOKE_UNITS_SIMD_0339
                                        + expected_account_info_cu( num_infos )
                                        + TEST_SYSTEM_PROGRAM_EXECUTE_CU;
  run_test( wksp,
            increase_cpi_account_info_limit,
            increase_tx_account_lock_limit,
            num_infos,
            FD_VM_SUCCESS,
            expected_cus );
}

static void
test_increase_tx_account_lock_limit_enabled_below_limit( fd_wksp_t * wksp ) {
  int   increase_cpi_account_info_limit = 0;
  int   increase_tx_account_lock_limit  = 1;
  ulong num_infos                       = 10UL;
  ulong expected_cus                    = FD_VM_INVOKE_UNITS + TEST_SYSTEM_PROGRAM_EXECUTE_CU;
  run_test( wksp,
            increase_cpi_account_info_limit,
            increase_tx_account_lock_limit,
            num_infos,
            FD_VM_SUCCESS,
            expected_cus );
}

static void
test_neither_enabled_below_limit( fd_wksp_t * wksp ) {
  int   increase_cpi_account_info_limit = 0;
  int   increase_tx_account_lock_limit  = 0;
  ulong num_infos                       = 10UL;
  ulong expected_cus                    = FD_VM_INVOKE_UNITS + TEST_SYSTEM_PROGRAM_EXECUTE_CU;
  run_test( wksp,
            increase_cpi_account_info_limit,
            increase_tx_account_lock_limit,
            num_infos,
            FD_VM_SUCCESS,
            expected_cus );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  char const * _page_sz = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",   NULL, "gigantic"      );
  ulong        page_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt",  NULL, 4UL             );
  ulong        near_cpu = fd_env_strip_cmdline_ulong( &argc, &argv, "--near-cpu",  NULL, fd_log_cpu_id() );

  fd_wksp_t * wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, near_cpu, "wksp", 0UL );
  FD_TEST( wksp );

  test_both_enabled_exceeds_limit( wksp );
  test_increase_cpi_account_info_limit_enabled_exceeds_limit( wksp );
  test_increase_tx_account_lock_limit_enabled_exceeds_limit( wksp );
  test_neither_enabled_exceeds_limit( wksp );
  test_both_enabled_at_limit( wksp );
  test_increase_cpi_account_info_limit_enabled_at_limit( wksp );
  test_increase_tx_account_lock_limit_enabled_at_limit( wksp );
  test_neither_enabled_at_limit( wksp );
  test_both_enabled_below_limit( wksp );
  test_increase_cpi_account_info_limit_enabled_below_limit( wksp );
  test_increase_tx_account_lock_limit_enabled_below_limit( wksp );
  test_neither_enabled_below_limit( wksp );

  fd_wksp_delete_anonymous( wksp );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
