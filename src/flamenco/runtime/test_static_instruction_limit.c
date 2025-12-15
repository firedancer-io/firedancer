/* Test for SIMD-0160 static_instruction_limit */

#include "fd_executor.h"
#include "fd_bank.h"
#include "fd_runtime.h"
#include "fd_runtime_err.h"
#include "../features/fd_features.h"

static void
init_bank( fd_bank_t * bank ) {
  memset( bank, 0, sizeof(fd_bank_t) );
  fd_bank_slot_set( bank, 1UL );
}

static void
init_txn_with_instr_cnt( fd_txn_p_t * txn_p,
                         ushort       instr_cnt ) {
  fd_txn_t * txn = TXN( txn_p );

  txn->transaction_version = FD_TXN_V0;
  txn->instr_cnt           = instr_cnt;

  for( ushort i=0; i<instr_cnt; i++ ) {
    txn->instr[i].program_id = 0;
    txn->instr[i].acct_cnt   = 0;
    txn->instr[i].data_sz    = 0;
    txn->instr[i].acct_off   = 0;
    txn->instr[i].data_off   = 0;
  }
}

static void
activate_static_instruction_limit( fd_bank_t * bank ) {
  fd_bank_features_modify( bank )->static_instruction_limit = 0UL;
}

static void
deactivate_static_instruction_limit( fd_bank_t * bank ) {
  fd_bank_features_modify( bank )->static_instruction_limit = FD_FEATURE_DISABLED;
}

static void
test_static_instruction_limit_deactivated( fd_bank_t * bank ) {
  fd_txn_p_t   txn_p[1]   = {0};
  fd_txn_out_t txn_out[1] = {0};

  init_bank( bank );
  deactivate_static_instruction_limit( bank );
  init_txn_with_instr_cnt( txn_p, 65 );

  fd_txn_in_t txn_in = { .txn = txn_p };

  FD_TEST( fd_executor_verify_transaction( bank, &txn_in, txn_out )==FD_RUNTIME_EXECUTE_SUCCESS );
}

static void
test_static_instruction_limit_exceeded( fd_bank_t * bank ) {
  fd_txn_p_t   txn_p[1]   = {0};
  fd_txn_out_t txn_out[1] = {0};

  init_bank( bank );
  activate_static_instruction_limit( bank );
  init_txn_with_instr_cnt( txn_p, 65 );

  fd_txn_in_t txn_in = { .txn = txn_p };

  FD_TEST( fd_executor_verify_transaction( bank, &txn_in, txn_out )==FD_RUNTIME_TXN_ERR_SANITIZE_FAILURE );
}

static void
test_static_instruction_limit_at_limit( fd_bank_t * bank ) {
  fd_txn_p_t   txn_p[1]   = {0};
  fd_txn_out_t txn_out[1] = {0};

  init_bank( bank );
  activate_static_instruction_limit( bank );
  init_txn_with_instr_cnt( txn_p, 64 );

  fd_txn_in_t txn_in = { .txn = txn_p };

  FD_TEST( fd_executor_verify_transaction( bank, &txn_in, txn_out )==FD_RUNTIME_EXECUTE_SUCCESS );
}

static void
test_static_instruction_limit_under_limit( fd_bank_t * bank ) {
  fd_txn_p_t   txn_p[1]   = {0};
  fd_txn_out_t txn_out[1] = {0};

  init_bank( bank );
  activate_static_instruction_limit( bank );
  init_txn_with_instr_cnt( txn_p, 1 );

  fd_txn_in_t txn_in = { .txn = txn_p };

  FD_TEST( fd_executor_verify_transaction( bank, &txn_in, txn_out )==FD_RUNTIME_EXECUTE_SUCCESS );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  char *      _page_sz = "normal";
  ulong       page_cnt = 710UL;
  ulong       numa_idx = fd_shmem_numa_idx( 0 );
  fd_wksp_t * wksp     = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ),
                                                page_cnt,
                                                fd_shmem_cpu_idx( numa_idx ),
                                                "wksp",
                                                0UL );
  FD_TEST( wksp );

  fd_bank_t * bank = fd_wksp_alloc_laddr( wksp, alignof(fd_bank_t), sizeof(fd_bank_t), 1UL );
  FD_TEST( bank );

  test_static_instruction_limit_deactivated( bank );
  test_static_instruction_limit_exceeded( bank );
  test_static_instruction_limit_at_limit( bank );
  test_static_instruction_limit_under_limit( bank );

  fd_wksp_delete_anonymous( wksp );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
