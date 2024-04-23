#include "../fd_tests.h"
int test_2419(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  test.bt = "   2: solana_system_program::system_processor::tests::test_process_withdraw_ix_only_nonce_acc_fail             at ./src/system_processor.rs:1631:9   3: solana_system_program::system_processor::tests::test_process_withdraw_ix_only_nonce_acc_fail::{{closure}}             at ./src/system_processor.rs:1629:55   4: core::ops::function::FnOnce::call_once             at /rustc/cc66ad468955717ab92600c770da8c1601a4ff33/library/core/src/ops/function.rs:250:5   5: core::ops::function::FnOnce::call_once             at /rustc/cc66ad468955717ab92600c770da8c1601a4ff33/library/core/src/ops/function.rs:250:5";
  test.test_name = "system_processor::tests::test_process_withdraw_ix_only_nonce_acc_fail";
  test.test_number = 2419;
  test.sysvar_cache.clock = "";
  test.sysvar_cache.epoch_schedule = "";
  test.sysvar_cache.epoch_rewards = "";
  test.sysvar_cache.fees = "";
  test.sysvar_cache.rent = "";
  test.sysvar_cache.slot_hashes = "";
  test.sysvar_cache.stake_history = "";
  test.sysvar_cache.slot_history = "";
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

 // {'clock': '', 'epoch_schedule': '', 'epoch_rewards': '', 'fees': '', 'rent': '', 'slot_hashes': '', 'recent_blockhashes': '', 'stake_history': '', 'last_restart_slot': ''}
  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111i3UXS5QPRQGNRDDqVnyWTnmFCTHDWtVyGB",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111111iSp8RBhg8ajFEeMvXDJpwv32pxYAE85oaX",  (uchar *) &test_acc->owner);
  fd_base58_decode_32( "1111111iSp8RBhg8ajFEeMvXDJpwv32pxYAE85oaX",  (uchar *) &test_acc->result_owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->result_executable= 0;
  test_acc->rent_epoch      = 0;
  test_acc->result_rent_epoch      = 0;
  test_acc++;
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "NativeLoader1111111111111111111111111111111",  (uchar *) &test_acc->owner);
  fd_base58_decode_32( "NativeLoader1111111111111111111111111111111",  (uchar *) &test_acc->result_owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->result_executable= 0;
  test_acc->rent_epoch      = 0;
  test_acc->result_rent_epoch      = 0;
  test_acc++;
  fd_base58_decode_32( "11111111111111111111111111111111",  (unsigned char *) &test.program_id);
  static uchar const fd_flamenco_native_prog_test_2419_raw[] = { 0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x01,0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x66,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x01,0x01,0x00,0x0c,0x05,0x00,0x00,0x00,0x2a,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
  test.raw_tx = fd_flamenco_native_prog_test_2419_raw;
  test.raw_tx_len = 182UL;
  test.expected_result = -20;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
// https://explorer.solana.com/tx/inspector?message=AQABAgAAAAAAAABmAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEBAQAMBQAAACoAAAAAAAAA
