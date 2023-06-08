#include "../fd_tests.h"
int test_1435(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 82,26,126,108,61,80,98,113,120,123,106,121,128,75,29,76,15,87,90,78,127,103,62,83,89,110,118,30,125,114,33,109,124,56,117,111,105,112,24,77,122,27,92,55,2,116,79 };
  test.disable_feature = disabled_features;
  test.bt = "   2: solana_runtime::system_instruction_processor::tests::test_process_nonce_ix_no_keyed_accs_fail             at ./src/system_instruction_processor.rs:1784:9   3: solana_runtime::system_instruction_processor::tests::test_process_nonce_ix_no_keyed_accs_fail::{{closure}}             at ./src/system_instruction_processor.rs:1783:5   4: core::ops::function::FnOnce::call_once             at /rustc/0677edc86e342f333d4828b0ee1ef395a4e70fe5/library/core/src/ops/function.rs:227:5   5: core::ops::function::FnOnce::call_once             at /rustc/0677edc86e342f333d4828b0ee1ef395a4e70fe5/library/core/src/ops/function.rs:227:5";
  test.test_name = "system_instruction_processor::tests::test_process_nonce_ix_no_keyed_accs_fail";
  test.test_nonce  = 22;
  test.test_number = 1435;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 0;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_base58_decode_32( "11111111111111111111111111111111",  (unsigned char *) &test.program_id);
  static uchar const fd_flamenco_native_prog_test_1435_raw[] = { 0x00,0x00,0x00,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x04,0x04,0x00,0x00,0x00 };
  test.raw_tx = fd_flamenco_native_prog_test_1435_raw;
  test.raw_tx_len = 77UL;
  test.expected_result = -20;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
