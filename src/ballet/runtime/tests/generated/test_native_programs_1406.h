#include "../fd_tests.h"
int test_1406(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 128,15,30,2,127,62,92,126,75,33,90,77,116,117,125,83,122,118,24,113,106,123,124,27,26,121,89,108,114,76,109,87,110,103,105,98,78,111,112,55,120,79,80,29,61,82,56 };
  test.disable_feature = disabled_features;
  test.bt = "   2: solana_runtime::system_instruction_processor::tests::test_nonce_account_upgrade             at ./src/system_instruction_processor.rs:2292:24   3: solana_runtime::system_instruction_processor::tests::test_nonce_account_upgrade::{{closure}}             at ./src/system_instruction_processor.rs:2273:5   4: core::ops::function::FnOnce::call_once             at /rustc/0677edc86e342f333d4828b0ee1ef395a4e70fe5/library/core/src/ops/function.rs:227:5   5: core::ops::function::FnOnce::call_once             at /rustc/0677edc86e342f333d4828b0ee1ef395a4e70fe5/library/core/src/ops/function.rs:227:5";
  test.test_name = "system_instruction_processor::tests::test_nonce_account_upgrade";
  test.test_nonce  = 20;
  test.test_number = 1406;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113Wkz5t6RU4FGfKMYK5DT31BHbrRL5ZjSjAFq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000UL;
  test_acc->result_lamports = 1000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  static uchar const fd_flamenco_native_prog_test_1406_acc_0_data[] = { 0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
  test_acc->data            = fd_flamenco_native_prog_test_1406_acc_0_data;
  test_acc->data_len        = 8UL;
  static uchar const fd_flamenco_native_prog_test_1406_acc_0_post_data[] = { 0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
  test_acc->result_data     = fd_flamenco_native_prog_test_1406_acc_0_post_data;
  test_acc->result_data_len = 8UL;
  test_acc++;
  fd_base58_decode_32( "11111111111111111111111111111111",  (unsigned char *) &test.program_id);
  static uchar const fd_flamenco_native_prog_test_1406_raw[] = { 0x00,0x00,0x00,0x01,0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x52,0x12,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x01,0x01,0x00,0x04,0x0c,0x00,0x00,0x00 };
  test.raw_tx = fd_flamenco_native_prog_test_1406_raw;
  test.raw_tx_len = 110UL;
  test.expected_result = -2;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
