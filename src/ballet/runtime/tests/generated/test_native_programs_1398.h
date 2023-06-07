#include "../fd_tests.h"
int test_1398(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 118,110,78,125,111,105,113,128,24,2,82,55,103,27,56,62,120,126,79,29,75,127,83,123,122,114,106,61,108,117,90,89,87,77,116,109,26,121,98,33,124,76,80,30,92,15,112 };
  test.disable_feature = disabled_features;
  test.test_name = "system_instruction_processor::tests::test_nonce_account_upgrade_check_owner";
  test.test_nonce  = 18;
  test.test_number = 1398;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113VRjC53aEjvdh6LKYSWu5p5DLoaUcTEUjDXd",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111113VS8Xg2gY2dp9y9kgXYKR8ZLcbCysPwiK3qy",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000UL;
  test_acc->result_lamports = 1000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  static uchar const fd_flamenco_native_prog_test_1398_acc_0_data[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
  test_acc->data            = fd_flamenco_native_prog_test_1398_acc_0_data;
  test_acc->data_len        = 8UL;
  static uchar const fd_flamenco_native_prog_test_1398_acc_0_post_data[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
  test_acc->result_data     = fd_flamenco_native_prog_test_1398_acc_0_post_data;
  test_acc->result_data_len = 8UL;
  test_acc++;
  fd_base58_decode_32( "11111111111111111111111111111111",  (unsigned char *) &test.program_id);
  static uchar const fd_flamenco_native_prog_test_1398_raw[] = { 0x00,0x00,0x00,0x01,0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x51,0x52,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x01,0x01,0x00,0x04,0x0c,0x00,0x00,0x00 };
  test.raw_tx = fd_flamenco_native_prog_test_1398_raw;
  test.raw_tx_len = 110UL;
  test.expected_result = -47;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
