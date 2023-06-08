#include "../fd_tests.h"
int test_41(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 90,80,126,83,105,114,110,116,113,77,127,121,117,75,112,128,98,79,125,78,55,103,89,92,30,82,106,33,122,24,56,111,15,120,29,62,108,76,61,123,2,87,109,27,118,26,124 };
  test.disable_feature = disabled_features;
  test.bt = "   2: solana_config_program::config_processor::tests::test_process_store_fail_account0_not_signer             at ./src/config_processor.rs:295:9   3: solana_config_program::config_processor::tests::test_process_store_fail_account0_not_signer::{{closure}}             at ./src/config_processor.rs:286:5";
  test.test_name = "config_processor::tests::test_process_store_fail_account0_not_signer";
  test.test_nonce  = 13;
  test.test_number = 41;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "BQrH8f9mmjtNFoNHqpE4SoWu9z2VKSrJnTRjNY1b6pzW",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  static uchar const fd_flamenco_native_prog_test_41_acc_0_data[] = { 0x00,0x15,0xcd,0x5b,0x07,0x00,0x00,0x00,0x00 };
  test_acc->data            = fd_flamenco_native_prog_test_41_acc_0_data;
  test_acc->data_len        = 9UL;
  static uchar const fd_flamenco_native_prog_test_41_acc_0_post_data[] = { 0x00,0x15,0xcd,0x5b,0x07,0x00,0x00,0x00,0x00 };
  test_acc->result_data     = fd_flamenco_native_prog_test_41_acc_0_post_data;
  test_acc->result_data_len = 9UL;
  test_acc++;
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  static uchar const fd_flamenco_native_prog_test_41_raw[] = { 0x00,0x00,0x00,0x01,0x02,0x9a,0xb0,0xf2,0x64,0x2c,0xac,0x25,0x46,0xbb,0x6d,0x2c,0x89,0x95,0x60,0x58,0xe9,0x9c,0x43,0x60,0xfd,0xa0,0x3d,0xc4,0x62,0xc9,0xfe,0x85,0xe8,0x8a,0xe6,0x6d,0xcb,0x03,0x06,0x4a,0xa3,0x00,0x2f,0x74,0xdc,0xc8,0x6e,0x43,0x31,0x0f,0x0c,0x05,0x2a,0xf8,0xc5,0xda,0x27,0xf6,0x10,0x40,0x19,0xa3,0x23,0xef,0xa0,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x01,0x01,0x00,0x09,0x00,0x2a,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
  test.raw_tx = fd_flamenco_native_prog_test_41_raw;
  test.raw_tx_len = 115UL;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
