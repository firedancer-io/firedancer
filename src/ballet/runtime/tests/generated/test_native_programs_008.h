#include "../fd_tests.h"
int test_8(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 103,80,55,89,90,127,79,123,122,114,118,126,29,56,26,98,117,62,30,108,125,2,116,77,33,109,76,61,27,110,113,121,75,111,105,92,82,112,128,120,124,83,24,87,106,15,78 };
  test.disable_feature = disabled_features;
  test.bt = "   2: solana_config_program::config_processor::tests::test_config_initialize_no_panic             at ./src/config_processor.rs:809:9   3: solana_config_program::config_processor::tests::test_config_initialize_no_panic::{{closure}}             at ./src/config_processor.rs:803:5";
  test.test_name = "config_processor::tests::test_config_initialize_no_panic";
  test.test_nonce  = 23;
  test.test_number = 8;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 0;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  static uchar const fd_flamenco_native_prog_test_8_raw[] = { 0x00,0x00,0x00,0x01,0x01,0x03,0x06,0x4a,0xa3,0x00,0x2f,0x74,0xdc,0xc8,0x6e,0x43,0x31,0x0f,0x0c,0x05,0x2a,0xf8,0xc5,0xda,0x27,0xf6,0x10,0x40,0x19,0xa3,0x23,0xef,0xa0,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x09,0x00,0x15,0xcd,0x5b,0x07,0x00,0x00,0x00,0x00 };
  test.raw_tx = fd_flamenco_native_prog_test_8_raw;
  test.raw_tx_len = 82UL;
  test.expected_result = -20;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
