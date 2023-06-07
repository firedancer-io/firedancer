#include "../fd_tests.h"
int test_1484(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 30,116,127,117,82,118,111,29,26,79,112,128,83,62,106,89,27,114,109,61,33,56,75,122,125,110,121,105,78,24,124,108,126,98,90,77,120,103,113,92,2,123,76,55,15,87,80 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_invoke_main";
  test.test_nonce  = 0;
  test.test_number = 1484;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 0;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_base58_decode_32( "BPFLoader2111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  static uchar const fd_flamenco_native_prog_test_1484_raw[] = { 0x00,0x00,0x00,0x01,0x01,0x02,0xa8,0xf6,0x91,0x4e,0x88,0xa1,0x6e,0x39,0x5a,0xe1,0x28,0x94,0x8f,0xfa,0x69,0x56,0x93,0x37,0x68,0x18,0xdd,0x47,0x43,0x52,0x21,0xf3,0xc6,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00 };
  test.raw_tx = fd_flamenco_native_prog_test_1484_raw;
  test.raw_tx_len = 73UL;
  test.expected_result = -20;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
