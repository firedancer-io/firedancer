#include "../fd_tests.h"
int test_1591(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 79,116,109,123,127,110,90,122,2,92,113,103,56,89,105,62,128,76,111,33,26,83,121,61,118,106,27,98,24,87,80,30,75,78,124,112,117,125,29,126,55,120,82,15,114,77,108 };
  test.disable_feature = disabled_features;
  test.bt = "   2: solana_bpf_loader_program::tests::test_bpf_loader_write             at ./src/lib.rs:1585:9   3: solana_bpf_loader_program::tests::test_bpf_loader_write::{{closure}}             at ./src/lib.rs:1564:5   4: core::ops::function::FnOnce::call_once             at /rustc/0677edc86e342f333d4828b0ee1ef395a4e70fe5/library/core/src/ops/function.rs:227:5";
  test.test_name = "tests::test_bpf_loader_write";
  test.test_nonce  = 10;
  test.test_number = 1591;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113CxUp7XncnNMd4qLYnQvMCsZB9Qvy5UVuaf",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoader2111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc++;
  fd_base58_decode_32( "BPFLoader2111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  static uchar const fd_flamenco_native_prog_test_1591_raw[] = { 0x00,0x00,0x00,0x01,0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x3e,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0xa8,0xf6,0x91,0x4e,0x88,0xa1,0x6e,0x39,0x5a,0xe1,0x28,0x94,0x8f,0xfa,0x69,0x56,0x93,0x37,0x68,0x18,0xdd,0x47,0x43,0x52,0x21,0xf3,0xc6,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x01,0x01,0x00,0x13,0x00,0x00,0x00,0x00,0x03,0x00,0x00,0x00,0x03,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x02,0x03 };
  test.raw_tx = fd_flamenco_native_prog_test_1591_raw;
  test.raw_tx_len = 125UL;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
