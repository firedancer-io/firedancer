#include "../fd_tests.h"
int test_1575(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 77,98,62,2,124,56,117,33,61,111,120,128,106,121,78,82,76,123,118,30,116,27,55,75,122,87,26,103,112,127,89,114,125,83,29,108,79,92,109,113,105,126,80,90,24,15,110 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_upgradeable_write";
  test.test_nonce  = 8;
  test.test_number = 1575;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113CxUp7XncnNMd4qLYnQvMCsZB9Qvy5UVuaf",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1575_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1575_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1575_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1575_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1575_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1575_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1576(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 113,83,82,122,124,123,103,126,112,62,89,128,61,114,92,127,77,121,75,98,30,80,116,76,15,108,118,109,26,27,105,29,33,90,55,87,24,117,79,78,125,106,110,2,111,56,120 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_upgradeable_write";
  test.test_nonce  = 24;
  test.test_number = 1576;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113BM8QB6bTweW7o6nCgjb5GNU2dPuCEYAaKH",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1576_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1576_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1576_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1576_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1576_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1576_raw_sz;
  test.expected_result = -5;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1577(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 113,83,82,122,124,123,103,126,112,62,89,128,61,114,92,127,77,121,75,98,30,80,116,76,15,108,118,109,26,27,105,29,33,90,55,87,24,117,79,78,125,106,110,2,111,56,120 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_upgradeable_write";
  test.test_nonce  = 23;
  test.test_number = 1577;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113CxUp7XncnNMd4qLYnQvMCsZB9Qvy5UVuaf",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1577_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1577_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1577_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1577_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1577_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1577_raw_sz;
  test.expected_result = -5;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1578(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 24,127,83,29,103,2,126,80,106,111,89,114,61,82,108,121,122,120,123,124,90,116,79,78,33,125,62,113,110,112,118,27,128,76,75,77,55,56,109,87,26,105,30,92,15,98,117 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_upgradeable_write";
  test.test_nonce  = 43;
  test.test_number = 1578;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113BM8QB6bTweW7o6nCgjb5GNU2dPuCEYAaKH",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1578_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1578_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1578_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1578_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1578_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1578_raw_sz;
  test.expected_result = -43;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1579(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 24,124,117,116,121,75,55,15,113,90,109,83,105,120,118,108,30,56,103,77,78,127,111,98,61,62,92,80,123,110,112,89,2,126,76,27,114,26,128,87,79,33,122,29,106,125,82 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_upgradeable_write";
  test.test_nonce  = 40;
  test.test_number = 1579;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113BM8QB6bTweW7o6nCgjb5GNU2dPuCEYAaKH",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1579_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1579_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1579_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1579_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113wCy9Vw5sLK1cwLyeMTtp838nENz1j4kNns",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1579_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1579_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1579_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1579_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1579_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1579_raw_sz;
  test.expected_result = -44;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1580(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 126,108,116,124,56,15,120,79,127,33,110,77,29,128,61,78,106,118,82,105,26,117,111,83,121,123,55,92,24,75,98,30,87,112,90,122,62,114,2,125,76,89,27,109,113,103,80 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_upgradeable_write";
  test.test_nonce  = 29;
  test.test_number = 1580;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113BM8QB6bTweW7o6nCgjb5GNU2dPuCEYAaKH",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1580_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1580_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1580_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1580_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1580_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1580_raw_sz;
  test.expected_result = -5;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1581(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 126,108,116,124,56,15,120,79,127,33,110,77,29,128,61,78,106,118,82,105,26,117,111,83,121,123,55,92,24,75,98,30,87,112,90,122,62,114,2,125,76,89,27,109,113,103,80 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_upgradeable_write";
  test.test_nonce  = 27;
  test.test_number = 1581;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113CxUp7XncnNMd4qLYnQvMCsZB9Qvy5UVuaf",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1581_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1581_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1581_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1581_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1581_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1581_raw_sz;
  test.expected_result = -5;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1582(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 126,108,116,124,56,15,120,79,127,33,110,77,29,128,61,78,106,118,82,105,26,117,111,83,121,123,55,92,24,75,98,30,87,112,90,122,62,114,2,125,76,89,27,109,113,103,80 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_upgradeable_write";
  test.test_nonce  = 34;
  test.test_number = 1582;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113CxUp7XncnNMd4qLYnQvMCsZB9Qvy5UVuaf",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1582_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1582_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1582_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1582_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113P1vtjFEpXswXWfpiPuFKL1Mqt2NYrL5jVH",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1582_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1582_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1582_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1582_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1582_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1582_raw_sz;
  test.expected_result = -44;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1583(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 126,108,116,124,56,15,120,79,127,33,110,77,29,128,61,78,106,118,82,105,26,117,111,83,121,123,55,92,24,75,98,30,87,112,90,122,62,114,2,125,76,89,27,109,113,103,80 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_upgradeable_write";
  test.test_nonce  = 36;
  test.test_number = 1583;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113CxUp7XncnNMd4qLYnQvMCsZB9Qvy5UVuaf",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1583_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1583_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1583_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1583_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1583_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1583_raw_sz;
  test.expected_result = -43;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1584(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 120,111,83,127,87,33,128,76,15,77,27,80,110,118,123,116,124,89,103,126,82,29,117,122,61,114,125,112,55,75,56,79,105,113,24,26,98,92,78,108,106,121,62,109,2,90,30 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_upgradeable_write";
  test.test_nonce  = 17;
  test.test_number = 1584;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113BM8QB6bTweW7o6nCgjb5GNU2dPuCEYAaKH",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1584_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1584_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1584_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1584_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1584_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1584_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1585(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 120,111,83,127,87,33,128,76,15,77,27,80,110,118,123,116,124,89,103,126,82,29,117,122,61,114,125,112,55,75,56,79,105,113,24,26,98,92,78,108,106,121,62,109,2,90,30 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_upgradeable_write";
  test.test_nonce  = 17;
  test.test_number = 1585;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113CxUp7XncnNMd4qLYnQvMCsZB9Qvy5UVuaf",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1585_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1585_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1585_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1585_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1585_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1585_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1586(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 108,24,114,61,56,75,126,113,120,123,116,55,106,124,78,90,76,121,2,15,77,29,30,82,89,112,79,105,109,26,118,103,87,110,111,125,98,62,27,117,92,83,128,80,33,122,127 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_write";
  test.test_nonce  = 18;
  test.test_number = 1586;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113CZ9D8RVL5BtkFQCTkzb2ikHPWug2NEv5GK",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoader2111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1586_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1586_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1586_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1586_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoader2111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1586_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1586_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1587(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 128,127,56,111,55,103,33,27,61,121,116,112,15,2,124,120,125,117,87,30,83,118,24,26,80,92,110,76,98,105,78,90,109,126,82,123,89,122,108,62,113,79,75,77,114,29,106 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_write";
  test.test_nonce  = 6;
  test.test_number = 1587;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 0;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_base58_decode_32( "BPFLoader2111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1587_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1587_raw_sz;
  test.expected_result = -20;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1588(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 124,103,26,33,30,113,24,62,128,82,77,79,75,105,108,83,15,56,120,121,80,106,29,89,98,116,90,76,125,111,55,61,78,126,109,87,112,92,123,118,110,117,2,27,114,127,122 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_write";
  test.test_nonce  = 13;
  test.test_number = 1588;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113CZ9D8RVL5BtkFQCTkzb2ikHPWug2NEv5GK",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoader2111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1588_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1588_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1588_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1588_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoader2111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1588_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1588_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1589(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 79,112,75,77,126,89,103,82,108,90,105,80,30,87,120,113,106,24,114,118,33,125,110,55,122,56,62,27,117,111,127,2,83,109,124,76,98,123,121,61,92,78,128,116,15,26,29 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_write";
  test.test_nonce  = 23;
  test.test_number = 1589;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113CZ9D8RVL5BtkFQCTkzb2ikHPWug2NEv5GK",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoader2111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1589_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1589_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1589_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1589_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoader2111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1589_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1589_raw_sz;
  test.expected_result = -5;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1590(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 79,112,75,77,126,89,103,82,108,90,105,80,30,87,120,113,106,24,114,118,33,125,110,55,122,56,62,27,117,111,127,2,83,109,124,76,98,123,121,61,92,78,128,116,15,26,29 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_write";
  test.test_nonce  = 15;
  test.test_number = 1590;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113CZ9D8RVL5BtkFQCTkzb2ikHPWug2NEv5GK",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoader2111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1590_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1590_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1590_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1590_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoader2111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1590_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1590_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1591(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 79,112,75,77,126,89,103,82,108,90,105,80,30,87,120,113,106,24,114,118,33,125,110,55,122,56,62,27,117,111,127,2,83,109,124,76,98,123,121,61,92,78,128,116,15,26,29 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_write";
  test.test_nonce  = 19;
  test.test_number = 1591;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113CZ9D8RVL5BtkFQCTkzb2ikHPWug2NEv5GK",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoader2111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1591_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1591_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1591_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1591_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoader2111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1591_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1591_raw_sz;
  test.expected_result = -5;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1592(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 79,112,75,77,126,89,103,82,108,90,105,80,30,87,120,113,106,24,114,118,33,125,110,55,122,56,62,27,117,111,127,2,83,109,124,76,98,123,121,61,92,78,128,116,15,26,29 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_write";
  test.test_nonce  = 6;
  test.test_number = 1592;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 0;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_base58_decode_32( "BPFLoader2111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1592_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1592_raw_sz;
  test.expected_result = -20;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1593(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 79,112,75,77,126,89,103,82,108,90,105,80,30,87,120,113,106,24,114,118,33,125,110,55,122,56,62,27,117,111,127,2,83,109,124,76,98,123,121,61,92,78,128,116,15,26,29 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_write";
  test.test_nonce  = 9;
  test.test_number = 1593;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113CZ9D8RVL5BtkFQCTkzb2ikHPWug2NEv5GK",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoader2111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1593_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1593_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1593_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1593_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoader2111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1593_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1593_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1594(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 79,112,75,77,126,89,103,82,108,90,105,80,30,87,120,113,106,24,114,118,33,125,110,55,122,56,62,27,117,111,127,2,83,109,124,76,98,123,121,61,92,78,128,116,15,26,29 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_authorize_voter";
  test.test_nonce  = 21;
  test.test_number = 1594;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "3nhrMssWFm5wkVJRtimUX5fa3aZutgnWozUoZ2VzwJuZ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 26858640UL;
  test_acc->result_lamports = 26858640UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1594_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1594_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1594_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1594_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1594_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1594_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1594_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1594_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "5wvxFgkBgkW9Bkx2csoLK5vPG8QFcubJ8aqYev7MiCoa",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1594_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1594_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1594_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1594_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1594_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1594_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1595(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 79,112,75,77,126,89,103,82,108,90,105,80,30,87,120,113,106,24,114,118,33,125,110,55,122,56,62,27,117,111,127,2,83,109,124,76,98,123,121,61,92,78,128,116,15,26,29 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_authorize_voter";
  test.test_nonce  = 31;
  test.test_number = 1595;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "3nhrMssWFm5wkVJRtimUX5fa3aZutgnWozUoZ2VzwJuZ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 26858640UL;
  test_acc->result_lamports = 26858640UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1595_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1595_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1595_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1595_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1595_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1595_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1595_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1595_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "5wvxFgkBgkW9Bkx2csoLK5vPG8QFcubJ8aqYev7MiCoa",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1595_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1595_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1595_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1595_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1595_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1595_raw_sz;
  test.expected_result = -26;
  test.custom_err = 5;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1596(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 79,112,75,77,126,89,103,82,108,90,105,80,30,87,120,113,106,24,114,118,33,125,110,55,122,56,62,27,117,111,127,2,83,109,124,76,98,123,121,61,92,78,128,116,15,26,29 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_authorize_voter";
  test.test_nonce  = 43;
  test.test_number = 1596;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "3nhrMssWFm5wkVJRtimUX5fa3aZutgnWozUoZ2VzwJuZ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 26858640UL;
  test_acc->result_lamports = 26858640UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1596_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1596_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1596_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1596_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1596_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1596_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1596_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1596_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "5wvxFgkBgkW9Bkx2csoLK5vPG8QFcubJ8aqYev7MiCoa",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1596_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1596_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1596_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1596_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1596_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1596_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1597(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 79,112,75,77,126,89,103,82,108,90,105,80,30,87,120,113,106,24,114,118,33,125,110,55,122,56,62,27,117,111,127,2,83,109,124,76,98,123,121,61,92,78,128,116,15,26,29 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_authorize_voter";
  test.test_nonce  = 5;
  test.test_number = 1597;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "3nhrMssWFm5wkVJRtimUX5fa3aZutgnWozUoZ2VzwJuZ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 26858640UL;
  test_acc->result_lamports = 26858640UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1597_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1597_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1597_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1597_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1597_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1597_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1597_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1597_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "5wvxFgkBgkW9Bkx2csoLK5vPG8QFcubJ8aqYev7MiCoa",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1597_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1597_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1597_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1597_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1597_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1597_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1598(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 103,114,15,106,76,29,26,61,121,112,123,75,126,127,80,98,79,78,92,30,108,87,124,83,116,33,90,56,122,128,27,113,125,105,111,118,82,62,89,55,77,2,109,120,117,110,24 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_authorize_voter";
  test.test_nonce  = 20;
  test.test_number = 1598;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "EhRLca7sXhU8VrWuz2Vp7kzKkAavmLEB9gp6mKcwLdrK",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 26858640UL;
  test_acc->result_lamports = 26858640UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1598_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1598_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1598_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1598_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1598_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1598_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1598_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1598_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "AcAbcZeZpoTb7fBes9rjgoBnvpFT8ZNkJvKfq9catgA5",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1598_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1598_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1598_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1598_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1598_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1598_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1599(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 108,103,77,120,15,79,61,76,127,113,114,89,62,126,82,125,121,105,2,118,80,55,75,29,111,33,122,24,83,26,78,27,123,128,110,112,109,124,87,116,106,56,90,117,30,92,98 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_authorize_voter";
  test.test_nonce  = 3;
  test.test_number = 1599;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "EhRLca7sXhU8VrWuz2Vp7kzKkAavmLEB9gp6mKcwLdrK",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 26858640UL;
  test_acc->result_lamports = 26858640UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1599_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1599_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1599_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1599_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1599_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1599_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1599_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1599_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "AcAbcZeZpoTb7fBes9rjgoBnvpFT8ZNkJvKfq9catgA5",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1599_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1599_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1599_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1599_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1599_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1599_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
