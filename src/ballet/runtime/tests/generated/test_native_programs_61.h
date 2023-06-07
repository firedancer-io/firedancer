#include "../fd_tests.h"
int test_1525(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 125,123,27,89,128,90,76,126,75,120,117,114,15,103,121,62,79,127,24,26,112,56,109,113,2,118,33,78,55,87,61,122,124,30,92,111,110,108,98,116,80,77,83,105,29,106,82 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_upgradeable_set_buffer_authority";
  test.test_nonce  = 35;
  test.test_number = 1525;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111137KkNL1caqqsMcmPLSYFtR7kALMKm8CLF9q",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1525_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1525_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1525_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1525_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111135iPxPaRS181rM2pzLrvcUcf1pLHzHFzutT",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "111111367jZNgiiiJUjATy5NHFvxjvoSqYvzVakCo",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1525_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1525_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1525_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1525_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111136X5AMo21RUwbyu7APhbFSsCb5LoshjAaX9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111136vQmLuKJ8fQUoLFFR7vZvzUNhr4pQxkQqV",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1525_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1525_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1525_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1525_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1525_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1525_raw_sz;
  test.expected_result = -43;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1526(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 125,123,27,89,128,90,76,126,75,120,117,114,15,103,121,62,79,127,24,26,112,56,109,113,2,118,33,78,55,87,61,122,124,30,92,111,110,108,98,116,80,77,83,105,29,106,82 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_upgradeable_set_buffer_authority";
  test.test_nonce  = 37;
  test.test_number = 1526;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111137KkNL1caqqsMcmPLSYFtR7kALMKm8CLF9q",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1526_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1526_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1526_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1526_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111135iPxPaRS181rM2pzLrvcUcf1pLHzHFzutT",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "111111367jZNgiiiJUjATy5NHFvxjvoSqYvzVakCo",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1526_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1526_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1526_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1526_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111136X5AMo21RUwbyu7APhbFSsCb5LoshjAaX9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111136vQmLuKJ8fQUoLFFR7vZvzUNhr4pQxkQqV",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1526_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1526_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1526_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1526_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1526_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1526_raw_sz;
  test.expected_result = -2;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1527(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 125,123,27,89,128,90,76,126,75,120,117,114,15,103,121,62,79,127,24,26,112,56,109,113,2,118,33,78,55,87,61,122,124,30,92,111,110,108,98,116,80,77,83,105,29,106,82 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_upgradeable_set_buffer_authority";
  test.test_nonce  = 5;
  test.test_number = 1527;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111137KkNL1caqqsMcmPLSYFtR7kALMKm8CLF9q",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1527_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1527_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1527_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1527_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111135iPxPaRS181rM2pzLrvcUcf1pLHzHFzutT",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "111111367jZNgiiiJUjATy5NHFvxjvoSqYvzVakCo",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1527_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1527_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1527_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1527_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111136X5AMo21RUwbyu7APhbFSsCb5LoshjAaX9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111136vQmLuKJ8fQUoLFFR7vZvzUNhr4pQxkQqV",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1527_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1527_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1527_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1527_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1527_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1527_raw_sz;
  test.expected_result = -44;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1528(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 29,27,124,24,30,92,112,125,33,98,121,90,76,56,103,61,78,62,117,122,26,105,55,89,77,118,111,79,109,113,126,106,75,15,82,123,120,108,127,80,114,110,87,83,2,116,128 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_upgradeable_set_upgrade_authority";
  test.test_nonce  = 38;
  test.test_number = 1528;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "4qqhELqHX6htvCdULVZszNARyyZbPPCuDXb6TxQfdcZ1",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1528_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1528_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1528_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1528_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111136vQmLuKJ8fQUoLFFR7vZvzUNhr4pQxkQqV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111137KkNL1caqqsMcmPLSYFtR7kALMKm8CLF9q",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1528_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1528_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1528_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1528_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1528_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1528_raw_sz;
  test.expected_result = -2;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1529(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 33,90,105,62,128,30,125,111,127,56,87,61,103,108,78,77,126,123,29,117,2,122,118,109,55,120,114,76,83,82,110,112,79,80,89,121,24,75,15,26,106,116,27,92,124,98,113 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_upgradeable_set_upgrade_authority";
  test.test_nonce  = 21;
  test.test_number = 1529;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "4qqhELqHX6htvCdULVZszNARyyZbPPCuDXb6TxQfdcZ1",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1529_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1529_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1529_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1529_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111136vQmLuKJ8fQUoLFFR7vZvzUNhr4pQxkQqV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111137KkNL1caqqsMcmPLSYFtR7kALMKm8CLF9q",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1529_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1529_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1529_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1529_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1529_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1529_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1530(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 109,62,92,127,118,108,89,15,26,117,111,79,2,103,82,78,75,80,113,123,114,124,112,30,90,120,98,87,110,116,61,126,125,55,122,77,83,56,24,76,33,121,106,29,128,27,105 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_upgradeable_set_upgrade_authority";
  test.test_nonce  = 33;
  test.test_number = 1530;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "4qqhELqHX6htvCdULVZszNARyyZbPPCuDXb6TxQfdcZ1",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1530_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1530_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1530_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1530_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111136vQmLuKJ8fQUoLFFR7vZvzUNhr4pQxkQqV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111137KkNL1caqqsMcmPLSYFtR7kALMKm8CLF9q",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1530_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1530_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1530_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1530_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1530_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1530_raw_sz;
  test.expected_result = -43;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1531(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 122,75,2,126,83,78,113,30,82,125,111,110,80,128,112,98,116,90,55,109,15,127,77,26,114,105,29,120,92,27,118,79,106,33,124,121,117,76,123,61,56,108,62,103,24,87,89 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_upgradeable_set_upgrade_authority";
  test.test_nonce  = 7;
  test.test_number = 1531;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "4qqhELqHX6htvCdULVZszNARyyZbPPCuDXb6TxQfdcZ1",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1531_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1531_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1531_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1531_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111136vQmLuKJ8fQUoLFFR7vZvzUNhr4pQxkQqV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111137KkNL1caqqsMcmPLSYFtR7kALMKm8CLF9q",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1531_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1531_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1531_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1531_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111137j5yK7usZ2LESCXRTxbCuF1wxrahqRv5UB",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "111111388RaJEDAGCo7FdfWVNvXPNHjbMqeYfVunX",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1531_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1531_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1531_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1531_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1531_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1531_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1532(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 80,29,118,2,98,121,116,108,90,128,122,110,24,77,55,120,103,27,106,62,112,127,89,113,61,76,126,114,125,117,79,124,123,111,33,92,109,75,83,105,30,82,26,78,87,15,56 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_upgradeable_set_upgrade_authority";
  test.test_nonce  = 15;
  test.test_number = 1532;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "4qqhELqHX6htvCdULVZszNARyyZbPPCuDXb6TxQfdcZ1",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1532_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1532_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1532_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1532_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111136vQmLuKJ8fQUoLFFR7vZvzUNhr4pQxkQqV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111137KkNL1caqqsMcmPLSYFtR7kALMKm8CLF9q",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1532_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1532_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1532_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1532_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1532_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1532_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1533(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 80,15,111,87,56,116,33,75,127,126,114,106,26,61,113,82,98,112,123,2,76,83,89,55,78,90,30,62,79,92,122,103,117,120,27,110,124,24,121,109,29,108,105,77,128,125,118 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_upgradeable_set_upgrade_authority";
  test.test_nonce  = 27;
  test.test_number = 1533;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "4qqhELqHX6htvCdULVZszNARyyZbPPCuDXb6TxQfdcZ1",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1533_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1533_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1533_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1533_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113bVQbFcUkYUJgs79Q9uaCMtoEPfMntbAZHy",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111137KkNL1caqqsMcmPLSYFtR7kALMKm8CLF9q",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1533_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1533_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1533_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1533_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111137j5yK7usZ2LESCXRTxbCuF1wxrahqRv5UB",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "111111388RaJEDAGCo7FdfWVNvXPNHjbMqeYfVunX",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1533_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1533_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1533_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1533_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1533_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1533_raw_sz;
  test.expected_result = -44;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1534(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 80,15,111,87,56,116,33,75,127,126,114,106,26,61,113,82,98,112,123,2,76,83,89,55,78,90,30,62,79,92,122,103,117,120,27,110,124,24,121,109,29,108,105,77,128,125,118 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_upgradeable_set_upgrade_authority";
  test.test_nonce  = 14;
  test.test_number = 1534;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "GucfQSkafkM2sWM92QRzLUoanPuP4C6aaimdqfo9vF3f",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1534_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1534_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1534_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1534_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111388RaJEDAGCo7FdfWVNvXPNHjbMqeYfVunX",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111138XmBHLWSyPFz54obWoFqsVZXDs6bFu5k6s",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1534_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1534_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1534_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1534_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1534_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1534_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1535(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 80,15,111,87,56,116,33,75,127,126,114,106,26,61,113,82,98,112,123,2,76,83,89,55,78,90,30,62,79,92,122,103,117,120,27,110,124,24,121,109,29,108,105,77,128,125,118 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_upgradeable_set_upgrade_authority";
  test.test_nonce  = 18;
  test.test_number = 1535;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "GucfQSkafkM2sWM92QRzLUoanPuP4C6aaimdqfo9vF3f",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1535_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1535_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1535_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1535_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111388RaJEDAGCo7FdfWVNvXPNHjbMqeYfVunX",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111138XmBHLWSyPFz54obWoFqsVZXDs6bFu5k6s",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1535_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1535_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1535_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1535_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1535_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1535_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1536(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 80,15,111,87,56,116,33,75,127,126,114,106,26,61,113,82,98,112,123,2,76,83,89,55,78,90,30,62,79,92,122,103,117,120,27,110,124,24,121,109,29,108,105,77,128,125,118 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_upgradeable_set_upgrade_authority";
  test.test_nonce  = 24;
  test.test_number = 1536;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "GucfQSkafkM2sWM92QRzLUoanPuP4C6aaimdqfo9vF3f",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1536_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1536_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1536_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1536_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113JzYrtAFwS5JmLLRr9hv8Ukdyayo7jzFQKq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111138XmBHLWSyPFz54obWoFqsVZXDs6bFu5k6s",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1536_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1536_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1536_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1536_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111138w6nGSojgZirtVwgYDbAMcqJrNMXy8faRD",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111139LSPFZ72PkBjhw5mZdvUqk76UscUgNFQjZ",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1536_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1536_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1536_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1536_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1536_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1536_raw_sz;
  test.expected_result = -44;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1537(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 80,15,111,87,56,116,33,75,127,126,114,106,26,61,113,82,98,112,123,2,76,83,89,55,78,90,30,62,79,92,122,103,117,120,27,110,124,24,121,109,29,108,105,77,128,125,118 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_upgradeable_set_upgrade_authority";
  test.test_nonce  = 28;
  test.test_number = 1537;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "GucfQSkafkM2sWM92QRzLUoanPuP4C6aaimdqfo9vF3f",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1537_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1537_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1537_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1537_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111388RaJEDAGCo7FdfWVNvXPNHjbMqeYfVunX",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111138XmBHLWSyPFz54obWoFqsVZXDs6bFu5k6s",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1537_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1537_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1537_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1537_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1537_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1537_raw_sz;
  test.expected_result = -43;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1538(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 80,15,111,87,56,116,33,75,127,126,114,106,26,61,113,82,98,112,123,2,76,83,89,55,78,90,30,62,79,92,122,103,117,120,27,110,124,24,121,109,29,108,105,77,128,125,118 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_upgradeable_set_upgrade_authority";
  test.test_nonce  = 33;
  test.test_number = 1538;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "GucfQSkafkM2sWM92QRzLUoanPuP4C6aaimdqfo9vF3f",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1538_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1538_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1538_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1538_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111388RaJEDAGCo7FdfWVNvXPNHjbMqeYfVunX",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111138XmBHLWSyPFz54obWoFqsVZXDs6bFu5k6s",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1538_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1538_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1538_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1538_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1538_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1538_raw_sz;
  test.expected_result = -2;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1539(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 80,15,111,87,56,116,33,75,127,126,114,106,26,61,113,82,98,112,123,2,76,83,89,55,78,90,30,62,79,92,122,103,117,120,27,110,124,24,121,109,29,108,105,77,128,125,118 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_upgradeable_set_upgrade_authority";
  test.test_nonce  = 7;
  test.test_number = 1539;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "GucfQSkafkM2sWM92QRzLUoanPuP4C6aaimdqfo9vF3f",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1539_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1539_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1539_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1539_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111388RaJEDAGCo7FdfWVNvXPNHjbMqeYfVunX",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111138XmBHLWSyPFz54obWoFqsVZXDs6bFu5k6s",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1539_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1539_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1539_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1539_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111138w6nGSojgZirtVwgYDbAMcqJrNMXy8faRD",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111139LSPFZ72PkBjhw5mZdvUqk76UscUgNFQjZ",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1539_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1539_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1539_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1539_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1539_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1539_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1540(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 111,76,55,92,116,33,89,124,103,126,90,105,30,118,87,112,109,128,61,98,114,75,127,121,78,108,77,56,120,83,123,110,27,122,113,82,125,117,80,62,24,26,29,15,106,2,79 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_upgradeable_upgrade";
  test.test_nonce  = 57;
  test.test_number = 1540;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "BnzjFjHHFH6AV7Db2f7m6HKDWbj7FQWRRm3VmQCRDrij",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 17184240UL;
  test_acc->result_lamports = 17184240UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1540_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1540_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1540_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1540_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111115uUxT8mjgyYcTCSaFJcVKqeSCye9udaQxco",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1141440UL;
  test_acc->result_lamports = 1141440UL;
  test_acc->executable      = 1;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1540_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1540_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1540_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1540_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111139jmzEfQK6vecXNDrb4FoKsNt7NsRPbqF3u",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1540_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1540_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1540_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1540_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111115utJ47t2ygj5L1siLL2peKmhzc9QrLoznw9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111115w6Js5CvqpGTxUB8bQHpbn9XMVfBgUWkHtB",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1540_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1540_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1540_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1540_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1540_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1540_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1540_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1540_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1540_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1540_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1540_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1540_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113A97bDmhbp77VLoMwcUb7ozefjt8N6qR5NF",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111115wVeU4KE8XSvqHcGgRi9vGGo98ASdBkL8CX",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1540_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1540_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1540_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1540_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1540_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1540_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1541(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 120,108,112,121,24,77,106,122,29,56,80,61,125,123,116,62,98,82,124,75,103,87,2,79,110,109,127,118,113,114,128,30,78,27,111,76,89,55,83,105,126,117,90,26,15,33,92 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_upgradeable_upgrade";
  test.test_nonce  = 50;
  test.test_number = 1541;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "FYGkp1XGx2TA9Tjm667QvpMQqGMzhotfysSRS9TsY8wu",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 17184240UL;
  test_acc->result_lamports = 17184240UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1541_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1541_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1541_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1541_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111114xkzRE1CWR1bHyVcTyZBytbRDP37cwj5fbu",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1141440UL;
  test_acc->result_lamports = 1141440UL;
  test_acc->executable      = 1;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1541_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1541_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1541_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1541_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111139jmzEfQK6vecXNDrb4FoKsNt7NsRPbqF3u",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1541_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1541_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1541_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1541_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111114yAL2D7Vo8C4AnvkYzyXJNih11YNZexfVvF",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111114yy1EBL6NYYyvRo2j3pBwLyEaGYtT5RqAYw",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1541_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1541_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1541_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1541_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1541_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1541_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1541_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1541_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1541_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1541_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1541_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1541_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113A97bDmhbp77VLoMwcUb7ozefjt8N6qR5NF",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111114zNLqASPfFjSoFEAp5EXFq6WMu49PnfQzsH",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1541_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1541_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1541_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1541_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1541_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1541_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1542(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 110,120,127,87,83,29,116,77,80,82,33,76,106,78,125,79,111,124,56,108,90,15,128,27,112,113,75,2,123,118,98,121,114,105,109,62,55,26,30,89,92,122,103,61,117,126,24 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_upgradeable_upgrade";
  test.test_nonce  = 8;
  test.test_number = 1542;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "F9Jf8qGVpc4sV8n8kTbzLBUo4cBwiQGccXPpNk9RJfBB",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 17184240UL;
  test_acc->result_lamports = 17184240UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1542_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1542_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1542_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1542_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113AYTCCsztXHaNAEW2dtvSJ7vTNPPJp4zugb",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1141440UL;
  test_acc->result_lamports = 1141440UL;
  test_acc->executable      = 1;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1542_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1542_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1542_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1542_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111139jmzEfQK6vecXNDrb4FoKsNt7NsRPbqF3u",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1542_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1542_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1542_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1542_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113AwnoBzJBEU3Eyfe7fKFknFCEzteFXJajzw",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111113CxUp7XncnNMd4qLYnQvMCsZB9Qvy5UVuaf",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1542_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1542_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1542_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1542_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1542_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1542_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1542_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1542_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1542_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1542_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1542_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1542_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113A97bDmhbp77VLoMwcUb7ozefjt8N6qR5NF",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111113DMpR6e5uVYpVtGUdoqFfgzpxmvBuni5ju1",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1542_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1542_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1542_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1542_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1542_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1542_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1543(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 108,116,109,75,77,90,26,15,87,117,127,61,62,27,76,114,30,106,110,105,118,33,24,122,124,56,120,112,89,103,123,29,55,79,125,78,80,83,126,111,2,98,82,128,121,92,113 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_upgradeable_upgrade";
  test.test_nonce  = 55;
  test.test_number = 1543;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "5wQiZwjtaJzwXMf5gnyebqx7Pgmh9dcV9je6f1nLgdBr",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 17184240UL;
  test_acc->result_lamports = 17184240UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1543_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1543_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1543_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1543_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111115gCoYeBuBYbKYD8yPVmVoqWTFCzenArAUBR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1141440UL;
  test_acc->result_lamports = 1141440UL;
  test_acc->executable      = 1;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1543_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1543_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1543_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1543_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111139jmzEfQK6vecXNDrb4FoKsNt7NsRPbqF3u",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1543_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1543_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1543_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1543_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111115gc99dJCUFmnR2a7UXBq8Kdj2qVuit5kJVm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111115hQpMbWo3g8iAfSPea2VmHtGc6WRcJYuy8T",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1543_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1543_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1543_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1543_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1543_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1543_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1543_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1543_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1543_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1543_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1543_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1543_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113A97bDmhbp77VLoMwcUb7ozefjt8N6qR5NF",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111115hp9xad6LPKB3UsXjbSq5n1YPj1gZ1nVoSo",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1543_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1543_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1543_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1543_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1543_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1543_raw_sz;
  test.expected_result = -5;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1544(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 108,77,56,125,75,123,29,112,61,98,2,116,62,30,128,106,90,117,76,55,114,110,79,89,109,113,105,111,122,15,83,124,127,24,103,78,87,26,27,92,118,33,80,82,121,120,126 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_upgradeable_upgrade";
  test.test_nonce  = 22;
  test.test_number = 1544;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "BHhZhV13zRcBnHDAf3AgVxfu56sC5NT2Ndg6XxDDYSwz",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 17184240UL;
  test_acc->result_lamports = 17184240UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1544_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1544_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1544_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1544_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113WG1kTCc1K8HJEULGqTF44GG1D71XeYajBV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1141440UL;
  test_acc->result_lamports = 1141440UL;
  test_acc->executable      = 1;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1544_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1544_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1544_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1544_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111139jmzEfQK6vecXNDrb4FoKsNt7NsRPbqF3u",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1544_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1544_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1544_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1544_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113WfMMSJuJ2JkB3uUMrsaNYPXnqcGUMnAZVq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111113XU2ZQXVsSffvgmkXuiF1We5N6cnMnFLE8X",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1544_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1544_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1544_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1544_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1544_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1544_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1544_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1544_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1544_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1544_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1544_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1544_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113A97bDmhbp77VLoMwcUb7ozefjt8N6qR5NF",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111113YGhmNk6Ss2bgKe2hxYueUtcwMdJFCiVtmD",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1544_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1544_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1544_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1544_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1544_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1544_raw_sz;
  test.expected_result = -43;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1545(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 26,75,122,92,117,120,80,106,82,27,33,15,76,56,112,108,29,113,78,30,79,128,55,125,105,111,98,124,110,2,116,123,127,126,114,89,109,24,62,61,77,103,118,121,83,90,87 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_upgradeable_upgrade";
  test.test_nonce  = 35;
  test.test_number = 1545;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "258oEiVNkhdqawdhyEzZzaiLT5pmTy2nkEgWRz4CD4Wd",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 17184240UL;
  test_acc->result_lamports = 17184240UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1545_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1545_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1545_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1545_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113m9X4tDdfaoRiVWVUjyZqzuL7VmYRxDAYtF",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1141440UL;
  test_acc->result_lamports = 1141440UL;
  test_acc->executable      = 1;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1545_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1545_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1545_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1545_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111139jmzEfQK6vecXNDrb4FoKsNt7NsRPbqF3u",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1545_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1545_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1545_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1545_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113mYrfsKvxHytbJwdZmPuAV2bu8GoNfSkPCb",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111113mxCGrSEF1AMU8NmenpEUy9sgkn4KNgLDWw",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1545_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1545_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1545_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1545_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1545_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1545_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1545_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1545_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1545_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1545_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1545_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1545_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113nksUpeppRXHDmF3pqeu7wQRG1naCo9Vt9d",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111113nMXsqYXXiLpLwoujpEZoTH9UPHKG5uv3qH",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1545_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1545_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1545_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1545_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1545_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1545_raw_sz;
  test.expected_result = -44;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1546(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 33,116,114,111,24,121,61,55,120,15,103,56,109,128,78,110,30,127,106,62,90,87,92,98,27,125,112,77,105,118,2,108,124,26,83,123,29,80,113,89,117,126,75,79,82,76,122 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_upgradeable_upgrade";
  test.test_nonce  = 60;
  test.test_number = 1546;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "93orAj3xFnCbKNwy1hjJs6wXCrPfKJESwASYYXQrWGsy",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 17184240UL;
  test_acc->result_lamports = 17184240UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1546_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1546_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1546_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1546_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111116bKRAcXFDGQVCAMNpj9Tsr4P6HafJ1mARvw",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1141440UL;
  test_acc->result_lamports = 1141440UL;
  test_acc->executable      = 1;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1546_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1546_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1546_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1546_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111139jmzEfQK6vecXNDrb4FoKsNt7NsRPbqF3u",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1546_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1546_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1546_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1546_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111116bikmbdYVyax4ynWukZoCLBesv5vEizkGFH",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111116c86NajqngmQwoDezmz8WpJvfYbBBSEL6Zd",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1546_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1546_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1546_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1546_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1546_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1546_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1546_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1546_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1546_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1546_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1546_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1546_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113A97bDmhbp77VLoMwcUb7ozefjt8N6qR5NF",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111116cvmaYxSN78LhS5wAppo9nZUEobh4rhVmCK",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1546_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1546_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1546_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1546_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1546_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1546_raw_sz;
  test.expected_result = -44;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1547(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 121,123,29,82,112,92,111,128,90,114,26,61,62,89,98,56,127,75,80,30,110,2,124,79,77,125,126,24,87,76,15,27,108,117,120,103,83,106,122,105,78,116,113,33,118,55,109 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_upgradeable_upgrade";
  test.test_nonce  = 53;
  test.test_number = 1547;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "DR7AytqL1JfbjNs56i1AHW7B94GbocPGjzRzAhpF6p5c",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 17184240UL;
  test_acc->result_lamports = 17184240UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1547_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1547_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1547_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1547_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111115TjKr7pfFXzxNrhehjmAvod1rhMfY8b5eNj",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1141440UL;
  test_acc->result_lamports = 1141440UL;
  test_acc->executable      = 1;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1547_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1547_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1547_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1547_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111139jmzEfQK6vecXNDrb4FoKsNt7NsRPbqF3u",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1547_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1547_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1547_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1547_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111115U8fT6vxYFBRFg8nnmBWFHkHeKrvUqpfUh5",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111115UY1463FpxMt8VZvsnbqZmsZRxNBRZ4FK1R",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1547_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1547_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1547_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1547_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1547_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1547_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1547_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1547_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1547_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1547_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1547_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1547_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113A97bDmhbp77VLoMwcUb7ozefjt8N6qR5NF",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111115UwLf59Z7fYM1K14xp2AtFzqDasSNGHq9Km",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1547_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1547_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1547_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1547_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1547_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1547_raw_sz;
  test.expected_result = -2;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1548(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 114,127,56,120,82,118,79,89,2,116,76,117,55,29,15,105,77,78,26,121,126,110,24,106,124,83,113,80,122,103,125,90,111,92,75,109,112,87,27,123,98,108,62,30,33,128,61 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_upgradeable_upgrade";
  test.test_nonce  = 47;
  test.test_number = 1548;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "Gwsvvq8JPdjAoxBjxEKsHcq7dXjKmR5jKJyfpKY5FqR2",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 17184240UL;
  test_acc->result_lamports = 17184240UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1548_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1548_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1548_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1548_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111114Wc2DDwpnGHULpKYqPHYGNSj5UFNJjWAX3V",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111114YDNdAP1w71Kr647BUxsYJwpDzGQ5aSVrJs",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1141440UL;
  test_acc->result_lamports = 1141440UL;
  test_acc->executable      = 1;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1548_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1548_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1548_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1548_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111139jmzEfQK6vecXNDrb4FoKsNt7NsRPbqF3u",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1548_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1548_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1548_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1548_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111114X1MpD484yTwDdkgvQhsarZzs6kdFSjkMMq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111114XQhRCARMgeQ6TBq1S8CuLhGejFtC9yLBgB",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1548_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1548_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1548_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1548_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1548_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1548_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1548_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1548_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1548_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1548_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1548_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1548_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113A97bDmhbp77VLoMwcUb7ozefjt8N6qR5NF",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111114Xp32BGiePpryGcy6TYYDppYSMm98sCv1zX",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1548_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1548_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1548_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1548_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1548_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1548_raw_sz;
  test.expected_result = -7;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1549(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 109,92,33,15,82,105,106,55,127,126,29,124,113,62,61,116,83,114,75,78,121,27,125,117,122,56,30,98,108,123,128,90,24,103,2,76,112,87,120,26,89,110,79,118,80,111,77 };
  test.disable_feature = disabled_features;
  test.test_name = "tests::test_bpf_loader_upgradeable_upgrade";
  test.test_nonce  = 59;
  test.test_number = 1549;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "dE2Y1iYiuQojiEkoiyxvchyMPFtDES2kH3UvSL3Bxoc",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 17184240UL;
  test_acc->result_lamports = 17184240UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1549_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1549_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1549_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1549_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111116NqwU6A1HFp82ov48y98zpAwhmwg3yW5c8F",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1141440UL;
  test_acc->result_lamports = 1141440UL;
  test_acc->executable      = 1;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1549_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1549_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1549_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1549_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111139jmzEfQK6vecXNDrb4FoKsNt7NsRPbqF3u",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1549_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1549_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1549_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1549_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111116PFH55GJZxzaudMCDzZUKJJDVQSvzgjfSSb",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111116Q3xH3Uu9PMWfGDUQ3Q8xGYm4fTSt7Cq75H",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1549_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1549_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1549_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1549_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1549_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1549_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1549_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1549_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1549_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1549_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1549_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1549_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113A97bDmhbp77VLoMwcUb7ozefjt8N6qR5NF",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111116QTHt2bCS6XyY5ecV4pUGkg2rHxhppSQwPd",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1549_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1549_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1549_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1549_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1549_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1549_raw_sz;
  test.expected_result = -44;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
