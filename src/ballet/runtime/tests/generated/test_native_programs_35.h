#include "../fd_tests.h"
int test_875(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 27,121,123,24,126,111,80,109,124,90,92,77,30,56,83,79,78,113,125,2,118,75,87,26,89,106,105,116,110,120,108,62,82,117,29,122,15,127,128,76,55,33,114,103,61,112,98 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_to_account_with_rent_exempt_reserve::old_behavior";
  test.test_nonce  = 332;
  test.test_number = 875;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "9GL4NbsVF4Awba2CSnbtUicfGZdgaWWU1CHba2VuDh9s",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565762UL;
  test_acc->result_lamports = 4565762UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_875_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_875_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_875_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_875_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "cfbLU4D6kkFVDumFJ35SGLfaYQjbcL4LxA1nuszGLsv",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282881UL;
  test_acc->result_lamports = 2282881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_875_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_875_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_875_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_875_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_875_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_875_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_875_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_875_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_875_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_875_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_876(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 27,121,123,24,126,111,80,109,124,90,92,77,30,56,83,79,78,113,125,2,118,75,87,26,89,106,105,116,110,120,108,62,82,117,29,122,15,127,128,76,55,33,114,103,61,112,98 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_to_account_with_rent_exempt_reserve::old_behavior";
  test.test_nonce  = 83;
  test.test_number = 876;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "9GL4NbsVF4Awba2CSnbtUicfGZdgaWWU1CHba2VuDh9s",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565762UL;
  test_acc->result_lamports = 4565762UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_876_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_876_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_876_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_876_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "cfbLU4D6kkFVDumFJ35SGLfaYQjbcL4LxA1nuszGLsv",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_876_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_876_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_876_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_876_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_876_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_876_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_876_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_876_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_876_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_876_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_877(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_to_account_with_rent_exempt_reserve::old_behavior";
  test.test_nonce  = 137;
  test.test_number = 877;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "6r7fKmhv5tMUK6mpis4zfpVXm7GR1agRay8abznFeJHK",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565762UL;
  test_acc->result_lamports = 4565762UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_877_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_877_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_877_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_877_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FgvX5XeawTTCytH6F8p9vG7bSmABWGZrfmnerfHjKHXG",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_877_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_877_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_877_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_877_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_877_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_877_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_877_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_877_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_877_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_877_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_878(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_to_account_with_rent_exempt_reserve::old_behavior";
  test.test_nonce  = 167;
  test.test_number = 878;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "6r7fKmhv5tMUK6mpis4zfpVXm7GR1agRay8abznFeJHK",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565762UL;
  test_acc->result_lamports = 4565762UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_878_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_878_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_878_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_878_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FgvX5XeawTTCytH6F8p9vG7bSmABWGZrfmnerfHjKHXG",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282879UL;
  test_acc->result_lamports = 2282879UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_878_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_878_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_878_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_878_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_878_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_878_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_878_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_878_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_878_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_878_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_879(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_to_account_with_rent_exempt_reserve::old_behavior";
  test.test_nonce  = 221;
  test.test_number = 879;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "6r7fKmhv5tMUK6mpis4zfpVXm7GR1agRay8abznFeJHK",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565762UL;
  test_acc->result_lamports = 4565762UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_879_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_879_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_879_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_879_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FgvX5XeawTTCytH6F8p9vG7bSmABWGZrfmnerfHjKHXG",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_879_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_879_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_879_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_879_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_879_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_879_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_879_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_879_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_879_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_879_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_880(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_to_account_with_rent_exempt_reserve::old_behavior";
  test.test_nonce  = 267;
  test.test_number = 880;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "6r7fKmhv5tMUK6mpis4zfpVXm7GR1agRay8abznFeJHK",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565762UL;
  test_acc->result_lamports = 4565762UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_880_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_880_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_880_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_880_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FgvX5XeawTTCytH6F8p9vG7bSmABWGZrfmnerfHjKHXG",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_880_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_880_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_880_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_880_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_880_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_880_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_880_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_880_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_880_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_880_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_881(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_to_account_with_rent_exempt_reserve::old_behavior";
  test.test_nonce  = 304;
  test.test_number = 881;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "6r7fKmhv5tMUK6mpis4zfpVXm7GR1agRay8abznFeJHK",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565762UL;
  test_acc->result_lamports = 4565762UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_881_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_881_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_881_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_881_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FgvX5XeawTTCytH6F8p9vG7bSmABWGZrfmnerfHjKHXG",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282881UL;
  test_acc->result_lamports = 2282881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_881_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_881_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_881_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_881_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_881_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_881_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_881_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_881_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_881_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_881_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_882(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 27,121,123,24,126,111,80,109,124,90,92,77,30,56,83,79,78,113,125,2,118,75,87,26,89,106,105,116,110,120,108,62,82,117,29,122,15,127,128,76,55,33,114,103,61,112,98 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_to_account_with_rent_exempt_reserve::old_behavior";
  test.test_nonce  = 137;
  test.test_number = 882;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "9GL4NbsVF4Awba2CSnbtUicfGZdgaWWU1CHba2VuDh9s",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565762UL;
  test_acc->result_lamports = 2282881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_882_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_882_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_882_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_882_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "cfbLU4D6kkFVDumFJ35SGLfaYQjbcL4LxA1nuszGLsv",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 2282881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_882_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_882_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_882_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_882_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_882_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_882_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_882_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_882_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_882_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_882_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_883(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 27,121,123,24,126,111,80,109,124,90,92,77,30,56,83,79,78,113,125,2,118,75,87,26,89,106,105,116,110,120,108,62,82,117,29,122,15,127,128,76,55,33,114,103,61,112,98 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_to_account_with_rent_exempt_reserve::old_behavior";
  test.test_nonce  = 203;
  test.test_number = 883;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "9GL4NbsVF4Awba2CSnbtUicfGZdgaWWU1CHba2VuDh9s",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565762UL;
  test_acc->result_lamports = 2282881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_883_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_883_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_883_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_883_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "cfbLU4D6kkFVDumFJ35SGLfaYQjbcL4LxA1nuszGLsv",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282879UL;
  test_acc->result_lamports = 4565760UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_883_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_883_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_883_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_883_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_883_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_883_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_883_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_883_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_883_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_883_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_884(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 27,121,123,24,126,111,80,109,124,90,92,77,30,56,83,79,78,113,125,2,118,75,87,26,89,106,105,116,110,120,108,62,82,117,29,122,15,127,128,76,55,33,114,103,61,112,98 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_to_account_with_rent_exempt_reserve::old_behavior";
  test.test_nonce  = 269;
  test.test_number = 884;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "9GL4NbsVF4Awba2CSnbtUicfGZdgaWWU1CHba2VuDh9s",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565762UL;
  test_acc->result_lamports = 2282881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_884_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_884_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_884_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_884_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "cfbLU4D6kkFVDumFJ35SGLfaYQjbcL4LxA1nuszGLsv",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 4565761UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_884_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_884_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_884_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_884_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_884_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_884_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_884_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_884_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_884_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_884_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_885(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 27,121,123,24,126,111,80,109,124,90,92,77,30,56,83,79,78,113,125,2,118,75,87,26,89,106,105,116,110,120,108,62,82,117,29,122,15,127,128,76,55,33,114,103,61,112,98 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_to_account_with_rent_exempt_reserve::old_behavior";
  test.test_nonce  = 314;
  test.test_number = 885;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "9GL4NbsVF4Awba2CSnbtUicfGZdgaWWU1CHba2VuDh9s",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565762UL;
  test_acc->result_lamports = 2282881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_885_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_885_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_885_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_885_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "cfbLU4D6kkFVDumFJ35SGLfaYQjbcL4LxA1nuszGLsv",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 4565761UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_885_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_885_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_885_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_885_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_885_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_885_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_885_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_885_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_885_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_885_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_886(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 27,121,123,24,126,111,80,109,124,90,92,77,30,56,83,79,78,113,125,2,118,75,87,26,89,106,105,116,110,120,108,62,82,117,29,122,15,127,128,76,55,33,114,103,61,112,98 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_to_account_with_rent_exempt_reserve::old_behavior";
  test.test_nonce  = 348;
  test.test_number = 886;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "9GL4NbsVF4Awba2CSnbtUicfGZdgaWWU1CHba2VuDh9s",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565762UL;
  test_acc->result_lamports = 2282881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_886_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_886_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_886_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_886_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "cfbLU4D6kkFVDumFJ35SGLfaYQjbcL4LxA1nuszGLsv",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282881UL;
  test_acc->result_lamports = 4565762UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_886_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_886_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_886_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_886_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_886_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_886_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_886_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_886_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_886_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_886_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_887(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_to_account_with_rent_exempt_reserve::old_behavior";
  test.test_nonce  = 151;
  test.test_number = 887;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "6r7fKmhv5tMUK6mpis4zfpVXm7GR1agRay8abznFeJHK",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565762UL;
  test_acc->result_lamports = 2282881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_887_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_887_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_887_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_887_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FgvX5XeawTTCytH6F8p9vG7bSmABWGZrfmnerfHjKHXG",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 2282881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_887_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_887_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_887_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_887_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_887_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_887_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_887_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_887_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_887_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_887_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_888(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_to_account_with_rent_exempt_reserve::old_behavior";
  test.test_nonce  = 187;
  test.test_number = 888;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "6r7fKmhv5tMUK6mpis4zfpVXm7GR1agRay8abznFeJHK",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565762UL;
  test_acc->result_lamports = 2282881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_888_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_888_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_888_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_888_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FgvX5XeawTTCytH6F8p9vG7bSmABWGZrfmnerfHjKHXG",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282879UL;
  test_acc->result_lamports = 4565760UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_888_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_888_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_888_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_888_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_888_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_888_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_888_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_888_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_888_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_888_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_889(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_to_account_with_rent_exempt_reserve::old_behavior";
  test.test_nonce  = 252;
  test.test_number = 889;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "6r7fKmhv5tMUK6mpis4zfpVXm7GR1agRay8abznFeJHK",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565762UL;
  test_acc->result_lamports = 2282881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_889_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_889_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_889_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_889_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FgvX5XeawTTCytH6F8p9vG7bSmABWGZrfmnerfHjKHXG",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 4565761UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_889_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_889_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_889_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_889_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_889_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_889_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_889_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_889_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_889_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_889_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_890(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_to_account_with_rent_exempt_reserve::old_behavior";
  test.test_nonce  = 287;
  test.test_number = 890;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "6r7fKmhv5tMUK6mpis4zfpVXm7GR1agRay8abznFeJHK",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565762UL;
  test_acc->result_lamports = 2282881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_890_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_890_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_890_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_890_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FgvX5XeawTTCytH6F8p9vG7bSmABWGZrfmnerfHjKHXG",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 4565761UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_890_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_890_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_890_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_890_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_890_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_890_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_890_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_890_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_890_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_890_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_891(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_to_account_with_rent_exempt_reserve::old_behavior";
  test.test_nonce  = 308;
  test.test_number = 891;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "6r7fKmhv5tMUK6mpis4zfpVXm7GR1agRay8abznFeJHK",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565762UL;
  test_acc->result_lamports = 2282881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_891_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_891_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_891_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_891_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FgvX5XeawTTCytH6F8p9vG7bSmABWGZrfmnerfHjKHXG",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282881UL;
  test_acc->result_lamports = 4565762UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_891_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_891_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_891_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_891_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_891_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_891_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_891_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_891_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_891_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_891_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_892(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 126,118,121,61,82,109,125,128,89,79,112,105,124,103,62,108,98,76,24,78,80,77,111,75,87,26,15,83,27,120,2,127,114,116,113,123,90,55,30,106,122,117,110,33,56,29,92 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_with_rent::new_behavior";
  test.test_nonce  = 199;
  test.test_number = 892;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "6r4jQfE9eoKkSqs8Ct7qVn6SwRVu8tL1uqTgFbt7vks5",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2004565760UL;
  test_acc->result_lamports = 1002282881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_892_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_892_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_892_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_892_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FuwyCFMbYTVQmX1ohcWcZrnBdQUtR6Znwjm4FULjrWYT",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 1002282879UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_892_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_892_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_892_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_892_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_892_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_892_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_892_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_892_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_892_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_892_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_893(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 126,118,121,61,82,109,125,128,89,79,112,105,124,103,62,108,98,76,24,78,80,77,111,75,87,26,15,83,27,120,2,127,114,116,113,123,90,55,30,106,122,117,110,33,56,29,92 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_with_rent::new_behavior";
  test.test_nonce  = 273;
  test.test_number = 893;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "ArCxhTFRmHDrtkiAhHwHz1oXt7eCW3ZasgzJCyCR9Ee8",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2004565760UL;
  test_acc->result_lamports = 2004565760UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_893_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_893_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_893_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_893_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "5jfpEmx62h5VcaZwcuDE3jjNnQ9NCYMbB2yPW7aYGuj",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_893_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_893_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_893_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_893_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_893_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_893_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_893_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_893_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_893_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_893_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_894(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 126,118,121,61,82,109,125,128,89,79,112,105,124,103,62,108,98,76,24,78,80,77,111,75,87,26,15,83,27,120,2,127,114,116,113,123,90,55,30,106,122,117,110,33,56,29,92 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_with_rent::new_behavior";
  test.test_nonce  = 109;
  test.test_number = 894;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "6r4jQfE9eoKkSqs8Ct7qVn6SwRVu8tL1uqTgFbt7vks5",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565760UL;
  test_acc->result_lamports = 4565760UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_894_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_894_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_894_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_894_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FuwyCFMbYTVQmX1ohcWcZrnBdQUtR6Znwjm4FULjrWYT",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_894_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_894_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_894_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_894_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_894_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_894_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_894_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_894_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_894_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_894_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_895(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 126,118,121,61,82,109,125,128,89,79,112,105,124,103,62,108,98,76,24,78,80,77,111,75,87,26,15,83,27,120,2,127,114,116,113,123,90,55,30,106,122,117,110,33,56,29,92 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_with_rent::new_behavior";
  test.test_nonce  = 183;
  test.test_number = 895;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "ArCxhTFRmHDrtkiAhHwHz1oXt7eCW3ZasgzJCyCR9Ee8",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565760UL;
  test_acc->result_lamports = 4565760UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_895_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_895_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_895_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_895_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "5jfpEmx62h5VcaZwcuDE3jjNnQ9NCYMbB2yPW7aYGuj",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_895_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_895_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_895_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_895_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_895_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_895_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_895_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_895_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_895_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_895_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_896(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 126,118,121,61,82,109,125,128,89,79,112,105,124,103,62,108,98,76,24,78,80,77,111,75,87,26,15,83,27,120,2,127,114,116,113,123,90,55,30,106,122,117,110,33,56,29,92 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_with_rent::new_behavior";
  test.test_nonce  = 242;
  test.test_number = 896;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "6r4jQfE9eoKkSqs8Ct7qVn6SwRVu8tL1uqTgFbt7vks5",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2004565760UL;
  test_acc->result_lamports = 1002282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_896_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_896_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_896_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_896_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FuwyCFMbYTVQmX1ohcWcZrnBdQUtR6Znwjm4FULjrWYT",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1002282880UL;
  test_acc->result_lamports = 2004565760UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_896_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_896_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_896_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_896_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_896_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_896_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_896_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_896_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_896_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_896_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_897(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 126,118,121,61,82,109,125,128,89,79,112,105,124,103,62,108,98,76,24,78,80,77,111,75,87,26,15,83,27,120,2,127,114,116,113,123,90,55,30,106,122,117,110,33,56,29,92 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_with_rent::new_behavior";
  test.test_nonce  = 315;
  test.test_number = 897;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "ArCxhTFRmHDrtkiAhHwHz1oXt7eCW3ZasgzJCyCR9Ee8",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2004565760UL;
  test_acc->result_lamports = 1002282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_897_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_897_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_897_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_897_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "5jfpEmx62h5VcaZwcuDE3jjNnQ9NCYMbB2yPW7aYGuj",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1002282880UL;
  test_acc->result_lamports = 2004565760UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_897_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_897_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_897_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_897_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_897_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_897_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_897_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_897_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_897_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_897_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_898(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 126,118,121,61,82,109,125,128,89,79,112,105,124,103,62,108,98,76,24,78,80,77,111,75,87,26,15,83,27,120,2,127,114,116,113,123,90,55,30,106,122,117,110,33,56,29,92 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_with_rent::new_behavior";
  test.test_nonce  = 168;
  test.test_number = 898;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "6r4jQfE9eoKkSqs8Ct7qVn6SwRVu8tL1uqTgFbt7vks5",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565760UL;
  test_acc->result_lamports = 4565760UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_898_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_898_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_898_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_898_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FuwyCFMbYTVQmX1ohcWcZrnBdQUtR6Znwjm4FULjrWYT",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_898_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_898_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_898_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_898_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_898_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_898_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_898_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_898_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_898_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_898_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_899(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 126,118,121,61,82,109,125,128,89,79,112,105,124,103,62,108,98,76,24,78,80,77,111,75,87,26,15,83,27,120,2,127,114,116,113,123,90,55,30,106,122,117,110,33,56,29,92 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_with_rent::new_behavior";
  test.test_nonce  = 216;
  test.test_number = 899;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "ArCxhTFRmHDrtkiAhHwHz1oXt7eCW3ZasgzJCyCR9Ee8",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565760UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_899_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_899_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_899_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_899_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "5jfpEmx62h5VcaZwcuDE3jjNnQ9NCYMbB2yPW7aYGuj",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 4565760UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_899_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_899_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_899_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_899_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_899_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_899_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_899_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_899_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_899_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_899_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
