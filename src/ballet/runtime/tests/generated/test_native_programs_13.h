#include "../fd_tests.h"
int test_325(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 83,108,78,79,128,61,117,124,33,116,114,111,121,62,27,98,126,82,112,90,75,24,92,2,55,120,106,76,122,109,80,105,127,56,87,26,123,118,125,15,77,103,29,89,30,110,113 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_active_stake::new_behavior";
  test.test_nonce  = 643;
  test.test_number = 325;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "HPupyEHGx5obkcTGAWxMkUm1wEBU7GNjXZYVmy2C84mn",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_325_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_325_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_325_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_325_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "97jUK7hiGqWE5H7daG8jAV3JJ2fVbKpm4zgnMKcawQsp",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_325_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_325_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_325_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_325_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FrMtC7PDULT3T41NMjLKB19XECXcM5wyMidxqy6mHojo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_325_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_325_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_325_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_325_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_325_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_325_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_325_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_325_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_325_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_325_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_325_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_325_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_325_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_325_raw_sz;
  test.expected_result = -26;
  test.custom_err = 5;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_326(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 83,108,78,79,128,61,117,124,33,116,114,111,121,62,27,98,126,82,112,90,75,24,92,2,55,120,106,76,122,109,80,105,127,56,87,26,123,118,125,15,77,103,29,89,30,110,113 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_active_stake::new_behavior";
  test.test_nonce  = 645;
  test.test_number = 326;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "HPupyEHGx5obkcTGAWxMkUm1wEBU7GNjXZYVmy2C84mn",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 8489414244UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_326_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_326_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_326_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_326_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "97jUK7hiGqWE5H7daG8jAV3JJ2fVbKpm4zgnMKcawQsp",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_326_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_326_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_326_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_326_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FrMtC7PDULT3T41NMjLKB19XECXcM5wyMidxqy6mHojo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_326_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_326_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_326_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_326_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_326_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_326_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_326_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_326_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_326_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_326_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_326_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_326_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_326_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_326_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_327(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 83,108,78,79,128,61,117,124,33,116,114,111,121,62,27,98,126,82,112,90,75,24,92,2,55,120,106,76,122,109,80,105,127,56,87,26,123,118,125,15,77,103,29,89,30,110,113 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_active_stake::new_behavior";
  test.test_nonce  = 647;
  test.test_number = 327;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "HPupyEHGx5obkcTGAWxMkUm1wEBU7GNjXZYVmy2C84mn",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_327_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_327_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_327_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_327_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "97jUK7hiGqWE5H7daG8jAV3JJ2fVbKpm4zgnMKcawQsp",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 8489414244UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_327_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_327_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_327_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_327_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FrMtC7PDULT3T41NMjLKB19XECXcM5wyMidxqy6mHojo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_327_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_327_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_327_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_327_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_327_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_327_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_327_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_327_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_327_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_327_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_327_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_327_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_327_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_327_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_328(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_active_stake::old_behavior";
  test.test_nonce  = 23;
  test.test_number = 328;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "36vMEM8PRCBd8iURUSgGB5HS6tGTJXi3icVKKLmdJcWy",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 8489414244UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_328_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_328_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_328_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_328_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "E19CCepTp4rdjj3Am81NBFouFSchgjvXZFuY1rpXeu5t",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_328_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_328_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_328_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_328_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "ABv85b6EYyLPQk7eaBsJRJvrxYvNBegiC1EPtssG4ofQ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_328_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_328_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_328_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_328_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_328_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_328_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_328_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_328_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_328_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_328_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_328_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_328_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_328_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_328_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_329(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_active_stake::old_behavior";
  test.test_nonce  = 303;
  test.test_number = 329;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "36vMEM8PRCBd8iURUSgGB5HS6tGTJXi3icVKKLmdJcWy",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_329_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_329_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_329_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_329_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "E19CCepTp4rdjj3Am81NBFouFSchgjvXZFuY1rpXeu5t",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 8489414244UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_329_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_329_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_329_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_329_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "ABv85b6EYyLPQk7eaBsJRJvrxYvNBegiC1EPtssG4ofQ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_329_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_329_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_329_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_329_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_329_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_329_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_329_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_329_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_329_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_329_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_329_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_329_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_329_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_329_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_330(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_active_stake::old_behavior";
  test.test_nonce  = 377;
  test.test_number = 330;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "36vMEM8PRCBd8iURUSgGB5HS6tGTJXi3icVKKLmdJcWy",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_330_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_330_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_330_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_330_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "E19CCepTp4rdjj3Am81NBFouFSchgjvXZFuY1rpXeu5t",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_330_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_330_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_330_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_330_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "ABv85b6EYyLPQk7eaBsJRJvrxYvNBegiC1EPtssG4ofQ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_330_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_330_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_330_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_330_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_330_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_330_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_330_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_330_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_330_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_330_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_330_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_330_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_330_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_330_raw_sz;
  test.expected_result = -26;
  test.custom_err = 5;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_331(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_active_stake::old_behavior";
  test.test_nonce  = 443;
  test.test_number = 331;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "36vMEM8PRCBd8iURUSgGB5HS6tGTJXi3icVKKLmdJcWy",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_331_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_331_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_331_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_331_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "E19CCepTp4rdjj3Am81NBFouFSchgjvXZFuY1rpXeu5t",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_331_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_331_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_331_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_331_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "ABv85b6EYyLPQk7eaBsJRJvrxYvNBegiC1EPtssG4ofQ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_331_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_331_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_331_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_331_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_331_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_331_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_331_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_331_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_331_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_331_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_331_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_331_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_331_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_331_raw_sz;
  test.expected_result = -26;
  test.custom_err = 5;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_332(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_active_stake::old_behavior";
  test.test_nonce  = 494;
  test.test_number = 332;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "36vMEM8PRCBd8iURUSgGB5HS6tGTJXi3icVKKLmdJcWy",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_332_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_332_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_332_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_332_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "E19CCepTp4rdjj3Am81NBFouFSchgjvXZFuY1rpXeu5t",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_332_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_332_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_332_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_332_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "ABv85b6EYyLPQk7eaBsJRJvrxYvNBegiC1EPtssG4ofQ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_332_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_332_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_332_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_332_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_332_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_332_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_332_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_332_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_332_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_332_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_332_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_332_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_332_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_332_raw_sz;
  test.expected_result = -26;
  test.custom_err = 5;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_333(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_active_stake::old_behavior";
  test.test_nonce  = 538;
  test.test_number = 333;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "36vMEM8PRCBd8iURUSgGB5HS6tGTJXi3icVKKLmdJcWy",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_333_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_333_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_333_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_333_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "E19CCepTp4rdjj3Am81NBFouFSchgjvXZFuY1rpXeu5t",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_333_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_333_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_333_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_333_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "ABv85b6EYyLPQk7eaBsJRJvrxYvNBegiC1EPtssG4ofQ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_333_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_333_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_333_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_333_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_333_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_333_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_333_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_333_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_333_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_333_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_333_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_333_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_333_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_333_raw_sz;
  test.expected_result = -26;
  test.custom_err = 5;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_334(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_active_stake::old_behavior";
  test.test_nonce  = 561;
  test.test_number = 334;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "36vMEM8PRCBd8iURUSgGB5HS6tGTJXi3icVKKLmdJcWy",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_334_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_334_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_334_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_334_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "E19CCepTp4rdjj3Am81NBFouFSchgjvXZFuY1rpXeu5t",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_334_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_334_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_334_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_334_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "ABv85b6EYyLPQk7eaBsJRJvrxYvNBegiC1EPtssG4ofQ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_334_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_334_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_334_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_334_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_334_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_334_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_334_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_334_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_334_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_334_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_334_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_334_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_334_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_334_raw_sz;
  test.expected_result = -26;
  test.custom_err = 5;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_335(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_active_stake::old_behavior";
  test.test_nonce  = 575;
  test.test_number = 335;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "36vMEM8PRCBd8iURUSgGB5HS6tGTJXi3icVKKLmdJcWy",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_335_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_335_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_335_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_335_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "E19CCepTp4rdjj3Am81NBFouFSchgjvXZFuY1rpXeu5t",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_335_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_335_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_335_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_335_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "ABv85b6EYyLPQk7eaBsJRJvrxYvNBegiC1EPtssG4ofQ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_335_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_335_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_335_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_335_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_335_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_335_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_335_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_335_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_335_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_335_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_335_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_335_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_335_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_335_raw_sz;
  test.expected_result = -26;
  test.custom_err = 5;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_336(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_active_stake::old_behavior";
  test.test_nonce  = 587;
  test.test_number = 336;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "36vMEM8PRCBd8iURUSgGB5HS6tGTJXi3icVKKLmdJcWy",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_336_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_336_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_336_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_336_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "E19CCepTp4rdjj3Am81NBFouFSchgjvXZFuY1rpXeu5t",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_336_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_336_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_336_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_336_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "ABv85b6EYyLPQk7eaBsJRJvrxYvNBegiC1EPtssG4ofQ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_336_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_336_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_336_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_336_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_336_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_336_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_336_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_336_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_336_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_336_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_336_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_336_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_336_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_336_raw_sz;
  test.expected_result = -26;
  test.custom_err = 5;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_337(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_active_stake::old_behavior";
  test.test_nonce  = 596;
  test.test_number = 337;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "36vMEM8PRCBd8iURUSgGB5HS6tGTJXi3icVKKLmdJcWy",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_337_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_337_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_337_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_337_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "E19CCepTp4rdjj3Am81NBFouFSchgjvXZFuY1rpXeu5t",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_337_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_337_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_337_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_337_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "ABv85b6EYyLPQk7eaBsJRJvrxYvNBegiC1EPtssG4ofQ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_337_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_337_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_337_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_337_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_337_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_337_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_337_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_337_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_337_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_337_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_337_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_337_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_337_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_337_raw_sz;
  test.expected_result = -26;
  test.custom_err = 5;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_338(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_active_stake::old_behavior";
  test.test_nonce  = 599;
  test.test_number = 338;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "36vMEM8PRCBd8iURUSgGB5HS6tGTJXi3icVKKLmdJcWy",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 8489414244UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_338_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_338_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_338_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_338_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "E19CCepTp4rdjj3Am81NBFouFSchgjvXZFuY1rpXeu5t",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_338_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_338_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_338_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_338_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "ABv85b6EYyLPQk7eaBsJRJvrxYvNBegiC1EPtssG4ofQ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_338_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_338_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_338_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_338_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_338_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_338_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_338_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_338_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_338_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_338_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_338_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_338_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_338_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_338_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_339(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_active_stake::old_behavior";
  test.test_nonce  = 607;
  test.test_number = 339;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "36vMEM8PRCBd8iURUSgGB5HS6tGTJXi3icVKKLmdJcWy",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_339_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_339_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_339_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_339_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "E19CCepTp4rdjj3Am81NBFouFSchgjvXZFuY1rpXeu5t",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 8489414244UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_339_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_339_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_339_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_339_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "ABv85b6EYyLPQk7eaBsJRJvrxYvNBegiC1EPtssG4ofQ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_339_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_339_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_339_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_339_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_339_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_339_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_339_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_339_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_339_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_339_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_339_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_339_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_339_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_339_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_340(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_active_stake::old_behavior";
  test.test_nonce  = 612;
  test.test_number = 340;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "36vMEM8PRCBd8iURUSgGB5HS6tGTJXi3icVKKLmdJcWy",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_340_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_340_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_340_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_340_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "E19CCepTp4rdjj3Am81NBFouFSchgjvXZFuY1rpXeu5t",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_340_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_340_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_340_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_340_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "ABv85b6EYyLPQk7eaBsJRJvrxYvNBegiC1EPtssG4ofQ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_340_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_340_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_340_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_340_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_340_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_340_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_340_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_340_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_340_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_340_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_340_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_340_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_340_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_340_raw_sz;
  test.expected_result = -26;
  test.custom_err = 5;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_341(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_active_stake::old_behavior";
  test.test_nonce  = 617;
  test.test_number = 341;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "36vMEM8PRCBd8iURUSgGB5HS6tGTJXi3icVKKLmdJcWy",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_341_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_341_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_341_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_341_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "E19CCepTp4rdjj3Am81NBFouFSchgjvXZFuY1rpXeu5t",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_341_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_341_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_341_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_341_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "ABv85b6EYyLPQk7eaBsJRJvrxYvNBegiC1EPtssG4ofQ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_341_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_341_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_341_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_341_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_341_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_341_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_341_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_341_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_341_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_341_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_341_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_341_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_341_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_341_raw_sz;
  test.expected_result = -26;
  test.custom_err = 5;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_342(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_active_stake::old_behavior";
  test.test_nonce  = 621;
  test.test_number = 342;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "36vMEM8PRCBd8iURUSgGB5HS6tGTJXi3icVKKLmdJcWy",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_342_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_342_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_342_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_342_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "E19CCepTp4rdjj3Am81NBFouFSchgjvXZFuY1rpXeu5t",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_342_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_342_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_342_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_342_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "ABv85b6EYyLPQk7eaBsJRJvrxYvNBegiC1EPtssG4ofQ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_342_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_342_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_342_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_342_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_342_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_342_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_342_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_342_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_342_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_342_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_342_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_342_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_342_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_342_raw_sz;
  test.expected_result = -26;
  test.custom_err = 5;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_343(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_active_stake::old_behavior";
  test.test_nonce  = 627;
  test.test_number = 343;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "36vMEM8PRCBd8iURUSgGB5HS6tGTJXi3icVKKLmdJcWy",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_343_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_343_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_343_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_343_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "E19CCepTp4rdjj3Am81NBFouFSchgjvXZFuY1rpXeu5t",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_343_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_343_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_343_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_343_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "ABv85b6EYyLPQk7eaBsJRJvrxYvNBegiC1EPtssG4ofQ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_343_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_343_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_343_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_343_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_343_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_343_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_343_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_343_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_343_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_343_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_343_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_343_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_343_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_343_raw_sz;
  test.expected_result = -26;
  test.custom_err = 5;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_344(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_active_stake::old_behavior";
  test.test_nonce  = 631;
  test.test_number = 344;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "36vMEM8PRCBd8iURUSgGB5HS6tGTJXi3icVKKLmdJcWy",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_344_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_344_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_344_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_344_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "E19CCepTp4rdjj3Am81NBFouFSchgjvXZFuY1rpXeu5t",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_344_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_344_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_344_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_344_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "ABv85b6EYyLPQk7eaBsJRJvrxYvNBegiC1EPtssG4ofQ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_344_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_344_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_344_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_344_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_344_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_344_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_344_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_344_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_344_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_344_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_344_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_344_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_344_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_344_raw_sz;
  test.expected_result = -26;
  test.custom_err = 5;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_345(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_active_stake::old_behavior";
  test.test_nonce  = 635;
  test.test_number = 345;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "36vMEM8PRCBd8iURUSgGB5HS6tGTJXi3icVKKLmdJcWy",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_345_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_345_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_345_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_345_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "E19CCepTp4rdjj3Am81NBFouFSchgjvXZFuY1rpXeu5t",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_345_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_345_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_345_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_345_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "ABv85b6EYyLPQk7eaBsJRJvrxYvNBegiC1EPtssG4ofQ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_345_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_345_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_345_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_345_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_345_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_345_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_345_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_345_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_345_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_345_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_345_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_345_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_345_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_345_raw_sz;
  test.expected_result = -26;
  test.custom_err = 5;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_346(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_active_stake::old_behavior";
  test.test_nonce  = 639;
  test.test_number = 346;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "36vMEM8PRCBd8iURUSgGB5HS6tGTJXi3icVKKLmdJcWy",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_346_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_346_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_346_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_346_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "E19CCepTp4rdjj3Am81NBFouFSchgjvXZFuY1rpXeu5t",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_346_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_346_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_346_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_346_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "ABv85b6EYyLPQk7eaBsJRJvrxYvNBegiC1EPtssG4ofQ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_346_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_346_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_346_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_346_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_346_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_346_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_346_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_346_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_346_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_346_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_346_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_346_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_346_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_346_raw_sz;
  test.expected_result = -26;
  test.custom_err = 5;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_347(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_active_stake::old_behavior";
  test.test_nonce  = 642;
  test.test_number = 347;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "36vMEM8PRCBd8iURUSgGB5HS6tGTJXi3icVKKLmdJcWy",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_347_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_347_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_347_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_347_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "E19CCepTp4rdjj3Am81NBFouFSchgjvXZFuY1rpXeu5t",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_347_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_347_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_347_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_347_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "ABv85b6EYyLPQk7eaBsJRJvrxYvNBegiC1EPtssG4ofQ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_347_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_347_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_347_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_347_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_347_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_347_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_347_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_347_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_347_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_347_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_347_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_347_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_347_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_347_raw_sz;
  test.expected_result = -26;
  test.custom_err = 5;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_348(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_active_stake::old_behavior";
  test.test_nonce  = 644;
  test.test_number = 348;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "36vMEM8PRCBd8iURUSgGB5HS6tGTJXi3icVKKLmdJcWy",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 8489414244UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_348_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_348_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_348_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_348_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "E19CCepTp4rdjj3Am81NBFouFSchgjvXZFuY1rpXeu5t",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_348_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_348_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_348_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_348_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "ABv85b6EYyLPQk7eaBsJRJvrxYvNBegiC1EPtssG4ofQ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_348_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_348_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_348_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_348_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_348_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_348_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_348_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_348_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_348_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_348_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_348_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_348_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_348_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_348_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_349(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_active_stake::old_behavior";
  test.test_nonce  = 646;
  test.test_number = 349;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "36vMEM8PRCBd8iURUSgGB5HS6tGTJXi3icVKKLmdJcWy",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_349_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_349_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_349_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_349_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "E19CCepTp4rdjj3Am81NBFouFSchgjvXZFuY1rpXeu5t",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 8489414244UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_349_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_349_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_349_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_349_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "ABv85b6EYyLPQk7eaBsJRJvrxYvNBegiC1EPtssG4ofQ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_349_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_349_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_349_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_349_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_349_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_349_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_349_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_349_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_349_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_349_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_349_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_349_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_349_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_349_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
