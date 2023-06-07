#include "../fd_tests.h"
int test_1275(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_lockup::old_behavior";
  test.test_nonce  = 433;
  test.test_number = 1275;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "FPGBVBEffFvScpBJ1Vucw9CfzSbFtiBDoDRYLZcnnje3",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1275_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1275_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1275_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1275_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BKvTbjA8MNrCmWSkLLkcNb5AUBxX5jNT4CZcky9qTgbM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1275_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1275_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1275_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1275_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "EP5DLKmbWZ66PjyrrefCk9kKGefuFtfT5iksvCUpmuch",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1275_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1275_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1275_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1275_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1275_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1275_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1275_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1275_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1275_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1275_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1275_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1275_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1275_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1275_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1276(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 89,83,92,114,24,80,30,125,75,108,55,77,121,76,113,106,123,26,105,112,109,62,27,110,33,120,61,78,111,127,116,87,79,126,122,82,29,124,118,103,128,98,2,90,15,56,117 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_minimum_stake_delegation::new_behavior";
  test.test_nonce  = 225;
  test.test_number = 1276;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "J6xrF9J9JKk3QyGqSye3PFNQR8b6GmyqNrAe4wKh4cVx",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2283003UL;
  test_acc->result_lamports = 2283003UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1276_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1276_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1276_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1276_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "4pbJae79cydUGciXRSsSCmYucKJr2fGYNUYAKbE9cTwz",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1276_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1276_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1276_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1276_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1276_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1276_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1276_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1276_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1276_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1276_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1276_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1276_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1276_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1276_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1276_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1276_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1276_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1276_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1276_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1276_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1276_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1276_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1277(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 89,83,92,114,24,80,30,125,75,108,55,77,121,76,113,106,123,26,105,112,109,62,27,110,33,120,61,78,111,127,116,87,79,126,122,82,29,124,118,103,128,98,2,90,15,56,117 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_minimum_stake_delegation::new_behavior";
  test.test_nonce  = 346;
  test.test_number = 1277;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "J6xrF9J9JKk3QyGqSye3PFNQR8b6GmyqNrAe4wKh4cVx",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1002283003UL;
  test_acc->result_lamports = 1002282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1277_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1277_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1277_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1277_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "4pbJae79cydUGciXRSsSCmYucKJr2fGYNUYAKbE9cTwz",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2283003UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1277_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1277_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1277_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1277_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1277_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1277_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1277_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1277_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1277_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1277_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1277_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1277_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1277_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1277_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1277_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1277_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1277_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1277_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1277_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1277_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1277_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1277_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1278(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 89,83,92,114,24,80,30,125,75,108,55,77,121,76,113,106,123,26,105,112,109,62,27,110,33,120,61,78,111,127,116,87,79,126,122,82,29,124,118,103,128,98,2,90,15,56,117 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_minimum_stake_delegation::new_behavior";
  test.test_nonce  = 286;
  test.test_number = 1278;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "6mrTuLcrEqYwEnE2Px7byJ88pzdSLMNwMJZd4MAGYb2b",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2283003UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1278_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1278_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1278_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1278_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "4kqQvy5dEvqGpbxHT5Lbc4Vzt3HPQjuEdaqj7Db7SphK",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2283003UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1278_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1278_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1278_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1278_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1278_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1278_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1278_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1278_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1278_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1278_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1278_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1278_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1278_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1278_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1278_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1278_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1278_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1278_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1278_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1278_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1278_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1278_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1279(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 89,83,92,114,24,80,30,125,75,108,55,77,121,76,113,106,123,26,105,112,109,62,27,110,33,120,61,78,111,127,116,87,79,126,122,82,29,124,118,103,128,98,2,90,15,56,117 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_minimum_stake_delegation::new_behavior";
  test.test_nonce  = 394;
  test.test_number = 1279;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "6mrTuLcrEqYwEnE2Px7byJ88pzdSLMNwMJZd4MAGYb2b",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1002283003UL;
  test_acc->result_lamports = 1002282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1279_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1279_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1279_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1279_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "4kqQvy5dEvqGpbxHT5Lbc4Vzt3HPQjuEdaqj7Db7SphK",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2283003UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1279_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1279_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1279_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1279_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1279_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1279_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1279_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1279_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1279_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1279_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1279_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1279_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1279_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1279_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1279_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1279_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1279_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1279_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1279_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1279_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1279_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1279_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1280(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 89,83,92,114,24,80,30,125,75,108,55,77,121,76,113,106,123,26,105,112,109,62,27,110,33,120,61,78,111,127,116,87,79,126,122,82,29,124,118,103,128,98,2,90,15,56,117 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_minimum_stake_delegation::new_behavior";
  test.test_nonce  = 407;
  test.test_number = 1280;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "J6xrF9J9JKk3QyGqSye3PFNQR8b6GmyqNrAe4wKh4cVx",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2283003UL;
  test_acc->result_lamports = 2283003UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1280_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1280_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1280_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1280_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "4pbJae79cydUGciXRSsSCmYucKJr2fGYNUYAKbE9cTwz",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1280_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1280_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1280_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1280_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1280_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1280_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1280_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1280_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1280_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1280_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1280_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1280_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1280_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1280_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1280_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1280_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1280_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1280_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1280_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1280_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1280_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1280_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1281(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 89,83,92,114,24,80,30,125,75,108,55,77,121,76,113,106,123,26,105,112,109,62,27,110,33,120,61,78,111,127,116,87,79,126,122,82,29,124,118,103,128,98,2,90,15,56,117 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_minimum_stake_delegation::new_behavior";
  test.test_nonce  = 464;
  test.test_number = 1281;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "J6xrF9J9JKk3QyGqSye3PFNQR8b6GmyqNrAe4wKh4cVx",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1002283003UL;
  test_acc->result_lamports = 1002283003UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1281_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1281_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1281_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1281_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "4pbJae79cydUGciXRSsSCmYucKJr2fGYNUYAKbE9cTwz",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1281_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1281_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1281_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1281_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1281_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1281_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1281_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1281_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1281_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1281_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1281_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1281_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1281_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1281_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1281_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1281_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1281_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1281_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1281_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1281_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1281_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1281_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1282(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 89,83,92,114,24,80,30,125,75,108,55,77,121,76,113,106,123,26,105,112,109,62,27,110,33,120,61,78,111,127,116,87,79,126,122,82,29,124,118,103,128,98,2,90,15,56,117 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_minimum_stake_delegation::new_behavior";
  test.test_nonce  = 451;
  test.test_number = 1282;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "6mrTuLcrEqYwEnE2Px7byJ88pzdSLMNwMJZd4MAGYb2b",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2283003UL;
  test_acc->result_lamports = 2283003UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1282_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1282_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1282_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1282_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "4kqQvy5dEvqGpbxHT5Lbc4Vzt3HPQjuEdaqj7Db7SphK",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1282_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1282_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1282_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1282_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1282_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1282_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1282_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1282_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1282_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1282_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1282_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1282_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1282_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1282_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1282_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1282_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1282_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1282_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1282_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1282_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1282_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1282_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1283(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 89,83,92,114,24,80,30,125,75,108,55,77,121,76,113,106,123,26,105,112,109,62,27,110,33,120,61,78,111,127,116,87,79,126,122,82,29,124,118,103,128,98,2,90,15,56,117 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_minimum_stake_delegation::new_behavior";
  test.test_nonce  = 511;
  test.test_number = 1283;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "6mrTuLcrEqYwEnE2Px7byJ88pzdSLMNwMJZd4MAGYb2b",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1002283003UL;
  test_acc->result_lamports = 1002283003UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1283_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1283_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1283_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1283_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "4kqQvy5dEvqGpbxHT5Lbc4Vzt3HPQjuEdaqj7Db7SphK",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1283_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1283_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1283_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1283_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1283_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1283_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1283_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1283_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1283_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1283_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1283_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1283_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1283_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1283_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1283_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1283_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1283_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1283_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1283_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1283_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1283_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1283_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1284(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 110,62,111,76,106,126,78,75,127,87,26,105,116,55,118,109,27,103,128,114,122,79,15,83,124,90,56,30,61,108,125,92,98,82,123,77,113,80,89,121,29,112,2,120,24,33,117 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_minimum_stake_delegation::old_behavior";
  test.test_nonce  = 213;
  test.test_number = 1284;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "UqpDr9nWMpPpusoXY8nJtTH6guUe9mscFTr2RgYaQ8Q",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2283003UL;
  test_acc->result_lamports = 2283003UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1284_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1284_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1284_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1284_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "AJFNQpNtXxFVQDUSsfUmjpQfAVsHRbu5XmSBrUyQBcvF",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1284_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1284_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1284_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1284_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1284_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1284_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1284_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1284_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1284_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1284_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1284_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1284_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1284_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1284_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1284_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1284_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1284_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1284_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1284_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1284_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1284_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1284_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1285(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 110,62,111,76,106,126,78,75,127,87,26,105,116,55,118,109,27,103,128,114,122,79,15,83,124,90,56,30,61,108,125,92,98,82,123,77,113,80,89,121,29,112,2,120,24,33,117 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_minimum_stake_delegation::old_behavior";
  test.test_nonce  = 273;
  test.test_number = 1285;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "UqpDr9nWMpPpusoXY8nJtTH6guUe9mscFTr2RgYaQ8Q",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2283004UL;
  test_acc->result_lamports = 2282881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1285_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1285_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1285_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1285_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "AJFNQpNtXxFVQDUSsfUmjpQfAVsHRbu5XmSBrUyQBcvF",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2283003UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1285_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1285_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1285_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1285_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1285_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1285_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1285_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1285_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1285_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1285_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1285_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1285_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1285_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1285_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1285_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1285_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1285_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1285_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1285_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1285_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1285_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1285_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1286(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_minimum_stake_delegation::old_behavior";
  test.test_nonce  = 290;
  test.test_number = 1286;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "2NbsVnChKRAxXz8E4ZzeJBbWxtsuceWymqRHwRF7NKon",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2283003UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1286_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1286_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1286_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1286_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "72Z4UdJbv3Pkq2RY3AFimDwKVfA2wc5PZoJyy8xYKgfF",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2283003UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1286_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1286_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1286_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1286_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1286_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1286_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1286_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1286_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1286_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1286_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1286_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1286_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1286_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1286_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1286_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1286_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1286_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1286_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1286_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1286_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1286_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1286_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1287(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_minimum_stake_delegation::old_behavior";
  test.test_nonce  = 400;
  test.test_number = 1287;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "2NbsVnChKRAxXz8E4ZzeJBbWxtsuceWymqRHwRF7NKon",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2283004UL;
  test_acc->result_lamports = 2282881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1287_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1287_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1287_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1287_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "72Z4UdJbv3Pkq2RY3AFimDwKVfA2wc5PZoJyy8xYKgfF",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2283003UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1287_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1287_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1287_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1287_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1287_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1287_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1287_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1287_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1287_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1287_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1287_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1287_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1287_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1287_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1287_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1287_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1287_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1287_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1287_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1287_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1287_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1287_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1288(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 110,62,111,76,106,126,78,75,127,87,26,105,116,55,118,109,27,103,128,114,122,79,15,83,124,90,56,30,61,108,125,92,98,82,123,77,113,80,89,121,29,112,2,120,24,33,117 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_minimum_stake_delegation::old_behavior";
  test.test_nonce  = 374;
  test.test_number = 1288;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "UqpDr9nWMpPpusoXY8nJtTH6guUe9mscFTr2RgYaQ8Q",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2283003UL;
  test_acc->result_lamports = 2283003UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1288_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1288_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1288_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1288_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "AJFNQpNtXxFVQDUSsfUmjpQfAVsHRbu5XmSBrUyQBcvF",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1288_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1288_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1288_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1288_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1288_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1288_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1288_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1288_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1288_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1288_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1288_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1288_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1288_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1288_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1288_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1288_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1288_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1288_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1288_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1288_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1288_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1288_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1289(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 110,62,111,76,106,126,78,75,127,87,26,105,116,55,118,109,27,103,128,114,122,79,15,83,124,90,56,30,61,108,125,92,98,82,123,77,113,80,89,121,29,112,2,120,24,33,117 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_minimum_stake_delegation::old_behavior";
  test.test_nonce  = 411;
  test.test_number = 1289;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "UqpDr9nWMpPpusoXY8nJtTH6guUe9mscFTr2RgYaQ8Q",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2283004UL;
  test_acc->result_lamports = 2283004UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1289_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1289_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1289_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1289_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "AJFNQpNtXxFVQDUSsfUmjpQfAVsHRbu5XmSBrUyQBcvF",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1289_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1289_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1289_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1289_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1289_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1289_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1289_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1289_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1289_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1289_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1289_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1289_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1289_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1289_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1289_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1289_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1289_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1289_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1289_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1289_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1289_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1289_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1290(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_minimum_stake_delegation::old_behavior";
  test.test_nonce  = 455;
  test.test_number = 1290;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "2NbsVnChKRAxXz8E4ZzeJBbWxtsuceWymqRHwRF7NKon",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2283003UL;
  test_acc->result_lamports = 2283003UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1290_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1290_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1290_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1290_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "72Z4UdJbv3Pkq2RY3AFimDwKVfA2wc5PZoJyy8xYKgfF",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1290_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1290_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1290_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1290_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1290_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1290_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1290_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1290_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1290_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1290_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1290_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1290_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1290_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1290_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1290_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1290_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1290_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1290_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1290_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1290_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1290_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1290_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1291(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_minimum_stake_delegation::old_behavior";
  test.test_nonce  = 515;
  test.test_number = 1291;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "2NbsVnChKRAxXz8E4ZzeJBbWxtsuceWymqRHwRF7NKon",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2283004UL;
  test_acc->result_lamports = 2283004UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1291_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1291_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1291_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1291_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "72Z4UdJbv3Pkq2RY3AFimDwKVfA2wc5PZoJyy8xYKgfF",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1291_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1291_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1291_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1291_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1291_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1291_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1291_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1291_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1291_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1291_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1291_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1291_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1291_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1291_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1291_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1291_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1291_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1291_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1291_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1291_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1291_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1291_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1292(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 116,90,24,77,78,114,33,55,62,56,110,82,75,108,126,123,128,29,105,26,121,122,127,87,111,83,120,79,92,98,118,89,2,109,103,113,15,76,30,117,106,125,124,27,61,112,80 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_rent_exempt::new_behavior";
  test.test_nonce  = 277;
  test.test_number = 1292;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "E3EYVYzAG1AJFRv5dmRDJr6SpET4ZyBb4iXdhUUZJyyg",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 7002282880UL;
  test_acc->result_lamports = 7002282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1292_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1292_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1292_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1292_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "GuGUaqraB3AKTWcphT8Uv7QqUmUW2aQdhkLdoHUy437d",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1292_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1292_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1292_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1292_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "C2VauE4i6BbxLi2tvNRosjoWcXpkaCNMmKJLYDxU9ZK",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1292_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1292_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1292_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1292_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1292_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1292_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1292_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1292_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1292_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1292_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1292_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1292_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1292_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1292_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1293(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 116,90,24,77,78,114,33,55,62,56,110,82,75,108,126,123,128,29,105,26,121,122,127,87,111,83,120,79,92,98,118,89,2,109,103,113,15,76,30,117,106,125,124,27,61,112,80 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_rent_exempt::new_behavior";
  test.test_nonce  = 254;
  test.test_number = 1293;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "6hTJBC5o2DPCpaQi7gsEhbMvVLCxAi5YsvFGMB1AH9Sv",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 7002282880UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1293_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1293_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1293_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1293_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "7NR2oWHj1qjsJ6YrXh3KisLW6a7AxzC4ssHZVyS71BjT",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 7000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1293_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1293_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1293_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1293_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "EDBbmMaTJhtbHni2uMx4zmvLzjAQ2WmuUKKZnaVVpey2",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1293_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1293_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1293_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1293_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1293_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1293_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1293_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1293_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1293_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1293_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1293_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1293_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1293_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1293_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1294(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 116,90,24,77,78,114,33,55,62,56,110,82,75,108,126,123,128,29,105,26,121,122,127,87,111,83,120,79,92,98,118,89,2,109,103,113,15,76,30,117,106,125,124,27,61,112,80 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_rent_exempt::new_behavior";
  test.test_nonce  = 355;
  test.test_number = 1294;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "E3EYVYzAG1AJFRv5dmRDJr6SpET4ZyBb4iXdhUUZJyyg",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 7002282880UL;
  test_acc->result_lamports = 7002282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1294_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1294_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1294_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1294_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "GuGUaqraB3AKTWcphT8Uv7QqUmUW2aQdhkLdoHUy437d",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1294_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1294_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1294_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1294_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "C2VauE4i6BbxLi2tvNRosjoWcXpkaCNMmKJLYDxU9ZK",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1294_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1294_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1294_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1294_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1294_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1294_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1294_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1294_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1294_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1294_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1294_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1294_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1294_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1294_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1295(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 116,90,24,77,78,114,33,55,62,56,110,82,75,108,126,123,128,29,105,26,121,122,127,87,111,83,120,79,92,98,118,89,2,109,103,113,15,76,30,117,106,125,124,27,61,112,80 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_rent_exempt::new_behavior";
  test.test_nonce  = 342;
  test.test_number = 1295;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "6hTJBC5o2DPCpaQi7gsEhbMvVLCxAi5YsvFGMB1AH9Sv",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 7002282880UL;
  test_acc->result_lamports = 7002282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1295_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1295_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1295_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1295_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "7NR2oWHj1qjsJ6YrXh3KisLW6a7AxzC4ssHZVyS71BjT",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1295_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1295_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1295_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1295_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "EDBbmMaTJhtbHni2uMx4zmvLzjAQ2WmuUKKZnaVVpey2",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1295_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1295_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1295_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1295_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1295_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1295_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1295_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1295_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1295_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1295_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1295_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1295_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1295_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1295_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1296(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 116,90,24,77,78,114,33,55,62,56,110,82,75,108,126,123,128,29,105,26,121,122,127,87,111,83,120,79,92,98,118,89,2,109,103,113,15,76,30,117,106,125,124,27,61,112,80 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_rent_exempt::new_behavior";
  test.test_nonce  = 382;
  test.test_number = 1296;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "E3EYVYzAG1AJFRv5dmRDJr6SpET4ZyBb4iXdhUUZJyyg",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 7002282880UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1296_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1296_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1296_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1296_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "GuGUaqraB3AKTWcphT8Uv7QqUmUW2aQdhkLdoHUy437d",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 7002282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1296_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1296_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1296_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1296_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "C2VauE4i6BbxLi2tvNRosjoWcXpkaCNMmKJLYDxU9ZK",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1296_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1296_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1296_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1296_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1296_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1296_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1296_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1296_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1296_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1296_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1296_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1296_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1296_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1296_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1297(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 116,90,24,77,78,114,33,55,62,56,110,82,75,108,126,123,128,29,105,26,121,122,127,87,111,83,120,79,92,98,118,89,2,109,103,113,15,76,30,117,106,125,124,27,61,112,80 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_rent_exempt::new_behavior";
  test.test_nonce  = 388;
  test.test_number = 1297;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "6hTJBC5o2DPCpaQi7gsEhbMvVLCxAi5YsvFGMB1AH9Sv",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 7002282880UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1297_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1297_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1297_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1297_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "7NR2oWHj1qjsJ6YrXh3KisLW6a7AxzC4ssHZVyS71BjT",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 7002282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1297_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1297_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1297_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1297_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "EDBbmMaTJhtbHni2uMx4zmvLzjAQ2WmuUKKZnaVVpey2",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1297_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1297_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1297_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1297_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1297_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1297_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1297_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1297_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1297_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1297_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1297_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1297_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1297_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1297_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1298(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_rent_exempt::old_behavior";
  test.test_nonce  = 258;
  test.test_number = 1298;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "Dp9gm8T98cdnRhaN9BAXnG4NsjECsgvHxXmh1a6Er28W",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282887UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1298_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1298_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1298_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1298_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "8ZWmxr5wyYa5PzoVCMWvzPaHhVnePnc2S9KXiBS6Zy24",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 7UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1298_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1298_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1298_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1298_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "6WnTucZhvQbVgazgDWrvnzDUammCnTVHiSTpsAAySYgr",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1298_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1298_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1298_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1298_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1298_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1298_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1298_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1298_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1298_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1298_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1298_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1298_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1298_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1298_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1299(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 62,61,105,98,122,76,80,110,79,92,78,30,2,109,103,106,118,116,89,123,124,77,27,127,83,55,126,90,15,128,121,82,111,24,56,120,87,26,125,114,112,75,113,117,29,108,33 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_rent_exempt::old_behavior";
  test.test_nonce  = 276;
  test.test_number = 1299;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "6qTh9GzmaWWpwSSyg71ZxVSz6oYMPrgAGC657tJuLcaG",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282887UL;
  test_acc->result_lamports = 2282887UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1299_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1299_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1299_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1299_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "ByoRhpidxmZNbF8p3ZL5cgspHmMaiJMLUDHJ8k3344qo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1299_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1299_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1299_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1299_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "5dLJwrwfk4Zh3ME1guXZDx3d2MGdhDR9EGkF9z7RD1TV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1299_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1299_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1299_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1299_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1299_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1299_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1299_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1299_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1299_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1299_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1299_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1299_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1299_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1299_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
