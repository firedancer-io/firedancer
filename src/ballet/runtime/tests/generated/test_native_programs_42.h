#include "../fd_tests.h"
int test_1050(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 80,33,118,125,105,108,109,78,111,76,124,56,120,15,114,30,123,126,98,121,89,83,62,79,2,55,27,112,127,103,106,26,110,77,128,82,61,87,92,117,116,90,75,24,29,113,122 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_delegate::old_behavior";
  test.test_nonce  = 599;
  test.test_number = 1050;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "3YakwNwqk1PH8mPYBp8v7gFFhmnBnPEyypz1A1yT5yaN",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1050_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1050_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1050_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1050_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "C34ou7TQp2cS2s4s461XUWkEhZFLVJaT5ZuAzvwqteHx",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1050_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1050_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1050_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1050_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BNuCFyLR7bvbCr2rq4yBQC13bbcfprH64ZYKadFiN4ki",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1050_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1050_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1050_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1050_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1050_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1050_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1050_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1050_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1050_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1050_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1050_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1050_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1050_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1050_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1050_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1050_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1050_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1050_raw_sz;
  test.expected_result = -26;
  test.custom_err = 3;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1051(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 80,33,118,125,105,108,109,78,111,76,124,56,120,15,114,30,123,126,98,121,89,83,62,79,2,55,27,112,127,103,106,26,110,77,128,82,61,87,92,117,116,90,75,24,29,113,122 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_delegate::old_behavior";
  test.test_nonce  = 610;
  test.test_number = 1051;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "3YakwNwqk1PH8mPYBp8v7gFFhmnBnPEyypz1A1yT5yaN",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1051_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1051_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1051_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1051_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "C34ou7TQp2cS2s4s461XUWkEhZFLVJaT5ZuAzvwqteHx",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1051_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1051_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1051_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1051_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BNuCFyLR7bvbCr2rq4yBQC13bbcfprH64ZYKadFiN4ki",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1051_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1051_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1051_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1051_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1051_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1051_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1051_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1051_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1051_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1051_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1051_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1051_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1051_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1051_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1051_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1051_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1051_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1051_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1052(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 80,33,118,125,105,108,109,78,111,76,124,56,120,15,114,30,123,126,98,121,89,83,62,79,2,55,27,112,127,103,106,26,110,77,128,82,61,87,92,117,116,90,75,24,29,113,122 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_delegate::old_behavior";
  test.test_nonce  = 617;
  test.test_number = 1052;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "3YakwNwqk1PH8mPYBp8v7gFFhmnBnPEyypz1A1yT5yaN",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1052_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1052_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1052_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1052_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BNuCFyLR7bvbCr2rq4yBQC13bbcfprH64ZYKadFiN4ki",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "652DsNESHSW7LjuKU6HogeMt6KknzTZMCNq7XNnZYk53",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1052_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1052_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1052_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1052_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BNuCFyLR7bvbCr2rq4yBQC13bbcfprH64ZYKadFiN4ki",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1052_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1052_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1052_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1052_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1052_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1052_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1052_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1052_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1052_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1052_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1052_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1052_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1052_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1052_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1052_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1052_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1052_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1052_raw_sz;
  test.expected_result = -7;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1053(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 80,33,118,125,105,108,109,78,111,76,124,56,120,15,114,30,123,126,98,121,89,83,62,79,2,55,27,112,127,103,106,26,110,77,128,82,61,87,92,117,116,90,75,24,29,113,122 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_delegate::old_behavior";
  test.test_nonce  = 624;
  test.test_number = 1053;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "3YakwNwqk1PH8mPYBp8v7gFFhmnBnPEyypz1A1yT5yaN",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1053_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1053_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1053_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1053_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BNuCFyLR7bvbCr2rq4yBQC13bbcfprH64ZYKadFiN4ki",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "652DsNESHSW7LjuKU6HogeMt6KknzTZMCNq7XNnZYk53",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1053_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1053_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1053_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1053_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BNuCFyLR7bvbCr2rq4yBQC13bbcfprH64ZYKadFiN4ki",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1053_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1053_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1053_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1053_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1053_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1053_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1053_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1053_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1053_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1053_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1053_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1053_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1053_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1053_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1053_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1053_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1053_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1053_raw_sz;
  test.expected_result = -7;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1054(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_delegate::old_behavior";
  test.test_nonce  = 481;
  test.test_number = 1054;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "7GDsDujDaq52WrtXswk1yKigtmLcY5HWnMhLmpkoMnxs",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1054_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1054_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1054_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1054_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "9CaeDFdhUVnpeeXkXUGK5vKS715bBNNHp7cCcYUSWBiF",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1054_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1054_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1054_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1054_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "EiDW2kbNZwzaUvsdTLgrpuYJDS7Xc42KYVPFSav7Wdvr",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1054_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1054_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1054_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1054_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1054_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1054_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1054_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1054_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1054_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1054_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1054_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1054_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1054_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1054_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1054_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1054_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1054_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1054_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1055(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 80,33,118,125,105,108,109,78,111,76,124,56,120,15,114,30,123,126,98,121,89,83,62,79,2,55,27,112,127,103,106,26,110,77,128,82,61,87,92,117,116,90,75,24,29,113,122 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_delegate::old_behavior";
  test.test_nonce  = 540;
  test.test_number = 1055;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "3YakwNwqk1PH8mPYBp8v7gFFhmnBnPEyypz1A1yT5yaN",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1055_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1055_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1055_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1055_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "C34ou7TQp2cS2s4s461XUWkEhZFLVJaT5ZuAzvwqteHx",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1055_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1055_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1055_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1055_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BNuCFyLR7bvbCr2rq4yBQC13bbcfprH64ZYKadFiN4ki",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1055_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1055_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1055_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1055_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1055_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1055_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1055_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1055_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1055_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1055_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1055_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1055_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1055_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1055_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1055_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1055_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1055_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1055_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1056(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 2,76,121,114,106,24,109,98,75,122,125,123,62,111,105,61,116,124,90,15,30,80,127,120,83,113,26,78,77,118,126,92,29,89,128,110,56,103,87,79,112,108,117,27,55,82,33 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_staked_split_destination_minimum_balance::new_behavior";
  test.test_nonce  = 210;
  test.test_number = 1056;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111VyLRtpTk7zN5tD3EmCywv2beKKYvBrzymq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 18446744073709551615UL;
  test_acc->result_lamports = 18446744073709551615UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1056_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1056_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1056_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1056_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111WNg2svm2qApxheBKndKGQ9sRwporu6ap6B",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1002282880UL;
  test_acc->result_lamports = 1002282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1056_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1056_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1056_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1056_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1056_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1056_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1056_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1056_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1056_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1056_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1057(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 2,76,121,114,106,24,109,98,75,122,125,123,62,111,105,61,116,124,90,15,30,80,127,120,83,113,26,78,77,118,126,92,29,89,128,110,56,103,87,79,112,108,117,27,55,82,33 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_staked_split_destination_minimum_balance::new_behavior";
  test.test_nonce  = 243;
  test.test_number = 1057;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111ZC3Fmgr3oS56Rg9vxZeVo2mwMMcTsjfeJb",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 18446744073709551615UL;
  test_acc->result_lamports = 18446744073709551615UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1057_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1057_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1057_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1057_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111ZbNrko9LWcXyF7J1yyypHA3iyrsQayFUcw",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1002282880UL;
  test_acc->result_lamports = 1002282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1057_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1057_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1057_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1057_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1057_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1057_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1057_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1057_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1057_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1057_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1058(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 2,76,121,114,106,24,109,98,75,122,125,123,62,111,105,61,116,124,90,15,30,80,127,120,83,113,26,78,77,118,126,92,29,89,128,110,56,103,87,79,112,108,117,27,55,82,33 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_staked_split_destination_minimum_balance::new_behavior";
  test.test_nonce  = 306;
  test.test_number = 1058;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111VyLRtpTk7zN5tD3EmCywv2beKKYvBrzymq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 18446744073709551615UL;
  test_acc->result_lamports = 18446744072709551615UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1058_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1058_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1058_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1058_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111WNg2svm2qApxheBKndKGQ9sRwporu6ap6B",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 1002282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1058_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1058_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1058_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1058_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1058_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1058_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1058_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1058_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1058_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1058_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1059(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 2,76,121,114,106,24,109,98,75,122,125,123,62,111,105,61,116,124,90,15,30,80,127,120,83,113,26,78,77,118,126,92,29,89,128,110,56,103,87,79,112,108,117,27,55,82,33 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_staked_split_destination_minimum_balance::new_behavior";
  test.test_nonce  = 373;
  test.test_number = 1059;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111VyLRtpTk7zN5tD3EmCywv2beKKYvBrzymq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 18446744073709551615UL;
  test_acc->result_lamports = 18446744072709551615UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1059_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1059_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1059_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1059_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111WNg2svm2qApxheBKndKGQ9sRwporu6ap6B",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282879UL;
  test_acc->result_lamports = 1002282879UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1059_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1059_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1059_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1059_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1059_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1059_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1059_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1059_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1059_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1059_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1060(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 2,76,121,114,106,24,109,98,75,122,125,123,62,111,105,61,116,124,90,15,30,80,127,120,83,113,26,78,77,118,126,92,29,89,128,110,56,103,87,79,112,108,117,27,55,82,33 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_staked_split_destination_minimum_balance::new_behavior";
  test.test_nonce  = 341;
  test.test_number = 1060;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111ZC3Fmgr3oS56Rg9vxZeVo2mwMMcTsjfeJb",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 18446744073709551615UL;
  test_acc->result_lamports = 18446744072709551615UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1060_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1060_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1060_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1060_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111ZbNrko9LWcXyF7J1yyypHA3iyrsQayFUcw",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 1002282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1060_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1060_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1060_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1060_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1060_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1060_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1060_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1060_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1060_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1060_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1061(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 2,76,121,114,106,24,109,98,75,122,125,123,62,111,105,61,116,124,90,15,30,80,127,120,83,113,26,78,77,118,126,92,29,89,128,110,56,103,87,79,112,108,117,27,55,82,33 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_staked_split_destination_minimum_balance::new_behavior";
  test.test_nonce  = 372;
  test.test_number = 1061;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111ZC3Fmgr3oS56Rg9vxZeVo2mwMMcTsjfeJb",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 18446744073709551615UL;
  test_acc->result_lamports = 18446744073709551615UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1061_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1061_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1061_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1061_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111ZbNrko9LWcXyF7J1yyypHA3iyrsQayFUcw",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282879UL;
  test_acc->result_lamports = 2282879UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1061_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1061_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1061_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1061_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1061_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1061_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1061_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1061_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1061_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1061_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1062(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 2,76,121,114,106,24,109,98,75,122,125,123,62,111,105,61,116,124,90,15,30,80,127,120,83,113,26,78,77,118,126,92,29,89,128,110,56,103,87,79,112,108,117,27,55,82,33 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_staked_split_destination_minimum_balance::new_behavior";
  test.test_nonce  = 245;
  test.test_number = 1062;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111VyLRtpTk7zN5tD3EmCywv2beKKYvBrzymq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 18446744073709551615UL;
  test_acc->result_lamports = 18446744073709551614UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1062_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1062_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1062_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1062_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111WNg2svm2qApxheBKndKGQ9sRwporu6ap6B",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1002282880UL;
  test_acc->result_lamports = 1002282881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1062_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1062_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1062_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1062_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1062_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1062_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1062_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1062_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1062_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1062_raw_sz;
  test.expected_result = -26;
  test.custom_err = 12;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1063(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 2,76,121,114,106,24,109,98,75,122,125,123,62,111,105,61,116,124,90,15,30,80,127,120,83,113,26,78,77,118,126,92,29,89,128,110,56,103,87,79,112,108,117,27,55,82,33 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_staked_split_destination_minimum_balance::new_behavior";
  test.test_nonce  = 271;
  test.test_number = 1063;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111VyLRtpTk7zN5tD3EmCywv2beKKYvBrzymq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 18446744073709551615UL;
  test_acc->result_lamports = 18446744073709551614UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1063_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1063_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1063_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1063_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111WNg2svm2qApxheBKndKGQ9sRwporu6ap6B",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1002282879UL;
  test_acc->result_lamports = 1002282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1063_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1063_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1063_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1063_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1063_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1063_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1063_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1063_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1063_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1063_raw_sz;
  test.expected_result = -26;
  test.custom_err = 12;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1064(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 2,76,121,114,106,24,109,98,75,122,125,123,62,111,105,61,116,124,90,15,30,80,127,120,83,113,26,78,77,118,126,92,29,89,128,110,56,103,87,79,112,108,117,27,55,82,33 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_staked_split_destination_minimum_balance::new_behavior";
  test.test_nonce  = 284;
  test.test_number = 1064;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111VyLRtpTk7zN5tD3EmCywv2beKKYvBrzymq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 18446744073709551615UL;
  test_acc->result_lamports = 18446744073709551614UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1064_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1064_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1064_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1064_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111WNg2svm2qApxheBKndKGQ9sRwporu6ap6B",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1002282878UL;
  test_acc->result_lamports = 1002282879UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1064_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1064_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1064_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1064_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1064_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1064_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1064_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1064_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1064_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1064_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1065(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 2,76,121,114,106,24,109,98,75,122,125,123,62,111,105,61,116,124,90,15,30,80,127,120,83,113,26,78,77,118,126,92,29,89,128,110,56,103,87,79,112,108,117,27,55,82,33 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_staked_split_destination_minimum_balance::new_behavior";
  test.test_nonce  = 276;
  test.test_number = 1065;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111ZC3Fmgr3oS56Rg9vxZeVo2mwMMcTsjfeJb",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 18446744073709551615UL;
  test_acc->result_lamports = 18446744073709551615UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1065_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1065_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1065_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1065_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111ZbNrko9LWcXyF7J1yyypHA3iyrsQayFUcw",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1002282880UL;
  test_acc->result_lamports = 1002282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1065_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1065_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1065_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1065_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1065_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1065_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1065_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1065_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1065_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1065_raw_sz;
  test.expected_result = -26;
  test.custom_err = 12;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1066(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 2,76,121,114,106,24,109,98,75,122,125,123,62,111,105,61,116,124,90,15,30,80,127,120,83,113,26,78,77,118,126,92,29,89,128,110,56,103,87,79,112,108,117,27,55,82,33 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_staked_split_destination_minimum_balance::new_behavior";
  test.test_nonce  = 313;
  test.test_number = 1066;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111ZC3Fmgr3oS56Rg9vxZeVo2mwMMcTsjfeJb",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 18446744073709551615UL;
  test_acc->result_lamports = 18446744073709551615UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1066_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1066_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1066_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1066_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111ZbNrko9LWcXyF7J1yyypHA3iyrsQayFUcw",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1002282879UL;
  test_acc->result_lamports = 1002282879UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1066_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1066_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1066_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1066_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1066_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1066_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1066_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1066_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1066_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1066_raw_sz;
  test.expected_result = -26;
  test.custom_err = 12;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1067(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 2,76,121,114,106,24,109,98,75,122,125,123,62,111,105,61,116,124,90,15,30,80,127,120,83,113,26,78,77,118,126,92,29,89,128,110,56,103,87,79,112,108,117,27,55,82,33 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_staked_split_destination_minimum_balance::new_behavior";
  test.test_nonce  = 325;
  test.test_number = 1067;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111ZC3Fmgr3oS56Rg9vxZeVo2mwMMcTsjfeJb",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 18446744073709551615UL;
  test_acc->result_lamports = 18446744073709551615UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1067_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1067_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1067_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1067_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111ZbNrko9LWcXyF7J1yyypHA3iyrsQayFUcw",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1002282878UL;
  test_acc->result_lamports = 1002282878UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1067_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1067_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1067_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1067_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1067_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1067_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1067_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1067_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1067_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1067_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1068(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 2,76,121,114,106,24,109,98,75,122,125,123,62,111,105,61,116,124,90,15,30,80,127,120,83,113,26,78,77,118,126,92,29,89,128,110,56,103,87,79,112,108,117,27,55,82,33 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_staked_split_destination_minimum_balance::new_behavior";
  test.test_nonce  = 350;
  test.test_number = 1068;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111VyLRtpTk7zN5tD3EmCywv2beKKYvBrzymq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 18446744073709551615UL;
  test_acc->result_lamports = 18446744072709551614UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1068_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1068_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1068_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1068_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111WNg2svm2qApxheBKndKGQ9sRwporu6ap6B",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282879UL;
  test_acc->result_lamports = 1002282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1068_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1068_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1068_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1068_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1068_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1068_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1068_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1068_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1068_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1068_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1069(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 2,76,121,114,106,24,109,98,75,122,125,123,62,111,105,61,116,124,90,15,30,80,127,120,83,113,26,78,77,118,126,92,29,89,128,110,56,103,87,79,112,108,117,27,55,82,33 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_staked_split_destination_minimum_balance::new_behavior";
  test.test_nonce  = 362;
  test.test_number = 1069;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111ZC3Fmgr3oS56Rg9vxZeVo2mwMMcTsjfeJb",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 18446744073709551615UL;
  test_acc->result_lamports = 18446744072709551614UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1069_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1069_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1069_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1069_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111ZbNrko9LWcXyF7J1yyypHA3iyrsQayFUcw",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282879UL;
  test_acc->result_lamports = 1002282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1069_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1069_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1069_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1069_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1069_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1069_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1069_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1069_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1069_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1069_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1070(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 2,76,121,114,106,24,109,98,75,122,125,123,62,111,105,61,116,124,90,15,30,80,127,120,83,113,26,78,77,118,126,92,29,89,128,110,56,103,87,79,112,108,117,27,55,82,33 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_staked_split_destination_minimum_balance::new_behavior";
  test.test_nonce  = 413;
  test.test_number = 1070;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111VyLRtpTk7zN5tD3EmCywv2beKKYvBrzymq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 18446744073709551615UL;
  test_acc->result_lamports = 18446744072707268737UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1070_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1070_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1070_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1070_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111WNg2svm2qApxheBKndKGQ9sRwporu6ap6B",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1002282879UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1070_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1070_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1070_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1070_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1070_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1070_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1070_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1070_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1070_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1070_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1071(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 2,76,121,114,106,24,109,98,75,122,125,123,62,111,105,61,116,124,90,15,30,80,127,120,83,113,26,78,77,118,126,92,29,89,128,110,56,103,87,79,112,108,117,27,55,82,33 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_staked_split_destination_minimum_balance::new_behavior";
  test.test_nonce  = 389;
  test.test_number = 1071;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111ZC3Fmgr3oS56Rg9vxZeVo2mwMMcTsjfeJb",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 18446744073709551615UL;
  test_acc->result_lamports = 18446744073709551615UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1071_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1071_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1071_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1071_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111ZbNrko9LWcXyF7J1yyypHA3iyrsQayFUcw",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1071_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1071_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1071_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1071_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1071_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1071_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1071_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1071_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1071_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1071_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1072(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 2,76,121,114,106,24,109,98,75,122,125,123,62,111,105,61,116,124,90,15,30,80,127,120,83,113,26,78,77,118,126,92,29,89,128,110,56,103,87,79,112,108,117,27,55,82,33 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_staked_split_destination_minimum_balance::new_behavior";
  test.test_nonce  = 395;
  test.test_number = 1072;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111VyLRtpTk7zN5tD3EmCywv2beKKYvBrzymq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 18446744073709551615UL;
  test_acc->result_lamports = 18446744072707268736UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1072_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1072_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1072_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1072_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111WNg2svm2qApxheBKndKGQ9sRwporu6ap6B",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1002282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1072_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1072_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1072_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1072_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1072_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1072_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1072_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1072_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1072_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1072_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1073(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 2,76,121,114,106,24,109,98,75,122,125,123,62,111,105,61,116,124,90,15,30,80,127,120,83,113,26,78,77,118,126,92,29,89,128,110,56,103,87,79,112,108,117,27,55,82,33 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_staked_split_destination_minimum_balance::new_behavior";
  test.test_nonce  = 458;
  test.test_number = 1073;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111VyLRtpTk7zN5tD3EmCywv2beKKYvBrzymq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 18446744073709551615UL;
  test_acc->result_lamports = 18446744072707268736UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1073_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1073_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1073_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1073_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111WNg2svm2qApxheBKndKGQ9sRwporu6ap6B",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 1002282879UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1073_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1073_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1073_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1073_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1073_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1073_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1073_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1073_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1073_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1073_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1074(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 2,76,121,114,106,24,109,98,75,122,125,123,62,111,105,61,116,124,90,15,30,80,127,120,83,113,26,78,77,118,126,92,29,89,128,110,56,103,87,79,112,108,117,27,55,82,33 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_staked_split_destination_minimum_balance::new_behavior";
  test.test_nonce  = 380;
  test.test_number = 1074;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111ZC3Fmgr3oS56Rg9vxZeVo2mwMMcTsjfeJb",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 18446744073709551615UL;
  test_acc->result_lamports = 18446744072707268736UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1074_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1074_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1074_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1074_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111ZbNrko9LWcXyF7J1yyypHA3iyrsQayFUcw",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1002282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1074_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1074_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1074_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1074_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1074_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1074_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1074_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1074_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1074_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1074_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
