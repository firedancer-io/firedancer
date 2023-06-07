#include "../fd_tests.h"
int test_725(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 90,27,83,127,125,108,62,82,98,114,106,77,121,124,111,87,26,61,15,123,120,105,78,76,89,109,103,79,112,117,55,29,80,33,30,113,128,75,126,122,24,56,118,2,116,92,110 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_from_smaller_sized_account::old_behavior";
  test.test_nonce  = 219;
  test.test_number = 725;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "A6vmuPzHCAF5LmsKHp9wg8ccAtjpm599kJUZNYgYTZyx",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2978881UL;
  test_acc->result_lamports = 2978881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_725_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_725_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_725_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_725_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2siPZWqLv9ydLwKaHFEihsjMZSWNFJmGnC38bVeieF13",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2978880UL;
  test_acc->result_lamports = 2978880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_725_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_725_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_725_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_725_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_725_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_725_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_725_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_725_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_725_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_725_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_726(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 90,27,83,127,125,108,62,82,98,114,106,77,121,124,111,87,26,61,15,123,120,105,78,76,89,109,103,79,112,117,55,29,80,33,30,113,128,75,126,122,24,56,118,2,116,92,110 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_from_smaller_sized_account::old_behavior";
  test.test_nonce  = 267;
  test.test_number = 726;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "A6vmuPzHCAF5LmsKHp9wg8ccAtjpm599kJUZNYgYTZyx",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2978881UL;
  test_acc->result_lamports = 2978881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_726_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_726_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_726_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_726_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2siPZWqLv9ydLwKaHFEihsjMZSWNFJmGnC38bVeieF13",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2978881UL;
  test_acc->result_lamports = 2978881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_726_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_726_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_726_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_726_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_726_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_726_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_726_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_726_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_726_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_726_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_727(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 90,27,83,127,125,108,62,82,98,114,106,77,121,124,111,87,26,61,15,123,120,105,78,76,89,109,103,79,112,117,55,29,80,33,30,113,128,75,126,122,24,56,118,2,116,92,110 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_from_smaller_sized_account::old_behavior";
  test.test_nonce  = 60;
  test.test_number = 727;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "A6vmuPzHCAF5LmsKHp9wg8ccAtjpm599kJUZNYgYTZyx",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2978881UL;
  test_acc->result_lamports = 2978881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_727_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_727_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_727_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_727_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2siPZWqLv9ydLwKaHFEihsjMZSWNFJmGnC38bVeieF13",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_727_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_727_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_727_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_727_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_727_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_727_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_727_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_727_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_727_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_727_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_728(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 82,126,15,127,26,106,123,118,103,30,98,83,78,89,75,105,113,125,33,56,124,24,122,109,80,2,111,61,110,90,77,114,112,92,29,55,128,79,76,120,121,116,62,117,87,27,108 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_full_amount_minimum_stake_delegation::new_behavior";
  test.test_nonce  = 153;
  test.test_number = 728;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111Bs8Haw3nAsWf5hmLfKzc6PMEzcxUCKkVYK",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1002282879UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_728_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_728_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_728_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_728_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111CGTta3M4t3yXu8uRgkKvaWd2d8DQuZLKrf",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 1002282879UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_728_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_728_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_728_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_728_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_728_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_728_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_728_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_728_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_728_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_728_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_729(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 82,126,15,127,26,106,123,118,103,30,98,83,78,89,75,105,113,125,33,56,124,24,122,109,80,2,111,61,110,90,77,114,112,92,29,55,128,79,76,120,121,116,62,117,87,27,108 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_full_amount_minimum_stake_delegation::new_behavior";
  test.test_nonce  = 125;
  test.test_number = 729;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111B4T5ciTCkWauSqVAcVKy88ofjcSamrapud",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1002282879UL;
  test_acc->result_lamports = 1002282879UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_729_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_729_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_729_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_729_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111BTngbpkVTh3nGGdFdufHcG5TN7hXV6AfDy",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_729_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_729_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_729_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_729_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_729_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_729_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_729_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_729_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_729_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_729_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_730(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 82,126,15,127,26,106,123,118,103,30,98,83,78,89,75,105,113,125,33,56,124,24,122,109,80,2,111,61,110,90,77,114,112,92,29,55,128,79,76,120,121,116,62,117,87,27,108 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_full_amount_minimum_stake_delegation::new_behavior";
  test.test_nonce  = 129;
  test.test_number = 730;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111Bs8Haw3nAsWf5hmLfKzc6PMEzcxUCKkVYK",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282879UL;
  test_acc->result_lamports = 2282879UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_730_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_730_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_730_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_730_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111CGTta3M4t3yXu8uRgkKvaWd2d8DQuZLKrf",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_730_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_730_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_730_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_730_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_730_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_730_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_730_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_730_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_730_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_730_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_731(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 82,126,15,127,26,106,123,118,103,30,98,83,78,89,75,105,113,125,33,56,124,24,122,109,80,2,111,61,110,90,77,114,112,92,29,55,128,79,76,120,121,116,62,117,87,27,108 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_full_amount_minimum_stake_delegation::new_behavior";
  test.test_nonce  = 114;
  test.test_number = 731;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111B4T5ciTCkWauSqVAcVKy88ofjcSamrapud",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282879UL;
  test_acc->result_lamports = 2282879UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_731_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_731_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_731_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_731_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111BTngbpkVTh3nGGdFdufHcG5TN7hXV6AfDy",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_731_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_731_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_731_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_731_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_731_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_731_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_731_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_731_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_731_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_731_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_732(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 82,126,15,127,26,106,123,118,103,30,98,83,78,89,75,105,113,125,33,56,124,24,122,109,80,2,111,61,110,90,77,114,112,92,29,55,128,79,76,120,121,116,62,117,87,27,108 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_full_amount_minimum_stake_delegation::new_behavior";
  test.test_nonce  = 99;
  test.test_number = 732;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111Bs8Haw3nAsWf5hmLfKzc6PMEzcxUCKkVYK",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1002282880UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_732_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_732_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_732_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_732_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111CGTta3M4t3yXu8uRgkKvaWd2d8DQuZLKrf",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 1002282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_732_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_732_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_732_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_732_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_732_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_732_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_732_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_732_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_732_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_732_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_733(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 82,126,15,127,26,106,123,118,103,30,98,83,78,89,75,105,113,125,33,56,124,24,122,109,80,2,111,61,110,90,77,114,112,92,29,55,128,79,76,120,121,116,62,117,87,27,108 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_full_amount_minimum_stake_delegation::new_behavior";
  test.test_nonce  = 101;
  test.test_number = 733;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111B4T5ciTCkWauSqVAcVKy88ofjcSamrapud",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1002282880UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_733_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_733_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_733_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_733_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111BTngbpkVTh3nGGdFdufHcG5TN7hXV6AfDy",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 1002282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_733_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_733_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_733_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_733_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_733_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_733_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_733_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_733_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_733_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_733_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_734(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 82,126,15,127,26,106,123,118,103,30,98,83,78,89,75,105,113,125,33,56,124,24,122,109,80,2,111,61,110,90,77,114,112,92,29,55,128,79,76,120,121,116,62,117,87,27,108 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_full_amount_minimum_stake_delegation::new_behavior";
  test.test_nonce  = 67;
  test.test_number = 734;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111Bs8Haw3nAsWf5hmLfKzc6PMEzcxUCKkVYK",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_734_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_734_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_734_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_734_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111CGTta3M4t3yXu8uRgkKvaWd2d8DQuZLKrf",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_734_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_734_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_734_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_734_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_734_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_734_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_734_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_734_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_734_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_734_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_735(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 82,126,15,127,26,106,123,118,103,30,98,83,78,89,75,105,113,125,33,56,124,24,122,109,80,2,111,61,110,90,77,114,112,92,29,55,128,79,76,120,121,116,62,117,87,27,108 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_full_amount_minimum_stake_delegation::new_behavior";
  test.test_nonce  = 72;
  test.test_number = 735;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111B4T5ciTCkWauSqVAcVKy88ofjcSamrapud",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_735_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_735_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_735_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_735_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111BTngbpkVTh3nGGdFdufHcG5TN7hXV6AfDy",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_735_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_735_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_735_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_735_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_735_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_735_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_735_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_735_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_735_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_735_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_736(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_full_amount_minimum_stake_delegation::old_behavior";
  test.test_nonce  = 117;
  test.test_number = 736;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111Bs8Haw3nAsWf5hmLfKzc6PMEzcxUCKkVYK",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282879UL;
  test_acc->result_lamports = 2282879UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_736_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_736_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_736_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_736_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111CGTta3M4t3yXu8uRgkKvaWd2d8DQuZLKrf",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_736_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_736_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_736_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_736_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_736_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_736_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_736_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_736_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_736_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_736_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_737(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 92,111,120,114,61,108,75,30,82,116,124,77,103,118,98,29,83,105,125,55,122,112,128,79,33,121,2,90,117,15,126,127,62,113,24,56,87,26,106,109,110,78,27,123,89,80,76 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_full_amount_minimum_stake_delegation::old_behavior";
  test.test_nonce  = 135;
  test.test_number = 737;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111B4T5ciTCkWauSqVAcVKy88ofjcSamrapud",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282879UL;
  test_acc->result_lamports = 2282879UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_737_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_737_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_737_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_737_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111BTngbpkVTh3nGGdFdufHcG5TN7hXV6AfDy",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_737_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_737_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_737_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_737_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_737_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_737_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_737_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_737_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_737_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_737_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_738(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_full_amount_minimum_stake_delegation::old_behavior";
  test.test_nonce  = 134;
  test.test_number = 738;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111Bs8Haw3nAsWf5hmLfKzc6PMEzcxUCKkVYK",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_738_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_738_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_738_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_738_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111CGTta3M4t3yXu8uRgkKvaWd2d8DQuZLKrf",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_738_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_738_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_738_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_738_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_738_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_738_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_738_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_738_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_738_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_738_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_739(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_full_amount_minimum_stake_delegation::old_behavior";
  test.test_nonce  = 75;
  test.test_number = 739;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111Bs8Haw3nAsWf5hmLfKzc6PMEzcxUCKkVYK",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_739_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_739_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_739_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_739_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111CGTta3M4t3yXu8uRgkKvaWd2d8DQuZLKrf",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_739_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_739_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_739_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_739_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_739_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_739_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_739_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_739_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_739_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_739_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_740(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 92,111,120,114,61,108,75,30,82,116,124,77,103,118,98,29,83,105,125,55,122,112,128,79,33,121,2,90,117,15,126,127,62,113,24,56,87,26,106,109,110,78,27,123,89,80,76 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_full_amount_minimum_stake_delegation::old_behavior";
  test.test_nonce  = 155;
  test.test_number = 740;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111B4T5ciTCkWauSqVAcVKy88ofjcSamrapud",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_740_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_740_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_740_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_740_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111BTngbpkVTh3nGGdFdufHcG5TN7hXV6AfDy",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_740_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_740_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_740_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_740_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_740_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_740_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_740_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_740_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_740_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_740_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_741(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 92,111,120,114,61,108,75,30,82,116,124,77,103,118,98,29,83,105,125,55,122,112,128,79,33,121,2,90,117,15,126,127,62,113,24,56,87,26,106,109,110,78,27,123,89,80,76 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_full_amount_minimum_stake_delegation::old_behavior";
  test.test_nonce  = 66;
  test.test_number = 741;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111B4T5ciTCkWauSqVAcVKy88ofjcSamrapud",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_741_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_741_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_741_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_741_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111BTngbpkVTh3nGGdFdufHcG5TN7hXV6AfDy",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_741_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_741_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_741_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_741_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_741_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_741_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_741_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_741_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_741_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_741_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_742(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_full_amount_minimum_stake_delegation::old_behavior";
  test.test_nonce  = 103;
  test.test_number = 742;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111Bs8Haw3nAsWf5hmLfKzc6PMEzcxUCKkVYK",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282881UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_742_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_742_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_742_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_742_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111CGTta3M4t3yXu8uRgkKvaWd2d8DQuZLKrf",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 2282881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_742_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_742_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_742_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_742_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_742_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_742_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_742_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_742_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_742_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_742_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_743(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 92,111,120,114,61,108,75,30,82,116,124,77,103,118,98,29,83,105,125,55,122,112,128,79,33,121,2,90,117,15,126,127,62,113,24,56,87,26,106,109,110,78,27,123,89,80,76 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_full_amount_minimum_stake_delegation::old_behavior";
  test.test_nonce  = 96;
  test.test_number = 743;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111B4T5ciTCkWauSqVAcVKy88ofjcSamrapud",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282881UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_743_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_743_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_743_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_743_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111BTngbpkVTh3nGGdFdufHcG5TN7hXV6AfDy",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 2282881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_743_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_743_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_743_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_743_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_743_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_743_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_743_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_743_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_743_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_743_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_744(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 105,114,87,116,29,112,90,33,24,55,78,123,113,126,121,106,89,124,108,83,26,127,79,61,128,118,77,120,76,80,30,82,56,27,75,122,103,125,15,62,2,92,117,109,111,110,98 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_minimum_stake_delegation::new_behavior";
  test.test_nonce  = 184;
  test.test_number = 744;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111CfoVZ9eMbESQia3WiAfF4dtpFdUMcnvAB1",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2004565759UL;
  test_acc->result_lamports = 1002282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_744_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_744_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_744_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_744_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111D596YFweJQuHY1BbjazZYmAbt8jJL2VzVM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 1002282879UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_744_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_744_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_744_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_744_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_744_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_744_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_744_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_744_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_744_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_744_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_745(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 105,114,87,116,29,112,90,33,24,55,78,123,113,126,121,106,89,124,108,83,26,127,79,61,128,118,77,120,76,80,30,82,56,27,75,122,103,125,15,62,2,92,117,109,111,110,98 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_minimum_stake_delegation::new_behavior";
  test.test_nonce  = 259;
  test.test_number = 745;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111CfoVZ9eMbESQia3WiAfF4dtpFdUMcnvAB1",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2004565758UL;
  test_acc->result_lamports = 1002282879UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_745_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_745_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_745_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_745_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111D596YFweJQuHY1BbjazZYmAbt8jJL2VzVM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 1002282879UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_745_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_745_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_745_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_745_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_745_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_745_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_745_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_745_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_745_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_745_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_746(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 105,114,87,116,29,112,90,33,24,55,78,123,113,126,121,106,89,124,108,83,26,127,79,61,128,118,77,120,76,80,30,82,56,27,75,122,103,125,15,62,2,92,117,109,111,110,98 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_minimum_stake_delegation::new_behavior";
  test.test_nonce  = 123;
  test.test_number = 746;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111CfoVZ9eMbESQia3WiAfF4dtpFdUMcnvAB1",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2004565759UL;
  test_acc->result_lamports = 2004565759UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_746_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_746_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_746_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_746_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111D596YFweJQuHY1BbjazZYmAbt8jJL2VzVM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_746_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_746_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_746_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_746_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_746_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_746_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_746_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_746_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_746_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_746_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_747(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 105,114,87,116,29,112,90,33,24,55,78,123,113,126,121,106,89,124,108,83,26,127,79,61,128,118,77,120,76,80,30,82,56,27,75,122,103,125,15,62,2,92,117,109,111,110,98 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_minimum_stake_delegation::new_behavior";
  test.test_nonce  = 189;
  test.test_number = 747;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111CfoVZ9eMbESQia3WiAfF4dtpFdUMcnvAB1",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2004565758UL;
  test_acc->result_lamports = 2004565758UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_747_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_747_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_747_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_747_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111D596YFweJQuHY1BbjazZYmAbt8jJL2VzVM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_747_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_747_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_747_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_747_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_747_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_747_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_747_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_747_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_747_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_747_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_748(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 105,114,87,116,29,112,90,33,24,55,78,123,113,126,121,106,89,124,108,83,26,127,79,61,128,118,77,120,76,80,30,82,56,27,75,122,103,125,15,62,2,92,117,109,111,110,98 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_minimum_stake_delegation::new_behavior";
  test.test_nonce  = 152;
  test.test_number = 748;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111CfoVZ9eMbESQia3WiAfF4dtpFdUMcnvAB1",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565759UL;
  test_acc->result_lamports = 4565759UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_748_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_748_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_748_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_748_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111D596YFweJQuHY1BbjazZYmAbt8jJL2VzVM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_748_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_748_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_748_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_748_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_748_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_748_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_748_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_748_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_748_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_748_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_749(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 105,114,87,116,29,112,90,33,24,55,78,123,113,126,121,106,89,124,108,83,26,127,79,61,128,118,77,120,76,80,30,82,56,27,75,122,103,125,15,62,2,92,117,109,111,110,98 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_minimum_stake_delegation::new_behavior";
  test.test_nonce  = 244;
  test.test_number = 749;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111CfoVZ9eMbESQia3WiAfF4dtpFdUMcnvAB1",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565758UL;
  test_acc->result_lamports = 4565758UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_749_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_749_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_749_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_749_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111D596YFweJQuHY1BbjazZYmAbt8jJL2VzVM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_749_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_749_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_749_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_749_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_749_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_749_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_749_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_749_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_749_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_749_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
