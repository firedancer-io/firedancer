#include "../fd_tests.h"
int test_1350(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 29,114,77,87,79,26,75,122,98,62,121,83,118,89,78,125,123,61,126,106,15,124,30,128,90,24,56,103,33,116,27,2,109,127,112,117,110,76,92,108,120,82,55,111,80,105,113 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_stake::old_behavior";
  test.test_nonce  = 550;
  test.test_number = 1350;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 9;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "78CBbBthbyVzayZ8HufuUYQLfKtwQZst1ordJmiGUqxZ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 11UL;
  test_acc->result_lamports = 11UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1350_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1350_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1350_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1350_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "CR2bBXBiKrsszkKwkAzmfGMphMuVdAdYPWV8SViRJah3",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1350_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1350_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1350_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1350_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BjcDvdU8j4Y8cfZZ7XdQ7TgZLJBRZoWPMxCm4CinPGcG",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1350_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1350_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1350_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1350_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "J4JgNJD7KM88cKBzizdoBcnFKJjnUsFcJTwUf9KwSq6H",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1350_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1350_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1350_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1350_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2wBmTv5Smvq1Tp1gxePALodKzi68LJ5KE8tmRFjYUCxG",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1350_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1350_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1350_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1350_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1350_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1350_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1350_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1350_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1350_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1350_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1350_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1350_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1350_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1350_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1350_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1350_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1350_acc_8_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1350_acc_8_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1350_acc_8_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1350_acc_8_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1350_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1350_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1351(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 29,114,77,87,79,26,75,122,98,62,121,83,118,89,78,125,123,61,126,106,15,124,30,128,90,24,56,103,33,116,27,2,109,127,112,117,110,76,92,108,120,82,55,111,80,105,113 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_stake::old_behavior";
  test.test_nonce  = 598;
  test.test_number = 1351;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 9;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "78CBbBthbyVzayZ8HufuUYQLfKtwQZst1ordJmiGUqxZ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 11UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1351_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1351_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1351_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1351_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "CR2bBXBiKrsszkKwkAzmfGMphMuVdAdYPWV8SViRJah3",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1351_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1351_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1351_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1351_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BjcDvdU8j4Y8cfZZ7XdQ7TgZLJBRZoWPMxCm4CinPGcG",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 11UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1351_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1351_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1351_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1351_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "J4JgNJD7KM88cKBzizdoBcnFKJjnUsFcJTwUf9KwSq6H",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1351_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1351_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1351_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1351_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2wBmTv5Smvq1Tp1gxePALodKzi68LJ5KE8tmRFjYUCxG",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1351_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1351_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1351_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1351_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1351_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1351_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1351_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1351_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1351_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1351_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1351_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1351_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1351_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1351_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1351_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1351_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1351_acc_8_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1351_acc_8_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1351_acc_8_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1351_acc_8_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1351_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1351_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1352(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_stake::old_behavior";
  test.test_nonce  = 550;
  test.test_number = 1352;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 9;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "713LmJkBtGtAduiL2A1KmakMQiwjhJDoi3yF1s1giRxY",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 11UL;
  test_acc->result_lamports = 11UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1352_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1352_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1352_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1352_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "A3ABCJbc5bM4HXDC3juo2tLzrNpyaATDvHtdvsvBNV4A",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1352_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1352_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1352_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1352_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BJdbtmhBrPVTfHW7KX3Rvi96i2LDE1VxpiE8eqLpfRrV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1352_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1352_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1352_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1352_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "WhcrHNyjtaXwBbeGeWv5qw4bHpftpG4ZeMbCAALj8eR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1352_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1352_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1352_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1352_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BP39WwKXxrCKdbWFEbzBbJCVtoJyc2YgRpPsomQG2s7C",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1352_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1352_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1352_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1352_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1352_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1352_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1352_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1352_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1352_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1352_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1352_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1352_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1352_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1352_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1352_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1352_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1352_acc_8_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1352_acc_8_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1352_acc_8_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1352_acc_8_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1352_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1352_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1353(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_stake::old_behavior";
  test.test_nonce  = 593;
  test.test_number = 1353;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 9;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "713LmJkBtGtAduiL2A1KmakMQiwjhJDoi3yF1s1giRxY",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 11UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1353_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1353_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1353_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1353_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "A3ABCJbc5bM4HXDC3juo2tLzrNpyaATDvHtdvsvBNV4A",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1353_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1353_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1353_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1353_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BJdbtmhBrPVTfHW7KX3Rvi96i2LDE1VxpiE8eqLpfRrV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 11UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1353_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1353_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1353_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1353_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "WhcrHNyjtaXwBbeGeWv5qw4bHpftpG4ZeMbCAALj8eR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1353_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1353_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1353_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1353_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BP39WwKXxrCKdbWFEbzBbJCVtoJyc2YgRpPsomQG2s7C",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1353_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1353_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1353_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1353_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1353_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1353_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1353_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1353_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1353_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1353_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1353_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1353_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1353_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1353_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1353_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1353_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1353_acc_8_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1353_acc_8_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1353_acc_8_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1353_acc_8_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1353_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1353_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1354(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 29,114,77,87,79,26,75,122,98,62,121,83,118,89,78,125,123,61,126,106,15,124,30,128,90,24,56,103,33,116,27,2,109,127,112,117,110,76,92,108,120,82,55,111,80,105,113 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_stake::old_behavior";
  test.test_nonce  = 586;
  test.test_number = 1354;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 9;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "78CBbBthbyVzayZ8HufuUYQLfKtwQZst1ordJmiGUqxZ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 11UL;
  test_acc->result_lamports = 11UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1354_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1354_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1354_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1354_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "CR2bBXBiKrsszkKwkAzmfGMphMuVdAdYPWV8SViRJah3",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1354_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1354_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1354_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1354_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BjcDvdU8j4Y8cfZZ7XdQ7TgZLJBRZoWPMxCm4CinPGcG",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1354_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1354_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1354_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1354_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "J4JgNJD7KM88cKBzizdoBcnFKJjnUsFcJTwUf9KwSq6H",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1354_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1354_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1354_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1354_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2wBmTv5Smvq1Tp1gxePALodKzi68LJ5KE8tmRFjYUCxG",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1354_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1354_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1354_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1354_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1354_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1354_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1354_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1354_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1354_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1354_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1354_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1354_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1354_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1354_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1354_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1354_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1354_acc_8_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1354_acc_8_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1354_acc_8_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1354_acc_8_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1354_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1354_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1355(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_stake::old_behavior";
  test.test_nonce  = 582;
  test.test_number = 1355;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 9;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "713LmJkBtGtAduiL2A1KmakMQiwjhJDoi3yF1s1giRxY",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 11UL;
  test_acc->result_lamports = 11UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1355_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1355_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1355_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1355_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "A3ABCJbc5bM4HXDC3juo2tLzrNpyaATDvHtdvsvBNV4A",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1355_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1355_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1355_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1355_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BJdbtmhBrPVTfHW7KX3Rvi96i2LDE1VxpiE8eqLpfRrV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1355_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1355_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1355_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1355_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "WhcrHNyjtaXwBbeGeWv5qw4bHpftpG4ZeMbCAALj8eR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1355_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1355_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1355_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1355_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BP39WwKXxrCKdbWFEbzBbJCVtoJyc2YgRpPsomQG2s7C",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1355_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1355_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1355_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1355_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1355_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1355_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1355_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1355_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1355_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1355_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1355_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1355_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1355_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1355_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1355_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1355_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1355_acc_8_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1355_acc_8_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1355_acc_8_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1355_acc_8_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1355_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1355_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1356(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 29,114,77,87,79,26,75,122,98,62,121,83,118,89,78,125,123,61,126,106,15,124,30,128,90,24,56,103,33,116,27,2,109,127,112,117,110,76,92,108,120,82,55,111,80,105,113 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_stake::old_behavior";
  test.test_nonce  = 607;
  test.test_number = 1356;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 9;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "78CBbBthbyVzayZ8HufuUYQLfKtwQZst1ordJmiGUqxZ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000000UL;
  test_acc->result_lamports = 1000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1356_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1356_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1356_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1356_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "CR2bBXBiKrsszkKwkAzmfGMphMuVdAdYPWV8SViRJah3",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1356_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1356_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1356_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1356_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BjcDvdU8j4Y8cfZZ7XdQ7TgZLJBRZoWPMxCm4CinPGcG",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000000UL;
  test_acc->result_lamports = 1000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1356_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1356_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1356_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1356_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "J4JgNJD7KM88cKBzizdoBcnFKJjnUsFcJTwUf9KwSq6H",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1356_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1356_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1356_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1356_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2wBmTv5Smvq1Tp1gxePALodKzi68LJ5KE8tmRFjYUCxG",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1356_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1356_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1356_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1356_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1356_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1356_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1356_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1356_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1356_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1356_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1356_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1356_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1356_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1356_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1356_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1356_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1356_acc_8_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1356_acc_8_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1356_acc_8_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1356_acc_8_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1356_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1356_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1357(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_stake::old_behavior";
  test.test_nonce  = 600;
  test.test_number = 1357;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 9;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "713LmJkBtGtAduiL2A1KmakMQiwjhJDoi3yF1s1giRxY",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000000UL;
  test_acc->result_lamports = 1000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1357_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1357_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1357_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1357_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "A3ABCJbc5bM4HXDC3juo2tLzrNpyaATDvHtdvsvBNV4A",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1357_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1357_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1357_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1357_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BJdbtmhBrPVTfHW7KX3Rvi96i2LDE1VxpiE8eqLpfRrV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000000UL;
  test_acc->result_lamports = 1000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1357_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1357_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1357_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1357_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "WhcrHNyjtaXwBbeGeWv5qw4bHpftpG4ZeMbCAALj8eR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1357_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1357_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1357_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1357_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BP39WwKXxrCKdbWFEbzBbJCVtoJyc2YgRpPsomQG2s7C",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1357_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1357_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1357_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1357_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1357_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1357_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1357_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1357_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1357_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1357_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1357_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1357_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1357_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1357_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1357_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1357_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1357_acc_8_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1357_acc_8_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1357_acc_8_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1357_acc_8_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1357_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1357_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1358(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 29,114,77,87,79,26,75,122,98,62,121,83,118,89,78,125,123,61,126,106,15,124,30,128,90,24,56,103,33,116,27,2,109,127,112,117,110,76,92,108,120,82,55,111,80,105,113 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_stake::old_behavior";
  test.test_nonce  = 571;
  test.test_number = 1358;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 9;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "78CBbBthbyVzayZ8HufuUYQLfKtwQZst1ordJmiGUqxZ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 11UL;
  test_acc->result_lamports = 11UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1358_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1358_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1358_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1358_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "CR2bBXBiKrsszkKwkAzmfGMphMuVdAdYPWV8SViRJah3",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1358_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1358_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1358_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1358_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BjcDvdU8j4Y8cfZZ7XdQ7TgZLJBRZoWPMxCm4CinPGcG",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1358_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1358_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1358_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1358_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "J4JgNJD7KM88cKBzizdoBcnFKJjnUsFcJTwUf9KwSq6H",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1358_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1358_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1358_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1358_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2wBmTv5Smvq1Tp1gxePALodKzi68LJ5KE8tmRFjYUCxG",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1358_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1358_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1358_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1358_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1358_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1358_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1358_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1358_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1358_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1358_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1358_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1358_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1358_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1358_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1358_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1358_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1358_acc_8_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1358_acc_8_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1358_acc_8_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1358_acc_8_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1358_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1358_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1359(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_stake::old_behavior";
  test.test_nonce  = 566;
  test.test_number = 1359;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 9;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "713LmJkBtGtAduiL2A1KmakMQiwjhJDoi3yF1s1giRxY",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 11UL;
  test_acc->result_lamports = 11UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1359_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1359_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1359_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1359_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "A3ABCJbc5bM4HXDC3juo2tLzrNpyaATDvHtdvsvBNV4A",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1359_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1359_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1359_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1359_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BJdbtmhBrPVTfHW7KX3Rvi96i2LDE1VxpiE8eqLpfRrV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1359_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1359_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1359_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1359_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "WhcrHNyjtaXwBbeGeWv5qw4bHpftpG4ZeMbCAALj8eR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1359_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1359_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1359_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1359_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BP39WwKXxrCKdbWFEbzBbJCVtoJyc2YgRpPsomQG2s7C",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1359_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1359_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1359_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1359_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1359_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1359_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1359_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1359_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1359_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1359_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1359_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1359_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1359_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1359_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1359_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1359_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1359_acc_8_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1359_acc_8_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1359_acc_8_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1359_acc_8_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1359_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1359_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1360(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 112,128,109,103,82,78,110,123,75,15,113,29,33,98,116,77,2,108,127,125,87,121,90,24,120,61,92,76,26,118,122,80,30,124,79,105,62,83,55,126,27,114,56,89,117,106,111 };
  test.disable_feature = disabled_features;
  test.test_name = "system_instruction_processor::tests::test_assign";
  test.test_nonce  = 0;
  test.test_number = 1360;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113U8tKsuNo9s5W8DhcKxs8XstiUWegzzvEGhV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1360_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1360_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1360_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1360_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1360_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1360_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1361(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 112,128,109,103,82,78,110,123,75,15,113,29,33,98,116,77,2,108,127,125,87,121,90,24,120,61,92,76,26,118,122,80,30,124,79,105,62,83,55,126,27,114,56,89,117,106,111 };
  test.disable_feature = disabled_features;
  test.test_name = "system_instruction_processor::tests::test_assign";
  test.test_nonce  = 2;
  test.test_number = 1361;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113WbKyQTpK9CwYHj8xzdP3MYH4yKDtvfpjAfZ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1361_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1361_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1361_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1361_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1361_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1361_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1362(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 27,109,55,127,30,29,118,111,105,126,112,122,106,82,116,15,75,77,56,33,113,98,121,76,24,120,89,124,108,90,26,80,117,110,2,103,83,125,87,92,114,61,79,78,128,62,123 };
  test.disable_feature = disabled_features;
  test.test_name = "system_instruction_processor::tests::test_assign";
  test.test_nonce  = 3;
  test.test_number = 1362;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113U8tKsuNo9s5W8DhcKxs8XstiUWegzzvEGhV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1362_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1362_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1362_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1362_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1362_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1362_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1363(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 27,109,55,127,30,29,118,111,105,126,112,122,106,82,116,15,75,77,56,33,113,98,121,76,24,120,89,124,108,90,26,80,117,110,2,103,83,125,87,92,114,61,79,78,128,62,123 };
  test.disable_feature = disabled_features;
  test.test_name = "system_instruction_processor::tests::test_assign";
  test.test_nonce  = 5;
  test.test_number = 1363;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113WbKyQTpK9CwYHj8xzdP3MYH4yKDtvfpjAfZ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1363_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1363_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1363_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1363_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1363_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1363_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1364(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 128,121,15,124,112,114,83,113,77,26,62,109,111,118,75,125,105,120,106,80,123,90,61,55,108,27,82,127,89,126,116,103,87,92,33,30,78,117,110,24,56,2,76,29,79,98,122 };
  test.disable_feature = disabled_features;
  test.test_name = "system_instruction_processor::tests::test_assign";
  test.test_nonce  = 1;
  test.test_number = 1364;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113U8tKsuNo9s5W8DhcKxs8XstiUWegzzvEGhV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1364_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1364_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1364_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1364_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1364_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1364_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1365(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 106,27,110,82,76,83,128,55,78,15,124,105,127,77,122,56,87,26,121,114,126,118,125,75,92,2,103,33,120,111,112,89,109,113,117,24,61,80,79,108,30,98,123,116,62,90,29 };
  test.disable_feature = disabled_features;
  test.test_name = "system_instruction_processor::tests::test_assign";
  test.test_nonce  = 2;
  test.test_number = 1365;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113U8tKsuNo9s5W8DhcKxs8XstiUWegzzvEGhV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1365_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1365_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1365_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1365_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1365_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1365_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1366(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 106,27,110,82,76,83,128,55,78,15,124,105,127,77,122,56,87,26,121,114,126,118,125,75,92,2,103,33,120,111,112,89,109,113,117,24,61,80,79,108,30,98,123,116,62,90,29 };
  test.disable_feature = disabled_features;
  test.test_name = "system_instruction_processor::tests::test_assign";
  test.test_nonce  = 3;
  test.test_number = 1366;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113WbKyQTpK9CwYHj8xzdP3MYH4yKDtvfpjAfZ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1366_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1366_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1366_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1366_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1366_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1366_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1367(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 106,27,110,82,76,83,128,55,78,15,124,105,127,77,122,56,87,26,121,114,126,118,125,75,92,2,103,33,120,111,112,89,109,113,117,24,61,80,79,108,30,98,123,116,62,90,29 };
  test.disable_feature = disabled_features;
  test.test_name = "system_instruction_processor::tests::test_assign";
  test.test_nonce  = 4;
  test.test_number = 1367;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113WbKyQTpK9CwYHj8xzdP3MYH4yKDtvfpjAfZ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1367_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1367_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1367_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1367_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1367_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1367_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1368(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 29,116,87,62,75,108,109,61,92,76,122,114,112,15,126,124,27,125,24,121,98,2,113,123,103,83,90,118,111,79,82,89,105,55,106,127,77,110,128,56,33,78,117,30,120,80,26 };
  test.disable_feature = disabled_features;
  test.test_name = "system_instruction_processor::tests::test_create_account";
  test.test_nonce  = 5;
  test.test_number = 1368;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113VDFiNXCzov3KvytDkktkw3KuR4qdDCDePiw",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 50UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1368_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1368_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1368_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1368_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113VDf3yWKJ6dDnooKMqnK6FXTBChLt9uTEE3H",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 50UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1368_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1368_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1368_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1368_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1368_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1368_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1369(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 29,116,87,62,75,108,109,61,92,76,122,114,112,15,126,124,27,125,24,121,98,2,113,123,103,83,90,118,111,79,82,89,105,55,106,127,77,110,128,56,33,78,117,30,120,80,26 };
  test.disable_feature = disabled_features;
  test.test_name = "system_instruction_processor::tests::test_create_account";
  test.test_nonce  = 0;
  test.test_number = 1369;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113Wa7xbWVRH5Q9fGqYjZ83Q5uFcRi86Y7yfiX",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 50UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1369_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1369_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1369_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1369_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113WaXJCVbiZnacY6GgpaYNia2XQ4DP3FMZW2s",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 50UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1369_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1369_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1369_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1369_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1369_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1369_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1370(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 30,55,110,118,117,116,77,98,79,120,103,87,80,90,26,125,112,105,61,89,83,33,62,2,114,124,92,113,109,56,126,82,27,111,121,128,106,78,123,108,76,15,127,29,122,75,24 };
  test.disable_feature = disabled_features;
  test.test_name = "system_instruction_processor::tests::test_create_account_with_seed_missing_sig";
  test.test_nonce  = 4;
  test.test_number = 1370;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113VETjBUXtg3aiZSBe1q9ktVhimxMQ3KvPtfy",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1370_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1370_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1370_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1370_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "D5JzgNbNVwnMkNZxDa1hn5MwejnnnBrq6XcbenctAWHR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1370_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1370_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1370_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1370_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1370_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1370_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1371(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 30,55,110,118,117,116,77,98,79,120,103,87,80,90,26,125,112,105,61,89,83,33,62,2,114,124,92,113,109,56,126,82,27,111,121,128,106,78,123,108,76,15,127,29,122,75,24 };
  test.disable_feature = disabled_features;
  test.test_name = "system_instruction_processor::tests::test_create_account_with_seed_missing_sig";
  test.test_nonce  = 1;
  test.test_number = 1371;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113WavdoUi1rVm5Quhpubxi349oBgidyxb9LMD",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1371_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1371_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1371_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1371_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "H631k9PwfCFMiAyPeMNi6wE7EWAoovk6EBE3BsaxFWC6",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1371_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1371_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1371_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1371_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1371_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1371_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1372(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 113,106,118,121,108,80,90,83,126,30,27,110,116,76,109,122,111,77,120,33,87,75,127,112,2,61,89,29,79,24,98,114,15,123,56,103,128,125,124,55,117,82,26,78,105,62,92 };
  test.disable_feature = disabled_features;
  test.test_name = "system_instruction_processor::tests::test_create_account_with_seed";
  test.test_nonce  = 6;
  test.test_number = 1372;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113VE4PaVRbPLQFgckVvojRa1aSzKr96cgp4Md",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 50UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1372_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1372_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1372_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1372_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "AGkK16FNw2mHre7XJTFpARdg3QQbDGWYcgXg2WH2em7F",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 50UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1372_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1372_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1372_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1372_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1372_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1372_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1373(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 113,106,118,121,108,80,90,83,126,30,27,110,116,76,109,122,111,77,120,33,87,75,127,112,2,61,89,29,79,24,98,114,15,123,56,103,128,125,124,55,117,82,26,78,105,62,92 };
  test.disable_feature = disabled_features;
  test.test_name = "system_instruction_processor::tests::test_create_account_with_seed";
  test.test_nonce  = 7;
  test.test_number = 1373;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113WcwKpQFWJ3fPnzsXLj4NdUnA7qEvhWm4Vvw",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 50UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1373_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1373_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1373_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1373_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "HUaY3suvBgxq7v7LGLQ8CUwfrvGmGBMYH9nYopC6ba4Z",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 50UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1373_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1373_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1373_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1373_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1373_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1373_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1374(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 90,33,128,116,127,75,121,24,120,83,87,109,112,56,62,103,26,77,89,82,114,124,113,105,30,29,110,27,106,79,80,125,61,123,2,76,55,111,98,122,78,126,15,92,117,118,108 };
  test.disable_feature = disabled_features;
  test.test_name = "system_instruction_processor::tests::test_create_account_with_seed_separate_base_account";
  test.test_nonce  = 14;
  test.test_number = 1374;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111113VEs4nTeBxkmBSFcn6ra6CypzZarez39yizK",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 50UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1374_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1374_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1374_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1374_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "7EY6dFfFVZeQE1rhHswTc4QTf1BkUZ5DtG2HZeodQmJF",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 50UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1374_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1374_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1374_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1374_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111113VFGQPSkVFTweK53vBszRXTxGMDMuvkPZZJf",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1374_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1374_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1374_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1374_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1374_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1374_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
