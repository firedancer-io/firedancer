#include "../fd_tests.h"
int test_100(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 111,62,30,126,77,120,114,87,110,89,83,98,76,33,116,29,127,103,26,15,118,108,79,112,55,121,106,122,92,117,124,75,105,61,125,128,123,2,24,27,113,56,109,82,90,80,78 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_authorize::new_behavior";
  test.test_nonce  = 490;
  test.test_number = 100;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "9dE87NP2Zugo1y1Hs6iYeEpRSF2LDCJ6AMACVZgoc8Gc",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_100_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_100_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_100_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_100_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BomyPTfQy5iKq6Pfn5mhhFKggL2SW7GYg7dyyS8dJF1G",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 43UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_100_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_100_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_100_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_100_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "ENq3xcfiAERckBGEpu2NFFCcUStTDyMtDBhzjHTBWTiK",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_100_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_100_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_100_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_100_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_100_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_100_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_100_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_100_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_100_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_100_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_100_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_100_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_100_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_100_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_101(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 111,62,30,126,77,120,114,87,110,89,83,98,76,33,116,29,127,103,26,15,118,108,79,112,55,121,106,122,92,117,124,75,105,61,125,128,123,2,24,27,113,56,109,82,90,80,78 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_authorize::new_behavior";
  test.test_nonce  = 534;
  test.test_number = 101;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "9dE87NP2Zugo1y1Hs6iYeEpRSF2LDCJ6AMACVZgoc8Gc",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_101_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_101_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_101_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_101_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BomyPTfQy5iKq6Pfn5mhhFKggL2SW7GYg7dyyS8dJF1G",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_101_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_101_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_101_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_101_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "ENq3xcfiAERckBGEpu2NFFCcUStTDyMtDBhzjHTBWTiK",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_101_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_101_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_101_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_101_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_101_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_101_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_101_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_101_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_101_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_101_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_101_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_101_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_101_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_101_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_102(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_authorize::old_behavior";
  test.test_nonce  = 381;
  test.test_number = 102;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "6tjMZQJpks7trBmtNLvv9WocqWwXAzYs1aX3YrYa3Znw",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_102_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_102_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_102_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_102_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "3x8szBYtMvXVyBUW64BBBfJwm7yDZGF93kG4RpQHWxBj",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_102_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_102_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_102_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_102_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "DvS8QM5B5hms7AJJLvtahEMXTCJQFvbGAFr9RkmoMKrf",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_102_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_102_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_102_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_102_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_102_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_102_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_102_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_102_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_102_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_102_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_102_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_102_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_102_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_102_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_103(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_authorize::old_behavior";
  test.test_nonce  = 442;
  test.test_number = 103;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "6tjMZQJpks7trBmtNLvv9WocqWwXAzYs1aX3YrYa3Znw",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_103_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_103_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_103_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_103_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "3x8szBYtMvXVyBUW64BBBfJwm7yDZGF93kG4RpQHWxBj",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_103_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_103_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_103_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_103_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "DvS8QM5B5hms7AJJLvtahEMXTCJQFvbGAFr9RkmoMKrf",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_103_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_103_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_103_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_103_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_103_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_103_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_103_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_103_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_103_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_103_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_103_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_103_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_103_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_103_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_104(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 126,120,87,112,24,61,114,79,83,127,29,113,121,122,78,26,118,123,55,108,76,105,62,109,80,128,82,98,90,30,116,92,15,124,33,75,106,103,77,111,117,89,110,125,2,56,27 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_authorize::old_behavior";
  test.test_nonce  = 160;
  test.test_number = 104;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "8aiZQANymkikdHLQGFkZPK4d76CvFvKphii5FraFUCXw",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_104_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_104_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_104_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_104_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "8fPyhmTb6LE8ao2SKVi97My5HvLh5StaS7vbdSxQEjqN",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_104_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_104_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_104_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_104_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "4euoZZzfTGDZeeCx8yArJWsVMpKargpdCXF5g32yAg19",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_104_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_104_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_104_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_104_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_104_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_104_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_104_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_104_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_104_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_104_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_104_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_104_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_104_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_104_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_105(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 126,120,87,112,24,61,114,79,83,127,29,113,121,122,78,26,118,123,55,108,76,105,62,109,80,128,82,98,90,30,116,92,15,124,33,75,106,103,77,111,117,89,110,125,2,56,27 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_authorize::old_behavior";
  test.test_nonce  = 5;
  test.test_number = 105;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "8aiZQANymkikdHLQGFkZPK4d76CvFvKphii5FraFUCXw",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_105_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_105_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_105_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_105_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "8fPyhmTb6LE8ao2SKVi97My5HvLh5StaS7vbdSxQEjqN",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_105_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_105_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_105_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_105_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "4euoZZzfTGDZeeCx8yArJWsVMpKargpdCXF5g32yAg19",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_105_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_105_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_105_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_105_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_105_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_105_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_105_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_105_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_105_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_105_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_105_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_105_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_105_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_105_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_106(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 126,120,87,112,24,61,114,79,83,127,29,113,121,122,78,26,118,123,55,108,76,105,62,109,80,128,82,98,90,30,116,92,15,124,33,75,106,103,77,111,117,89,110,125,2,56,27 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_authorize::old_behavior";
  test.test_nonce  = 239;
  test.test_number = 106;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "8aiZQANymkikdHLQGFkZPK4d76CvFvKphii5FraFUCXw",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_106_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_106_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_106_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_106_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "8fPyhmTb6LE8ao2SKVi97My5HvLh5StaS7vbdSxQEjqN",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_106_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_106_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_106_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_106_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "4euoZZzfTGDZeeCx8yArJWsVMpKargpdCXF5g32yAg19",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_106_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_106_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_106_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_106_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_106_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_106_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_106_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_106_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_106_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_106_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_106_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_106_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_106_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_106_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_107(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 126,120,87,112,24,61,114,79,83,127,29,113,121,122,78,26,118,123,55,108,76,105,62,109,80,128,82,98,90,30,116,92,15,124,33,75,106,103,77,111,117,89,110,125,2,56,27 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_authorize::old_behavior";
  test.test_nonce  = 336;
  test.test_number = 107;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "8aiZQANymkikdHLQGFkZPK4d76CvFvKphii5FraFUCXw",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_107_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_107_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_107_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_107_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "8fPyhmTb6LE8ao2SKVi97My5HvLh5StaS7vbdSxQEjqN",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_107_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_107_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_107_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_107_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "4euoZZzfTGDZeeCx8yArJWsVMpKargpdCXF5g32yAg19",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_107_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_107_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_107_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_107_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_107_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_107_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_107_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_107_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_107_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_107_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_107_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_107_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_107_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_107_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_108(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 126,120,87,112,24,61,114,79,83,127,29,113,121,122,78,26,118,123,55,108,76,105,62,109,80,128,82,98,90,30,116,92,15,124,33,75,106,103,77,111,117,89,110,125,2,56,27 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_authorize::old_behavior";
  test.test_nonce  = 387;
  test.test_number = 108;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "8aiZQANymkikdHLQGFkZPK4d76CvFvKphii5FraFUCXw",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_108_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_108_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_108_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_108_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "8fPyhmTb6LE8ao2SKVi97My5HvLh5StaS7vbdSxQEjqN",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_108_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_108_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_108_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_108_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "4euoZZzfTGDZeeCx8yArJWsVMpKargpdCXF5g32yAg19",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_108_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_108_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_108_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_108_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_108_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_108_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_108_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_108_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_108_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_108_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_108_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_108_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_108_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_108_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_109(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_authorize::old_behavior";
  test.test_nonce  = 162;
  test.test_number = 109;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "6tjMZQJpks7trBmtNLvv9WocqWwXAzYs1aX3YrYa3Znw",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_109_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_109_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_109_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_109_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "3x8szBYtMvXVyBUW64BBBfJwm7yDZGF93kG4RpQHWxBj",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_109_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_109_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_109_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_109_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "DvS8QM5B5hms7AJJLvtahEMXTCJQFvbGAFr9RkmoMKrf",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_109_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_109_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_109_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_109_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_109_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_109_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_109_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_109_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_109_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_109_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_109_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_109_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_109_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_109_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_110(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_authorize::old_behavior";
  test.test_nonce  = 1;
  test.test_number = 110;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "6tjMZQJpks7trBmtNLvv9WocqWwXAzYs1aX3YrYa3Znw",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_110_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_110_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_110_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_110_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "3x8szBYtMvXVyBUW64BBBfJwm7yDZGF93kG4RpQHWxBj",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_110_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_110_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_110_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_110_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "DvS8QM5B5hms7AJJLvtahEMXTCJQFvbGAFr9RkmoMKrf",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_110_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_110_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_110_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_110_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_110_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_110_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_110_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_110_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_110_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_110_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_110_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_110_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_110_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_110_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_111(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_authorize::old_behavior";
  test.test_nonce  = 295;
  test.test_number = 111;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "6tjMZQJpks7trBmtNLvv9WocqWwXAzYs1aX3YrYa3Znw",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_111_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_111_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_111_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_111_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "3x8szBYtMvXVyBUW64BBBfJwm7yDZGF93kG4RpQHWxBj",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_111_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_111_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_111_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_111_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "DvS8QM5B5hms7AJJLvtahEMXTCJQFvbGAFr9RkmoMKrf",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_111_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_111_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_111_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_111_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_111_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_111_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_111_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_111_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_111_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_111_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_111_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_111_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_111_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_111_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_112(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_authorize::old_behavior";
  test.test_nonce  = 493;
  test.test_number = 112;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "6tjMZQJpks7trBmtNLvv9WocqWwXAzYs1aX3YrYa3Znw",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_112_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_112_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_112_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_112_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "3x8szBYtMvXVyBUW64BBBfJwm7yDZGF93kG4RpQHWxBj",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 43UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_112_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_112_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_112_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_112_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "DvS8QM5B5hms7AJJLvtahEMXTCJQFvbGAFr9RkmoMKrf",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_112_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_112_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_112_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_112_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_112_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_112_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_112_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_112_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_112_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_112_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_112_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_112_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_112_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_112_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_113(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_authorize::old_behavior";
  test.test_nonce  = 536;
  test.test_number = 113;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "6tjMZQJpks7trBmtNLvv9WocqWwXAzYs1aX3YrYa3Znw",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_113_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_113_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_113_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_113_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "3x8szBYtMvXVyBUW64BBBfJwm7yDZGF93kG4RpQHWxBj",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_113_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_113_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_113_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_113_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "DvS8QM5B5hms7AJJLvtahEMXTCJQFvbGAFr9RkmoMKrf",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_113_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_113_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_113_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_113_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_113_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_113_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_113_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_113_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_113_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_113_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_113_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_113_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_113_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_113_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_114(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 126,120,87,112,24,61,114,79,83,127,29,113,121,122,78,26,118,123,55,108,76,105,62,109,80,128,82,98,90,30,116,92,15,124,33,75,106,103,77,111,117,89,110,125,2,56,27 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_authorize::old_behavior";
  test.test_nonce  = 447;
  test.test_number = 114;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "8aiZQANymkikdHLQGFkZPK4d76CvFvKphii5FraFUCXw",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_114_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_114_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_114_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_114_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "8fPyhmTb6LE8ao2SKVi97My5HvLh5StaS7vbdSxQEjqN",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 43UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_114_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_114_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_114_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_114_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "4euoZZzfTGDZeeCx8yArJWsVMpKargpdCXF5g32yAg19",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_114_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_114_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_114_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_114_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_114_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_114_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_114_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_114_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_114_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_114_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_114_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_114_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_114_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_114_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_115(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 126,120,87,112,24,61,114,79,83,127,29,113,121,122,78,26,118,123,55,108,76,105,62,109,80,128,82,98,90,30,116,92,15,124,33,75,106,103,77,111,117,89,110,125,2,56,27 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_authorize::old_behavior";
  test.test_nonce  = 494;
  test.test_number = 115;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "8aiZQANymkikdHLQGFkZPK4d76CvFvKphii5FraFUCXw",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_115_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_115_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_115_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_115_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "8fPyhmTb6LE8ao2SKVi97My5HvLh5StaS7vbdSxQEjqN",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_115_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_115_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_115_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_115_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "4euoZZzfTGDZeeCx8yArJWsVMpKargpdCXF5g32yAg19",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_115_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_115_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_115_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_115_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_115_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_115_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_115_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_115_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_115_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_115_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_115_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_115_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_115_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_115_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_116(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 124,92,125,61,78,89,117,114,103,113,83,15,87,128,120,116,76,90,109,77,75,122,55,62,30,105,111,82,56,26,79,110,106,118,98,121,33,112,108,29,126,127,2,123,27,80,24 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_authorize_override::new_behavior";
  test.test_nonce  = 45;
  test.test_number = 116;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "BF1zyfcd411FVZkLPE8xEE3YRYPggG2Huy2tPgnGc6wF",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_116_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_116_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_116_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_116_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "8bxAPvRsdc9Uf3az4HZZJbNrqdLHZ9B5U8NhDLPgvDgu",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_116_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_116_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_116_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_116_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_116_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_116_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_116_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_116_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_116_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_116_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_117(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 124,92,125,61,78,89,117,114,103,113,83,15,87,128,120,116,76,90,109,77,75,122,55,62,30,105,111,82,56,26,79,110,106,118,98,121,33,112,108,29,126,127,2,123,27,80,24 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_authorize_override::new_behavior";
  test.test_nonce  = 18;
  test.test_number = 117;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "9KE9CYxji5WJJt6jiMfeV41zntEbNv7FZCsKB1TyZ56P",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_117_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_117_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_117_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_117_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "ApbwCvbaVcpdM9Q1x3DKFstmuisYTgWmdqV3E21buzJR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_117_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_117_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_117_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_117_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_117_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_117_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_117_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_117_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_117_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_117_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_118(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 124,92,125,61,78,89,117,114,103,113,83,15,87,128,120,116,76,90,109,77,75,122,55,62,30,105,111,82,56,26,79,110,106,118,98,121,33,112,108,29,126,127,2,123,27,80,24 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_authorize_override::new_behavior";
  test.test_nonce  = 15;
  test.test_number = 118;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "BF1zyfcd411FVZkLPE8xEE3YRYPggG2Huy2tPgnGc6wF",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_118_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_118_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_118_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_118_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "8bxAPvRsdc9Uf3az4HZZJbNrqdLHZ9B5U8NhDLPgvDgu",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_118_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_118_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_118_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_118_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_118_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_118_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_118_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_118_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_118_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_118_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_119(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 124,92,125,61,78,89,117,114,103,113,83,15,87,128,120,116,76,90,109,77,75,122,55,62,30,105,111,82,56,26,79,110,106,118,98,121,33,112,108,29,126,127,2,123,27,80,24 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_authorize_override::new_behavior";
  test.test_nonce  = 75;
  test.test_number = 119;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "BF1zyfcd411FVZkLPE8xEE3YRYPggG2Huy2tPgnGc6wF",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_119_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_119_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_119_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_119_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "8bxAPvRsdc9Uf3az4HZZJbNrqdLHZ9B5U8NhDLPgvDgu",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_119_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_119_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_119_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_119_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_119_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_119_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_119_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_119_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_119_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_119_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_120(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 124,92,125,61,78,89,117,114,103,113,83,15,87,128,120,116,76,90,109,77,75,122,55,62,30,105,111,82,56,26,79,110,106,118,98,121,33,112,108,29,126,127,2,123,27,80,24 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_authorize_override::new_behavior";
  test.test_nonce  = 114;
  test.test_number = 120;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "BF1zyfcd411FVZkLPE8xEE3YRYPggG2Huy2tPgnGc6wF",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_120_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_120_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_120_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_120_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "8bxAPvRsdc9Uf3az4HZZJbNrqdLHZ9B5U8NhDLPgvDgu",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_120_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_120_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_120_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_120_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_120_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_120_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_120_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_120_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_120_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_120_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_121(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 124,92,125,61,78,89,117,114,103,113,83,15,87,128,120,116,76,90,109,77,75,122,55,62,30,105,111,82,56,26,79,110,106,118,98,121,33,112,108,29,126,127,2,123,27,80,24 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_authorize_override::new_behavior";
  test.test_nonce  = 95;
  test.test_number = 121;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "BF1zyfcd411FVZkLPE8xEE3YRYPggG2Huy2tPgnGc6wF",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_121_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_121_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_121_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_121_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "8bxAPvRsdc9Uf3az4HZZJbNrqdLHZ9B5U8NhDLPgvDgu",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_121_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_121_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_121_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_121_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_121_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_121_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_121_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_121_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_121_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_121_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_122(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 124,92,125,61,78,89,117,114,103,113,83,15,87,128,120,116,76,90,109,77,75,122,55,62,30,105,111,82,56,26,79,110,106,118,98,121,33,112,108,29,126,127,2,123,27,80,24 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_authorize_override::new_behavior";
  test.test_nonce  = 37;
  test.test_number = 122;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "9KE9CYxji5WJJt6jiMfeV41zntEbNv7FZCsKB1TyZ56P",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_122_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_122_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_122_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_122_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "ApbwCvbaVcpdM9Q1x3DKFstmuisYTgWmdqV3E21buzJR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_122_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_122_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_122_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_122_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_122_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_122_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_122_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_122_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_122_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_122_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_123(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 124,92,125,61,78,89,117,114,103,113,83,15,87,128,120,116,76,90,109,77,75,122,55,62,30,105,111,82,56,26,79,110,106,118,98,121,33,112,108,29,126,127,2,123,27,80,24 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_authorize_override::new_behavior";
  test.test_nonce  = 3;
  test.test_number = 123;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "9KE9CYxji5WJJt6jiMfeV41zntEbNv7FZCsKB1TyZ56P",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_123_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_123_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_123_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_123_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "ApbwCvbaVcpdM9Q1x3DKFstmuisYTgWmdqV3E21buzJR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_123_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_123_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_123_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_123_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_123_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_123_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_123_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_123_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_123_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_123_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_124(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 124,92,125,61,78,89,117,114,103,113,83,15,87,128,120,116,76,90,109,77,75,122,55,62,30,105,111,82,56,26,79,110,106,118,98,121,33,112,108,29,126,127,2,123,27,80,24 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_authorize_override::new_behavior";
  test.test_nonce  = 46;
  test.test_number = 124;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "9KE9CYxji5WJJt6jiMfeV41zntEbNv7FZCsKB1TyZ56P",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_124_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_124_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_124_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_124_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "ApbwCvbaVcpdM9Q1x3DKFstmuisYTgWmdqV3E21buzJR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_124_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_124_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_124_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_124_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_124_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_124_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_124_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_124_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_124_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_124_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
