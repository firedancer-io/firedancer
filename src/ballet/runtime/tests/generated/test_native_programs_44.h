#include "../fd_tests.h"
int test_1100(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 83,89,82,125,2,15,90,56,103,79,55,120,122,98,61,110,118,117,87,30,26,29,62,123,113,126,111,106,27,108,78,121,116,76,114,109,92,80,75,33,124,24,105,128,77,127,112 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_staked_split_destination_minimum_balance::old_behavior";
  test.test_nonce  = 398;
  test.test_number = 1100;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111Wn1ds34KYMHqX5KQp3eatH9DaL4ocLAeQX",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 18446744073709551615UL;
  test_acc->result_lamports = 18446744073707268735UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1100_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1100_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1100_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1100_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111XBMEr9McFXkiLWTVqTyuNQR1CqKkKZkUis",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 2282881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1100_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1100_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1100_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1100_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1100_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1100_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1100_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1100_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1100_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1100_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1101(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 83,89,82,125,2,15,90,56,103,79,55,120,122,98,61,110,118,117,87,30,26,29,62,123,113,126,111,106,27,108,78,121,116,76,114,109,92,80,75,33,124,24,105,128,77,127,112 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_staked_split_destination_minimum_balance::old_behavior";
  test.test_nonce  = 460;
  test.test_number = 1101;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111Wn1ds34KYMHqX5KQp3eatH9DaL4ocLAeQX",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 18446744073709551615UL;
  test_acc->result_lamports = 18446744073709551615UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1101_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1101_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1101_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1101_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111XBMEr9McFXkiLWTVqTyuNQR1CqKkKZkUis",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1101_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1101_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1101_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1101_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1101_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1101_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1101_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1101_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1101_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1101_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1102(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_staked_split_destination_minimum_balance::old_behavior";
  test.test_nonce  = 390;
  test.test_number = 1102;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111YPN3oUFUP59LnoskuiyrpnEN6M6aTGVyfu",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 18446744073709551615UL;
  test_acc->result_lamports = 18446744073707268734UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1102_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1102_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1102_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1102_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111YnhenaYm6FcDcF1qw9KBJuW9irMXAW5ozF",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 2282881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1102_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1102_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1102_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1102_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1102_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1102_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1102_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1102_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1102_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1102_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1103(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 83,89,82,125,2,15,90,56,103,79,55,120,122,98,61,110,118,117,87,30,26,29,62,123,113,126,111,106,27,108,78,121,116,76,114,109,92,80,75,33,124,24,105,128,77,127,112 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_staked_split_destination_minimum_balance::old_behavior";
  test.test_nonce  = 439;
  test.test_number = 1103;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111Wn1ds34KYMHqX5KQp3eatH9DaL4ocLAeQX",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 18446744073709551615UL;
  test_acc->result_lamports = 18446744073707268734UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1103_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1103_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1103_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1103_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111XBMEr9McFXkiLWTVqTyuNQR1CqKkKZkUis",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 2282881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1103_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1103_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1103_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1103_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1103_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1103_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1103_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1103_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1103_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1103_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1104(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 120,92,98,105,2,124,108,113,106,80,125,27,15,75,126,103,116,114,128,83,76,109,87,26,118,117,122,30,79,61,110,127,33,24,62,82,29,77,56,121,112,55,78,89,90,123,111 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_get_minimum_delegation::new_behavior";
  test.test_nonce  = 132;
  test.test_number = 1104;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111NKuyBkoGdZZSLyPbJEetheRhMjezgQv9mH",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1104_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1104_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1104_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1104_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1104_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1104_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1105(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 120,92,98,105,2,124,108,113,106,80,125,27,15,75,126,103,116,114,128,83,76,109,87,26,118,117,122,30,79,61,110,127,33,24,62,82,29,77,56,121,112,55,78,89,90,123,111 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_get_minimum_delegation::new_behavior";
  test.test_nonce  = 169;
  test.test_number = 1105;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111NKuyBkoGdZZSLyPbJEetheRhMjezgQv9mH",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1105_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1105_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1105_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1105_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1105_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1105_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1106(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_get_minimum_delegation::old_behavior";
  test.test_nonce  = 171;
  test.test_number = 1106;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111NjFaAs6ZLk2KAQXgKezDBmhUzEuwPeVz5d",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1106_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1106_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1106_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1106_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1106_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1106_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1107(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 33,114,120,123,108,112,27,122,56,92,82,110,26,77,124,89,128,121,76,109,83,125,79,78,118,126,116,62,15,24,103,127,87,75,80,117,29,90,113,111,55,61,30,98,106,105,2 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_get_minimum_delegation::old_behavior";
  test.test_nonce  = 158;
  test.test_number = 1107;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111NjFaAs6ZLk2KAQXgKezDBmhUzEuwPeVz5d",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1107_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1107_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1107_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1107_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1107_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1107_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1108(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 33,114,120,123,108,112,27,122,56,92,82,110,26,77,124,89,128,121,76,109,83,125,79,78,118,126,116,62,15,24,103,127,87,75,80,117,29,90,113,111,55,61,30,98,106,105,2 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_initialize::new_behavior";
  test.test_nonce  = 233;
  test.test_number = 1108;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "FmwyArjV9pQM136ZQSG3qEqbTng593brT3hvLFf2LnMu",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1108_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1108_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1108_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1108_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1108_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1108_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1108_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1108_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1108_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1108_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1109(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 33,114,120,123,108,112,27,122,56,92,82,110,26,77,124,89,128,121,76,109,83,125,79,78,118,126,116,62,15,24,103,127,87,75,80,117,29,90,113,111,55,61,30,98,106,105,2 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_initialize::new_behavior";
  test.test_nonce  = 281;
  test.test_number = 1109;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "FmwyArjV9pQM136ZQSG3qEqbTng593brT3hvLFf2LnMu",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1109_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1109_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1109_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1109_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1109_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1109_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1109_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1109_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1109_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1109_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1110(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 33,114,120,123,108,112,27,122,56,92,82,110,26,77,124,89,128,121,76,109,83,125,79,78,118,126,116,62,15,24,103,127,87,75,80,117,29,90,113,111,55,61,30,98,106,105,2 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_initialize::new_behavior";
  test.test_nonce  = 296;
  test.test_number = 1110;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "FmwyArjV9pQM136ZQSG3qEqbTng593brT3hvLFf2LnMu",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1110_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1110_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1110_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1110_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1110_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1110_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1110_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1110_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1110_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1110_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1111(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 33,114,120,123,108,112,27,122,56,92,82,110,26,77,124,89,128,121,76,109,83,125,79,78,118,126,116,62,15,24,103,127,87,75,80,117,29,90,113,111,55,61,30,98,106,105,2 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_initialize::new_behavior";
  test.test_nonce  = 317;
  test.test_number = 1111;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "FmwyArjV9pQM136ZQSG3qEqbTng593brT3hvLFf2LnMu",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1111_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1111_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1111_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1111_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1111_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1111_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1111_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1111_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1111_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1111_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1112(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 33,114,120,123,108,112,27,122,56,92,82,110,26,77,124,89,128,121,76,109,83,125,79,78,118,126,116,62,15,24,103,127,87,75,80,117,29,90,113,111,55,61,30,98,106,105,2 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_initialize::new_behavior";
  test.test_nonce  = 323;
  test.test_number = 1112;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "FmwyArjV9pQM136ZQSG3qEqbTng593brT3hvLFf2LnMu",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1112_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1112_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1112_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1112_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1112_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1112_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1112_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1112_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1112_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1112_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1113(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 2,103,33,106,27,123,117,98,126,111,128,76,121,114,122,127,24,116,83,79,80,109,56,120,113,77,26,62,92,78,125,82,30,105,29,110,112,61,118,89,75,55,15,108,124,90,87 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_initialize::new_behavior";
  test.test_nonce  = 206;
  test.test_number = 1113;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "JBvyEpXGVozuwzqnvS5KGmuX55ULMsWJQHcD9U2s1jiJ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1113_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1113_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1113_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1113_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1113_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1113_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1113_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1113_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1113_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1113_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1114(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 2,103,33,106,27,123,117,98,126,111,128,76,121,114,122,127,24,116,83,79,80,109,56,120,113,77,26,62,92,78,125,82,30,105,29,110,112,61,118,89,75,55,15,108,124,90,87 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_initialize::new_behavior";
  test.test_nonce  = 238;
  test.test_number = 1114;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "JBvyEpXGVozuwzqnvS5KGmuX55ULMsWJQHcD9U2s1jiJ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1114_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1114_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1114_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1114_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1114_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1114_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1114_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1114_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1114_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1114_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1115(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 2,103,33,106,27,123,117,98,126,111,128,76,121,114,122,127,24,116,83,79,80,109,56,120,113,77,26,62,92,78,125,82,30,105,29,110,112,61,118,89,75,55,15,108,124,90,87 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_initialize::new_behavior";
  test.test_nonce  = 270;
  test.test_number = 1115;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "JBvyEpXGVozuwzqnvS5KGmuX55ULMsWJQHcD9U2s1jiJ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1115_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1115_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1115_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1115_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1115_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1115_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1115_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1115_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1115_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1115_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1116(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 2,103,33,106,27,123,117,98,126,111,128,76,121,114,122,127,24,116,83,79,80,109,56,120,113,77,26,62,92,78,125,82,30,105,29,110,112,61,118,89,75,55,15,108,124,90,87 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_initialize::new_behavior";
  test.test_nonce  = 283;
  test.test_number = 1116;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "JBvyEpXGVozuwzqnvS5KGmuX55ULMsWJQHcD9U2s1jiJ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1116_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1116_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1116_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1116_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1116_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1116_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1116_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1116_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1116_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1116_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1117(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 2,103,33,106,27,123,117,98,126,111,128,76,121,114,122,127,24,116,83,79,80,109,56,120,113,77,26,62,92,78,125,82,30,105,29,110,112,61,118,89,75,55,15,108,124,90,87 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_initialize::new_behavior";
  test.test_nonce  = 305;
  test.test_number = 1117;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "JBvyEpXGVozuwzqnvS5KGmuX55ULMsWJQHcD9U2s1jiJ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1117_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1117_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1117_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1117_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1117_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1117_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1117_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1117_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1117_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1117_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1118(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 113,78,30,24,26,98,106,29,33,82,117,80,55,122,76,2,109,75,128,124,89,116,27,111,108,126,105,61,79,112,92,83,123,90,15,77,127,120,62,87,125,110,114,103,56,118,121 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_initialize::old_behavior";
  test.test_nonce  = 278;
  test.test_number = 1118;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "9VeZJE4mGRLaZt9DdBaGshLVeJKTG8wxu5rTHYyJemW2",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1118_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1118_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1118_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1118_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1118_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1118_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1118_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1118_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1118_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1118_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1119(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 113,78,30,24,26,98,106,29,33,82,117,80,55,122,76,2,109,75,128,124,89,116,27,111,108,126,105,61,79,112,92,83,123,90,15,77,127,120,62,87,125,110,114,103,56,118,121 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_initialize::old_behavior";
  test.test_nonce  = 298;
  test.test_number = 1119;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "9VeZJE4mGRLaZt9DdBaGshLVeJKTG8wxu5rTHYyJemW2",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1119_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1119_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1119_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1119_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1119_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1119_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1119_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1119_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1119_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1119_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1120(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 113,78,30,24,26,98,106,29,33,82,117,80,55,122,76,2,109,75,128,124,89,116,27,111,108,126,105,61,79,112,92,83,123,90,15,77,127,120,62,87,125,110,114,103,56,118,121 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_initialize::old_behavior";
  test.test_nonce  = 313;
  test.test_number = 1120;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "9VeZJE4mGRLaZt9DdBaGshLVeJKTG8wxu5rTHYyJemW2",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1120_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1120_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1120_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1120_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1120_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1120_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1120_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1120_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1120_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1120_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1121(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 113,78,30,24,26,98,106,29,33,82,117,80,55,122,76,2,109,75,128,124,89,116,27,111,108,126,105,61,79,112,92,83,123,90,15,77,127,120,62,87,125,110,114,103,56,118,121 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_initialize::old_behavior";
  test.test_nonce  = 334;
  test.test_number = 1121;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "9VeZJE4mGRLaZt9DdBaGshLVeJKTG8wxu5rTHYyJemW2",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1121_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1121_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1121_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1121_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1121_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1121_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1121_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1121_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1121_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1121_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1122(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 113,78,30,24,26,98,106,29,33,82,117,80,55,122,76,2,109,75,128,124,89,116,27,111,108,126,105,61,79,112,92,83,123,90,15,77,127,120,62,87,125,110,114,103,56,118,121 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_initialize::old_behavior";
  test.test_nonce  = 347;
  test.test_number = 1122;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "9VeZJE4mGRLaZt9DdBaGshLVeJKTG8wxu5rTHYyJemW2",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1122_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1122_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1122_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1122_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1122_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1122_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1122_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1122_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1122_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1122_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1123(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_initialize::old_behavior";
  test.test_nonce  = 182;
  test.test_number = 1123;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "HD11ZVE7824S4Ja7c6cCDvB4zncZWnuvKoxNXJLDN9PN",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1123_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1123_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1123_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1123_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1123_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1123_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1123_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1123_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1123_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1123_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1124(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_initialize::old_behavior";
  test.test_nonce  = 188;
  test.test_number = 1124;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "HD11ZVE7824S4Ja7c6cCDvB4zncZWnuvKoxNXJLDN9PN",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1124_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1124_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1124_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1124_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1124_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1124_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1124_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1124_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1124_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1124_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
