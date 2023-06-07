#include "../fd_tests.h"
int test_1025(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 26,90,103,79,112,15,56,29,116,75,2,111,76,24,114,78,98,80,110,127,62,113,125,123,117,124,77,126,27,87,105,92,61,108,33,128,120,106,118,30,82,89,55,121,83,109,122 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_delegate::new_behavior";
  test.test_nonce  = 336;
  test.test_number = 1025;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "2EUrYmRGLhdLT8RUFs8tiWqF5dVDd7GuCXQ4PtDuNou6",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000000UL;
  test_acc->result_lamports = 1000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1025_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1025_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1025_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1025_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "CK5zcbPkc1p6CYAHQySMEb7s1hAbwHEcWBitf3e9RBjo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1025_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1025_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1025_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1025_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "CifNCrz1ArKbQLzLQW6pLZjAe2grZe3ccmQzpA9AaZZx",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1025_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1025_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1025_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1025_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1025_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1025_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1025_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1025_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1025_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1025_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1025_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1025_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1025_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1025_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1025_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1025_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1025_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1025_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1026(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 26,90,103,79,112,15,56,29,116,75,2,111,76,24,114,78,98,80,110,127,62,113,125,123,117,124,77,126,27,87,105,92,61,108,33,128,120,106,118,30,82,89,55,121,83,109,122 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_delegate::new_behavior";
  test.test_nonce  = 429;
  test.test_number = 1026;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "2EUrYmRGLhdLT8RUFs8tiWqF5dVDd7GuCXQ4PtDuNou6",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000000UL;
  test_acc->result_lamports = 1000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1026_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1026_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1026_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1026_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "CK5zcbPkc1p6CYAHQySMEb7s1hAbwHEcWBitf3e9RBjo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1026_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1026_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1026_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1026_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "CifNCrz1ArKbQLzLQW6pLZjAe2grZe3ccmQzpA9AaZZx",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1026_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1026_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1026_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1026_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1026_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1026_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1026_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1026_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1026_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1026_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1026_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1026_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1026_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1026_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1026_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1026_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1026_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1026_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1027(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 26,90,103,79,112,15,56,29,116,75,2,111,76,24,114,78,98,80,110,127,62,113,125,123,117,124,77,126,27,87,105,92,61,108,33,128,120,106,118,30,82,89,55,121,83,109,122 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_delegate::new_behavior";
  test.test_nonce  = 510;
  test.test_number = 1027;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "2EUrYmRGLhdLT8RUFs8tiWqF5dVDd7GuCXQ4PtDuNou6",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000000UL;
  test_acc->result_lamports = 1000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1027_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1027_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1027_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1027_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "CK5zcbPkc1p6CYAHQySMEb7s1hAbwHEcWBitf3e9RBjo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1027_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1027_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1027_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1027_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "CifNCrz1ArKbQLzLQW6pLZjAe2grZe3ccmQzpA9AaZZx",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1027_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1027_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1027_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1027_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1027_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1027_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1027_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1027_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1027_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1027_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1027_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1027_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1027_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1027_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1027_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1027_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1027_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1027_raw_sz;
  test.expected_result = -26;
  test.custom_err = 3;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1028(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 26,90,103,79,112,15,56,29,116,75,2,111,76,24,114,78,98,80,110,127,62,113,125,123,117,124,77,126,27,87,105,92,61,108,33,128,120,106,118,30,82,89,55,121,83,109,122 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_delegate::new_behavior";
  test.test_nonce  = 585;
  test.test_number = 1028;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "2EUrYmRGLhdLT8RUFs8tiWqF5dVDd7GuCXQ4PtDuNou6",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000000UL;
  test_acc->result_lamports = 1000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1028_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1028_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1028_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1028_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "CK5zcbPkc1p6CYAHQySMEb7s1hAbwHEcWBitf3e9RBjo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1028_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1028_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1028_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1028_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "CifNCrz1ArKbQLzLQW6pLZjAe2grZe3ccmQzpA9AaZZx",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1028_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1028_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1028_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1028_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1028_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1028_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1028_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1028_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1028_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1028_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1028_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1028_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1028_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1028_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1028_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1028_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1028_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1028_raw_sz;
  test.expected_result = -26;
  test.custom_err = 3;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1029(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 26,90,103,79,112,15,56,29,116,75,2,111,76,24,114,78,98,80,110,127,62,113,125,123,117,124,77,126,27,87,105,92,61,108,33,128,120,106,118,30,82,89,55,121,83,109,122 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_delegate::new_behavior";
  test.test_nonce  = 602;
  test.test_number = 1029;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "2EUrYmRGLhdLT8RUFs8tiWqF5dVDd7GuCXQ4PtDuNou6",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000000UL;
  test_acc->result_lamports = 1000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1029_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1029_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1029_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1029_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "CK5zcbPkc1p6CYAHQySMEb7s1hAbwHEcWBitf3e9RBjo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1029_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1029_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1029_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1029_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "CifNCrz1ArKbQLzLQW6pLZjAe2grZe3ccmQzpA9AaZZx",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1029_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1029_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1029_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1029_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1029_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1029_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1029_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1029_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1029_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1029_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1029_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1029_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1029_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1029_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1029_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1029_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1029_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1029_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1030(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 26,90,103,79,112,15,56,29,116,75,2,111,76,24,114,78,98,80,110,127,62,113,125,123,117,124,77,126,27,87,105,92,61,108,33,128,120,106,118,30,82,89,55,121,83,109,122 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_delegate::new_behavior";
  test.test_nonce  = 616;
  test.test_number = 1030;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "2EUrYmRGLhdLT8RUFs8tiWqF5dVDd7GuCXQ4PtDuNou6",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000000UL;
  test_acc->result_lamports = 1000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1030_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1030_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1030_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1030_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "CK5zcbPkc1p6CYAHQySMEb7s1hAbwHEcWBitf3e9RBjo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1030_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1030_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1030_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1030_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "CifNCrz1ArKbQLzLQW6pLZjAe2grZe3ccmQzpA9AaZZx",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1030_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1030_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1030_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1030_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1030_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1030_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1030_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1030_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1030_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1030_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1030_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1030_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1030_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1030_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1030_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1030_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1030_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1030_raw_sz;
  test.expected_result = -26;
  test.custom_err = 3;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1031(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 26,90,103,79,112,15,56,29,116,75,2,111,76,24,114,78,98,80,110,127,62,113,125,123,117,124,77,126,27,87,105,92,61,108,33,128,120,106,118,30,82,89,55,121,83,109,122 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_delegate::new_behavior";
  test.test_nonce  = 626;
  test.test_number = 1031;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "2EUrYmRGLhdLT8RUFs8tiWqF5dVDd7GuCXQ4PtDuNou6",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000000UL;
  test_acc->result_lamports = 1000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1031_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1031_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1031_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1031_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "CK5zcbPkc1p6CYAHQySMEb7s1hAbwHEcWBitf3e9RBjo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1031_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1031_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1031_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1031_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "CifNCrz1ArKbQLzLQW6pLZjAe2grZe3ccmQzpA9AaZZx",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1031_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1031_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1031_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1031_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1031_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1031_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1031_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1031_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1031_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1031_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1031_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1031_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1031_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1031_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1031_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1031_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1031_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1031_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1032(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 26,90,103,79,112,15,56,29,116,75,2,111,76,24,114,78,98,80,110,127,62,113,125,123,117,124,77,126,27,87,105,92,61,108,33,128,120,106,118,30,82,89,55,121,83,109,122 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_delegate::new_behavior";
  test.test_nonce  = 633;
  test.test_number = 1032;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "2EUrYmRGLhdLT8RUFs8tiWqF5dVDd7GuCXQ4PtDuNou6",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000000UL;
  test_acc->result_lamports = 1000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1032_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1032_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1032_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1032_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "CifNCrz1ArKbQLzLQW6pLZjAe2grZe3ccmQzpA9AaZZx",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "HWFfhYx4VQxLQjzWkUXbYFBR85QgZ737kvPT52pQhBiG",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1032_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1032_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1032_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1032_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "CifNCrz1ArKbQLzLQW6pLZjAe2grZe3ccmQzpA9AaZZx",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1032_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1032_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1032_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1032_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1032_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1032_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1032_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1032_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1032_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1032_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1032_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1032_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1032_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1032_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1032_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1032_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1032_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1032_raw_sz;
  test.expected_result = -7;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1033(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 26,90,103,79,112,15,56,29,116,75,2,111,76,24,114,78,98,80,110,127,62,113,125,123,117,124,77,126,27,87,105,92,61,108,33,128,120,106,118,30,82,89,55,121,83,109,122 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_delegate::new_behavior";
  test.test_nonce  = 638;
  test.test_number = 1033;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "2EUrYmRGLhdLT8RUFs8tiWqF5dVDd7GuCXQ4PtDuNou6",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000000UL;
  test_acc->result_lamports = 1000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1033_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1033_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1033_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1033_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "CifNCrz1ArKbQLzLQW6pLZjAe2grZe3ccmQzpA9AaZZx",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "HWFfhYx4VQxLQjzWkUXbYFBR85QgZ737kvPT52pQhBiG",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1033_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1033_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1033_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1033_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "CifNCrz1ArKbQLzLQW6pLZjAe2grZe3ccmQzpA9AaZZx",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1033_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1033_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1033_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1033_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1033_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1033_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1033_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1033_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1033_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1033_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1033_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1033_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1033_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1033_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1033_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1033_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1033_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1033_raw_sz;
  test.expected_result = -7;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1034(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 26,90,103,79,112,15,56,29,116,75,2,111,76,24,114,78,98,80,110,127,62,113,125,123,117,124,77,126,27,87,105,92,61,108,33,128,120,106,118,30,82,89,55,121,83,109,122 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_delegate::new_behavior";
  test.test_nonce  = 539;
  test.test_number = 1034;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "7vE2aTfQk6WeBaTnb7RJbRb9e1psH6GGf1ZYHTo3X8Ry",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000000UL;
  test_acc->result_lamports = 1000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1034_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1034_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1034_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1034_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "HezP98LPSimUAXSkHQRfXsqUsMthfuHnDRJvWqJMiW2k",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1034_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1034_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1034_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1034_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FmLQHWGUvVe3rKhFrm6tHus1gKvEXtH5StcEFzZpeZJS",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1034_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1034_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1034_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1034_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1034_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1034_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1034_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1034_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1034_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1034_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1034_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1034_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1034_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1034_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1034_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1034_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1034_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1034_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1035(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 26,90,103,79,112,15,56,29,116,75,2,111,76,24,114,78,98,80,110,127,62,113,125,123,117,124,77,126,27,87,105,92,61,108,33,128,120,106,118,30,82,89,55,121,83,109,122 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_delegate::new_behavior";
  test.test_nonce  = 551;
  test.test_number = 1035;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "2EUrYmRGLhdLT8RUFs8tiWqF5dVDd7GuCXQ4PtDuNou6",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000000UL;
  test_acc->result_lamports = 1000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1035_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1035_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1035_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1035_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "CK5zcbPkc1p6CYAHQySMEb7s1hAbwHEcWBitf3e9RBjo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1035_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1035_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1035_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1035_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "CifNCrz1ArKbQLzLQW6pLZjAe2grZe3ccmQzpA9AaZZx",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1035_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1035_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1035_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1035_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1035_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1035_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1035_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1035_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1035_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1035_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1035_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1035_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1035_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1035_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1035_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1035_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1035_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1035_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1036(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_delegate::old_behavior";
  test.test_nonce  = 324;
  test.test_number = 1036;
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
  test_acc->data            = fd_flamenco_native_prog_test_1036_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1036_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1036_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1036_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "9CaeDFdhUVnpeeXkXUGK5vKS715bBNNHp7cCcYUSWBiF",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1036_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1036_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1036_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1036_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "EiDW2kbNZwzaUvsdTLgrpuYJDS7Xc42KYVPFSav7Wdvr",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1036_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1036_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1036_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1036_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1036_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1036_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1036_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1036_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1036_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1036_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1036_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1036_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1036_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1036_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1036_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1036_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1036_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1036_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1037(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_delegate::old_behavior";
  test.test_nonce  = 385;
  test.test_number = 1037;
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
  test_acc->data            = fd_flamenco_native_prog_test_1037_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1037_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1037_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1037_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "9CaeDFdhUVnpeeXkXUGK5vKS715bBNNHp7cCcYUSWBiF",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1037_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1037_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1037_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1037_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "EiDW2kbNZwzaUvsdTLgrpuYJDS7Xc42KYVPFSav7Wdvr",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1037_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1037_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1037_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1037_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1037_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1037_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1037_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1037_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1037_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1037_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1037_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1037_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1037_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1037_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1037_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1037_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1037_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1037_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1038(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_delegate::old_behavior";
  test.test_nonce  = 439;
  test.test_number = 1038;
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
  test_acc->data            = fd_flamenco_native_prog_test_1038_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1038_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1038_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1038_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "9CaeDFdhUVnpeeXkXUGK5vKS715bBNNHp7cCcYUSWBiF",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1038_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1038_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1038_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1038_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "EiDW2kbNZwzaUvsdTLgrpuYJDS7Xc42KYVPFSav7Wdvr",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1038_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1038_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1038_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1038_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1038_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1038_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1038_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1038_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1038_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1038_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1038_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1038_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1038_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1038_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1038_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1038_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1038_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1038_raw_sz;
  test.expected_result = -26;
  test.custom_err = 3;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1039(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_delegate::old_behavior";
  test.test_nonce  = 521;
  test.test_number = 1039;
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
  test_acc->data            = fd_flamenco_native_prog_test_1039_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1039_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1039_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1039_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "9CaeDFdhUVnpeeXkXUGK5vKS715bBNNHp7cCcYUSWBiF",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1039_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1039_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1039_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1039_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "EiDW2kbNZwzaUvsdTLgrpuYJDS7Xc42KYVPFSav7Wdvr",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1039_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1039_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1039_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1039_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1039_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1039_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1039_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1039_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1039_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1039_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1039_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1039_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1039_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1039_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1039_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1039_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1039_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1039_raw_sz;
  test.expected_result = -26;
  test.custom_err = 3;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1040(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_delegate::old_behavior";
  test.test_nonce  = 546;
  test.test_number = 1040;
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
  test_acc->data            = fd_flamenco_native_prog_test_1040_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1040_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1040_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1040_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "9CaeDFdhUVnpeeXkXUGK5vKS715bBNNHp7cCcYUSWBiF",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1040_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1040_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1040_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1040_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "EiDW2kbNZwzaUvsdTLgrpuYJDS7Xc42KYVPFSav7Wdvr",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1040_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1040_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1040_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1040_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1040_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1040_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1040_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1040_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1040_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1040_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1040_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1040_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1040_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1040_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1040_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1040_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1040_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1040_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1041(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_delegate::old_behavior";
  test.test_nonce  = 565;
  test.test_number = 1041;
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
  test_acc->data            = fd_flamenco_native_prog_test_1041_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1041_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1041_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1041_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "9CaeDFdhUVnpeeXkXUGK5vKS715bBNNHp7cCcYUSWBiF",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1041_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1041_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1041_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1041_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "EiDW2kbNZwzaUvsdTLgrpuYJDS7Xc42KYVPFSav7Wdvr",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1041_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1041_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1041_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1041_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1041_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1041_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1041_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1041_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1041_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1041_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1041_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1041_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1041_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1041_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1041_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1041_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1041_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1041_raw_sz;
  test.expected_result = -26;
  test.custom_err = 3;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1042(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_delegate::old_behavior";
  test.test_nonce  = 584;
  test.test_number = 1042;
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
  test_acc->data            = fd_flamenco_native_prog_test_1042_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1042_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1042_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1042_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "9CaeDFdhUVnpeeXkXUGK5vKS715bBNNHp7cCcYUSWBiF",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1042_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1042_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1042_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1042_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "EiDW2kbNZwzaUvsdTLgrpuYJDS7Xc42KYVPFSav7Wdvr",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1042_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1042_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1042_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1042_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1042_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1042_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1042_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1042_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1042_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1042_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1042_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1042_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1042_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1042_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1042_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1042_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1042_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1042_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1043(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_delegate::old_behavior";
  test.test_nonce  = 597;
  test.test_number = 1043;
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
  test_acc->data            = fd_flamenco_native_prog_test_1043_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1043_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1043_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1043_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "EiDW2kbNZwzaUvsdTLgrpuYJDS7Xc42KYVPFSav7Wdvr",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "FKKcoDeb5fb8YsRaL6CeMzKBuUbCKxKGKEZZvYQhBup7",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1043_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1043_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1043_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1043_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "EiDW2kbNZwzaUvsdTLgrpuYJDS7Xc42KYVPFSav7Wdvr",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1043_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1043_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1043_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1043_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1043_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1043_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1043_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1043_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1043_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1043_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1043_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1043_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1043_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1043_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1043_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1043_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1043_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1043_raw_sz;
  test.expected_result = -7;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1044(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_delegate::old_behavior";
  test.test_nonce  = 605;
  test.test_number = 1044;
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
  test_acc->data            = fd_flamenco_native_prog_test_1044_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1044_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1044_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1044_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "EiDW2kbNZwzaUvsdTLgrpuYJDS7Xc42KYVPFSav7Wdvr",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "FKKcoDeb5fb8YsRaL6CeMzKBuUbCKxKGKEZZvYQhBup7",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1044_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1044_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1044_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1044_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "EiDW2kbNZwzaUvsdTLgrpuYJDS7Xc42KYVPFSav7Wdvr",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1044_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1044_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1044_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1044_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1044_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1044_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1044_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1044_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1044_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1044_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1044_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1044_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1044_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1044_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1044_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1044_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1044_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1044_raw_sz;
  test.expected_result = -7;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1045(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 80,33,118,125,105,108,109,78,111,76,124,56,120,15,114,30,123,126,98,121,89,83,62,79,2,55,27,112,127,103,106,26,110,77,128,82,61,87,92,117,116,90,75,24,29,113,122 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_delegate::old_behavior";
  test.test_nonce  = 300;
  test.test_number = 1045;
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
  test_acc->data            = fd_flamenco_native_prog_test_1045_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1045_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1045_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1045_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "C34ou7TQp2cS2s4s461XUWkEhZFLVJaT5ZuAzvwqteHx",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1045_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1045_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1045_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1045_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BNuCFyLR7bvbCr2rq4yBQC13bbcfprH64ZYKadFiN4ki",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1045_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1045_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1045_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1045_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1045_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1045_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1045_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1045_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1045_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1045_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1045_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1045_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1045_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1045_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1045_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1045_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1045_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1045_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1046(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 80,33,118,125,105,108,109,78,111,76,124,56,120,15,114,30,123,126,98,121,89,83,62,79,2,55,27,112,127,103,106,26,110,77,128,82,61,87,92,117,116,90,75,24,29,113,122 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_delegate::old_behavior";
  test.test_nonce  = 425;
  test.test_number = 1046;
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
  test_acc->data            = fd_flamenco_native_prog_test_1046_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1046_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1046_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1046_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "C34ou7TQp2cS2s4s461XUWkEhZFLVJaT5ZuAzvwqteHx",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1046_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1046_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1046_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1046_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BNuCFyLR7bvbCr2rq4yBQC13bbcfprH64ZYKadFiN4ki",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1046_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1046_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1046_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1046_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1046_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1046_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1046_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1046_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1046_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1046_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1046_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1046_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1046_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1046_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1046_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1046_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1046_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1046_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1047(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 80,33,118,125,105,108,109,78,111,76,124,56,120,15,114,30,123,126,98,121,89,83,62,79,2,55,27,112,127,103,106,26,110,77,128,82,61,87,92,117,116,90,75,24,29,113,122 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_delegate::old_behavior";
  test.test_nonce  = 495;
  test.test_number = 1047;
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
  test_acc->data            = fd_flamenco_native_prog_test_1047_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1047_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1047_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1047_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "C34ou7TQp2cS2s4s461XUWkEhZFLVJaT5ZuAzvwqteHx",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1047_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1047_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1047_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1047_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BNuCFyLR7bvbCr2rq4yBQC13bbcfprH64ZYKadFiN4ki",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1047_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1047_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1047_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1047_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1047_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1047_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1047_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1047_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1047_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1047_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1047_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1047_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1047_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1047_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1047_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1047_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1047_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1047_raw_sz;
  test.expected_result = -26;
  test.custom_err = 3;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1048(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 80,33,118,125,105,108,109,78,111,76,124,56,120,15,114,30,123,126,98,121,89,83,62,79,2,55,27,112,127,103,106,26,110,77,128,82,61,87,92,117,116,90,75,24,29,113,122 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_delegate::old_behavior";
  test.test_nonce  = 572;
  test.test_number = 1048;
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
  test_acc->data            = fd_flamenco_native_prog_test_1048_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1048_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1048_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1048_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "C34ou7TQp2cS2s4s461XUWkEhZFLVJaT5ZuAzvwqteHx",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1048_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1048_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1048_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1048_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BNuCFyLR7bvbCr2rq4yBQC13bbcfprH64ZYKadFiN4ki",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1048_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1048_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1048_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1048_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1048_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1048_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1048_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1048_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1048_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1048_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1048_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1048_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1048_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1048_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1048_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1048_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1048_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1048_raw_sz;
  test.expected_result = -26;
  test.custom_err = 3;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1049(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 80,33,118,125,105,108,109,78,111,76,124,56,120,15,114,30,123,126,98,121,89,83,62,79,2,55,27,112,127,103,106,26,110,77,128,82,61,87,92,117,116,90,75,24,29,113,122 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_delegate::old_behavior";
  test.test_nonce  = 590;
  test.test_number = 1049;
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
  test_acc->data            = fd_flamenco_native_prog_test_1049_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1049_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1049_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1049_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "C34ou7TQp2cS2s4s461XUWkEhZFLVJaT5ZuAzvwqteHx",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1049_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1049_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1049_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1049_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BNuCFyLR7bvbCr2rq4yBQC13bbcfprH64ZYKadFiN4ki",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1049_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1049_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1049_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1049_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1049_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1049_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1049_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1049_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1049_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1049_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1049_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1049_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1049_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1049_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1049_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1049_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1049_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1049_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
